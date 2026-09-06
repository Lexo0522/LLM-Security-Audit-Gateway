// Package consumer provides at-least-once Kafka to ClickHouse audit delivery.
package consumer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	store "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/segmentio/kafka-go"
)

type EventStore interface {
	EnsureSchema(context.Context) error
	InsertEvents(context.Context, []audit.Event) error
	Ping(context.Context) error
}

type messageWriter interface {
	WriteMessages(context.Context, ...kafka.Message) error
	Close() error
}

type Config struct {
	Brokers                  []string
	Topic, DLQTopic, GroupID string
}
type Consumer struct {
	config  Config
	store   EventStore
	reader  *kafka.Reader
	dlq     messageWriter
	logger  *slog.Logger
	metrics *observability.Metrics
	retry   time.Duration
}

func New(config Config, destination EventStore, logger *slog.Logger, metrics *observability.Metrics) (*Consumer, error) {
	if len(config.Brokers) == 0 || config.Topic == "" || config.GroupID == "" || destination == nil {
		return nil, fmt.Errorf("kafka brokers, topic, group id, and clickhouse store are required")
	}
	if config.DLQTopic == "" {
		config.DLQTopic = config.Topic + ".dlq"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Consumer{config: config, store: destination, logger: logger, metrics: metrics, retry: time.Second, reader: kafka.NewReader(kafka.ReaderConfig{Brokers: config.Brokers, Topic: config.Topic, GroupID: config.GroupID, StartOffset: kafka.FirstOffset, CommitInterval: 0, MaxBytes: 10 << 20}), dlq: &kafka.Writer{Addr: kafka.TCP(config.Brokers...), Topic: config.DLQTopic, RequiredAcks: kafka.RequireAll, Async: false, AllowAutoTopicCreation: true, WriteTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second}}, nil
}
func (c *Consumer) Close() error {
	if c == nil {
		return nil
	}
	_ = c.reader.Close()
	return c.dlq.Close()
}

// Run does not return for recoverable Kafka or ClickHouse failures. Offsets are
// committed only after the destination operation has completed successfully.
func (c *Consumer) Run(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("consumer disabled")
	}
	if err := c.ensureTopic(ctx); err != nil {
		return err
	}
	if err := c.ensureSchema(ctx); err != nil {
		return err
	}
	go c.sampleStats(ctx)
	for {
		message, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.metrics.Inc("audit_clickhouse_consumer_kafka_errors_total", nil)
			c.logger.Warn("fetch kafka audit event", slog.Any("error", err))
			if !wait(ctx, time.Second) {
				return nil
			}
			continue
		}
		batch := []kafka.Message{message}
		var events []audit.Event
		invalidReason := ""
		var event audit.Event
		if err = json.Unmarshal(message.Value, &event); err != nil {
			invalidReason = err.Error()
		} else if validation := store.ValidateEvent(event); validation != nil {
			invalidReason = validation.Error()
		} else {
			events = append(events, event)
		}
		batchCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		for invalidReason == "" && len(batch) < 100 {
			next, fetchErr := c.reader.FetchMessage(batchCtx)
			if fetchErr != nil {
				break
			}
			var candidate audit.Event
			batch = append(batch, next)
			if decodeErr := json.Unmarshal(next.Value, &candidate); decodeErr != nil {
				invalidReason = decodeErr.Error()
				break
			}
			if validation := store.ValidateEvent(candidate); validation != nil {
				invalidReason = validation.Error()
				break
			}
			events = append(events, candidate)
		}
		cancel()
		if len(events) > 0 {
			if err = c.insertWithRetry(ctx, events); err != nil {
				return err
			}
		}
		if invalidReason != "" {
			if err = c.publishDLQWithRetry(ctx, batch[len(batch)-1], invalidReason); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
		if err = c.reader.CommitMessages(ctx, batch...); err != nil {
			c.metrics.Inc("audit_clickhouse_consumer_commits_total", map[string]string{"result": "error"})
			c.logger.Warn("commit audit offsets", slog.Any("error", err))
			continue
		}
		for range events {
			c.metrics.Inc("audit_clickhouse_consumer_events_total", map[string]string{"result": "success"})
		}
		c.metrics.Inc("audit_clickhouse_consumer_commits_total", map[string]string{"result": "success"})
	}
}

// sampleStats surfaces reader lag, rebalances, and fetch errors as gauges; lag
// is the primary signal that the ClickHouse pipeline is falling behind.
func (c *Consumer) sampleStats(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := c.reader.Stats()
			c.metrics.Set("audit_kafka_consumer_lag", float64(stats.Lag), nil)
			c.metrics.Set("audit_kafka_consumer_rebalances", float64(stats.Rebalances), nil)
			c.metrics.Set("audit_kafka_consumer_fetch_errors", float64(stats.Errors), nil)
		}
	}
}

// ensureTopic creates the audit topic when it does not exist yet. A consumer
// group that joins before the topic exists receives an empty partition
// assignment and would starve forever, so the topic must precede the first
// fetch. CreateTopics is idempotent; production deployments that pre-create
// the topic with custom replication simply skip the creation call.
func (c *Consumer) ensureTopic(ctx context.Context) error {
	for {
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.createTopic(probe)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		c.metrics.Inc("audit_clickhouse_consumer_topic_total", map[string]string{"result": "error"})
		c.logger.Warn("ensure kafka audit topic", slog.Any("error", err))
		if !wait(ctx, time.Second) {
			return ctx.Err()
		}
	}
}

func (c *Consumer) createTopic(ctx context.Context) error {
	conn, err := kafka.DialContext(ctx, "tcp", c.config.Brokers[0])
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	controller, err := conn.Controller()
	if err != nil {
		return err
	}
	controllerConn, err := kafka.DialContext(ctx, "tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)))
	if err != nil {
		return err
	}
	defer func() { _ = controllerConn.Close() }()
	return controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             c.config.Topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
}

func (c *Consumer) ensureSchema(ctx context.Context) error {
	for {
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.store.EnsureSchema(probe)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		c.metrics.Inc("audit_clickhouse_consumer_schema_total", map[string]string{"result": "error"})
		c.logger.Warn("ensure clickhouse schema", slog.Any("error", err))
		if !wait(ctx, time.Second) {
			return ctx.Err()
		}
	}
}

// maxInsertAttempts bounds ClickHouse insert retries; exceeding it returns an
// error so the process exits and the supervisor restarts consumption from the
// last committed offset instead of spinning forever on a broken destination.
const maxInsertAttempts = 10

func (c *Consumer) insertWithRetry(ctx context.Context, events []audit.Event) error {
	for attempt := 1; ; attempt++ {
		started := time.Now()
		insertCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.store.InsertEvents(insertCtx, events)
		cancel()
		c.metrics.Observe("audit_clickhouse_insert_duration_seconds", time.Since(started).Seconds(), nil)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		c.metrics.Inc("audit_clickhouse_consumer_inserts_total", map[string]string{"result": "error"})
		c.logger.Warn("write clickhouse audit events", slog.Any("error", err))
		if attempt >= maxInsertAttempts {
			return fmt.Errorf("clickhouse insert failed after %d attempts: %w", attempt, err)
		}
		if !wait(ctx, time.Second) {
			return ctx.Err()
		}
	}
}
func (c *Consumer) publishDLQ(ctx context.Context, message kafka.Message, reason string) error {
	payload, err := deadLetterPayload(message, reason)
	if err != nil {
		return err
	}
	return c.dlq.WriteMessages(ctx, kafka.Message{Key: message.Key, Value: payload, Headers: []kafka.Header{{Key: "source_event", Value: []byte("audit.events")}}})
}

func (c *Consumer) publishDLQWithRetry(ctx context.Context, message kafka.Message, reason string) error {
	for {
		if err := c.publishDLQ(ctx, message, reason); err == nil {
			c.metrics.Inc("audit_clickhouse_consumer_dlq_total", map[string]string{"result": "success"})
			return nil
		} else {
			c.metrics.Inc("audit_clickhouse_consumer_dlq_total", map[string]string{"result": "error"})
			c.logger.Warn("publish audit DLQ", slog.Any("error", err))
		}
		if !wait(ctx, c.retryDelay()) {
			return ctx.Err()
		}
	}
}

func (c *Consumer) retryDelay() time.Duration {
	if c.retry <= 0 {
		return time.Second
	}
	return c.retry
}

func deadLetterPayload(message kafka.Message, reason string) ([]byte, error) {
	return json.Marshal(struct {
		SourceTopic   string `json:"source_topic"`
		Partition     int    `json:"partition"`
		Offset        int64  `json:"offset"`
		Reason        string `json:"reason"`
		PayloadBase64 string `json:"payload_base64"`
	}{
		SourceTopic:   message.Topic,
		Partition:     message.Partition,
		Offset:        message.Offset,
		Reason:        reason,
		PayloadBase64: base64.StdEncoding.EncodeToString(message.Value),
	})
}
func (c *Consumer) KafkaHealth(ctx context.Context) error {
	connection, err := kafka.DialContext(ctx, "tcp", c.config.Brokers[0])
	if err != nil {
		return err
	}
	return connection.Close()
}
func (c *Consumer) ClickHouseHealth(ctx context.Context) error { return c.store.Ping(ctx) }
func wait(ctx context.Context, duration time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(duration):
		return true
	}
}
