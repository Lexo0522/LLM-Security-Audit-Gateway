package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/segmentio/kafka-go"
)

type Sink interface {
	StoreEvents(context.Context, []audit.Event) error
}
type Publisher interface {
	Publish(context.Context, audit.Event) error
	Close() error
}
type KafkaPublisher struct{ writer *kafka.Writer }

func NewKafka(brokers []string, topic string) *KafkaPublisher {
	if len(brokers) == 0 {
		return nil
	}
	return &KafkaPublisher{writer: &kafka.Writer{Addr: kafka.TCP(brokers...), Topic: topic, RequiredAcks: kafka.RequireAll, Async: false, AllowAutoTopicCreation: true, WriteTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, Balancer: &kafka.Hash{}}}
}
func (p *KafkaPublisher) Publish(ctx context.Context, event audit.Event) error {
	if p == nil {
		return nil
	}
	event = audit.RedactEvidence(event)
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return p.writer.WriteMessages(ctx, kafka.Message{Key: []byte(event.TenantID), Value: payload})
}
func (p *KafkaPublisher) Close() error {
	if p == nil {
		return nil
	}
	return p.writer.Close()
}

// Pipeline batches storage without putting external availability on the request path.
type Pipeline struct {
	ch        chan audit.Event
	sink      Sink
	publisher Publisher
	logger    *slog.Logger
	metrics   *observability.Metrics
	done      chan struct{}
	once      sync.Once
}

func NewPipeline(size int, sink Sink, publisher Publisher, logger *slog.Logger, metrics ...*observability.Metrics) *Pipeline {
	if size < 1 {
		size = 1000
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	p := &Pipeline{ch: make(chan audit.Event, size), sink: sink, publisher: publisher, logger: logger, metrics: collector, done: make(chan struct{})}
	go p.run()
	return p
}
func (p *Pipeline) Enqueue(event audit.Event) bool {
	event = audit.RedactEvidence(event)
	select {
	case p.ch <- event:
		p.metrics.Inc("audit_events_enqueued_total", nil)
		return true
	default:
		p.logger.Warn("audit event queue full; event dropped", slog.String("event_id", event.EventID))
		p.metrics.Inc("audit_events_dropped_total", map[string]string{"reason": "queue_full"})
		return false
	}
}
func (p *Pipeline) Close() {
	p.once.Do(func() {
		close(p.ch)
		<-p.done
		if p.publisher != nil {
			_ = p.publisher.Close()
		}
	})
}
func (p *Pipeline) run() {
	defer close(p.done)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]audit.Event, 0, 100)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if p.sink != nil {
			if err := p.sink.StoreEvents(ctx, batch); err != nil {
				p.logger.Warn("audit record write failed", slog.Any("error", err))
				p.metrics.Inc("audit_postgres_batches_total", map[string]string{"result": "error"})
			} else {
				p.metrics.Inc("audit_postgres_batches_total", map[string]string{"result": "success"})
			}
		}
		if p.publisher != nil {
			for _, event := range batch {
				if err := p.publisher.Publish(ctx, event); err != nil {
					p.logger.Warn("audit event publish failed", slog.Any("error", err))
					p.metrics.Inc("audit_kafka_events_total", map[string]string{"result": "error"})
					break
				}
				p.metrics.Inc("audit_kafka_events_total", map[string]string{"result": "success"})
			}
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-p.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

var _ Sink = (*storage.Repository)(nil)
