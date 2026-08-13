package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
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

type KafkaPublisher struct {
	writer  *kafka.Writer
	brokers []string
}

func NewKafka(brokers []string, topic string) *KafkaPublisher {
	if len(brokers) == 0 {
		return nil
	}
	return &KafkaPublisher{brokers: brokers, writer: &kafka.Writer{Addr: kafka.TCP(brokers...), Topic: topic, RequiredAcks: kafka.RequireAll, Async: false, AllowAutoTopicCreation: true, WriteTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, Balancer: &kafka.Hash{}}}
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
	return p.writer.WriteMessages(ctx, kafka.Message{Key: []byte(event.TenantID), Value: payload, Headers: []kafka.Header{{Key: "event_id", Value: []byte(event.EventID)}}})
}
func (p *KafkaPublisher) Health(ctx context.Context) error {
	if p == nil || len(p.brokers) == 0 {
		return fmt.Errorf("kafka disabled")
	}
	connection, err := kafka.DialContext(ctx, "tcp", p.brokers[0])
	if err != nil {
		return err
	}
	return connection.Close()
}
func (p *KafkaPublisher) Close() error {
	if p == nil {
		return nil
	}
	return p.writer.Close()
}

// Pipeline is a bounded durable queue. A capacity token is released only after
// PostgreSQL commits its audit record and transactional-outbox row.
type Pipeline struct {
	ch        chan audit.Event
	slots     chan struct{}
	sink      Sink
	logger    *slog.Logger
	metrics   *observability.Metrics
	done      chan struct{}
	closing   atomic.Bool
	once      sync.Once
	mu        sync.RWMutex
	capacity  int
	lastErr   string
	saturated bool
	onFailure func(Status)
}

func (p *Pipeline) OnFailure(callback func(Status)) {
	if p != nil {
		p.mu.Lock()
		p.onFailure = callback
		p.mu.Unlock()
	}
}

type Status struct {
	Capacity  int    `json:"capacity"`
	Pending   int    `json:"pending"`
	Saturated bool   `json:"saturated"`
	LastError string `json:"last_error,omitempty"`
}

// The publisher argument remains for source compatibility. Kafka delivery is
// deliberately performed by Dispatcher after the transaction commits.
func NewPipeline(size int, sink Sink, _ Publisher, logger *slog.Logger, metrics ...*observability.Metrics) *Pipeline {
	if size < 1 {
		size = 1000
	}
	if logger == nil {
		logger = slog.Default()
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	p := &Pipeline{ch: make(chan audit.Event, size), slots: make(chan struct{}, size), sink: sink, logger: logger, metrics: collector, done: make(chan struct{}), capacity: size}
	for range size {
		p.slots <- struct{}{}
	}
	go p.run()
	return p
}
func (p *Pipeline) Enqueue(event audit.Event) bool {
	event = audit.RedactEvidence(event)
	select {
	case <-p.slots:
		select {
		case p.ch <- event:
			p.metrics.Inc("audit_events_enqueued_total", nil)
			p.updateMetrics()
			return true
		default:
			p.slots <- struct{}{}
		}
	default:
	}
	p.mu.Lock()
	p.saturated = true
	callback := p.onFailure
	p.mu.Unlock()
	p.logger.Warn("audit event queue full; gateway should be removed from readiness", slog.String("event_id", event.EventID))
	p.metrics.Inc("audit_events_dropped_total", map[string]string{"reason": "queue_full"})
	p.updateMetrics()
	if callback != nil {
		callback(p.Status())
	}
	return false
}
func (p *Pipeline) Status() Status {
	if p == nil {
		return Status{LastError: "audit pipeline disabled", Saturated: true}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Status{Capacity: p.capacity, Pending: p.capacity - len(p.slots), Saturated: p.saturated || len(p.slots) == 0, LastError: p.lastErr}
}
func (p *Pipeline) Ready() bool {
	status := p.Status()
	return !status.Saturated && status.LastError == ""
}
func (p *Pipeline) Close() {
	p.once.Do(func() {
		p.closing.Store(true)
		close(p.ch)
		<-p.done
	})
}
func (p *Pipeline) run() {
	defer close(p.done)
	batch := make([]audit.Event, 0, 100)
	flushTimer := time.NewTimer(200 * time.Millisecond)
	defer flushTimer.Stop()
	for {
		if len(batch) == 0 {
			select {
			case event, ok := <-p.ch:
				if !ok {
					return
				}
				batch = append(batch, event)
			}
		}
		for len(batch) < cap(batch) {
			select {
			case event, ok := <-p.ch:
				if !ok {
					p.storeOnce(batch)
					return
				}
				batch = append(batch, event)
			default:
				goto flush
			}
		}
	flush:
		if !flushTimer.Stop() {
			select {
			case <-flushTimer.C:
			default:
			}
		}
		flushTimer.Reset(200 * time.Millisecond)
		for {
			if p.storeOnce(batch) {
				batch = batch[:0]
				break
			}
			select {
			case <-time.After(p.retryDelay()):
				if p.closing.Load() {
					p.storeOnce(batch)
					return
				}
			case <-flushTimer.C:
			}
		}
	}
}
func (p *Pipeline) storeOnce(batch []audit.Event) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := error(nil)
	if p.sink == nil {
		err = fmt.Errorf("audit persistence disabled")
	} else {
		err = p.sink.StoreEvents(ctx, batch)
	}
	cancel()
	p.mu.Lock()
	if err != nil {
		p.lastErr = err.Error()
		callback := p.onFailure
		p.mu.Unlock()
		p.logger.Warn("audit record write failed; retrying", slog.Any("error", err))
		p.metrics.Inc("audit_postgres_batches_total", map[string]string{"result": "error"})
		p.updateMetrics()
		if callback != nil {
			callback(p.Status())
		}
		return false
	}
	p.lastErr = ""
	p.saturated = false
	p.mu.Unlock()
	for range batch {
		p.slots <- struct{}{}
	}
	p.metrics.Inc("audit_postgres_batches_total", map[string]string{"result": "success"})
	p.updateMetrics()
	return true
}
func (p *Pipeline) retryDelay() time.Duration { return time.Second }
func (p *Pipeline) updateMetrics() {
	if p.metrics == nil {
		return
	}
	status := p.Status()
	p.metrics.Set("audit_event_queue_pending", float64(status.Pending), nil)
	p.metrics.Set("audit_event_queue_capacity", float64(status.Capacity), nil)
	p.metrics.Set("audit_event_queue_healthy", map[bool]float64{true: 1, false: 0}[p.Ready()], nil)
}

// Dispatcher provides at-least-once Kafka delivery from PostgreSQL's outbox.
type Dispatcher struct {
	source    *storage.Repository
	publisher Publisher
	logger    *slog.Logger
	metrics   *observability.Metrics
	done      chan struct{}
	cancel    context.CancelFunc
}

func NewDispatcher(source *storage.Repository, publisher Publisher, logger *slog.Logger, metrics *observability.Metrics) *Dispatcher {
	if publisher == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{source: source, publisher: publisher, logger: logger, metrics: metrics, done: make(chan struct{})}
}
func (d *Dispatcher) Start(ctx context.Context) {
	if d == nil {
		return
	}
	dispatchCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	go func() {
		defer close(d.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			d.dispatch(dispatchCtx)
			select {
			case <-dispatchCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	<-d.done
	_ = d.publisher.Close()
}
func (d *Dispatcher) dispatch(ctx context.Context) {
	claimCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	records, err := d.source.ClaimOutbox(claimCtx, 100, 30*time.Second)
	cancel()
	if err != nil {
		d.logger.Warn("audit outbox claim failed", slog.Any("error", err))
		d.metrics.Inc("audit_outbox_claims_total", map[string]string{"result": "error"})
		return
	}
	for _, record := range records {
		var event audit.Event
		if err := json.Unmarshal(record.Payload, &event); err == nil {
			err = d.publisher.Publish(ctx, event)
		}
		if err != nil {
			_ = d.source.RetryOutbox(ctx, record.EventID, record.Attempts, err)
			d.metrics.Inc("audit_kafka_events_total", map[string]string{"result": "error"})
			continue
		}
		if err := d.source.MarkOutboxPublished(ctx, record.EventID); err != nil {
			d.logger.Warn("mark audit outbox published", slog.Any("error", err))
			continue
		}
		d.metrics.Inc("audit_kafka_events_total", map[string]string{"result": "success"})
	}
	if pending, err := d.source.OutboxPending(ctx); err == nil {
		d.metrics.Set("audit_outbox_pending", float64(pending), nil)
	}
}

var _ Sink = (*storage.Repository)(nil)
