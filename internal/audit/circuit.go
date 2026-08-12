package audit

import (
	"context"
	"errors"
	"github.com/example/ai-audit-gateway/internal/observability"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("auditor circuit open")

// CircuitBreaker protects synchronous calls; it is safe for concurrent use.
type CircuitBreaker struct {
	inner       Auditor
	maxFailures int
	openFor     time.Duration
	sem         chan struct{}
	mu          sync.Mutex
	failures    int
	openedUntil time.Time
	metrics     *observability.Metrics
}

func NewCircuitBreaker(inner Auditor, maxFailures, concurrency int, openFor time.Duration, metrics ...*observability.Metrics) *CircuitBreaker {
	if maxFailures < 1 {
		maxFailures = 5
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if openFor <= 0 {
		openFor = 30 * time.Second
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	return &CircuitBreaker{inner: inner, maxFailures: maxFailures, openFor: openFor, sem: make(chan struct{}, concurrency), metrics: collector}
}

func (b *CircuitBreaker) Name() string                     { return b.inner.Name() }
func (b *CircuitBreaker) Health(ctx context.Context) error { return b.inner.Health(ctx) }
func (b *CircuitBreaker) Audit(ctx context.Context, input Input) (ModelResult, error) {
	b.mu.Lock()
	if time.Now().Before(b.openedUntil) {
		b.mu.Unlock()
		b.metrics.Inc("audit_auditor_calls_total", map[string]string{"result": "circuit_open"})
		return ModelResult{}, ErrCircuitOpen
	}
	b.mu.Unlock()
	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
	case <-ctx.Done():
		return ModelResult{}, ctx.Err()
	}
	started := time.Now()
	result, err := b.inner.Audit(ctx, input)
	b.metrics.Observe("audit_auditor_duration_seconds", time.Since(started).Seconds(), map[string]string{"result": map[bool]string{true: "error", false: "success"}[err != nil]})
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.failures = 0
		b.metrics.Inc("audit_auditor_calls_total", map[string]string{"result": "success"})
		return result, nil
	}
	b.failures++
	b.metrics.Inc("audit_auditor_calls_total", map[string]string{"result": "error"})
	if b.failures >= b.maxFailures {
		b.openedUntil = time.Now().Add(b.openFor)
		b.failures = 0
		b.metrics.Inc("audit_auditor_circuit_open_total", nil)
	}
	return result, err
}
