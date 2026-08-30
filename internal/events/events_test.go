package events

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/storage"
)

type memorySink struct {
	mu     sync.Mutex
	events []audit.Event
}
type failingSink struct {
	calls   int
	failing atomic.Bool
}

func (s *failingSink) StoreEvents(context.Context, []audit.Event) error {
	s.calls++
	if !s.failing.Load() {
		return nil
	}
	return errors.New("postgres offline")
}

func TestRedactedEventNeverContainsEvidenceOrCredential(t *testing.T) {
	sink := &memorySink{}
	pipeline := NewPipeline(1, sink, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pipeline.Enqueue(audit.Event{SchemaVersion: "2", TenantID: "tenant-a", Decision: "redact", Matches: []audit.Match{{Evidence: "secret-value"}}, Auditor: &audit.ModelResult{Evidence: "agw.super-secret"}})
	pipeline.Close()
	sink.mu.Lock()
	event := sink.events[0]
	sink.mu.Unlock()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "secret-value") || strings.Contains(string(payload), "agw.") || event.Metadata["evidence_redacted"] != "true" {
		t.Fatalf("redacted event leaked material: %s", payload)
	}
}

func (s *memorySink) StoreEvents(_ context.Context, events []audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}
func TestPipelineWritesV2Metadata(t *testing.T) {
	sink := &memorySink{}
	m := observability.NewMetrics()
	pipeline := NewPipeline(1, sink, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	pipeline.Enqueue(audit.Event{SchemaVersion: "2", EventID: "00000000-0000-0000-0000-000000000001", Direction: audit.DirectionAdmin, Metadata: map[string]string{"operation": "publish"}})
	pipeline.Close()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 || sink.events[0].Metadata["operation"] != "publish" {
		t.Fatal("event not stored")
	}
	if m.Render() == "" {
		t.Fatal("missing metrics")
	}
}
func TestPipelineReportsFailureUntilPersistenceSucceeds(t *testing.T) {
	sink := &failingSink{}
	sink.failing.Store(true)
	pipeline := NewPipeline(1, sink, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !pipeline.Enqueue(audit.Event{EventID: "00000000-0000-0000-0000-000000000001"}) {
		t.Fatal("first event should enter queue")
	}
	time.Sleep(50 * time.Millisecond)
	if pipeline.Ready() || pipeline.Status().LastError == "" {
		t.Fatalf("status=%+v", pipeline.Status())
	}
	if pipeline.Enqueue(audit.Event{EventID: "00000000-0000-0000-0000-000000000002"}) {
		t.Fatal("full durable queue should reject second event")
	}
	sink.failing.Store(false)
	time.Sleep(1100 * time.Millisecond)
	pipeline.Close()
	if !pipeline.Ready() {
		t.Fatalf("recovered status=%+v", pipeline.Status())
	}
}

type fakeSource struct {
	mu        sync.Mutex
	claimed   []storage.OutboxRecord
	retried   []string
	published []string
	pending   int64
	poison    int64
}

func (s *fakeSource) ClaimOutbox(context.Context, int, time.Duration) ([]storage.OutboxRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.claimed
	s.claimed = nil
	return records, nil
}
func (s *fakeSource) RetryOutbox(_ context.Context, eventID string, _ int, _ error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retried = append(s.retried, eventID)
	return nil
}
func (s *fakeSource) MarkOutboxPublished(_ context.Context, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.published = append(s.published, eventID)
	return nil
}
func (s *fakeSource) OutboxPending(context.Context) (int64, error)  { return s.pending, nil }
func (s *fakeSource) OutboxPoison(context.Context, int) (int64, error) { return s.poison, nil }

type fakePublisher struct {
	fail   bool
	events []audit.Event
}

func (p *fakePublisher) Publish(_ context.Context, event audit.Event) error {
	if p.fail {
		return errors.New("kafka offline")
	}
	p.events = append(p.events, event)
	return nil
}
func (p *fakePublisher) Close() error { return nil }

func newTestDispatcher(t *testing.T, source Source, publisher Publisher) (*Dispatcher, *observability.Metrics) {
	t.Helper()
	metrics := observability.NewMetrics()
	dispatcher := NewDispatcher(source, publisher, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics)
	if dispatcher == nil {
		t.Fatal("dispatcher should not be nil")
	}
	return dispatcher, metrics
}

func TestDispatcherRetriesUndecodablePayloadWithoutPublishing(t *testing.T) {
	source := &fakeSource{claimed: []storage.OutboxRecord{{EventID: "00000000-0000-0000-0000-00000000000a", TenantID: "tenant-a", Payload: []byte("{not-json"), Attempts: 1}}}
	publisher := &fakePublisher{}
	dispatcher, metrics := newTestDispatcher(t, source, publisher)
	dispatcher.dispatch(context.Background())
	if len(publisher.events) != 0 {
		t.Fatal("undecodable payload must not be published")
	}
	if len(source.published) != 0 {
		t.Fatalf("undecodable payload was marked published: %v", source.published)
	}
	if len(source.retried) != 1 || source.retried[0] != "00000000-0000-0000-0000-00000000000a" {
		t.Fatalf("undecodable payload must re-enter retry: %v", source.retried)
	}
	if !strings.Contains(metrics.Render(), "audit_outbox_poison") {
		t.Fatal("poison gauge missing from metrics")
	}
}

func TestDispatcherMarksPublishedOnlyAfterDelivery(t *testing.T) {
	payload, err := json.Marshal(audit.Event{SchemaVersion: "2", EventID: "00000000-0000-0000-0000-00000000000b", TenantID: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeSource{claimed: []storage.OutboxRecord{{EventID: "00000000-0000-0000-0000-00000000000b", TenantID: "tenant-a", Payload: payload, Attempts: 1}}}
	publisher := &fakePublisher{}
	dispatcher, _ := newTestDispatcher(t, source, publisher)
	dispatcher.dispatch(context.Background())
	if len(source.published) != 1 || source.published[0] != "00000000-0000-0000-0000-00000000000b" {
		t.Fatalf("delivered event must be marked published: %v", source.published)
	}
	if len(source.retried) != 0 {
		t.Fatalf("delivered event must not be retried: %v", source.retried)
	}
}

func TestDispatcherRetriesWhenPublishFails(t *testing.T) {
	payload, err := json.Marshal(audit.Event{SchemaVersion: "2", EventID: "00000000-0000-0000-0000-00000000000c", TenantID: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeSource{claimed: []storage.OutboxRecord{{EventID: "00000000-0000-0000-0000-00000000000c", TenantID: "tenant-a", Payload: payload, Attempts: 1}}}
	publisher := &fakePublisher{fail: true}
	dispatcher, _ := newTestDispatcher(t, source, publisher)
	dispatcher.dispatch(context.Background())
	if len(source.published) != 0 {
		t.Fatalf("failed delivery must not be marked published: %v", source.published)
	}
	if len(source.retried) != 1 || source.retried[0] != "00000000-0000-0000-0000-00000000000c" {
		t.Fatalf("failed delivery must re-enter retry: %v", source.retried)
	}
}
