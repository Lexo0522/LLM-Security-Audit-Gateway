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
