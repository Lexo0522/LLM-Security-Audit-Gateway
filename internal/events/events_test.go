package events

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/observability"
)

type memorySink struct {
	mu     sync.Mutex
	events []audit.Event
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
