package clickhouse

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/google/uuid"
)

func TestSchemaRetainsAndDeduplicatesEvents(t *testing.T) {
	for _, expected := range []string{"ReplacingMergeTree", "PARTITION BY toYYYYMM(event_time)", "ORDER BY (tenant_id, event_time, event_id)", "TTL toDateTime(event_time) + INTERVAL 180 DAY DELETE"} {
		if !strings.Contains(schemaDDL, expected) {
			t.Fatalf("schema missing %q", expected)
		}
	}
}
func TestValidateEventRequiresSupportedV2Event(t *testing.T) {
	event := audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now(), RequestID: "request-a", TenantID: "tenant-a", Direction: audit.DirectionRequest, Path: "/v1/chat/completions", Decision: "allow", RuleVersion: "rules-v1"}
	if err := ValidateEvent(event); err != nil {
		t.Fatal(err)
	}
	event.SchemaVersion = "1"
	if !errors.Is(ValidateEvent(event), ErrInvalidEvent) {
		t.Fatalf("unexpected error: %v", ValidateEvent(event))
	}
	event.SchemaVersion = "2"
	event.BodyBytes = -1
	if !errors.Is(ValidateEvent(event), ErrInvalidEvent) {
		t.Fatalf("negative size error: %v", ValidateEvent(event))
	}
	event.BodyBytes = 0
	event.Decision = "unbounded-cardinality-value"
	if !errors.Is(ValidateEvent(event), ErrInvalidEvent) {
		t.Fatalf("decision error: %v", ValidateEvent(event))
	}
}
func TestFilterValidationAndCursor(t *testing.T) {
	from := time.Now().UTC().Add(-time.Hour)
	eventID := uuid.NewString()
	encoded := encodeCursor(cursor{Time: from, EventID: eventID})
	filter, err := normalizeFilter(EventFilter{From: from, To: from.Add(time.Hour), Limit: 10, Direction: "request", Decision: "allow", Model: "gpt-test", RuleID: "rule-a", Cursor: encoded})
	if err != nil || filter.Limit != 10 {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	if _, err := normalizeFilter(EventFilter{From: from, To: from.Add(32 * 24 * time.Hour)}); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("range error=%v", err)
	}
	if _, err := normalizeFilter(EventFilter{From: from, To: from.Add(time.Hour), Decision: "drop"}); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("decision error=%v", err)
	}
	condition, args, err := where(filter)
	if err != nil || !strings.Contains(condition, "model = ?") || !strings.Contains(condition, "JSONExtractString") || len(args) != 9 {
		t.Fatalf("condition=%q args=%v err=%v", condition, args, err)
	}
}
