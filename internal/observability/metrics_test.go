package observability

import (
	"strings"
	"testing"
)

func TestMetricsRenderDeterministically(t *testing.T) {
	m := NewMetrics()
	m.Inc("audit_events_enqueued_total", nil)
	m.Observe("audit_http_duration_seconds", .01, map[string]string{"endpoint": "/v1/chat/completions"})
	text := m.Render()
	for _, want := range []string{"# TYPE audit_events_enqueued_total counter", "audit_events_enqueued_total 1", "# TYPE audit_http_duration_seconds histogram", `endpoint="/v1/chat/completions"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
}
