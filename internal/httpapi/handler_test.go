package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
)

func TestRequiresTenant(t *testing.T) {
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "a", Pattern: "needle", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	New(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, registry, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 400 {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestMetricsEndpointUsesPrometheusText(t *testing.T) {
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "a", Pattern: "needle", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	metrics.Inc("audit_events_enqueued_total", nil)
	app := fiber.New()
	New(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, registry, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil, metrics).Register(app)
	response, err := app.Test(httptest.NewRequest("GET", "/metrics", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || response.Header.Get("Content-Type") == "" {
		t.Fatalf("response=%d type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}
