package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/health"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
)

func TestReadyzUsesComponentReport(t *testing.T) {
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "rule", Pattern: "safe"}})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	handler := New(config.Config{}, registry, policy.NewResolver(nil), nil, ratelimit.MemoryLimiter{}, nil, nil)
	readiness := health.New(time.Hour, time.Second, nil)
	readiness.Add("postgres", true, func(context.Context) (map[string]any, error) { return map[string]any{"identity": "ok"}, nil })
	readiness.Add("rules", true, func(context.Context) (map[string]any, error) {
		return map[string]any{"source": "managed", "version": "version-1"}, nil
	})
	readiness.Add("redis", false, func(context.Context) (map[string]any, error) {
		return map[string]any{"degraded": true}, context.Canceled
	})
	readiness.ProbeNow(t.Context())
	handler.SetReadiness(readiness)
	handler.Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	readiness.SetRequiredFailure("postgres", "offline", map[string]any{"identity": "unavailable"})
	response, err = app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.StatusCode)
	}
}
