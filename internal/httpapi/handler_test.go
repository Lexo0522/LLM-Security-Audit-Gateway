package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
)

type testAuthenticator struct {
	identity auth.Identity
	err      error
}

func (a testAuthenticator) Authenticate(context.Context, string) (auth.Identity, error) {
	return a.identity, a.err
}

func testHandler(t *testing.T, cfg config.Config, identity auth.Authenticator) *Handler {
	t.Helper()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "a", Pattern: "needle", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, registry, policy.NewResolver(nil), identity, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil)
}

func TestPublicRequestUsesAuthenticatedTenant(t *testing.T) {
	var gotAuthorization, gotTenant string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization, gotTenant = r.Header.Get("Authorization"), r.Header.Get("X-Tenant-ID")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	app := fiber.New()
	h := testHandler(t, config.Config{UpstreamURL: upstream.URL, MaxBodyBytes: 1024, MaxResponseBytes: 1024}, testAuthenticator{identity: auth.Identity{TenantID: "trusted-tenant", APIKeyID: "key-1"}})
	h.Register(app)
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
	req.Header.Set("Authorization", "Bearer client-key")
	req.Header.Set("X-Tenant-ID", "forged-tenant")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if gotAuthorization != "" || gotTenant != "" {
		t.Fatalf("caller identity leaked upstream: auth=%q tenant=%q", gotAuthorization, gotTenant)
	}
}

func TestPublicRequestRejectsInvalidRevokedAndUnavailableIdentity(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()
	for name, authResult := range map[string]testAuthenticator{
		"invalid":     {err: auth.ErrInvalidKey},
		"revoked":     {err: auth.ErrInvalidKey},
		"unavailable": {err: auth.ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			called = false
			app := fiber.New()
			testHandler(t, config.Config{UpstreamURL: upstream.URL, MaxBodyBytes: 1024, MaxResponseBytes: 1024}, authResult).Register(app)
			response, err := app.Test(httptest.NewRequest("POST", "/v1/chat/completions", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			expected := http.StatusUnauthorized
			if name == "unavailable" {
				expected = http.StatusServiceUnavailable
			}
			if response.StatusCode != expected || called {
				t.Fatalf("status=%d upstream_called=%v", response.StatusCode, called)
			}
		})
	}
}

func TestRedactDoesNotRewriteProxiedBody(t *testing.T) {
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 85, Action: "redact"}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := policy.NewResolver(policySource{policies: []policy.Policy{
		{ID: "tenant", Scope: "tenant:tenant-a", RoutePath: "/v1/chat/completions", Direction: "request", MonitorAt: 30, InterventionAt: 80, InterventionAction: policy.Redact, AuditorFailureMode: "fail_closed"},
		{ID: "tenant-response", Scope: "tenant:tenant-a", RoutePath: "/v1/chat/completions", Direction: "response", MonitorAt: 30, InterventionAt: 80, InterventionAction: policy.Redact, AuditorFailureMode: "fail_open"},
	}})
	if err := resolver.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	defer upstream.Close()
	app := fiber.New()
	New(config.Config{UpstreamURL: upstream.URL, MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, resolver, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "key-a"}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	response, err := app.Test(httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"prompt":"needle"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != `{"prompt":"needle"}` {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}

type failingAuditor struct{}

func (failingAuditor) Audit(context.Context, audit.Input) (audit.ModelResult, error) {
	return audit.ModelResult{}, errors.New("offline")
}
func (failingAuditor) Health(context.Context) error { return nil }
func (failingAuditor) Name() string                 { return "failing" }

func TestPolicyActionsAndAuditorFailureMode(t *testing.T) {
	t.Run("fail closed auditor blocks monitored request", func(t *testing.T) {
		registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "monitor", Pattern: "monitor-me", Weight: 40, Action: "monitor"}})
		if err != nil {
			t.Fatal(err)
		}
		resolver := policy.NewResolver(policySource{policies: []policy.Policy{{ID: "closed", Scope: "tenant:tenant-a", RoutePath: "/v1/chat/completions", Direction: "request", MonitorAt: 30, InterventionAt: 80, InterventionAction: policy.Block, AuditorFailureMode: "fail_closed"}}})
		if err := resolver.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		app := fiber.New()
		New(config.Config{UpstreamURL: "http://127.0.0.1:1", MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true, AuditorURL: "http://auditor"}, registry, resolver, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a"}}, ratelimit.MemoryLimiter{}, failingAuditor{}, nil).Register(app)
		response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"prompt":"monitor-me"}`)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("status=%d", response.StatusCode)
		}
	})
	t.Run("non-streaming response is blocked before status is forwarded", func(t *testing.T) {
		registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "response", Pattern: "response-secret", Weight: 85, Action: "block"}})
		if err != nil {
			t.Fatal(err)
		}
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("response-secret"))
		}))
		defer upstream.Close()
		app := fiber.New()
		New(config.Config{UpstreamURL: upstream.URL, MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a"}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
		response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("status=%d", response.StatusCode)
		}
	})
}

func TestMetricsEndpointUsesPrometheusText(t *testing.T) {
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "a", Pattern: "needle", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	metrics.Inc("audit_events_enqueued_total", nil)
	app := fiber.New()
	New(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, registry, policy.NewResolver(nil), testAuthenticator{}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil, metrics).Register(app)
	response, err := app.Test(httptest.NewRequest("GET", "/metrics", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || response.Header.Get("Content-Type") == "" {
		t.Fatalf("response=%d type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}

type policySource struct{ policies []policy.Policy }

func (s policySource) ListPolicies(context.Context) ([]policy.Policy, error) { return s.policies, nil }
