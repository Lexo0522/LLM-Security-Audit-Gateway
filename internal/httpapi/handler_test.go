package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/example/ai-audit-gateway/internal/stream"
	"github.com/gofiber/fiber/v2"
)

type testAuthenticator struct {
	identity auth.Identity
	err      error
}

func (a testAuthenticator) Authenticate(context.Context, string) (auth.Identity, error) {
	return a.identity, a.err
}

var testUpstreamURL string

func newTestUpstream(handler http.Handler) *httptest.Server {
	server := httptest.NewServer(handler)
	testUpstreamURL = server.URL
	return server
}

type testUpstreamResolver struct {
	upstreams map[string]storage.UpstreamSecret
	err       error
}

func (r testUpstreamResolver) GetUpstreamForGatewayKey(_ context.Context, keyID string, _ *internalcrypto.Key) (storage.UpstreamSecret, error) {

	if r.err != nil {
		return storage.UpstreamSecret{}, r.err
	}
	value, ok := r.upstreams[keyID]
	if !ok {
		return storage.UpstreamSecret{}, storage.ErrUpstreamDisabled
	}
	return value, nil
}

func bindTestUpstream(h *Handler, keyID, baseURL string) *Handler {
	h.SetUpstreamResolver(testUpstreamResolver{upstreams: map[string]storage.UpstreamSecret{
		keyID: {Upstream: storage.Upstream{BaseURL: baseURL, Enabled: true}},
	}})
	key, _ := internalcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	h.SetEncryptionKey(key)
	return h
}

func NewBound(cfg config.Config, rules *rule.Registry, policies *policy.Resolver, identities auth.Authenticator, limiter ratelimit.Limiter, auditor audit.Auditor, pipeline *events.Pipeline, metrics ...*observability.Metrics) *Handler {
	h := New(cfg, rules, policies, identities, limiter, auditor, pipeline, metrics...)
	if value, ok := identities.(testAuthenticator); ok && value.identity.UpstreamID != "" {
		bindTestUpstream(h, value.identity.APIKeyID, value.identity.UpstreamID)
	}
	return h
}

func testHandler(t *testing.T, cfg config.Config, identity auth.Authenticator) *Handler {
	t.Helper()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "a", Pattern: "needle", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	return NewBound(cfg, registry, policy.NewResolver(nil), identity, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil)
}

func TestPublicRequestUsesAuthenticatedTenant(t *testing.T) {
	var gotAuthorization, gotTenant string
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization, gotTenant = r.Header.Get("Authorization"), r.Header.Get("X-Tenant-ID")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	app := fiber.New()
	h := testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, testAuthenticator{identity: auth.Identity{TenantID: "trusted-tenant", APIKeyID: "key-1", UpstreamID: testUpstreamURL}})
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
	upstream := newTestUpstream(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()
	for name, authResult := range map[string]testAuthenticator{
		"invalid":     {err: auth.ErrInvalidKey},
		"revoked":     {err: auth.ErrInvalidKey},
		"unavailable": {err: auth.ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			called = false
			app := fiber.New()
			testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, authResult).Register(app)
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
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	defer upstream.Close()
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, resolver, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "key-a", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
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
		NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true, AuditorURL: "http://auditor"}, registry, resolver, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, failingAuditor{}, nil).Register(app)
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
		upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("response-secret"))
		}))
		defer upstream.Close()
		app := fiber.New()
		NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
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

func TestSSEAllowsSemanticContentUnchanged(t *testing.T) {
	raw := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"safe\"}}]}\n\ndata: [DONE]\n\n"
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}).Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" || string(body) != raw {
		t.Fatalf("status=%d type=%q body=%q", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
}

func TestSSECrossEventBlockTerminatesAndCancelsUpstream(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	var once sync.Once
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer once.Do(func() { close(upstreamCanceled) })
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"nee\"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"dle\"}}]}\n\n")
		flusher.Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()

	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 85, Action: "block"}})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true, SSEAuditWindowBytes: 16}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "key-a", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
	req.Header.Set("X-Request-ID", "request-stream-block")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	want := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"nee\"}}]}\n\n" + string(stream.SecurityTermination("stream_policy_blocked", "request-stream-block"))
	if response.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("status=%d body=%q want=%q", response.StatusCode, body, want)
	}
	if strings.Contains(string(body), "dle") || strings.Contains(string(body), "needle") || strings.Contains(string(body), "[DONE]") {
		t.Fatalf("blocked SSE event leaked: %q", body)
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(time.Second):
		t.Fatal("upstream request context was not canceled")
	}
}

func TestSSERedactKeepsOriginalEvent(t *testing.T) {
	raw := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"needle\"}}]}\n\ndata: [DONE]\n\n"
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer upstream.Close()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 40, Action: "redact"}})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != raw || strings.Contains(string(body), "gateway.security_terminated") {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
}

func TestSSEEventLimitTerminatesWithoutForwardingOversizedEvent(t *testing.T) {
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+strings.Repeat("x", 100)+"\n\n")
	}))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true, SSEMaxEventBytes: 64}, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}).Register(app)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
	req.Header.Set("X-Request-ID", "request-event-limit")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	want := string(stream.SecurityTermination("sse_event_too_large", "request-event-limit"))
	if response.StatusCode != http.StatusOK || string(body) != want || strings.Contains(string(body), "xxxxx") {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
}

func TestSSEAuditEventsIncludeChannelAndRedactEvidence(t *testing.T) {
	raw := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"needle\"}}]}\n\n"
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer upstream.Close()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 40, Action: "redact"}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &handlerMemorySink{}
	pipeline := events.NewPipeline(4, sink, nil)
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, pipeline).Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test"}`)))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	pipeline.Close()
	if len(sink.events) != 2 {
		t.Fatalf("events=%#v", sink.events)
	}
	responseEvent := sink.events[1]
	if responseEvent.Direction != audit.DirectionResponse || responseEvent.Metadata["sse"] != "true" || responseEvent.Metadata["sse_channel"] != "chat:choice:0:content" || responseEvent.Metadata["evidence_redacted"] != "true" {
		t.Fatalf("response event=%#v", responseEvent)
	}
	if len(responseEvent.Matches) != 0 || responseEvent.ContentSHA256 == "" || responseEvent.BodyBytes != len("needle") {
		t.Fatalf("redacted response event=%#v", responseEvent)
	}
}

func TestResponsesSSECrossEventBlockTerminatesAndCancelsUpstream(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	var once sync.Once
	first := "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg-1\",\"output_index\":0,\"content_index\":0,\"delta\":\"nee\"}\n\n"
	second := "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg-1\",\"output_index\":0,\"content_index\":0,\"delta\":\"dle\"}\n\n"
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer once.Do(func() { close(upstreamCanceled) })
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, first)
		flusher.Flush()
		_, _ = io.WriteString(w, second)
		flusher.Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 85, Action: "block"}})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true, SSEAuditWindowBytes: 16}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "key-a", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test","stream":true}`))
	req.Header.Set("X-Request-ID", "request-responses-block")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	want := first + string(stream.SecurityTermination("stream_policy_blocked", "request-responses-block"))
	if response.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("status=%d body=%q want=%q", response.StatusCode, body, want)
	}
	if strings.Contains(string(body), second) || strings.Contains(string(body), "needle") {
		t.Fatalf("blocked Responses event leaked: %q", body)
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(time.Second):
		t.Fatal("upstream Responses request context was not canceled")
	}
}

func TestResponsesSSERedactPreservesRawEventAndAuditMetadata(t *testing.T) {
	raw := "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call-1\",\"output_index\":0,\"delta\":\"needle\"}\n\n"
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer upstream.Close()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 40, Action: "redact"}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &handlerMemorySink{}
	pipeline := events.NewPipeline(4, sink, nil)
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, pipeline).Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test","stream":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	pipeline.Close()
	if response.StatusCode != http.StatusOK || string(body) != raw {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if len(sink.events) != 2 {
		t.Fatalf("events=%#v", sink.events)
	}
	responseEvent := sink.events[1]
	if responseEvent.Path != "/v1/responses" || responseEvent.Metadata["sse"] != "true" || responseEvent.Metadata["sse_channel"] != "responses:response.function_call_arguments.delta:item:call-1:output:0" || responseEvent.Metadata["evidence_redacted"] != "true" {
		t.Fatalf("response event=%#v", responseEvent)
	}
	if len(responseEvent.Matches) != 0 || responseEvent.BodyBytes != len("needle") {
		t.Fatalf("redacted response event=%#v", responseEvent)
	}
}

func TestResponsesRouteSpecificPolicyApplies(t *testing.T) {
	resolver := policy.NewResolver(policySource{policies: []policy.Policy{{ID: "responses-block", Scope: "tenant:tenant-a", RoutePath: "/v1/responses", Direction: "response", MonitorAt: 30, InterventionAt: 80, InterventionAction: policy.Block, AuditorFailureMode: "fail_open"}}})
	if err := resolver.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg\",\"output_index\":0,\"content_index\":0,\"delta\":\"policy-risk\"}\n\n")
	}))
	defer upstream.Close()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "policy-risk", Pattern: "policy-risk", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, registry, resolver, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test","stream":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "gateway.security_terminated") || strings.Contains(string(body), "policy-risk") {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
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
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, registry, policy.NewResolver(nil), testAuthenticator{}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil, metrics).Register(app)
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

type handlerMemorySink struct{ events []audit.Event }

func (s *handlerMemorySink) StoreEvents(_ context.Context, records []audit.Event) error {
	s.events = append(s.events, records...)
	return nil
}

func gzipBody(t *testing.T, payload string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := io.WriteString(writer, payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// serveOnEphemeralPort exercises the real fasthttp server path. fiber's
// app.Test helper decompresses gzip request bodies (httputil.DumpRequest), so
// wire-level encoding behavior must be tested against a live listener.
func serveOnEphemeralPort(t *testing.T, app *fiber.App) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(listener) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	return "http://" + listener.Addr().String()
}

func postGzip(t *testing.T, base, encoding string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer client-key")
	req.Header.Set("Content-Encoding", encoding)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response
}

func TestGzipRequestBodyIsAuditedAndBlocked(t *testing.T) {
	called := false
	upstream := newTestUpstream(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}).Register(app)
	base := serveOnEphemeralPort(t, app)
	response := postGzip(t, base, "gzip", gzipBody(t, `{"messages":[{"role":"user","content":"needle hidden in gzip"}]}`))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if called {
		t.Fatal("blocked gzip request must not reach upstream")
	}
}

func TestGzipRequestBodyForwardedDecoded(t *testing.T) {
	plaintext := `{"messages":[{"role":"user","content":"hello"}]}`
	var gotEncoding string
	var gotBody []byte
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}).Register(app)
	base := serveOnEphemeralPort(t, app)
	response := postGzip(t, base, "gzip", gzipBody(t, plaintext))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if gotEncoding != "" || string(gotBody) != plaintext {
		t.Fatalf("upstream must receive decoded plaintext: encoding=%q body=%q", gotEncoding, gotBody)
	}
}

func TestBrotliRequestBodyIsAuditedAndBlocked(t *testing.T) {
	called := false
	upstream := newTestUpstream(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}).Register(app)
	base := serveOnEphemeralPort(t, app)
	var buffer bytes.Buffer
	writer := brotli.NewWriter(&buffer)
	_, _ = io.WriteString(writer, `{"messages":[{"role":"user","content":"needle in brotli"}]}`)
	_ = writer.Close()
	response := postGzip(t, base, "br", buffer.Bytes())
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if called {
		t.Fatal("blocked brotli request must not reach upstream")
	}
}

func TestUnsupportedAndMalformedRequestEncodingRejected(t *testing.T) {
	upstream := newTestUpstream(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: true}, testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}).Register(app)
	base := serveOnEphemeralPort(t, app)
	for name, request := range map[string]struct {
		body     []byte
		encoding string
		status   int
	}{
		"zstd":      {body: []byte("raw"), encoding: "zstd", status: http.StatusUnsupportedMediaType},
		"malformed": {body: []byte("not gzip"), encoding: "gzip", status: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			response := postGzip(t, base, request.encoding, request.body)
			if response.StatusCode != request.status {
				t.Fatalf("status=%d want=%d", response.StatusCode, request.status)
			}
		})
	}
}

func TestAuditDisabledProxiesWithoutAuditing(t *testing.T) {
	needleRule := []rule.Definition{{ID: "needle", Pattern: "needle", Weight: 85, Action: "block"}}
	registry, err := rule.NewRegistry(nil, needleRule)
	if err != nil {
		t.Fatal(err)
	}
	raw := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"needle in stream\"}}]}\n\ndata: [DONE]\n\n"
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer upstream.Close()
	sink := &handlerMemorySink{}
	pipeline := events.NewPipeline(4, sink, nil)
	app := fiber.New()
	NewBound(config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024, AuditEnabled: false}, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: "test-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, pipeline).Register(app)
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"prompt":"needle"}`)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	pipeline.Close()
	if response.StatusCode != http.StatusOK || string(body) != raw {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if len(sink.events) != 0 {
		t.Fatalf("disabled audit must not persist events: %#v", sink.events)
	}
}

func TestPublicAuthFailuresAreThrottled(t *testing.T) {
	upstream := newTestUpstream(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	app := fiber.New()
	testHandler(t, config.Config{MaxBodyBytes: 1024, MaxResponseBytes: 1024}, testAuthenticator{err: auth.ErrInvalidKey}).Register(app)
	var lastStatus int
	for i := 0; i < 31; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
		request.Header.Set("Authorization", "Bearer wrong-key")
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		lastStatus = response.StatusCode
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429 after repeated invalid keys", lastStatus)
	}
}
