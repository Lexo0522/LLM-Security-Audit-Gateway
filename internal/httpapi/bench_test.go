package httpapi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
)

// The benchmarks measure the full public request path: fiber routing, API key
// authentication, rate limiting, body decode, normalization, rule scan, policy
// resolution, event enqueue, and the upstream exchange through the pipe. They
// run through fiber's test connection, so absolute numbers are only comparable
// between runs on the same machine - the point is a regression baseline.

const benchRequestBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello world, please summarize this"}]}`

func benchApp(b *testing.B, cfg config.Config) *fiber.App {
	b.Helper()
	registry, err := rule.NewRegistry(nil, []rule.Definition{
		{ID: "keyword", Pattern: "needle", Weight: 40},
		{ID: "regex", Pattern: `sk-[a-z0-9]+`, Regex: true, Weight: 60},
	})
	if err != nil {
		b.Fatal(err)
	}
	app := fiber.New()
	NewBound(cfg, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "bench-tenant", APIKeyID: "bench-key", UpstreamID: testUpstreamURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil).Register(app)
	return app
}

func benchRequest(b *testing.B, app *fiber.App, body string, stream bool) {
	b.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer bench-key")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	response, err := app.Test(req, 10000)
	if err != nil {
		b.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		b.Fatalf("status=%d", response.StatusCode)
	}
}

func BenchmarkProxyJSON(b *testing.B) {
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hello! how can I help you today?"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":12,"total_tokens":21}}`))
	}))
	defer upstream.Close()
	app := benchApp(b, config.Config{MaxBodyBytes: 1 << 20, MaxResponseBytes: 1 << 20, AuditEnabled: true})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRequest(b, app, benchRequestBody, false)
	}
}

func BenchmarkProxyJSONAuditDisabled(b *testing.B) {
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	app := benchApp(b, config.Config{MaxBodyBytes: 1 << 20, MaxResponseBytes: 1 << 20, AuditEnabled: false})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRequest(b, app, benchRequestBody, false)
	}
}

func BenchmarkProxySSE(b *testing.B) {
	const events = 50
	upstream := newTestUpstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < events; i++ {
			_, _ = fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"token %s \"}}]}\n\n", strconv.Itoa(i))
			flusher.Flush()
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()
	app := benchApp(b, config.Config{MaxBodyBytes: 1 << 20, MaxResponseBytes: 1 << 20, AuditEnabled: true})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRequest(b, app, `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hello"}]}`, true)
	}
}
