package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
)

// countingUpstream is a mock upstream that counts every request it receives.
type countingUpstream struct {
	server *httptest.Server
	hits   atomic.Int64
	auth   atomic.Value // last Authorization header value
}

func newCountingUpstream(handler func(w http.ResponseWriter, r *http.Request, hits int64)) *countingUpstream {
	upstream := &countingUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits := upstream.hits.Add(1)
		upstream.auth.Store(r.Header.Get("Authorization"))
		if handler != nil {
			handler(w, r, hits)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	return upstream
}

func newBoundaryHandler(t *testing.T, cfg config.Config, keyID, baseURL, serverAPIKey string, enabled bool) (*Handler, *fiber.App) {
	t.Helper()
	registry, err := rule.NewRegistry(nil, []rule.Definition{{ID: "a", Pattern: "needle", Weight: 85}})
	if err != nil {
		t.Fatal(err)
	}
	h := NewBound(cfg, registry, policy.NewResolver(nil), testAuthenticator{identity: auth.Identity{TenantID: "tenant-a", APIKeyID: keyID, UpstreamID: baseURL}}, ratelimit.MemoryLimiter{}, audit.NoopAuditor{}, nil)
	h.SetUpstreamResolver(testUpstreamResolver{upstreams: map[string]storage.UpstreamSecret{
		keyID: {Upstream: storage.Upstream{BaseURL: baseURL, Enabled: enabled}, APIKey: serverAPIKey},
	}})
	key, _ := internalcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	h.SetEncryptionKey(key)
	app := fiber.New()
	h.Register(app)
	return h, app
}

func doProxy(t *testing.T, app *fiber.App, path, query, body string, header func(*http.Request)) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer client-key")
	if header != nil {
		header(req)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestRequestsCannotSteerAwayFromTheBoundUpstream(t *testing.T) {
	target := newCountingUpstream(nil)
	defer target.server.Close()
	other := newCountingUpstream(nil)
	defer other.server.Close()

	_, app := newBoundaryHandler(t, config.Config{UpstreamAllowPrivateNetworks: true, MaxBodyBytes: 1024, MaxResponseBytes: 1024}, "key-1", target.server.URL, "", true)

	// Steering attempts via header, query, body, and path traversal all still
	// land on the upstream the key is bound to.
	attempts := []struct {
		name              string
		path, query, body string
		header            func(*http.Request)
	}{
		{"header", "/v1/chat/completions", "", `{"model":"m"}`, func(r *http.Request) { r.Header.Set("X-Upstream", other.server.URL) }},
		{"query", "/v1/chat/completions", "?upstream=" + other.server.URL, `{"model":"m"}`, nil},
		{"body", "/v1/chat/completions", "", `{"model":"m","upstream":"` + other.server.URL + `"}`, nil},
		{"path traversal", "/v1/../v2/secret", "", `{"model":"m"}`, nil},
		{"host header", "/v1/chat/completions", "", `{"model":"m"}`, func(r *http.Request) { r.Header.Set("X-Forwarded-Host", other.server.URL) }},
	}
	for _, attempt := range attempts {
		resp := doProxy(t, app, attempt.path, attempt.query, attempt.body, attempt.header)
		// Path traversal is refused at the /v1 boundary instead of served;
		// every other steering attempt is simply ignored.
		if attempt.name == "path traversal" {
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("%s: traversal must not be served", attempt.name)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status=%d", attempt.name, resp.StatusCode)
		}
	}
	// The traversal attempt is refused before any dial, so the bound upstream
	// only ever sees the four legitimate-shaped requests.
	if got := target.hits.Load(); got != int64(len(attempts)-1) {
		t.Fatalf("bound upstream hits=%d, want %d", got, len(attempts)-1)
	}
	if got := other.hits.Load(); got != 0 {
		t.Fatalf("another upstream was reached: hits=%d", got)
	}
}

func TestUpstreamRedirectStaysInBoundaryAndKeepsServerKey(t *testing.T) {
	other := newCountingUpstream(func(w http.ResponseWriter, _ *http.Request, _ int64) {
		_, _ = w.Write([]byte(`{"escaped":true}`))
	})
	defer other.server.Close()
	target := newCountingUpstream(func(w http.ResponseWriter, r *http.Request, _ int64) {
		switch r.URL.Path {
		case "/v1/redirect":
			http.Redirect(w, r, "/v1/final", http.StatusFound)
		case "/v1/elsewhere":
			http.Redirect(w, r, other.server.URL+"/v1/escape", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})
	defer target.server.Close()

	_, app := newBoundaryHandler(t, config.Config{UpstreamAllowPrivateNetworks: true, MaxBodyBytes: 1024, MaxResponseBytes: 1024}, "key-1", target.server.URL, "server-secret-key-0001", true)

	// Same-host redirect: the server key follows, the client key never does.
	resp := doProxy(t, app, "/v1/redirect", "", `{"model":"m"}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-host redirect status=%d", resp.StatusCode)
	}
	if auth, _ := target.auth.Load().(string); auth != "Bearer server-secret-key-0001" {
		t.Fatalf("upstream saw Authorization=%q", auth)
	}

	// Cross-host redirect: refused before any connection is made.
	resp = doProxy(t, app, "/v1/elsewhere", "", `{"model":"m"}`, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("cross-host redirect status=%d, want 502", resp.StatusCode)
	}
	if got := other.hits.Load(); got != 0 {
		t.Fatalf("the redirect target was contacted: hits=%d", got)
	}
}

func TestUpstreamSecurityHeadersDoNotReachClients(t *testing.T) {
	target := newCountingUpstream(func(w http.ResponseWriter, _ *http.Request, _ int64) {
		w.Header().Set("Set-Cookie", "session=pwned; HttpOnly")
		w.Header().Set("X-Internal-Auth", "internal-secret")
		w.Header().Set("Access-Control-Allow-Origin", "https://evil.test")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	defer target.server.Close()

	_, app := newBoundaryHandler(t, config.Config{UpstreamAllowPrivateNetworks: true, MaxBodyBytes: 1024, MaxResponseBytes: 1024}, "key-1", target.server.URL, "", true)
	resp := doProxy(t, app, "/v1/chat/completions", "", `{"model":"m"}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	for _, header := range []string{"Set-Cookie", "X-Internal-Auth", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
		if values := resp.Header.Values(header); len(values) != 0 {
			t.Fatalf("%s leaked to the client: %v", header, values)
		}
	}
}

func TestDisabledOrUnreachableUpstreamsFailStably(t *testing.T) {
	idle := newCountingUpstream(nil)
	defer idle.server.Close()
	timeoutServer := newCountingUpstream(func(w http.ResponseWriter, _ *http.Request, _ int64) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	defer timeoutServer.server.Close()
	oversized := newCountingUpstream(func(w http.ResponseWriter, _ *http.Request, _ int64) {
		_, _ = w.Write([]byte(strings.Repeat("x", 64)))
	})
	defer oversized.server.Close()

	cases := []struct {
		name             string
		baseURL          string
		enabled          bool
		requestTimeoutMS int
		maxResponseBytes int
	}{
		{"disabled upstream", idle.server.URL, false, 1000, 1024},
		{"connection refused", "http://127.0.0.1:1", true, 1000, 1024},
		{"response header timeout", timeoutServer.server.URL, true, 30, 1024},
		{"oversized response", oversized.server.URL, true, 1000, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, app := newBoundaryHandler(t, config.Config{UpstreamAllowPrivateNetworks: true, MaxBodyBytes: 1024, MaxResponseBytes: tc.maxResponseBytes, RequestTimeoutMS: tc.requestTimeoutMS}, "key-1", tc.baseURL, "", tc.enabled)
			before := idle.hits.Load()
			resp := doProxy(t, app, "/v1/chat/completions", "", `{"model":"m"}`, nil)
			if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout {
				t.Fatalf("status=%d, want a stable 502/503/504", resp.StatusCode)
			}
			raw := readAll(t, resp)
			if !strings.Contains(raw, "upstream") {
				t.Fatalf("error body must stay generic: %q", raw)
			}
			if tc.name == "disabled upstream" && idle.hits.Load() != before {
				t.Fatal("a disabled upstream must not be contacted")
			}
		})
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
