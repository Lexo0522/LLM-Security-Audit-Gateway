//go:build smoke

// Package smoke drives the full Compose stack exactly as a user would: the
// management surface through http://localhost:3000 (the SPA nginx proxying to
// the admin listener) and proxy traffic through http://localhost:8080.
// tests/smoke/run-smoke.ps1 builds the images, boots a dedicated compose
// project with fresh volumes, runs this test, and tears everything down.
package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	adminUsername = "smoke-admin"
	adminPassword = "smoke-admin-password-1"
	// No "sk-" prefix: the demo bootstrap rules block responses matching
	// sk-[a-z0-9], and the mock upstreams echo the Authorization header back.
	upstreamKeyA      = "upstream-a-key-1234567890"
	upstreamKeyB      = "upstream-b-key-0987654321"
	upstreamABaseURL  = "http://upstream-a"
	upstreamBBaseURL  = "http://upstream-b"
	sessionCookieName = "gateway_admin_session"
)

var (
	webBase     = envDefault("SMOKE_WEB_URL", "http://localhost:3000")
	gatewayBase = envDefault("SMOKE_GATEWAY_URL", "http://localhost:8080")
)

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

type stackClient struct {
	t    *testing.T
	http *http.Client
}

func newStackClient(t *testing.T) *stackClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &stackClient{t: t, http: &http.Client{Timeout: 30 * time.Second, Jar: jar}}
}

// adminCall talks to the management surface through the web service. Write
// requests carry a browser-like same-site Origin header, which is how the SPA
// satisfies the admin CSRF middleware.
func (s *stackClient) adminCall(method, path string, body []byte, origin string) (int, string) {
	s.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, webBase+path, reader)
	if err != nil {
		s.t.Fatalf("build request %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp.StatusCode, string(raw)
}

func (s *stackClient) proxyCall(key string, body []byte) (int, string) {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodPost, gatewayBase+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		s.t.Fatalf("build proxy request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := s.http.Do(req)
	if err != nil {
		s.t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("proxy request: read body: %v", err)
	}
	return resp.StatusCode, string(raw)
}

func (s *stackClient) statusOf(rawURL string) int {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (s *stackClient) sessionCookie(t *testing.T) string {
	t.Helper()
	base, err := url.Parse(webBase)
	if err != nil {
		t.Fatalf("parse web base: %v", err)
	}
	for _, cookie := range s.http.Jar.Cookies(base) {
		if cookie.Name == sessionCookieName {
			return cookie.Value
		}
	}
	return ""
}

func (s *stackClient) collectAuditPages(t *testing.T) []string {
	t.Helper()
	var pages []string
	cursor := ""
	for range 20 {
		path := "/admin/v1/audit/events?page_size=200"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		status, body := s.adminCall(http.MethodGet, path, nil, "")
		if status != http.StatusOK {
			return nil
		}
		pages = append(pages, body)
		var page auditPage
		if err := json.Unmarshal([]byte(body), &page); err != nil {
			t.Fatalf("decode audit page: %v", err)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return pages
}

type setupStatus struct {
	Initialized   bool `json:"initialized"`
	SetupRequired bool `json:"setup_required"`
}

type adminUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type upstream struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	Enabled   bool   `json:"enabled"`
	HasAPIKey bool   `json:"has_api_key"`
}

type keyRecord struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	UpstreamID string `json:"upstream_id"`
	Prefix     string `json:"prefix"`
	Key        string `json:"key,omitempty"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

type auditPage struct {
	Events     []json.RawMessage `json:"events"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// secretSet maps a human label to secret material so leak failures can name
// what leaked without ever printing the secret itself.
type secretSet map[string]string

func assertNoSecrets(t *testing.T, label, body string, secrets secretSet) {
	t.Helper()
	for name, value := range secrets {
		if value != "" && strings.Contains(body, value) {
			t.Fatalf("secret leak: %s found in %s", name, label)
		}
	}
}

func wantStatus(t *testing.T, got, want int, label, body string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got status %d, want %d; body: %.500s", label, got, want, body)
	}
}

func wantCode(t *testing.T, body, want string, label string) {
	t.Helper()
	var errResp apiError
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("%s: decode error body: %v; body: %.500s", label, err, body)
	}
	if errResp.Error.Code != want {
		t.Fatalf("%s: got error code %q, want %q; body: %.500s", label, errResp.Error.Code, want, body)
	}
}

func decodeInto(t *testing.T, body string, target any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), target); err != nil {
		t.Fatalf("decode response: %v; body: %.500s", err, body)
	}
}

func chatBody(content string) []byte {
	payload := map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return raw
}

func waitFor(t *testing.T, timeout time.Duration, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if check() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Second)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	if root := strings.TrimSpace(os.Getenv("SMOKE_REPO_ROOT")); root != "" {
		return root
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	return root
}

func restartGateway(t *testing.T, project string) {
	t.Helper()
	cmd := exec.Command("docker", "compose", "-p", project,
		"-f", "deploy/docker-compose.yml", "-f", "deploy/docker-compose.smoke.yml",
		"restart", "gateway")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restart gateway container: %v\n%s", err, out)
	}
}

// TestComposeSmoke walks the acceptance path for the whole stack: first-run
// admin setup, upstream and key provisioning, per-key routing isolation,
// disable/revoke enforcement, secret decryption across a gateway restart, and
// the absence of secret material on every management surface.
func TestComposeSmoke(t *testing.T) {
	c := newStackClient(t)
	origin := webBase

	secrets := secretSet{
		"admin password":     adminPassword,
		"upstream a api key": upstreamKeyA,
		"upstream b api key": upstreamKeyB,
	}

	var (
		upstreamA, upstreamB upstream
		keyA, keyB           keyRecord
		sessionToken         string
	)

	t.Run("web serves the SPA", func(t *testing.T) {
		status, body := c.adminCall(http.MethodGet, "/", nil, "")
		wantStatus(t, status, http.StatusOK, "GET /", body)
		if !strings.Contains(body, `id="app"`) {
			t.Fatalf("web index does not contain the SPA mount point: %.200s", body)
		}
	})

	t.Run("first admin setup", func(t *testing.T) {
		status, body := c.adminCall(http.MethodGet, "/admin/v1/setup/status", nil, "")
		wantStatus(t, status, http.StatusOK, "setup status", body)
		var state setupStatus
		decodeInto(t, body, &state)
		if state.Initialized {
			t.Skip("stack already initialized; recreate the smoke project for a clean first-run pass")
		}
		// A cross-site origin must be rejected before any setup work happens.
		status, body = c.adminCall(http.MethodPost, "/admin/v1/setup", []byte(`{}`), "http://evil.example")
		wantStatus(t, status, http.StatusForbidden, "cross-origin setup", body)

		payload := fmt.Sprintf(`{"username":%q,"password":%q}`, adminUsername, adminPassword)
		status, body = c.adminCall(http.MethodPost, "/admin/v1/setup", []byte(payload), origin)
		wantStatus(t, status, http.StatusCreated, "setup", body)
		assertNoSecrets(t, "setup response", body, secrets)
	})

	t.Run("login and session", func(t *testing.T) {
		badPayload := fmt.Sprintf(`{"username":%q,"password":"definitely-wrong-1"}`, adminUsername)
		status, body := c.adminCall(http.MethodPost, "/admin/v1/auth/login", []byte(badPayload), origin)
		wantStatus(t, status, http.StatusUnauthorized, "login with wrong password", body)
		assertNoSecrets(t, "failed login response", body, secrets)

		payload := fmt.Sprintf(`{"username":%q,"password":%q}`, adminUsername, adminPassword)
		status, body = c.adminCall(http.MethodPost, "/admin/v1/auth/login", []byte(payload), origin)
		wantStatus(t, status, http.StatusOK, "login", body)
		var user adminUser
		decodeInto(t, body, &user)
		if user.Username != adminUsername {
			t.Fatalf("login returned user %q", user.Username)
		}
		sessionToken = c.sessionCookie(t)
		if sessionToken == "" {
			t.Fatal("login did not set the session cookie")
		}
		secrets["admin session token"] = sessionToken

		status, body = c.adminCall(http.MethodGet, "/admin/v1/auth/me", nil, "")
		wantStatus(t, status, http.StatusOK, "me", body)
		assertNoSecrets(t, "me response", body, secrets)
	})

	t.Run("create upstreams", func(t *testing.T) {
		for _, tc := range []struct {
			name, baseURL, apiKey string
			out                   *upstream
		}{
			{"upstream-a", upstreamABaseURL, upstreamKeyA, &upstreamA},
			{"upstream-b", upstreamBBaseURL, upstreamKeyB, &upstreamB},
		} {
			payload := fmt.Sprintf(`{"name":%q,"base_url":%q,"api_key":%q,"enabled":true}`, tc.name, tc.baseURL, tc.apiKey)
			status, body := c.adminCall(http.MethodPost, "/admin/v1/upstreams", []byte(payload), origin)
			wantStatus(t, status, http.StatusCreated, "create "+tc.name, body)
			decodeInto(t, body, tc.out)
			if !tc.out.Enabled || !tc.out.HasAPIKey {
				t.Fatalf("created upstream %s: enabled=%v has_api_key=%v", tc.name, tc.out.Enabled, tc.out.HasAPIKey)
			}
			// The creation response stores the key encrypted; the plaintext
			// must never come back.
			assertNoSecrets(t, "create upstream response", body, secrets)
		}

		status, body := c.adminCall(http.MethodGet, "/admin/v1/upstreams", nil, "")
		wantStatus(t, status, http.StatusOK, "list upstreams", body)
		assertNoSecrets(t, "upstream list", body, secrets)
		var list []upstream
		decodeInto(t, body, &list)
		if len(list) != 2 {
			t.Fatalf("upstream list has %d entries, want 2", len(list))
		}
	})

	t.Run("ssrf guard refuses metadata targets", func(t *testing.T) {
		// 169.254.169.254 is refused in every mode, including this stack's
		// development mode that otherwise permits private networks.
		payload := `{"name":"metadata-target","base_url":"http://169.254.169.254/latest/meta-data/","api_key":"irrelevant"}`
		status, body := c.adminCall(http.MethodPost, "/admin/v1/upstreams", []byte(payload), origin)
		wantStatus(t, status, http.StatusBadRequest, "create metadata upstream", body)
		assertNoSecrets(t, "metadata rejection body", body, secrets)
	})

	t.Run("create gateway keys", func(t *testing.T) {
		for _, tc := range []struct {
			tenant, displayName string
			target              *upstream
			out                 *keyRecord
			label               string
		}{
			{"tenant-a", "key for upstream a", &upstreamA, &keyA, "gateway key a"},
			{"tenant-b", "key for upstream b", &upstreamB, &keyB, "gateway key b"},
		} {
			payload := fmt.Sprintf(`{"tenant_id":%q,"upstream_id":%q,"display_name":%q}`, tc.tenant, tc.target.ID, tc.displayName)
			status, body := c.adminCall(http.MethodPost, "/admin/v1/api-keys", []byte(payload), origin)
			wantStatus(t, status, http.StatusCreated, "create "+tc.label, body)
			decodeInto(t, body, tc.out)
			if !strings.HasPrefix(tc.out.Key, "agw.") {
				t.Fatalf("%s: response does not carry the one-time key", tc.label)
			}
			if tc.out.UpstreamID != tc.target.ID {
				t.Fatalf("%s: bound to %q, want %q", tc.label, tc.out.UpstreamID, tc.target.ID)
			}
			secrets[tc.label] = tc.out.Key

			// The key list must never contain the plaintext secret.
			status, body = c.adminCall(http.MethodGet, "/admin/v1/api-keys", nil, "")
			wantStatus(t, status, http.StatusOK, "list keys", body)
			assertNoSecrets(t, "key list", body, secrets)
		}
	})

	t.Run("keys route to their own upstreams", func(t *testing.T) {
		status, raw := c.proxyCall(keyA.Key, chatBody("hello via key a"))
		wantStatus(t, status, http.StatusOK, "proxy with key a", raw)
		for _, want := range []string{`"upstream":"a"`, `"auth":"Bearer ` + upstreamKeyA + `"`} {
			if !strings.Contains(raw, want) {
				t.Fatalf("key a response missing %s; body: %.500s", want, raw)
			}
		}
		if strings.Contains(raw, `"upstream":"b"`) {
			t.Fatalf("key a reached upstream b; body: %.500s", raw)
		}

		status, raw = c.proxyCall(keyB.Key, chatBody("hello via key b"))
		wantStatus(t, status, http.StatusOK, "proxy with key b", raw)
		for _, want := range []string{`"upstream":"b"`, `"auth":"Bearer ` + upstreamKeyB + `"`} {
			if !strings.Contains(raw, want) {
				t.Fatalf("key b response missing %s; body: %.500s", want, raw)
			}
		}
		if strings.Contains(raw, `"upstream":"a"`) {
			t.Fatalf("key b reached upstream a; body: %.500s", raw)
		}
	})

	t.Run("disabling an upstream cuts off its keys", func(t *testing.T) {
		// Always restore upstream-a so a mid-subtest failure does not leave it
		// disabled for the restart step below.
		t.Cleanup(func() {
			payload := fmt.Sprintf(`{"name":%q,"base_url":%q,"enabled":true}`, upstreamA.Name, upstreamA.BaseURL)
			req, err := http.NewRequest(http.MethodPut, webBase+"/admin/v1/upstreams/"+upstreamA.ID, strings.NewReader(payload))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", origin)
				if resp, err := c.http.Do(req); err == nil {
					_ = resp.Body.Close()
				}
			}
		})

		payload := fmt.Sprintf(`{"name":%q,"base_url":%q,"enabled":false}`, upstreamA.Name, upstreamA.BaseURL)
		status, body := c.adminCall(http.MethodPut, "/admin/v1/upstreams/"+upstreamA.ID, []byte(payload), origin)
		wantStatus(t, status, http.StatusOK, "disable upstream-a", body)

		status, raw := c.proxyCall(keyA.Key, chatBody("while upstream a is disabled"))
		wantStatus(t, status, http.StatusServiceUnavailable, "proxy with key a while disabled", raw)
		wantCode(t, raw, "upstream_unavailable", "disabled upstream error")
		assertNoSecrets(t, "disabled upstream error body", raw, secrets)

		// The other upstream keeps serving.
		status, raw = c.proxyCall(keyB.Key, chatBody("while upstream a is disabled"))
		wantStatus(t, status, http.StatusOK, "proxy with key b while a disabled", raw)

		// Re-enabling restores the route and still decrypts the stored key.
		payload = fmt.Sprintf(`{"name":%q,"base_url":%q,"enabled":true}`, upstreamA.Name, upstreamA.BaseURL)
		status, body = c.adminCall(http.MethodPut, "/admin/v1/upstreams/"+upstreamA.ID, []byte(payload), origin)
		wantStatus(t, status, http.StatusOK, "re-enable upstream-a", body)
		status, raw = c.proxyCall(keyA.Key, chatBody("after re-enabling upstream a"))
		wantStatus(t, status, http.StatusOK, "proxy with key a after re-enable", raw)
		if !strings.Contains(raw, `"auth":"Bearer `+upstreamKeyA+`"`) {
			t.Fatalf("re-enabled upstream did not receive the stored api key; body: %.500s", raw)
		}
	})

	t.Run("revoked key returns 401", func(t *testing.T) {
		status, body := c.adminCall(http.MethodPost, "/admin/v1/api-keys/"+keyB.ID+"/revoke", nil, origin)
		wantStatus(t, status, http.StatusOK, "revoke key b", body)

		status, raw := c.proxyCall(keyB.Key, chatBody("after revocation"))
		wantStatus(t, status, http.StatusUnauthorized, "proxy with revoked key b", raw)
		wantCode(t, raw, "invalid_api_key", "revoked key error")
		assertNoSecrets(t, "revoked key error body", raw, secrets)
	})

	t.Run("gateway restart keeps decryption and revocations", func(t *testing.T) {
		project := strings.TrimSpace(os.Getenv("SMOKE_COMPOSE_PROJECT"))
		if project == "" {
			t.Log("SMOKE_COMPOSE_PROJECT is not set; skipping the container restart step")
			return
		}
		restartGateway(t, project)
		waitFor(t, 2*time.Minute, "gateway /healthz after restart", func() bool {
			return c.statusOf(gatewayBase+"/healthz") == http.StatusOK
		})

		// The stored upstream API key must still decrypt after a cold process.
		status, raw := c.proxyCall(keyA.Key, chatBody("after gateway restart"))
		wantStatus(t, status, http.StatusOK, "proxy with key a after restart", raw)
		if !strings.Contains(raw, `"upstream":"a"`) || !strings.Contains(raw, `"auth":"Bearer `+upstreamKeyA+`"`) {
			t.Fatalf("after restart key a did not reach upstream a with the stored api key; body: %.500s", raw)
		}

		// Revocation is durable too.
		status, raw = c.proxyCall(keyB.Key, chatBody("after gateway restart"))
		wantStatus(t, status, http.StatusUnauthorized, "proxy with revoked key b after restart", raw)
	})

	t.Run("management surfaces and audit trail never contain secrets", func(t *testing.T) {
		for _, path := range []string{"/admin/v1/upstreams", "/admin/v1/api-keys"} {
			status, body := c.adminCall(http.MethodGet, path, nil, "")
			wantStatus(t, status, http.StatusOK, path, body)
			assertNoSecrets(t, path, body, secrets)
		}

		// The audit pipeline (PostgreSQL outbox -> Kafka -> ClickHouse) needs
		// a moment to deliver the events produced above.
		var pages []string
		waitFor(t, 2*time.Minute, "audit events to reach the query API", func() bool {
			pages = c.collectAuditPages(t)
			for _, page := range pages {
				if strings.Contains(page, `"event_id"`) {
					return true
				}
			}
			return false
		})
		for i, page := range pages {
			assertNoSecrets(t, fmt.Sprintf("audit events page %d", i), page, secrets)
		}
	})
}
