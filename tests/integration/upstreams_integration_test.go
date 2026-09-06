//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/auth"
	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
	"github.com/example/ai-audit-gateway/internal/httpapi"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func newStorageRepo(t *testing.T) (*storage.Repository, *internalcrypto.Key) {
	t.Helper()
	ctx := context.Background()
	repo, err := storage.Open(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	if err := repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := internalcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "integration-encryption.key"))
	if err != nil {
		t.Fatal(err)
	}
	return repo, key
}

func TestUpstreamLifecycleWithRealPostgres(t *testing.T) {
	ctx := context.Background()
	repo, key := newStorageRepo(t)
	suffix := uuid.NewString()[:8]
	nameA := "it-upstream-a-" + suffix
	nameB := "it-upstream-b-" + suffix

	created, err := repo.CreateUpstream(ctx, nameA, "http://upstream-a", "it-secret-a-0001", true, key)
	if err != nil {
		t.Fatal(err)
	}
	if !created.HasAPIKey || !created.Enabled {
		t.Fatalf("created=%+v", created)
	}
	if serialized, marshalErr := json.Marshal(created); marshalErr != nil || strings.Contains(string(serialized), "it-secret-a-0001") {
		t.Fatalf("creation model leaks the api key: %s", serialized)
	}

	// Duplicate names are refused.
	if _, err = repo.CreateUpstream(ctx, nameA, "http://elsewhere", "k", true, key); !errors.Is(err, storage.ErrDuplicateUpstreamName) {
		t.Fatalf("duplicate name err=%v", err)
	}
	// Non-HTTP schemes are refused.
	var validation *storage.ValidationError
	if _, err = repo.CreateUpstream(ctx, "it-bad-"+suffix, "ftp://upstream", "", true, key); !errors.As(err, &validation) {
		t.Fatalf("invalid URL must be a validation error, got %v", err)
	}

	// An update without an api key keeps the stored one.
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "", true, key); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetUpstream(ctx, created.ID, key)
	if err != nil || stored.APIKey != "it-secret-a-0001" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	// An update with an api key rotates it.
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "it-rotated-a-0002", true, key); err != nil {
		t.Fatal(err)
	}
	if stored, err = repo.GetUpstream(ctx, created.ID, key); err != nil || stored.APIKey != "it-rotated-a-0002" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}

	// Listing never carries secrets, and the total reflects the full set.
	list, total, err := repo.ListUpstreams(ctx, 0, 0)
	if err != nil || total < 2 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	serialized, marshalErr := json.Marshal(list)
	if marshalErr != nil || strings.Contains(string(serialized), "it-rotated-a-0002") || strings.Contains(string(serialized), "it-secret-a-0001") {
		t.Fatalf("list leaks api keys: %s", serialized)
	}

	createdB, err := repo.CreateUpstream(ctx, nameB, "http://upstream-b", "it-secret-b-0001", true, key)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	recordA, plaintextA, err := manager.CreateForUpstream(ctx, "it-tenant-a", created.ID, "key-a")
	if err != nil || !strings.HasPrefix(plaintextA, "agw.") {
		t.Fatalf("record=%+v key=%q err=%v", recordA, plaintextA, err)
	}
	recordB, _, err := manager.CreateForUpstream(ctx, "it-tenant-b", createdB.ID, "key-b")
	if err != nil {
		t.Fatal(err)
	}

	// Each key resolves to its own upstream with its own decrypted api key.
	routeA, err := repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key)
	if err != nil || routeA.ID != created.ID || routeA.APIKey != "it-rotated-a-0002" {
		t.Fatalf("routeA=%+v err=%v", routeA, err)
	}
	routeB, err := repo.GetUpstreamForGatewayKey(ctx, recordB.ID, key)
	if err != nil || routeB.ID != createdB.ID || routeB.APIKey != "it-secret-b-0001" {
		t.Fatalf("routeB=%+v err=%v", routeB, err)
	}

	// Deletion is blocked while keys reference the upstream.
	if err = repo.DeleteUpstream(ctx, created.ID); !errors.Is(err, storage.ErrUpstreamInUse) {
		t.Fatalf("delete with bound keys err=%v", err)
	}

	// Disabling the upstream cuts off its keys immediately.
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "", false, key); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key); err == nil {
		t.Fatal("a disabled upstream must not resolve for its keys")
	}
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "", true, key); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key); err != nil {
		t.Fatalf("re-enabled upstream must resolve again: %v", err)
	}

	// A revoked key stops resolving.
	if _, found, err := manager.Revoke(ctx, recordB.ID); err != nil || !found {
		t.Fatalf("revoke found=%v err=%v", found, err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordB.ID, key); err == nil {
		t.Fatal("a revoked key must not resolve its upstream")
	}
}

func TestAdminSessionLifecycleWithRealPostgres(t *testing.T) {
	ctx := context.Background()
	repo, key := newStorageRepo(t)
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	admin := &httpapi.Admin{Repo: repo, EncryptionKey: key, Keys: manager, CookieSecureMode: "never"}
	admin.Register(app)

	var bodyOf func(*http.Response) string
	call := func(method, path, body string, cookies []*http.Cookie, set func(*http.Request)) *http.Response {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		if set != nil {
			set(req)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	bodyOf = func(resp *http.Response) string {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	sameOrigin := func(req *http.Request) {
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("X-Forwarded-Host", "localhost:3000")
		req.Header.Set("X-Forwarded-Proto", "http")
	}
	decodeUser := func(resp *http.Response) storage.AdminUser {
		var user storage.AdminUser
		if err := json.Unmarshal([]byte(bodyOf(resp)), &user); err != nil {
			t.Fatalf("decode user: %v", err)
		}
		return user
	}

	username := "it-admin-" + uuid.NewString()[:8]
	password := "it-password-one-000"
	newPassword := "it-password-two-000"

	// First-run setup. Skip when this database already has an administrator
	// (a previous run against a persistent volume). Browsers always attach an
	// Origin header to writes, so every write below does too.
	status := call(http.MethodGet, "/admin/v1/setup/status", "", nil, nil)
	var state struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.Unmarshal([]byte(bodyOf(status)), &state); err != nil {
		t.Fatal(err)
	}
	if state.Initialized {
		t.Skip("database already has an administrator; recreate the integration volume for a clean run")
	}
	setup := call(http.MethodPost, "/admin/v1/setup", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin)
	if setup.StatusCode != http.StatusCreated {
		t.Fatalf("setup status=%d body=%s", setup.StatusCode, bodyOf(setup))
	}

	// Login sets the session and CSRF cookies; Secure stays off for "never".
	login := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, bodyOf(login))
	}
	sessionCookies := login.Cookies()
	for _, cookie := range sessionCookies {
		if cookie.Name == "gateway_admin_session" && cookie.Secure {
			t.Fatal("session cookie must not be Secure under the never mode")
		}
	}
	me := call(http.MethodGet, "/admin/v1/auth/me", "", sessionCookies, nil)
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d", me.StatusCode)
	}
	if user := decodeUser(me); user.Username != username {
		t.Fatalf("me returned %q", user.Username)
	}

	// A session-cookie write goes through the same-origin CSRF path and hits
	// the real database.
	upstreamPayload := fmt.Sprintf(`{"name":"it-admin-upstream-%s","base_url":"http://upstream-a","api_key":"it-admin-key-1"}`, uuid.NewString()[:8])
	created := call(http.MethodPost, "/admin/v1/upstreams", upstreamPayload, sessionCookies, sameOrigin)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("upstream create status=%d body=%s", created.StatusCode, bodyOf(created))
	}
	var createdUpstream struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(bodyOf(created)), &createdUpstream); err != nil || createdUpstream.ID == "" {
		t.Fatalf("created=%s err=%v", bodyOf(created), err)
	}
	if hasSecrets, err := repo.HasUpstreamSecrets(ctx); err != nil || !hasSecrets {
		t.Fatalf("hasSecrets=%v err=%v", hasSecrets, err)
	}
	// The same session with a hostile origin is rejected.
	hostile := call(http.MethodPost, "/admin/v1/upstreams", upstreamPayload, sessionCookies, func(req *http.Request) {
		req.Header.Set("Origin", "http://evil.test")
	})
	if hostile.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin write status=%d, want 403", hostile.StatusCode)
	}

	// Batch revocation is idempotent and reports unknown ids.
	keyCreate := call(http.MethodPost, "/admin/v1/api-keys",
		fmt.Sprintf(`{"tenant_id":"it-tenant-batch","upstream_id":%q,"display_name":"batch"}`, createdUpstream.ID),
		sessionCookies, sameOrigin)
	if keyCreate.StatusCode != http.StatusCreated {
		t.Fatalf("key create status=%d body=%s", keyCreate.StatusCode, bodyOf(keyCreate))
	}
	var createdKey struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(bodyOf(keyCreate)), &createdKey); err != nil || createdKey.ID == "" {
		t.Fatalf("key=%s err=%v", bodyOf(keyCreate), err)
	}
	batchBody := fmt.Sprintf(`{"ids":[%q,"00000000-0000-0000-0000-000000000000"]}`, createdKey.ID)
	batch := call(http.MethodPost, "/admin/v1/api-keys/revoke", batchBody, sessionCookies, sameOrigin)
	if batch.StatusCode != http.StatusOK {
		t.Fatalf("batch revoke status=%d body=%s", batch.StatusCode, bodyOf(batch))
	}
	var batchResult struct {
		Revoked int      `json:"revoked"`
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal([]byte(bodyOf(batch)), &batchResult); err != nil {
		t.Fatal(err)
	}
	if batchResult.Revoked != 1 || len(batchResult.Missing) != 1 {
		t.Fatalf("batch result=%+v", batchResult)
	}
	retry := call(http.MethodPost, "/admin/v1/api-keys/revoke", batchBody, sessionCookies, sameOrigin)
	var retryResult struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal([]byte(bodyOf(retry)), &retryResult); err != nil || retryResult.Revoked != 1 {
		t.Fatalf("retry must return a stable count, result=%s err=%v", bodyOf(retry), err)
	}

	// A second login coexists until the password rotation revokes it.
	login2 := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin)
	if login2.StatusCode != http.StatusOK {
		t.Fatalf("second login status=%d", login2.StatusCode)
	}

	// Rotating the password keeps the current session and kills the other.
	change := call(http.MethodPost, "/admin/v1/auth/password",
		fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, password, newPassword),
		sessionCookies, sameOrigin)
	if change.StatusCode != http.StatusNoContent {
		t.Fatalf("password change status=%d body=%s", change.StatusCode, bodyOf(change))
	}
	if me2 := call(http.MethodGet, "/admin/v1/auth/me", "", login2.Cookies(), nil); me2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other session must be revoked, got status=%d", me2.StatusCode)
	}
	if me1 := call(http.MethodGet, "/admin/v1/auth/me", "", sessionCookies, nil); me1.StatusCode != http.StatusOK {
		t.Fatalf("current session must survive the rotation, got status=%d", me1.StatusCode)
	}

	// Logout-all revokes the remaining session too.
	logoutAll := call(http.MethodPost, "/admin/v1/auth/sessions/logout-all", "", sessionCookies, sameOrigin)
	if logoutAll.StatusCode != http.StatusNoContent {
		t.Fatalf("logout-all status=%d", logoutAll.StatusCode)
	}
	if me3 := call(http.MethodGet, "/admin/v1/auth/me", "", sessionCookies, nil); me3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session must be revoked after logout-all, got status=%d", me3.StatusCode)
	}

	// The old password no longer works; the new one does.
	if bad := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin); bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password must fail, got status=%d", bad.StatusCode)
	}
	fresh := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, newPassword), nil, sameOrigin)
	if fresh.StatusCode != http.StatusOK {
		t.Fatalf("new password must work, got status=%d body=%s", fresh.StatusCode, bodyOf(fresh))
	}
	user := decodeUser(fresh)

	// Expired sessions are unusable and the sweeper removes them.
	deadHash := []byte("integration-dead-session-hash")
	if _, err := repo.CreateAdminSession(ctx, user.ID, deadHash, time.Now().Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.GetAdminSession(ctx, deadHash); err == nil {
		t.Fatal("an expired session must not authenticate")
	}
	deleted, err := repo.CleanupExpiredAdminSessions(ctx, 24*time.Hour, 100)
	if err != nil || deleted < 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
}
