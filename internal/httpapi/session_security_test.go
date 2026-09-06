package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func TestLoginGuardLocksAfterMaxFailures(t *testing.T) {
	now := time.Unix(1700000000, 0)
	guard := newLoginGuard(3, time.Minute)
	guard.now = func() time.Time { return now }

	if guard.blocked("admin") {
		t.Fatal("a fresh account must not be locked")
	}
	guard.fail("admin")
	guard.fail("admin")
	if guard.blocked("admin") {
		t.Fatal("below the failure threshold the account must stay usable")
	}
	guard.fail("admin")
	if !guard.blocked("admin") {
		t.Fatal("exhausting the failure budget must lock the account")
	}
	now = now.Add(time.Minute + time.Second)
	if guard.blocked("admin") {
		t.Fatal("the lockout must expire with its window")
	}

	// Usernames are matched case-insensitively and a successful login clears
	// the failure history.
	guard.fail("Admin")
	guard.fail("ADMIN")
	guard.success("admin")
	if guard.blocked("admin") {
		t.Fatal("a successful login must clear prior failures")
	}
}

func TestAdminCSRFTrustedOrigins(t *testing.T) {
	app := fiber.New()
	(&Admin{TrustedOrigins: []string{"https://admin.example.com"}}).Register(app)

	post := func(origin string, headers map[string]string) int {
		request := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{}`))
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}

	// A trusted origin passes CSRF and reaches the handler, which fails later
	// on the missing database (503) rather than at the CSRF wall (403).
	if code := post("https://admin.example.com", nil); code == http.StatusForbidden {
		t.Fatal("a configured trusted origin must pass the CSRF check")
	}
	if code := post("https://admin.example.com.evil.test", nil); code != http.StatusForbidden {
		t.Fatalf("a suffix lookalike origin must be rejected, got %d", code)
	}
	if code := post("http://admin.example.com", nil); code != http.StatusForbidden {
		t.Fatalf("a scheme change must be rejected, got %d", code)
	}
	// Forwarded headers can no longer forge acceptance of another origin.
	if code := post("http://evil.test", map[string]string{"X-Forwarded-Host": "admin.example.com", "X-Forwarded-Proto": "https"}); code != http.StatusForbidden {
		t.Fatalf("forged forwarded headers must not admit an untrusted origin, got %d", code)
	}
}

func TestAdminCookieSecureModes(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		origins  []string
		fwdProto string
		want     bool
	}{
		{"auto stays insecure on plain http", "auto", nil, "", false},
		{"auto trusts a forwarded https exchange", "auto", nil, "https", true},
		{"auto trusts https origins", "auto", []string{"https://admin.example.com"}, "", true},
		{"always secures", "always", nil, "", true},
		{"never never secures", "never", nil, "https", false},
	}
	for _, tc := range cases {
		admin := &Admin{CookieSecureMode: tc.mode, TrustedOrigins: tc.origins}
		app := fiber.New()
		got := false
		app.Get("/probe", func(c *fiber.Ctx) error { got = admin.cookieSecure(c); return nil })
		request := httptest.NewRequest(http.MethodGet, "/probe", nil)
		if tc.fwdProto != "" {
			request.Header.Set("X-Forwarded-Proto", tc.fwdProto)
		}
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if got != tc.want {
			t.Errorf("%s: cookieSecure=%v, want %v", tc.name, got, tc.want)
		}
	}
}
