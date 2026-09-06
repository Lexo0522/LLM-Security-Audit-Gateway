package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/example/ai-audit-gateway/internal/proxy"

	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	clickstore "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Admin struct {
	Logger        *slog.Logger
	Repo          *storage.Repository
	EncryptionKey *internalcrypto.Key
	Rules         *rule.Registry
	RuleChanged   func(context.Context, string)
	Events        *events.Pipeline
	Keys          *auth.Manager
	Policies      *policy.Resolver
	PolicyChanged func(context.Context)
	Audit         AuditReader
	// UpstreamClient and its TargetPolicy guard every outbound request an
	// administrator-configured upstream can cause, including the test probe.
	UpstreamClient *proxy.Client
	TargetPolicy   *proxy.TargetPolicy
	// Session hardening. Zero values fall back to the historical behavior in
	// Register: 24h sessions, auto Secure cookies, per-account lockout after
	// 5 failures for 15 minutes.
	SessionTTL       time.Duration
	CookieSecureMode string
	TrustedOrigins   []string
	LoginMaxFailures int
	LoginLockout     time.Duration
	logins           *loginGuard
	dummyHash        []byte
	throttle         *authThrottle
}

// fail logs the underlying cause and returns a client-safe response. Only
// storage validation messages are shown; anything else returns a generic
// internal error so database details never reach the caller.
func (a *Admin) fail(operation string, err error) error {
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("admin operation failed", slog.String("operation", operation), slog.Any("error", err))
	var validation *storage.ValidationError
	if errors.As(err, &validation) {
		return fiber.NewError(fiber.StatusBadRequest, validation.Error())
	}
	if errors.Is(err, storage.ErrDuplicateUpstreamName) || errors.Is(err, storage.ErrDuplicateAdminUsername) {
		return fiber.NewError(fiber.StatusConflict, "name already exists")
	}
	if errors.Is(err, storage.ErrUpstreamInUse) {
		return fiber.NewError(fiber.StatusConflict, "upstream has bound gateway keys")
	}
	if storage.IsNotFound(err) {
		return fiber.ErrNotFound
	}
	return fiber.ErrInternalServerError
}

func (a *Admin) Register(app *fiber.App) {
	if a.throttle == nil {
		a.throttle = newAuthThrottle(30, time.Minute)
	}
	if a.logins == nil {
		a.logins = newLoginGuard(a.LoginMaxFailures, a.LoginLockout)
	}
	if a.SessionTTL <= 0 {
		a.SessionTTL = 24 * time.Hour
	}
	if a.CookieSecureMode == "" {
		a.CookieSecureMode = "auto"
	}
	if a.dummyHash == nil {
		// Only consumed to equalize bcrypt timing for unknown usernames.
		a.dummyHash, _ = bcrypt.GenerateFromPassword([]byte("gateway-timing-equalizer"), bcrypt.DefaultCost)
	}
	app.Use(a.csrf)
	app.Get("/admin/v1/setup/status", a.setupStatus)
	app.Post("/admin/v1/setup", a.setup)
	app.Post("/admin/v1/auth/login", a.login)
	app.Post("/admin/v1/auth/logout", a.logout)
	app.Get("/admin/v1/auth/me", a.me)
	app.Use(a.authenticate)
	app.Post("/admin/v1/auth/password", a.changePassword)
	app.Post("/admin/v1/auth/sessions/logout-all", a.logoutAll)
	app.Post("/admin/v1/rule-sets", a.create)
	app.Get("/admin/v1/rule-sets", a.list)
	app.Get("/admin/v1/rule-sets/:version", a.get)
	app.Post("/admin/v1/rule-sets/:version/publish", a.publish)
	app.Post("/admin/v1/rule-sets/:scope/rollback", a.rollback)
	app.Post("/admin/v1/api-keys", a.createKey)
	app.Get("/admin/v1/api-keys", a.listKeys)
	app.Get("/admin/v1/upstreams", a.listUpstreams)
	app.Post("/admin/v1/upstreams", a.createUpstream)
	app.Put("/admin/v1/upstreams/:id", a.updateUpstream)
	app.Delete("/admin/v1/upstreams/:id", a.deleteUpstream)
	app.Post("/admin/v1/upstreams/:id/test", a.testUpstream)
	app.Post("/admin/v1/api-keys/revoke", a.revokeKeysBatch)
	app.Post("/admin/v1/api-keys/:id/revoke", a.revokeKey)
	app.Post("/admin/v1/policies", a.createPolicy)
	app.Get("/admin/v1/policies", a.listPolicies)
	app.Put("/admin/v1/policies/:id", a.updatePolicy)
	app.Delete("/admin/v1/policies/:id", a.deletePolicy)
	app.Get("/admin/v1/audit/events", a.listAuditEvents)
	app.Get("/admin/v1/audit/events/:event_id", a.getAuditEvent)
	app.Get("/admin/v1/audit/summary", a.auditSummary)
}

type AuditReader interface {
	ListEvents(context.Context, clickstore.EventFilter) (clickstore.EventPage, error)
	GetEvent(context.Context, string) (audit.Event, error)
	Summary(context.Context, clickstore.EventFilter, string) (clickstore.Summary, error)
}

const adminSessionCookie = "gateway_admin_session"
const adminCSRFCookie = "gateway_admin_csrf"

var errMissingSessionCookie = errors.New("session cookie is missing")

func (a *Admin) authenticate(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	user, err := a.sessionUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fiber.Map{"message": "authentication required"}})
	}
	c.Locals("admin_user", user)
	return c.Next()
}

// sessionUser resolves the caller from the session cookie. It backs both the
// authenticate middleware and the me endpoint, which calls it directly: a
// terminal handler must not drive fiber's router through c.Next().
func (a *Admin) sessionUser(c *fiber.Ctx) (storage.AdminUser, error) {
	cookie := c.Cookies(adminSessionCookie)
	if cookie == "" {
		return storage.AdminUser{}, errMissingSessionCookie
	}
	_, user, err := a.Repo.GetAdminSession(c.UserContext(), sessionHash(cookie))
	if err != nil {
		return storage.AdminUser{}, err
	}
	return user, nil
}

func (a *Admin) me(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	user, err := a.sessionUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fiber.Map{"message": "authentication required"}})
	}
	return c.JSON(user)
}

func sessionHash(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }

func sameOrigin(c *fiber.Ctx, origin *url.URL) bool {
	if origin == nil || origin.Scheme == "" || origin.Host == "" {
		return false
	}
	host := c.Get("X-Forwarded-Host")
	if host == "" {
		host = c.Get(fiber.HeaderHost)
	}
	scheme := c.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = c.Protocol()
	}
	return strings.EqualFold(origin.Scheme, scheme) && strings.EqualFold(origin.Host, host)
}

func (a *Admin) csrf(c *fiber.Ctx) error {
	if c.Method() == http.MethodGet || c.Method() == http.MethodHead || c.Method() == http.MethodOptions {
		return c.Next()
	}
	origin := c.Get("Origin")
	if origin != "" {
		if a.originAllowed(c, origin) {
			return c.Next()
		}
		return fiber.NewError(fiber.StatusForbidden, "csrf validation failed")
	}
	csrfCookie := c.Cookies(adminCSRFCookie)
	csrfHeader := c.Get("X-CSRF-Token")
	if csrfCookie != "" && csrfHeader != "" && subtle.ConstantTimeCompare([]byte(csrfCookie), []byte(csrfHeader)) == 1 {
		return c.Next()
	}
	return fiber.NewError(fiber.StatusForbidden, "csrf validation failed")
}

// originAllowed decides whether a request Origin may write. With trusted
// origins configured, only exact scheme+host matches pass and forwarded
// headers are ignored — an untrusted proxy can no longer forge acceptance.
// Without configuration, the legacy same-origin check against
// X-Forwarded-Host applies, which is safe only behind a proxy that overwrites
// those headers (the compose web service does).
func (a *Admin) originAllowed(c *fiber.Ctx, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if len(a.TrustedOrigins) > 0 {
		for _, trusted := range a.TrustedOrigins {
			entry, parseErr := url.Parse(strings.TrimSpace(trusted))
			if parseErr != nil {
				continue
			}
			if strings.EqualFold(entry.Scheme, parsed.Scheme) && strings.EqualFold(entry.Host, parsed.Host) {
				return true
			}
		}
		return false
	}
	return sameOrigin(c, parsed)
}

// cookieSecure decides the Secure attribute. "auto" marks the cookie Secure
// whenever https is plausible: direct TLS, a forwarded https header, or an
// https trusted origin. Over-marking only makes the cookie unavailable over
// plain HTTP, while under-marking would leak it, so the safer side wins.
func (a *Admin) cookieSecure(c *fiber.Ctx) bool {
	switch a.CookieSecureMode {
	case "always":
		return true
	case "never":
		return false
	}
	if c.Secure() || strings.EqualFold(c.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	for _, origin := range a.TrustedOrigins {
		if parsed, err := url.Parse(origin); err == nil && strings.EqualFold(parsed.Scheme, "https") {
			return true
		}
	}
	return false
}

func (a *Admin) sessionTTL() time.Duration {
	if a.SessionTTL > 0 {
		return a.SessionTTL
	}
	return 24 * time.Hour
}

// throttled mirrors the proxy handler's rate-limit error shape.
func throttled(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": fiber.Map{"message": "too many attempts; try again later", "type": "rate_limit_error", "code": "rate_limited"}})
}

func (a *Admin) setupStatus(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	count, err := a.Repo.CountAdminUsers(c.UserContext())
	if err != nil {
		return a.fail("setup_status", err)
	}
	return c.JSON(fiber.Map{"initialized": count != 0, "setup_required": count == 0})
}

func (a *Admin) setup(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	count, err := a.Repo.CountAdminUsers(c.UserContext())
	if err != nil {
		return a.fail("setup_status", err)
	}
	if count != 0 {
		return fiber.NewError(fiber.StatusConflict, "admin setup already completed")
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Username == "" || len(input.Password) < 12 {
		return fiber.NewError(fiber.StatusBadRequest, "username and password are required; password must be at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return a.fail("admin_setup_hash", err)
	}
	user, err := a.Repo.CreateAdminUser(c.UserContext(), input.Username, hash)
	if err != nil {
		return a.fail("admin_setup", err)
	}
	return c.Status(http.StatusCreated).JSON(user)
}

func (a *Admin) login(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	if a.throttle.blocked(c.IP()) {
		return throttled(c)
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if a.logins.blocked(input.Username) {
		a.emitOperation(c, "admin_login", "", "throttled", "")
		return throttled(c)
	}
	user, hash, err := a.Repo.GetAdminUser(c.UserContext(), input.Username)
	if err != nil {
		// Unknown username still burns one bcrypt comparison so response
		// timing does not reveal which accounts exist.
		_ = bcrypt.CompareHashAndPassword(a.dummyHash, []byte(input.Password))
		a.loginFailed(c, input.Username)
		return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(input.Password)) != nil {
		a.loginFailed(c, input.Username)
		return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
	}
	a.logins.success(input.Username)
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return a.fail("admin_session_generate", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	csrfRaw := make([]byte, 32)
	if _, err = rand.Read(csrfRaw); err != nil {
		return a.fail("admin_csrf_generate", err)
	}
	csrfToken := base64.RawURLEncoding.EncodeToString(csrfRaw)
	ttl := a.sessionTTL()
	if _, err = a.Repo.CreateAdminSession(c.UserContext(), user.ID, sessionHash(token), time.Now().Add(ttl)); err != nil {
		return a.fail("admin_session_create", err)
	}
	secure := a.cookieSecure(c)
	maxAge := int(ttl / time.Second)
	c.Cookie(&fiber.Cookie{Name: adminSessionCookie, Value: token, HTTPOnly: true, Secure: secure, SameSite: "Lax", Path: "/", MaxAge: maxAge})
	c.Cookie(&fiber.Cookie{Name: adminCSRFCookie, Value: csrfToken, HTTPOnly: false, Secure: secure, SameSite: "Lax", Path: "/", MaxAge: maxAge})
	c.Locals("admin_user", user)
	a.emitOperation(c, "admin_login", "", "success", "")
	return c.JSON(user)
}

// loginFailed feeds both throttles and leaves an audit trace; the response it
// accompanies reveals nothing about which limit fired.
func (a *Admin) loginFailed(c *fiber.Ctx, username string) {
	a.throttle.fail(c.IP())
	a.logins.fail(username)
	a.emitOperation(c, "admin_login", "", "failure", "")
}

func (a *Admin) logout(c *fiber.Ctx) error {
	if token := c.Cookies(adminSessionCookie); token != "" && a.Repo != nil {
		_, user, userErr := a.Repo.GetAdminSession(c.UserContext(), sessionHash(token))
		if err := a.Repo.RevokeAdminSession(c.UserContext(), sessionHash(token)); err != nil {
			return a.fail("admin_logout", err)
		}
		if userErr == nil {
			c.Locals("admin_user", user)
		}
	}
	a.emitOperation(c, "admin_logout", "", "success", "")
	c.ClearCookie(adminSessionCookie)
	c.ClearCookie(adminCSRFCookie)
	return c.SendStatus(http.StatusNoContent)
}

// changePassword rotates the administrator password and revokes every other
// live session so stolen cookies die with the old credential. The current
// session survives so the caller is not logged out mid-flow.
func (a *Admin) changePassword(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	user, ok := c.Locals("admin_user").(storage.AdminUser)
	if !ok {
		return fiber.ErrUnauthorized
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if len(input.NewPassword) < 12 {
		return fiber.NewError(fiber.StatusBadRequest, "new password must be at least 12 characters")
	}
	_, hash, err := a.Repo.GetAdminUser(c.UserContext(), user.Username)
	if err != nil || bcrypt.CompareHashAndPassword(hash, []byte(input.CurrentPassword)) != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "current password is incorrect")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return a.fail("admin_password_hash", err)
	}
	if err = a.Repo.UpdateAdminPassword(c.UserContext(), user.ID, newHash); err != nil {
		return a.fail("admin_password_update", err)
	}
	var kept []byte
	if token := c.Cookies(adminSessionCookie); token != "" {
		kept = sessionHash(token)
	}
	if _, err = a.Repo.RevokeAdminSessions(c.UserContext(), user.ID, kept); err != nil {
		return a.fail("admin_session_revoke", err)
	}
	a.emitOperation(c, "admin_password_change", "", "success", "")
	return c.SendStatus(http.StatusNoContent)
}

// logoutAll revokes every session of the administrator, including the one
// that issued the request.
func (a *Admin) logoutAll(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	user, ok := c.Locals("admin_user").(storage.AdminUser)
	if !ok {
		return fiber.ErrUnauthorized
	}
	if _, err := a.Repo.RevokeAdminSessions(c.UserContext(), user.ID, nil); err != nil {
		return a.fail("admin_session_revoke_all", err)
	}
	a.emitOperation(c, "admin_session_revoke_all", "", "success", "")
	c.ClearCookie(adminSessionCookie)
	c.ClearCookie(adminCSRFCookie)
	return c.SendStatus(http.StatusNoContent)
}

func (a *Admin) create(c *fiber.Ctx) error {
	var input struct {
		Scope string            `json:"scope"`
		Rules []rule.Definition `json:"rules"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	set, err := a.Repo.CreateRuleSet(c.Context(), input.Scope, input.Rules)
	if err != nil {
		return a.fail("rule_set_create", err)
	}
	a.emitOperation(c, "rule_set_create", set.Scope, "success", set.Version)
	return c.Status(201).JSON(set)
}
func (a *Admin) list(c *fiber.Ctx) error {
	sets, err := a.Repo.ListRuleSets(c.Context())
	if err != nil {
		return a.fail("rule_set_list", err)
	}
	return c.JSON(sets)
}
func (a *Admin) get(c *fiber.Ctx) error {
	set, err := a.Repo.GetRuleSet(c.Context(), c.Params("version"))
	if err != nil {
		return fiber.ErrNotFound
	}
	return c.JSON(set)
}
func (a *Admin) publish(c *fiber.Ctx) error {
	set, err := a.Repo.Publish(c.Context(), c.Params("version"))
	if err != nil {
		return a.fail("rule_set_publish", err)
	}
	if a.RuleChanged != nil {
		a.RuleChanged(c.Context(), set.Scope)
	}
	if err = a.Rules.Refresh(c.Context(), set.Scope); err != nil {
		return a.fail("rule_set_publish_refresh", err)
	}
	a.emitOperation(c, "rule_set_publish", set.Scope, "success", set.Version)
	return c.JSON(set)
}
func (a *Admin) rollback(c *fiber.Ctx) error {
	var input struct {
		Version string `json:"version"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	set, err := a.Repo.Rollback(c.Context(), c.Params("scope"), input.Version)
	if err != nil {
		return a.fail("rule_set_rollback", err)
	}
	if a.RuleChanged != nil {
		a.RuleChanged(c.Context(), set.Scope)
	}
	if err = a.Rules.Refresh(c.Context(), set.Scope); err != nil {
		return a.fail("rule_set_rollback_refresh", err)
	}
	a.emitOperation(c, "rule_set_rollback", set.Scope, "success", set.Version)
	return c.JSON(set)
}
func (a *Admin) createKey(c *fiber.Ctx) error {
	if a.Keys == nil {
		return fiber.ErrServiceUnavailable
	}
	var input struct {
		TenantID    string `json:"tenant_id"`
		UpstreamID  string `json:"upstream_id"`
		DisplayName string `json:"display_name"`
	}

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if !auth.ValidTenantID(input.TenantID) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid tenant_id")
	}
	if a.Repo == nil || input.UpstreamID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "upstream_id is required")
	}
	bound, err := a.Repo.GetUpstream(c.UserContext(), input.UpstreamID, a.EncryptionKey)
	if err != nil {
		return a.fail("api_key_upstream_lookup", err)
	}
	if !bound.Enabled {
		return fiber.NewError(fiber.StatusBadRequest, "upstream is disabled")
	}
	record, key, err := a.Keys.CreateForUpstream(c.Context(), input.TenantID, input.UpstreamID, input.DisplayName)
	if err != nil {
		return a.fail("api_key_create", err)
	}
	a.emitOperation(c, "api_key_create", "tenant:"+record.TenantID, "success", record.ID)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": record.ID, "tenant_id": record.TenantID, "upstream_id": record.UpstreamID, "display_name": record.DisplayName, "prefix": record.Prefix, "created_at": record.CreatedAt, "key": key})
}
// pageParams parses ?limit/&offset for list endpoints. limit 0 means "all"
// for internal callers; the API defaults to 50 and never exceeds 200 rows.
func pageParams(c *fiber.Ctx) (int, int) {
	limit, offset := 50, 0
	if raw := c.Query("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 {
			limit = value
		}
	}
	if raw := c.Query("offset"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 {
			offset = value
		}
	}
	if limit > 200 {
		limit = 200
	}
	return limit, offset
}

func (a *Admin) listKeys(c *fiber.Ctx) error {
	if a.Keys == nil {
		return fiber.ErrServiceUnavailable
	}
	limit, offset := pageParams(c)
	keys, total, err := a.Keys.List(c.Context(), c.Query("tenant_id"), limit, offset)
	if err != nil {
		return a.fail("api_key_list", err)
	}
	c.Set("X-Total-Count", strconv.FormatInt(total, 10))
	return c.JSON(keys)
}
func (a *Admin) revokeKey(c *fiber.Ctx) error {
	if a.Keys == nil {
		return fiber.ErrServiceUnavailable
	}
	record, found, err := a.Keys.Revoke(c.Context(), c.Params("id"))
	if err != nil {
		return a.fail("api_key_revoke", err)
	}
	if !found {
		return fiber.ErrNotFound
	}
	a.emitOperation(c, "api_key_revoke", "tenant:"+record.TenantID, "success", record.ID)
	return c.JSON(record)
}

// revokeKeysBatch revokes many gateway keys in one call. "revoked" counts ids
// that exist and are revoked after the call — already-revoked ids stay counted
// on a retried batch, so repeating the request returns the same result.
// Unknown ids are reported as missing instead of failing.
func (a *Admin) revokeKeysBatch(c *fiber.Ctx) error {
	if a.Keys == nil {
		return fiber.ErrServiceUnavailable
	}
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := c.BodyParser(&input); err != nil || len(input.IDs) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "ids is required")
	}
	if len(input.IDs) > 500 {
		return fiber.NewError(fiber.StatusBadRequest, "at most 500 ids per batch")
	}
	revoked := 0
	missing := []string{}
	for _, id := range input.IDs {
		record, found, err := a.Keys.Revoke(c.Context(), id)
		if err != nil {
			return a.fail("api_key_revoke_batch", err)
		}
		if found {
			revoked++
			// The per-key audit event fires only for fresh revocations so a
			// retried batch does not duplicate them.
			if record.RevokedAt != nil && time.Since(*record.RevokedAt) < time.Minute {
				a.emitOperation(c, "api_key_revoke", "tenant:"+record.TenantID, "success", record.ID, map[string]string{"batch": "true"})
			}
		} else {
			missing = append(missing, id)
		}
	}
	a.emitOperation(c, "api_key_revoke_batch", "", "success", strconv.Itoa(revoked))
	return c.JSON(fiber.Map{"revoked": revoked, "missing": missing})
}
func (a *Admin) listUpstreams(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	limit, offset := pageParams(c)
	values, total, err := a.Repo.ListUpstreams(c.UserContext(), limit, offset)
	if err != nil {
		return a.fail("upstream_list", err)
	}
	c.Set("X-Total-Count", strconv.FormatInt(total, 10))
	return c.JSON(values)
}

func (a *Admin) createUpstream(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	var input struct {
		Name    string `json:"name"`
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Enabled *bool  `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if err := a.checkTarget(c, input.BaseURL); err != nil {
		return err
	}
	value, err := a.Repo.CreateUpstream(c.UserContext(), input.Name, input.BaseURL, input.APIKey, enabled, a.EncryptionKey)
	if err != nil {
		return a.fail("upstream_create", err)
	}
	a.emitOperation(c, "upstream_create", "", "success", value.ID)
	return c.Status(http.StatusCreated).JSON(value)
}

func (a *Admin) updateUpstream(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	var input struct {
		Name    string `json:"name"`
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Enabled bool   `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := a.checkTarget(c, input.BaseURL); err != nil {
		return err
	}
	value, err := a.Repo.UpdateUpstream(c.UserContext(), c.Params("id"), input.Name, input.BaseURL, input.APIKey, input.Enabled, a.EncryptionKey)
	if err != nil {
		return a.fail("upstream_update", err)
	}
	a.emitOperation(c, "upstream_update", "", "success", value.ID, map[string]string{"key_rotated": strconv.FormatBool(input.APIKey != "")})
	return c.JSON(value)
}

func (a *Admin) deleteUpstream(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	if err := a.Repo.DeleteUpstream(c.UserContext(), c.Params("id")); err != nil {
		return a.fail("upstream_delete", err)
	}
	a.emitOperation(c, "upstream_delete", "", "success", c.Params("id"))
	return c.SendStatus(http.StatusNoContent)
}

func (a *Admin) testUpstream(c *fiber.Ctx) error {
	if a.Repo == nil || a.UpstreamClient == nil {
		return fiber.ErrServiceUnavailable
	}
	value, err := a.Repo.GetUpstream(c.UserContext(), c.Params("id"), a.EncryptionKey)
	if err != nil {
		return a.fail("upstream_test_load", err)
	}
	if !value.Enabled {
		return fiber.NewError(http.StatusServiceUnavailable, "upstream is disabled")
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 10*time.Second)
	defer cancel()
	var status int
	err = a.UpstreamClient.DoUpstream(ctx, proxy.Upstream{BaseURL: value.BaseURL, APIKey: value.APIKey, Enabled: value.Enabled}, http.MethodGet, "/v1/models", "", nil, nil, io.Discard, func(code int, _ http.Header) { status = code }, nil, nil)
	if err != nil {
		// The cause stays in the logs — it can name internal targets — and
		// only a generic message reaches the caller.
		logger := a.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("upstream test request failed", slog.Any("error", err))
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"ok": false, "message": "upstream unavailable"})
	}
	return c.JSON(fiber.Map{"ok": status >= 200 && status < 500, "status": status})
}

// checkTarget applies the SSRF policy to an administrator-supplied upstream
// URL before it is stored. The response carries only a fixed message; the
// denial category is in the log.
func (a *Admin) checkTarget(c *fiber.Ctx, rawURL string) error {
	if a.TargetPolicy == nil {
		return nil
	}
	if err := a.TargetPolicy.ValidateTarget(c.UserContext(), rawURL); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "upstream target not allowed")
	}
	return nil
}

func (a *Admin) createPolicy(c *fiber.Ctx) error {
	var value policy.Policy
	if err := c.BodyParser(&value); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	created, err := a.Repo.CreatePolicy(c.Context(), value)
	if err != nil {
		return a.fail("policy_create", err)
	}
	a.refreshPolicies(c.Context())
	a.emitOperation(c, "policy_create", created.Scope, "success", created.ID)
	return c.Status(fiber.StatusCreated).JSON(created)
}
func (a *Admin) listPolicies(c *fiber.Ctx) error {
	values, err := a.Repo.ListPolicies(c.Context())
	if err != nil {
		return a.fail("policy_list", err)
	}
	return c.JSON(values)
}
func (a *Admin) updatePolicy(c *fiber.Ctx) error {
	var value policy.Policy
	if err := c.BodyParser(&value); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	updated, err := a.Repo.UpdatePolicy(c.Context(), c.Params("id"), value)
	if err != nil {
		return a.fail("policy_update", err)
	}
	a.refreshPolicies(c.Context())
	a.emitOperation(c, "policy_update", updated.Scope, "success", updated.ID)
	return c.JSON(updated)
}
func (a *Admin) deletePolicy(c *fiber.Ctx) error {
	deleted, err := a.Repo.DeletePolicy(c.Context(), c.Params("id"))
	if err != nil {
		return a.fail("policy_delete", err)
	}
	if !deleted {
		return fiber.ErrNotFound
	}
	a.refreshPolicies(c.Context())
	a.emitOperation(c, "policy_delete", "", "success", c.Params("id"))
	return c.SendStatus(fiber.StatusNoContent)
}
func (a *Admin) refreshPolicies(ctx context.Context) {
	if a.Policies != nil {
		_ = a.Policies.Refresh(ctx)
	}
	if a.PolicyChanged != nil {
		a.PolicyChanged(ctx)
	}
}
func (a *Admin) emitOperation(c *fiber.Ctx, operation, scope, outcome, version string, detail ...map[string]string) {
	if a.Events == nil {
		return
	}
	actor := "unknown"
	if user, ok := c.Locals("admin_user").(storage.AdminUser); ok {
		actor = user.ID + ":" + user.Username
	}
	requestID := c.Get("X-Request-ID")
	if requestID == "" {
		requestID = uuid.NewString()
	}
	metadata := map[string]string{"operation": operation, "scope": scope, "actor": actor, "outcome": outcome}
	if len(detail) > 0 {
		for key, value := range detail[0] {
			metadata[key] = value
		}
	}
	a.Events.Enqueue(audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: requestID, TenantID: "admin", Direction: audit.DirectionAdmin, Path: c.Path(), Decision: outcome, RuleVersion: version, Metadata: metadata})
}
