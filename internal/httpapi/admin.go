package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

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
	throttle      *authThrottle
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
	if storage.IsNotFound(err) {
		return fiber.ErrNotFound
	}
	return fiber.ErrInternalServerError
}

func (a *Admin) Register(app *fiber.App) {
	if a.throttle == nil {
		a.throttle = newAuthThrottle(30, time.Minute)
	}
	app.Use(a.csrf)
	app.Get("/admin/v1/setup/status", a.setupStatus)
	app.Post("/admin/v1/setup", a.setup)
	app.Post("/admin/v1/auth/login", a.login)
	app.Post("/admin/v1/auth/logout", a.logout)
	app.Get("/admin/v1/auth/me", a.me)
	app.Use(a.authenticate)
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
		u, err := url.Parse(origin)
		if err == nil && sameOrigin(c, u) {
			return c.Next()
		}
	}
	csrfCookie := c.Cookies("gateway_admin_csrf")
	csrfHeader := c.Get("X-CSRF-Token")
	if csrfCookie != "" && csrfHeader != "" && subtle.ConstantTimeCompare([]byte(csrfCookie), []byte(csrfHeader)) == 1 {
		return c.Next()
	}
	return fiber.NewError(fiber.StatusForbidden, "csrf validation failed")
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
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	user, hash, err := a.Repo.GetAdminUser(c.UserContext(), input.Username)
	if err != nil || bcrypt.CompareHashAndPassword(hash, []byte(input.Password)) != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
	}
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
	if _, err = a.Repo.CreateAdminSession(c.UserContext(), user.ID, sessionHash(token), time.Now().Add(24*time.Hour)); err != nil {
		return a.fail("admin_session_create", err)
	}
	c.Cookie(&fiber.Cookie{Name: adminSessionCookie, Value: token, HTTPOnly: true, Secure: false, SameSite: "Lax", Path: "/", MaxAge: 86400})
	c.Cookie(&fiber.Cookie{Name: "gateway_admin_csrf", Value: csrfToken, HTTPOnly: false, Secure: false, SameSite: "Lax", Path: "/", MaxAge: 86400})
	return c.JSON(user)
}

func (a *Admin) logout(c *fiber.Ctx) error {
	if token := c.Cookies(adminSessionCookie); token != "" && a.Repo != nil {
		if err := a.Repo.RevokeAdminSession(c.UserContext(), sessionHash(token)); err != nil {
			return a.fail("admin_logout", err)
		}
	}
	c.ClearCookie(adminSessionCookie)
	c.ClearCookie("gateway_admin_csrf")
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
func (a *Admin) listKeys(c *fiber.Ctx) error {
	if a.Keys == nil {
		return fiber.ErrServiceUnavailable
	}
	keys, err := a.Keys.List(c.Context(), c.Query("tenant_id"))
	if err != nil {
		return a.fail("api_key_list", err)
	}
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
func (a *Admin) listUpstreams(c *fiber.Ctx) error {
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	values, err := a.Repo.ListUpstreams(c.UserContext())
	if err != nil {
		return a.fail("upstream_list", err)
	}
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
	value, err := a.Repo.UpdateUpstream(c.UserContext(), c.Params("id"), input.Name, input.BaseURL, input.APIKey, input.Enabled, a.EncryptionKey)
	if err != nil {
		return a.fail("upstream_update", err)
	}
	a.emitOperation(c, "upstream_update", "", "success", value.ID)
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
	if a.Repo == nil {
		return fiber.ErrServiceUnavailable
	}
	value, err := a.Repo.GetUpstream(c.UserContext(), c.Params("id"), a.EncryptionKey)
	if err != nil {
		return a.fail("upstream_test_load", err)
	}
	if !value.Enabled {
		return fiber.NewError(http.StatusServiceUnavailable, "upstream is disabled")
	}
	u, err := url.Parse(value.BaseURL)
	if err != nil {
		return a.fail("upstream_test_url", err)
	}
	req, err := http.NewRequestWithContext(c.UserContext(), http.MethodGet, strings.TrimRight(u.String(), "/")+"/v1/models", nil)
	if err != nil {
		return a.fail("upstream_test_request", err)
	}
	if value.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+value.APIKey)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"ok": false, "message": "upstream unavailable"})
	}
	defer resp.Body.Close()
	return c.JSON(fiber.Map{"ok": resp.StatusCode >= 200 && resp.StatusCode < 500, "status": resp.StatusCode})
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
func (a *Admin) emitOperation(c *fiber.Ctx, operation, scope, outcome, version string) {
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
	a.Events.Enqueue(audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: requestID, TenantID: "admin", Direction: audit.DirectionAdmin, Path: c.Path(), Decision: outcome, RuleVersion: version, Metadata: map[string]string{"operation": operation, "scope": scope, "actor": actor, "outcome": outcome}})
}
