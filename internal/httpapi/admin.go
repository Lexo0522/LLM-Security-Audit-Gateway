package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

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
	Token         string
	Logger        *slog.Logger
	Repo          *storage.Repository
	Rules         *rule.Registry
	RuleChanged   func(context.Context, string)
	Events        *events.Pipeline
	Keys          *auth.Manager
	Policies      *policy.Resolver
	PolicyChanged func(context.Context)
	Audit         AuditReader
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
	app.Use(a.authenticate)
	app.Post("/admin/v1/rule-sets", a.create)
	app.Get("/admin/v1/rule-sets", a.list)
	app.Get("/admin/v1/rule-sets/:version", a.get)
	app.Post("/admin/v1/rule-sets/:version/publish", a.publish)
	app.Post("/admin/v1/rule-sets/:scope/rollback", a.rollback)
	app.Post("/admin/v1/api-keys", a.createKey)
	app.Get("/admin/v1/api-keys", a.listKeys)
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

func (a *Admin) authenticate(c *fiber.Ctx) error {
	value := strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if value == "" || subtle.ConstantTimeCompare([]byte(value), []byte(a.Token)) != 1 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fiber.Map{"message": "invalid admin token"}})
	}
	return c.Next()
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
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if !auth.ValidTenantID(input.TenantID) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid tenant_id")
	}
	record, key, err := a.Keys.Create(c.Context(), input.TenantID)
	if err != nil {
		return a.fail("api_key_create", err)
	}
	a.emitOperation(c, "api_key_create", "tenant:"+record.TenantID, "success", record.ID)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": record.ID, "tenant_id": record.TenantID, "prefix": record.Prefix, "created_at": record.CreatedAt, "key": key})
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
	token := strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	sum := sha256.Sum256([]byte(token))
	requestID := c.Get("X-Request-ID")
	if requestID == "" {
		requestID = uuid.NewString()
	}
	a.Events.Enqueue(audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: requestID, TenantID: "admin", Direction: audit.DirectionAdmin, Path: c.Path(), Decision: outcome, RuleVersion: version, Metadata: map[string]string{"operation": operation, "scope": scope, "actor_hash": hex.EncodeToString(sum[:]), "outcome": outcome}})
}
