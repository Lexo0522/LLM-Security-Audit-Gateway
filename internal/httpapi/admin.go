package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Admin struct {
	Token       string
	Repo        *storage.Repository
	Rules       *rule.Registry
	RuleChanged func(context.Context, string)
	Events      *events.Pipeline
}

func (a *Admin) Register(app *fiber.App) {
	app.Use(a.authenticate)
	app.Post("/admin/v1/rule-sets", a.create)
	app.Get("/admin/v1/rule-sets", a.list)
	app.Get("/admin/v1/rule-sets/:version", a.get)
	app.Post("/admin/v1/rule-sets/:version/publish", a.publish)
	app.Post("/admin/v1/rule-sets/:scope/rollback", a.rollback)
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
		return fiber.NewError(400, err.Error())
	}
	set, err := a.Repo.CreateRuleSet(c.Context(), input.Scope, input.Rules)
	if err != nil {
		return fiber.NewError(400, err.Error())
	}
	a.emit(c, "create", set, "success")
	return c.Status(201).JSON(set)
}
func (a *Admin) list(c *fiber.Ctx) error {
	sets, err := a.Repo.ListRuleSets(c.Context())
	if err != nil {
		return err
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
		return fiber.NewError(400, err.Error())
	}
	if a.RuleChanged != nil {
		a.RuleChanged(c.Context(), set.Scope)
	}
	if err = a.Rules.Refresh(c.Context(), set.Scope); err != nil {
		return err
	}
	a.emit(c, "publish", set, "success")
	return c.JSON(set)
}
func (a *Admin) rollback(c *fiber.Ctx) error {
	var input struct {
		Version string `json:"version"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(400, err.Error())
	}
	set, err := a.Repo.Rollback(c.Context(), c.Params("scope"), input.Version)
	if err != nil {
		return fiber.NewError(400, err.Error())
	}
	if a.RuleChanged != nil {
		a.RuleChanged(c.Context(), set.Scope)
	}
	if err = a.Rules.Refresh(c.Context(), set.Scope); err != nil {
		return err
	}
	a.emit(c, "rollback", set, "success")
	return c.JSON(set)
}
func (a *Admin) emit(c *fiber.Ctx, operation string, set storage.RuleSet, outcome string) {
	if a.Events == nil {
		return
	}
	token := strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	sum := sha256.Sum256([]byte(token))
	requestID := c.Get("X-Request-ID")
	if requestID == "" {
		requestID = uuid.NewString()
	}
	a.Events.Enqueue(audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: requestID, TenantID: "admin", Direction: audit.DirectionAdmin, Path: c.Path(), Decision: outcome, RuleVersion: set.Version, Metadata: map[string]string{"operation": operation, "scope": set.Scope, "actor_hash": hex.EncodeToString(sum[:]), "outcome": outcome}})
}
