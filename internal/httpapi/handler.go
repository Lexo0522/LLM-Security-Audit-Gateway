package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/normalize"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/proxy"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Handler struct {
	cfg      config.Config
	rules    *rule.Engine
	upstream *proxy.Client
}

func New(cfg config.Config, rules *rule.Engine) *Handler {
	return &Handler{cfg: cfg, rules: rules, upstream: proxy.New(cfg)}
}

func (h *Handler) Register(app *fiber.App) {
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	app.Get("/readyz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ready"}) })
	app.All("/v1/*", h.proxy)
}

func (h *Handler) proxy(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodPost {
		return fiber.ErrMethodNotAllowed
	}
	if len(c.Body()) > h.cfg.MaxBodyBytes {
		return blocked(c, "request_too_large", "request body exceeds configured limit")
	}
	requestID := c.Get("X-Request-ID")
	if requestID == "" {
		requestID = uuid.NewString()
	}
	c.Set("X-Request-ID", requestID)
	body := append([]byte(nil), c.Body()...)
	text := normalize.Text(body)
	result := h.rules.Audit(context.Background(), audit.Input{RequestID: requestID, Direction: audit.DirectionRequest, Text: text})
	decision := policy.Decide(result, policy.Policy{})
	if h.cfg.AuditEnabled && decision == policy.Block {
		return blocked(c, "policy_blocked", fmt.Sprintf("request blocked by audit policy; risk_score=%d", result.Score))
	}
	c.Set(fiber.HeaderContentType, c.Get(fiber.HeaderContentType, "application/json"))
	path := c.Path()
	inspect := func(chunk []byte) bool {
		response := h.rules.Audit(context.Background(), audit.Input{RequestID: requestID, Direction: audit.DirectionResponse, Text: normalize.Text(chunk)})
		return policy.Decide(response, policy.Policy{}) != policy.Block
	}
	err := h.upstream.Do(c.Context(), c.Method(), path, body, c.GetReqHeaders(), c.Response().BodyWriter(), func(status int, headers http.Header) {
		for key, values := range headers {
			for _, value := range values {
				c.Response().Header.Add(key, value)
			}
		}
		c.Status(status)
	}, inspect)
	if err != nil {
		return err
	}
	return nil
}

func blocked(c *fiber.Ctx, code, message string) error {
	c.Status(fiber.StatusForbidden)
	return c.JSON(fiber.Map{"error": fiber.Map{"message": message, "type": "audit_blocked", "code": code}})
}

func JSON(v any) string   { data, _ := json.Marshal(v); return string(data) }
func _unused(_ ...string) { _ = strings.Builder{} }
