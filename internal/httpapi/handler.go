package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/normalize"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/proxy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

var tenantID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Handler struct {
	cfg      config.Config
	rules    *rule.Registry
	upstream *proxy.Client
	limiter  ratelimit.Limiter
	auditor  audit.Auditor
	events   *events.Pipeline
	metrics  *observability.Metrics
}

func New(cfg config.Config, rules *rule.Registry, limiter ratelimit.Limiter, auditor audit.Auditor, pipeline *events.Pipeline, metrics ...*observability.Metrics) *Handler {
	if limiter == nil {
		limiter = ratelimit.MemoryLimiter{}
	}
	if auditor == nil {
		auditor = audit.NoopAuditor{}
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	return &Handler{cfg: cfg, rules: rules, upstream: proxy.New(cfg), limiter: limiter, auditor: auditor, events: pipeline, metrics: collector}
}
func (h *Handler) Register(app *fiber.App) {
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	app.Get("/metrics", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; version=0.0.4; charset=utf-8")
		return c.SendString(h.metrics.Render())
	})
	app.Get("/readyz", func(c *fiber.Ctx) error {
		if !h.rules.Ready() {
			return c.Status(503).JSON(fiber.Map{"status": "not_ready"})
		}
		return c.JSON(fiber.Map{"status": "ready"})
	})
	app.All("/v1/*", h.proxy)
}
func (h *Handler) proxy(c *fiber.Ctx) error {
	startedRequest := time.Now()
	defer func() {
		h.metrics.Inc("audit_http_requests_total", map[string]string{"endpoint": endpoint(c.Path()), "status": fmt.Sprint(c.Response().StatusCode())})
		h.metrics.Observe("audit_http_duration_seconds", time.Since(startedRequest).Seconds(), map[string]string{"endpoint": endpoint(c.Path())})
	}()
	if c.Method() != fiber.MethodPost {
		return fiber.ErrMethodNotAllowed
	}
	tenant := c.Get("X-Tenant-ID")
	if !tenantID.MatchString(tenant) {
		return invalidTenant(c)
	}
	allowed, retry, err := h.limiter.Allow(c.Context(), tenant+":"+c.Path())
	if err == nil && !allowed {
		h.metrics.Inc("audit_rate_limit_rejections_total", map[string]string{"endpoint": endpoint(c.Path())})
		c.Set("Retry-After", fmt.Sprintf("%d", max(1, int(retry.Seconds()))))
		return c.Status(429).JSON(fiber.Map{"error": fiber.Map{"message": "rate limit exceeded", "type": "rate_limit_error", "code": "rate_limit_exceeded"}})
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
	model := requestModel(body)
	text := normalize.Text(body)
	started := time.Now()
	input := audit.Input{RequestID: requestID, TenantID: tenant, Direction: audit.DirectionRequest, Path: c.Path(), Model: model, Text: text}
	result, version := h.rules.Audit(c.Context(), tenant, input)
	decision := policy.Decide(result, policy.Policy{})
	h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(decision), "direction": "request"})
	if h.cfg.AuditEnabled && decision == policy.Block {
		h.emit(input, result, version, string(decision), nil, "", started, body)
		return blocked(c, "policy_blocked", fmt.Sprintf("request blocked by audit policy; risk_score=%d", result.Score))
	}
	var modelResult *audit.ModelResult
	var auditorErr string
	if h.cfg.AuditEnabled && decision == policy.Monitor && h.cfg.AuditorURL != "" {
		ctx, cancel := context.WithTimeout(c.Context(), time.Duration(h.cfg.AuditorTimeoutMS)*time.Millisecond)
		res, callErr := h.auditor.Audit(ctx, input)
		cancel()
		if callErr != nil {
			auditorErr = callErr.Error()
			if h.cfg.FailClosed {
				h.emit(input, result, version, "block", nil, auditorErr, started, body)
				return blocked(c, "auditor_unavailable", "synchronous auditor unavailable")
			}
		} else {
			modelResult = &res
			if res.Verdict == "block" || res.Score >= 80 {
				h.emit(input, result, version, "block", modelResult, "", started, body)
				return blocked(c, "auditor_blocked", "request blocked by model audit")
			}
		}
	}
	h.emit(input, result, version, string(decision), modelResult, auditorErr, started, body)
	if h.cfg.AuditEnabled && decision == policy.Allow && h.cfg.AuditorURL != "" {
		go h.shadow(input, result, version, body)
	}
	c.Set(fiber.HeaderContentType, c.Get(fiber.HeaderContentType, "application/json"))
	path := c.Path()
	inspect := func(chunk []byte) bool {
		responseInput := input
		responseInput.Direction = audit.DirectionResponse
		responseInput.Text = normalize.Text(chunk)
		responseResult, responseVersion := h.rules.Audit(context.Background(), tenant, responseInput)
		responseDecision := policy.Decide(responseResult, policy.Policy{})
		h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(responseDecision), "direction": "response"})
		h.emit(responseInput, responseResult, responseVersion, string(responseDecision), nil, "", time.Now(), chunk)
		if h.cfg.AuditEnabled && responseDecision == policy.Allow && h.cfg.AuditorURL != "" {
			go h.shadow(responseInput, responseResult, responseVersion, chunk)
		}
		return !h.cfg.AuditEnabled || responseDecision != policy.Block
	}
	err = h.upstream.Do(c.Context(), c.Method(), path, body, c.GetReqHeaders(), c.Response().BodyWriter(), func(status int, headers http.Header) {
		for key, values := range headers {
			for _, value := range values {
				c.Response().Header.Add(key, value)
			}
		}
		c.Status(status)
	}, inspect)
	return err
}
func (h *Handler) shadow(input audit.Input, result audit.Result, version string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(h.cfg.AuditorTimeoutMS)*time.Millisecond)
	defer cancel()
	res, err := h.auditor.Audit(ctx, input)
	if err != nil {
		h.emit(input, result, version, "allow", nil, err.Error(), time.Now(), body)
		return
	}
	h.emit(input, result, version, "allow", &res, "", time.Now(), body)
}
func (h *Handler) emit(input audit.Input, result audit.Result, version, decision string, model *audit.ModelResult, auditorErr string, started time.Time, body []byte) {
	if h.events == nil {
		return
	}
	hash := sha256.Sum256(body)
	h.events.Enqueue(audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: input.RequestID, TenantID: input.TenantID, Direction: input.Direction, Path: input.Path, Model: input.Model, Decision: decision, RiskScore: result.Score, RuleVersion: version, Matches: result.Matches, Auditor: model, AuditorError: auditorErr, LatencyMS: time.Since(started).Milliseconds(), BodyBytes: len(body), ContentSHA256: hex.EncodeToString(hash[:])})
}
func endpoint(path string) string {
	if strings.HasPrefix(path, "/v1/chat/") {
		return "/v1/chat/completions"
	}
	if strings.HasPrefix(path, "/v1/completions") {
		return "/v1/completions"
	}
	if strings.HasPrefix(path, "/v1/embeddings") {
		return "/v1/embeddings"
	}
	return "/v1/other"
}
func blocked(c *fiber.Ctx, code, message string) error {
	c.Status(fiber.StatusForbidden)
	return c.JSON(fiber.Map{"error": fiber.Map{"message": message, "type": "audit_blocked", "code": code}})
}
func invalidTenant(c *fiber.Ctx) error {
	return c.Status(400).JSON(fiber.Map{"error": fiber.Map{"message": "X-Tenant-ID is required and must contain only letters, digits, dot, dash, or underscore", "type": "invalid_request_error", "code": "invalid_tenant"}})
}
func requestModel(body []byte) string {
	var value struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &value)
	return value.Model
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
