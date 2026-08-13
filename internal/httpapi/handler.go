package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/normalize"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/proxy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/stream"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Handler struct {
	cfg        config.Config
	rules      *rule.Registry
	policies   *policy.Resolver
	identities auth.Authenticator
	upstream   *proxy.Client
	limiter    ratelimit.Limiter
	auditor    audit.Auditor
	events     *events.Pipeline
	metrics    *observability.Metrics
}

func New(cfg config.Config, rules *rule.Registry, policies *policy.Resolver, identities auth.Authenticator, limiter ratelimit.Limiter, auditor audit.Auditor, pipeline *events.Pipeline, metrics ...*observability.Metrics) *Handler {
	if limiter == nil {
		limiter = ratelimit.MemoryLimiter{}
	}
	if auditor == nil {
		auditor = audit.NoopAuditor{}
	}
	if policies == nil {
		policies = policy.NewResolver(nil)
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	if collector == nil {
		collector = observability.NewMetrics()
	}
	return &Handler{cfg: cfg, rules: rules, policies: policies, identities: identities, upstream: proxy.New(cfg), limiter: limiter, auditor: auditor, events: pipeline, metrics: collector}
}

func (h *Handler) Register(app *fiber.App) {
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	app.Get("/metrics", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; version=0.0.4; charset=utf-8")
		return c.SendString(h.metrics.Render())
	})
	app.Get("/readyz", func(c *fiber.Ctx) error {
		if h.rules == nil || !h.rules.Ready() {
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
	if h.identities == nil {
		return identityUnavailable(c)
	}
	requestContext := c.UserContext()
	identity, err := h.identities.Authenticate(requestContext, c.Get(fiber.HeaderAuthorization))
	if err != nil {
		if errors.Is(err, auth.ErrUnavailable) {
			return identityUnavailable(c)
		}
		return invalidAPIKey(c)
	}
	allowed, retry, err := h.limiter.Allow(requestContext, identity.TenantID+":"+c.Path())
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
	input := audit.Input{RequestID: requestID, TenantID: identity.TenantID, APIKeyID: identity.APIKeyID, Direction: audit.DirectionRequest, Path: c.Path(), Model: requestModel(body), Text: normalize.Text(body)}
	started := time.Now()
	result, ruleVersion := h.rules.Audit(requestContext, identity.TenantID, input)
	configured := h.policies.Resolve(identity.TenantID, c.Path(), "request")
	decision := policy.Elevate(result, policy.Decide(result, configured))
	h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(decision), "direction": "request"})
	if h.cfg.AuditEnabled && decision == policy.Block {
		h.emit(input, result, ruleVersion, configured, decision, nil, "", started, body)
		return blocked(c, "policy_blocked", fmt.Sprintf("request blocked by audit policy; risk_score=%d", result.Score))
	}
	var modelResult *audit.ModelResult
	var auditorErr string
	if h.cfg.AuditEnabled && decision == policy.Monitor && h.cfg.AuditorURL != "" {
		ctx, cancel := context.WithTimeout(requestContext, time.Duration(h.cfg.AuditorTimeoutMS)*time.Millisecond)
		res, callErr := h.auditor.Audit(ctx, input)
		cancel()
		if callErr != nil {
			auditorErr = callErr.Error()
			if configured.AuditorFailureMode == "fail_closed" {
				h.emit(input, result, ruleVersion, configured, policy.Block, nil, auditorErr, started, body)
				return blocked(c, "auditor_unavailable", "synchronous auditor unavailable")
			}
		} else {
			modelResult = &res
			if res.Verdict == "block" || res.Score >= configured.InterventionAt {
				h.emit(input, result, ruleVersion, configured, policy.Block, modelResult, "", started, body)
				return blocked(c, "auditor_blocked", "request blocked by model audit")
			}
		}
	}
	h.emit(input, result, ruleVersion, configured, decision, modelResult, auditorErr, started, body)
	if h.cfg.AuditEnabled && decision == policy.Allow && h.cfg.AuditorURL != "" {
		go h.shadow(input, result, ruleVersion, configured, body)
	}
	c.Set(fiber.HeaderContentType, c.Get(fiber.HeaderContentType, "application/json"))
	streamWindows := stream.NewWindows(h.cfg.SSEAuditWindowBytes)
	streamContext, cancelStream := context.WithCancel(requestContext)
	defer cancelStream()
	terminationCode := ""
	inspect := func(event stream.Event) bool {
		for _, fragment := range event.Fragments {
			responseInput := input
			responseInput.Direction = audit.DirectionResponse
			responseInput.Text = normalize.Text(streamWindows.Feed(fragment.Channel, fragment.Text))
			responseResult, responseVersion := h.rules.Audit(streamContext, identity.TenantID, responseInput)
			responsePolicy := h.policies.Resolve(identity.TenantID, c.Path(), "response")
			responseDecision := policy.Elevate(responseResult, policy.Decide(responseResult, responsePolicy))
			h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(responseDecision), "direction": "response"})
			metadata := map[string]string{"sse": "true", "sse_channel": fragment.Channel}
			if h.cfg.AuditEnabled && responseDecision == policy.Block {
				terminationCode = "stream_policy_blocked"
				metadata["stream_termination_reason"] = terminationCode
				h.emitMetadata(responseInput, responseResult, responseVersion, responsePolicy, responseDecision, nil, "", time.Now(), fragment.Text, metadata)
				cancelStream()
				return false
			}
			h.emitMetadata(responseInput, responseResult, responseVersion, responsePolicy, responseDecision, nil, "", time.Now(), fragment.Text, metadata)
			if h.cfg.AuditEnabled && responseDecision == policy.Allow && h.cfg.AuditorURL != "" {
				go h.shadow(responseInput, responseResult, responseVersion, responsePolicy, fragment.Text)
			}
		}
		return true
	}
	inspectNonStream := func(chunk []byte) bool {
		responseInput := input
		responseInput.Direction = audit.DirectionResponse
		responseInput.Text = normalize.Text(chunk)
		responseResult, responseVersion := h.rules.Audit(context.Background(), identity.TenantID, responseInput)
		responsePolicy := h.policies.Resolve(identity.TenantID, c.Path(), "response")
		responseDecision := policy.Elevate(responseResult, policy.Decide(responseResult, responsePolicy))
		h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(responseDecision), "direction": "response"})
		h.emit(responseInput, responseResult, responseVersion, responsePolicy, responseDecision, nil, "", time.Now(), chunk)
		if h.cfg.AuditEnabled && responseDecision == policy.Allow && h.cfg.AuditorURL != "" {
			go h.shadow(responseInput, responseResult, responseVersion, responsePolicy, chunk)
		}
		return !h.cfg.AuditEnabled || responseDecision != policy.Block
	}
	err = h.upstream.Do(streamContext, c.Method(), c.Path(), body, c.GetReqHeaders(), c.Response().BodyWriter(), func(status int, headers http.Header) {
		copyResponseHeaders(c, headers)
		c.Status(status)
	}, inspectNonStream, inspect)
	var inspectionBlocked *proxy.InspectionBlockedError
	if errors.As(err, &inspectionBlocked) {
		if inspectionBlocked.ResponseStarted {
			cancelStream()
			code := inspectionBlocked.Code
			if code == "" {
				code = terminationCode
			}
			if code == "" {
				code = "stream_policy_blocked"
			}
			if code == "sse_event_too_large" {
				responseInput := input
				responseInput.Direction = audit.DirectionResponse
				responsePolicy := h.policies.Resolve(identity.TenantID, c.Path(), "response")
				h.emitMetadata(responseInput, audit.Result{}, ruleVersion, responsePolicy, policy.Block, nil, "", time.Now(), nil, map[string]string{"sse": "true", "stream_termination_reason": code})
			}
			_, _ = c.Response().BodyWriter().Write(stream.SecurityTermination(code, requestID))
			stream.Flush(c.Response().BodyWriter())
			return nil
		}
		return blocked(c, "response_policy_blocked", "response blocked by audit policy")
	}
	return err
}

func (h *Handler) shadow(input audit.Input, result audit.Result, ruleVersion string, configured policy.Policy, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(h.cfg.AuditorTimeoutMS)*time.Millisecond)
	defer cancel()
	res, err := h.auditor.Audit(ctx, input)
	if err != nil {
		h.emit(input, result, ruleVersion, configured, policy.Allow, nil, err.Error(), time.Now(), body)
		return
	}
	h.emit(input, result, ruleVersion, configured, policy.Allow, &res, "", time.Now(), body)
}

func (h *Handler) emit(input audit.Input, result audit.Result, ruleVersion string, configured policy.Policy, decision policy.Decision, model *audit.ModelResult, auditorErr string, started time.Time, body []byte) {
	h.emitMetadata(input, result, ruleVersion, configured, decision, model, auditorErr, started, body, nil)
}

func (h *Handler) emitMetadata(input audit.Input, result audit.Result, ruleVersion string, configured policy.Policy, decision policy.Decision, model *audit.ModelResult, auditorErr string, started time.Time, body []byte, metadata map[string]string) {
	if h.events == nil {
		return
	}
	hash := sha256.Sum256(body)
	h.events.Enqueue(audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: input.RequestID, TenantID: input.TenantID, APIKeyID: input.APIKeyID, Direction: input.Direction, Path: input.Path, Model: input.Model, Decision: string(decision), RiskScore: result.Score, RuleVersion: ruleVersion, PolicyID: configured.ID, PolicyRevision: configured.Revision, Matches: result.Matches, Auditor: model, AuditorError: auditorErr, LatencyMS: time.Since(started).Milliseconds(), BodyBytes: len(body), ContentSHA256: hex.EncodeToString(hash[:]), Metadata: metadata})
}

func endpoint(path string) string {
	switch path {
	case "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/responses":
		return path
	default:
		return "/v1/other"
	}
}
func blocked(c *fiber.Ctx, code, message string) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": fiber.Map{"message": message, "type": "audit_blocked", "code": code}})
}
func invalidAPIKey(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fiber.Map{"message": "invalid API key", "type": "authentication_error", "code": "invalid_api_key"}})
}
func identityUnavailable(c *fiber.Ctx) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": fiber.Map{"message": "gateway identity service unavailable", "type": "service_unavailable", "code": "identity_unavailable"}})
}

func copyResponseHeaders(c *fiber.Ctx, headers http.Header) {
	for key, values := range headers {
		switch http.CanonicalHeaderKey(key) {
		case "Connection", "Content-Length", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
			continue
		}
		c.Response().Header.Del(key)
		for _, value := range values {
			c.Response().Header.Add(key, value)
		}
	}
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
