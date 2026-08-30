package httpapi

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/health"
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
	cfg           config.Config
	rules         *rule.Registry
	policies      *policy.Resolver
	identities    auth.Authenticator
	upstream      *proxy.Client
	limiter       ratelimit.Limiter
	auditor       audit.Auditor
	shadowAuditor audit.Auditor
	events        *events.Pipeline
	metrics       *observability.Metrics
	readiness     *health.Manager
	authThrottle  *authThrottle
	shadowOnce    sync.Once
	shadowJobs    chan shadowJob
}

type shadowJob struct {
	input       audit.Input
	result      audit.Result
	ruleVersion string
	configured  policy.Policy
	body        []byte
}

const shadowQueueSize = 256

// submitShadow queues a best-effort shadow audit. The queue bounds the work in
// flight; when it is full the job is dropped and counted instead of growing
// without limit.
func (h *Handler) submitShadow(job shadowJob) {
	h.shadowOnce.Do(func() {
		h.shadowJobs = make(chan shadowJob, shadowQueueSize)
		for range 2 {
			go h.shadowWorker()
		}
	})
	select {
	case h.shadowJobs <- job:
	default:
		h.metrics.Inc("audit_shadow_dropped_total", nil)
	}
}

func (h *Handler) shadowWorker() {
	for job := range h.shadowJobs {
		h.shadow(job.input, job.result, job.ruleVersion, job.configured, job.body)
	}
}

func (h *Handler) SetReadiness(readiness *health.Manager) { h.readiness = readiness }

// SetShadowAuditor swaps the auditor used by asynchronous shadow audits so
// shadow traffic shares neither the failure count nor the concurrency budget of
// the synchronous path.
func (h *Handler) SetShadowAuditor(auditor audit.Auditor) {
	if auditor != nil {
		h.shadowAuditor = auditor
	}
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
	return &Handler{cfg: cfg, rules: rules, policies: policies, identities: identities, upstream: proxy.New(cfg), limiter: limiter, auditor: auditor, shadowAuditor: auditor, events: pipeline, metrics: collector, authThrottle: newAuthThrottle(30, time.Minute)}
}

func (h *Handler) Register(app *fiber.App) {
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok", "version": h.cfg.Version}) })
	app.Get("/metrics", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; version=0.0.4; charset=utf-8")
		return c.SendString(h.metrics.Render())
	})
	app.Get("/readyz", func(c *fiber.Ctx) error {
		if h.readiness != nil {
			report := h.readiness.Report()
			if report.Status != "ready" {
				return c.Status(fiber.StatusServiceUnavailable).JSON(report)
			}
			return c.JSON(report)
		}
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
	// c.Context() is only safe while the handler runs: fasthttp recycles the
	// RequestCtx as soon as the response completes, and its Done() channel
	// signals server shutdown rather than client disconnects. Everything that
	// outlives the handler uses Background-derived contexts instead, and the
	// values the streaming goroutine needs are captured explicitly.
	requestContext := c.UserContext()
	// Failed gateway key lookups hit PostgreSQL, so repeated invalid keys are
	// throttled per client address before they can be replayed.
	if h.authThrottle.blocked(c.IP()) {
		h.metrics.Inc("auth_throttle_rejections_total", nil)
		c.Set("Retry-After", "60")
		return c.Status(429).JSON(fiber.Map{"error": fiber.Map{"message": "too many failed authentications", "type": "rate_limit_error", "code": "auth_throttled"}})
	}
	identity, err := h.identities.Authenticate(requestContext, c.Get(fiber.HeaderAuthorization))
	if err != nil {
		if errors.Is(err, auth.ErrUnavailable) {
			return identityUnavailable(c)
		}
		h.authThrottle.fail(c.IP())
		h.metrics.Inc("auth_failures_total", nil)
		return invalidAPIKey(c)
	}
	allowed, retry, err := h.limiter.Allow(requestContext, identity.TenantID+":"+c.Path())
	if err == nil && !allowed {
		h.metrics.Inc("audit_rate_limit_rejections_total", map[string]string{"endpoint": endpoint(c.Path())})
		c.Set("Retry-After", fmt.Sprintf("%d", max(1, int(retry.Seconds()))))
		return c.Status(429).JSON(fiber.Map{"error": fiber.Map{"message": "rate limit exceeded", "type": "rate_limit_error", "code": "rate_limit_exceeded"}})
	}
	// fiber's ctx.Body() transparently decodes gzip/deflate/brotli and even
	// returns the decode-error text as the body, so audit and forwarding both
	// work from the raw wire bytes in c.Request().Body() instead.
	if len(c.Request().Body()) > h.cfg.MaxBodyBytes {
		return tooLarge(c, "request body exceeds configured limit")
	}
	requestID := c.Get("X-Request-ID")
	if requestID == "" {
		requestID = uuid.NewString()
	}
	c.Set("X-Request-ID", requestID)
	// The plaintext copy is what rules and the model auditor see and what is
	// forwarded upstream; wire-level encodings must never reach them encoded.
	// One JSON pass produces both the normalized text and the model field.
	auditBody, decodeErr := decodeAuditedBody(c.Request().Body(), c.Get(fiber.HeaderContentEncoding))
	if decodeErr != nil {
		return encodingError(c, decodeErr)
	}
	normalizedText, model, streamRequested := normalize.Parse(auditBody)
	input := audit.Input{RequestID: requestID, TenantID: identity.TenantID, APIKeyID: identity.APIKeyID, Direction: audit.DirectionRequest, Path: c.Path(), Model: model, Text: normalizedText}
	started := time.Now()
	var (
		result      audit.Result
		ruleVersion string
		configured  policy.Policy
		decision    = policy.Allow
	)
	var modelResult *audit.ModelResult
	var auditorErr string
	if h.cfg.AuditEnabled {
		result, ruleVersion = h.rules.Audit(requestContext, identity.TenantID, input)
		configured = h.policies.Resolve(identity.TenantID, c.Path(), "request")
		decision = policy.Elevate(result, policy.Decide(result, configured))
		h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(decision), "direction": "request"})
		if decision == policy.Block {
			h.emit(input, result, ruleVersion, configured, decision, nil, "", started, auditBody)
			return blocked(c, "policy_blocked", fmt.Sprintf("request blocked by audit policy; risk_score=%d", result.Score))
		}
		if decision == policy.Monitor && h.cfg.AuditorURL != "" {
			ctx, cancel := context.WithTimeout(requestContext, time.Duration(h.cfg.AuditorTimeoutMS)*time.Millisecond)
			res, callErr := h.auditor.Audit(ctx, input)
			cancel()
			if callErr != nil {
				auditorErr = callErr.Error()
				// AUDIT_FAIL_CLOSED is the deployment-wide override; policies can
				// tighten it per scope but cannot relax it.
				if configured.AuditorFailureMode == "fail_closed" || h.cfg.FailClosed {
					h.emit(input, result, ruleVersion, configured, policy.Block, nil, auditorErr, started, auditBody)
					return blocked(c, "auditor_unavailable", "synchronous auditor unavailable")
				}
			} else {
				modelResult = &res
				if res.Verdict == "block" || res.Score >= configured.InterventionAt {
					h.emit(input, result, ruleVersion, configured, policy.Block, modelResult, "", started, auditBody)
					return blocked(c, "auditor_blocked", "request blocked by model audit")
				}
			}
		}
		h.emit(input, result, ruleVersion, configured, decision, modelResult, auditorErr, started, auditBody)
		if decision == policy.Allow && h.cfg.AuditorURL != "" {
			h.submitShadow(shadowJob{input: input, result: result, ruleVersion: ruleVersion, configured: configured, body: auditBody})
		}
	}
	streamWindows := stream.NewWindows(h.cfg.SSEAuditWindowBytes)
	// The streaming goroutine outlives the handler, so its context is derived
	// from the user context (Background unless the embedder sets one) and never
	// from the fasthttp RequestCtx, which is recycled after the response.
	streamContext, cancelStream := context.WithCancel(requestContext)
	terminationCode := ""

	// Everything the streaming goroutine touches is captured up front: the
	// fiber request context is recycled once the response completes and must
	// not be read concurrently with the response write.
	pathValue := string(c.Path())
	methodValue := c.Method()
	reqHeaders := c.GetReqHeaders()
	queryString := string(c.Request().URI().QueryString())

	inspect := func(event stream.Event) bool {
		if !h.cfg.AuditEnabled {
			return true
		}
		for _, fragment := range event.Fragments {
			responseInput := input
			responseInput.Direction = audit.DirectionResponse
			responseInput.Text = normalize.Text(streamWindows.Feed(fragment.Channel, fragment.Text))
			responseResult, responseVersion := h.rules.Audit(streamContext, identity.TenantID, responseInput)
			responsePolicy := h.policies.Resolve(identity.TenantID, pathValue, "response")
			responseDecision := policy.Elevate(responseResult, policy.Decide(responseResult, responsePolicy))
			h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(responseDecision), "direction": "response"})
			metadata := map[string]string{"sse": "true", "sse_channel": fragment.Channel}
			if responseDecision == policy.Block {
				terminationCode = "stream_policy_blocked"
				metadata["stream_termination_reason"] = terminationCode
				h.emitMetadata(responseInput, responseResult, responseVersion, responsePolicy, responseDecision, nil, "", time.Now(), fragment.Text, metadata)
				cancelStream()
				return false
			}
			h.emitMetadata(responseInput, responseResult, responseVersion, responsePolicy, responseDecision, nil, "", time.Now(), fragment.Text, metadata)
			if responseDecision == policy.Allow && h.cfg.AuditorURL != "" {
				h.submitShadow(shadowJob{input: responseInput, result: responseResult, ruleVersion: responseVersion, configured: responsePolicy, body: fragment.Text})
			}
		}
		return true
	}
	inspectNonStream := func(chunk []byte) bool {
		if !h.cfg.AuditEnabled {
			return true
		}
		responseInput := input
		responseInput.Direction = audit.DirectionResponse
		responseInput.Text = normalize.Text(chunk)
		responseResult, responseVersion := h.rules.Audit(streamContext, identity.TenantID, responseInput)
		responsePolicy := h.policies.Resolve(identity.TenantID, pathValue, "response")
		responseDecision := policy.Elevate(responseResult, policy.Decide(responseResult, responsePolicy))
		h.metrics.Inc("audit_rule_decisions_total", map[string]string{"decision": string(responseDecision), "direction": "response"})
		h.emit(responseInput, responseResult, responseVersion, responsePolicy, responseDecision, nil, "", time.Now(), chunk)
		if responseDecision == policy.Allow && h.cfg.AuditorURL != "" {
			h.submitShadow(shadowJob{input: responseInput, result: responseResult, ruleVersion: responseVersion, configured: responsePolicy, body: chunk})
		}
		return responseDecision != policy.Block
	}

	// Non-streaming exchanges get the overall request timeout; requests that
	// ask for streaming are exempt so long-lived SSE sessions survive. The
	// cancel function is owned by the streaming goroutine: the handler returns
	// before the exchange begins, and canceling here would abort it.
	upstreamCtx := streamContext
	var cancelTimeout context.CancelFunc
	if !streamRequested && h.cfg.RequestTimeoutMS > 0 {
		upstreamCtx, cancelTimeout = context.WithTimeout(streamContext, time.Duration(h.cfg.RequestTimeoutMS)*time.Millisecond)
	}

	// The upstream exchange streams through a pipe so each approved SSE event
	// reaches the network as it is inspected instead of accumulating in memory.
	// The handler waits only for the upstream response headers, registers them
	// on the response, and hands the pipe to fasthttp.
	type headerResult struct {
		status  int
		headers http.Header
		err     error
	}
	headerCh := make(chan headerResult, 1)
	bodyReader, bodyWriter := io.Pipe()
	var dst io.Writer = bodyWriter
	if clientStallTimeout > 0 {
		// fasthttp stops draining the pipe when the client disappears, which
		// would otherwise block this goroutine on a full pipe forever.
		dst = &stallWriter{w: bodyWriter, abort: cancelStream, limit: clientStallTimeout}
	}
	go func() {
		defer cancelStream()
		if cancelTimeout != nil {
			defer cancelTimeout()
		}
		defer bodyWriter.Close()
		err := h.upstream.Do(upstreamCtx, methodValue, pathValue, queryString, auditBody, reqHeaders, dst, func(status int, headers http.Header) {
			headerCh <- headerResult{status: status, headers: headers}
		}, inspectNonStream, inspect)
		if err == nil {
			return
		}
		var inspectionBlocked *proxy.InspectionBlockedError
		if errors.As(err, &inspectionBlocked) && inspectionBlocked.ResponseStarted {
			code := inspectionBlocked.Code
			if code == "" {
				code = terminationCode
			}
			if code == "" {
				code = "stream_policy_blocked"
			}
			if code == "sse_event_too_large" && h.cfg.AuditEnabled {
				responseInput := input
				responseInput.Direction = audit.DirectionResponse
				responsePolicy := h.policies.Resolve(identity.TenantID, pathValue, "response")
				h.emitMetadata(responseInput, audit.Result{}, ruleVersion, responsePolicy, policy.Block, nil, "", time.Now(), nil, map[string]string{"sse": "true", "stream_termination_reason": code})
			}
			_, _ = bodyWriter.Write(stream.SecurityTermination(code, requestID))
			return
		}
		headerCh <- headerResult{err: err}
	}()
	var headerTimeout <-chan time.Time
	if h.cfg.RequestTimeoutMS > 0 {
		headerTimeout = time.After(time.Duration(h.cfg.RequestTimeoutMS) * time.Millisecond)
	}
	select {
	case result := <-headerCh:
		if result.err != nil {
			var inspectionBlocked *proxy.InspectionBlockedError
			if errors.As(result.err, &inspectionBlocked) {
				cancelStream()
				return blocked(c, "response_policy_blocked", "response blocked by audit policy")
			}
			cancelStream()
			return fiber.NewError(fiber.StatusBadGateway, "upstream request failed")
		}
		copyResponseHeaders(c, result.headers)
		c.Status(result.status)
	case <-headerTimeout:
		cancelStream()
		return fiber.NewError(fiber.StatusGatewayTimeout, "upstream response headers timed out")
	}
	c.Response().SetBodyStream(bodyReader, -1)
	return nil
}

func (h *Handler) shadow(input audit.Input, result audit.Result, ruleVersion string, configured policy.Policy, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(h.cfg.AuditorTimeoutMS)*time.Millisecond)
	defer cancel()
	res, err := h.shadowAuditor.Audit(ctx, input)
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
		case "Connection", "Content-Length", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
			// The gateway owns the client relationship; upstream cookies and
			// CORS policy must not silently apply to gateway clients.
			"Set-Cookie",
			"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Expose-Headers", "Access-Control-Max-Age":
			continue
		}
		c.Response().Header.Del(key)
		for _, value := range values {
			c.Response().Header.Add(key, value)
		}
	}
}

var errUnsupportedEncoding = errors.New("unsupported content encoding")
var errMalformedEncoding = errors.New("malformed compressed request body")
var errDecodedBodyTooLarge = errors.New("decoded request body exceeds audit limit")

const maxDecodedBodyBytes = 64 << 20

// clientStallTimeout bounds how long the streaming goroutine may stay blocked
// writing into the response pipe. fasthttp stops draining the pipe when the
// client connection disappears; without this bound an abandoned stream would
// pin the goroutine and the upstream connection forever.
const clientStallTimeout = 10 * time.Minute

// stallWriter aborts the stream when the client stops draining the response
// pipe for longer than the stall limit: it cancels the stream context and
// closes the underlying pipe so the blocked write fails.
type stallWriter struct {
	w     *io.PipeWriter
	abort context.CancelFunc
	limit time.Duration
}

func (s *stallWriter) Write(p []byte) (int, error) {
	written := make(chan error, 1)
	go func() {
		_, err := s.w.Write(p)
		written <- err
	}()
	select {
	case err := <-written:
		return len(p), err
	case <-time.After(s.limit):
		s.abort()
		_ = s.w.CloseWithError(errClientStalled)
		return 0, errClientStalled
	}
}

var errClientStalled = errors.New("client stopped draining the response stream")

func tooLarge(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": fiber.Map{"message": message, "type": "request_too_large", "code": "request_too_large"}})
}

// decodeAuditedBody returns the plaintext form of a request body so rule and
// model audit run on readable content. The plaintext result is also what gets
// forwarded upstream, which is why copyHeaders drops Content-Encoding.
// Unsupported encodings are refused rather than forwarded unaudited.
func decodeAuditedBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return append([]byte(nil), body...), nil
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, errMalformedEncoding
		}
		defer reader.Close()
		return readBounded(reader)
	case "deflate":
		if zlibReader, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer zlibReader.Close()
			return readBounded(zlibReader)
		}
		flateReader := flate.NewReader(bytes.NewReader(body))
		defer flateReader.Close()
		return readBounded(flateReader)
	case "br", "brotli":
		return readBounded(brotli.NewReader(bytes.NewReader(body)))
	default:
		return nil, errUnsupportedEncoding
	}
}

func readBounded(reader io.Reader) ([]byte, error) {
	decoded, err := io.ReadAll(io.LimitReader(reader, maxDecodedBodyBytes+1))
	if err != nil {
		return nil, errMalformedEncoding
	}
	if len(decoded) > maxDecodedBodyBytes {
		return nil, errDecodedBodyTooLarge
	}
	return decoded, nil
}

func encodingError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, errUnsupportedEncoding):
		return c.Status(fiber.StatusUnsupportedMediaType).JSON(fiber.Map{"error": fiber.Map{"message": "request content encoding cannot be audited", "type": "invalid_request_error", "code": "unsupported_content_encoding"}})
	case errors.Is(err, errDecodedBodyTooLarge):
		return tooLarge(c, "decoded request body exceeds configured limit")
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fiber.Map{"message": "request content encoding is malformed", "type": "invalid_request_error", "code": "invalid_content_encoding"}})
	}
}
