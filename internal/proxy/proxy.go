package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/stream"
)

// InspectionBlockedError reports whether a streaming response may already have
// reached the client when a response-side policy blocks subsequent content.
type InspectionBlockedError struct {
	ResponseStarted bool
	Code            string
}

func (e *InspectionBlockedError) Error() string { return "upstream response blocked by audit policy" }

type Client struct {
	cfg  config.Config
	http *http.Client
}

func New(cfg config.Config) *Client {
	// A dedicated transport with per-phase budgets: connection churn is avoided
	// by a large idle pool, stalls before first response byte are capped by
	// ResponseHeaderTimeout, and no overall Client.Timeout is set because it
	// would kill long-lived SSE responses mid-stream. Non-streaming requests
	// get an overall timeout from the handler.
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.RequestTimeoutMS) * time.Millisecond,
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: transport}}
}

// Do forwards a request to the configured upstream. Non-SSE responses are
// inspected as one bounded body, while SSE responses are inspected as complete
// events before each event is written to the client.
func (c *Client) Do(ctx context.Context, method, path, query string, body []byte, headers http.Header, dst io.Writer, onHeaders func(int, http.Header), inspectResponse func([]byte) bool, inspectSSE stream.Inspector) error {
	target, err := url.JoinPath(c.cfg.UpstreamURL, path)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return err
	}
	parsed.RawQuery = query
	// Clean dot segments again (url.Parse does not) so neither a decoded
	// traversal from the front framework nor an encoded one can normalize the
	// target outside the /v1 boundary.
	parsed.Path = pathpkg.Clean("/" + parsed.Path)
	parsed.RawPath = ""
	if !strings.HasPrefix(parsed.Path, "/v1/") {
		return fmt.Errorf("upstream path %q escapes the /v1 boundary", path)
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	copyHeaders(req.Header, headers)
	if c.cfg.UpstreamAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.UpstreamAPIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// An upstream that gzips without being asked leaves the body unreadable to
	// the audit path; net/http only auto-decompresses what it negotiated, and
	// x-gzip is never auto-decompressed, so both need this explicit wrap.
	respBody := io.Reader(resp.Body)
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if !resp.Uncompressed && (encoding == "gzip" || encoding == "x-gzip") {
		gzipReader, gzipErr := gzip.NewReader(resp.Body)
		if gzipErr != nil {
			return gzipErr
		}
		defer gzipReader.Close()
		respBody = gzipReader
		resp.Header.Del("Content-Encoding")
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		if onHeaders != nil {
			onHeaders(resp.StatusCode, resp.Header)
		}
		if err := stream.Copy(ctx, dst, respBody, c.cfg.SSEMaxEventBytes, inspectSSE); err != nil {
			if errors.Is(err, stream.ErrInspectionBlocked) {
				return &InspectionBlockedError{ResponseStarted: true, Code: "stream_policy_blocked"}
			}
			if errors.Is(err, stream.ErrEventTooLarge) {
				return &InspectionBlockedError{ResponseStarted: true, Code: "sse_event_too_large"}
			}
			return err
		}
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(respBody, int64(c.cfg.MaxResponseBytes)+1))
	if err != nil {
		return err
	}
	if len(data) > c.cfg.MaxResponseBytes {
		return fmt.Errorf("upstream response exceeds limit")
	}
	if inspectResponse != nil && !inspectResponse(data) {
		return &InspectionBlockedError{}
	}
	if onHeaders != nil {
		onHeaders(resp.StatusCode, resp.Header)
	}
	_, err = dst.Write(data)
	return err
}

// upstreamForwardHeaders is an allowlist of client headers the upstream may
// see. Everything else — cookies, forwarding chains, caller identity, internal
// hops — is stripped, and Authorization is always re-set from configuration.
var upstreamForwardHeaders = map[string]struct{}{
	"Accept":         {},
	"Accept-Charset": {},
	"Content-Type":   {},
	"User-Agent":     {},
	"X-Request-Id":   {},
	"OpenAI-Beta":    {},
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if _, ok := upstreamForwardHeaders[http.CanonicalHeaderKey(key)]; !ok {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
