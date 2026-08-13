package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/stream"
)

// InspectionBlockedError reports whether a streaming response may already have
// reached the client when a response-side policy blocks subsequent content.
type InspectionBlockedError struct{ ResponseStarted bool }

func (e *InspectionBlockedError) Error() string { return "upstream response blocked by audit policy" }

type Client struct {
	cfg  config.Config
	http *http.Client
}

func New(cfg config.Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: time.Duration(cfg.RequestTimeoutMS) * time.Millisecond}}
}

func (c *Client) Do(ctx context.Context, method, path string, body []byte, headers http.Header, dst io.Writer, onHeaders func(int, http.Header), inspect func([]byte) bool) error {
	target, err := url.JoinPath(c.cfg.UpstreamURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
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
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		onHeaders(resp.StatusCode, resp.Header)
		if err := stream.Copy(ctx, dst, resp.Body, inspect); err != nil {
			if err == io.ErrClosedPipe {
				return &InspectionBlockedError{ResponseStarted: true}
			}
			return err
		}
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.cfg.MaxResponseBytes)+1))
	if err != nil {
		return err
	}
	if len(data) > c.cfg.MaxResponseBytes {
		return fmt.Errorf("upstream response exceeds limit")
	}
	if !inspect(data) {
		return &InspectionBlockedError{}
	}
	onHeaders(resp.StatusCode, resp.Header)
	_, err = dst.Write(data)
	return err
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "host" || lower == "content-length" || lower == "authorization" || lower == "x-tenant-id" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
