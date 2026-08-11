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
	onHeaders(resp.StatusCode, resp.Header)
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return stream.Copy(ctx, dst, resp.Body, inspect)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.cfg.MaxResponseBytes)+1))
	if err != nil {
		return err
	}
	if len(data) > c.cfg.MaxResponseBytes {
		return fmt.Errorf("upstream response exceeds limit")
	}
	if !inspect(data) {
		return io.ErrClosedPipe
	}
	_, err = dst.Write(data)
	return err
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "host" || lower == "content-length" || lower == "authorization" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
