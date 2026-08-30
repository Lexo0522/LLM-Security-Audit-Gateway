package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/stream"
)

func TestCopyHeadersDoesNotForwardCallerIdentity(t *testing.T) {
	source := http.Header{"Authorization": []string{"Bearer client-key"}, "X-Tenant-ID": []string{"forged"}, "X-Request-ID": []string{"request-a"}}
	destination := http.Header{}
	copyHeaders(destination, source)
	if destination.Get("Authorization") != "" || destination.Get("X-Tenant-ID") != "" || destination.Get("X-Request-ID") != "request-a" {
		t.Fatalf("unexpected forwarded headers: %#v", destination)
	}
}

func TestSSEBlockReportsStartedResponseAndDoesNotWriteMatchedEvent(t *testing.T) {
	raw := "data: {\"choices\":[{\"delta\":{\"content\":\"blocked\"}}]}\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer upstream.Close()
	client := New(config.Config{UpstreamURL: upstream.URL, RequestTimeoutMS: 1000})
	var destination bytes.Buffer
	headerCalls := 0
	err := client.Do(context.Background(), http.MethodPost, "/v1/chat/completions", "", nil, nil, &destination, func(int, http.Header) {
		headerCalls++
	}, nil, func(stream.Event) bool { return false })
	var blocked *InspectionBlockedError
	if !errors.As(err, &blocked) || !blocked.ResponseStarted || blocked.Code != "stream_policy_blocked" {
		t.Fatalf("error=%#v", err)
	}
	if headerCalls != 1 || destination.Len() != 0 {
		t.Fatalf("headers=%d destination=%q", headerCalls, destination.Bytes())
	}
}

func TestNonSSEInspectionRunsBeforeHeadersAndBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	client := New(config.Config{UpstreamURL: upstream.URL, RequestTimeoutMS: 1000, MaxResponseBytes: 1024})
	var destination bytes.Buffer
	inspected := false
	headersStarted := false
	err := client.Do(context.Background(), http.MethodPost, "/v1/chat/completions", "", nil, nil, &destination, func(status int, headers http.Header) {
		headersStarted = true
		if status != http.StatusCreated || headers.Get("Content-Type") != "application/json" {
			t.Fatalf("headers status=%d headers=%v", status, headers)
		}
	}, func(body []byte) bool {
		inspected = true
		if headersStarted || string(body) != `{"ok":true}` {
			t.Fatalf("headersStarted=%v body=%q", headersStarted, body)
		}
		return true
	}, nil)
	if err != nil || !inspected || !headersStarted || destination.String() != `{"ok":true}` {
		t.Fatalf("err=%v inspected=%v headers=%v destination=%q", err, inspected, headersStarted, destination.String())
	}
}

func TestCopyHeadersStripsAcceptEncoding(t *testing.T) {
	source := http.Header{"Accept-Encoding": []string{"br"}}
	destination := http.Header{}
	copyHeaders(destination, source)
	if destination.Get("Accept-Encoding") != "" {
		t.Fatal("client accept-encoding must not reach upstream")
	}
}

func TestClientAcceptEncodingNeverReachesUpstream(t *testing.T) {
	var gotAcceptEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAcceptEncoding = r.Header.Get("Accept-Encoding")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	client := New(config.Config{UpstreamURL: upstream.URL, RequestTimeoutMS: 1000, MaxResponseBytes: 1024})
	headers := http.Header{}
	headers.Set("Accept-Encoding", "br")
	var destination bytes.Buffer
	if err := client.Do(context.Background(), http.MethodPost, "/v1/chat/completions", "", nil, headers, &destination, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if gotAcceptEncoding != "gzip" {
		t.Fatalf("upstream accept-encoding=%q, want transport-negotiated gzip", gotAcceptEncoding)
	}
}

func TestUnsolicitedGzipResponseIsDecompressedForAudit(t *testing.T) {
	plain := `{"ok":true}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "x-gzip")
		gzipWriter := gzip.NewWriter(w)
		_, _ = io.WriteString(gzipWriter, plain)
		_ = gzipWriter.Close()
	}))
	defer upstream.Close()
	client := New(config.Config{UpstreamURL: upstream.URL, RequestTimeoutMS: 1000, MaxResponseBytes: 1024})
	var destination bytes.Buffer
	var forwarded http.Header
	err := client.Do(context.Background(), http.MethodPost, "/v1/chat/completions", "", nil, nil, &destination, func(_ int, headers http.Header) {
		forwarded = headers
	}, func([]byte) bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if destination.String() != plain {
		t.Fatalf("decompressed body mismatch: %q", destination.String())
	}
	if forwarded.Get("Content-Encoding") != "" {
		t.Fatalf("content-encoding must be dropped after decompression: %v", forwarded)
	}
}

func TestQueryStringsAreForwardedUpstream(t *testing.T) {
	var gotPath, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	client := New(config.Config{UpstreamURL: upstream.URL, RequestTimeoutMS: 1000, MaxResponseBytes: 1024})
	var destination bytes.Buffer
	if err := client.Do(context.Background(), http.MethodPost, "/v1/chat/completions", "api-version=2024-01&user=alice", nil, nil, &destination, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/chat/completions" || gotQuery != "api-version=2024-01&user=alice" {
		t.Fatalf("path=%q query=%q", gotPath, gotQuery)
	}
}
