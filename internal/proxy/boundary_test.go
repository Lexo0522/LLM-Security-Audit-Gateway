package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/config"
)

func TestSSEUpstreamCanceledWhenGatewayContextEnds(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		// Hold the request open until the gateway cancels it.
		<-r.Context().Done()
		close(upstreamCanceled)
	}))
	defer upstream.Close()

	client := New(config.Config{RequestTimeoutMS: 1000, MaxResponseBytes: 1 << 20, SSEMaxEventBytes: 1 << 20, UpstreamAllowPrivateNetworks: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.DoUpstream(ctx, Upstream{BaseURL: upstream.URL, Enabled: true}, http.MethodPost, "/v1/chat/completions", "", nil, nil, io.Discard, nil, nil, nil)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("upstream never received the request")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-upstreamCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("the upstream request must be canceled once the gateway context ends")
	}
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("DoUpstream err=%v", err)
	}
}

func TestFailedUpstreamRequestsAreNeverRetried(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream exploded"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	client := New(config.Config{RequestTimeoutMS: 1000, MaxResponseBytes: 1 << 20, UpstreamAllowPrivateNetworks: true})
	var dst bytes.Buffer
	if err := client.DoUpstream(context.Background(), Upstream{BaseURL: upstream.URL, Enabled: true}, http.MethodPost, "/v1/chat/completions", "", nil, nil, &dst, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d, want exactly one attempt for a non-idempotent POST", hits.Load())
	}
}

func TestEmptyOrUnsupportedTargetsMakeNoRequest(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()

	client := New(config.Config{RequestTimeoutMS: 1000, MaxResponseBytes: 1 << 20, UpstreamAllowPrivateNetworks: true})
	ctx := context.Background()
	if err := client.DoUpstream(ctx, Upstream{BaseURL: "  ", Enabled: true}, http.MethodPost, "/v1/chat/completions", "", nil, nil, io.Discard, nil, nil, nil); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("empty base URL err=%v", err)
	}
	if err := client.DoUpstream(ctx, Upstream{BaseURL: "ftp://" + strings.TrimPrefix(upstream.URL, "http://"), Enabled: true}, http.MethodPost, "/v1/chat/completions", "", nil, nil, io.Discard, nil, nil, nil); err == nil {
		t.Fatal("an unsupported scheme must fail")
	}
	if err := client.DoUpstream(ctx, Upstream{BaseURL: upstream.URL, Enabled: false}, http.MethodPost, "/v1/chat/completions", "", nil, nil, io.Discard, nil, nil, nil); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("disabled upstream err=%v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the upstream was contacted %d times", hits.Load())
	}
}
