package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/config"
)

type fakeResolver struct {
	records map[string][]net.IPAddr
	err     error
}

func (r *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.records[host], nil
}

func TestDenyReasonCategorizesAddresses(t *testing.T) {
	public := &TargetPolicy{Resolver: &fakeResolver{}}
	dev := &TargetPolicy{AllowPrivateNetworks: true, Resolver: &fakeResolver{}}
	for _, tc := range []struct {
		ip         string
		wantPublic string
		wantDev    string
	}{
		{"8.8.8.8", "", ""},
		{"127.0.0.1", "private or loopback network", ""},
		{"10.1.2.3", "private or loopback network", ""},
		{"172.16.0.9", "private or loopback network", ""},
		{"172.31.255.254", "private or loopback network", ""},
		{"192.168.10.10", "private or loopback network", ""},
		{"169.254.10.1", "private or loopback network", ""},
		{"::1", "private or loopback network", ""},
		{"fe80::1", "private or loopback network", ""},
		{"fd12::1", "private or loopback network", ""},
		{"::ffff:10.0.0.5", "private or loopback network", ""},
		// Metadata endpoints are denied in every mode.
		{"169.254.169.254", "cloud metadata endpoint", "cloud metadata endpoint"},
		{"168.63.129.16", "cloud metadata endpoint", "cloud metadata endpoint"},
		{"fd00:ec2::254", "cloud metadata endpoint", "cloud metadata endpoint"},
		// Special-use ranges stay denied even with the development switch.
		{"0.0.0.0", "non-routable address", "non-routable address"},
		{"100.64.0.1", "non-routable address", "non-routable address"},
		{"100.100.200.200", "non-routable address", "non-routable address"},
		{"198.18.0.1", "non-routable address", "non-routable address"},
		{"192.0.2.1", "non-routable address", "non-routable address"},
		{"240.0.0.1", "non-routable address", "non-routable address"},
		{"255.255.255.255", "non-routable address", "non-routable address"},
		{"224.0.0.1", "non-routable address", "non-routable address"},
		{"2001:db8::1", "non-routable address", "non-routable address"},
		{"2606:4700::1111", "", ""},
	} {
		if got := public.denyReason(net.ParseIP(tc.ip)); got != tc.wantPublic {
			t.Errorf("%s: public mode reason %q, want %q", tc.ip, got, tc.wantPublic)
		}
		if got := dev.denyReason(net.ParseIP(tc.ip)); got != tc.wantDev {
			t.Errorf("%s: development mode reason %q, want %q", tc.ip, got, tc.wantDev)
		}
	}
	if public.denyReason(nil) == "" {
		t.Error("nil address must be denied")
	}
}

func TestValidateTarget(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]net.IPAddr{
		"public.test":  {{IP: net.ParseIP("93.184.216.34")}},
		"private.test": {{IP: net.ParseIP("10.0.0.7")}},
	}}
	public := &TargetPolicy{Resolver: resolver}
	dev := &TargetPolicy{AllowPrivateNetworks: true, Resolver: resolver}
	ctx := context.Background()

	for _, tc := range []struct {
		name, rawURL string
		policy       *TargetPolicy
		wantDenied   bool
	}{
		{"public hostname", "http://public.test", public, false},
		{"public hostname in dev", "http://public.test", dev, false},
		{"private hostname", "http://private.test", public, true},
		{"private hostname in dev", "http://private.test", dev, false},
		{"metadata literal", "http://169.254.169.254/latest/meta-data/", public, true},
		{"metadata literal in dev", "http://169.254.169.254/latest/meta-data/", dev, true},
		{"loopback with port", "http://127.0.0.1:8080", public, true},
		{"ftp scheme", "ftp://public.test", public, true},
		{"unix socket scheme", "unix:///var/run/upstream.sock", public, true},
		{"user info", "http://user:pass@public.test", public, true},
		{"missing host", "http://", public, true},
		{"unresolvable host accepted at configuration time", "http://later.test", public, false},
	} {
		err := tc.policy.ValidateTarget(ctx, tc.rawURL)
		if denied := err != nil; denied != tc.wantDenied {
			t.Errorf("%s: denied=%v err=%v, want denied=%v", tc.name, denied, err, tc.wantDenied)
		}
		if err != nil && !errors.Is(err, ErrUpstreamTargetDenied) {
			t.Errorf("%s: error does not wrap ErrUpstreamTargetDenied: %v", tc.name, err)
		}
	}
}

func TestSafeDialerValidatesResolvedAddresses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reached")
	}))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	resolver := &fakeResolver{records: map[string][]net.IPAddr{
		"upstream.test": {{IP: net.ParseIP("127.0.0.1")}},
	}}

	dial := func(policy *TargetPolicy, address string) error {
		dialer := &safeDialer{policy: policy, dialer: &net.Dialer{Timeout: 2 * time.Second}}
		conn, err := dialer.DialContext(context.Background(), "tcp", address)
		if err != nil {
			return err
		}
		return conn.Close()
	}

	if err := dial(&TargetPolicy{AllowPrivateNetworks: true, Resolver: resolver}, "upstream.test:"+port); err != nil {
		t.Fatalf("development mode must reach the mock upstream: %v", err)
	}
	err = dial(&TargetPolicy{Resolver: resolver}, "upstream.test:"+port)
	if !errors.Is(err, ErrUpstreamTargetDenied) {
		t.Fatalf("private target must be denied: %v", err)
	}
	if err = dial(&TargetPolicy{AllowPrivateNetworks: true, Resolver: resolver}, "missing.test:"+port); !errors.Is(err, ErrUpstreamTargetDenied) {
		t.Fatalf("unresolvable host must fail closed: %v", err)
	}
	if err = dial(&TargetPolicy{Resolver: resolver}, "169.254.169.254:80"); !errors.Is(err, ErrUpstreamTargetDenied) {
		t.Fatalf("metadata literal must be denied: %v", err)
	}
}

func TestRedirectsStayOnTheConfiguredHostAndScheme(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/final", http.StatusFound)
	})
	mux.HandleFunc("/v1/final", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "final")
	})
	mux.HandleFunc("/v1/cross-host", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/v1/escape", http.StatusFound)
	})
	mux.HandleFunc("/v1/cross-scheme", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/v1/escape", http.StatusFound)
	})
	mux.HandleFunc("/v1/spiral", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/spiral1", http.StatusFound)
	})
	mux.HandleFunc("/v1/spiral1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/spiral2", http.StatusFound)
	})
	mux.HandleFunc("/v1/spiral2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/spiral3", http.StatusFound)
	})
	upstream := httptest.NewServer(mux)
	defer upstream.Close()

	client := New(config.Config{RequestTimeoutMS: 1000, MaxResponseBytes: 1 << 20, UpstreamAllowPrivateNetworks: true})
	ctx := context.Background()

	var destination bytes.Buffer
	if err := client.DoUpstream(ctx, Upstream{BaseURL: upstream.URL, Enabled: true}, http.MethodGet, "/v1/loop", "", nil, nil, &destination, nil, nil, nil); err != nil {
		t.Fatalf("same-host redirect must be followed: %v", err)
	}
	if !strings.Contains(destination.String(), "final") {
		t.Fatalf("redirected response missing: %q", destination.String())
	}

	for _, path := range []string{"/v1/cross-host", "/v1/cross-scheme", "/v1/spiral"} {
		err := client.DoUpstream(ctx, Upstream{BaseURL: upstream.URL, Enabled: true}, http.MethodGet, path, "", nil, nil, io.Discard, nil, nil, nil)
		if !errors.Is(err, ErrUpstreamTargetDenied) {
			t.Errorf("%s: must be denied, got %v", path, err)
		}
	}
}
