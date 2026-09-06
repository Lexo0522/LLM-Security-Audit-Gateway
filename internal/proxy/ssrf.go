package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/config"
)

// ErrUpstreamTargetDenied marks a target the SSRF guard refuses to contact.
// The guard never embeds resolved addresses or credentials in the error, and
// handlers must keep the cause out of client-facing responses.
var ErrUpstreamTargetDenied = errors.New("upstream target not allowed")

// TargetPolicy decides which upstream hosts may be contacted. Denials are
// fail-closed: a host that cannot be resolved and checked is never dialed.
//
// Cloud metadata endpoints are refused in every mode, including development
// stacks with AllowPrivateNetworks.
type TargetPolicy struct {
	// AllowPrivateNetworks permits loopback, RFC1918/ULA, and ordinary
	// link-local targets. It exists for development stacks (compose runs mock
	// upstreams on internal addresses); config.Validate refuses to combine it
	// with GATEWAY_ENV=production.
	AllowPrivateNetworks bool
	Resolver             ipResolver
	log                  *slog.Logger
}

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

func NewTargetPolicy(cfg config.Config) *TargetPolicy {
	return &TargetPolicy{AllowPrivateNetworks: cfg.UpstreamAllowPrivateNetworks, Resolver: net.DefaultResolver, log: slog.Default()}
}

// ValidateTarget checks the textual form of a configured upstream URL and,
// when the host resolves, every resolved address. An unresolvable host is
// accepted at configuration time — DNS may not be set up yet — because the
// dialer re-checks every connection at request time.
func (p *TargetPolicy) ValidateTarget(ctx context.Context, rawURL string) error {
	reason := p.checkURL(ctx, rawURL)
	if reason == "" {
		return nil
	}
	p.logDenial(hostOf(rawURL), reason)
	return fmt.Errorf("%w: %s", ErrUpstreamTargetDenied, reason)
}

func (p *TargetPolicy) checkURL(ctx context.Context, rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "malformed URL"
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return "scheme must be http or https"
	}
	if parsed.User != nil {
		return "user info is not allowed"
	}
	host := parsed.Hostname()
	if host == "" {
		return "host is required"
	}
	if ip := net.ParseIP(host); ip != nil {
		return p.denyReason(ip)
	}
	ips, err := p.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return ""
	}
	for _, addr := range ips {
		if reason := p.denyReason(addr.IP); reason != "" {
			return reason
		}
	}
	return ""
}

// denyReason categorizes an address the policy refuses to dial; the empty
// string means the address is acceptable. Categories are internal labels that
// name no address.
func (p *TargetPolicy) denyReason(ip net.IP) string {
	switch classifyIP(ip) {
	case "":
		return ""
	case "metadata":
		return "cloud metadata endpoint"
	case "loopback", "private", "link-local":
		if p.AllowPrivateNetworks {
			return ""
		}
		return "private or loopback network"
	default:
		return "non-routable address"
	}
}

func (p *TargetPolicy) deny(host, reason string) error {
	p.logDenial(host, reason)
	return fmt.Errorf("%w: %s", ErrUpstreamTargetDenied, reason)
}

func (p *TargetPolicy) logDenial(host, reason string) {
	if p.log != nil {
		// Host and category only: never the resolved internal address, the
		// request path, or any credential.
		p.log.Warn("upstream target denied by SSRF guard", slog.String("host", host), slog.String("reason", reason))
	}
}

// redirectPolicy refuses redirects that move the request to another host or
// scheme. The dialer validates every redirect hop independently, but a redirect
// must also stay inside the configured target's boundary.
func (p *TargetPolicy) redirectPolicy() func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("%w: more than 3 redirects", ErrUpstreamTargetDenied)
		}
		first := via[0]
		if !strings.EqualFold(req.URL.Scheme, first.URL.Scheme) {
			return fmt.Errorf("%w: redirect changed the scheme", ErrUpstreamTargetDenied)
		}
		if !strings.EqualFold(req.URL.Host, first.URL.Host) {
			return fmt.Errorf("%w: redirect changed the host", ErrUpstreamTargetDenied)
		}
		return nil
	}
}

// classifyIP buckets an address into a fixed category. Metadata ranges are
// checked before the generic classes so development mode cannot reach them.
func classifyIP(ip net.IP) string {
	if ip == nil {
		return "invalid"
	}
	if ip4 := ip.To4(); ip4 != nil {
		// ip.To4() also matches IPv4-mapped IPv6 addresses, so an encoded
		// ::ffff:10.0.0.1 is judged by its IPv4 value.
		switch {
		case ip4.IsUnspecified():
			return "unspecified"
		case ip4.IsLoopback():
			return "loopback"
		case ip4.Equal(net.IPv4(169, 254, 169, 254)):
			return "metadata"
		case ip4.Equal(net.IPv4(168, 63, 129, 16)): // Azure platform endpoint
			return "metadata"
		case ip4.IsPrivate():
			return "private"
		case ip4.IsLinkLocalUnicast():
			return "link-local"
		case ip4.IsLinkLocalMulticast(), ip4.IsMulticast(), ip4.Equal(net.IPv4bcast):
			return "multicast"
		case isReservedIPv4(ip4):
			return "reserved"
		}
		return ""
	}
	switch {
	case ip.Equal(net.IPv6loopback):
		return "loopback"
	case ip.Equal(net.ParseIP("fd00:ec2::254")): // AWS metadata over IPv6
		return "metadata"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsPrivate():
		return "private"
	case ip.IsMulticast(), ip.IsLinkLocalMulticast():
		return "multicast"
	case isReservedIPv6(ip):
		return "reserved"
	}
	return ""
}

// isReservedIPv4 reports special-use ranges that are never valid upstream
// targets: the "this network" block, CGNAT (which also carries the Alibaba
// Cloud metadata endpoint), benchmarking, documentation, and class E.
func isReservedIPv4(ip net.IP) bool {
	return anyBlockContains(ip,
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
	)
}

func isReservedIPv6(ip net.IP) bool {
	return anyBlockContains(ip,
		"100::/64", // discard-only
		"2001:2::/48",
		"2001:db8::/32",
	)
}

func anyBlockContains(ip net.IP, cidrs ...string) bool {
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func hostOf(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// safeDialer dials upstream addresses only after every IP the host resolves to
// passes the policy. DNS rebinding cannot slip through: each connection
// re-resolves and re-checks, and the connection targets the validated IP while
// TLS keeps the URL hostname for SNI and certificate verification.
type safeDialer struct {
	policy *TargetPolicy
	dialer *net.Dialer
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, d.policy.deny("", "malformed dial address")
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := d.policy.denyReason(ip); reason != "" {
			return nil, d.policy.deny(host, reason)
		}
		return d.dialer.DialContext(ctx, network, address)
	}
	ips, err := d.policy.Resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, d.policy.deny(host, "unresolvable host")
	}
	var lastErr error
	for _, addr := range ips {
		if reason := d.policy.denyReason(addr.IP); reason != "" {
			return nil, d.policy.deny(host, reason)
		}
		conn, dialErr := d.dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no dialable address", ErrUpstreamTargetDenied)
	}
	return nil, lastErr
}

// dialTimeout matches the per-connection budget the transport used before the
// SSRF guard wrapped it.
const dialTimeout = 5 * time.Second
