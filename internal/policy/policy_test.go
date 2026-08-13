package policy

import (
	"context"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
)

func TestDecideThresholds(t *testing.T) {
	if Decide(audit.Result{Score: 29}, Policy{}) != Allow {
		t.Fatal("29 should allow")
	}
	if Decide(audit.Result{Score: 30}, Policy{}) != Monitor {
		t.Fatal("30 should monitor")
	}
	if Decide(audit.Result{Score: 80}, Policy{}) != Block {
		t.Fatal("80 should block")
	}
}

type policySource struct{ policies []Policy }

func (s policySource) ListPolicies(context.Context) ([]Policy, error) { return s.policies, nil }

func TestResolverPrecedence(t *testing.T) {
	resolver := NewResolver(policySource{policies: []Policy{
		{ID: "global-default", Scope: "global", RoutePath: "*", Direction: "request", MonitorAt: 30, InterventionAt: 80, InterventionAction: Block, AuditorFailureMode: "fail_open"},
		{ID: "global-route", Scope: "global", RoutePath: "/v1/chat/completions", Direction: "request", MonitorAt: 25, InterventionAt: 70, InterventionAction: Block, AuditorFailureMode: "fail_open"},
		{ID: "tenant-default", Scope: "tenant:tenant-a", RoutePath: "*", Direction: "request", MonitorAt: 20, InterventionAt: 60, InterventionAction: Redact, AuditorFailureMode: "fail_closed"},
		{ID: "tenant-route", Scope: "tenant:tenant-a", RoutePath: "/v1/chat/completions", Direction: "request", MonitorAt: 10, InterventionAt: 50, InterventionAction: Block, AuditorFailureMode: "fail_closed"},
		{ID: "responses-route", Scope: "tenant:tenant-a", RoutePath: "/v1/responses", Direction: "response", MonitorAt: 15, InterventionAt: 55, InterventionAction: Block, AuditorFailureMode: "fail_open"},
	}})
	if err := resolver.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := resolver.Resolve("tenant-a", "/v1/chat/completions", "request"); got.ID != "tenant-route" {
		t.Fatalf("got %q", got.ID)
	}
	if got := resolver.Resolve("tenant-a", "/v1/completions", "request"); got.ID != "tenant-default" {
		t.Fatalf("got %q", got.ID)
	}
	if got := resolver.Resolve("tenant-b", "/v1/chat/completions", "request"); got.ID != "global-route" {
		t.Fatalf("got %q", got.ID)
	}
	if got := resolver.Resolve("tenant-b", "/v1/embeddings", "request"); got.ID != "global-default" {
		t.Fatalf("got %q", got.ID)
	}
	if got := resolver.Resolve("tenant-a", "/v1/responses", "response"); got.ID != "responses-route" {
		t.Fatalf("responses policy got %q", got.ID)
	}
}
