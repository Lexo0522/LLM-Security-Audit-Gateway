package rule

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
)

type staticLoader struct {
	rules   []Definition
	version string
}

func (l staticLoader) ActiveDefinitions(context.Context, string) ([]Definition, string, error) {
	return l.rules, l.version, nil
}

func TestEngineMatchesKeywordAndRegex(t *testing.T) {
	engine, err := New([]Definition{
		{ID: "keyword", Pattern: "ignore previous instructions", Weight: 50},
		{ID: "secret", Pattern: `sk-[a-z0-9]+`, Regex: true, Weight: 60},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Audit(context.Background(), audit.Input{Text: "Please IGNORE previous instructions and sk-abc123"})
	if result.Score != 100 || len(result.Matches) != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestReplaceKeepsPreviousSnapshotOnCompileError(t *testing.T) {
	engine, err := New([]Definition{{ID: "safe", Pattern: "safe", Weight: 10}})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Replace([]Definition{{ID: "bad", Pattern: "[", Regex: true}}); err == nil {
		t.Fatal("expected compile error")
	}
	result := engine.Audit(context.Background(), audit.Input{Text: "safe"})
	if len(result.Matches) != 1 {
		t.Fatalf("snapshot was replaced after error: %#v", result)
	}
}

func TestRegistryReadinessRequiresManagedFreshSnapshot(t *testing.T) {
	registry, err := NewRegistry(nil, []Definition{{ID: "safe", Pattern: "safe"}})
	if err != nil {
		t.Fatal(err)
	}
	if registry.Ready() {
		t.Fatal("demo bootstrap must not be ready")
	}
	registry.SetGlobalSource("managed")
	if !registry.Ready() {
		t.Fatal("managed snapshot should be ready")
	}
	registry.MarkStale()
	if registry.Ready() {
		t.Fatal("stale snapshot must not be ready")
	}
}

func TestRegistryRefreshDoesNotInferManagedSource(t *testing.T) {
	registry, err := NewRegistry(staticLoader{rules: []Definition{{ID: "demo", Pattern: "demo"}}, version: "v1"}, []Definition{{ID: "bootstrap", Pattern: "bootstrap"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Refresh(context.Background(), "global"); err != nil {
		t.Fatal(err)
	}
	if got := registry.Status().Source; got != "demo" {
		t.Fatalf("refresh inferred source %q; want demo", got)
	}
}

type flakyLoader struct {
	calls    int32
	failures int32
	rules    []Definition
	version  string
}

func (l *flakyLoader) ActiveDefinitions(context.Context, string) ([]Definition, string, error) {
	if atomic.AddInt32(&l.calls, 1) <= l.failures {
		return nil, "", errors.New("postgres offline")
	}
	return l.rules, l.version, nil
}

func TestEnsureTenantRetriesAfterDatabaseError(t *testing.T) {
	loader := &flakyLoader{failures: 1, rules: []Definition{{ID: "tenant-rule", Pattern: "tenant-secret", Weight: 90}}, version: "t1"}
	registry, err := NewRegistry(loader, []Definition{{ID: "global-rule", Pattern: "global-secret", Weight: 90}})
	if err != nil {
		t.Fatal(err)
	}
	input := audit.Input{Text: "tenant-secret global-secret"}
	result, version := registry.Audit(context.Background(), "tenant-a", input)
	if version != "bootstrap" || len(result.Matches) != 1 || result.Matches[0].RuleID != "global-rule" {
		t.Fatalf("failed lookup must fall back to global: version=%s matches=%+v", version, result.Matches)
	}
	result, version = registry.Audit(context.Background(), "tenant-a", input)
	if version != "t1" || len(result.Matches) != 1 || result.Matches[0].RuleID != "tenant-rule" {
		t.Fatalf("tenant lookup must retry after failure: version=%s matches=%+v", version, result.Matches)
	}
	scopes := registry.TenantScopes()
	if len(scopes) != 1 || scopes[0] != "tenant:tenant-a" {
		t.Fatalf("tenant scopes=%v", scopes)
	}
}
