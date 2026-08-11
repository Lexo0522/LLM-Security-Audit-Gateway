package rule

import (
	"context"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
)

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
