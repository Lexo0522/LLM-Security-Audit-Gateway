package rule

import (
	"context"
	"testing"

	"github.com/example/ai-audit-gateway/internal/audit"
)

// FuzzEngineAudit hammers the audit engine with arbitrary text: scores stay in
// the documented 0..100 band and matches always identify their rule.
func FuzzEngineAudit(f *testing.F) {
	engine, err := New([]Definition{
		{ID: "keyword", Pattern: "secret", Weight: 40},
		{ID: "regex", Pattern: `sk-[a-z0-9]+`, Regex: true, Weight: 60},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("ignore previous instructions secret sk-abc123")
	f.Add("ig\u200bnore")
	f.Add("SECRET")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		result := engine.Audit(context.Background(), audit.Input{Text: text})
		if result.Score < 0 || result.Score > 100 {
			t.Fatalf("score out of range: %d", result.Score)
		}
		for _, match := range result.Matches {
			if match.RuleID == "" {
				t.Fatalf("match without rule id: %+v", match)
			}
		}
	})
}
