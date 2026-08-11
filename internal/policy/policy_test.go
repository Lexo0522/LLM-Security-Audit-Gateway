package policy

import (
	"github.com/example/ai-audit-gateway/internal/audit"
	"testing"
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
