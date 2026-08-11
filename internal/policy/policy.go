package policy

import "github.com/example/ai-audit-gateway/internal/audit"

type Decision string

const (
	Allow   Decision = "allow"
	Block   Decision = "block"
	Monitor Decision = "monitor"
)

type Policy struct {
	MonitorAt int
	BlockAt   int
}

func Decide(result audit.Result, policy Policy) Decision {
	if policy.BlockAt <= 0 {
		policy.BlockAt = 80
	}
	if policy.MonitorAt <= 0 {
		policy.MonitorAt = 30
	}
	if result.Score >= policy.BlockAt {
		return Block
	}
	if result.Score >= policy.MonitorAt {
		return Monitor
	}
	return Allow
}
