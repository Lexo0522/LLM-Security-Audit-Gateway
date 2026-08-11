package audit

import "context"

type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

type Input struct {
	RequestID string
	TenantID  string
	Direction Direction
	Model     string
	Text      string
}

type Match struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Weight   int    `json:"weight"`
	Evidence string `json:"evidence"`
}

type Result struct {
	Score   int     `json:"risk_score"`
	Matches []Match `json:"matches"`
}

type Engine interface {
	Audit(context.Context, Input) Result
}
