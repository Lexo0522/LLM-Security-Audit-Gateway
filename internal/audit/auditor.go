package audit

import (
	"context"
	"time"
)

type Auditor interface {
	Audit(context.Context, Input) (ModelResult, error)
	Health(context.Context) error
	Name() string
}

type ModelResult struct {
	Verdict    string        `json:"verdict"`
	Score      int           `json:"risk_score"`
	Confidence float64       `json:"confidence"`
	Categories []string      `json:"categories"`
	Evidence   string        `json:"evidence"`
	Model      string        `json:"model"`
	Latency    time.Duration `json:"-"`
}

type NoopAuditor struct{}

func (NoopAuditor) Audit(context.Context, Input) (ModelResult, error) {
	return ModelResult{Verdict: "unknown"}, nil
}
func (NoopAuditor) Health(context.Context) error { return nil }
func (NoopAuditor) Name() string                 { return "noop" }
