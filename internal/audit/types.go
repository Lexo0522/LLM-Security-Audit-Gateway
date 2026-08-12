package audit

import (
	"context"
	"time"
)

type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
	DirectionAdmin    Direction = "admin"
)

type Input struct {
	RequestID string    `json:"request_id"`
	TenantID  string    `json:"tenant_id"`
	Direction Direction `json:"direction"`
	Model     string    `json:"model"`
	Path      string    `json:"path"`
	Text      string    `json:"text"`
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

type Event struct {
	SchemaVersion string            `json:"schema_version"`
	EventID       string            `json:"event_id"`
	EventTime     time.Time         `json:"event_time"`
	RequestID     string            `json:"request_id"`
	TenantID      string            `json:"tenant_id"`
	Direction     Direction         `json:"direction"`
	Path          string            `json:"path"`
	Model         string            `json:"model,omitempty"`
	Decision      string            `json:"decision"`
	RiskScore     int               `json:"risk_score"`
	RuleVersion   string            `json:"rule_version"`
	Matches       []Match           `json:"matches,omitempty"`
	Auditor       *ModelResult      `json:"auditor,omitempty"`
	AuditorError  string            `json:"auditor_error,omitempty"`
	LatencyMS     int64             `json:"latency_ms"`
	BodyBytes     int               `json:"body_bytes"`
	ContentSHA256 string            `json:"content_sha256"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}
