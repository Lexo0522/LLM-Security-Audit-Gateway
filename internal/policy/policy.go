package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
)

type Decision string

const (
	Allow   Decision = "allow"
	Block   Decision = "block"
	Monitor Decision = "monitor"
	Redact  Decision = "redact"
)

type Policy struct {
	ID                 string    `json:"id"`
	Scope              string    `json:"scope"`
	RoutePath          string    `json:"route_path"`
	Direction          string    `json:"direction"`
	MonitorAt          int       `json:"monitor_at"`
	InterventionAt     int       `json:"intervention_at"`
	InterventionAction Decision  `json:"intervention_action"`
	AuditorFailureMode string    `json:"auditor_failure_mode"`
	Revision           int64     `json:"revision"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func Default() Policy {
	return Policy{Scope: "global", RoutePath: "*", Direction: "request", MonitorAt: 30, InterventionAt: 80, InterventionAction: Block, AuditorFailureMode: "fail_open", Revision: 1}
}

func (p Policy) Normalized() Policy {
	if p.Scope == "" {
		p.Scope = "global"
	}
	if p.RoutePath == "" {
		p.RoutePath = "*"
	}
	if p.Direction == "" {
		p.Direction = "request"
	}
	if p.MonitorAt <= 0 {
		p.MonitorAt = 30
	}
	if p.InterventionAt <= 0 {
		p.InterventionAt = 80
	}
	if p.InterventionAction == "" {
		p.InterventionAction = Block
	}
	if p.AuditorFailureMode == "" {
		p.AuditorFailureMode = "fail_open"
	}
	if p.Revision <= 0 {
		p.Revision = 1
	}
	return p
}

func Decide(result audit.Result, configured Policy) Decision {
	configured = configured.Normalized()
	if result.Score >= configured.InterventionAt {
		return configured.InterventionAction
	}
	if result.Score >= configured.MonitorAt {
		return Monitor
	}
	return Allow
}

// Elevate applies a rule's explicit action without ever lowering the policy decision.
func Elevate(result audit.Result, decision Decision) Decision {
	for _, match := range result.Matches {
		switch Decision(match.Action) {
		case Block:
			return Block
		case Redact:
			if decision != Block {
				decision = Redact
			}
		case Monitor:
			if decision == Allow {
				decision = Monitor
			}
		}
	}
	return decision
}

type Source interface {
	ListPolicies(context.Context) ([]Policy, error)
}

// Resolver publishes complete immutable snapshots, so policy updates never
// expose a partial set of tenant/route overrides.
type Resolver struct {
	source  Source
	current atomic.Pointer[snapshot]
}
type snapshot struct {
	policies []Policy
	stale    bool
}
type Status struct {
	Hash  string `json:"hash"`
	Stale bool   `json:"stale"`
	Count int    `json:"count"`
}

func NewResolver(source Source) *Resolver {
	r := &Resolver{source: source}
	r.current.Store(&snapshot{policies: []Policy{Default()}})
	return r
}
func (r *Resolver) Refresh(ctx context.Context) error {
	if r.source == nil {
		return nil
	}
	policies, err := r.source.ListPolicies(ctx)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		policies = []Policy{Default()}
	}
	compiled := make([]Policy, len(policies))
	for i, p := range policies {
		if err := Validate(p); err != nil {
			return err
		}
		compiled[i] = p.Normalized()
	}
	r.current.Store(&snapshot{policies: compiled, stale: false})
	return nil
}
func (r *Resolver) MarkStale() {
	current := r.current.Load()
	if current == nil {
		return
	}
	r.current.Store(&snapshot{policies: current.policies, stale: true})
}
func (r *Resolver) Status() Status {
	current := r.current.Load()
	if current == nil {
		return Status{Stale: true}
	}
	value := fmt.Sprintf("%#v", current.policies)
	sum := sha256.Sum256([]byte(value))
	return Status{Hash: hex.EncodeToString(sum[:]), Count: len(current.policies), Stale: current.stale}
}
func (r *Resolver) Resolve(tenant, route, direction string) Policy {
	current := r.current.Load()
	if current == nil {
		return Default()
	}
	best := Default()
	bestScore := -1
	for _, candidate := range current.policies {
		if candidate.Direction != direction {
			continue
		}
		score := specificity(candidate, tenant, route)
		if score > bestScore {
			best, bestScore = candidate, score
		}
	}
	return best.Normalized()
}
func specificity(candidate Policy, tenant, route string) int {
	scopeScore := 0
	if candidate.Scope == "tenant:"+tenant {
		scopeScore = 2
	} else if candidate.Scope == "global" {
		scopeScore = 0
	} else {
		return -1
	}
	routeScore := 0
	if candidate.RoutePath == route {
		routeScore = 1
	} else if candidate.RoutePath != "*" {
		return -1
	}
	return scopeScore*2 + routeScore
}

func Validate(p Policy) error {
	p = p.Normalized()
	if p.Scope != "global" && (!strings.HasPrefix(p.Scope, "tenant:") || len(strings.TrimPrefix(p.Scope, "tenant:")) == 0) {
		return fmt.Errorf("policy scope must be global or tenant:<id>")
	}
	if p.RoutePath != "*" && p.RoutePath != "/v1/chat/completions" && p.RoutePath != "/v1/completions" && p.RoutePath != "/v1/embeddings" && p.RoutePath != "/v1/responses" {
		return fmt.Errorf("unsupported policy route_path")
	}
	if p.Direction != "request" && p.Direction != "response" {
		return fmt.Errorf("policy direction must be request or response")
	}
	if p.MonitorAt < 1 || p.InterventionAt > 100 || p.MonitorAt >= p.InterventionAt {
		return fmt.Errorf("policy thresholds must satisfy 1 <= monitor_at < intervention_at <= 100")
	}
	if p.InterventionAction != Block && p.InterventionAction != Redact {
		return fmt.Errorf("intervention_action must be block or redact")
	}
	if p.AuditorFailureMode != "fail_open" && p.AuditorFailureMode != "fail_closed" {
		return fmt.Errorf("auditor_failure_mode must be fail_open or fail_closed")
	}
	return nil
}
