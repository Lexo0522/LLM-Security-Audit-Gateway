package storage

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type RuleSet struct {
	Version   string            `json:"version"`
	Scope     string            `json:"scope"`
	Status    string            `json:"status"`
	Rules     []rule.Definition `json:"rules"`
	CreatedAt time.Time         `json:"created_at"`
}

type Repository struct{ pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Repository, error) {
	if url == "" {
		return nil, nil
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Repository{pool: pool}, nil
}
func (r *Repository) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}
func (r *Repository) Migrate(ctx context.Context) error {
	if r == nil {
		return nil
	}
	files, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, f := range files {
		data, err := migrations.ReadFile("migrations/" + f.Name())
		if err != nil {
			return err
		}
		if _, err = r.pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("migration %s: %w", f.Name(), err)
		}
	}
	return nil
}
func (r *Repository) CreateRuleSet(ctx context.Context, scope string, definitions []rule.Definition) (RuleSet, error) {
	if r == nil {
		return RuleSet{}, fmt.Errorf("postgres disabled")
	}
	if scope == "" {
		scope = "global"
	}
	if err := validate(scope, definitions); err != nil {
		return RuleSet{}, err
	}
	version := uuid.NewString()
	raw, err := json.Marshal(definitions)
	if err != nil {
		return RuleSet{}, err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO rule_sets(version, scope, status, rules) VALUES($1,$2,'draft',$3)`, version, scope, raw)
	if err != nil {
		return RuleSet{}, err
	}
	return r.GetRuleSet(ctx, version)
}
func (r *Repository) GetRuleSet(ctx context.Context, version string) (RuleSet, error) {
	var set RuleSet
	var raw []byte
	err := r.pool.QueryRow(ctx, `SELECT version,scope,status,rules,created_at FROM rule_sets WHERE version=$1`, version).Scan(&set.Version, &set.Scope, &set.Status, &raw, &set.CreatedAt)
	if err == nil {
		err = json.Unmarshal(raw, &set.Rules)
	}
	return set, err
}
func (r *Repository) ListRuleSets(ctx context.Context) ([]RuleSet, error) {
	rows, err := r.pool.Query(ctx, `SELECT version,scope,status,rules,created_at FROM rule_sets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []RuleSet
	for rows.Next() {
		var s RuleSet
		var raw []byte
		if err = rows.Scan(&s.Version, &s.Scope, &s.Status, &raw, &s.CreatedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &s.Rules); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}
func (r *Repository) Publish(ctx context.Context, version string) (RuleSet, error) {
	set, err := r.GetRuleSet(ctx, version)
	if err != nil {
		return RuleSet{}, err
	}
	if err = validate(set.Scope, set.Rules); err != nil {
		return RuleSet{}, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return RuleSet{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE rule_sets SET status='archived' WHERE scope=$1 AND status='published'`, set.Scope); err != nil {
		return RuleSet{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE rule_sets SET status='published', published_at=now() WHERE version=$1`, version); err != nil {
		return RuleSet{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return RuleSet{}, err
	}
	return r.GetRuleSet(ctx, version)
}
func (r *Repository) Rollback(ctx context.Context, scope, version string) (RuleSet, error) {
	set, err := r.GetRuleSet(ctx, version)
	if err != nil {
		return RuleSet{}, err
	}
	if set.Scope != scope {
		return RuleSet{}, fmt.Errorf("rule set does not belong to scope")
	}
	return r.Publish(ctx, version)
}
func (r *Repository) Active(ctx context.Context, scope string) (RuleSet, error) {
	var version string
	err := r.pool.QueryRow(ctx, `SELECT version FROM rule_sets WHERE scope=$1 AND status='published' ORDER BY published_at DESC LIMIT 1`, scope).Scan(&version)
	if err != nil {
		return RuleSet{}, err
	}
	return r.GetRuleSet(ctx, version)
}
func (r *Repository) ActiveDefinitions(ctx context.Context, scope string) ([]rule.Definition, string, error) {
	set, err := r.Active(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	return set.Rules, set.Version, nil
}
func (r *Repository) EnsureBootstrap(ctx context.Context, definitions []rule.Definition) (RuleSet, error) {
	if r == nil {
		return RuleSet{}, nil
	}
	set, err := r.Active(ctx, "global")
	if err == nil {
		return set, nil
	}
	set, err = r.CreateRuleSet(ctx, "global", definitions)
	if err != nil {
		return RuleSet{}, err
	}
	return r.Publish(ctx, set.Version)
}
func (r *Repository) StoreEvents(ctx context.Context, events []audit.Event) error {
	if r == nil || len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		matches, _ := json.Marshal(e.Matches)
		metadata, _ := json.Marshal(e.Metadata)
		var auditor []byte
		if e.Auditor != nil {
			auditor, _ = json.Marshal(e.Auditor)
		}
		batch.Queue(`INSERT INTO audit_records(id,event_id,request_id,tenant_id,direction,path,model,risk_score,decision,rule_version,matches,auditor,auditor_error,latency_ms,body_bytes,content_sha256,metadata,created_at) VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT (event_id) DO NOTHING`, e.EventID, e.RequestID, e.TenantID, e.Direction, e.Path, e.Model, e.RiskScore, e.Decision, e.RuleVersion, matches, auditor, e.AuditorError, e.LatencyMS, e.BodyBytes, e.ContentSHA256, metadata, e.EventTime)
	}
	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range events {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}
func validate(scope string, definitions []rule.Definition) error {
	if scope != "global" && !strings.HasPrefix(scope, "tenant:") {
		return fmt.Errorf("scope must be global or tenant:<id>")
	}
	if len(definitions) == 0 || len(definitions) > 1000 {
		return fmt.Errorf("rule count must be 1..1000")
	}
	_, err := rule.New(definitions)
	return err
}
