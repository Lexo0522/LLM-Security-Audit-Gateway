package storage

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/policy"
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
func (r *Repository) CreateGatewayAPIKey(ctx context.Context, record auth.KeyRecord) (auth.KeyRecord, error) {
	if r == nil {
		return auth.KeyRecord{}, fmt.Errorf("postgres disabled")
	}
	err := r.pool.QueryRow(ctx, `INSERT INTO gateway_api_keys(id,tenant_id,prefix,key_hmac) VALUES($1,$2,$3,$4) RETURNING created_at`, record.ID, record.TenantID, record.Prefix, record.HMAC).Scan(&record.CreatedAt)
	return record, err
}
func (r *Repository) LookupGatewayAPIKey(ctx context.Context, id string) (auth.KeyRecord, bool, error) {
	if r == nil {
		return auth.KeyRecord{}, false, fmt.Errorf("postgres disabled")
	}
	var record auth.KeyRecord
	err := r.pool.QueryRow(ctx, `SELECT id,tenant_id,prefix,key_hmac,created_at,revoked_at FROM gateway_api_keys WHERE id=$1`, id).Scan(&record.ID, &record.TenantID, &record.Prefix, &record.HMAC, &record.CreatedAt, &record.RevokedAt)
	if err == pgx.ErrNoRows {
		return auth.KeyRecord{}, false, nil
	}
	return record, err == nil, err
}
func (r *Repository) ListGatewayAPIKeys(ctx context.Context, tenantID string) ([]auth.KeyRecord, error) {
	if r == nil {
		return nil, fmt.Errorf("postgres disabled")
	}
	query := `SELECT id,tenant_id,prefix,created_at,revoked_at FROM gateway_api_keys`
	var rows pgx.Rows
	var err error
	if tenantID == "" {
		rows, err = r.pool.Query(ctx, query+` ORDER BY created_at DESC`)
	} else {
		rows, err = r.pool.Query(ctx, query+` WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []auth.KeyRecord{}
	for rows.Next() {
		var record auth.KeyRecord
		if err := rows.Scan(&record.ID, &record.TenantID, &record.Prefix, &record.CreatedAt, &record.RevokedAt); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}
func (r *Repository) RevokeGatewayAPIKey(ctx context.Context, id string) (auth.KeyRecord, bool, error) {
	if r == nil {
		return auth.KeyRecord{}, false, fmt.Errorf("postgres disabled")
	}
	var record auth.KeyRecord
	err := r.pool.QueryRow(ctx, `UPDATE gateway_api_keys SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 RETURNING id,tenant_id,prefix,created_at,revoked_at`, id).Scan(&record.ID, &record.TenantID, &record.Prefix, &record.CreatedAt, &record.RevokedAt)
	if err == pgx.ErrNoRows {
		return auth.KeyRecord{}, false, nil
	}
	return record, err == nil, err
}
func (r *Repository) EnsurePolicies(ctx context.Context) error {
	if r == nil {
		return nil
	}
	for _, direction := range []string{"request", "response"} {
		defaultPolicy := policy.Default()
		defaultPolicy.Direction = direction
		if _, err := r.pool.Exec(ctx, `INSERT INTO policies(id,scope,route_path,direction,monitor_at,intervention_at,intervention_action,auditor_failure_mode,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(scope,route_path,direction) DO NOTHING`, uuid.NewString(), defaultPolicy.Scope, defaultPolicy.RoutePath, defaultPolicy.Direction, defaultPolicy.MonitorAt, defaultPolicy.InterventionAt, defaultPolicy.InterventionAction, defaultPolicy.AuditorFailureMode, defaultPolicy.Revision); err != nil {
			return err
		}
	}
	return nil
}
func (r *Repository) CreatePolicy(ctx context.Context, value policy.Policy) (policy.Policy, error) {
	if r == nil {
		return policy.Policy{}, fmt.Errorf("postgres disabled")
	}
	if err := policy.Validate(value); err != nil {
		return policy.Policy{}, err
	}
	value = value.Normalized()
	value.ID = uuid.NewString()
	err := r.pool.QueryRow(ctx, `INSERT INTO policies(id,scope,route_path,direction,monitor_at,intervention_at,intervention_action,auditor_failure_mode,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1) RETURNING created_at,updated_at`, value.ID, value.Scope, value.RoutePath, value.Direction, value.MonitorAt, value.InterventionAt, value.InterventionAction, value.AuditorFailureMode).Scan(&value.CreatedAt, &value.UpdatedAt)
	return value, err
}
func (r *Repository) ListPolicies(ctx context.Context) ([]policy.Policy, error) {
	if r == nil {
		return nil, fmt.Errorf("postgres disabled")
	}
	rows, err := r.pool.Query(ctx, `SELECT id,scope,route_path,direction,monitor_at,intervention_at,intervention_action,auditor_failure_mode,revision,created_at,updated_at FROM policies ORDER BY scope,route_path,direction`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []policy.Policy{}
	for rows.Next() {
		var value policy.Policy
		if err := rows.Scan(&value.ID, &value.Scope, &value.RoutePath, &value.Direction, &value.MonitorAt, &value.InterventionAt, &value.InterventionAction, &value.AuditorFailureMode, &value.Revision, &value.CreatedAt, &value.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}
func (r *Repository) UpdatePolicy(ctx context.Context, id string, value policy.Policy) (policy.Policy, error) {
	if r == nil {
		return policy.Policy{}, fmt.Errorf("postgres disabled")
	}
	if err := policy.Validate(value); err != nil {
		return policy.Policy{}, err
	}
	value = value.Normalized()
	value.ID = id
	err := r.pool.QueryRow(ctx, `UPDATE policies SET scope=$2,route_path=$3,direction=$4,monitor_at=$5,intervention_at=$6,intervention_action=$7,auditor_failure_mode=$8,revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision,created_at,updated_at`, id, value.Scope, value.RoutePath, value.Direction, value.MonitorAt, value.InterventionAt, value.InterventionAction, value.AuditorFailureMode).Scan(&value.Revision, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}
func (r *Repository) DeletePolicy(ctx context.Context, id string) (bool, error) {
	if r == nil {
		return false, fmt.Errorf("postgres disabled")
	}
	result, err := r.pool.Exec(ctx, `DELETE FROM policies WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return result.RowsAffected() == 1, nil
}
func (r *Repository) StoreEvents(ctx context.Context, events []audit.Event) error {
	if r == nil || len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		e = audit.RedactEvidence(e)
		matches, _ := json.Marshal(e.Matches)
		metadata, _ := json.Marshal(e.Metadata)
		var auditor []byte
		if e.Auditor != nil {
			auditor, _ = json.Marshal(e.Auditor)
		}
		batch.Queue(`INSERT INTO audit_records(id,event_id,request_id,tenant_id,direction,path,model,risk_score,decision,rule_version,matches,auditor,auditor_error,latency_ms,body_bytes,content_sha256,metadata,api_key_id,policy_id,policy_revision,created_at) VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT (event_id) DO NOTHING`, e.EventID, e.RequestID, e.TenantID, e.Direction, e.Path, e.Model, e.RiskScore, e.Decision, e.RuleVersion, matches, auditor, e.AuditorError, e.LatencyMS, e.BodyBytes, e.ContentSHA256, metadata, nullableUUID(e.APIKeyID), nullableUUID(e.PolicyID), nullableRevision(e.PolicyRevision), e.EventTime)
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
func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func nullableRevision(value int64) any {
	if value == 0 {
		return nil
	}
	return value
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
