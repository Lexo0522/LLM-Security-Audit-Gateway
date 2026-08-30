// Package clickhouse persists and queries Kafka-delivered audit events.
package clickhouse

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/google/uuid"
)

var (
	ErrNotFound      = errors.New("audit event not found")
	ErrInvalidEvent  = errors.New("invalid audit event")
	ErrInvalidFilter = errors.New("invalid audit query filter")
)

const schemaDDL = `
CREATE TABLE IF NOT EXISTS audit_events (
  event_id UUID,
  event_time DateTime64(3, 'UTC'),
  request_id String,
  tenant_id LowCardinality(String),
  api_key_id String,
  direction LowCardinality(String),
  path String,
  model String,
  decision LowCardinality(String),
  risk_score Int32,
  rule_version String,
  policy_id String,
  policy_revision Int64,
  matches String,
  auditor String,
  auditor_error String,
  latency_ms Int64,
  body_bytes UInt64,
  content_sha256 String,
  metadata String,
  schema_version LowCardinality(String),
  ingested_at DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_time, event_id)
TTL toDateTime(event_time) + INTERVAL 180 DAY DELETE
`

type Store struct{ db *sql.DB }

func Open(dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("CLICKHOUSE_DSN is required")
	}
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(time.Hour)
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("clickhouse disabled")
	}
	return s.db.PingContext(ctx)
}
func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("clickhouse disabled")
	}
	if _, err := s.db.ExecContext(ctx, schemaDDL); err != nil {
		return err
	}
	// Metadata-only idempotent ALTERs for indexes the original CREATE TABLE
	// did not include; they apply to new parts and merged parts. Existing
	// parts are not materialized (that would trigger a mutation on every
	// start), so event_id lookups on old partitions stay a full scan until
	// parts are rewritten.
	for _, statement := range schemaIndexes {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

var schemaIndexes = []string{
	`ALTER TABLE audit_events ADD INDEX IF NOT EXISTS audit_events_event_id_idx event_id TYPE bloom_filter GRANULARITY 4`,
}

// dedupSource replaces the merge-on-read FINAL modifier: ReplacingMergeTree
// duplicates (redelivered events) collapse by the table's ORDER BY key before
// aggregation, without forcing every query to merge parts at read time.
func dedupSource(condition string) string {
	return "SELECT * FROM audit_events WHERE " + condition + " LIMIT 1 BY tenant_id, event_time, event_id"
}

func ValidateEvent(event audit.Event) error {
	if event.SchemaVersion != "2" || event.EventID == "" || event.EventTime.IsZero() || event.RequestID == "" || event.TenantID == "" || event.Path == "" || event.Decision == "" || event.RuleVersion == "" {
		return fmt.Errorf("%w: missing required v2 fields", ErrInvalidEvent)
	}
	if _, err := uuid.Parse(event.EventID); err != nil {
		return fmt.Errorf("%w: event_id: %v", ErrInvalidEvent, err)
	}
	switch event.Direction {
	case audit.DirectionRequest, audit.DirectionResponse, audit.DirectionAdmin:
	default:
		return fmt.Errorf("%w: unsupported direction %q", ErrInvalidEvent, event.Direction)
	}
	switch event.Decision {
	case "allow", "monitor", "block", "redact", "success":
	default:
		return fmt.Errorf("%w: unsupported decision %q", ErrInvalidEvent, event.Decision)
	}
	if event.RiskScore < 0 || event.RiskScore > 100 || event.LatencyMS < 0 || event.BodyBytes < 0 {
		return fmt.Errorf("%w: numeric field outside supported range", ErrInvalidEvent)
	}
	if len(event.TenantID) > 256 || len(event.RequestID) > 256 || len(event.Path) > 2048 || len(event.Model) > 512 || len(event.RuleVersion) > 512 {
		return fmt.Errorf("%w: string field exceeds supported length", ErrInvalidEvent)
	}
	return nil
}

func (s *Store) InsertEvents(ctx context.Context, events []audit.Event) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("clickhouse disabled")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// clickhouse-go/v2's database/sql batch contract is
	// Begin -> Prepare(INSERT) -> Exec(rows) -> Commit.
	// Ref: https://github.com/ClickHouse/clickhouse-go/blob/v2.38.1/examples/std/batch.go
	statement, err := tx.PrepareContext(ctx, `INSERT INTO audit_events (event_id,event_time,request_id,tenant_id,api_key_id,direction,path,model,decision,risk_score,rule_version,policy_id,policy_revision,matches,auditor,auditor_error,latency_ms,body_bytes,content_sha256,metadata,schema_version,ingested_at)`)
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, event := range events {
		if err := ValidateEvent(event); err != nil {
			return err
		}
		event = audit.RedactEvidence(event)
		matches, _ := json.Marshal(event.Matches)
		metadata, _ := json.Marshal(event.Metadata)
		auditor := []byte{}
		if event.Auditor != nil {
			auditor, _ = json.Marshal(event.Auditor)
		}
		if _, err = statement.ExecContext(ctx, event.EventID, event.EventTime.UTC(), event.RequestID, event.TenantID, event.APIKeyID, string(event.Direction), event.Path, event.Model, event.Decision, event.RiskScore, event.RuleVersion, event.PolicyID, event.PolicyRevision, string(matches), string(auditor), event.AuditorError, event.LatencyMS, uint64(event.BodyBytes), event.ContentSHA256, string(metadata), event.SchemaVersion, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type EventFilter struct {
	From, To     time.Time
	TenantID     string
	Decision     string
	Direction    string
	Path         string
	Model        string
	RuleID       string
	MinRiskScore *int
	Cursor       string
	Limit        int
}
type EventPage struct {
	Events     []audit.Event `json:"events"`
	NextCursor string        `json:"next_cursor,omitempty"`
}
type Summary struct {
	TotalEvents      int64            `json:"total_events"`
	AverageRisk      float64          `json:"average_risk_score"`
	MaximumRisk      int              `json:"maximum_risk_score"`
	AverageLatencyMS float64          `json:"average_latency_ms"`
	MaximumLatencyMS int64            `json:"maximum_latency_ms"`
	ByDecision       map[string]int64 `json:"by_decision"`
	ByDirection      map[string]int64 `json:"by_direction"`
	ByModel          map[string]int64 `json:"by_model"`
	ByPath           map[string]int64 `json:"by_path"`
	ByRule           map[string]int64 `json:"by_rule"`
	Series           []TrendPoint     `json:"series"`
}
type TrendPoint struct {
	Start       time.Time `json:"start"`
	TotalEvents int64     `json:"total_events"`
	AverageRisk float64   `json:"average_risk_score"`
	MaximumRisk int       `json:"maximum_risk_score"`
}

type cursor struct {
	Time    time.Time `json:"time"`
	EventID string    `json:"event_id"`
}

func encodeCursor(value cursor) string {
	raw, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func decodeCursor(value string) (cursor, error) {
	var result cursor
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Time.IsZero() {
		return result, fmt.Errorf("%w: cursor", ErrInvalidFilter)
	}
	if _, err := uuid.Parse(result.EventID); err != nil {
		return result, fmt.Errorf("%w: cursor event id", ErrInvalidFilter)
	}
	return result, nil
}

func normalizeFilter(filter EventFilter) (EventFilter, error) {
	if filter.To.IsZero() {
		filter.To = time.Now().UTC()
	}
	if filter.From.IsZero() {
		filter.From = filter.To.Add(-24 * time.Hour)
	}
	filter.From, filter.To = filter.From.UTC(), filter.To.UTC()
	if !filter.From.Before(filter.To) || filter.To.Sub(filter.From) > 31*24*time.Hour {
		return filter, fmt.Errorf("%w: range must be positive and at most 31 days", ErrInvalidFilter)
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	if filter.Limit < 1 || filter.Limit > 200 {
		return filter, fmt.Errorf("%w: limit must be 1..200", ErrInvalidFilter)
	}
	if filter.Direction != "" && filter.Direction != string(audit.DirectionRequest) && filter.Direction != string(audit.DirectionResponse) && filter.Direction != string(audit.DirectionAdmin) {
		return filter, fmt.Errorf("%w: direction", ErrInvalidFilter)
	}
	if filter.Decision != "" && filter.Decision != "allow" && filter.Decision != "monitor" && filter.Decision != "block" && filter.Decision != "redact" && filter.Decision != "success" {
		return filter, fmt.Errorf("%w: decision", ErrInvalidFilter)
	}
	if filter.MinRiskScore != nil && (*filter.MinRiskScore < 0 || *filter.MinRiskScore > 100) {
		return filter, fmt.Errorf("%w: min_risk_score", ErrInvalidFilter)
	}
	if len(filter.TenantID) > 256 || len(filter.Path) > 2048 || len(filter.Model) > 512 || len(filter.RuleID) > 512 {
		return filter, fmt.Errorf("%w: filter value too long", ErrInvalidFilter)
	}
	if filter.Cursor != "" {
		if _, err := decodeCursor(filter.Cursor); err != nil {
			return filter, err
		}
	}
	return filter, nil
}

func where(filter EventFilter) (string, []any, error) {
	filter, err := normalizeFilter(filter)
	if err != nil {
		return "", nil, err
	}
	clauses, args := []string{"event_time >= ?", "event_time < ?"}, []any{filter.From, filter.To}
	for _, item := range []struct{ value, column string }{{filter.TenantID, "tenant_id"}, {filter.Decision, "decision"}, {filter.Direction, "direction"}, {filter.Path, "path"}, {filter.Model, "model"}} {
		if item.value != "" {
			clauses, args = append(clauses, item.column+" = ?"), append(args, item.value)
		}
	}
	if filter.RuleID != "" {
		clauses, args = append(clauses, "arrayExists(item -> JSONExtractString(item, 'rule_id') = ?, JSONExtractArrayRaw(matches))"), append(args, filter.RuleID)
	}
	if filter.MinRiskScore != nil {
		clauses, args = append(clauses, "risk_score >= ?"), append(args, *filter.MinRiskScore)
	}
	if filter.Cursor != "" {
		current, _ := decodeCursor(filter.Cursor)
		clauses, args = append(clauses, "(event_time < ? OR (event_time = ? AND event_id < toUUID(?)))"), append(args, current.Time, current.Time, current.EventID)
	}
	return strings.Join(clauses, " AND "), args, nil
}

const eventColumns = `event_id,event_time,request_id,tenant_id,api_key_id,direction,path,model,decision,risk_score,rule_version,policy_id,policy_revision,matches,auditor,auditor_error,latency_ms,body_bytes,content_sha256,metadata,schema_version`

func scanEvent(scanner interface{ Scan(...any) error }) (audit.Event, error) {
	var event audit.Event
	var matches, auditor, metadata string
	err := scanner.Scan(&event.EventID, &event.EventTime, &event.RequestID, &event.TenantID, &event.APIKeyID, &event.Direction, &event.Path, &event.Model, &event.Decision, &event.RiskScore, &event.RuleVersion, &event.PolicyID, &event.PolicyRevision, &matches, &auditor, &event.AuditorError, &event.LatencyMS, &event.BodyBytes, &event.ContentSHA256, &metadata, &event.SchemaVersion)
	if err != nil {
		return event, err
	}
	_ = json.Unmarshal([]byte(matches), &event.Matches)
	_ = json.Unmarshal([]byte(metadata), &event.Metadata)
	if auditor != "" {
		var value audit.ModelResult
		if json.Unmarshal([]byte(auditor), &value) == nil {
			event.Auditor = &value
		}
	}
	return event, nil
}

func (s *Store) ListEvents(ctx context.Context, filter EventFilter) (EventPage, error) {
	filter, err := normalizeFilter(filter)
	if err != nil {
		return EventPage{}, err
	}
	condition, args, err := where(filter)
	if err != nil {
		return EventPage{}, err
	}
	args = append(args, filter.Limit+1)
	rows, err := s.db.QueryContext(ctx, "SELECT "+eventColumns+" FROM ("+
		"SELECT "+eventColumns+" FROM audit_events WHERE "+condition+
		" ORDER BY event_time DESC, event_id DESC LIMIT 1 BY tenant_id, event_time, event_id LIMIT ?"+
		") ORDER BY event_time DESC, event_id DESC", args...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	page := EventPage{Events: make([]audit.Event, 0, filter.Limit)}
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return EventPage{}, err
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return EventPage{}, err
	}
	if len(page.Events) > filter.Limit {
		page.Events = page.Events[:filter.Limit]
		last := page.Events[len(page.Events)-1]
		page.NextCursor = encodeCursor(cursor{Time: last.EventTime.UTC(), EventID: last.EventID})
	}
	return page, nil
}
func (s *Store) GetEvent(ctx context.Context, eventID string) (audit.Event, error) {
	if _, err := uuid.Parse(eventID); err != nil {
		return audit.Event{}, fmt.Errorf("%w: event_id", ErrInvalidFilter)
	}
	row := s.db.QueryRowContext(ctx, "SELECT "+eventColumns+" FROM audit_events WHERE event_id = toUUID(?) ORDER BY ingested_at DESC LIMIT 1", eventID)
	event, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.Event{}, ErrNotFound
	}
	return event, err
}
func (s *Store) Summary(ctx context.Context, filter EventFilter, bucket string) (Summary, error) {
	filter.Limit = 1
	filter, err := normalizeFilter(filter)
	if err != nil {
		return Summary{}, err
	}
	if bucket != "hour" && bucket != "day" {
		return Summary{}, fmt.Errorf("%w: bucket", ErrInvalidFilter)
	}
	condition, args, err := where(filter)
	if err != nil {
		return Summary{}, err
	}
	result := Summary{ByDecision: map[string]int64{}, ByDirection: map[string]int64{}, ByModel: map[string]int64{}, ByPath: map[string]int64{}, ByRule: map[string]int64{}}
	if err = s.db.QueryRowContext(ctx, "SELECT count(), ifNull(avgOrNull(risk_score), 0), ifNull(maxOrNull(risk_score), 0), ifNull(avgOrNull(latency_ms), 0), ifNull(maxOrNull(latency_ms), 0) FROM ("+dedupSource(condition)+")", args...).Scan(&result.TotalEvents, &result.AverageRisk, &result.MaximumRisk, &result.AverageLatencyMS, &result.MaximumLatencyMS); err != nil {
		return Summary{}, err
	}
	for _, aggregate := range []struct {
		column string
		into   map[string]int64
	}{{"decision", result.ByDecision}, {"direction", result.ByDirection}, {"model", result.ByModel}, {"path", result.ByPath}} {
		rows, queryErr := s.db.QueryContext(ctx, "SELECT "+aggregate.column+", count() FROM ("+dedupSource(condition)+") GROUP BY "+aggregate.column, args...)
		if queryErr != nil {
			return Summary{}, queryErr
		}
		for rows.Next() {
			var key string
			var count int64
			if queryErr = rows.Scan(&key, &count); queryErr != nil {
				rows.Close()
				return Summary{}, queryErr
			}
			aggregate.into[key] = count
		}
		if queryErr = rows.Err(); queryErr != nil {
			rows.Close()
			return Summary{}, queryErr
		}
		rows.Close()
	}
	ruleRows, err := s.db.QueryContext(ctx, "SELECT rule_id, count() FROM (SELECT JSONExtractString(arrayJoin(JSONExtractArrayRaw(matches)), 'rule_id') AS rule_id FROM ("+dedupSource(condition)+")) WHERE rule_id != '' GROUP BY rule_id", args...)
	if err != nil {
		return Summary{}, err
	}
	for ruleRows.Next() {
		var ruleID string
		var count int64
		if err = ruleRows.Scan(&ruleID, &count); err != nil {
			ruleRows.Close()
			return Summary{}, err
		}
		result.ByRule[ruleID] = count
	}
	if err = ruleRows.Err(); err != nil {
		ruleRows.Close()
		return Summary{}, err
	}
	ruleRows.Close()
	function := "toStartOfHour"
	if bucket == "day" {
		function = "toStartOfDay"
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+function+"(event_time), count(), avgOrNull(risk_score), max(risk_score) FROM ("+dedupSource(condition)+") GROUP BY 1 ORDER BY 1", args...)
	if err != nil {
		return Summary{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var point TrendPoint
		if err = rows.Scan(&point.Start, &point.TotalEvents, &point.AverageRisk, &point.MaximumRisk); err != nil {
			return Summary{}, err
		}
		result.Series = append(result.Series, point)
	}
	return result, rows.Err()
}
