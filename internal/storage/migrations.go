package storage

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationAdvisoryLock int64 = 0x61695f6d696772

var migrationNamePattern = regexp.MustCompile(`^([0-9]+)_([a-z0-9][a-z0-9_]*)\.sql$`)

var errUnsupportedSchema = errors.New("unsupported existing database schema")

type migration struct {
	version  int64
	name     string
	checksum []byte
	sql      string
}

type appliedMigration struct {
	version  int64
	name     string
	checksum []byte
	mode     string
}

func normalizeMigrationSQL(data []byte) string {
	value := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

func parseMigrationName(name string) (int64, error) {
	matches := migrationNamePattern.FindStringSubmatch(name)
	if matches == nil {
		return 0, fmt.Errorf("invalid migration filename %q: want NNN_name.sql", name)
	}
	version, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("invalid migration version in %q", name)
	}
	return version, nil
}

func loadMigrations(source fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, err
	}
	migrations := make([]migration, 0, len(entries))
	seen := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version, err := parseMigrationName(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, previous, entry.Name())
		}
		data, err := fs.ReadFile(source, entry.Name())
		if err != nil {
			return nil, err
		}
		sql := normalizeMigrationSQL(data)
		hash := sha256.Sum256([]byte(sql))
		seen[version] = entry.Name()
		migrations = append(migrations, migration{version: version, name: entry.Name(), checksum: hash[:], sql: sql})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	for index, migration := range migrations {
		want := int64(index + 1)
		if migration.version != want {
			return nil, fmt.Errorf("migration versions must be contiguous from 1: found %d at position %d", migration.version, index+1)
		}
	}
	return migrations, nil
}

func (r *Repository) Migrate(ctx context.Context) error {
	if r == nil || r.pool == nil {
		return nil
	}
	source, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	migrations, err := loadMigrations(source)
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLock); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLock) }()

	if _, err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS public.schema_migrations (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			checksum BYTEA NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			execution_ms BIGINT NOT NULL DEFAULT 0,
			mode TEXT NOT NULL CHECK (mode IN ('applied', 'baseline'))
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := readAppliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		if existing, err := gatewaySchemaObjectCount(ctx, conn); err != nil {
			return err
		} else if existing > 0 {
			if err := baselineCurrentSchema(ctx, conn, migrations); err != nil {
				return err
			}
			applied, err = readAppliedMigrations(ctx, conn)
			if err != nil {
				return err
			}
		}
	}
	if err := validateAppliedMigrations(applied, migrations); err != nil {
		return err
	}
	for _, migration := range migrations {
		if _, ok := applied[migration.version]; ok {
			continue
		}
		if err := applyMigration(ctx, conn, migration); err != nil {
			return err
		}
	}
	return nil
}

func readAppliedMigrations(ctx context.Context, conn interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (map[int64]appliedMigration, error) {
	rows, err := conn.Query(ctx, `SELECT version,name,checksum,mode FROM public.schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	result := map[int64]appliedMigration{}
	for rows.Next() {
		var value appliedMigration
		if err := rows.Scan(&value.version, &value.name, &value.checksum, &value.mode); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		if value.mode != "applied" && value.mode != "baseline" {
			return nil, fmt.Errorf("schema_migrations version %d has invalid mode %q", value.version, value.mode)
		}
		if _, exists := result[value.version]; exists {
			return nil, fmt.Errorf("schema_migrations contains duplicate version %d", value.version)
		}
		result[value.version] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	return result, nil
}

func validateAppliedMigrations(applied map[int64]appliedMigration, migrations []migration) error {
	available := make(map[int64]migration, len(migrations))
	for _, migration := range migrations {
		available[migration.version] = migration
	}
	for version, value := range applied {
		migration, ok := available[version]
		if !ok {
			return fmt.Errorf("schema migration %d (%s) is recorded but missing from the binary", version, value.name)
		}
		if value.name != migration.name {
			return fmt.Errorf("schema migration %d renamed from %s to %s", version, value.name, migration.name)
		}
		if !equalBytes(value.checksum, migration.checksum) {
			return fmt.Errorf("schema migration %d checksum drift: database=%s binary=%s", version, hex.EncodeToString(value.checksum), hex.EncodeToString(migration.checksum))
		}
	}
	missing := false
	for _, migration := range migrations {
		_, present := applied[migration.version]
		if !present {
			missing = true
			continue
		}
		if missing {
			return fmt.Errorf("schema migrations are out of order: version %d is recorded after an unapplied version", migration.version)
		}
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}

func applyMigration(ctx context.Context, conn interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}, migration migration) error {
	started := time.Now()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", migration.name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, migration.sql); err != nil {
		return fmt.Errorf("migration %s: %w", migration.name, err)
	}
	if err = recordMigration(ctx, tx, migration, "applied", time.Since(started).Milliseconds()); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", migration.name, err)
	}
	return nil
}

func recordMigration(ctx context.Context, tx pgx.Tx, migration migration, mode string, executionMS int64) error {
	if mode != "applied" && mode != "baseline" {
		return fmt.Errorf("invalid migration mode %q", mode)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.schema_migrations(version,name,checksum,execution_ms,mode) VALUES($1,$2,$3,$4,$5)`, migration.version, migration.name, migration.checksum, executionMS, mode); err != nil {
		return fmt.Errorf("record migration %s: %w", migration.name, err)
	}
	return nil
}

func gatewaySchemaObjectCount(ctx context.Context, conn interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (int, error) {
	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relname = ANY($1::text[])`, []string{
		"admin_users", "admin_sessions", "upstream_configs", "gateway_api_keys", "rule_sets", "policies", "audit_records", "audit_outbox",
	}).Scan(&count); err != nil {
		return 0, fmt.Errorf("inspect gateway schema: %w", err)
	}
	return count, nil
}

func baselineCurrentSchema(ctx context.Context, conn interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}, migrations []migration) error {
	if err := validateCurrentSchema(ctx, conn); err != nil {
		return err
	}
	baselineVersions := []int64{1, 2}
	var hasLifecycleConstraint bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='upstream_configs_deleting_timestamps_check' AND conrelid=to_regclass('public.upstream_configs'))`).Scan(&hasLifecycleConstraint); err != nil {
		return fmt.Errorf("inspect lifecycle constraint: %w", err)
	}
	if hasLifecycleConstraint {
		baselineVersions = append(baselineVersions, 3)
	}
	byVersion := make(map[int64]migration, len(migrations))
	for _, migration := range migrations {
		byVersion[migration.version] = migration
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin schema baseline: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, version := range baselineVersions {
		migration, ok := byVersion[version]
		if !ok {
			return fmt.Errorf("cannot baseline missing migration version %d", version)
		}
		if err := recordMigration(ctx, tx, migration, "baseline", 0); err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema baseline: %w", err)
	}
	return nil
}

func validateCurrentSchema(ctx context.Context, conn interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) error {
	var missing []string
	required := map[string][]string{
		"admin_users":      {"id", "username", "password_hash"},
		"admin_sessions":   {"id", "token_hash", "admin_user_id"},
		"upstream_configs": {"id", "name", "base_url", "api_key_ciphertext", "enabled", "lifecycle_state", "delete_requested_at", "purge_after"},
		"gateway_api_keys": {"id", "tenant_id", "upstream_id", "key_digest", "key_salt", "revoked_at"},
		"rule_sets":        {"version", "scope", "status", "source", "rules"},
		"policies":         {"id", "scope", "route_path", "direction"},
		"audit_records":    {"id", "event_id", "matches", "metadata", "api_key_id", "policy_id"},
		"audit_outbox":     {"event_id", "payload", "published_at"},
	}
	for table, columns := range required {
		for _, column := range columns {
			var present bool
			if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2)`, table, column).Scan(&present); err != nil {
				return fmt.Errorf("inspect %s.%s: %w", table, column, err)
			}
			if !present {
				missing = append(missing, table+"."+column)
			}
		}
	}
	var legacyKeyColumn, unknownSource, nullableEvent, malformedDeleting, lifecycleTrigger, keyBindingConstraint, auditEventConstraint, sourceConstraint bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='gateway_api_keys' AND column_name='key_hmac')`).Scan(&legacyKeyColumn); err != nil {
		return fmt.Errorf("inspect legacy gateway key schema: %w", err)
	}
	if len(missing) == 0 {
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.rule_sets WHERE source='unknown')`).Scan(&unknownSource); err != nil {
			return fmt.Errorf("inspect legacy rule source: %w", err)
		}
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.audit_records WHERE event_id IS NULL)`).Scan(&nullableEvent); err != nil {
			return fmt.Errorf("inspect audit event ids: %w", err)
		}
	}
	if len(missing) == 0 {
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.upstream_configs WHERE lifecycle_state='deleting' AND (delete_requested_at IS NULL OR purge_after IS NULL OR purge_after < delete_requested_at))`).Scan(&malformedDeleting); err != nil {
			return fmt.Errorf("inspect deleting timestamps: %w", err)
		}
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('public.upstream_configs') AND tgname='upstream_configs_lifecycle_projection')`).Scan(&lifecycleTrigger); err != nil {
			return fmt.Errorf("inspect lifecycle trigger: %w", err)
		}
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('public.gateway_api_keys') AND contype='f' AND pg_get_constraintdef(oid) LIKE '%upstream_configs%')`).Scan(&keyBindingConstraint); err != nil {
			return fmt.Errorf("inspect gateway key binding constraint: %w", err)
		}
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('public.audit_records') AND conname='audit_records_event_id_key')`).Scan(&auditEventConstraint); err != nil {
			return fmt.Errorf("inspect audit event constraint: %w", err)
		}
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('public.rule_sets') AND conname='rule_sets_source_check')`).Scan(&sourceConstraint); err != nil {
			return fmt.Errorf("inspect rule source constraint: %w", err)
		}
	}
	if len(missing) > 0 || legacyKeyColumn || unknownSource || nullableEvent || malformedDeleting || !lifecycleTrigger || !keyBindingConstraint || !auditEventConstraint || !sourceConstraint {
		reasons := append([]string{}, missing...)
		if legacyKeyColumn {
			reasons = append(reasons, "gateway_api_keys.key_hmac is present")
		}
		if unknownSource {
			reasons = append(reasons, "rule_sets contains source=unknown")
		}
		if nullableEvent {
			reasons = append(reasons, "audit_records contains NULL event_id")
		}
		if malformedDeleting {
			reasons = append(reasons, "deleting upstream has missing or invalid timestamps")
		}
		if !lifecycleTrigger {
			reasons = append(reasons, "upstream lifecycle trigger is missing")
		}
		if !keyBindingConstraint {
			reasons = append(reasons, "gateway_api_keys upstream foreign key is missing")
		}
		if !auditEventConstraint {
			reasons = append(reasons, "audit_records event_id unique constraint is missing")
		}
		if !sourceConstraint {
			reasons = append(reasons, "rule_sets source constraint is missing")
		}
		return fmt.Errorf("%w: %s", errUnsupportedSchema, strings.Join(reasons, ", "))
	}
	return nil
}
