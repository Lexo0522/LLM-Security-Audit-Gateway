CREATE TABLE IF NOT EXISTS rule_sets (
  version UUID PRIMARY KEY, scope TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','published','archived')),
  rules JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), published_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS audit_records (
  id UUID PRIMARY KEY, event_id UUID, request_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT 'default', direction TEXT NOT NULL, path TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0, decision TEXT NOT NULL, rule_version TEXT NOT NULL DEFAULT 'bootstrap',
  model_name TEXT, evidence_hash TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rule_sets_scope_status_idx ON rule_sets(scope, status, published_at DESC);
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS event_id UUID;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS model TEXT;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS matches JSONB NOT NULL DEFAULT '[]';
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS auditor JSONB;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS auditor_error TEXT;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS latency_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS body_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS content_sha256 TEXT;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX IF NOT EXISTS audit_records_event_id_idx ON audit_records(event_id) WHERE event_id IS NOT NULL;
