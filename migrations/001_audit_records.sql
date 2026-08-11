CREATE TABLE IF NOT EXISTS audit_records (
  id UUID PRIMARY KEY,
  request_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  direction TEXT NOT NULL,
  path TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  decision TEXT NOT NULL,
  rule_version TEXT NOT NULL DEFAULT 'bootstrap',
  model_name TEXT,
  evidence_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_records_created_at_idx ON audit_records (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_records_tenant_idx ON audit_records (tenant_id, created_at DESC);
