CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY,
  scope TEXT NOT NULL,
  route_path TEXT NOT NULL,
  direction TEXT NOT NULL,
  monitor_at INTEGER NOT NULL,
  intervention_at INTEGER NOT NULL,
  intervention_action TEXT NOT NULL,
  auditor_failure_mode TEXT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scope, route_path, direction)
);
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS api_key_id UUID;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS policy_id UUID;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS policy_revision BIGINT;
