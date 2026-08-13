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

ALTER TABLE rule_sets ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'unknown';
DO $$ BEGIN
  ALTER TABLE rule_sets ADD CONSTRAINT rule_sets_source_check CHECK (source IN ('unknown','demo','managed'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS audit_outbox (
  event_id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_until TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  published_at TIMESTAMPTZ,
  last_error TEXT
);
CREATE INDEX IF NOT EXISTS audit_outbox_dispatch_idx ON audit_outbox(published_at, available_at, lease_until);
