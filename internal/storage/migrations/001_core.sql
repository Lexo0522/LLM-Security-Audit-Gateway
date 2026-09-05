-- Current schema. This migration is intentionally destructive: deployments must
-- recreate the PostgreSQL volume when upgrading from the pre-admin schema.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL UNIQUE,
  password_hash BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash BYTEA NOT NULL UNIQUE,
  admin_user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admin_sessions_user_idx ON admin_sessions(admin_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_sessions_active_idx ON admin_sessions(token_hash, expires_at, revoked_at);

CREATE TABLE IF NOT EXISTS upstream_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  base_url TEXT NOT NULL,
  api_key_ciphertext BYTEA,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gateway_api_keys (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  upstream_id UUID NOT NULL REFERENCES upstream_configs(id) ON DELETE RESTRICT,
  display_name TEXT,
  prefix TEXT NOT NULL,
  key_digest BYTEA NOT NULL,
  key_salt BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS gateway_api_keys_tenant_idx ON gateway_api_keys(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS gateway_api_keys_upstream_idx ON gateway_api_keys(upstream_id, created_at DESC);

CREATE TABLE IF NOT EXISTS rule_sets (
  version UUID PRIMARY KEY,
  scope TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('draft','published','archived')),
  source TEXT NOT NULL CHECK(source IN ('demo','managed')),
  rules JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS rule_sets_scope_status_idx ON rule_sets(scope, status, published_at DESC);

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

CREATE TABLE IF NOT EXISTS audit_records (
  id UUID PRIMARY KEY,
  event_id UUID NOT NULL UNIQUE,
  request_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  direction TEXT NOT NULL,
  path TEXT NOT NULL,
  model TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  decision TEXT NOT NULL,
  rule_version TEXT NOT NULL DEFAULT 'bootstrap',
  matches JSONB NOT NULL DEFAULT '[]',
  auditor JSONB,
  auditor_error TEXT,
  latency_ms BIGINT NOT NULL DEFAULT 0,
  body_bytes INTEGER NOT NULL DEFAULT 0,
  content_sha256 TEXT,
  metadata JSONB NOT NULL DEFAULT '{}',
  api_key_id UUID REFERENCES gateway_api_keys(id) ON DELETE SET NULL,
  policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
  policy_revision BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_records_created_at_idx ON audit_records(created_at);
CREATE INDEX IF NOT EXISTS audit_records_tenant_created_idx ON audit_records(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_outbox (
  event_id UUID PRIMARY KEY REFERENCES audit_records(event_id) ON DELETE CASCADE,
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
