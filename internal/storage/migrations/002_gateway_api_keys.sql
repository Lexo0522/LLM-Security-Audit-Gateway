CREATE TABLE IF NOT EXISTS gateway_api_keys (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  prefix TEXT NOT NULL,
  key_hmac BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS gateway_api_keys_tenant_idx ON gateway_api_keys(tenant_id, created_at DESC);
