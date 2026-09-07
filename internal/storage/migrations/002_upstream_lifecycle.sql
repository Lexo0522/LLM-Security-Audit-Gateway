-- Upstream lifecycle expansion. This migration is additive and safe to rerun.
ALTER TABLE upstream_configs
  ADD COLUMN IF NOT EXISTS lifecycle_state TEXT,
  ADD COLUMN IF NOT EXISTS delete_requested_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS purge_after TIMESTAMPTZ;

UPDATE upstream_configs
SET lifecycle_state = CASE WHEN enabled THEN 'active' ELSE 'disabled' END
WHERE lifecycle_state IS NULL;

ALTER TABLE upstream_configs
  ALTER COLUMN lifecycle_state SET DEFAULT 'active',
  ALTER COLUMN lifecycle_state SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'upstream_configs_lifecycle_state_check'
      AND conrelid = 'upstream_configs'::regclass
  ) THEN
    ALTER TABLE upstream_configs ADD CONSTRAINT upstream_configs_lifecycle_state_check
      CHECK (lifecycle_state IN ('active', 'disabled', 'deleting'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'upstream_configs_enabled_lifecycle_check'
      AND conrelid = 'upstream_configs'::regclass
  ) THEN
    ALTER TABLE upstream_configs ADD CONSTRAINT upstream_configs_enabled_lifecycle_check
      CHECK (enabled = (lifecycle_state = 'active'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS upstream_configs_deleting_purge_idx
  ON upstream_configs(lifecycle_state, purge_after)
  WHERE lifecycle_state = 'deleting';

-- Keep legacy binaries compatible while making deleting terminal. Older writers
-- only update enabled; this trigger projects that write into lifecycle_state.
CREATE OR REPLACE FUNCTION sync_upstream_lifecycle_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.lifecycle_state IS NULL OR NEW.lifecycle_state = ''
       OR (NEW.lifecycle_state = 'active' AND NOT NEW.enabled AND NEW.delete_requested_at IS NULL) THEN
      NEW.lifecycle_state := CASE WHEN NEW.enabled THEN 'active' ELSE 'disabled' END;
    END IF;
    IF NEW.lifecycle_state = 'deleting' THEN
      NEW.enabled := false;
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.lifecycle_state = 'deleting' THEN
    NEW.lifecycle_state := 'deleting';
    NEW.enabled := false;
    NEW.delete_requested_at := OLD.delete_requested_at;
    NEW.purge_after := OLD.purge_after;
    NEW.api_key_ciphertext := NULL;
    RETURN NEW;
  END IF;

  IF NEW.lifecycle_state = OLD.lifecycle_state
     AND NEW.enabled IS DISTINCT FROM OLD.enabled THEN
    NEW.lifecycle_state := CASE WHEN NEW.enabled THEN 'active' ELSE 'disabled' END;
  END IF;
  IF NEW.lifecycle_state = 'deleting' THEN
    NEW.enabled := false;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS upstream_configs_lifecycle_projection ON upstream_configs;
CREATE TRIGGER upstream_configs_lifecycle_projection
  BEFORE INSERT OR UPDATE ON upstream_configs
  FOR EACH ROW EXECUTE FUNCTION sync_upstream_lifecycle_projection();

-- Protect the transition when an older gateway binary still writes keys without
-- the new row-lock check. A key can only be created for an active upstream.
CREATE OR REPLACE FUNCTION reject_nonactive_upstream_key()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  state TEXT;
  is_enabled BOOLEAN;
BEGIN
  SELECT lifecycle_state, enabled INTO state, is_enabled
  FROM upstream_configs WHERE id = NEW.upstream_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'upstream % does not exist', NEW.upstream_id
      USING ERRCODE = '23503';
  END IF;
  IF state <> 'active' OR NOT is_enabled THEN
    RAISE EXCEPTION 'upstream % is not active', NEW.upstream_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS gateway_api_keys_upstream_lifecycle_guard ON gateway_api_keys;
CREATE TRIGGER gateway_api_keys_upstream_lifecycle_guard
  BEFORE INSERT OR UPDATE OF upstream_id ON gateway_api_keys
  FOR EACH ROW EXECUTE FUNCTION reject_nonactive_upstream_key();

-- Keep the legacy projection safe for old readers: deleting is never enabled.
UPDATE upstream_configs SET enabled = (lifecycle_state = 'active')
WHERE enabled IS DISTINCT FROM (lifecycle_state = 'active');
