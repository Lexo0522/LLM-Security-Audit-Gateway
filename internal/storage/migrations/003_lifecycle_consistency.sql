-- Enforce the data required for a deleting upstream to be finalized.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'upstream_configs_deleting_timestamps_check'
      AND conrelid = 'upstream_configs'::regclass
  ) THEN
    ALTER TABLE upstream_configs ADD CONSTRAINT upstream_configs_deleting_timestamps_check
      CHECK (
        lifecycle_state <> 'deleting'
        OR (
          delete_requested_at IS NOT NULL
          AND purge_after IS NOT NULL
          AND purge_after >= delete_requested_at
        )
      );
  END IF;
END $$;
