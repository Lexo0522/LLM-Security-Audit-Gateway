# Key management and recovery

The gateway encrypts upstream API keys with AES-256-GCM under a single master key read from `GATEWAY_ENCRYPTION_KEY_FILE` (default `/var/lib/gateway/keys/encryption.key`, stored in the `gateway-keys` volume). Losing that file is unrecoverable by design: there is no escrow, no KMS, no second copy.

## The recovery unit

**The `gateway-keys` volume and the `postgres-data` volume are one recovery unit.** Back them up together and restore them together:

- With the keys volume but no database: you hold a key for ciphertexts that no longer exist.
- With the database but no keys volume: every stored upstream API key is undecryptable. The gateway refuses to start in this state — a freshly generated key paired with existing ciphertexts aborts boot with an explicit error — and each proxied request would otherwise fail with an unexplained 502.

Backup (adjust the compose project prefix `audit-gateway_` to yours):

```bash
# Master key volume
docker run --rm -v audit-gateway_gateway-keys:/keys:ro -v "$PWD":/backup alpine \
  tar czf /backup/gateway-keys-$(date +%F).tgz -C /keys .

# PostgreSQL (identity, upstreams, keys, sessions, audit records)
docker compose -p audit-gateway exec -T postgres \
  pg_dump -U audit -d audit_gateway | gzip > postgres-$(date +%F).sql.gz
```

Restore: recreate the volumes, restore the key files into `gateway-keys`, then `gunzip -c postgres-….sql.gz | docker compose exec -T postgres psql -U audit -d audit_gateway` before starting the gateway.

On Windows with Git Bash, Docker bind mounts need a Windows-style path. Convert the backup directory before mounting it:

```bash
BACKUP_DIR=$(cygpath -m "$PWD/backups")
docker run --rm -v audit-gateway_gateway-keys:/keys:ro -v "$BACKUP_DIR:/backup" alpine \
  tar czf /backup/gateway-keys.tgz -C /keys .
```

The recovery procedure was exercised against an isolated Compose project on 2026-09-06: after destroying both volumes, restoring the key archive plus PostgreSQL dump preserved administrator login, gateway-key routing, and decryption of the stored upstream API key. The lost-key case was also exercised: the gateway remains in a restart loop with the explicit recovery error and removes each rejected newly generated key so `restart: unless-stopped` cannot bypass the guard on its next attempt.

Keep the master key out of git, out of CI logs, and out of shell history. File mode must stay 0600 with a 0700 parent directory (the gateway enforces both on load).

## Lost master key

If the key file is gone:

1. Restore the key file from backup into the `gateway-keys` volume; restart. This is the only path that preserves the stored upstream keys.
2. If no backup exists, the ciphertexts in `upstream_configs` are permanently unreadable. Delete the affected upstreams in the admin UI and re-enter their API keys. Do not set `GATEWAY_ENCRYPTION_KEY_ALLOW_GENERATE=true` in production to "get past" the startup error — that switch exists only for environments where no secrets exist yet.

## Rotating an upstream API key (no downtime)

`PUT /admin/v1/upstreams/:id` with a new `api_key` re-encrypts and stores it immediately; omitting `api_key` keeps the stored one. Rotation is audited with `key_rotated: true`. Verify with `POST /admin/v1/upstreams/:id/test` afterwards.

## Rotating the master key (downtime rotation)

There is no online re-encryption; plan a maintenance window:

1. Stop writers: `docker compose stop web gateway audit-consumer`.
2. Back up both volumes (see above). Verify the backup decompresses.
3. Move the old key file aside inside the `gateway-keys` volume and install a fresh 32-byte key as `encryption.key`.
4. Start the gateway. It must boot with **no** upstream secrets — if `upstream_configs` still holds ciphertexts, startup aborts; re-enter keys through the admin UI instead (step 5 re-encrypts them under the new key).
5. For every upstream, `PUT /admin/v1/upstreams/:id` with its API key. Each write encrypts under the new master key.
6. Verify each upstream with the test probe, then destroy the old key file.

## Passwords and defaults

The compose stack's `change-me` database passwords are development-only. `deploy/docker-compose.prod.yml` is an override that requires `POSTGRES_PASSWORD` and `CLICKHOUSE_PASSWORD` (unset variables fail the stack), removes the data-service host port bindings, sets `GATEWAY_ENV=production`, and requires `ADMIN_TRUSTED_ORIGINS`. Use it as `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.prod.yml up -d`.
