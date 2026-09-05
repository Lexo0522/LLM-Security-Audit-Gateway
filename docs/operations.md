# Operations

## Production bootstrap

Before starting a production gateway, set `POSTGRES_URL` and run:

```powershell
go run ./cmd/seed -file ./configs/seed.example.json
```

The command is deliberately non-overwriting. Change published rules and policies through the management API after initial provisioning. Production startup rejects `ALLOW_DEMO_BOOTSTRAP_RULES=true`, missing managed global rules, and missing global request or response policy snapshots.

## Readiness and failure policy

`/healthz` only proves that the process is alive. `/readyz` returns per-component JSON and is 200 only when PostgreSQL, managed rule and policy snapshots, and the audit persistence queue are healthy. PostgreSQL loss marks cached snapshots `stale`, returns 503 for load balancers, and allows already admitted requests to finish. Direct new requests still fail authentication with 503 once PostgreSQL is unavailable.

Kafka, Redis, and the configured Auditor appear in `/readyz` as degraded but do not themselves turn it into 503. Kafka events are stored in PostgreSQL's outbox and replayed at least once after recovery. Redis failures use a per-process limiter until Redis responds again. Auditor `fail_closed` remains a request-level policy decision.

## Alerts

Load `deploy/prometheus-alerts.yml` into the deployment's Prometheus. Investigate `AuditGatewayNotReady` by reading `/readyz`; repair PostgreSQL first, then ensure the audit queue drains. For `AuditOutboxBacklog`, restore Kafka and watch `audit_outbox_pending` decline. For Redis fallback, treat limits as per-instance until shared Redis recovers.

## ClickHouse audit consumer

Run `cmd/audit-consumer` independently from the gateway. It requires `KAFKA_BROKERS` and `CLICKHOUSE_DSN`; `KAFKA_CONSUMER_GROUP` defaults to `audit-clickhouse-v1`, and invalid v2 messages are sent to `${KAFKA_AUDIT_TOPIC}.dlq` unless `KAFKA_AUDIT_DLQ_TOPIC` is set. DLQ envelopes retain the original bytes in `payload_base64`. A failed DLQ write is retried before the source offset can be committed. The consumer creates its idempotent `audit_events` schema at startup, retains events for 180 days, and exposes `/healthz`, `/readyz`, and `/metrics` on `AUDIT_CONSUMER_LISTEN_ADDR` (default `:9090`).

The gateway's admin listener exposes read-only ClickHouse views when `CLICKHOUSE_DSN` is configured. Sign in through the web app at `http://localhost:3000`; it reverse-proxies same-origin management requests to the gateway's internal `:8081` listener. The web app also provides first-time administrator setup, upstream configuration, and gateway-key management. The gateway encryption key is stored at `/var/lib/gateway/keys/encryption.key` on the `gateway-keys` volume; back up that volume with the database, because losing the key makes saved upstream credentials unrecoverable:

- `GET /admin/v1/audit/events?from=<RFC3339>&to=<RFC3339>&tenant_id=&decision=&direction=&path=&model=&rule_id=&min_risk_score=&page_size=&cursor=`
- `GET /admin/v1/audit/events/<event_id>`
- `GET /admin/v1/audit/summary?from=<RFC3339>&to=<RFC3339>&bucket=hour|day`

Event ranges default to the previous 24 hours and are capped at 31 days. Summaries include decision, direction, model, path, rule, risk, latency, and hourly/daily trend aggregates. ClickHouse availability is intentionally not part of the gateway request readiness contract; an unavailable query store returns 503 only for these admin routes.

## Kafka fault drill

With the Compose project running, sign in through the web app and stop Kafka with `docker compose -f deploy/docker-compose.yml stop kafka`. Confirm `GET /readyz` remains HTTP 200 with the Kafka component degraded, then generate an audited request or admin operation. Check `audit_outbox_pending` on gateway `/metrics` rises. Start Kafka again with `docker compose -f deploy/docker-compose.yml start kafka`; the metric must return to zero after retry backoff, and the replayed `event_id` must appear through the web app's audit view or `GET /admin/v1/audit/events`. This demonstrates that requests are independent of Kafka and that committed audit events are replayable.

## Docker Desktop path compatibility

Docker Compose v5/BuildKit can reject a Windows build context whose absolute path contains non-ASCII punctuation before it reads the Dockerfile. Prefer cloning the repository under an ASCII-only path. As a temporary Docker Desktop fallback, set `$env:DOCKER_BUILDKIT='0'` for the `docker compose build` or `up --build` command; the classic builder is deprecated and should not be the long-term deployment path.
