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
