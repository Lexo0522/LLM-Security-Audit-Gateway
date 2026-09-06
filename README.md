# AI API Security Audit Gateway

## Metrics and integration tests

`GET /metrics` exposes Prometheus-format, low-cardinality gateway metrics: request latency/counts, rule decisions, rate-limit rejections, Auditor outcomes/circuit openings, audit queue drops, PostgreSQL batch results, Kafka publish results, Redis limiter/cache results, consumer lag, outbox backlog/age, and retention deletions. Tenant IDs, request IDs, rule IDs, request bodies, tokens, and content hashes are never metric labels.

Run the real PostgreSQL/Redis/Kafka smoke test with Docker Desktop available:

```powershell
./tests/integration/run-compose.ps1
```

The normal `go test ./...` command remains Docker-free. Rule create, publish, and rollback requests are emitted through the same best-effort audit pipeline as proxy traffic, with schema version `2`. These events retain only operation metadata, scope, and outcome.

## Production readiness and managed bootstrap

`/healthz` reports process liveness and build version. `/readyz` reports PostgreSQL identity/audit capability, managed rules and policies, audit queue status, Redis, Kafka/outbox, and the optional model auditor. PostgreSQL, managed snapshots, and audit persistence are required; Redis, Kafka, and the auditor are observable degraded dependencies. Kafka delivery uses a PostgreSQL transactional outbox and replays at least once after recovery.

Production does not run example rules. Run `go run ./cmd/seed -file ./configs/seed.example.json` before the first gateway start, supplying deployment-owned rules instead of the example. `ALLOW_DEMO_BOOTSTRAP_RULES=true` is allowed only for `GATEWAY_ENV=development` or `test`.

## Request and response body handling

The gateway audits the decoded plaintext of every request body. `Content-Encoding: gzip`, `deflate`, and `brotli` are decompressed for rule and model audit, and the decoded body is what reaches the upstream; other encodings are refused with `415` instead of passing through unaudited. On the response side the client's `Accept-Encoding` is replaced so the upstream negotiates only encodings the gateway can decode, and forwarded request headers are an allowlist (cookies, forwarding chains, and caller identity headers never reach the upstream). The proxied target is constrained to the `/v1` boundary of the configured upstream.

`AUDIT_ENABLED=false` turns the audit engine off entirely: the gateway proxies without rule scans, model audits, event persistence, or blocking. `AUDIT_FAIL_CLOSED=true` overrides any per-policy fail-open setting and blocks monitored requests while the synchronous auditor is unavailable.

## ClickHouse audit queries

`go run ./cmd/audit-consumer` consumes the Kafka audit topic into ClickHouse using the consumer group `audit-clickhouse-v1`. Set `CLICKHOUSE_DSN` (the Compose stack derives an authenticated DSN from `CLICKHOUSE_PASSWORD`); events are retained for 180 days and deduplicated by `event_id` at query time. Configure the same DSN on the gateway to enable the admin-only endpoints for paged event search, event detail, and hourly/daily summaries. Consumer failure never changes gateway request readiness.

## SSE incremental auditing and safe termination

Streaming Chat Completions, Legacy Completions, and Responses API responses are parsed as SSE events before forwarding. The gateway audits Chat `choices[].delta.content`, `choices[].delta.tool_calls[].function.arguments`, `choices[].delta.function_call.arguments`, and Legacy `choices[].text`. For `/v1/responses`, it audits `response.output_text.delta`, `response.function_call_arguments.delta`, `response.refusal.delta`, `response.reasoning_text.delta`, and `response.reasoning_summary_text.delta` events through their non-empty JSON `delta` fields. Comments, non-JSON data, unknown event types/JSON fields, and `[DONE]` remain wire-compatible pass-through events.

The gateway keeps an independent rolling semantic window for each choice/content or tool-argument channel, and for each Responses event type plus its item/output/content-or-summary identity. This detects a high-risk string split across events without combining unrelated choices, outputs, tool calls, refusals, or reasoning. `SSE_AUDIT_WINDOW_BYTES` defaults to `16384`; `SSE_MAX_EVENT_BYTES` defaults to `262144` and caps the raw bytes of one complete SSE event.

When a response policy blocks an event, or when an event exceeds the size limit, the gateway cancels the upstream request, does not forward the triggering event, then emits one final event and closes the stream (without adding `[DONE]`):

```text
event: gateway.security_terminated
data: {"error":{"type":"security_termination","code":"stream_policy_blocked","message":"stream response blocked by audit policy","request_id":"<request-id>"}}

```

The alternative size-limit code is `sse_event_too_large`. This event never reveals matched rules, evidence, scores, policies, or model-auditor details. Events already delivered before a later match cannot be retracted. A `redact` decision only redacts audit evidence; it does not alter the upstream SSE bytes.

## Gateway API keys and policy management

Public `/v1/*` calls require a gateway-issued `Authorization: Bearer agw.<uuid>.<secret>` value. The gateway derives the tenant and bound upstream from that key and ignores (and never forwards) caller-provided `X-Tenant-ID`. Identity, upstream configuration, and key metadata are stored in PostgreSQL; key and administrator secrets are never stored in plaintext.

The management web app is served at `http://localhost:3000` by the Compose stack. On first access, use **Set up** to create the administrator account, then sign in. Configure one or more upstreams in the web UI and create a gateway key bound to an upstream; the complete key is shown only once. Use the web UI to manage policies, rules, audit queries, and key revocation. The gateway admin API remains on its internal `:8081` listener and is reverse-proxied by the web service.

`redact` decisions retain hashes and metadata but clear audit evidence; they do not modify proxied model content.

独立部署在用户与兼容上游服务之间的 OpenAI 兼容安全审计网关。当前已提供可运行的 P0–P2 主链路：请求体限制、规则审计、风险评分、阻断、普通响应与 SSE 代理、持久化审计、Kafka 投递和 ClickHouse 分析查询。

## Quick start

```bash
go mod tidy
GATEWAY_ENV=development ALLOW_DEMO_BOOTSTRAP_RULES=true go run ./cmd/gateway
```

For a local deployment, configure upstreams and administrator access through the management web app rather than environment variables. Production deployments must first run `go run ./cmd/seed -file ./configs/seed.example.json` with deployment-owned rules and policies, then start the gateway with the default `GATEWAY_ENV=production`.

网关监听 `:8080`：

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/v1/chat/completions \
	-H 'Authorization: Bearer agw.<uuid>.<secret>' \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

## Docker Compose

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Docker image builds default to China-friendly mirrors (`goproxy.cn` for Go modules, `registry.npmmirror.com` for npm). If your build host can reach the official registries, copy `deploy/.env.example` to `deploy/.env` and point `DOCKER_BUILD_GOPROXY` / `DOCKER_NPM_REGISTRY` back at `proxy.golang.org` / `registry.npmjs.org` (pass `--env-file deploy/.env` when invoking compose from the repo root).

`go test -race` requires cgo and a C toolchain; it runs in CI on Linux. On Windows hosts without GCC, run `make test` locally and let CI cover the race detector.

Open `http://localhost:3000` to complete first-time administrator setup and sign in. The web service serves the SPA and proxies `/admin/v1` to the gateway admin listener, so the management port does not need to be exposed publicly. Add and test upstreams from the web UI, then issue gateway keys bound to those upstreams. The stack retains PostgreSQL, Redis, Kafka, ClickHouse, and the gateway key-encryption volume; no fixed upstream service is bundled. Back up the `gateway-keys` volume together with PostgreSQL: losing `/var/lib/gateway/keys/encryption.key` makes stored upstream API keys unrecoverable. The Compose defaults for database passwords are development-only and must be overridden in production.

## 当前边界

- API Key 与策略依赖 PostgreSQL；API Key 原文不落库。策略通过不可变快照解析，并可经 Redis 通知跨实例刷新。认证失败按来源地址限流。
- 关键词规则使用内存常驻的 Aho-Corasick 自动机，正则规则使用 Go RE2；规则发布后通过不可变快照原子切换，归一化在 NFKC 之外还会剥离零宽等格式字符。
- Kafka→ClickHouse consumer、管理网页和只读审计查询已经实现；完整 RBAC、用量/费用事件仍未实现。PostgreSQL 侧审计表与 outbox 按保留策略定期清理。
- SSE 在转发前逐事件扫描并即时下发（有界内存），命中阻断时终止后续输出；已经发送的数据无法撤回。
- 默认示例规则仅用于演示，请在生产环境改为数据库/配置管理。

工程化基线：根目录 `Makefile` 提供 build/test/race/vet/lint/fuzz/integration/docker；`.github/workflows/ci.yml` 在 Linux 上运行 vet、gofmt、`-race` 测试、govulncheck、fuzz 冒烟与 Compose 集成测试。下一阶段重点是热路径压测、威胁模型和审计模型校准；真实审计模型先以异步影子模式校准，再按策略进入同步阻断路径。
