# AI API Security Audit Gateway

## Metrics and integration tests

`GET /metrics` exposes Prometheus-format, low-cardinality gateway metrics: request latency/counts, rule decisions, rate-limit rejections, Auditor outcomes/circuit openings, audit queue drops, PostgreSQL batch results, Kafka publish results, and Redis limiter/cache results. Tenant IDs, request IDs, rule IDs, request bodies, tokens, and content hashes are never metric labels.

Run the real PostgreSQL/Redis/Kafka smoke test with Docker Desktop available:

```powershell
./tests/integration/run-compose.ps1
```

The normal `go test ./...` command remains Docker-free. Rule create, publish, and rollback requests are emitted through the same best-effort audit pipeline as proxy traffic, with schema version `2`. These events retain only operation metadata, scope, outcome, and a SHA-256 digest of the administrator token.

## Gateway API keys and policy management

Public `/v1/*` calls require a gateway-issued `Authorization: Bearer agw.<uuid>.<secret>` value. The gateway derives the tenant from that key and ignores (and never forwards) caller-provided `X-Tenant-ID`. Set `POSTGRES_URL` and a random `GATEWAY_API_KEY_PEPPER` of at least 32 bytes before starting; identity storage failure returns `503` rather than allowing an unauthenticated request.

With `ADMIN_API_TOKEN` configured on the admin listener, use `POST /admin/v1/api-keys` with `{ "tenant_id": "tenant-a" }` to create a key. The raw key is returned only by that response. `GET /admin/v1/api-keys` lists safe metadata, and `POST /admin/v1/api-keys/:id/revoke` immediately revokes a key. `POST/GET /admin/v1/policies` plus `PUT/DELETE /admin/v1/policies/:id` manage per-scope, route, and direction audit thresholds. `redact` decisions retain hashes and metadata but clear audit evidence; they do not modify proxied model content.

独立部署在用户与 NewAPI 之间的 OpenAI 兼容安全审计网关。当前已提供可运行的 P0/P1 骨架：请求体限制、规则审计、风险评分、阻断、普通响应代理和 SSE 逐行透传扫描。

## Quick start

```bash
go mod tidy
go run ./cmd/gateway
```

设置 `NEWAPI_BASE_URL` 指向 NewAPI，例如：

```bash
NEWAPI_BASE_URL=http://localhost:3000 go run ./cmd/gateway
```

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

Compose 中的 NewAPI 镜像和环境变量仅用于开发起步；生产部署前应固定镜像版本、配置持久化、认证、TLS 和密钥管理。

## 当前边界

- API Key 与策略依赖 PostgreSQL；API Key 原文不落库。策略通过不可变快照解析，并可经 Redis 通知跨实例刷新。
- 规则使用关键词包含匹配或 Go RE2；Aho-Corasick 自动机将在规则规模扩大时替换关键词实现。
- ClickHouse consumer、完整 RBAC 和后台 UI 尚未实现。
- SSE 能在转发前按行扫描，并可在命中阻断时终止后续输出；已经发送的数据无法撤回。
- 默认示例规则仅用于演示，请在生产环境改为数据库/配置管理。

后续按 `C:\Users\Xing\.claude\plans\ai-api-jazzy-lerdorf.md` 中的 P1–P4 阶段继续实现。
