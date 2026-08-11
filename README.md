# AI API Security Audit Gateway

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
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

## Docker Compose

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Compose 中的 NewAPI 镜像和环境变量仅用于开发起步；生产部署前应固定镜像版本、配置持久化、认证、TLS 和密钥管理。

## 当前边界

- 规则在进程启动时加载为不可变快照；后续接 PostgreSQL/Redis 管理发布和回滚。
- 规则使用关键词包含匹配或 Go RE2；Aho-Corasick 自动机将在规则规模扩大时替换关键词实现。
- 当前没有完整审计事件持久化、Kafka producer、ClickHouse consumer、模型 auditor 和后台 API。
- SSE 能在转发前按行扫描，并可在命中阻断时终止后续输出；已经发送的数据无法撤回。
- 默认示例规则仅用于演示，请在生产环境改为数据库/配置管理。

后续按 `C:\Users\Xing\.claude\plans\ai-api-jazzy-lerdorf.md` 中的 P1–P4 阶段继续实现。
