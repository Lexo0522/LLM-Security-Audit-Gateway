# API 兼容性

网关首版保留 NewAPI 的 OpenAI 兼容路径和主要请求字段：

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`
- `stream=true` 的 SSE 响应
- `usage`、`tool_calls`、`finish_reason` 和 `[DONE]`

网关不允许请求体指定任意上游地址；上游只由 `NEWAPI_BASE_URL` 配置。请求方向使用规范化副本审计，原始 body 继续转发。

流式响应会逐行扫描并及时转发。若后续 chunk 命中高风险规则，网关会停止继续转发，但已经发送给客户端的内容无法撤回。
