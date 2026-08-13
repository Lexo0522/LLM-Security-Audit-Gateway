# API 兼容性

## SSE incremental audit behavior

The gateway preserves each upstream SSE event byte-for-byte, while parsing event `data:` values for response auditing. It supports Chat Completions `choices[].delta.content`, `choices[].delta.tool_calls[].function.arguments`, and `choices[].delta.function_call.arguments`, plus Legacy Completions `choices[].text`. `/v1/responses` additionally supports the non-empty JSON `delta` field of `response.output_text.delta`, `response.function_call_arguments.delta`, `response.refusal.delta`, `response.reasoning_text.delta`, and `response.reasoning_summary_text.delta`. Multi-line `data:` fields are joined according to SSE rules. Comments, empty data, `[DONE]`, non-JSON data, unknown event types, and unknown JSON structures are forwarded without content inspection.

Each semantic field has an independent `SSE_AUDIT_WINDOW_BYTES` rolling window (default `16384`) so rules can match content split across events without concatenating separate choices, tool calls, Responses outputs, refusals, or reasoning. Responses windows are keyed by event type and item/output/content-or-summary identifiers. A complete raw SSE event may not exceed `SSE_MAX_EVENT_BYTES` (default `262144`).

After a response-side `block`, the gateway cancels the upstream request before forwarding the matched event and writes this terminal SSE event before closing the client connection:

```text
event: gateway.security_terminated
data: {"error":{"type":"security_termination","code":"stream_policy_blocked","message":"stream response blocked by audit policy","request_id":"<request-id>"}}

```

An oversized event uses the same format with code `sse_event_too_large`. The gateway never appends `[DONE]` after either terminal event and never includes rule, score, policy, evidence, or auditor details. Previously forwarded events cannot be withdrawn. `redact` affects audit evidence only and does not rewrite streaming content.

网关首版保留 NewAPI 的 OpenAI 兼容路径和主要请求字段：

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`
- `POST /v1/responses`
- `stream=true` 的 SSE 响应
- `usage`、`tool_calls`、`finish_reason` 和 `[DONE]`

网关不允许请求体指定任意上游地址；上游只由 `NEWAPI_BASE_URL` 配置。请求方向使用规范化副本审计，原始 body 继续转发。

流式响应会逐行扫描并及时转发。若后续 chunk 命中高风险规则，网关会停止继续转发，但已经发送给客户端的内容无法撤回。
