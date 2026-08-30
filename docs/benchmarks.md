# 热路径基准（Baseline）

微基准覆盖完整的公开代理路径：fiber 路由 → API Key 认证 → 限流 → 请求体解码
→ 归一化 → 规则扫描 → 策略解析 → 审计事件入队 → 上游交换（经响应管道回写）。
客户端侧走 fiber 的测试连接、上游为 `httptest` 内存服务，因此**绝对数值只在同
一台机器、同一版本之间可比**——它的用途是回归基线，不是容量规划。

## 复现

```bash
go test -run=^$ -bench=. -benchmem -benchtime=2s ./internal/httpapi
```

对比两次运行可用 `benchstat`：

```bash
go test -run=^$ -bench=. -benchmem -count=10 ./internal/httpapi > new.txt
benchstat old.txt new.txt
```

## 基线

记录时间：2026-08-30 · Windows 10（10.0.26100）· 24 线程 · Go 1.26.6 ·
fiber v2.52.15 / fasthttp v1.73.0 · commit 参见 git 历史（本文件首次提交）。

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| ProxyJSON（审计全开） | 292,073 | 38,988 | 279 |
| ProxyJSONAuditDisabled（AUDIT_ENABLED=false） | 257,741 | 30,678 | 216 |
| ProxySSE（50 个 delta 事件 + [DONE]） | 2,399,021 | 349,941 | 2,442 |

## 观察点

- **审计引擎的代价约为 +13% 延迟**（+34µs）、+8KB 内存、+63 次分配每请求；
  这是规则扫描 + 策略解析 + 事件入队的全套开销。
- **SSE 约为 48µs/事件、49 allocs/事件**：每个事件经历窗口拼接 → 归一化 →
  规则扫描 → 策略解析 → 审计事件入队 → 管道回写。
- 每次改动热路径（normalize、rule 引擎、metrics、stream、响应回写）后应重跑
  基准并与本表对比，防止回归悄悄叠加。

## 已落地的热路径优化（对照提交历史）

- 请求体单次 JSON 解析（text/model/stream 一次产出）
- Aho-Corasick 匹配去 map 化（代际数组 + 池化缓冲）
- metrics 写入 32 分片，热路径不再争抢全局锁
- 上游专用 Transport（连接复用 + 分阶段超时）
- SSE 响应经 io.Pipe 真流式下发，内存有界
- SSE 片段抽取单次 Unmarshal；滚动窗口缓冲复用
- shadow 审计改为有界队列（256 槽 + 2 worker）
