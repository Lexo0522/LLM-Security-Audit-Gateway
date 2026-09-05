# 需求备忘（原始需求整理）

开发一个独立的 AI API 安全审计网关（AI Firewall Gateway），部署在用户与兼容上游服务
之间，实现请求审计、违规检测、自动拦截、风险评分、日志分析，并尽可能保持低延迟。

## 技术选型

- 网关框架：Go Fiber（上游代理走 net/http Transport）
- 规则引擎：关键词 Aho-Corasick + Go RE2 正则
- 缓存/限流：Redis
- 数据库：PostgreSQL（身份、规则/策略快照、审计落盘、事务性 outbox）
- 分析库：ClickHouse（Kafka 消费写入）
- 消息队列：Kafka
- 后台：Vue3 管理网页（通过同源 `/admin/v1` 配置管理员、上游和网关 Key）
- 审计模型：通用 `AUDITOR_URL` HTTP 审计器适配（可对接 Qwen2.5 / Llama Guard 等）
- 部署：Docker Compose

> 本文件由仓库根目录的原始需求草稿整理而来；与当前实现不一致处以代码与
> README 为准。
