# 审计日志系统 (Audit System)

系统内置了全面的审计追踪能力，记录所有与安全相关的关键事件，以满足合规性与故障排查需求。

## 1. 系统架构

审计系统采用**异步写入、双级缓冲**的设计，以确保审计日志生成不阻塞主业务流程。

1.  **采集**: 业务代码通过领域事件触发审计记录。
2.  **缓冲 (Redis Stream)**: 审计事件首先被推送至 Redis Stream (`idp:dev:audit:stream`)。这提供了极高的写入吞吐量，并能应对 MySQL 瞬时负载过高的问题。
3.  **持久化 (Consumer)**: 后台 Consumer 协程异步消费 Stream 数据，并将其批量持久化至 MySQL `audit_events` 表。
4.  **DLQ 机制**: 若持久化连续失败，事件会被转移至 `idp:dev:audit:dlq` 进行重试或人工干预。

## 2. 审计事件结构

每个审计事件包含以下核心字段：

*   **`event_id`**: 全球唯一标识。
*   **`event_type`**: 事件分类（如：`authn.login_success`, `authz.token_issued`, `mfa.bound`）。
*   **上下文主体**: `user_id`, `client_id`, `ip_address`, `user_agent`。
*   **`metadata_json`**: 存储特定事件的补充信息（如：OAuth2 的 Scopes，登录失败的原因等）。

## 3. 典型监控场景

*   **异常异地登录**: 监控同一个用户在短时间内 IP 发生剧烈变动的 `authn.login_success` 事件。
*   **凭据重放检测**: 监控 `token.refresh_replay_detected` 事件。
*   **RBAC 提权监控**: 监控所有对 `users` 表 `role_code` 字段进行修改的 `admin.user_update` 事件。
