# 安全加固与密码学指南 (Security & Cryptography)

本系统在设计之初就将安全性作为最高优先级，遵循“安全默认 (Secure by Default)”原则。

## 1. 凭据与数据保护

### 1.1 密码哈希 (Password Hashing)
*   **算法**: 默认使用 `Bcrypt` (Cost: 10)，未来支持平滑迁移至 `Argon2id`。
*   **迁移机制**: 每次用户登录时，系统会自动检查哈希版本。如果检测到算法过时或参数过低，会在验证成功后自动重算并更新数据库。

### 1.2 敏感数据加密 (Secret Encryption)
*   **算法**: `AES-256-GCM` (Authenticated Encryption with Associated Data)。
*   **应用场景**: TOTP 密钥、OAuth2 Client Secret。
*   **密钥管理**: 系统主加密密钥通过环境变量注入。存储格式包含版本前缀（如 `enc:v1:`），支持未来无损进行密钥轮转。

## 2. OAuth2/OIDC 安全协议

*   **PKCE 强制**: 所有的公共客户端（Public Clients）强制启用 PKCE。对于机密客户端，推荐启用 PKCE 以防止授权码拦截。
*   **Token 轮转 (Refresh Token Rotation)**：
    *   Refresh Token 每次使用后都会作废并生成新的。
    *   如果旧的 Refresh Token 再次被使用，系统会判定为重放攻击，立即撤销该 Token 家族下的所有活跃 Token（Family Revocation）。
*   **JWK 轮转**: 签名私钥定期轮转，历史公钥会在 `jwks.json` 中保留一段时间，以确保已签发的令牌在过期前仍可被校验。

## 3. 防御性措施

### 3.1 速率限制 (Rate Limiting)
*   **登录尝试**: 针对 `username` 和 `ip` 两个维度进行计数。连续失败超过阈值将触发锁定。
*   **Redis 实现**: 利用 Lua 脚本实现滑动窗口/固定窗口计数，并自动在 Redis 中创建 `lock:user:{id}`。

### 3.2 账号锁定策略
*   **触发条件**: 默认 15 分钟内连续 5 次登录失败。
*   **解锁方式**: 
    *   自动解锁：到达锁定过期时间。
    *   管理员手动解锁。
*   **审计日志**: 所有的锁定和尝试操作都会被记录在 `audit_events` 中。

## 4. 前端安全
*   **Cookie 安全**: `idp_session` Cookie 强制开启 `HttpOnly`, `Secure` 和 `SameSite=Lax`。
*   **CSP 策略**: 响应头包含严格的内容安全策略，防止 XSS 攻击。
