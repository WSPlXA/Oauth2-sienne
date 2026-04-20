# 多因素认证 (MFA) 与 Passkey 设计

本系统提供金融级的多因素认证能力，支持传统的 TOTP 令牌以及现代的 WebAuthn (Passkey) 生物识别认证。

## 1. 认证方法支持

### 1.1 TOTP (Time-based One-Time Password)
*   **算法**: 遵循 RFC 6238，默认使用 `SHA1` 算法，6位数字，30秒步长。
*   **安全性**: 
    *   **加密存储**: TOTP 密钥在数据库中通过 `AES-256-GCM` 加密，前缀为 `enc:v1:`。
    *   **重放保护**: 使用 Redis 记录已使用的步数（Step），在有效期内禁止同一个验证码被二次提交。

### 1.2 WebAuthn / Passkey
*   **支持**: FIDO2 规范。支持指纹、面容 ID、USB 安全密钥（如 YubiKey）。
*   **流程**:
    *   **注册**: 后台生成 `Challenge` 并存入 Redis，前端调用 WebAuthn API 进行签名并返回公钥及凭据 ID。
    *   **认证**: 后台检索凭据公钥，校验前端返回的签名及 `SignCount`，防止克隆攻击。

## 2. MFA 挑战-响应机制 (Challenge-Response)

系统采用异步且有状态的挑战机制：

1.  **触发挑战**: 在用户完成密码验证后，若检测到用户开启了 MFA，系统会生成一个唯一的 `mfa_challenge_id`。
2.  **状态存储**: 挑战上下文（包含所属用户、可选认证方式、尝试次数）存储在 Redis 哈希中 (`idp:dev:mfa:challenge:{id}`)。
3.  **状态掩码 (Bitfield)**：利用 Redis Bitfield 存储挑战的当前阶段（如：等待 TOTP、等待 WebAuthn、已锁定等）。
4.  **最终决策**: 只有当 MFA 挑战状态变为 `verified` 时，系统才会签发最终的 `idp_session` 或 OAuth2 Code。

## 3. 安全策略

*   **阶梯式锁定**: 同一个 MFA 挑战如果连续失败 3 次，该次挑战将失效。
*   **环境一致性**: 校验挑战响应时，会检查请求的 IP 和 User-Agent 是否与发起挑战时一致，防止会话劫持。
