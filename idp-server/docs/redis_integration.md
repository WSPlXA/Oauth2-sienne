# Redis 集成与数据架构说明

本系统深度集成 Redis 作为高性能的热数据缓存层和状态机引擎，旨在实现无状态的应用节点以及毫秒级的认证状态校验。

## 1. 使用的数据类型

系统根据不同的业务场景，选用了 Redis 提供的多种高效数据结构：
# Redis 集成与高性能状态机设计

本系统将 Redis 7.0+ 作为核心的高性能缓存与状态存储层。除了基础的 K-V 存储外，系统深度利用了 Redis 的原子性操作和高级数据结构。

## 1. 核心数据结构应用

| 功能模块 | Redis 数据类型 | 应用场景说明 |
| :--- | :--- | :--- |
| **会话对象** | `Hash` | 存储 `idp_session` 的详细元数据（UID, ACR, AMRs 等）。 |
| **状态掩码** | `Bitfield` | 存储会话或 MFA 挑战的当前阶段，利用位运算实现极速状态机。 |
| **用户会话索引** | `Set` | 记录用户名下所有的活跃会话 ID，支持“退出所有设备”功能。 |
| **限流计数器** | `String` | 配合 `INCR` 和 `EXPIRE` 实现 IP 或用户维度的滑动窗口限流。 |
| **防重放保护** | `String` | 存储 Nonce 或已使用的 TOTP 步数，设置短 TTL 自动过期。 |
| **令牌轮转** | `String` | 存储 Refresh Token 家族的最新状态，防止令牌拦截重放。 |
| **审计缓冲** | `Stream` | 异步记录安全审计事件，解耦主业务与数据库写入负载。 |

## 2. Key 命名规范与模式

所有 Key 均遵循 `{Prefix}:{Env}:{Module}:{Type}:{Identifier}` 的格式。

| 模式 (Key Pattern) | 说明 | TTL 策略 |
| :--- | :--- | :--- |
| `idp:dev:session:sid:{sid}` | 会话元数据 (Hash) | 8h (默认) |
| `idp:dev:session:state:{sid}` | 会话状态位 (Bitfield) | 与会话同步 |
| `idp:dev:session:user:{uid}` | 用户会话集合 (Set) | 动态续期 |
| `idp:dev:mfa:challenge:{cid}` | MFA 挑战上下文 (Hash) | 15m |
| `idp:dev:token:refresh:sha256:{sha}` | 刷新令牌元数据 | 14d |
| `idp:dev:lock:user:{uid}` | 账号锁定标记 | 15m |
| `idp:dev:audit:stream` | 审计日志流 (Stream) | 无 (由 Consumer 清理) |

## 3. 原子操作示例 (Atomic Patterns)

系统通过 **Lua 脚本** 确保在分布式环境下的操作原子性，防止 Race Condition。

### 3.1 令牌轮转与重放防护 (Token Rotation)
当使用 Refresh Token 换取新令牌时，系统必须原子性地：
1. 校验旧令牌是否有效。
2. 校验该令牌家族（Family）是否已被标记为泄露。
3. 作废旧令牌并签发新令牌。

```lua
-- rotate_token.lua 逻辑片段
local current_token = redis.call('GET', KEYS[1])
if not current_token then return {err = "token_expired"} end

local family_revoked = redis.call('GET', KEYS[2])
if family_revoked then
    -- 如果家族已被撤销，说明是重放攻击
    return {err = "family_compromised"}
end

-- 标记旧令牌为已使用，并设置短暂的 Grace Period (宽限期)
redis.call('SETEX', KEYS[1], ARGV[1], "used")
-- 存储新令牌关系...
```

### 3.2 MFA 挑战状态机 (MFA Bitfield)
使用 `BITFIELD` 存储状态，例如：
*   第 0 位：是否已完成密码验证
*   第 1 位：是否已完成 TOTP 验证
*   第 2 位：是否已完成 WebAuthn 验证

```go
// 通过 Redis 原子位操作更新状态
// SET u1 #0 1 -> 将第 0 个无符号 1 位字段设为 1
err := rdb.BitField(ctx, challengeKey, "SET", "u1", "#1", 1).Err()
```

### 3.3 审计流异步缓冲 (Stream Buffering)
```go
// 生产者：业务端极速写入
_, err := rdb.XAdd(ctx, &redis.XAddArgs{
    Stream: "idp:dev:audit:stream",
    Values: map[string]interface{}{
        "event_id":   "evt_123",
        "event_type": "login_success",
        "payload":    jsonPayload,
    },
}).Result()
```

## 4. 性能优化点

1.  **HMGet 批量获取**: 在加载 Session 时，一次性从 Redis Hash 中取出所有必要字段，减少网络 RTT。
2.  **Pipeline 合并写入**: 在创建授权码和关联状态时，使用 Pipeline 合并多个命令。
3.  **Lua 脚本预加载**: 系统启动时通过 `SCRIPT LOAD` 预加载所有状态机脚本，后续调用仅传输 SHA1 值。
