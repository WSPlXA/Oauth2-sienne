# oauth2-sienne-idp

语言: [English](README.md) | [简体中文](README.zh-CN.md)

`oauth2-sienne-idp` 是一个高性能的、基于 Go 开发的 Identity Provider (IdP)，完整实现了 OAuth2 和 OpenID Connect (OIDC) 协议。系统提供面向生产环境的会话状态管理、令牌生命周期控制、防重放攻击保护以及签名密钥轮转能力。

## 已实现能力

### 认证与会话
- 本地用户注册、登录与登出。
- 基于 MySQL + Redis 联合承载的浏览器会话 Cookie（`idp_session`）。
- 联邦 OIDC 登录（支持上游 OP 回调后映射本地用户，首次登录可自动静默注册）。
- OIDC End Session 端点（`/connect/logout`）。
- 单点登出（注销当前会话并支持踢除当前用户的所有在线端）。

### OAuth2 / OIDC 特性
- `authorization_code` 授权码模式，强制支持 PKCE（`plain` / `S256`）。
- 授权同意 (Consent) 页面与同意记录复用机制。
- 刷新令牌 (Refresh Token) 轮转。
- `client_credentials` 客户端凭据模式。
- `password` 密码模式（兼容旧版客户端）。
- 设备授权码流程（`urn:ietf:params:oauth:grant-type:device_code`）。
- 标准端点：Discovery、UserInfo、Introspection、JWKS。

### MFA (多因素认证)
- TOTP 密钥绑定（二维码直接以 Base64 data URL 返回）。
- TOTP 二步验证登录（`/login/totp`）。
- 强制 MFA 入组策略（通过 `FORCE_MFA_ENROLLMENT=true` 默认开启）。
- TOTP 步数级防重放保护（`user + purpose + step` 联合防刷）。

### 安全与运维
- CSRF 双提交校验（cookie + body/header 联合校验）。
- `return_to` 本地路径防篡改校验（防御开放重定向攻击）。
- 登录失败限流与用户自动锁定机制。
- **高性能状态机**：会话与 MFA 状态采用 32 位掩码（Bitmask）存储，替代传统的字符串比较，充分利用 CPU 原生位运算完成毫秒级状态校验。
- **原子 CAS (Compare-And-Swap)**：通过 Redis Lua 脚本实现原生的乐观锁，杜绝高并发链路中的“更新丢失”，确保所有状态转换的绝对原子化。
- **硬件亲和型缓存层**：优化 Redis 访问模型，采用 `HMGet` 配合紧凑的 `BITFIELD` 状态存储格式，大幅减少内存分配碎片与网络往返（RTT）。
- 32 位 RBAC 权限掩码保护所有管理接口。
- 敏感管理操作强制写入 `audit_events` 审计日志表。
- 内置运维角色初始化与用户角色分配 API。

## 架构摘要

系统的部署模型采用**无状态应用实例 + 共享状态服务**架构：
- **MySQL**：负责持久化核心实体（如：用户、客户端应用、授权码、令牌、会话元数据、密钥、审计日志）。
- **Redis**：承载高频热点与临时状态（如：会话缓存、State/Nonce、防重放锁、限流计数器、MFA 挑战状态、设备授权码轮询状态）。
- **JWT + JWKS**：允许下游资源服务直接拉取公钥在本地进行 Access Token 的验签，无需频繁回调。

这种架构解耦了单机内存会话依赖，使服务天然支持水平横向扩展 (Horizontal Scaling)。

## 深入技术文档

关于技术细节和架构深度的说明，请参考：

*   **[架构设计概览](file:///f:/siene/sienne/idp-server/docs/architecture_overview.md)**: 逻辑分层、DDD 以及技术栈选型。
*   **[数据库架构设计](file:///f:/siene/sienne/idp-server/docs/database_design.md)**: MySQL 表结构、实体关系及性能优化。
*   **[Redis 集成说明](file:///f:/siene/sienne/idp-server/docs/redis_integration.md)**: 数据类型选用、Key 命名规范及缓存策略。
*   **[安全加固与密码学](file:///f:/siene/sienne/idp-server/docs/security_guide.md)**: 密码哈希、敏感数据加密及协议安全。
*   **[MFA 与 Passkey 设计](file:///f:/siene/sienne/idp-server/docs/mfa_passkey_design.md)**: TOTP、WebAuthn 以及挑战响应逻辑。
*   **[审计日志系统](file:///f:/siene/sienne/idp-server/docs/audit_system.md)**: 异步事件追踪与合规性日志架构。

### 核心技术流程图

核心 OAuth2/OIDC 流程的可视化展示：

*   **[授权码模式 + PKCE](file:///f:/siene/sienne/idp-server/docs/seq_auth_code_pkce.md)**
*   **[联邦 OIDC 登录](file:///f:/siene/sienne/idp-server/docs/seq_federated_login.md)**
*   **[设备授权码模式](file:///f:/siene/sienne/idp-server/docs/seq_device_flow.md)**
*   **[客户端凭据模式](file:///f:/siene/sienne/idp-server/docs/seq_client_credentials.md)**
*   **[登出与会话销毁](file:///f:/siene/sienne/idp-server/docs/seq_logout.md)**

## 目录结构

- `idp-server/cmd/idp`: 程序主入口。
- `idp-server/internal/application`: 核心业务逻辑与流程编排。
- `idp-server/internal/interfaces/http`: HTTP 处理器与路由分发。
- `idp-server/internal/infrastructure`: 基础设施层（MySQL、Redis、密码学算法、外部接口集成）。
- `idp-server/internal/plugins`: 可插拔的 AuthN / Client-Auth / Grant 处理器。
- `idp-server/scripts/migrate.sql`: 数据库初始化 Schema 与测试 Seed 数据。
- `idp-server/scripts/lua`: Redis Lua 原子操作脚本库。
- `idp-server/deploy`: Kubernetes 与 Podman 的部署清单文件。

## 快速开始

### 方案 A：使用 Docker Compose 预构建镜像（推荐快速体验）
```bash
docker compose -f compose.quickstart.yaml up -d
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
```

### 方案 B：本地源码编译构建
```bash
cd idp-server
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

### 运行单元测试
```bash
cd idp-server
go test ./...
```

## 预置 Seed 数据（用于本地演示）

数据库通过 `idp-server/scripts/migrate.sql` 初始化后，会默认包含以下测试数据：

### 测试用户
- `alice` / 密码：`alice123`
- `bob` / 密码：`bob123`
- `locked_user` / 密码：`locked123`（默认已锁定状态）

### 测试客户端 (Clients)
- `web-client`：`authorization_code`、`refresh_token`，强制要求 PKCE。（Secret: `secret123`）
- `mobile-public-client`：`authorization_code`、`refresh_token`，公共客户端，认证方式为 `none`。
- `service-client`：`client_credentials` 模式。（Secret: `service123`）
- `legacy-client`：`password`、`refresh_token` 模式。（复用 service-client 相同的 Secret Hash）
- `tv-client`：`urn:ietf:params:oauth:grant-type:device_code` 设备授权码模式。（复用相同的 Secret Hash）

*(注：明文 Fixture Secret 生成逻辑位于 `idp-server/scripts/generate_fixture_hashes.go`)*

### 预置流程样本
- Session ID: `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- Authorization Code: `sample_auth_code_abc123`
- PKCE Verifier 样本: `verifier123`
- Redirect URI 回调地址: `http://localhost:3060/callback`

## 接口端点总览

详细路由定义请参考：`idp-server/internal/interfaces/http/router.go`

- **UI / 认证模块**: `/register`、`/login`、`/login/totp`、`/mfa/totp/setup`、`/consent`、`/device`
- **会话与注销**: `/logout`、`/logout/all`、`/connect/logout`
- **OAuth2 / OIDC**: `/.well-known/openid-configuration`、`/oauth2/authorize`、`/oauth2/token`、`/oauth2/device/authorize`、`/oauth2/introspect`、`/oauth2/userinfo`、`/oauth2/jwks`
- **Admin / RBAC 管理**: `/admin/rbac/roles`、`/admin/rbac/usage`、`/admin/rbac/bootstrap`、`/admin/users/:user_id/role`、`/admin/users/:user_id/logout-all`

## 核心配置参考

配置对象的自动装配入口位于：`idp-server/internal/bootstrap/wire.go`

**运行时基础配置**
- `ISSUER`（默认：`http://localhost:8080`）
- `TOTP_ISSUER`（认证器 App 中显示的名称；未设置时回退使用 ISSUER 的域名）
- `LISTEN_ADDR`（默认：`:8080`）
- `SESSION_TTL`（默认：`8h`）
- `APP_ENV`（默认：`dev`）

**持久化存储**
- `MYSQL_DSN`（或提供 `MYSQL_HOST`/`MYSQL_PORT`...）
- `REDIS_ADDR`（或提供 `REDIS_HOST`/`REDIS_PORT`...）
- `REDIS_KEY_PREFIX`（Redis 键前缀，默认：`idp`）

**安全防护**
- `FORCE_MFA_ENROLLMENT`（默认：`true`）
- 防刷与风控参数：`LOGIN_FAILURE_WINDOW`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_MAX_FAILURES_PER_USER`, `LOGIN_USER_LOCK_THRESHOLD`, `LOGIN_USER_LOCK_TTL`

**JWT 与密钥轮转**
- `JWT_KEY_ID`, `SIGNING_KEY_DIR`, `SIGNING_KEY_BITS`, `SIGNING_KEY_CHECK_INTERVAL`, `SIGNING_KEY_ROTATE_BEFORE`, `SIGNING_KEY_RETIRE_AFTER`

### Google 联邦登录（Quick Start 配置）
1. 在 Google Cloud Console 中创建一个 OAuth Client (Web Application)，将回调地址配置为 `http://localhost:8080/login`。
2. 注入以下环境变量：
   ```env
   FEDERATED_OIDC_ISSUER=https://accounts.google.com
   FEDERATED_OIDC_CLIENT_ID=<your-client-id>
   FEDERATED_OIDC_CLIENT_SECRET=<your-client-secret>
   FEDERATED_OIDC_REDIRECT_URI=http://localhost:8080/login
   FEDERATED_OIDC_PROVIDER_NAME=Google
   FEDERATED_OIDC_CLIENT_AUTH_METHOD=client_secret_post
   FEDERATED_OIDC_USERNAME_CLAIM=email
   ```
3. 重启 `idp-server`，再次访问 `/login` 页面，即可看见 Google 专属登录按钮并体验联邦回调闭环。


---
**⚠️ 生产部署注意事项（密钥轮转）**：当前版本的私钥引用于宿主机/容器文件系统。在生产环境执行多节点水平扩容时，请确保将私钥挂载迁移至高可用共享卷（如 NFS/RWX 存储）或专业密钥管理系统 (KMS/Vault)，并配合显式的 Leader 选举机制来执行安全的自动化密钥轮转。
