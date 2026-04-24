# 架构设计概览 (Architecture Overview)

`idp-server` 遵循 **Clean Architecture (整洁架构)** 思想，并结合 **DDD (领域驱动设计)** 的分层模型进行工程化落地。

## 1. 逻辑分层结构

代码组织严格遵循“依赖向内”原则：

### 1.1 Interface 层 (接口层)
*   **路径**: `internal/interfaces/`
*   **职责**: 处理外部协议输入。
*   **组件**:
    *   `http/`: 基于 Gin 框架实现的 RESTful API 和 OAuth2 端点。
    *   `middleware/`: 处理全局 Trace ID、日志、跨域及 Session 恢复。

### 1.2 Application 层 (应用层)
*   **路径**: `internal/application/`
*   **职责**: 编排业务逻辑，处理跨领域的工作流（Use Cases）。
*   **组件**:
    *   `service/`: 如 `AuthService` (登录编排)、`TokenService` (令牌发放流程)。它不涉及具体存储，而是调用 Domain 层的接口。

### 1.3 Domain 层 (领域层) - 核心
*   **路径**: `internal/domain/`
*   **职责**: 核心业务实体、领域逻辑及抽象接口（Ports）。
*   **组件**:
    *   `entity/`: 纯净的业务对象（如 `User`, `OAuthClient`）。
    *   `repository/`: 定义持久化接口（Interface），不依赖具体数据库。
    *   `logic/`: 复杂的领域算法（如权限掩码计算、Token 签名逻辑）。

### 1.4 Infrastructure 层 (基础设施层)
*   **路径**: `internal/infrastructure/`
*   **职责**: 为内部层提供具体的技术实现。
*   **组件**:
    *   `persistence/`: MySQL 具体实现。
    *   `cache/`: Redis 具体实现。
    *   `crypto/`: 密码哈希、AES 加密、RSA 签名工具。

## 2. 核心技术选型

*   **依赖注入 (DI)**: 使用 **Google Wire** 进行静态依赖注入。在 `internal/bootstrap` 中通过 `wire.go` 编译生成依赖图，确保了组件间的松耦合。
*   **状态管理**:
    *   **持久化状态**: 存储于 MySQL。
    *   **热状态 (Hot State)**: 存储于 Redis。
*   **安全加固**:
    *   **密文存储**: 敏感字段采用 `AES-GCM` 加密。
    *   **签名机制**: 令牌采用 `RS256` 算法，支持 JWK 轮转。

## 3. 典型的请求处理链路

1.  **Router** 接收请求 -> **Middleware** 注入 Context -> **Controller** 解析参数。
2.  **Controller** 调用 **Application Service**。
3.  **Application Service** 从 **Repository (Port)** 读取数据。
4.  **Infrastructure (MySQL/Redis)** 提供数据实现。
5.  **Application Service** 执行业务规则，并调用 **Domain Entity**。
6.  **Application Service** 通过 **Repository** 保存结果，并返回。
