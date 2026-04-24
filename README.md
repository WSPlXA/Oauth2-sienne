# oauth2-sienne-idp

Language: [English](README.md) | [简体中文](README.zh-CN.md)

`oauth2-sienne-idp` is a highly performant, Go-based Identity Provider (IdP) that implements OAuth2 and OpenID Connect (OIDC). It is built with production-oriented controls for session state management, token lifecycle, replay protection, and key rotation.

## Features

### Authentication & Sessions
- Local registration, login, and logout.
- Browser session cookies (`idp_session`) backed by MySQL and Redis.
- Federated OIDC login (upstream OP -> local user mapping with first-login auto-provisioning).
- OIDC end-session endpoint (`/connect/logout`).
- Single Sign-Out (Logout current session and logout all sessions for current user).

### OAuth2 / OIDC Capabilities
- `authorization_code` grant with PKCE (`plain` and `S256`).
- Consent screen and consent reuse logic.
- Refresh token rotation.
- `client_credentials` grant.
- `password` (legacy grant).
- Device Code Flow (`urn:ietf:params:oauth:grant-type:device_code`).
- Standard endpoints: Discovery, UserInfo, Introspection, JWKS.

### MFA (Multi-Factor Authentication)
- TOTP enrollment (QR returned as a data URL).
- TOTP login challenge (`/login/totp`).
- Forced MFA enrollment policy (`FORCE_MFA_ENROLLMENT=true` by default).
- TOTP step replay protection (`user + purpose + step`).

### Security & Operations
- CSRF double-submit protection (cookie + body/header).
- `return_to` local-path validation (open redirect guard).
- Login rate limiting and account lock protection.
- **High-Performance State Machine**: Session and MFA states use 32-bit bitmasks instead of string comparisons, leveraging CPU-native bitwise operations for state validation.
- **Atomic CAS (Compare-And-Swap)**: Redis-native optimistic concurrency control via Lua scripts prevents "lost updates" and ensures atomic state transitions in concurrent flows.
- **Hardware-Friendly Cache Layer**: Optimized Redis access using `HMGet` and packed `BITFIELD` state storage, reducing memory allocations and network RTT.
- 32-bit RBAC privilege mask for administrative endpoints.
- Audit trail in `audit_events` for admin-sensitive operations.
- Built-in operator role bootstrap and role assignment APIs.

## Architecture Summary

The deployment model utilizes stateless application instances with shared state services:
- **MySQL**: Stores durable entities (users, clients, auth codes, tokens, sessions, key metadata, audits).
- **Redis**: Stores hot/ephemeral state (session cache, state/nonce, replay locks, throttle counters, MFA challenges, device flow state).
- **JWT + JWKS**: Allows resource services to validate access tokens locally when needed.

This architecture ensures high availability and horizontal scalability without depending on in-memory session state in a single node.

## Deep Documentation

For technical details and architectural deep dives, please refer to:

*   **[Architecture Overview](file:///f:/siene/sienne/idp-server/docs/architecture_overview.md)**: Logic layers, DDD, and technology stack.
*   **[Database Design](file:///f:/siene/sienne/idp-server/docs/database_design.md)**: MySQL schema, entity relationships, and optimizations.
*   **[Redis Integration](file:///f:/siene/sienne/idp-server/docs/redis_integration.md)**: Data types, key patterns, and caching strategies.
*   **[Security & Cryptography](file:///f:/siene/sienne/idp-server/docs/security_guide.md)**: Password hashing, secret encryption, and protocol hardening.
*   **[MFA & Passkey Design](file:///f:/siene/sienne/idp-server/docs/mfa_passkey_design.md)**: TOTP, WebAuthn, and challenge-response logic.
*   **[Audit System](file:///f:/siene/sienne/idp-server/docs/audit_system.md)**: Asynchronous event tracking and compliance logging.

### Technical Sequence Diagrams

Visual representations of core OAuth2/OIDC flows:

*   **[Authorization Code + PKCE](file:///f:/siene/sienne/idp-server/docs/seq_auth_code_pkce.md)**
*   **[Federated OIDC Login](file:///f:/siene/sienne/idp-server/docs/seq_federated_login.md)**
*   **[Device Code Flow](file:///f:/siene/sienne/idp-server/docs/seq_device_flow.md)**
*   **[Client Credentials](file:///f:/siene/sienne/idp-server/docs/seq_client_credentials.md)**
*   **[Logout & Session Termination](file:///f:/siene/sienne/idp-server/docs/seq_logout.md)**

## Repository Structure

- `idp-server/cmd/idp`: Application entrypoint.
- `idp-server/internal/application`: Core business orchestration.
- `idp-server/internal/interfaces/http`: HTTP handlers and routers.
- `idp-server/internal/infrastructure`: MySQL, Redis, crypto, and external integrations.
- `idp-server/internal/plugins`: Pluggable authn/client-auth/grant handlers.
- `idp-server/scripts/migrate.sql`: Database schema and seed fixtures.
- `idp-server/scripts/lua`: Redis atomic scripts.
- `idp-server/deploy`: Kubernetes and Podman deployment manifests.

## Quick Start

### Option A: Prebuilt Image Stack (Docker Compose)
```bash
docker compose -f compose.quickstart.yaml up -d
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
```

### Option B: Build Locally from Source
```bash
cd idp-server
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

### Run Tests
```bash
cd idp-server
go test ./...
```

## Seed Data (for Local Demo)

The system initializes with seed data located in `idp-server/scripts/migrate.sql`.

### Users
- `alice` / `alice123`
- `bob` / `bob123`
- `locked_user` / `locked123` (Locked by default)

### Clients
- `web-client`: `authorization_code`, `refresh_token`, PKCE required. (Secret: `secret123`)
- `mobile-public-client`: `authorization_code`, `refresh_token`, public client, auth method `none`.
- `service-client`: `client_credentials`. (Secret: `service123`)
- `legacy-client`: `password`, `refresh_token`. (Shares secret hash with `service-client`)
- `tv-client`: `urn:ietf:params:oauth:grant-type:device_code`. (Shares secret hash with `service-client`)

*(Note: Fixture plaintext secrets are generated via `idp-server/scripts/generate_fixture_hashes.go`)*

### Flow Fixtures
- Session ID: `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- Authorization Code: `sample_auth_code_abc123`
- PKCE Verifier: `verifier123`
- Redirect URI: `http://localhost:3060/callback`

## Endpoint Overview

Router source: `idp-server/internal/interfaces/http/router.go`

- **UI/Auth**: `/register`, `/login`, `/login/totp`, `/mfa/totp/setup`, `/consent`, `/device`
- **Session**: `/logout`, `/logout/all`, `/connect/logout`
- **OAuth2/OIDC**: `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/device/authorize`, `/oauth2/introspect`, `/oauth2/userinfo`, `/oauth2/jwks`
- **Admin/RBAC**: `/admin/rbac/roles`, `/admin/rbac/usage`, `/admin/rbac/bootstrap`, `/admin/users/:user_id/role`, `/admin/users/:user_id/logout-all`

## Key Configuration

Configuration is bootstrapped via `idp-server/internal/bootstrap/wire.go`.

**Core Runtime**
- `ISSUER` (default: `http://localhost:8080`)
- `TOTP_ISSUER` (Authenticator display name, fallbacks to ISSUER host)
- `LISTEN_ADDR` (default: `:8080`)
- `SESSION_TTL` (default: `8h`)
- `APP_ENV` (default: `dev`)

**Storage**
- `MYSQL_DSN` or `MYSQL_HOST`/`MYSQL_PORT`/etc.
- `REDIS_ADDR` or `REDIS_HOST`/`REDIS_PORT`/etc.
- `REDIS_KEY_PREFIX` (default: `idp`)

**Security Controls**
- `FORCE_MFA_ENROLLMENT` (default: `true`)
- `LOGIN_FAILURE_WINDOW`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_MAX_FAILURES_PER_USER`, `LOGIN_USER_LOCK_THRESHOLD`, `LOGIN_USER_LOCK_TTL`

**JWT & Key Rotation**
- `JWT_KEY_ID`, `SIGNING_KEY_DIR`, `SIGNING_KEY_BITS`, `SIGNING_KEY_CHECK_INTERVAL`, `SIGNING_KEY_ROTATE_BEFORE`, `SIGNING_KEY_RETIRE_AFTER`

### Google Federated Login (Quick Start)
1. Create an OAuth Client (Web Application) in Google Cloud Console. Set callback URL to `http://localhost:8080/login`.
2. Configure the following environment variables:
   ```env
   FEDERATED_OIDC_ISSUER=https://accounts.google.com
   FEDERATED_OIDC_CLIENT_ID=<your-client-id>
   FEDERATED_OIDC_CLIENT_SECRET=<your-client-secret>
   FEDERATED_OIDC_REDIRECT_URI=http://localhost:8080/login
   FEDERATED_OIDC_PROVIDER_NAME=Google
   FEDERATED_OIDC_CLIENT_AUTH_METHOD=client_secret_post
   FEDERATED_OIDC_USERNAME_CLAIM=email
   ```
3. Restart `idp-server` and open `/login`. The Google federated button will now be available.


---
**⚠️ Deployment Note for Key Rotation**: Current key management persists metadata in the DB and references private keys via filesystem paths. For safe multi-replica signing, move private-key storage to a shared KMS/Vault/RWX storage with explicit leader control before scaling `idp-server` writers.
