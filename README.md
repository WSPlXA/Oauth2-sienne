# idp-server

Go で実装した IDP / OAuth2 / OIDC サーバーです。  
現在のリポジトリでは、ログイン、認可コードフロー、リフレッシュトークンのローテーション、`userinfo`、OIDC Discovery、JWKS、Redis Lua スクリプトのプリロードまでを一通り試せます。

## 提供中の API

- `POST /register`
- `POST /login`
- `POST /logout`
- `GET /oauth2/authorize`
- `POST /oauth2/token` の `authorization_code`
- `POST /oauth2/token` の `refresh_token`
- `POST /oauth2/token` の `client_credentials`
- `POST /oauth2/clients`
- `POST /oauth2/clients/:client_id/redirect-uris`
- `GET /oauth2/userinfo`
- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- Redis Lua スクリプトのプリロードと実行

`/oauth2/authorize` では以下を検証します。

- `response_type=code`
- client の存在、状態、`authorization_code` grant の許可
- `redirect_uri`
- request scope が client の許可範囲内か
- PKCE パラメータ
- `idp_session` に対応するログインセッションの有効性

条件を満たすと、新しい authorization code を発行して client にリダイレクトします。

`/consent` では以下の挙動があります。

- client が consent 必須で、現在の scope が未許可の場合、`/oauth2/authorize` は `/consent?return_to=...` に遷移
- `GET /consent` は HTML の consent 画面または JSON サマリーを返す
- `POST /consent` は `action=accept` / `action=deny` を受け付ける
- `accept` は consent を保存して元の authorize リクエストに戻す
- `deny` は client の `redirect_uri` に `error=access_denied` を付けて戻す

OIDC メタデータ系のエンドポイントも利用できます。

- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`

認可要求に `openid` scope が含まれている場合、`POST /oauth2/token` は `id_token` も返します。現在の `id_token` には以下の代表的な claims が含まれます。

- `iss`
- `sub`
- `aud`
- `exp`
- `iat`
- `auth_time`
- `nonce`
- `azp`
- `name`
- `preferred_username`
- `email`
- `email_verified`

## 動作要件

- Go 1.24+
- MySQL 8
- Redis 7+

## データベース初期化

基本は `make` 経由が簡単です。

```bash
make migrate
```

MySQL がコンテナ内にある場合は次でも実行できます。

```bash
make migrate-docker
```

内部では [migrate.sql](idp-server/scripts/migrate.sql) を流しています。

## 環境変数

起動時はまず完全な接続設定を参照し、未設定ならホスト名ベースの設定から組み立てます。

### MySQL

次のどちらかを設定します。

- `MYSQL_DSN`
- または以下をまとめて設定
  - `MYSQL_HOST`
  - `MYSQL_DATABASE`
  - `MYSQL_USER`
  - `MYSQL_PASSWORD`
  - `MYSQL_PORT` は省略時 `3306`

### Redis

次のどちらかを設定します。

- `REDIS_ADDR`
- または以下を設定
  - `REDIS_HOST`
  - `REDIS_PORT` は省略時 `6379`

### このプロジェクトでの Redis の役割

Redis は単なる任意キャッシュではなく、OAuth2 / OIDC の状態管理レイヤーとして使っています。TTL 付きで高速判定が必要なデータや、原子的に更新したいデータを置く想定です。

現在、主フローに入っている用途は次の通りです。

- ログイン session cache
  ログイン成功時に Redis へ session を保存し、ユーザーから session へのインデックスも管理します。
- token cache
  access token / refresh token のハッシュ、失効マーカー、ローテーション状態を保持します。
- token revoke / refresh rotation
  Redis Lua スクリプトを使い、失効や refresh token rotation を原子的に処理します。
- consent のセッション確認
  `/consent` は Redis session cache を優先的に参照します。

既に実装済みだが、まだ主フローへ完全には組み込まれていないものもあります。

- authorization code の一度きり消費キャッシュ
- OAuth `state` / OIDC `nonce` の再利用防止
- ログイン失敗回数と一時ロック

整理すると次のイメージです。

- MySQL は永続的な truth source
- Redis は短期状態と高速・原子的な制御を担う層

### MySQL / Redis のリクエストフロー

大きな流れは次の通りです。

- ログイン状態や token の短期状態は Redis で高速に扱う
- ユーザー、client、authorization code、refresh token の永続データは主に MySQL に保存する

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser / Client
    participant A as authn service
    participant Z as authz service
    participant T as token service
    participant M as MySQL
    participant R as Redis

    Note over B,R: 1. Login
    B->>A: POST /login
    A->>M: users を参照しパスワード検証
    A->>M: login_sessions へ保存
    A->>R: session cache と user-session index を保存
    A-->>B: idp_session cookie を返す

    Note over B,R: 2. Authorization Code
    B->>Z: GET /oauth2/authorize + idp_session
    Z->>M: oauth_clients / login_sessions / consents を参照
    Z->>M: authorization_codes を保存
    Z-->>B: code 付きで 302 redirect

    Note over B,R: 3. Exchange Token
    B->>T: POST /oauth2/token (authorization_code)
    T->>M: authorization code を消費
    T->>M: access_tokens / refresh_tokens を保存
    T->>R: access / refresh token cache を保存
    T-->>B: access_token / refresh_token / id_token を返す

    Note over B,R: 4. Refresh Token Rotation
    B->>T: POST /oauth2/token (refresh_token)
    T->>M: 旧 refresh token の有効性を確認
    T->>M: 新 access token / refresh token を保存
    T->>R: rotate_token.lua で原子的に回転
    T-->>B: 新しい access_token / refresh_token を返す
```

現在のコードベースに即して言うと、役割分担はだいたい次のようになります。

- ログイン
  MySQL でユーザーとパスワードを検証した後、session を MySQL と Redis の両方へ保存
- 認可コード
  `/oauth2/authorize` は主に MySQL の client / session / consent を参照し、authorization code を MySQL に永続化
- code から token 交換
  MySQL 上の authorization code を消費し、access token / refresh token を発行して MySQL と Redis に保存
- refresh token 交換
  MySQL を基準に有効性を判定しつつ、Redis では新 token 状態と revoke marker を原子的に管理

### その他の設定

- `REDIS_PASSWORD`
- `REDIS_DB` 既定値 `0`
- `REDIS_KEY_PREFIX` 既定値 `idp`
- `APP_ENV` 既定値 `dev`
- `SESSION_TTL` 既定値 `8h`
- `ISSUER` 既定値 `http://localhost:8080`
- `JWT_KEY_ID` 既定値 `kid-2026-01-rs256`
- `LISTEN_ADDR` 既定値 `:8080`

### Federated OIDC

外部 OIDC Provider を上流 IdP として使う場合は、少なくとも次を設定します。

- `FEDERATED_OIDC_ISSUER`
- `FEDERATED_OIDC_CLIENT_ID`
- `FEDERATED_OIDC_CLIENT_SECRET`
- `FEDERATED_OIDC_REDIRECT_URI`

必要に応じて次も上書きできます。

- `FEDERATED_OIDC_CLIENT_AUTH_METHOD`
  - `client_secret_basic` または `client_secret_post`
- `FEDERATED_OIDC_SCOPES`
  - 既定値 `openid profile email`
- `FEDERATED_OIDC_STATE_TTL`
  - 既定値 `10m`
- `FEDERATED_OIDC_USERNAME_CLAIM`
  - 既定値 `preferred_username`
- `FEDERATED_OIDC_DISPLAY_NAME_CLAIM`
  - 既定値 `name`
- `FEDERATED_OIDC_EMAIL_CLAIM`
  - 既定値 `email`

例:

```bash
export FEDERATED_OIDC_ISSUER=https://accounts.example.com
export FEDERATED_OIDC_CLIENT_ID=idp-server
export FEDERATED_OIDC_CLIENT_SECRET=replace-me
export FEDERATED_OIDC_REDIRECT_URI=http://localhost:8080/login
export FEDERATED_OIDC_SCOPES="openid profile email"
```

現在の実装では、外部 OIDC から取得した `sub` / username / email のいずれかでローカル `users` を引けることが前提です。初回ログイン時の自動ユーザー作成はまだ行いません。

## ローカル起動

例えば現在の環境変数が次のようになっているなら:

```bash
export REDIS_HOST=redis
export MYSQL_HOST=db
export MYSQL_DATABASE=app
export MYSQL_USER=app
export MYSQL_PASSWORD=apppass
```

追加で次を設定しておくと分かりやすいです。

```bash
export APP_ENV=dev
export ISSUER=http://localhost:8080
export LISTEN_ADDR=:8080
```

有効な設定値は次で確認できます。

```bash
make env
```

ワンライナーで起動する場合（環境変数をそのまま渡す）:

```bash
REDIS_HOST=redis MYSQL_HOST=db MYSQL_DATABASE=app MYSQL_USER=app MYSQL_PASSWORD=apppass APP_ENV=dev ISSUER=http://localhost:8080 LISTEN_ADDR=:8080 make run
```

PowerShell で一行起動する場合:

```powershell
$env:REDIS_HOST='redis'; $env:MYSQL_HOST='db'; $env:MYSQL_DATABASE='app'; $env:MYSQL_USER='app'; $env:MYSQL_PASSWORD='apppass'; $env:APP_ENV='dev'; $env:ISSUER='http://localhost:8080'; $env:LISTEN_ADDR=':8080'; make run
```

起動:

```bash
make run
```

ヘルスチェック:

```bash
curl http://localhost:8080/healthz
```

## Docker で一発起動

手元で MySQL や Redis を個別に用意したくない場合は、リポジトリ直下の [compose.quickstart.yaml](compose.quickstart.yaml) を使うのが最短です。

前提:

- `ghcr.io` にログイン済みで、`ghcr.io/wsplxa/oauth2-sienne-idp-server` を pull できること
- Docker Compose v2 が使えること

ログイン例:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

起動:

```bash
docker compose -f compose.quickstart.yaml up -d
```

PowerShell でソース不要の一行起動（compose を取得して起動）:
※ `compose.quickstart.yaml` を公開 URL から取得できる場合のみ。

```powershell
irm https://YOUR_PUBLIC_HOST/compose.quickstart.yaml -OutFile compose.quickstart.yaml; docker compose -f compose.quickstart.yaml up -d
```

スクリプト経由で一行起動（1. スクリプト取得 2. compose 実行 3. 起動）:
リポジトリが private の場合は `quickstart.ps1` を公開 URL に置いてください（URL を差し替え）。

```powershell
irm https://YOUR_PUBLIC_HOST/quickstart.ps1 -OutFile quickstart.ps1; powershell -ExecutionPolicy Bypass -File .\quickstart.ps1
```

これで次がまとめて起動します。

- MySQL 8.4
- Redis 7
- GHCR 上の `idp-server` イメージ

初回起動時は [migrate.sql](idp-server/scripts/migrate.sql) が MySQL に自動適用されるので、追加の手動初期化は不要です。

確認:

```bash
curl http://localhost:8080/healthz
```

既定では server イメージに `latest` タグを使います。特定の SHA タグを使いたい場合は環境変数で上書きできます。

```bash
IDP_SERVER_IMAGE=ghcr.io/wsplxa/oauth2-sienne-idp-server:sha-5367b14 \
docker compose -f compose.quickstart.yaml up -d
```

主な上書き可能項目:

- `IDP_SERVER_IMAGE`
- `IDP_SERVER_PORT`
- `IDP_ISSUER`
- `IDP_MYSQL_PORT`
- `IDP_REDIS_PORT`
- `IDP_MYSQL_DATABASE`
- `IDP_MYSQL_USER`
- `IDP_MYSQL_PASSWORD`

停止:

```bash
docker compose -f compose.quickstart.yaml down
```

DB / Redis のデータも含めて初期化し直したい場合:

```bash
docker compose -f compose.quickstart.yaml down -v
```

## 現在利用できるテストアカウントと client

以下の fixture は [migrate.sql](idp-server/scripts/migrate.sql) に含まれています。

### ユーザー

- `alice / alice123`
- `bob / bob123`
- `locked_user / locked123`

### OAuth Client

- `web-client / secret123`
- `mobile-public-client / (public client, client secret なし)`
- `service-client / service123`

### 認可コードの疎通確認用 fixture

- `code`: `sample_auth_code_abc123`
- `redirect_uri`: `http://localhost:8081/callback`
- `code_verifier`: `verifier123`
- `seed session cookie`: `idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`

## API 利用例

### 1. ユーザー登録

`POST /register` では次を検証します。

- username 形式
- email 形式
- display name 長さ
- password 強度
- username の一意性
- email の一意性
- `PasswordVerifier.HashPassword(...)` による bcrypt hash 生成
- `users` への保存

例:

```bash
curl -i \
  -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "charlie01",
    "email": "charlie01@example.com",
    "display_name": "Charlie One",
    "password": "charlie123"
  }'
```

成功時は `201 Created` と新規ユーザー情報を返します。

パスワードポリシー:

- 長さ `8-128`
- 英字を 1 文字以上含む
- 数字を 1 文字以上含む

主なエラー:

- username / email 重複: `409 Conflict`
- 形式不正または弱い password: `400 Bad Request`

### 2. ログイン

`GET /login` は次の 2 モードをサポートします。

- ブラウザ向け: 送信可能な HTML ログインページを返す
- API 向け: JSON の案内を返す
- `method=federated_oidc` を付けると外部 OIDC ログインを開始する

ログイン実行は `POST /login` です。

```bash
curl -i \
  -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "password": "alice123"
  }'
```

成功時の挙動:

- `session_id` を返す
- `idp_session` cookie を設定
- MySQL `login_sessions` に保存
- Redis session cache と user-session index に保存

### 2.1 Federated OIDC ログイン

外部 OIDC を使う場合、ブラウザは次から開始できます。

```text
/login?method=federated_oidc&return_to=/oauth2/authorize?...
```

流れ:

- `/login?method=federated_oidc...` へアクセス
- server が `state` / `nonce` を Redis に保存
- 外部 OIDC Provider の `authorization_endpoint` へ 302 redirect
- 外部 Provider から `GET /login?code=...&state=...` で戻る
- server が token exchange と userinfo 取得を行う
- ローカル user と紐づけば `idp_session` cookie を設定
- 元の `return_to` へ戻る

注意:

- `FEDERATED_OIDC_*` を未設定のまま `method=federated_oidc` を呼ぶと失敗します
- 現時点では Just-In-Time provisioning は未実装で、ローカル user が既に存在する必要があります

### 2.2 ログアウト

`POST /logout` では次を行います。

- `idp_session` cookie を読む
- MySQL `login_sessions.logged_out_at` を更新
- Redis session cache と user-session index を削除
- ブラウザの `idp_session` cookie を消す

```bash
curl -i -X POST http://localhost:8080/logout \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
```

ブラウザフォーム的な流れでは `return_to` を渡すこともでき、その場合は成功後に `302` で戻します。

```bash
curl -i -X POST http://localhost:8080/logout \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  --data-urlencode 'return_to=/login'
```

### 2.3 OAuth Client 管理

`POST /oauth2/clients` は以下のテーブルへまとめて書き込みます。

- `oauth_clients`
- `oauth_client_grant_types`
- `oauth_client_auth_methods`
- `oauth_client_scopes`
- `oauth_client_redirect_uris`
  `redirect_uris` があり、grant に `authorization_code` が含まれる場合

confidential web client の作成:

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/clients \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "demo-web-client",
    "client_name": "Demo Web Client",
    "client_secret": "super-secret-1",
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "offline_access"],
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

service client の作成:

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/clients \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "demo-service-client",
    "client_name": "Demo Service Client",
    "client_secret": "service-secret-1",
    "grant_types": ["client_credentials"],
    "scopes": ["internal.api.read", "internal.api.write"]
  }'
```

主な作成ルール:

- `client_type` の既定値は `confidential`
- `confidential` の既定 `token_endpoint_auth_method` は `client_secret_basic`
- `public` の既定 `token_endpoint_auth_method` は `none`
- `public` client は PKCE 必須
- `client_credentials` は `confidential` client のみ
- `authorization_code` client は少なくとも 1 つの有効な `redirect_uri` が必要

既存 client への redirect URI 追加:

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/clients/demo-web-client/redirect-uris \
  -H 'Content-Type: application/json' \
  -d '{
    "redirect_uris": [
      "http://localhost:3000/callback",
      "http://localhost:5173/callback"
    ]
  }'
```

このエンドポイントは冪等です。同じ URI を重ねて登録しても重複保存しません。

### 3. authorization code で token 交換

最も簡単なのは seed の sample code を使う方法です。

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=sample_auth_code_abc123' \
  -d 'redirect_uri=http://localhost:8081/callback' \
  -d 'code_verifier=verifier123'
```

成功時のレスポンス:

- `access_token`
- `refresh_token`
- `token_type`
- `expires_in`
- `scope`

### 3.1 authorize を実際に試す

seed の session cookie を直接使うと確認が早いです。

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  'http://localhost:8080/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email&state=demo-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

成功時は `302` で次へ飛びます。

```text
http://localhost:8081/callback?code=...&state=demo-state
```

### 3.2 未ログイン時の挙動

`idp_session` が無い場合、`/oauth2/authorize` はまず `/login` にリダイレクトし、元の authorize URL を `return_to` に乗せます。

```text
/login?return_to=/oauth2/authorize?...
```

ログイン成功後、`POST /login` は `idp_session` cookie を設定した上で元の authorize URL に戻します。

### 3.3 consent フロー

既存 consent より広い scope を要求した場合、例えば `offline_access` を追加すると `/oauth2/authorize` は先に `/consent` へ遷移します。

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  'http://localhost:8080/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email%20offline_access&state=consent-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

このとき:

```text
Location: /consent?return_to=...
```

consent 内容の確認:

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  'http://localhost:8080/consent?return_to=/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email%20offline_access&state=consent-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

accept:

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  -X POST http://localhost:8080/consent \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=accept' \
  --data-urlencode 'return_to=/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid profile email offline_access&state=consent-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

deny:

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  -X POST http://localhost:8080/consent \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=deny' \
  --data-urlencode 'return_to=/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid profile email offline_access&state=deny-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

deny 時の戻り先:

```text
http://localhost:8081/callback?error=access_denied&state=deny-state
```

### 4. refresh token rotation

取得済みの `refresh_token` を使います。

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=REPLACE_WITH_REFRESH_TOKEN'
```

現在の実装では実際に rotation を行います。

- 旧 refresh token に MySQL で `revoked_at` を設定
- 新 refresh token を生成
- Redis で `rotate_token.lua` を実行
- 旧 token の revoke marker を Redis に保存

### 4.1 client_credentials

service client なら `client_credentials` grant を使えます。

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u service-client:service123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=internal.api.read'
```

成功時:

- `access_token`
- `token_type`
- `expires_in`
- `scope`

現在のルール:

- `scope` 未指定時は、その client に許可された全 scope を発行
- 許可されていない scope を要求すると `invalid_scope`
- `client_credentials` では `refresh_token` は返さない

### 5. userinfo

`access_token` を Bearer token として渡します。

```bash
curl -i \
  http://localhost:8080/oauth2/userinfo \
  -H 'Authorization: Bearer REPLACE_WITH_ACCESS_TOKEN'
```

レスポンス例:

```json
{
  "sub": "11111111-1111-1111-1111-111111111111",
  "name": "Alice",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true
}
```

### 6. OIDC Discovery

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

主な項目:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `response_types_supported`
- `grant_types_supported`
- `code_challenge_methods_supported`

### 7. JWKS

```bash
curl http://localhost:8080/oauth2/jwks
```

公開 JWK には主に次が含まれます。

- `kty`
- `kid`
- `use`
- `alg`
- `n`
- `e`

## Signing Key の永続化

現在は「プロセス起動時に毎回一時鍵を作る」方式に依存しません。

起動時の流れ:

1. MySQL `jwk_keys` から有効な key metadata を読む
2. `private_key_ref` から秘密鍵を読み込む
3. active signing key で JWT を署名する
4. `jwk_keys` の公開情報から `/oauth2/jwks` を構築する
5. `rotates_at` を定期確認し、ローテーション期間に入ったら次の鍵を生成する
6. 旧 active key は非 active にしつつ、既存 token 検証のため一定期間 JWKS に残す

`private_key_ref` でサポートしている形式:

- `file://relative/or/absolute/path`
- `env://ENV_VAR_NAME`
- `vault://path/to/key`
- `kms://key/name`

開発環境では安定した dev key を seed 済みです。

- `kid`: `kid-2026-01-rs256`
- `private_key_ref`: `file://scripts/dev_keys/kid-2026-01-rs256.pem`

これにより:

- 再起動しても `kid` が変わらない
- `/.well-known/openid-configuration` と `/oauth2/jwks` が安定した鍵を返す
- 新規 JWT の header に安定した `kid` が入る
- `rotates_at` が近づくと自動で新 key を生成して `jwk_keys` とメモリ上の key manager を更新する
- 旧 key は退役ウィンドウ中も JWKS に残る

もし DB に利用可能な key がない場合、サービスは起動不能を避けるためプロセス内生成 key にフォールバックします。ただし、推奨は [migrate.sql](idp-server/scripts/migrate.sql) を再適用するか、`jwk_keys` を更新して永続 key を使うことです。

関連環境変数:

- `SIGNING_KEY_DIR` 既定値 `scripts/dev_keys`
- `SIGNING_KEY_BITS` 既定値 `2048`
- `SIGNING_KEY_CHECK_INTERVAL` 既定値 `1h`
- `SIGNING_KEY_ROTATE_BEFORE` 既定値 `24h`
- `SIGNING_KEY_RETIRE_AFTER` 既定値 `24h`

`vault://` と `kms://` について:

- 現在は起動時読み込みに接続されている
- 既定では参照先を環境変数へマッピングして PEM を読む
- 例: `vault://idp/keys/main` -> `VAULT_IDP_KEYS_MAIN`
- 例: `kms://prod/signing/key` -> `KMS_PROD_SIGNING_KEY`

## Redis Lua スクリプト

Lua スクリプトは [scripts/lua](idp-server/scripts/lua) にあります。サービス起動時に `SCRIPT LOAD` でプリロードされます。

現在含まれているスクリプト:

- `save_session.lua`
- `delete_session.lua`
- `consume_authorization_code.lua`
- `save_oauth_state.lua`
- `reserve_nonce.lua`
- `increment_with_ttl.lua`
- `revoke_token.lua`
- `rotate_token.lua`

主な用途:

- session と user index の原子的な保存 / 削除
- authorization code の一度きり消費
- state / nonce の再利用防止
- ログイン失敗回数カウント
- token revoke ブラックリスト
- refresh token rotation

パラメータの詳細は [scripts/lua/README.md](idp-server/scripts/lua/README.md) を参照してください。

## ログと認証ミドルウェア

HTTP レイヤーには次が入っています。

- リクエストログミドルウェア
- Bearer token 認証ミドルウェア

ログに含まれる主なフィールド:

- `request_id`
- `method`
- `path`
- `status`
- `duration`
- `client_id`
- `subject`

`X-Request-ID` がない場合はサーバー側で生成し、レスポンスヘッダーにも返します。

## 現在の制約

このサーバーは実際の token / userinfo 連携を試せますが、まだ完全な OIDC server ではありません。

現在の主な制約:

- `vault://` / `kms://` は本物の SDK 統合ではなく、現状は環境変数アダプター
- key rotation はプロセス内タイマーで行っており、分散ロックや専用制御面は未実装
- 外部 OIDC ログインは既存ローカル user への紐付けを前提としており、初回ログイン時の自動 user 作成は未実装

## よく使う開発コマンド

```bash
make build
make run
make test
make fmt
make env
make migrate
make migrate-docker
```

## ビルドとデプロイ

基本は [Makefile](idp-server/Makefile) の利用を推奨します。

### ローカルビルド

```bash
make build
```

出力先:

```text
bin/idp-server
```

### ローカル起動

```bash
make run
```

既定値を上書きする場合:

```bash
make run ISSUER=http://localhost:8080 LISTEN_ADDR=:8080
```

### DB 初期化

ローカル MySQL:

```bash
make migrate
```

コンテナ内 MySQL:

```bash
make migrate-docker
```

### Docker イメージビルド

既定では [dockerfile.server](idp-server/dockerfile.server) を使います。

```bash
make docker-build IMAGE=idp-server:latest
```

### Compose 起動 / 停止

リポジトリ内の compose ファイルは [docker-compose.yml](idp-server/docker-compose.yml) です。

```bash
make up
make logs
make down
```

別の compose ファイルを使う場合:

```bash
make up COMPOSE_FILE=../infra/docker-compose.yml
```

### 典型的なデプロイ順

開発・検証環境:

```bash
make migrate-docker
make build
make run ISSUER=http://localhost:8080
```

コンテナ配備:

```bash
make migrate-docker
make docker-build IMAGE=idp-server:latest
make up
```
