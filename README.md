# APITrench Fixture API

A safe live API you can deploy and import into APITrench to test:

- no-auth endpoints
- API key header credentials
- API key query credentials
- bearer token credentials
- basic auth credentials
- custom header credentials
- custom template/HMAC edge cases
- OAuth authorization-code + PKCE provider flow
- real Google OAuth access-token profile + token-to-JWT workflow
- real GitHub OAuth access-token profile + token-to-JWT workflow
- OAuth refresh token flow
- OAuth access token -> JWT chained workflow
- API key -> session token chained workflow
- Basic auth -> bearer token chained workflow
- JWT -> downstream bearer chained workflow
- read/write/destructive tool safety metadata
- large/nested/html/binary responses
- slow endpoints, redirects, upstream errors, upstream-style rate limits

The app uses only Node's standard library. No database. All issued codes/tokens are in memory and reset when the process restarts.

## Demo credentials

```txt
API key: atk_live_demo
Bearer token: bearer_demo
Basic username: demo
Basic password: secret
Custom header token: client_token_demo
Custom client id: demo-client
Custom client secret: demo-client-secret
OAuth client id: apitrench-client
OAuth client secret: apitrench-secret
HMAC secret: fixture-hmac-secret
```

Override any of them with environment variables in `src/server.mjs`.

## Run locally

```bash
npm start
# or
$env:PORT=8080; $env:FIXTURE_BASE_URL='http://localhost:8080'; npm start # PowerShell
# or
PORT=8080 FIXTURE_BASE_URL=http://localhost:8080 npm start # bash/zsh
```

Open:

```txt
http://localhost:8080/public/openapi.json
http://localhost:8080/public/demo-credentials
```

## Deploy to Fly.io

Fly.io is a good fit for this because this fixture is a small HTTP service, and Fly supports Dockerfile-based apps plus `fly launch` / `fly deploy` workflows.

```bash
fly auth login
fly launch --no-deploy
fly secrets set \
  FIXTURE_BASE_URL=https://YOUR-FLY-APP.fly.dev \
  ALLOWED_REDIRECT_ORIGINS='*'
fly deploy
```

Then import:

```txt
https://YOUR-FLY-APP.fly.dev/public/openapi.json
```

For a stricter OAuth callback setup, replace `ALLOWED_REDIRECT_ORIGINS='*'` with the origin of your APITrench backend callback host, for example:

```bash
fly secrets set ALLOWED_REDIRECT_ORIGINS=https://your-apitrench-backend.example.com
```

## Recommended APITrench tests

### 1. Import OpenAPI

Create an integration from `/public/openapi.json`.

Expected upstream base URL:

```txt
https://YOUR-FLY-APP.fly.dev
```

### 2. Test simple credential application modes

Create credential seeds:

- `api_key_header`: `{ "api_key": "atk_live_demo" }`
- `api_key_query`: `{ "api_key": "atk_live_demo" }`
- `bearer_header`: `{ "access_token": "bearer_demo" }`
- `basic_header`: `{ "username": "demo", "password": "secret" }`
- `custom_header`: `{ "token": "client_token_demo" }`

Then bind them to these paths:

- `/auth/api-key-header`
- `/auth/api-key-query`
- `/auth/bearer`
- `/auth/basic`
- `/auth/custom-header`

### 3. Test OAuth provider flow

Create OAuth provider config:

```json
{
  "providerKey": "apitrench-fixture",
  "displayName": "APITrench Fixture OAuth",
  "authorizationUrl": "https://YOUR-FLY-APP.fly.dev/oauth/authorize",
  "tokenUrl": "https://YOUR-FLY-APP.fly.dev/oauth/token",
  "userinfoUrl": "https://YOUR-FLY-APP.fly.dev/oauth/userinfo",
  "revokeUrl": "https://YOUR-FLY-APP.fly.dev/oauth/revoke",
  "clientId": "apitrench-client",
  "clientSecret": "apitrench-secret",
  "defaultScopes": ["profile", "email", "read:data", "mint:jwt"],
  "tokenAuthMethod": "client_secret_post",
  "pkceEnabled": true,
  "userinfoMapping": {
    "providerUserId": ["sub", "email"],
    "displayName": ["name", "email"]
  },
  "enabled": true
}
```

Start OAuth from APITrench. The fixture immediately redirects back with a fake code; no login screen.

### 3b. Test real Google and GitHub OAuth providers

The fixture also exposes endpoints that accept real Google/GitHub access tokens issued by APITrench:

- `GET /real-oauth/google/profile`
- `POST /exchange/google-oauth-to-jwt`
- `GET /real-oauth/github/profile`
- `POST /exchange/github-oauth-to-jwt`

Use these example provider configs:

```txt
examples/google-oauth-provider-config.json
examples/github-oauth-provider-config.json
```

For both providers, the OAuth callback URL should be your APITrench backend callback, not this fixture app:

```txt
https://YOUR-APITRENCH-BACKEND/v1/oauth/callback
```

Flow examples:

1. Google authorization code -> Google access token -> `/exchange/google-oauth-to-jwt` -> fixture JWT -> `/protected/jwt/resource`
2. GitHub authorization code -> GitHub access token -> `/exchange/github-oauth-to-jwt` -> fixture JWT -> `/protected/jwt/resource`


### 4. Test chained workflows

These are the important workflow combinations:

1. OAuth authorization code -> access token -> `/exchange/oauth-to-jwt` -> JWT -> `/protected/jwt/resource`
2. API key header -> `/exchange/api-key-to-session` -> `x-client-token` -> `/protected/session/resource`
3. Basic auth -> `/exchange/basic-to-bearer` -> bearer token -> `/oauth/userinfo`
4. OAuth access token -> JWT -> `/exchange/jwt-to-downstream-token` -> bearer token -> `/protected/downstream/resource`

### 5. Test safety and response policies

- `/policy/read-safe`
- `/policy/write-safe`
- `/policy/destructive`
- `/responses/large?count=500`
- `/responses/nested`
- `/responses/html`
- `/responses/binary`
- `/edge/slow?ms=20000`
- `/edge/status/500`
- `/edge/redirect`
- `/edge/rate-limit-demo`

## Useful curl checks

```bash
BASE=http://localhost:8080
curl "$BASE/public/ping"
curl -H 'x-api-key: atk_live_demo' "$BASE/auth/api-key-header"
curl "$BASE/auth/api-key-query?api_key=atk_live_demo"
curl -H 'authorization: Bearer bearer_demo' "$BASE/auth/bearer"
curl -u demo:secret "$BASE/auth/basic"
curl -H 'x-client-token: client_token_demo' "$BASE/auth/custom-header"
```

HMAC demo:

```bash
BASE=http://localhost:8080
BODY='{"hello":"world"}'
TS=$(date +%s)
SIG=$(printf "POST\n/auth/hmac\n$TS\n$BODY" | openssl dgst -sha256 -hmac fixture-hmac-secret -hex | awk '{print $2}')
curl -X POST "$BASE/auth/hmac" \
  -H "content-type: application/json" \
  -H "x-timestamp: $TS" \
  -H "x-signature: $SIG" \
  -d "$BODY"
```

## Standalone Google/GitHub OAuth testing

This fixture app can run its own manual OAuth login flows. These are separate from the built-in fake `/oauth/*` provider.

Set these env vars in this app:

```env
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:8080/real-oauth/google/callback

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_OAUTH_REDIRECT_URI=http://localhost:8080/real-oauth/github/callback
```

Register these callback URLs in the provider dashboards:

```txt
http://localhost:8080/real-oauth/google/callback
http://localhost:8080/real-oauth/github/callback
```

Then test manually in a browser:

```txt
http://localhost:8080/real-oauth/google/login
http://localhost:8080/real-oauth/github/login
```

After login, the callback returns JSON with `access_token`, profile info, and example curl commands for these protected endpoints:

```txt
GET  /real-oauth/google/profile
POST /exchange/google-oauth-to-jwt
GET  /real-oauth/github/profile
POST /exchange/github-oauth-to-jwt
```
