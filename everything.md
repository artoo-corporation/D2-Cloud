# D2 Cloud Control-Plane – Codebase Reference

*Last updated: 2025-08-28 – includes AuthContext refactor and app name normalization*

---

## 1. High-Level Architecture

The repository implements the **control-plane** for D2 Cloud.  It is a
FastAPI application backed by Supabase (PostgreSQL + Realtime) and
integrating with external services such as ClickHouse and Logflare.

```
┌───────────────┐      HTTP (ASGI)      ┌───────────────┐
│ Vercel Edge   │  ───────────────────▶ │   FastAPI     │
│  /  Server    │                       │  (app.main)   │
└───────────────┘                       │               │
                                        │  ├ Routers    │
                                        │  ├ Middleware │
                                        │  └ Utils      │
                                        └──────┬────────┘
                                               │ async
                                               ▼
                                 ┌───────────────────────────┐
                                 │  Supabase Postgres (DB)   │
                                 └───────────────────────────┘
                                               │ cron/export
                                               ▼
                                 ┌───────────────────────────┐
                                 │   ClickHouse (analytics)  │
                                 └───────────────────────────┘
```

The control-plane exposes **private REST APIs** (for SDK / CLI usage) and a
minimal **public JWKS discovery** endpoint for policy verification.  The code
is organised under the `app/` package with clear separation between routers,
utils, cron jobs and schemas.

---

## 2. Runtime Entry-Point

### app/main.py

* Creates the global `FastAPI` instance plus an embedded **public sub-app**
  mounted at `/public`.
* Configures:
  * JSON logging (`app.utils.logger`)
  * Request-context middleware for structured logs
  * SlowAPI **rate-limiting** middleware (global default `60/minute`)
  * CORS – private origins driven by `ALLOWED_ORIGINS`, public app wildcard
  * Health-check at `/`.
* Registers all routers in explicit order to allow override precedence:
  `auth`, `policy`, `keys`, `jwks-admin`, `events`.
* Exposes `/.well-known/jwks.json` via the public sub-app.
* Exports `app` symbol which Vercel automatically detects.

### Environment Detection

```
APP_ENV        – defaults to "production" (switches off docs/openapi routes)
SUPABASE_URL   – required, loaded from .env via python-dotenv
SUPABASE_KEY   – required secret service key
```

---

## 3. Configuration & Settings

| Module | Purpose |
| ------ | ------- |
| `app/settings.py` | Lightweight helper to build **ALLOWED_ORIGINS** list from env vars (`FRONTEND_ORIGIN`, `DOCS_ORIGIN`, `EXTRA_ORIGIN`). Falls back to `http://localhost:5173`. |
| `app/utils/plans.py` | Central source-of-truth for **subscription tiers** (`trial`, `essentials`, `pro`, `enterprise`, `locked`). Defines quotas (`max_tools`, `min_poll`, `ingest_interval`) and `MAX_BATCH_BYTES` (1 MiB). Provides enforcement helpers used by routers. |
| `.env` (not committed) | Stores secrets such as `JWK_AES_KEY` (32-byte urlsafe-base64) for private-JWK encryption, Supabase credentials, ClickHouse connection, etc. |

---

## 4. Utility Modules

### app/utils/security_utils.py

* **Token hashing / verification** – bcrypt-salts SHA-256 digests for API tokens; supports legacy plain hashes.
* **RSA JWK generation** – 2048-bit keys for policy JWS signing.
* **AES-GCM encryption** of private JWKs at rest (env `JWK_AES_KEY`).  Falls
  back to plaintext JSON when the key is absent (dev/test convenience).
* **get_active_private_jwk** – fetches the newest encrypted key for a tenant.

### app/utils/database.py

Idiomatic async wrappers around Supabase-py:

* `insert_data`, `query_data`, `update_data` – convenience plus error mapping.
* `query_one`, `query_many` – thin helpers returning parsed rows.
* Back-compat wrapper keeps previous positional-argument signature working.

### app/utils/dependencies.py

FastAPI dependency that yields a **fresh Supabase async client**.  When
`SUPABASE_URL` starts with `https://test.` a **stub client** from
`tests.supabase_stub` is injected to avoid network access in unit tests.

**Authentication Dependencies:**
- `require_token_admin()` validates admin Bearer tokens
- `require_actor_admin()` provides unified auth for both Supabase JWTs and D2 tokens

### app/utils/require_scope.py

**NEW (2025-08-28)**: Implements the AuthContext pattern for clean, type-safe authentication.
`require_scope(*scopes)` returns an `AuthContext` object instead of just `account_id`,
providing explicit access to `account_id`, `scopes`, `user_id`, `token_id`, and `app_name`.
This replaces the old pattern of hidden `request.state` data with explicit, typed authentication.

```python
# New pattern (AuthContext)
@router.get("/endpoint")
async def handler(auth: AuthContext = Depends(require_scope("policy.read"))):
    # Direct access: auth.account_id, auth.scopes, auth.user_id, etc.
    
# Helper methods
auth.has_scope("admin")  # Check specific scope
auth.is_dev()           # Check if dev token
auth.is_admin()         # Check if admin token
```

### app/utils/logger.py

Structured JSON logs with consistent fields (`level`, `name`, `message`,
`time`, optional extra context).

### Misc

* `utils.utils.py` – trivial helpers (`generate_uuid`, `get_env_bool`).
  **NEW (2025-08-28)**: `normalize_app_name()` – converts spaces to underscores 
  in app names for consistency across all endpoints. Ensures "my app" and "my_app" 
  are treated as the same application.

---

## 5. Routers / API Surface

Below every path is prefixed by `/api` (or similar) depending on deployment –
All paths below are fully-qualified with the base URL `https://d2.artoo.love`.

### 5.1 Accounts & Authentication (`accounts_routes.py` + `tokens_routes.py`)

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| GET | `/v1/accounts/me` | Bearer token | Returns plan info, quotas, and account metadata. |
| POST | `/v1/accounts/{account_id}/tokens` | Supabase JWT | Creates **long-lived opaque API key** with app assignment and user assignment. |
| GET | `/v1/accounts/{account_id}/tokens` | Supabase JWT | Lists tokens with creator/assignee names. |
| DELETE | `/v1/accounts/{account_id}/tokens/{token_id}` | Supabase JWT | Revokes token. |
| POST | `/v1/accounts/{account_id}/tokens/{token_id}/rotate` | Supabase JWT | **NEW**: Generates new token value, revokes old one. |
| GET | `/v1/accounts/{account_id}/tokens/scopes` | Supabase JWT | **NEW**: Lists available scopes for token creation UI. |
| GET | `/v1/accounts/{account_id}/tokens/users` | Supabase JWT | **NEW**: Lists users for token assignment dropdown. |

**Key Changes (2025-08-28):**
- Token creation now supports `app_name` and `assigned_user_id` for better organization
- All app names are automatically normalized (spaces → underscores)
- Authentication switched to Supabase JWTs for dashboard-only access

### 5.2 Policy Service (`app/routers/policy_routes.py` – prefix `/v1/policy`)

| Method | Path | Notes |
| ------ | ---- | ----- |
| GET | `/v1/policy/bundle` | Fetch latest signed bundle; enforces ETag, poll-rate, size & revoke checks. **Dev-friendly polling**: dev/admin tokens bypass rate limits. |
| PUT | `/v1/policy/draft` | Upload unsigned draft (tool-quota enforced). Auto-extracts app name from bundle. |
| POST | `/v1/policy/publish` | Verify Ed25519 signature & publish as signed JWS. Supports optimistic concurrency (ETags). |
| DELETE | `/v1/policy/revoke` | **NEW**: Soft-revokes active policy for specified app. Requires `policy.revoke` scope. |
| GET | `/v1/policy/versions` | **NEW**: List policy version history with optional bundle content for comparison. |
| POST | `/v1/policy/revert` | **NEW**: Revert to specific policy version. Requires `policy.revert` scope. |
| GET | `/v1/policy/list` | **NEW**: List all policies (drafts + published) for frontend display. |
| GET | `/v1/policy/{policy_id}` | **NEW**: Get detailed policy information by ID. |
| PATCH | `/v1/policy/{policy_id}/description` | **NEW**: Update policy description. |
| PATCH | `/v1/policy/{policy_id}/bundle` | **NEW**: Update policy bundle content from editor. |
| POST | `/v1/policy/validate` | **NEW**: Validate policy bundle syntax and provide feedback. |
| GET | `/v1/policy/apps` | **NEW**: List distinct app names for dropdowns. |

**Key Changes (2025-08-28):**
- All app names automatically normalized (spaces → underscores) 
- AuthContext pattern: routes now receive explicit `auth: AuthContext` instead of hidden `request.state`
- Developer-friendly polling: dev/admin tokens bypass rate limits for local development
- Comprehensive audit logging with user attribution
- Full policy lifecycle support: drafts → publish → versioning → reversion

### 5.3 Events & Audit (`events_routes.py` + `audit_routes.py` – prefix `/v1`)

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/v1/events/ingest` | Rejects payloads > 32 KiB; enforces per-plan ingest rate; optionally forwards to Logflare; persists to Supabase `events`. **NEW**: Auto-converts SDK events to audit logs. |
| GET | `/v1/events` | **NEW**: List events for dashboard with cursor-based pagination. Requires `metrics.read` scope. |
| GET | `/v1/audit` | **NEW**: List audit logs for compliance (admin only). Comprehensive tracking of all system actions. |

**Key Changes (2025-08-28):**
- **Batched Event Processing**: Now handles SDK's batched event structure (`events` array)
- **Enhanced Telemetry Mapping**: Properly maps `tool_invoked` events to audit logs
- **Rich Metadata Capture**: Extracts service, host, PID, policy ETag from SDK telemetry
- **Threading Security Telemetry**: Comprehensive tracking of multi-threaded context violations
- **Service Name Resolution**: Uses policy bundle `metadata.name` as authoritative source
- **Security Alerting**: Context violations, confused deputy detection, context leaks
- **Comprehensive Audit Trail**: All authorization decisions automatically create audit entries
- **User Attribution**: Links SDK events to users via token association

### 5.4 JWKS (`app/routers/jwks_routes.py`)

* **Public discovery:** `GET https://d2.artoo.love/.well-known/jwks.json` (rate-limited 60/min).
* **Admin rotation:** `POST https://d2.artoo.love/v1/jwks/rotate` – generates fresh RSA pair, stores encrypted private key and publishes the public part.

### 5.5 Public Keys (`app/routers/keys_routes.py` – prefix `/v1/keys`)

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/v1/keys` | Add Base64 Ed25519 public key (returns `key_added`). **NEW**: Tracks user_id from dev token. |
| DELETE | `/v1/keys/{key_id}` | Soft-revoke a key. **NEW**: Uses AuthContext, adds audit logging. |
| GET | `/v1/keys` | List keys with user attribution; `include_revoked` query-param. **NEW**: Returns uploader names. |

**Key Changes (2025-08-28):**
- Public keys now track which user uploaded them via `user_id` field
- Key listing includes uploader display names for UI attribution
- Consistent AuthContext usage across all key management endpoints
- Enhanced audit logging for key revocations

### 5.6 Multi-Tenancy (`invitations_routes.py` – prefix `/v1/invitations`)

**NEW (2025-08-28)**: Invitation-based multi-tenancy system for secure organization management.

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| POST | `/v1/invitations` | Supabase JWT | Create invitation for new organization member. |
| GET | `/v1/invitations` | Supabase JWT | List pending invitations for account. |
| DELETE | `/v1/invitations/{invitation_id}` | Supabase JWT | Cancel pending invitation. |
| GET | `/public/invitations/{invitation_token}` | None | **Public**: Get invitation details for acceptance page. |
| POST | `/public/invitations/accept` | Supabase JWT | **Public**: Accept invitation and join organization. |

**Key Features:**
- Secure invitation tokens with 7-day expiry
- Role-based permissions (admin, member)
- Email-based invitations with account isolation
- Comprehensive audit logging of invitation lifecycle

### 5.7 Token Bootstrap & Scopes

*Two distinct token profiles are supported – both share the same `d2_` prefix but differ **only by scopes**:*

* **Developer token** – scopes `dev` → shorthand for `policy.read`, `policy.publish`, `key.upload`, `event.ingest`.
* **Server token** – scopes `server` → shorthand for `policy.read`, `event.ingest` (read-only).

Production servers **must use** `server` tokens; developer laptops/CI **should use** `dev` tokens.  Admin tokens (`admin` scope) retain full CRUD capability and are typically created via the dashboard by an account owner.

Supported individual scopes:

* `policy.read` – download bundles
* `policy.publish` – upload draft & publish policies
* `policy.revoke` – **NEW**: revoke active policies (admin-level)
* `policy.revert` – **NEW**: revert to previous policy versions (admin-level)  
* `key.upload` – manage public signing keys
* `event.ingest` – send usage events
* `metrics.read` – **NEW**: access events and dashboard metrics
* `admin` – **NEW**: full system access including audit logs
* Composite shorthands: 
  - `dev` → `policy.read` + `policy.publish` + `key.upload`
  - `server` → `policy.read` + `event.ingest` (read-only)
  - `admin` → wildcard access to all scopes

**Key Changes (2025-08-28):**
- Granular scopes for advanced policy operations (revoke, revert)
- Separate `metrics.read` scope for dashboard access
- Developer-friendly polling: `dev` and `admin` tokens bypass rate limits

### 5.7 Audit & Telemetry

Every state-changing action and SDK telemetry event is mirrored into `audit_logs`:

| Action | Trigger |
| ------ | ------- |
| `token.create`, `token.revoke`, `token.rotate` | Token management routes |
| `policy.draft`, `policy.publish`, `policy.update`, `policy.revert`, `policy.revoke` | Policy routes |
| `key.upload` | Public key routes |
| `auth.decision`, `tool.invocation`, `policy.poll`, … | SDK `events/ingest` telemetry |

Audit records store `actor_id`, `token_id`, optional `user_id`, `status` (success / failure / denied) and `version` where relevant.  The dashboard surfaces these logs with cursor-based pagination via `/v1/audit`.

---

## 6. Database Tables (Supabase)

The code interacts with these tables (names are hard-coded):

| Table | Purpose |
| ----- | ------- |
| `accounts` | Tenant metadata (plan, trial expiry, metrics toggle, etc.). |
| `api_tokens` | Bearer token store (`token_id`, bcrypt-hashed `token_sha256`, scopes, expiry, revoked_at). |
| `events` | Raw usage events (mirrored from ingest endpoint). |
| `export_state` | Single-row high-water mark for Cron export to ClickHouse. |
| `jwks_keys` | RSA key pairs per tenant (`kid`, `public_jwk`, encrypted `private_jwk`). |
| `policies` | Policy bundles (draft & published versions, JWS, revocation time). |
| `public_keys` | User-managed Ed25519 keys for signing publish requests. |
| `audit_logs` | (Used only for force-publish tracking). |

---

## 7. Background Jobs (app/cron)

| File | Schedule (external) | Function |
| ---- | ------------------- | -------- |
| `event_rollup.py` | e.g. every 5 min | Ships new rows from `events` to ClickHouse via HTTP JSONEachRow. Maintains checkpoint in `export_state`. |
| `key_rotation_sweeper.py` | daily | Rotates / garbage-collects stale RSA keys (file present, logic TBD). |
| `revoke_enforcer.py` | hourly | Deletes/archives tokens or policies past revocation window. |
| `trial_locker.py` | daily | Downgrades expired trial accounts to `locked` plan (enforces 0-tool quota). |

*(The `api/cron_*.py` copies are legacy duplicates kept for compatibility – prefer `app/cron/*`.)*

---

## 8. Security Measures

1. **Bearer tokens** – bcrypt-salted SHA-256 digests; verification traverses all rows to support legacy clear hashes.
2. **Admin scope** – actions that mutate state (token creation, key rotation, policy publication) require `admin` scope.
3. **Rate-limiting** – IP-based (`SlowAPI`) global limit plus router-specific JWKS limit.
4. **AES-GCM encryption** – private RSA keys are encrypted server-side at rest using tenant-wide `JWK_AES_KEY`.
5. **Plan enforcement** – batch size, ingest interval, poll interval, and tool-count checked on each request.
6. **ETag concurrency** – prevents accidental overwrites of policy bundles; supports If-Match/If-None-Match.

---

## 9. OpenAPI Generation

`app/openapi.py` exposes YAML and is mounted on the public sub-app at
`/public/openapi.yaml` (wildcard CORS). The YAML is generated at request time
and prefixed with a generation-date comment. Cache: `public, max-age=300`.

---

## 10. Scripting Utilities (`scripts/`)

* `generate_jwk_aes_key.py` – one-off generation of a 256-bit AES key; supports writing to `.env` or clipboard.
* `rotate_all_jwks.py` – CLI helper that iterates through all tenants and calls the JWKS rotate endpoint.

---

## 11. Testing Strategy (`tests/`)

* **pytest**-based unit tests (21 passing as of repo snapshot).
* Uses `tests/supabase_stub.py` to stub Supabase network calls – triggered by
  setting `SUPABASE_URL` to a special `https://test.` prefix.
* Coverage includes:
  * Security utils (hash/encrypt/decrypt)
  * CORS headers, OpenAPI route, JWKS rotation, policy publish logic, etc.

---

## 12. External Dependencies (excerpt from `requirements.txt`)

* `fastapi`, `starlette`, `slowapi` – web framework & rate-limiting.
* `cryptography`, `python-jose` – RSA & JWK/JWS operations.
* `bcrypt` – password/token hashing.
* `supabase-py` – Postgres access layer.
* `httpx` – async HTTP client (Logflare, ClickHouse).
* `pydantic` v2 – request/response validation.
* `python-dotenv` – env file loading.

---

## 13. Vercel Configuration (`vercel.json`)

Defines default build output and routes for serverless deployment, mapping all
requests to the FastAPI ASGI handler.

---

## 14. File/Directory Overview

```
api/                 – legacy copies of cron jobs (to be removed)
app/
  ├ cron/            – async standalone scripts executed on schedules
  ├ routers/         – versioned REST endpoints grouped by domain
  ├ utils/           – cross-cutting helpers (DB, security, logger, plans…)
  ├ models/          – Pydantic models (request/response + DB)
  ├ main.py          – ASGI app factory & configuration
  ├ openapi.py       – YAML schema generator route
  └ settings.py      – lightweight env config logic
scripts/             – one-off helper CLIs
public/              – generated OpenAPI YAML (committed for docs hosting)

tests/               – pytest suite with Supabase stub
```

---

## 15. Environment Variables (non-exhaustive)

| Name | Used in | Description |
| ---- | ------- | ----------- |
| `SUPABASE_URL` / `SUPABASE_KEY` | `app/utils/dependencies.py` | Connection details (required). |
| `APP_ENV` | `app/main.py` | `production` hides docs/openapi. |
| `FRONTEND_ORIGIN` / `DOCS_ORIGIN` / `EXTRA_ORIGIN` | `app/settings.py` | Allowed CORS origins. |
| `PRO_EVENT_MAX_BYTES` / `ENTERPRISE_EVENT_MAX_BYTES` | `accounts_routes.py` | Optional per-plan override for quotas.event_payload_max_bytes (default 32768). |
| `JWK_AES_KEY` | `app/utils/security_utils` | 32-byte urlsafe-Base64 key for AES-GCM encryption. |
| `LOGFLARE_HTTP_ENDPOINT` / `LOGFLARE_API_KEY` | `events_routes.py` | Usage event sink. |
| `CLICKHOUSE_HTTP_ENDPOINT`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | `cron/event_rollup.py` | Analytics export. |

---

## 16. How Things Fit Together

1. **Clients** authenticate with a long-living **Bearer token** issued via
   `/v1/token` (admin) or obtained during the initial bootstrap call.  Tokens authorize subsequent
   access to policy, events and key management APIs.
2. **Policy bundles** are drafted, signed using client-side Ed25519 keys and
   then **published**.  On publish the server re-signs the bundle as a JWS with
   the tenant’s private RSA key and stores it.  SDKs fetch the signed bundle
   via `https://d2.artoo.love/v1/policy/bundle`, validating ETags for efficiency.
3. **Usage events** are pushed to `/v1/events/ingest` – the endpoint validates
   rate limits, enforces plan quotas and forwards to Logflare.
4. Background cron **event_rollup** exports the events table to ClickHouse for
   analytics dashboards.
5. JWKS discovery for offline bundle verification is served at
   `https://d2.artoo.love/.well-known/jwks.json` with strong 5-minute cache headers.

---

> **End of documentation** 
