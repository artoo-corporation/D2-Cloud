## Updates – Auth and Metrics (current)

### Centralized authentication
- All routes now use a single dependency: `require_auth(...)` from `app/utils/auth.py`.
- Supported patterns:
  - `require_auth("policy.read")` – explicit scope
  - `require_auth(["policy.read", "metrics.read"])` – multiple scopes (all required)
  - `require_auth(require_privileged=True)` – owner/dev via Supabase JWT or privileged API token
  - `require_auth("metrics.read", strict=True)` – no wildcard; explicit scopes required
  - `require_auth(require_user=True)` – must be a Supabase user session (user_id present)
- Deprecated/removed: `require_scope`, `require_scope_strict`, `require_actor_admin`, `require_account_admin`, `require_token_admin`.
- **Role Model**: Only `owner` (account creator) and `dev` (invited users) roles exist. No `admin` or `member` roles.
- **API Tokens**: Only `dev` and `server` scopes available. No user assignment - tokens belong to the account.

### Accounts – event sampling
- `GET /v1/accounts/me` now returns `event_sample: { [eventType]: float }`.
- Merge precedence: account JSON column > `EVENT_SAMPLE_JSON` env > defaults.
- Values are clamped to `[0.0, 1.0]`; unknown keys preserved for forward-compat.
- Initial keys: `authz_decision=1.0`, `tool_invoked=1.0`, `policy_poll_interval=0.1`, `missing_policy=0.5`.

### Metrics endpoints
- Base: `/v1/metrics` (private dashboard API)
- Auth: `require_auth(require_user=True)` – any authenticated OAuth user can access
- Endpoints:
  - `GET /v1/metrics/summary`
  - `GET /v1/metrics/timeseries`
  - `GET /v1/metrics/top`
- Backed by Supabase queries; in-app aggregation; no longer gated by `accounts.metrics_enabled`.

### Tokens – performance notes (server-side only)
- Token verification uses a fast lookup index `api_tokens.token_lookup` derived from the raw token via HMAC(pepper, sha256(token)). The pepper is the AES key `JWK_AES_KEY`.
- If `token_lookup` is missing for legacy tokens, the first verification does a slow full-scan, then the server backfills `token_lookup` to make subsequent requests fast.
- **Token Model**: Only `dev` and `server` tokens exist. No user assignment (`assigned_user_id` removed).
- **App Association**: Tokens include `app_name` field for organization.
- Recommended DB index:
  ```sql
  create index concurrently if not exists api_tokens_token_lookup_idx on api_tokens (token_lookup);
  ```

### Operational scripts
- `scripts/rotate_jwk_aes_key.py` – rotate only the AES key (`JWK_AES_KEY`) and re-encrypt `jwks_keys.private_jwk` rows. Prints the new key for your env. Does not rotate RSA keys.
- `scripts/rotate_all_jwks.py` – rotate RSA JWKS signing keys and re-sign active policies. Use for scheduled rotation or incident response.
- `scripts/generate_jwk_aes_key.py` – optional helper to print a base64url 32-byte AES key; not required if using the rotate script.

# D2 Cloud API Contracts

*Last updated: 2025-09-15 – includes dual policy publish responses, role management, app quotas, frontend publishing, policy crafting assistance, and comprehensive audit logging*

## Overview

This document provides comprehensive API contracts for the D2 Cloud control plane. It's designed to be used by frontend developers and LLMs to understand how to interact with the API correctly.

## Recent Updates (2025-09-15)

### 🔍 Comprehensive Audit Logging *(ENHANCED 2025-09-15)*
- **Enhanced audit trail**: Complete tracking of all system operations with rich context
- **User name resolution**: Shows actual user names instead of cryptic UUIDs in audit logs
- **Resource attribution**: New `resource_type` and `resource_id` fields for precise resource tracking
- **Rich metadata**: Structured additional data for each operation (token scopes, policy versions, etc.)
- **Status tracking**: Clear success/failure/denied status for all operations
- **Compliance ready**: Full audit trail suitable for security and compliance requirements

### 🎯 Policy Crafting Assistance *(NEW 2025-09-15)*
- **New `/v1/policy/roles-permissions` endpoint**: Extracts all unique roles and permissions from existing policy bundles
- **Smart suggestions**: Frontend can now suggest previously used roles and permissions in autocomplete dropdowns
- **Role-permission mappings**: Shows which permissions each role typically has for intelligent suggestions
- **Template creation**: Enable "create role like existing X" functionality with pre-populated permissions
- **Consistency checking**: Help users maintain consistent permission patterns across policies

## Previous Updates (2025-09-08)

### 🔄 Consistent JWS Responses
Policy publishing returns JWS format for all authentication methods:
- **Frontend and CLI/SDK**: Both receive JWS and version (consistent with GET /bundle)
- **Frontend**: Can decode JWS to extract policy metadata (same as bundle endpoint)
- **Backward Compatibility**: Maintains existing API contracts

### 👥 Enhanced Role Management
- New `dev` role for policy editing without admin privileges
  (User roles are fixed: owner (creator) and dev (invited). No role update endpoint.)
- Invitation system now restricts to `admin` and `dev` roles only
- `owner` role is immutable and assigned automatically to first user

### 📱 App Quota System
Plan-based limits on the number of **published** applications per account:
- **Free**: 1 app, **Essentials**: 5 apps, **Pro**: 25 apps, **Enterprise**: 1000 apps
- **Drafts are unlimited** - create as many draft policies as needed for any app
- **Quota enforced only during publishing** - when publishing a draft for a **new app name** that has never been published before
- **Updates allowed** - republishing/updating existing published apps doesn't count against quota
- Clear error messages and SDK guidance for quota exceeded scenarios

### 🔐 Frontend Policy Publishing
- Supabase JWT users can publish policies without cryptographic signing
- API tokens still require `X-D2-Signature` and `X-D2-Key-Id` headers
- Simplified frontend integration while maintaining CLI/SDK security

### 🗃️ Database Schema Cleanup
- Removed `description` column from policies table
- Policy descriptions now managed via `bundle.metadata.description`
- Cleaner separation of concerns between policy content and metadata

### ⏰ Auto-Refresh Policy Expiry
- **Server-side expiry enforcement**: All policies get 1-week expiry from submission time
- **Auto-refresh on access**: Expired policies are automatically extended by 1 week when accessed via GET /bundle
- **Seamless operation**: SDKs continue working without interruption when policies expire
- **Consistent behavior**: Both drafts and published policies follow the same expiry rules

## Authentication

All API endpoints (except public ones) require authentication via Bearer tokens:

```http
Authorization: Bearer d2_[token_value]
```

### Token Types & Scopes

**API Token Types**: Only two roles exist – `dev` (developer) and `server` (service). No user assignment or admin tokens.

**User Roles**: Only `owner` (account creator) and `dev` (invited users). All authenticated OAuth users can access dashboard content.

### Authentication Errors

```json
// 401 Unauthorized
{
  "detail": "invalid_token"
}

// 403 Forbidden  
{
  "detail": "insufficient_scope"
}
```

---

## 📋 Account Management

### GET /v1/accounts/me

**Purpose**: Get current account information, plan details, and quotas.

**Auth**: Any valid token

**Member Quotas**: Each plan includes limits on the number of team members (users) per account:

| Plan | Max Members | Description |
|------|-------------|-------------|
| Free | 2 | Owner + 1 dev |
| Essentials | 5 | Small team |
| Pro | 15 | Medium team |
| Enterprise | 100 | Large organization |
| Locked | 1 | Owner only (no invites) |

**Response**:
```json
{
  "account_id": "6359c37c-fe0b-4bcf-aa5f-d15f0c40cdc7",
  "plan": "pro",
  "trial_expires": "2024-12-31T23:59:59Z",
  "quotas": {
    "poll_sec": 30,
    "event_batch": 1000,
    "max_tools": 50,
    "max_members": 15,
    "current_members": 3,
    "event_payload_max_bytes": 1048576
  },
  "metrics_enabled": true,
  "poll_seconds": 30,
  "event_sample": {
    "authz_decision": 1.0,
    "tool_invoked": 1.0,
    "policy_poll_interval": 0.1,
    "missing_policy": 0.5
  }
}
```

Note:
- `account_id` is returned for frontend routing convenience. All account-scoped server routes still enforce `auth.account_id == {account_id}`; knowing an ID does not grant access.

### PATCH /v1/accounts/{account_id}/name

**Purpose**: Rename the organization (account display name).

**Auth**: Supabase JWT (owner/dev). Caller must belong to the target account.

**Request**:
```json
{
  "name": "New Organization Name"
}
```

**Responses**:
```json
// 200 OK – updated
{ "message": "account_name_updated", "name": "Acme Inc" }

// 200 OK – no-op (same name)
{ "message": "account_name_unchanged", "name": "Acme Inc" }

// 400 Bad Request – invalid
{ "detail": "invalid_account_name" }

// 403 Forbidden – different account
{ "detail": "account_mismatch" }

// 404 Not Found – account missing
{ "detail": "account_not_found" }
```

**Notes**:
- Idempotent if name is unchanged.
- Audited as `account.update` with old/new values and user context.

**Event Sampling Semantics**

- `event_sample` provides server-driven sampling probabilities per event type used by SDKs to throttle raw telemetry volume.
- Values are floats in [0.0, 1.0]: `1.0` always send, `0.0` never send, `0.5` ~50% of events (client-side randomized).
- Affects telemetry emission only; it does not affect authorization decisions.
- Initial keys:
  - `authz_decision`: keep at 1.0 for accurate allow/deny metrics.
  - `tool_invoked`: can be reduced to cut noise while retaining attribution.
  - `policy_poll_interval`: safe to heavily downsample (heartbeat-style).
  - `missing_policy`: downsample to avoid spikes during incidents.
- Unknown keys are allowed and preserved; SDKs ignore keys they don’t understand.
- Merge precedence: account `event_sample` > env `EVENT_SAMPLE_JSON` > defaults. Non-numeric values ignored; numeric values clamped to [0,1].
- SDKs typically cache `/v1/accounts/me` for ~5 minutes; changes propagate within that window.

**Frontend Usage**:
```typescript
// Check user's plan and limits
const account = await fetch('/v1/accounts/me', {
  headers: { Authorization: `Bearer ${token}` }
}).then(r => r.json());

// Show upgrade prompt if on trial
if (account.trial_expires) {
  showTrialBanner(account.trial_expires);
}
```

---

## 🔑 Token Management

### POST /v1/accounts/{account_id}/tokens

**Purpose**: Create new API tokens (dashboard only - requires Supabase session)

**Auth**: Supabase JWT (owner/dev)

**Request**:
```json
{
  "token_name": "My Dev Token",
  "scopes": ["dev"],
  "app_name": "my-app"
}
```

**Response**:
```json
{
  "token_id": "uuid",
  "token": "d2_abc123...",
  "scopes": ["dev"],
  "expires_at": null
}
```

**Frontend Usage**:
```typescript
// Token creation form
const createToken = async (data) => {
  const response = await fetch(`/v1/accounts/${accountId}/tokens`, {
    method: 'POST',
    headers: { 
      Authorization: `Bearer ${supabaseSession.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  });
  
  if (response.ok) {
    const token = await response.json();
    // Show token once, then hide for security
    showTokenDialog(token.token);
  }
};
```

### GET /v1/accounts/{account_id}/tokens

**Purpose**: List all tokens for account

**Auth**: Supabase JWT (owner/dev)

**Response**:
```json
[
  {
    "token_id": "uuid",
    "token_name": "My Dev Token", 
    "scopes": ["dev"],
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": null,
    "revoked_at": null,
    "app_name": "my-app",
    "created_by_name": "John Doe"
  }
]
```

### DELETE /v1/accounts/{account_id}/tokens/{token_id}

**Purpose**: Revoke a token permanently

**Auth**: Supabase JWT (owner/dev)

**Response**: `204 No Content`

### POST /v1/accounts/{account_id}/tokens/{token_id}/rotate

**Purpose**: Generate new token value, revoke old one

**Auth**: Supabase JWT (owner/dev)

**Response**:
```json
{
  "token": "d2_new_token_value...",
  "expires_at": null
}
```

### GET /v1/accounts/{account_id}/tokens/scopes

**Purpose**: List available scopes for token creation UI

**Auth**: Supabase JWT (owner/dev)

**Response**:
```json
[
  {
    "scope": "dev", 
    "description": "Policy editing and key management for development"
  },
  {
    "scope": "server",
    "description": "Runtime policy access for production servers"
  }
]
```

---

## 📜 Policy Management

### 🏷️ ETags and Concurrency Control

D2 Cloud uses HTTP ETags for efficient caching and optimistic concurrency control across all policy operations. ETags prevent conflicts when multiple clients modify policies and reduce bandwidth through intelligent caching.

#### **ETag Calculation**

ETags are SHA256 hashes calculated differently based on policy state:

**Published Policies (with JWS signature)**:
```python
etag = sha256(jws_content.encode()).hexdigest()
```

**Draft Policies (without JWS)**:
```python
bundle_json = json.dumps(bundle, separators=(",", ":"), sort_keys=True)
etag = sha256(bundle_json.encode()).hexdigest()
```

**Key Characteristics**:
- **Content-based**: Any change to policy content produces a completely different ETag
- **Deterministic**: Same content always produces the same ETag
- **Format**: 64-character hexadecimal string (SHA256)
- **Response format**: Always quoted as strong ETag: `ETag: "abc123..."`

#### **Caching with If-None-Match**

Use `If-None-Match` header for efficient caching on GET requests:

```bash
# Client includes last known ETag
curl -H "If-None-Match: \"3c2a7d4f5e6a7b8c\"" \
     -H "Authorization: Bearer $TOKEN" \
     "/v1/policy/bundle?app_name=my-app"
```

**Server Behavior**:
- **ETag matches**: Returns `304 Not Modified` with minimal payload
- **ETag differs**: Returns `200 OK` with full policy and new ETag
- **Draft policies**: If-None-Match is ignored (drafts change frequently)

**304 Response** (ETag unchanged):
```json
{
  "jws": null,
  "version": 5,
  "etag": "3c2a7d4f5e6a7b8c",
  "bundle": null
}
```

#### **Concurrency Control with If-Match**

Use `If-Match` header to prevent conflicts during policy publishing:

```bash
# Client must provide current ETag to publish
curl -X POST "/v1/policy/publish?app_name=my-app" \
     -H "Authorization: Bearer $TOKEN" \
     -H "If-Match: \"3c2a7d4f5e6a7b8c\"" \
     -d '{}'
```

**Concurrency Rules**:

| Scenario | If-Match Value | Behavior |
|----------|---------------|----------|
| **First publish** | `*`, `"*"`, `W/*`, or omitted | ✅ Allowed |
| **Update existing** | Current ETag | ✅ Allowed if ETag matches |
| **Update existing** | Wrong/old ETag | ❌ `409 etag_mismatch` |
| **Update existing** | Omitted | ❌ `409 etag_mismatch` |

**Error Response** (409 Conflict):
```json
{
  "detail": "etag_mismatch",
  "message": "Policy was modified by another client. Fetch latest version and retry."
}
```

#### **ETag Format Handling**

The server normalizes various ETag formats:

```python
# All these formats are equivalent:
"If-Match: \"abc123\""      # Quoted strong ETag
"If-Match: W/\"abc123\""    # Quoted weak ETag  
"If-Match: abc123"          # Unquoted
```

**Server normalization**:
```python
normalized_etag = provided_etag.lstrip("W/").strip('"')
```

#### **Complete Workflow Example**

```typescript
// 1. Fetch policy with caching
const fetchPolicy = async (lastETag?: string) => {
  const headers = {
    'Authorization': `Bearer ${token}`,
    ...(lastETag && { 'If-None-Match': lastETag })
  };
  
  const response = await fetch('/v1/policy/bundle?app_name=my-app', { headers });
  
  if (response.status === 304) {
    return { policy: cachedPolicy, etag: lastETag, unchanged: true };
  }
  
  const policy = await response.json();
  const etag = response.headers.get('ETag')?.replace(/"/g, '');
  return { policy, etag, unchanged: false };
};

// 2. Publish with concurrency control
const publishPolicy = async (currentETag: string) => {
  const response = await fetch('/v1/policy/publish?app_name=my-app', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'If-Match': `"${currentETag}"`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
  });
  
  if (response.status === 409) {
    const error = await response.json();
    if (error.detail === 'etag_mismatch') {
      throw new ConflictError('Policy was modified by another user. Please refresh and try again.');
    }
  }
  
  const result = await response.json();
  const newETag = response.headers.get('ETag')?.replace(/"/g, '');
  return { ...result, etag: newETag };
};

// 3. Handle conflicts gracefully
const safePublish = async () => {
  try {
    const { policy, etag } = await fetchPolicy();
    await publishPolicy(etag);
  } catch (error) {
    if (error instanceof ConflictError) {
      // Refresh and retry logic
      const { policy, etag } = await fetchPolicy(); // Get latest
      await publishPolicy(etag); // Retry with new ETag
    }
  }
};
```

#### **Best Practices**

1. **Always use If-Match for publishing**: Prevents accidental overwrites
2. **Cache with If-None-Match**: Reduces bandwidth for frequent polling
3. **Handle 409 conflicts gracefully**: Refresh data and retry with new ETag
4. **Store ETags with cached data**: Enable efficient validation
5. **First publish uses `*`**: Use `If-Match: *` for new app policies
6. **Monitor ETag changes**: Different ETag = content changed

---

### GET /v1/policy/bundle

**Purpose**: Get policy bundle for SDK consumption (with polling rate limits)

**Auth**: `policy.read` scope

**Query Parameters**:
- `app_name` (optional): Defaults to token's app_name
- `stage` (optional): `published` | `draft` | `auto` (default)

**Headers**:
- `If-None-Match`: ETag for caching

**Response** (Published):
```json
{
  "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9...",
  "version": 5,
  "etag": "abc123",
  "bundle": null
}
```

**Auto-Refresh Behavior** *(NEW 2025-09-08)*:
- **Expired policies are automatically refreshed** when accessed
- If a policy has expired, the server extends the expiry by 1 week from the current time
- This happens transparently - SDKs receive the policy without interruption
- The refreshed expiry is persisted in the database for future requests

**Response** (Draft):
```json
{
  "jws": null,
  "version": 6,
  "etag": "def456", 
  "bundle": {
    "metadata": {
      "name": "my-app",
      "version": "1.2.0"
    },
    "policies": [...],
    "expiry": "2024-12-31T23:59:59Z"
  }
}
```

**Rate Limiting** (Updated 2025-08-28):
- **Dev tokens**: No polling limits (developer-friendly for local development)
- **Server tokens**: Plan-based limits (30-300s for production)
- **Privileged users**: Owner/dev OAuth sessions bypass polling limits

### 🔢 App Quota (NEW 2025-09-08)
Each subscription plan limits the number of **published** apps (unique `app_name` values with published policies) per account:

| Plan | Max Published Apps |
|------|-------------------|
| Free | 1 |
| Essentials | 5 |
| Pro | 25 |
| Enterprise | 1000 |

**Important Quota Rules**:
- **Drafts are unlimited** - create as many draft policies as needed for any app name
- **Quota applies only to new published apps** - when publishing a draft for an app name that has never been published before
- **Updates are always allowed** - republishing or updating existing published apps doesn't count against quota

Attempting to **publish** a policy for a *brand new app* beyond the limit returns:

```json
{
  "detail": "quota_apps_exceeded",
  "message": "Your plan allows 5 apps; please upgrade to create more."
}
```

**Headers** (429 Response):
```http
Retry-After: 30
```

**SDK Usage**:
```bash
# SDK polls this endpoint
curl -H "Authorization: Bearer d2_server_token" \
     "/v1/policy/bundle?app_name=my-service"
```

### 🤖 SDK Guidance: Handling `quota_apps_exceeded`

When the SDK publishes a draft for a **brand new app name** (that has never been published before) it may receive a quota error:

```http
HTTP/1.1 403 Forbidden

{
  "detail": "quota_apps_exceeded",
  "message": "Your plan allows 5 published apps; please upgrade to create more."
}
```

**Important Notes**:
- **Drafts never trigger quota errors** - unlimited drafts are allowed
- **Updates never trigger quota errors** - republishing existing apps is always allowed
- **Only new published apps count** - first-time publishing of a new app name

The SDK (or CI script) **MUST** interpret this as a *non-retryable* error:

1. **Stop automatic retries** – further attempts will always fail until the plan is upgraded or an old published app is deleted.
2. **Surface actionable feedback** – bubble up the human-readable message so developers know why the publish failed.
3. **Optional** – call `/v1/accounts/me` to fetch `quotas.max_apps` and display current usage vs. limit.

Example TypeScript helper:

```ts
async function publishPolicy(appName: string, token: string) {
  const resp = await fetch(`/v1/policy/publish?app_name=${appName}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'If-Match': currentEtag || '*'
    },
    body: JSON.stringify({}),
  });

  if (resp.status === 403) {
    const err = await resp.json();
    if (err.detail === 'quota_apps_exceeded') {
      throw new Error(
        `Published app limit reached: ${err.message}. ` +
        'Upgrade your plan or delete unused published apps. ' +
        'Note: Drafts are unlimited, only new published apps count.'
      );
    }
  }

  if (!resp.ok) {
    throw new Error(`Policy publish failed: ${resp.status}`);
  }
}
```

Including this logic ensures CI pipelines fail fast with a clear reason instead of looping indefinitely.

### PUT /v1/policy/draft

**Purpose**: Upload/update policy draft with strict validation

**Auth**: `policy.publish` scope

**Request** *(Updated 2025-09-08 - Strict Validation)*:
```json
{
  "bundle": {
    "metadata": {
      "name": "my-app"  // REQUIRED - app name, non-empty
      // "expires" ignored - server generates 1-week expiry
    },
    "policies": [  // REQUIRED - at least one policy
      {
        "role": "user",           // REQUIRED - non-empty string
        "permissions": ["read"]   // REQUIRED - at least one permission
      }
    ]
  }
}
```

**Validation Rules** *(NEW 2025-09-08)*:
- ✅ **metadata.name required** - Cannot be empty or missing (this is the app name)
- ✅ **At least one policy required** - policies array cannot be empty
- ✅ **Each policy must have a role** - Non-empty string required
- ✅ **Each policy must have permissions** - At least one permission required
- ✅ **Server-side expiry** - Any client expiry is ignored, server sets 1 week from now

**Success Response**:
```json
{
  "message": "Draft policy uploaded for 'my-app' (v6)"
}
```

**Validation Error Response** *(400 Bad Request)*:
```json
{
  "detail": "policy_validation_failed: Missing required 'metadata.name' field (app name)"
}
```

**Common Validation Errors**:
```json
// Missing app name
{"detail": "policy_validation_failed: Missing required 'metadata.name' field (app name)"}

// Missing role
{"detail": "policy_validation_failed: policies[0] missing required 'role' field"}

// Empty permissions
{"detail": "policy_validation_failed: policies[0].permissions must contain at least one permission"}

// No policies
{"detail": "policy_validation_failed: Missing required 'policies' section"}
```

**Frontend Usage**:
```typescript
// Policy editor save with validation error handling
const saveDraft = async (bundleContent) => {
  const response = await fetch('/v1/policy/draft', {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${devToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      bundle: bundleContent
    })
  });
  
  if (response.ok) {
    showSuccessMessage("Draft saved");
  } else if (response.status === 400) {
    const error = await response.json();
    if (error.detail?.startsWith('policy_validation_failed:')) {
      const validationMessage = error.detail.replace('policy_validation_failed: ', '');
      showValidationError(`Policy validation failed: ${validationMessage}`);
    } else {
      showGenericError("Failed to save draft");
    }
  }
};

// Example validation error handling
const handleValidationError = (errorDetail) => {
  const errors = errorDetail.replace('policy_validation_failed: Policy validation failed: ', '').split('; ');
  
  errors.forEach(error => {
    if (error.includes("metadata.name")) {
      highlightField("app-name", "App name is required");
    } else if (error.includes("missing required 'role'")) {
      highlightField("policy-role", "Each policy must have a role");
    } else if (error.includes("permissions must contain at least one")) {
      highlightField("policy-permissions", "Each policy must have at least one permission");
    }
  });
};
```

### POST /v1/policy/publish

**Purpose**: Publish draft policy with strict validation

**Auth**: `policy.publish` scope

**Query Parameters**:
- `app_name`: App being published

**Headers**:
- `X-D2-Signature`: Base64 Ed25519 signature of request body *(required for API tokens, optional for Supabase JWTs)*
- `X-D2-Key-Id`: Key ID used for signing *(required for API tokens, optional for Supabase JWTs)*
- `If-Match`: ETag for optimistic concurrency

**Authentication Modes** *(Updated 2025-09-08)*:

**Frontend Users (Supabase JWT)**:
```bash
# No signature required - just the JWT
curl -X POST "/v1/policy/publish?app_name=my-app" \
  -H "Authorization: Bearer $SUPABASE_JWT" \
  -H "If-Match: current_etag" \
  -d '{}'
```

**API Tokens (CLI/SDK)**:
```bash
# Signature required for security
curl -X POST "/v1/policy/publish?app_name=my-app" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "X-D2-Signature: $BASE64_SIGNATURE" \
  -H "X-D2-Key-Id: my-signing-key" \
  -H "If-Match: current_etag" \
  -d '{}'
```

**Response** *(Updated 2025-09-08 - JWS Format)*:
```json
{
  "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9...",
  "version": 6
}
```

**Validation** *(NEW 2025-09-08)*:
- **Same strict validation as draft upload** - ensures draft meets all requirements before publishing
- **Server-side expiry refresh** - generates new 1-week expiry at publish time
- **400 Bad Request** - if draft fails validation (same error format as draft endpoint)

**Headers**:
```http
ETag: "new_etag_value"
X-D2-Poll-Seconds: 30
```

**Concurrency Control**:
- First publish: `If-Match: *`
- Subsequent: `If-Match: "current_etag"`

**Frontend Usage**:

**For Supabase JWT Users (Frontend)**:
```typescript
// Simplified publish flow - no signature required
const publishPolicy = async (appName, supabaseJWT) => {
  // 1. Get current ETag
  const currentPolicy = await getCurrentPolicy();
  
  // 2. Publish (no signature needed)
  const response = await fetch(`/v1/policy/publish?app_name=${appName}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${supabaseJWT}`,
      'If-Match': currentPolicy?.etag || '*',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
  });
  
  if (response.status === 409) {
    // ETag conflict - reload and retry
    showConflictDialog();
  } else if (response.ok) {
    const result = await response.json();
    // Frontend can decode JWS (consistent with GET /bundle)
    const policyData = decodeJWS(result.jws);
    showSuccessMessage(`Policy v${result.version} published for ${policyData.metadata.name}`);
  }
};
```

**For API Tokens (CLI/SDK)**:
```typescript
// Traditional flow with signature verification
const publishPolicySDK = async (keyId, privateKey, apiToken) => {
  // 1. Get current ETag
  const currentPolicy = await getCurrentPolicy();
  
  // 2. Sign empty body with Ed25519
  const signature = await signRequest('', privateKey);
  
  // 3. Publish
  const response = await fetch(`/v1/policy/publish?app_name=${appName}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiToken}`,
      'X-D2-Signature': signature,
      'X-D2-Key-Id': keyId,
      'If-Match': currentPolicy?.etag || '*'
    }
  });
  
  if (response.ok) {
    const result = await response.json();
    // SDK gets JWS for distribution
    return { jws: result.jws, version: result.version };
  }
};
```

### DELETE /v1/policy/revoke

**Purpose**: Revoke active policy (admin only)

**Auth**: `policy.revoke` scope

**Query Parameters**:
- `app_name`: App to revoke

**Response**:
```json
{
  "message": "Active policy revoked for app 'my-app'"
}
```

### GET /v1/policy/versions

**Purpose**: List policy version history

**Auth**: `policy.read` scope

**Query Parameters**:
- `app_name` (optional): Filter by app
- `include_bundle` (optional): Include bundle content for comparison

**Response**:
```json
[
  {
    "id": "uuid",
    "version": 6,
    "active": true,
    "published_at": "2024-01-01T12:00:00Z",
    "expires": "2024-12-31T23:59:59Z",
    "revocation_time": null,
    "app_name": "my-app",
    "published_by": "John Doe",
    "bundle": {...} // if include_bundle=true
  }
]
```

**Frontend Usage**:
```typescript
// Version history panel
const loadVersionHistory = async () => {
  const versions = await fetch(`/v1/policy/versions?app_name=${appName}&include_bundle=true`, {
    headers: { Authorization: `Bearer ${token}` }
  }).then(r => r.json());
  
  // Render timeline with diff capabilities
  renderVersionTimeline(versions);
};
```

### POST /v1/policy/revert

**Purpose**: Revert to specific policy version

**Auth**: `policy.revert` scope

**Request**:
```json
{
  "policy_id": "uuid_of_version_to_revert_to"
}
```

**Response**:
```json
{
  "message": "Reverted to policy version 4"
}
```

### GET /v1/policy/list

**Purpose**: List all policies (drafts + published) for frontend

**Auth**: `policy.read` scope

**Response**:
```json
[
  {
    "id": "uuid",
    "app_name": "my-app",
    "version": 6,
    "is_draft": false,
    "active": true,
    "created_at": "2024-01-01T00:00:00Z"
  },
  {
    "id": "uuid2", 
    "app_name": "my-app",
    "version": 7,
    "is_draft": true,
    "active": false,
    "created_at": "2024-01-02T00:00:00Z"
  }
]
```

### GET /v1/policy/{policy_id}

**Purpose**: Get detailed policy information

**Auth**: `policy.read` scope

**Response**:
```json
{
  "id": "uuid",
  "app_name": "my-app", 
  "version": 6,
  "is_draft": false,
  "active": true,
  "bundle": {...},
  "created_at": "2024-01-01T00:00:00Z",
  "published_at": "2024-01-01T12:00:00Z"
}
```


### PATCH /v1/policy/{policy_id}/bundle

**Purpose**: Update policy bundle content (editor)

**Auth**: `policy.publish` scope

**Request**:
```json
{
  "bundle": {...}
}
```

**Response**:
```json
{
  "message": "Policy bundle updated"
}
```

### POST /v1/policy/validate

**Purpose**: Validate policy bundle syntax

**Auth**: `policy.read` scope

**Request**:
```json
{
  "bundle": {...}
}
```

**Response**:
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Consider adding explicit deny rules"
  ]
}
```

**Frontend Usage**:
```typescript
// Real-time validation in policy editor
const validatePolicy = async (bundleContent) => {
  const result = await fetch('/v1/policy/validate', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ bundle: bundleContent })
  }).then(r => r.json());
  
  // Show errors/warnings in editor
  updateEditorDiagnostics(result.errors, result.warnings);
};
```

### GET /v1/policy/apps

**Purpose**: List app names for dropdowns

**Auth**: `policy.read` scope

**Response**:
```json
["my-app", "api-service", "worker-service"]
```

### GET /v1/policy/roles-permissions *(NEW 2025-09-15)*

**Purpose**: Extract all unique roles and permissions from existing policy bundles for UI suggestions

**Auth**: `policy.read` scope

**Response**:
```json
{
  "roles": [
    "admin",
    "developer", 
    "viewer",
    "custom_role"
  ],
  "permissions": [
    "*",
    "database:query",
    "weather_api",
    "notifications:send",
    "file:read"
  ],
  "role_mappings": {
    "admin": ["*"],
    "developer": [
      "database:query",
      "weather_api", 
      "notifications:send"
    ],
    "viewer": ["file:read"],
    "custom_role": ["database:query", "file:read"]
  }
}
```

**Frontend Usage**:
```typescript
// Load suggestions for policy editor
const loadPolicySuggestions = async () => {
  const suggestions = await fetch('/v1/policy/roles-permissions', {
    headers: { Authorization: `Bearer ${token}` }
  }).then(r => r.json());
  
  // Populate role dropdown
  const roleDropdown = suggestions.roles;
  
  // When user selects a role, suggest its typical permissions
  const onRoleSelect = (selectedRole) => {
    const typicalPermissions = suggestions.role_mappings[selectedRole] || [];
    suggestPermissions(typicalPermissions);
  };
  
  // Populate permission autocomplete
  const permissionAutocomplete = suggestions.permissions;
};

// Smart permission suggestions based on role selection
const suggestPermissionsForRole = (role, suggestions) => {
  const commonPermissions = suggestions.role_mappings[role] || [];
  
  if (commonPermissions.length > 0) {
    showSuggestionTooltip(`${role} roles typically have: ${commonPermissions.join(', ')}`);
    prePopulatePermissions(commonPermissions);
  }
};

// Role template creation
const createRoleTemplate = (existingRole, suggestions) => {
  const template = {
    role: `${existingRole}_copy`,
    permissions: suggestions.role_mappings[existingRole] || []
  };
  
  return template;
};
```

**Use Cases**:
- **Autocomplete dropdowns**: Populate role and permission fields with previously used values
- **Smart suggestions**: When user selects "admin" role, auto-suggest "*" permission
- **Consistency checking**: Warn if user gives admin role limited permissions (usually gets "*")
- **Template creation**: "Create role like existing 'developer'" → pre-fill with developer permissions
- **Pattern recognition**: Show most common permission combinations for each role type

---

## 🔐 Key Management

### POST /v1/keys

**Purpose**: Upload Ed25519 public key for policy signing

**Auth**: `key.upload` scope

**Request** *(Updated 2025-09-15)*:
```json
{
  "public_key": "base64_encoded_public_key"
}
```

**Security Note**: `key_id` is now system-generated (format: `ed_<12-hex-chars>`) for security and audit consistency. User-provided key IDs are no longer accepted.

**Response** *(Updated 2025-09-15)*:
```json
{
  "message": "key_added: ed_5742a979d8b3"
}
```

**Frontend Usage** *(Updated 2025-09-15)*:
```typescript
// Key upload form - key_id is now system-generated
const uploadKey = async (publicKeyBase64) => {
  const response = await fetch('/v1/keys', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${devToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      public_key: publicKeyBase64
    })
  });
  
  if (response.ok) {
    const result = await response.json();
    // Extract generated key ID from response message
    const keyId = result.message.split(': ')[1];
    showKeyAddedMessage(`Key uploaded successfully with ID: ${keyId}`);
    refreshKeyList();
  }
};
```

### GET /v1/keys

**Purpose**: List uploaded keys with user attribution (for frontend display)

**Auth**: Supabase JWT (owner/dev) *(Updated 2025-09-08)*

**Query Parameters**:
- `include_revoked`: Include revoked keys (0/1)

**Response** (Updated 2025-08-28):
```json
[
  {
    "key_id": "my-signing-key-1",
    "algo": "ed25519",
    "public_key": "base64_encoded_key",
    "created_at": "2024-01-01T00:00:00Z",
    "revoked_at": null,
    "user_id": "user-uuid-123",
    "uploaded_by_name": "Alex Brown"
  }
]
```

**New Fields**:
- `user_id`: ID of user who uploaded the key
- `uploaded_by_name`: Display name of uploader (for UI attribution)

**Frontend Usage** *(Updated 2025-09-08)*:
```typescript
// Frontend can now list all keys for the organization
const listKeys = async (supabaseJWT: string) => {
  const response = await fetch('/v1/keys', {
    headers: {
      Authorization: `Bearer ${supabaseJWT}`,
    }
  });
  
  if (response.ok) {
    const keys = await response.json();
    // Display keys in UI with uploader attribution
    keys.forEach(key => {
      console.log(`Key ${key.key_id} uploaded by ${key.uploaded_by_name}`);
    });
  }
};
```

### DELETE /v1/keys/{key_id}

**Purpose**: Revoke a signing key

**Auth**: `key.upload` scope (Updated 2025-08-28)

**Response**:
```json
{
  "message": "key_revoked"
}
```

---

## 📊 Events & Metrics

### POST /v1/events/ingest

**Purpose**: Ingest batched telemetry events from SDK

**Auth**: `event.ingest` scope

**Request** (Updated 2025-08-28):
```json
{
  "events": [
    {
      "event_type": "tool_invoked",
      "payload": {
        "service": "api-gateway",
        "host": "prod-server-01", 
        "pid": 12345,
        "flush_interval_s": 60,
        "tool_id": "weather_api",
        "decision": "allowed",
        "resource": "weather_api",
        "policy_etag": "3c2a7d4f5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
      },
      "occurred_at": "2025-01-15T10:30:45.123Z"
    }
  ]
}
```

**Key Changes**:
- Now expects batched events in `events` array (matches SDK structure)
- `tool_invoked` is the primary event type for authorization decisions
- Rich metadata includes service, host, PID, and policy ETag
- **NEW (2025-08-28)**: Threading security telemetry support
- **CRITICAL**: Service name now comes from policy bundle `metadata.name` (not env vars)
- Automatic audit log creation for comprehensive tracking

**Response**:
```json
{
  "message": "Accepted 1 events"
}
```

#### Threading Security Telemetry (NEW 2025-08-28)

The SDK now sends comprehensive threading security events for multi-threaded applications:

**Context Submission Event**:
```json
{
  "event_type": "context_submission",
  "payload": {
    "service": "api-gateway",
    "host": "prod-server-01",
    "thread_name": "ThreadPoolExecutor-1",
    "tool_id": "file_processor",
    "method": "explicit_actor"
  },
  "occurred_at": "2025-01-15T10:30:45.123Z"
}
```

**Security Violation Event** (High Priority Alert):
```json
{
  "event_type": "context_missing_actor", 
  "payload": {
    "service": "api-gateway",
    "host": "prod-server-01",
    "thread_name": "background-worker",
    "tool_id": "sensitive_operation"
  },
  "occurred_at": "2025-01-15T10:30:45.123Z"
}
```

**Confused Deputy Detection** (Security Alert):
```json
{
  "event_type": "context_actor_override",
  "payload": {
    "service": "api-gateway", 
    "host": "prod-server-01",
    "thread_name": "request-handler",
    "tool_id": "admin_function",
    "ambient_user": "user123",
    "explicit_user": "admin456"
  },
  "occurred_at": "2025-01-15T10:30:45.123Z"
}
```

**Context Leak Detection**:
```json
{
  "event_type": "context_leak_detected",
  "payload": {
    "service": "api-gateway",
    "host": "prod-server-01", 
    "thread_name": "cleanup-worker",
    "tool_id": "data_processor"
  },
  "occurred_at": "2025-01-15T10:30:45.123Z"
}
```

**Alert Priorities**:
- `context_missing_actor`, `d2_no_context_error`: **HIGH** - Security violations
- `context_actor_override`: **HIGH** - Potential confused deputy attacks  
- `context_leak_detected`: **MEDIUM** - Context hygiene issues
- `context_submission`, `thread_entrypoint`: **LOW** - Informational tracking

### GET /v1/events

**Purpose**: List events for dashboard

**Auth**: `metrics.read` scope

**Query Parameters**:
- `limit`: Max 1000
- `cursor`: Pagination cursor

**Response**:
```json
[
  {
    "id": "uuid",
    "occurred_at": "2024-01-01T12:00:00Z",
    "event_type": "authorization_decision",
    "payload": {...},
    "ingested_at": "2024-01-01T12:00:01Z",
    "host": "api-server-1",
    "source_ip": "192.168.1.10"
  }
]
```

**Headers** (for pagination):
```http
X-Next-Cursor: "2024-01-01T11:59:59Z,uuid"
```

### 📈 Metrics (Supabase-backed)

All metrics endpoints require `metrics.read` via strict scope check and `accounts.metrics_enabled = true`.

#### GET /v1/metrics/summary

**Purpose**: Overall summary for a time range.

**Auth**: `metrics.read`

**Query Parameters**:
- `start`: ISO timestamp (optional; default now-30d)
- `end`: ISO timestamp (optional; default now)

**Response**:
```json
{
  "start": "2025-01-01T00:00:00Z",
  "end": "2025-01-31T23:59:59Z",
  "total_authorizations": 12345,
  "total_denied": 234,
  "deny_rate": 0.0189,
  "unique_tools": 17,
  "unique_resources": 17,
  "avg_decision_ms": 12.5,
  "avg_ingest_lag_ms": 85.2
}
```

Notes:
- Allowed/denied inferred from `tool_invoked`/`authz_decision` payload `decision`/`allowed`.
- `avg_decision_ms` is computed only if SDK sends `decision_ms`/`decision_time_ms`/`latency_ms`/`duration_ms` in payload.

#### GET /v1/metrics/timeseries

**Purpose**: Allowed vs denied over time buckets.

**Auth**: `metrics.read`

**Query Parameters**:
- `bucket`: `hour` or `day` (default `day`)
- `days`: window size (default 7, max 90)

**Response**:
```json
{
  "bucket": "day",
  "start": "2025-01-24T00:00:00Z",
  "end": "2025-01-31T00:00:00Z",
  "points": [
    { "ts": "2025-01-24T00:00:00Z", "allowed": 120, "denied": 3, "total": 123 }
  ]
}
```

#### GET /v1/metrics/top

**Purpose**: Top-N breakdown by dimension.

**Auth**: `metrics.read`

**Query Parameters**:
- `dimension`: `tools` | `resources` | `event_type` (default `tools`)
- `days`: window size (default 30)
- `n`: top-N size (default 10, max 100)

**Response**:
```json
{
  "dimension": "tools",
  "start": "2025-01-01T00:00:00Z",
  "end": "2025-01-31T23:59:59Z",
  "total": 12345,
  "items": [ { "key": "weather_api", "count": 3210 } ]
}
```

---

## 📋 Audit Logs *(Enhanced 2025-09-15)*

### GET /v1/audit

**Purpose**: List comprehensive audit logs with user attribution (admin only)

**Auth**: dev or server API token (depending on endpoint)

**Query Parameters**:
- `limit`: Max 1000 (default: 100)
- `cursor`: Pagination cursor `'<iso>,<id>'` from `X-Next-Cursor` header

**Response** *(Updated 2025-09-15)*:
```json
[
  {
    "id": 9,
    "actor_id": "f6188bb0-c023-47d4-86c5-13ad0fbc3b92",
    "user_id": "f6188bb0-c023-47d4-86c5-13ad0fbc3b92",
    "user_name": "David Kim",
    "token_id": "6f53c148-ef6c-48b2-bb91-372959021df8",
    "action": "key.revoke",
    "key_id": "test-audit-key",
    "version": null,
    "status": "success",
    "resource_type": "key",
    "resource_id": "test-audit-key",
    "metadata": {},
    "created_at": "2025-09-15T23:16:45.756085Z"
  },
  {
    "id": 8,
    "actor_id": "f6188bb0-c023-47d4-86c5-13ad0fbc3b92",
    "user_id": "f6188bb0-c023-47d4-86c5-13ad0fbc3b92",
    "user_name": "David Kim",
    "token_id": "6f53c148-ef6c-48b2-bb91-372959021df8",
    "action": "key.upload",
    "key_id": "test-audit-key",
    "version": null,
    "status": "success",
    "resource_type": "key",
    "resource_id": "test-audit-key",
    "metadata": {
      "algorithm": "ed25519"
    },
    "created_at": "2025-09-15T23:15:56.266945Z"
  }
]
```

**Headers** (for pagination):
```http
X-Next-Cursor: "2025-09-15T23:15:56Z,8"
```

### 🔍 Audit Log Fields *(NEW 2025-09-15)*

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique audit log entry ID |
| `actor_id` | string | Account ID performing the action |
| `user_id` | string\|null | User who performed the action (null for server tokens) |
| `user_name` | string\|null | **NEW**: Display name of user (resolved from users table) |
| `token_id` | string\|null | API token used for the action |
| `action` | string | Standardized action type (e.g., `key.upload`, `policy.publish`) |
| `key_id` | string\|null | Cryptographic key ID (for key operations) |
| `version` | integer\|null | Resource version (for versioned resources like policies) |
| `status` | string | **NEW**: Operation status (`success`, `failure`, `denied`, etc.) |
| `resource_type` | string\|null | **NEW**: Type of resource (`token`, `key`, `policy`, `invitation`, `user`) |
| `resource_id` | string\|null | **NEW**: ID of the specific resource acted upon |
| `metadata` | object\|null | **NEW**: Additional structured data about the operation |
| `created_at` | datetime | When the audit event occurred |

### 📊 Audit Action Types

**Token Operations**:
- `token.create` - API token creation
- `token.revoke` - API token revocation  
- `token.rotate` - API token rotation

**Key Operations**:
- `key.upload` - Ed25519 public key upload
- `key.revoke` - Key revocation

**Policy Operations**:
- `policy.draft` - Policy draft creation/update
- `policy.publish` - Policy publication
- `policy.revoke` - Policy revocation
- `policy.revert` - Policy reversion to previous version
- `policy.update` - Policy bundle content update

**User Operations**:
- `user.role_update` - User role change

**Invitation Operations**:
- `invitation.create` - Invitation creation
- `invitation.accept` - Invitation acceptance
- `invitation.cancel` - Invitation cancellation

### 📋 Metadata Examples

**Token Creation**:
```json
{
  "metadata": {
    "token_name": "My Dev Token",
    "scopes": ["dev"],
    "app_name": "my-app",
    "assigned_user_id": "user-uuid",
    "token_type": "user"
  }
}
```

**Policy Publish**:
```json
{
  "metadata": {
    "app_name": "my-app",
    "version": 3,
    "key_id": "signing-key-123",
    "signature_required": true,
    "bundle_size": 2048
  }
}
```

**User Role Update**:
```json
{
  "metadata": {
    "target_user_id": "user-uuid",
    "old_role": "member",
    "new_role": "dev"
  }
}
```

**Invitation Management**:
```json
{
  "metadata": {
    "email": "newuser@example.com",
    "role": "dev",
    "invited_by": "inviter-user-id"
  }
}
```

### 🔍 Frontend Usage

```typescript
// Audit log viewer with rich user context
const loadAuditLogs = async (cursor?: string) => {
  const url = `/v1/audit?limit=50${cursor ? `&cursor=${cursor}` : ''}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  
  const logs = await response.json();
  const nextCursor = response.headers.get('X-Next-Cursor');
  
  return { logs, nextCursor };
};

// Display user-friendly audit entries
const renderAuditEntry = (entry) => {
  const userName = entry.user_name || 'System';
  const action = entry.action.replace('.', ' ').toUpperCase();
  const resource = entry.resource_type ? `${entry.resource_type}:${entry.resource_id}` : 'N/A';
  
  return `${userName} performed ${action} on ${resource} at ${entry.created_at}`;
};

// Filter by resource type
const filterByResource = async (resourceType: string) => {
  // Note: Filtering by resource_type requires backend implementation
  // For now, filter client-side after fetching
  const { logs } = await loadAuditLogs();
  return logs.filter(log => log.resource_type === resourceType);
};

// Security monitoring - detect suspicious patterns
const detectSuspiciousActivity = (logs) => {
  const suspiciousPatterns = [
    logs.filter(log => log.action === 'user.role_update' && log.metadata?.new_role === 'admin'),
    logs.filter(log => log.action === 'token.create' && log.metadata?.scopes?.includes('admin')),
    logs.filter(log => log.status === 'failure' && log.action.includes('policy')),
  ];
  
  return suspiciousPatterns.flat();
};
```

### 🎯 Use Cases

1. **Compliance Auditing**: Complete trail of who did what when
2. **Security Monitoring**: Track admin actions and permission changes  
3. **Debugging**: Understand what operations led to issues
4. **User Attribution**: See actual user names instead of cryptic IDs
5. **Resource Tracking**: Find all operations on specific resources
6. **Analytics**: Usage patterns and operation frequency

---

## 🏢 Multi-Tenancy (Invitations)

### POST /v1/accounts/{account_id}/invitations  _(create invitation)_

**Purpose**: Invite a user to the organisation

**Auth**: Supabase JWT (`role` = `admin` **or** `owner`)

**Role Choices** *(updated 2025-09-08)*:
`admin`, `dev` — other roles cannot be assigned via invitation.

**Request**:
```json
{
  "email": "dev@example.com",
  "role": "dev"  // or "admin"
}
```

**Response** *(model `InvitationCreateResponse`)*:
```json
{
  "message": "invitation_sent_to_dev@example.com",
  "invitation_url": "https://d2.artoo.love/invitations/accept?token=inv_abc123..."
}
```
Send the returned `invitation_url` to the invitee (email, Slack, etc.).

### GET /v1/accounts/{account_id}/invitations  _(list invitations)_

**Purpose**: List invitations for the account (pending by default)

**Auth**: Supabase JWT – caller must be `admin`/`owner` **and** belong to the account

**Query Params**:
| name | type | default | description |
|------|------|---------|-------------|
| `include_accepted` | bool | `false` | Include accepted/expired invitations |

**Response** `InvitationListResponse`:
```json
{
  "invitations": [
  {
    "id": "uuid",
    "email": "newuser@example.com", 
    "role": "member",
      "invited_by_user_id": "user-123",
      "invited_by_name": "Alice",
      "expires_at": "2025-10-01T00:00:00Z",
      "accepted_at": null,
      "created_at": "2025-09-25T00:00:00Z",
      "invitation_token": "inv_abc123..."  // Only returned to admins for copy-link
    }
  ]
}
```

### GET /v1/accounts/{account_id}/invitations/members  _(list account users)_

Returns every user already in the organisation with their names & roles.

**Auth**: Supabase JWT – caller must be `admin`/`owner` of the account.

**Response** `AccountMembersResponse`:
```json
{
  "members": [
    {
      "user_id": "f6188bb0…",
      "email": "founder@example.com",
      "full_name": "David Kim",
      "display_name": "David",
      "role": "owner",
      "created_at": "2025-08-15T02:33:39Z"
    },
    {
      "user_id": "6359c37c…",
      "email": "dev@example.com",
      "full_name": "Alpaca",
      "display_name": "Alpaca",
      "role": "admin",
      "created_at": "2025-09-13T19:56:51Z"
    }
  ]
}
```

### DELETE /v1/accounts/{account_id}/invitations/{invitation_id}

**Purpose**: Cancel invitation

**Auth**: Supabase JWT (admin role)

**Response**: `204 No Content`

### GET /v1/invitations/info/{invitation_token}

**Purpose**: Get invitation details (public endpoint) *(Updated 2025-09-08)*

**Auth**: None

**Response**:
```json
{
  "invitation_id": "uuid",
  "account_id": "uuid",
  "account_name": "Acme Corp",
  "email": "newuser@example.com",
  "role": "member",
  "expires_at": "2024-01-08T00:00:00Z"
}
```

### GET /v1/invitations/accept

**Purpose**: Get invitation acceptance page info (what user sees when clicking email link) *(NEW 2025-09-08)*

**Auth**: None (public endpoint)

**Query Parameters**:
- `token`: Invitation token from email link

**Request**:
```bash
GET /v1/invitations/accept?token=inv_abc123...
```

**Response**:
```json
{
  "account_name": "Acme Corp",
  "invited_by_name": "John Smith", 
  "role": "dev",
  "expires_at": "2024-01-08T00:00:00Z"
}
```

### POST /v1/invitations/accept

**Purpose**: Accept invitation and join organization *(Updated 2025-09-08)*

**Auth**: Supabase JWT (user accepting)

**Query Parameters**:
- `token`: Invitation token from email link

**Request**:
```bash
POST /v1/invitations/accept?token=inv_abc123...
# No request body needed
```

**Response**:
```json
{
  "message": "invitation_accepted"
}
```

### PATCH /v1/accounts/{account_id}/users/{user_id}/role *(NEW 2025-09-08)*

**Purpose**: Promote or demote an existing user (admin/owner only)

**Auth**: Supabase JWT (`admin` or `owner`)

**Request**:
```json
{
  "role": "admin"   // "admin", "dev", or "member"
}
```

**Constraints**:
- Cannot assign or modify the `owner` role via API.
- Cannot modify users outside the caller’s account (`account_mismatch` error).

**Response**:
```json
{
  "message": "role_updated"
}
```

---

## 🔧 JWKS (Public)

### GET /.well-known/jwks.json

**Purpose**: Public JWKS endpoint for JWT verification

**Auth**: None

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-id-123",
      "use": "sig",
      "alg": "RS256",
      "n": "base64_encoded_modulus",
      "e": "AQAB"
    }
  ]
}
```

---

## 🚨 Error Patterns

### Standard Error Response

```json
{
  "detail": "error_code",
  "message": "Human readable description"
}
```

### Common Error Codes

**Authentication**:
- `invalid_token`: Token malformed or expired
- `insufficient_scope`: Token lacks required permissions

**Policy Management**:
- `etag_mismatch`: Concurrent modification detected
- `version_rollback`: Attempting to publish older version
- `no_draft_found`: No draft to publish
- `policy_validation_failed`: Invalid policy syntax or missing required fields

**Policy Validation Errors** *(NEW 2025-09-08)*:
- `policy_validation_failed: Missing required 'metadata.name' field (app name)`
- `policy_validation_failed: policies[0] missing required 'role' field`
- `policy_validation_failed: policies[0].permissions must contain at least one permission`
- `policy_validation_failed: Missing required 'policies' section`

**Rate Limiting**:
- `bundle_poll_rate_limit`: Too frequent policy bundle requests
- `event_rate_limit`: Too many events ingested

**Resource Management**:
- `key_not_found`: Signing key doesn't exist
- `policy_not_found`: Policy doesn't exist
- `account_not_found`: Account doesn't exist
- `signature_required`: API token publish requires X-D2-Signature and X-D2-Key-Id headers

### Frontend Error Handling

```typescript
const handleApiError = async (response) => {
  if (!response.ok) {
    const error = await response.json();
    
    switch (error.detail) {
      case 'etag_mismatch':
        // Reload and retry
        await refreshData();
        showRetryDialog();
        break;
        
      case 'insufficient_scope':
        // Redirect to token management
        redirectToTokens();
        break;
        
      case 'bundle_poll_rate_limit':
        // Show rate limit warning
        const retryAfter = response.headers.get('Retry-After');
        showRateLimit(retryAfter);
        break;
        
      default:
        showGenericError(error.detail);
    }
  }
};
```

---

## 🔄 Common Workflows

### 1. Policy Development Workflow

```typescript
// 1. Create dev token (dashboard)
const devToken = await createToken({ scopes: ['dev'], app_name: 'my-app' });

// 2. Upload signing key
await uploadKey('my-key-1', publicKeyBase64);

// 3. Create/edit draft
await saveDraft(policyBundle);

// 4. Validate policy
const validation = await validatePolicy(policyBundle);

// 5. Publish policy
await publishPolicy('my-key-1', privateKey);

// 6. Monitor in production
const events = await getEvents();
```

### 2. Multi-User Setup

```typescript
// 1. Owner creates organization (automatic on signup)

// 2. Invite team members
await inviteUser('dev@example.com', 'member');

// 3. Member accepts invitation
await acceptInvitation(invitationToken);

// 4. Create tokens for each team member
await createToken({
  scopes: ['dev'],
  assigned_user_id: memberUserId
});
```

### 3. Production Deployment

```typescript
// 1. Create server token
const serverToken = await createToken({ 
  scopes: ['server'], 
  app_name: 'my-service' 
});

// 2. Configure SDK
process.env.D2_TOKEN = serverToken;
process.env.D2_POLICY_URL = 'https://api.d2cloud.com/v1/policy/bundle';

// 3. SDK polls for policy updates automatically
// 4. Monitor events and audit logs
```

---

## 📝 Notes for Frontend Development

### State Management
- Cache policies locally with ETag validation
- Implement optimistic updates for drafts
- Handle concurrent editing scenarios

### Real-time Updates
- Poll `/v1/policy/versions` for version history updates
- Use WebSockets or SSE for real-time collaboration (future)

### Security Considerations
- Never log or store API tokens
- Validate all user inputs before API calls
- Implement proper error boundaries

### Performance
- Implement proper pagination for large lists
- Use debouncing for policy validation
- Cache static data (scopes, app names)

---

## Lead Generation API

### POST /public/v1/leads/

**Purpose**: Submit lead information from contact forms (no authentication required)

**Request**:
```json
{
  "email": "john@acme.com",
  "company_name": "Acme Corp", 
  "ai_agents_description": "We need help securing our AI agents that access customer databases and external APIs. Currently struggling with permission management and audit trails."
}
```

**Validation Rules**:
- `email`: Must be valid email format, automatically converted to lowercase
- `company_name`: Minimum 2 characters, whitespace trimmed
- `ai_agents_description`: Minimum 10 characters, whitespace trimmed

**Success Response** (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "john@acme.com",
  "company_name": "Acme Corp",
  "ai_agents_description": "We need help securing our AI agents...",
  "created_at": "2025-09-19T12:00:00Z",
  "updated_at": "2025-09-19T12:00:00Z"
}
```

**Duplicate Handling**: If email already exists, returns the existing lead (same 201 status)

**Error Responses**:
- `422 Validation Error`: Invalid input data
- `500 Internal Server Error`: Database/server issues

**CORS**: Fully enabled for all origins on public endpoints

### GET /public/v1/leads/

**Purpose**: List all leads (for admin/testing purposes)

**Response**: Array of lead objects

### GET /public/v1/leads/health

**Purpose**: Health check for leads service

**Response**: `{"status": "healthy", "service": "leads"}`

---

This document should provide everything needed for comprehensive frontend development against the D2 Cloud API.

## Accounts – members

- **GET /v1/accounts/{account_id}/invitations/members** – Owner/Dev only; lists all users belonging to the account with their `full_name` / `display_name` and role.
- Response model:
```json
{
  "members": [
    { "user_id": "…", "email": "…", "full_name": "…", "display_name": "…", "role": "owner", "created_at": "2025-09-15T12:34:56Z" }
  ]
}
```
