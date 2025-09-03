# D2 Cloud API Contracts

*Last updated: 2025-08-28 – includes AuthContext refactor, app name normalization, and comprehensive audit logging*

## Overview

This document provides comprehensive API contracts for the D2 Cloud control plane. It's designed to be used by frontend developers and LLMs to understand how to interact with the API correctly.

## Recent Updates (2025-08-28)

### 🔄 AuthContext Refactor
All routes now use clean, type-safe `AuthContext` objects instead of hidden `request.state` magic:
```typescript
// Routes now provide explicit auth context
interface AuthContext {
  account_id: string;
  scopes: string[];
  user_id?: string;
  token_id?: string;
  app_name?: string;
}
```

### 🏷️ App Name Normalization  
All app names are automatically normalized (spaces → underscores) for consistency:
- `"my app"` and `"my_app"` are treated as the same application
- Prevents mismatches between API requests and database storage

### 📊 Enhanced Audit Logging
Comprehensive tracking of all system actions with user attribution, resource metadata, and status tracking.

## Authentication

All API endpoints (except public ones) require authentication via Bearer tokens:

```http
Authorization: Bearer d2_[token_value]
```

### Token Types & Scopes

- **Admin Tokens**: Full access (`admin` scope)
- **Dev Tokens**: Policy editing (`dev` scope = `policy.read` + `policy.publish` + `key.upload`)  
- **Server Tokens**: Runtime access (`server` scope = `policy.read` + `event.ingest`)

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

**Response**:
```json
{
  "plan": "pro",
  "trial_expires": "2024-12-31T23:59:59Z",
  "quotas": {
    "poll_sec": 30,
    "event_batch": 1000,
    "max_tools": 50,
    "event_payload_max_bytes": 1048576
  },
  "metrics_enabled": true,
  "poll_seconds": 30
}
```

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

**Auth**: Supabase JWT (admin role)

**Request**:
```json
{
  "token_name": "My Dev Token",
  "scopes": ["dev"],
  "app_name": "my-app",
  "assigned_user_id": "user_uuid"
}
```

**Response**:
```json
{
  "token_id": "uuid",
  "token": "d2_abc123...",
  "scopes": ["dev"],
  "expires_at": null,
  "app_name": "my-app"
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

**Auth**: Supabase JWT (admin role)

**Response**:
```json
[
  {
    "token_id": "uuid",
    "name": "My Dev Token", 
    "scopes": ["dev"],
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": null,
    "revoked_at": null,
    "app_name": "my-app",
    "creator_name": "John Doe",
    "assigned_user_name": "Jane Smith"
  }
]
```

### DELETE /v1/accounts/{account_id}/tokens/{token_id}

**Purpose**: Revoke a token permanently

**Auth**: Supabase JWT (admin role)

**Response**: `204 No Content`

### POST /v1/accounts/{account_id}/tokens/{token_id}/rotate

**Purpose**: Generate new token value, revoke old one

**Auth**: Supabase JWT (admin role)

**Response**:
```json
{
  "token": "d2_new_token_value...",
  "expires_at": null
}
```

### GET /v1/accounts/{account_id}/tokens/scopes

**Purpose**: List available scopes for token creation UI

**Auth**: Supabase JWT (admin role)

**Response**:
```json
[
  {
    "scope": "admin",
    "description": "Full access to all resources and settings"
  },
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

### GET /v1/accounts/{account_id}/tokens/users

**Purpose**: List users for token assignment dropdown

**Auth**: Supabase JWT (admin role)

**Response**:
```json
{
  "users": [
    {
      "user_id": "uuid",
      "display_name": "John Doe",
      "email": "john@example.com", 
      "full_name": "John Doe"
    }
  ]
}
```

---

## 📜 Policy Management

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
- **Admin tokens**: No polling limits (admin privilege)
- **Server tokens**: Plan-based limits (30-300s for production)

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

### PUT /v1/policy/draft

**Purpose**: Upload/update policy draft

**Auth**: `policy.publish` scope

**Request**:
```json
{
  "bundle": {
    "metadata": {
      "name": "my-app",
      "version": "1.2.0"
    },
    "policies": [
      {
        "name": "resource_access",
        "rules": [...]
      }
    ],
    "expiry": "2024-12-31T23:59:59Z"
  },
  "description": "Added new resource permissions"
}
```

**Response**:
```json
{
  "message": "Draft policy uploaded for 'my-app' (v6)"
}
```

**Frontend Usage**:
```typescript
// Policy editor save
const saveDraft = async (bundleContent) => {
  const response = await fetch('/v1/policy/draft', {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${devToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      bundle: bundleContent,
      description: "Updated permissions"
    })
  });
  
  if (response.ok) {
    showSuccessMessage("Draft saved");
  }
};
```

### POST /v1/policy/publish

**Purpose**: Publish draft policy (requires Ed25519 signature)

**Auth**: `policy.publish` scope

**Query Parameters**:
- `app_name`: App being published

**Headers**:
- `X-D2-Signature`: Base64 Ed25519 signature of request body
- `X-D2-Key-Id`: Key ID used for signing
- `If-Match`: ETag for optimistic concurrency

**Response**:
```json
{
  "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9...",
  "version": 6
}
```

**Headers**:
```http
ETag: "new_etag_value"
X-D2-Poll-Seconds: 30
```

**Concurrency Control**:
- First publish: `If-Match: *`
- Subsequent: `If-Match: "current_etag"`

**Frontend Usage**:
```typescript
// Publish flow
const publishPolicy = async (keyId, privateKey) => {
  // 1. Get current ETag
  const currentPolicy = await getCurrentPolicy();
  
  // 2. Sign empty body with Ed25519
  const signature = await signRequest('', privateKey);
  
  // 3. Publish
  const response = await fetch(`/v1/policy/publish?app_name=${appName}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${devToken}`,
      'X-D2-Signature': signature,
      'X-D2-Key-Id': keyId,
      'If-Match': currentPolicy?.etag || '*'
    }
  });
  
  if (response.status === 409) {
    // ETag conflict - reload and retry
    showConflictDialog();
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
    "description": "Added new permissions",
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
    "description": "Production policy",
    "created_at": "2024-01-01T00:00:00Z"
  },
  {
    "id": "uuid2", 
    "app_name": "my-app",
    "version": 7,
    "is_draft": true,
    "active": false,
    "description": "Work in progress",
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
  "description": "Production policy",
  "bundle": {...},
  "created_at": "2024-01-01T00:00:00Z",
  "published_at": "2024-01-01T12:00:00Z"
}
```

### PATCH /v1/policy/{policy_id}/description

**Purpose**: Update policy description

**Auth**: `policy.publish` scope

**Request**:
```json
{
  "description": "Updated description"
}
```

**Response**:
```json
{
  "message": "Policy description updated"
}
```

### PATCH /v1/policy/{policy_id}/bundle

**Purpose**: Update policy bundle content (editor)

**Auth**: `policy.publish` scope

**Request**:
```json
{
  "bundle": {...},
  "description": "Updated bundle via editor"
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

---

## 🔐 Key Management

### POST /v1/keys

**Purpose**: Upload Ed25519 public key for policy signing

**Auth**: `key.upload` scope

**Request**:
```json
{
  "key_id": "my-signing-key-1",
  "public_key": "base64_encoded_public_key"
}
```

**Response**:
```json
{
  "message": "key_added"
}
```

**Frontend Usage**:
```typescript
// Key upload form
const uploadKey = async (keyId, publicKeyBase64) => {
  const response = await fetch('/v1/keys', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${devToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      key_id: keyId,
      public_key: publicKeyBase64
    })
  });
  
  if (response.ok) {
    refreshKeyList();
  }
};
```

### GET /v1/keys

**Purpose**: List uploaded keys with user attribution

**Auth**: `key.upload` scope (Updated 2025-08-28)

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

---

## 📋 Audit Logs

### GET /v1/audit

**Purpose**: List audit logs (admin only)

**Auth**: `admin` scope

**Query Parameters**:
- `limit`: Max 1000
- `cursor`: Pagination cursor

**Response**:
```json
[
  {
    "id": "uuid",
    "action": "policy.publish",
    "actor_id": "account_uuid",
    "timestamp": "2024-01-01T12:00:00Z",
    "status": "success",
    "resource_type": "policy",
    "resource_id": "policy_uuid",
    "metadata": {
      "app_name": "my-app",
      "version": 6
    },
    "user_id": "user_uuid"
  }
]
```

---

## 🏢 Multi-Tenancy (Invitations)

### POST /v1/invitations

**Purpose**: Invite user to organization

**Auth**: Supabase JWT (admin role)

**Request**:
```json
{
  "email": "newuser@example.com",
  "role": "member"
}
```

**Response**:
```json
{
  "id": "uuid",
  "email": "newuser@example.com",
  "role": "member",
  "invitation_token": "secure_token",
  "expires_at": "2024-01-08T00:00:00Z",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### GET /v1/invitations

**Purpose**: List pending invitations

**Auth**: Supabase JWT (admin role)

**Response**:
```json
[
  {
    "id": "uuid",
    "email": "newuser@example.com", 
    "role": "member",
    "expires_at": "2024-01-08T00:00:00Z",
    "created_at": "2024-01-01T00:00:00Z",
    "accepted_at": null
  }
]
```

### DELETE /v1/invitations/{invitation_id}

**Purpose**: Cancel invitation

**Auth**: Supabase JWT (admin role)

**Response**: `204 No Content`

### GET /public/invitations/{invitation_token}

**Purpose**: Get invitation details (public endpoint)

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

### POST /public/invitations/accept

**Purpose**: Accept invitation (public endpoint)

**Auth**: Supabase JWT (user accepting)

**Request**:
```json
{
  "invitation_token": "secure_token"
}
```

**Response**:
```json
{
  "message": "Invitation accepted successfully"
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
- `policy_validation_failed`: Invalid policy syntax

**Rate Limiting**:
- `bundle_poll_rate_limit`: Too frequent policy bundle requests
- `event_rate_limit`: Too many events ingested

**Resource Management**:
- `key_not_found`: Signing key doesn't exist
- `policy_not_found`: Policy doesn't exist
- `account_not_found`: Account doesn't exist

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

This document should provide everything needed for comprehensive frontend development against the D2 Cloud API.
