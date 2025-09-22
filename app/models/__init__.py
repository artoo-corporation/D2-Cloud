from __future__ import annotations

"""Unified models namespace – contains both API (request/response) and DB models.

All FastAPI route models, enums and helpers live directly in this package so
call-sites can simply::

    from app.models import PolicyBundleResponse, PlanTier, APITokenResponse

Legacy imports like ``from app.schemas import …`` are still supported via a thin
re-export shim in ``app/schemas/__init__.py``.
"""

from datetime import datetime
from enum import Enum
from importlib import import_module
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from pydantic import BaseModel, Field, validator

# External enums -------------------------------------------------------------
from app.models.scopes import Scope

# ---------------------------------------------------------------------------
# Authentication Models
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """Authentication context from validated API token.
    
    This replaces the old pattern of storing auth data in request.state
    and makes authentication data explicit and type-safe.
    """
    account_id: str
    scopes: list[str]
    user_id: str | None = None
    token_id: str | None = None
    app_name: str | None = None
    
    def has_scope(self, scope: str) -> bool:
        """Check if the token has a specific scope."""
        return scope in self.scopes or "admin" in self.scopes
    
    def has_any_scope(self, *scopes: str) -> bool:
        """Check if the token has any of the given scopes."""
        return any(self.has_scope(scope) for scope in scopes)
    
    def is_admin(self) -> bool:
        """Check if this is an admin token."""
        return "admin" in self.scopes
    
    def is_dev(self) -> bool:
        """Check if this is a dev token."""
        return "dev" in self.scopes
    
    def is_server(self) -> bool:
        """Check if this is a server token."""
        return "server" in self.scopes

# ---------------------------------------------------------------------------
# Enums – shareable across request / DB models
# ---------------------------------------------------------------------------

class PlanTier(str, Enum):
    trial = "trial"
    essentials = "essentials"
    pro = "pro"
    enterprise = "enterprise"

class AuditAction(str, Enum):
    """Standardized audit action types for comprehensive logging."""
    # Token operations
    token_create = "token.create"
    token_revoke = "token.revoke"
    token_rotate = "token.rotate"
    
    # Policy operations
    policy_draft = "policy.draft"
    policy_publish = "policy.publish"
    policy_update = "policy.update"
    policy_revert = "policy.revert"
    policy_revoke = "policy.revoke"
    
    # Key operations
    key_upload = "key.upload"
    key_revoke = "key.revoke"
    
    # SDK telemetry operations
    tool_invocation = "tool.invocation"
    auth_decision = "auth.decision"
    policy_poll = "policy.poll"
    policy_load = "policy.load"
    jwks_fetch = "jwks.fetch"
    context_leak = "context.leak"
    missing_policy = "missing.policy"
    sync_in_async_denied = "sync_in_async.denied"
    
    # Threading security operations (NEW 2025-08-28)
    context_submission = "context.submission"
    context_missing_actor = "context.missing_actor"
    context_leak_detected = "context.leak_detected"
    context_actor_override = "context.actor_override"
    thread_entrypoint = "thread.entrypoint"
    context_no_context_error = "context.no_context_error"

    # User operations
    user_role_update = "user.role_update"

    # Invitation operations
    invitation_create = "invitation.create"
    invitation_accept = "invitation.accept"
    invitation_cancel = "invitation.cancel"
    
    # Authentication/Authorization operations (NEW 2025-09-15)
    auth_failure = "auth.failure"
    auth_success = "auth.success"
    scope_denied = "auth.scope_denied"
    token_expired = "auth.token_expired"
    token_revoked = "auth.token_revoked"
    
    # Data access operations (NEW 2025-09-15)
    data_access = "data.access"
    sensitive_data_access = "data.sensitive_access"

class AuditStatus(str, Enum):
    """Status of audited operations."""
    success = "success"
    failure = "failure"
    denied = "denied"
    allowed = "allowed"
    
    # Threading security statuses (NEW 2025-08-28)
    context_violation = "context_violation"  # Missing actor, context leaks
    security_override = "security_override"  # Actor overrides, confused deputy
    context_hygiene = "context_hygiene"     # Context cleanup issues

# ---------------------------------------------------------------------------
# API  Pydantic models (previously in app.schemas)
# ---------------------------------------------------------------------------

class BaseResponse(BaseModel):
    # Pydantic v2 compatible: enable attribute access on ORM objects
    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"example": {"message": "OK"}},
    }

class MessageResponse(BaseResponse):
    message: str = Field(..., example="OK")

class PolicyBundleResponse(BaseModel):
    jws: Optional[str] = Field(None, description="Signed bundle (None when draft)")
    version: int
    etag: str
    bundle: Optional[Dict[str, Any]] = Field(None, description="Raw bundle content (included for drafts)")

class PolicyDraft(BaseModel):
    bundle: Dict[str, Any] = Field(..., description="Raw policy document")
    # version is now auto-generated by the backend

class PolicyPublishResponse(BaseModel):
    """Policy publish response with JWS (consistent with GET /bundle)."""
    jws: str = Field(..., description="Signed policy bundle")
    version: int = Field(..., description="Published policy version")

class PolicyVersionResponse(BaseModel):
    id: str = Field(..., description="Policy ID")
    version: int = Field(..., description="Policy version number")
    active: bool = Field(..., description="Whether this version is currently active")
    is_draft: bool = Field(..., description="Whether this version is a draft")
    published_at: datetime = Field(..., description="When this version was published")
    expires: Optional[datetime] = Field(None, description="When this policy expires")
    revocation_time: Optional[datetime] = Field(None, description="When this version was revoked")
    app_name: str = Field(..., description="App name for this policy")
    bundle: Optional[Dict[str, Any]] = Field(None, description="Policy bundle content (for comparison)")
    published_by: Optional[str] = Field(None, description="Name of user who published this version")

class PolicyRevertRequest(BaseModel):
    policy_id: str = Field(..., description="ID of the policy version to revert to")

class MeResponse(BaseModel):
    plan: str
    trial_expires: Optional[datetime] = None
    quotas: Dict[str, int] = Field(default_factory=dict, description="Plan quota limits")
    metrics_enabled: bool
    poll_seconds: int
    event_sample: Dict[str, float] = Field(default_factory=dict, description="Per-event sampling probabilities [0..1]")

class EventsBatch(BaseModel):
    events: List[Dict[str, Any]]

class APIKeyDB(BaseModel):
    token_id: str
    account_id: str
    scopes: List[str]
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]

class TokenCreateRequest(BaseModel):
    token_name: Optional[str] = Field(None, description="Friendly label for the token")
    scopes: Optional[List[Scope]] = Field(
        default_factory=lambda: [Scope.read],
        description="Token capability scopes",
    )
    app_name: Optional[str] = Field(None, description="Associate token with specific app")
    assigned_user_id: Optional[str] = Field(None, description="Assign token to specific user (defaults to current user)")

class ServerTokenRequest(BaseModel):
    """Request model for creating server tokens (not assigned to individual users)."""
    token_name: Optional[str] = Field(None, description="Friendly label for the server token")
    app_name: Optional[str] = Field(None, description="Associate token with specific app")


class TokenCreateResponse(BaseModel):
    token_id: str
    token: str  # plaintext token (returned only once)
    scopes: List[str]
    expires_at: Optional[datetime]

class APITokenResponse(BaseModel):
    token_id: str
    scopes: List[str]
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    token_name: Optional[str] = None
    created_at: Optional[datetime] = None
    created_by_name: Optional[str] = None

class TokenRevokeRequest(BaseModel):
    token_id: str = Field(..., description="Token ID to revoke")

class SignupRequest(BaseModel):
    name: str
    plan: PlanTier = Field(default=PlanTier.trial, description="Initial plan tier")

class SignupResponse(BaseModel):
    account_id: str
    admin_token: str

# Event model ---------------------------------------------------------------
from app.models.events import EventIngest  # noqa: E402

# Basic User model used by security_utils
class User(BaseModel):  # noqa: D101 – simple data carrier
    id: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class PublicKeyAddRequest(BaseModel):
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key")
    # NOTE: key_id is system-generated for security - user input not accepted

class PublicKeyResponse(BaseModel):
    key_id: str
    algo: str = Field(default="ed25519")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key")
    created_at: datetime
    revoked_at: Optional[datetime]
    user_id: Optional[str] = Field(None, description="User who uploaded this key")
    uploaded_by_name: Optional[str] = Field(None, description="Display name of user who uploaded this key")
    

class AccountCreateResponse(BaseModel):
    """Returned by the (now optional) account-bootstrap endpoint."""

    account_id: str

class TokenScopeError(BaseModel):
    """403 response for insufficient token scope."""

    error: str = Field("insufficient_scope", pattern="^insufficient_scope$")

# Add new request model for app rename


# ---------------------------------------------------------------------------
# Re-export DB row models
# ---------------------------------------------------------------------------

_db = import_module("app.models.db")

# Merge symbols into current module globals so consumers can ``import app.models as m``
_globals_update = {k: getattr(_db, k) for k in getattr(_db, "__all__", [])}
_globals_update.update(globals())
globals().update(_globals_update)

# Build __all__
__all__: list[str] = list(_globals_update.keys()) 



class PolicyBundleUpdate(BaseModel):
    """Payload for updating a policy bundle content from the editor."""
    bundle: Dict[str, Any] = Field(..., description="Updated policy bundle content")

class PolicyValidationRequest(BaseModel):
    """Request for validating a policy bundle in the editor."""
    bundle: Dict[str, Any] = Field(..., description="Policy bundle to validate")

class PolicyValidationResponse(BaseModel):
    """Response for policy validation with detailed feedback."""
    valid: bool = Field(..., description="Whether the policy is valid")
    errors: List[str] = Field(default_factory=list, description="Validation error messages")
    warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extracted metadata from bundle") 


class PolicySummary(BaseModel):
    id: str
    app_name: str
    version: int
    active: bool
    is_draft: bool
    published_at: Optional[datetime] = None
    expires: Optional[datetime] = None
    revocation_time: Optional[datetime] = None
    is_revoked: bool = False
    bundle: dict | None = None


class EventRecord(BaseModel):
    id: str
    occurred_at: datetime
    event_type: str
    payload: dict
    ingested_at: datetime
    host: str | None = None
    source_ip: str | None = None

class AuditLogRecord(BaseModel):
    id: int
    actor_id: str  # Keep for backward compatibility, maps to account_id
    user_id: str | None = None
    user_name: str | None = Field(None, description="Display name of user who performed the action")
    token_id: str | None = None
    action: str
    key_id: str | None = None
    version: int | None = None
    status: str | None = Field(None, description="Operation status")
    resource_type: str | None = Field(None, description="Type of resource acted upon")
    resource_id: str | None = Field(None, description="ID of the specific resource")
    metadata: dict | None = Field(None, description="Additional structured data")
    created_at: datetime


class JWKSConfigurationResponse(BaseModel):
    """Current JWKS configuration for an account."""
    current_key_id: str = Field(..., description="Current active key ID") 
    algorithm: str = Field(..., description="Key algorithm (e.g., 'RS256')")
    jwks_url: str = Field(..., description="Public JWKS URL for this account")
    public_key: Dict[str, Any] = Field(..., description="Current public key JWK")
    rotation_enabled: bool = Field(False, description="Whether automatic rotation is enabled")
    rotation_interval_days: int = Field(90, description="Rotation interval in days")


class JWKSRotationResponse(BaseModel):
    """Response from JWKS key rotation."""
    message: str = Field(..., description="Success message")
    new_key_id: str = Field(..., description="ID of the newly created key")
    algorithm: str = Field(..., description="Algorithm of the new key")
    rotation_completed_at: datetime = Field(..., description="When the rotation was completed")
    old_keys_expire_at: datetime = Field(..., description="When old keys will be cleaned up")


class JWKSKeyHistoryItem(BaseModel):
    """Individual key in JWKS history."""
    key_id: str = Field(..., description="Key ID")
    algorithm: str = Field(..., description="Key algorithm")
    created_at: datetime = Field(..., description="When this key was created")
    expires_at: Optional[datetime] = Field(None, description="When this key expires (if set)")
    is_active: bool = Field(..., description="Whether this is the currently active key")
    public_key: Dict[str, Any] = Field(..., description="Public key JWK")


class JWKSHistoryResponse(BaseModel):
    """Complete JWKS rotation history for an account."""
    keys: List[JWKSKeyHistoryItem] = Field(..., description="List of all keys, newest first")
    total_rotations: int = Field(..., description="Total number of rotations performed")
    overlap_days: int = Field(7, description="Number of days keys overlap before cleanup")


# ---------------------------------------------------------------------------
# Metrics response models (Supabase-backed, aggregation in app layer)
# ---------------------------------------------------------------------------


class MetricsSummaryResponse(BaseModel):
    start: datetime
    end: datetime
    total_authorizations: int
    total_denied: int
    deny_rate: float
    unique_tools: int
    unique_resources: int
    avg_decision_ms: float | None = None
    avg_ingest_lag_ms: float | None = None


class TimeseriesPoint(BaseModel):
    ts: datetime
    allowed: int
    denied: int
    total: int


class MetricsTimeseriesResponse(BaseModel):
    bucket: str  # "hour" | "day"
    start: datetime
    end: datetime
    points: List[TimeseriesPoint]


class TopItem(BaseModel):
    key: str
    count: int


class MetricsTopResponse(BaseModel):
    dimension: str  # "tools" | "resources" | "event_type"
    start: datetime
    end: datetime
    total: int
    items: List[TopItem]


# ---------------------------------------------------------------------------
# Lead generation models
# ---------------------------------------------------------------------------

class LeadRequest(BaseModel):
    email: str = Field(..., description="Email address of the lead")
    company_name: str = Field(..., description="Company name")
    ai_agents_description: str = Field(..., description="Description of AI agents problems/use case")

    @validator('email')
    def validate_email(cls, v):
        if not v or '@' not in v:
            raise ValueError('Valid email address required')
        return v.strip().lower()
    
    @validator('company_name')
    def validate_company_name(cls, v):
        if not v or len(v.strip()) < 2:
            raise ValueError('Company name must be at least 2 characters')
        return v.strip()
    
    @validator('ai_agents_description')
    def validate_description(cls, v):
        if not v or len(v.strip()) < 10:
            raise ValueError('Description must be at least 10 characters')
        return v.strip()


class LeadResponse(BaseModel):
    id: str
    email: str
    company_name: str
    ai_agents_description: str
    created_at: datetime
    updated_at: datetime