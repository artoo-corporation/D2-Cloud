from __future__ import annotations

"""Persistence / Supabase row models (moved from previous app.models package)."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, constr

__all__ = [
    "APIToken",
    "DeveloperKey",
    "PolicyRevision",
]


class APIToken(BaseModel):
    """Row in `api_tokens`."""

    id: Optional[str] = Field(None, description="Primary key (UUID, db-generated)")
    org_id: str = Field(..., description="Tenant / organisation ID")
    kid: Optional[str] = Field(None, description="Optional Key ID if JWT based")
    token_sha256: str = Field(..., description="bcrypt-salted SHA-256 hash")
    scopes: List[str] = Field(..., min_items=1, description="Capability scopes")
    created_by: Optional[str] = Field(None, description="Actor that issued the token")
    created_at: Optional[datetime] = Field(None, description="Server timestamp")
    expires_at: Optional[datetime] = Field(None, description="Absolute expiry")
    revoked_at: Optional[datetime] = Field(None, description="Soft-delete marker")


class DeveloperKey(BaseModel):
    """Row in `developer_keys` – Ed25519 public keys uploaded by developers."""

    kid: constr(strip_whitespace=True, min_length=1)  # type: ignore[valid-type]
    org_id: str
    key_fingerprint: constr(strip_whitespace=True, min_length=64, max_length=64)  # SHA-256 hex
    public_key: str = Field(..., description="Base64 encoded public key bytes")
    uploaded_by: Optional[str] = Field(None, description="Actor that uploaded the key")
    created_at: Optional[datetime] = None


class PolicyRevision(BaseModel):
    """Immutable audit record for every successful policy publish."""

    id: Optional[int] = Field(None, description="Bigserial primary key (db-generated)")
    org_id: str
    actor_sub: Optional[str] = None
    git_sha: constr(strip_whitespace=True, min_length=40, max_length=40)  # type: ignore[valid-type]
    key_fp: constr(strip_whitespace=True, min_length=64, max_length=64)
    source_ip: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None 