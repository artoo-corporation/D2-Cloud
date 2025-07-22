from __future__ import annotations

"""Central Pydantic models for request/response bodies.

This file was previously a standalone module (``schemas.py``). It now lives as
``app/schemas/__init__.py`` so we can add extra sub-modules (e.g. ``events``)
without breaking existing ``from app.schemas import ...`` imports.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Existing models (moved verbatim from the old schemas.py)
# ---------------------------------------------------------------------------


class BaseResponse(BaseModel):
    class Config:
        orm_mode = True
        json_schema_extra = {"example": {"message": "OK"}}


class MessageResponse(BaseResponse):
    message: str = Field(..., example="OK")


class PolicyBundleResponse(BaseModel):
    jws: str
    version: int
    etag: str


class PolicyDraft(BaseModel):
    version: int = Field(..., example=1)
    bundle: Dict[str, Any] = Field(..., description="Raw policy document")


class PolicyPublishResponse(BaseModel):
    jws: str
    version: int


class MeResponse(BaseModel):
    plan: str
    metrics_enabled: bool
    poll_seconds: int


class EventsBatch(BaseModel):
    events: List[Dict[str, Any]]


class APIKeyDB(BaseModel):
    token_id: str
    account_id: str
    scopes: List[str]
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]


class TokenCreateRequest(BaseModel):
    name: Optional[str] = Field(None, description="Friendly label for the token")
    scopes: Optional[List[str]] = Field(default_factory=lambda: ["read"], description="Token scopes")
    expires_at: Optional[datetime] = Field(None, description="Expiry timestamp (UTC)")


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


# ---------------------------------------------------------------------------
# Re-export new sub-module models so legacy imports keep working.
# ---------------------------------------------------------------------------

from .events import EventIngest  # noqa: E402, F401

__all__ = [
    # Base
    "MessageResponse",
    "PolicyBundleResponse",
    "PolicyDraft",
    "PolicyPublishResponse",
    "MeResponse",
    "EventsBatch",
    "APIKeyDB",
    "TokenCreateRequest",
    "TokenCreateResponse",
    "APITokenResponse",
    # New
    "EventIngest",
] 