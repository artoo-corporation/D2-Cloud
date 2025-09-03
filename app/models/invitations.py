"""Invitation system models for multi-tenant account management."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, validator


class InvitationRole(str, Enum):
    """Roles that can be assigned to invited users."""
    owner = "owner"      # Full admin access (cannot be invited, only original creator)
    admin = "admin"      # Can manage users, tokens, policies
    member = "member"    # Can view and use tokens/policies


class InvitationCreateRequest(BaseModel):
    """Request model for creating a new invitation."""
    email: str = Field(..., description="Email address to invite")
    role: InvitationRole = Field(default=InvitationRole.member, description="Role to assign")
    
    @validator("email")
    def validate_email(cls, v):
        """Basic email validation."""
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v.lower().strip()


class InvitationResponse(BaseModel):
    """Response model for invitation operations."""
    id: str = Field(..., description="Invitation ID")
    email: str = Field(..., description="Invited email address")
    role: str = Field(..., description="Assigned role")
    invited_by_user_id: str = Field(..., description="Who sent the invitation")
    expires_at: datetime = Field(..., description="When invitation expires")
    accepted_at: Optional[datetime] = Field(None, description="When invitation was accepted")
    created_at: datetime = Field(..., description="When invitation was created")


class InvitationAcceptRequest(BaseModel):
    """Request model for accepting an invitation."""
    invitation_token: str = Field(..., description="Secure invitation token from email link")


class InvitationListResponse(BaseModel):
    """Response model for listing account invitations."""
    invitations: list[InvitationResponse] = Field(..., description="List of invitations")


class PendingInvitationInfo(BaseModel):
    """Information about a pending invitation (for accept page)."""
    account_name: str = Field(..., description="Name of the account being invited to")
    invited_by_name: str = Field(..., description="Name of the person who sent the invitation")
    role: str = Field(..., description="Role being offered")
    expires_at: datetime = Field(..., description="When invitation expires")
