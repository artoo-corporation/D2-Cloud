from __future__ import annotations

from pydantic import BaseModel
from typing import List, Optional


class AccountMember(BaseModel):
    """A single user belonging to an account (for admin dashboard)."""

    user_id: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    display_name: Optional[str] = None
    role: str  # owner | dev
    created_at: Optional[str] = None  # ISO timestamp string


class AccountMembersResponse(BaseModel):
    """Response wrapper for the /members endpoint."""

    members: List[AccountMember]
