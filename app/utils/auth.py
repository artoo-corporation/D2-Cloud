"""Centralized authentication system for D2 Cloud API.

This module provides a single, consistent auth interface that all routes can use.
It handles both D2 API tokens and Supabase JWTs with proper scope enforcement.
"""

from __future__ import annotations

import inspect
import os
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from app import APP_ENV
from app.models import AuthContext
from app.utils.database import query_one
from app.utils.dependencies import get_supabase_async
from app.utils.security_utils import verify_api_token, verify_supabase_jwt


def _dev_account_id() -> str:
    return os.getenv("D2_DEV_ACCOUNT_ID", "dev_account")


class AuthRequirement:
    """Represents an authentication requirement for a route."""
    
    def __init__(
        self,
        scopes: list[str] | None = None,
        *,
        require_privileged: bool = False,
        strict: bool = False,
        require_user: bool = False,
    ):
        """
        Args:
            scopes: Required scopes (e.g., ["policy.read", "metrics.read"])
            require_privileged: Require owner/dev role
            strict: No wildcard for privileged users - must have explicit scopes
            require_user: Must be a Supabase JWT (has user_id), not just API token
        """
        self.scopes = set(scopes or [])
        self.require_privileged = require_privileged
        self.strict = strict
        self.require_user = require_user
        
    
async def _authenticate_token(
    token: str,
    supabase,
    requirement: AuthRequirement,
) -> AuthContext:
    
    user_id: str | None = None
    token_id: str | None = None
    app_name: str | None = None
    is_privileged = False
    role: str | None = None

    if token.startswith("d2_"):
        # D2 API Token
        if requirement.require_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="supabase_session_required"
            )
            
        result: Any = verify_api_token(
            token,
            supabase,
            admin_only=requirement.require_privileged,
            return_details=True,
        )

        if inspect.isawaitable(result):
            result = await result

        if isinstance(result, dict):
            account_id = result["account_id"]
            scopes = result.get("scopes", [])
            user_id = result.get("user_id")
            token_id = result.get("token_id")
            app_name = result.get("app_name")
        elif isinstance(result, tuple):
            account_id, scopes = result
        else:
            account_id = result
            # Privilege for API tokens is already enforced by verify_api_token
            # when admin_only=True is passed.
            scopes = []

    else:
        # Supabase JWT - validate JWT and get user_id from claims
        jwt_user_id, claims = await verify_supabase_jwt(token, admin_only=False, return_claims=True)
        
        # Extract user ID and role from the already-parsed JWT claims
        user_id = claims.get("sub")
        role = (claims.get("role") or "authenticated").lower()
        
        # CRITICAL: For OAuth users, we need to look up their account_id from the users table
        # because invited users belong to the inviter's account, not their own user_id
        try:
            user_row = await query_one(
                supabase,
                "users", 
                match={"user_id": user_id},
                select_fields="account_id,role"
            )
            
            if user_row:
                # Use the account_id from the users table (this is the key fix!)
                account_id = user_row.get("account_id")
                db_role = user_row.get("role")
                if db_role:
                    role = db_role
            else:
                # User not found in users table - this shouldn't happen for valid users
                # DEBUG: Include user_id in error for debugging
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, 
                    detail=f"user_not_found_in_system_user_id_{user_id}"
                )
                
        except HTTPException:
            raise
        except Exception as e:
            # Database lookup failed - be conservative and deny access
            # DEBUG: Include the actual error for debugging
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
                detail=f"database_lookup_failed_{str(e)}"
            )
        
        # Additional privilege check for require_privileged endpoints
        if requirement.require_privileged and role not in {"owner", "dev"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="owner_or_dev_required"
            )
        
        # Determine privilege from role
        if role in {"owner", "dev"}:
            is_privileged = True
            scopes = []  # Scopes are expanded below based on privilege
        elif role == "authenticated":
            scopes = ["policy.read"]  # Basic read access for authenticated users
        else:
            scopes = []

    # Final privilege check
    if requirement.require_privileged and not is_privileged:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="owner_or_dev_required",
        )

    # Expand shorthand scopes
    effective_scopes = set(scopes)
    if is_privileged:
        effective_scopes |= {
            "policy.read", "policy.publish", "policy.revoke", "policy.revert",
            "key.upload", "event.ingest", "metrics.read"
        }
    if "dev" in scopes: # For API tokens with "dev" scope
        effective_scopes |= {"policy.read", "policy.publish", "key.upload", "event.ingest"}
    if "server" in scopes: # For API tokens with "server" scope
        effective_scopes |= {"policy.read", "event.ingest"}

    # Check scope requirements
    if requirement.scopes:
        # Wildcard for privileged users unless in strict mode
        if is_privileged and not requirement.strict:
            pass  # Privileged users bypass scope checks unless strict
        else:
            if not requirement.scopes.issubset(effective_scopes):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="insufficient_scope",
                )

    # Ensure account_id is not None
    if not account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"account_id_is_none_for_user_{user_id}"
        )
    
    return AuthContext(
        account_id=account_id,
        scopes=list(scopes),
        is_privileged=is_privileged,
        user_id=user_id,
        token_id=token_id,
        app_name=app_name,
    )


def require_auth(
    scopes: list[str] | str | None = None,
    *,
    require_privileged: bool = False,
    strict: bool = False,
    require_user: bool = False,
):
    """
    Centralized auth dependency factory.
    
    Examples:
        # Basic scope check
        auth: AuthContext = Depends(require_auth("policy.read"))
        
        # Multiple scopes
        auth: AuthContext = Depends(require_auth(["policy.read", "metrics.read"]))
        
        # Owner/dev only (any owner/dev mechanism)
        auth: AuthContext = Depends(require_auth(require_privileged=True))
        
        # Strict scope (no wildcard for privileged users)
        auth: AuthContext = Depends(require_auth("metrics.read", strict=True))
        
        # Must be Supabase user (for token creation, etc.)
        auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True))
    """
    
    # Normalize scopes to list
    if isinstance(scopes, str):
        scopes = [scopes]
    
    requirement = AuthRequirement(
        scopes=scopes,
        require_privileged=require_privileged,
        strict=strict,
        require_user=require_user,
    )
    
    async def _auth_dependency(
        request: Request,
        authorization: str | None = Header(None),
        supabase=Depends(get_supabase_async),
    ) -> AuthContext:
        # Development bypass
        if authorization is None and APP_ENV == "development":
            account_id = _dev_account_id()
            dev_scopes = ["admin"] if not strict else (scopes or [])  # Dev bypass
            
            # Store for backward compatibility
            request.state.account_id = account_id
            request.state.scopes = dev_scopes
            request.state.user_id = account_id
            request.state.token_id = None
            
            return AuthContext(
                account_id=account_id,
                scopes=dev_scopes,
                user_id=account_id,
                token_id=None,
            )

        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing_authorization",
            )

        token = authorization.split(" ")[-1]
        auth_context = await _authenticate_token(token, supabase, requirement)
        
        # Store for backward compatibility with existing routes
        request.state.account_id = auth_context.account_id
        request.state.scopes = auth_context.scopes
        request.state.user_id = auth_context.user_id
        request.state.token_id = auth_context.token_id
        if auth_context.app_name:
            request.state.app_name = auth_context.app_name
        
        return auth_context
    
    return _auth_dependency


# Convenience aliases for common patterns
def require_privileged_user() -> Any:
    """Require owner/dev role (any auth mechanism)."""
    return require_auth(require_privileged=True)


def require_privileged_session() -> Any:
    """Require owner/dev role via Supabase JWT (for user attribution)."""
    return require_auth(require_privileged=True, require_user=True)


def require_scope_any(*scopes: str) -> Any:
    """Require any of the given scopes (privileged user wildcard applies)."""
    return require_auth(list(scopes))


def require_scope_strict(*scopes: str) -> Any:
    """Require explicit scopes (no privileged user wildcard)."""
    return require_auth(list(scopes), strict=True)
