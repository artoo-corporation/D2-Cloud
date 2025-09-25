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
        admin_only: bool = False,
        strict: bool = False,
        require_user: bool = False,
    ):
        """
        Args:
            scopes: Required scopes (e.g., ["policy.read", "metrics.read"])
            admin_only: Require admin role (shorthand for admin scope)
            strict: No admin wildcard - must have explicit scopes
            require_user: Must be a Supabase JWT (has user_id), not just API token
        """
        self.scopes = set(scopes or [])
        self.admin_only = admin_only
        self.strict = strict
        self.require_user = require_user
        
        if admin_only:
            self.scopes.add("admin")


async def _authenticate_token(
    token: str,
    supabase,
    requirement: AuthRequirement,
) -> AuthContext:
    """Core authentication logic - handles both D2 tokens and Supabase JWTs."""
    
    user_id = None
    token_id = None
    app_name = None
    
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
            admin_only=requirement.admin_only,
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
            if requirement.strict:
                # For strict mode, admin tokens get explicit scopes
                scopes = [
                    "policy.read", "policy.publish", "policy.revoke", "policy.revert",
                    "key.upload", "event.ingest", "metrics.read"
                ]
            else:
                scopes = ["admin"]  # Wildcard
    else:
        # Supabase JWT - get account_id and claims in one call
        account_id, claims = await verify_supabase_jwt(token, admin_only=requirement.admin_only, return_claims=True)

        # Extract user ID and role from the already-parsed JWT claims
        user_id = claims.get("sub")
        role = claims.get("role") or claims.get("user_metadata", {}).get("role")
        
        # Use database role if it was fetched by verify_supabase_jwt
        db_role = claims.get("db_role")
        if db_role:
            role = db_role
        
        # For admin-only endpoints, look up user's actual role in database
        # because JWT only contains "authenticated", not the D2 system role
        if requirement.admin_only and role == "authenticated":
            from app.utils.database import query_one
            
            try:
                user_row = await query_one(
                    supabase,
                    "users", 
                    match={"user_id": user_id},
                    select_fields="role"
                )
                
                if user_row and user_row.get("role") in {"admin", "owner"}:
                    role = user_row.get("role")  # Use database role
                else:
                    # User not found or not admin - deny access
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN, 
                        detail="admin_required"
                    )
                    
            except HTTPException:
                raise
            except Exception as e:
                # Database lookup failed - be conservative and deny access
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
                    detail="database_lookup_failed"
                )
        
        # Map role to scopes
        if role in {"admin", "owner", "authenticated"}:
            if requirement.strict:
                # Explicit scopes for strict mode
                scopes = [
                    "policy.read", "policy.publish", "policy.revoke", "policy.revert",
                    "key.upload", "event.ingest", "metrics.read"
                ]
            else:
                scopes = ["admin"]  # Wildcard
        elif role == "dev":
            scopes = ["dev"]
        elif role == "member":
            scopes = ["policy.read"]
        elif role == "authenticated":
            scopes = ["policy.read"]  # Basic read access for authenticated users
        else:
            scopes = []

    # Expand shorthand scopes
    effective_scopes = set(scopes)
    if "admin" in effective_scopes:
        effective_scopes |= {
            "policy.read", "policy.publish", "policy.revoke", "policy.revert",
            "key.upload", "event.ingest", "metrics.read"
        }
    if "dev" in effective_scopes:
        effective_scopes |= {"policy.read", "policy.publish", "key.upload", "event.ingest"}
    if "server" in effective_scopes:
        effective_scopes |= {"policy.read", "event.ingest"}

    # Check scope requirements
    if requirement.scopes:
        if requirement.strict or "admin" not in effective_scopes:
            if not requirement.scopes.issubset(effective_scopes):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="insufficient_scope",
                )

    return AuthContext(
        account_id=account_id,
        scopes=list(scopes),
        user_id=user_id,
        token_id=token_id,
        app_name=app_name,
    )


def require_auth(
    scopes: list[str] | str | None = None,
    *,
    admin_only: bool = False,
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
        
        # Admin only (any admin mechanism)
        auth: AuthContext = Depends(require_auth(admin_only=True))
        
        # Strict scope (no admin wildcard)
        auth: AuthContext = Depends(require_auth("metrics.read", strict=True))
        
        # Must be Supabase user (for token creation, etc.)
        auth: AuthContext = Depends(require_auth(admin_only=True, require_user=True))
    """
    
    # Normalize scopes to list
    if isinstance(scopes, str):
        scopes = [scopes]
    
    requirement = AuthRequirement(
        scopes=scopes,
        admin_only=admin_only,
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
            dev_scopes = ["admin"] if not strict else (scopes or [])
            
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
def require_admin() -> Any:
    """Require admin role (any auth mechanism)."""
    return require_auth(admin_only=True)


def require_user_admin() -> Any:
    """Require admin role via Supabase JWT (for user attribution)."""
    return require_auth(admin_only=True, require_user=True)


def require_scope_any(*scopes: str) -> Any:
    """Require any of the given scopes (admin wildcard applies)."""
    return require_auth(list(scopes))


def require_scope_strict(*scopes: str) -> Any:
    """Require explicit scopes (no admin wildcard)."""
    return require_auth(list(scopes), strict=True)
