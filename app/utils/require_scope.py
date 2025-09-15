from __future__ import annotations

"""FastAPI dependency factory that asserts a bearer token covers *all* expected scopes.

Usage:

    from app.utils.require_scope import require_scope

    @router.post("/v1/policy/publish", dependencies=[Depends(require_scope("policy.write"))])
    async def publish_policy(...):
        ...

The dependency returns ``account_id`` so route handlers can keep using it.
"""

from typing import Any
import inspect
import os

from fastapi import Depends, Header, HTTPException, Request, status

from app.models import AuthContext
from app.utils.dependencies import get_supabase_async
from app.utils.security_utils import verify_api_token
from app.utils.security_utils import verify_supabase_jwt
from app.utils.database import query_one
from app import APP_ENV
from jose import jwt as jose_jwt


def _dev_account_id() -> str:
    return os.getenv("D2_DEV_ACCOUNT_ID", "dev_account")


def require_scope(*expected_scopes: str):  # noqa: D401 – factory function
    """Return a FastAPI dependency that validates the inbound token scopes."""

    expected: set[str] = set(expected_scopes)

    async def _checker(
        request: Request,
        authorization: str | None = Header(None),
        supabase=Depends(get_supabase_async),
    ) -> AuthContext:
        """Ensure token has the required scopes and return AuthContext."""

        # Development bypass: no header required in APP_ENV=development
        if authorization is None and APP_ENV == "development":
            account_id = _dev_account_id()
            # Grant broad scopes so expected ⊆ effective_scopes holds
            request.state.account_id = account_id  # type: ignore[attr-defined] - Keep for backward compatibility
            request.state.scopes = ["admin"]      # type: ignore[attr-defined] - Keep for backward compatibility
            return AuthContext(
                account_id=account_id,
                scopes=["admin"],
                user_id=account_id,  # In dev mode, user_id = account_id
            )

        token = (authorization or "").split(" ")[-1]

        # ------------------------------------------------------------------
        # Mixed auth support: Opaque D2 tokens OR Supabase JWTs (frontend)
        # ------------------------------------------------------------------
        if token.startswith("d2_"):
            # Opaque D2 tokens – use API token verifier and get details
            result: Any = verify_api_token(
                token,
                supabase,
                admin_only=False,
                return_details=True,
            )

            if inspect.isawaitable(result):
                result = await result

            # Result can be either details dict, (account_id, scopes) tuple, or bare account_id
            if isinstance(result, dict):
                account_id = result["account_id"]
                scopes = result.get("scopes", [])
                request.state.app_name = result.get("app_name")  # Store app_name from token
                user_id = result.get("user_id")
                token_id = result.get("token_id")
            elif isinstance(result, tuple):
                account_id, scopes = result
                user_id = None
                token_id = None
            else:
                account_id, scopes = result, ["admin"]  # Legacy path – full privileges
                user_id = None
                token_id = None
        else:
            # Supabase JWT – validate session and map user role -> effective scopes
            account_id = await verify_supabase_jwt(token, admin_only=False)

            # Extract Supabase auth user id from claims for attribution
            try:
                claims = jose_jwt.get_unverified_claims(token)
                user_id = claims.get("sub")
            except Exception:  # noqa: BLE001
                user_id = None

            # Look up role in our users table to determine capabilities
            role_row = None
            if user_id is not None:
                role_row = await query_one(supabase, "users", match={"user_id": user_id})

            role = (role_row or {}).get("role")
            # Base scopes derived from role
            if role in {"admin", "owner"}:
                scopes = ["admin"]
            elif role == "dev":
                scopes = ["dev"]
            elif role == "member":
                scopes = ["policy.read"]
            else:
                scopes = []
            token_id = None

        effective_scopes = set(scopes)

        # Expand dev shorthand to its component capabilities
        if "dev" in effective_scopes:
            effective_scopes |= {"policy.read", "policy.publish", "key.upload"}
        if "server" in effective_scopes:
            effective_scopes |= {"policy.read", "event.ingest"}

        # Admin scope acts as wildcard
        if "admin" not in effective_scopes and not expected.issubset(effective_scopes):
            # Log authorization failure
            try:
                from app.utils.audit import log_audit_event
                from app.models import AuditAction, AuditStatus
                await log_audit_event(
                    supabase,
                    action=AuditAction.scope_denied,
                    actor_id=account_id,
                    status=AuditStatus.denied,
                    token_id=details.get("token_id") if isinstance(details, dict) else None,
                    user_id=details.get("user_id") if isinstance(details, dict) else None,
                    metadata={
                        "required_scopes": list(expected),
                        "available_scopes": list(effective_scopes),
                        "endpoint": str(request.url) if request else None,
                    },
                )
            except Exception:
                pass  # Don't let audit logging break auth
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient_scope",
            )

        # Store context for backward compatibility with existing code
        request.state.account_id = account_id  # type: ignore[attr-defined]
        request.state.scopes = scopes          # type: ignore[attr-defined]
        request.state.token_id = token_id      # type: ignore[attr-defined]
        request.state.user_id = user_id        # type: ignore[attr-defined]
        # app_name only set for D2 tokens carrying app context

        return AuthContext(
            account_id=account_id,
            scopes=scopes,
            user_id=user_id,
            token_id=token_id,
            app_name=getattr(request.state, "app_name", None),
        )

    return _checker


def require_scope_strict(*expected_scopes: str):  # noqa: D401 – factory function
    """Return a dependency that requires explicit scopes (no admin wildcard)."""

    expected: set[str] = set(expected_scopes)

    async def _checker(
        request: Request,
        authorization: str | None = Header(None),
        supabase=Depends(get_supabase_async),
    ) -> AuthContext:
        # Development bypass
        if authorization is None and APP_ENV == "development":
            account_id = _dev_account_id()
            request.state.account_id = account_id  # type: ignore[attr-defined]
            request.state.scopes = []              # type: ignore[attr-defined]
            return AuthContext(
                account_id=account_id,
                scopes=[],
                user_id=account_id,
            )

        token = (authorization or "").split(" ")[-1]

        result: Any = verify_api_token(
            token,
            supabase,
            admin_only=False,
            return_details=True,
        )

        if inspect.isawaitable(result):
            result = await result

        if isinstance(result, dict):
            account_id = result["account_id"]
            scopes = result.get("scopes", [])
            request.state.app_name = result.get("app_name")  # Store app_name from token
        elif isinstance(result, tuple):
            account_id, scopes = result
        else:
            account_id, scopes = result, []  # strict: no implicit privileges

        expanded_scopes = set(scopes)
        if "dev" in expanded_scopes:
            expanded_scopes |= {"policy.read", "policy.publish", "key.upload", "event.ingest"}
        if "server" in expanded_scopes:
            expanded_scopes |= {"policy.read", "event.ingest"}

        if not expected.issubset(expanded_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient_scope",
            )

        request.state.account_id = account_id  # type: ignore[attr-defined]
        request.state.scopes = scopes          # type: ignore[attr-defined]
        request.state.token_id = result.get("token_id") if isinstance(result, dict) else None  # type: ignore[attr-defined]
        request.state.user_id = result.get("user_id") if isinstance(result, dict) else None    # type: ignore[attr-defined]
        request.state.app_name = result.get("app_name") if isinstance(result, dict) else None  # type: ignore[attr-defined]
        
        return AuthContext(
            account_id=account_id,
            scopes=scopes,
            user_id=result.get("user_id") if isinstance(result, dict) else None,
            token_id=result.get("token_id") if isinstance(result, dict) else None,
            app_name=result.get("app_name") if isinstance(result, dict) else None,
        )

    return _checker 