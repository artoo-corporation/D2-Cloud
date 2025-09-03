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
from app import APP_ENV


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

        # `verify_api_token` is *async* in production, but some unit tests patch
        # it with a synchronous stub.  We therefore support both calling
        # conventions.

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
        elif isinstance(result, tuple):
            account_id, scopes = result
        else:
            account_id, scopes = result, ["admin"]  # Legacy path – full privileges

        effective_scopes = set(scopes)

        # Expand dev shorthand to its component capabilities
        if "dev" in effective_scopes:
            effective_scopes |= {"policy.read", "policy.publish", "key.upload"}
        if "server" in effective_scopes:
            effective_scopes |= {"policy.read", "event.ingest"}

        # Admin scope acts as wildcard
        if "admin" not in effective_scopes and not expected.issubset(effective_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient_scope",
            )

        # Store context for backward compatibility with existing code
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