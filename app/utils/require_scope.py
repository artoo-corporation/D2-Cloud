from __future__ import annotations

"""FastAPI dependency factory that asserts a bearer token covers *all* expected scopes.

Usage:

    from app.utils.require_scope import require_scope

    @router.post("/v1/policy/publish", dependencies=[Depends(require_scope("policy.write"))])
    async def publish_policy(...):
        ...

The dependency returns ``account_id`` so route handlers can keep using it.
"""

from typing import List, Any
import inspect

from fastapi import Depends, Header, HTTPException, Request, status

from app.utils.dependencies import get_supabase_async
from app.utils.security_utils import verify_api_token


def require_scope(*expected_scopes: str):  # noqa: D401 – factory function
    """Return a FastAPI dependency that validates the inbound token scopes."""

    expected: set[str] = set(expected_scopes)

    async def _checker(
        request: Request,
        authorization: str = Header(...),
        supabase=Depends(get_supabase_async),
    ) -> str:
        """Ensure token has the required scopes and return account_id."""

        token = authorization.split(" ")[-1]

        # `verify_api_token` is *async* in production, but some unit tests patch
        # it with a synchronous stub.  We therefore support both calling
        # conventions.

        result: Any = verify_api_token(
            token,
            supabase,
            admin_only=False,
            return_scopes=True,
        )

        if inspect.isawaitable(result):
            result = await result

        # Result can be either (account_id, scopes) tuple or bare account_id
        if isinstance(result, tuple):
            account_id, scopes = result
        else:
            account_id, scopes = result, ["admin"]  # Legacy path – full privileges

        effective_scopes = set(scopes)

        # Admin scope acts as wildcard
        if "admin" not in effective_scopes and not expected.issubset(effective_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient_scope",
            )

        # Store helpful context for downstream handlers / middleware
        request.state.account_id = account_id  # type: ignore[attr-defined]
        request.state.scopes = scopes          # type: ignore[attr-defined]

        return account_id

    return _checker 