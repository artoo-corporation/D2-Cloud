"""FastAPI dependency providers for external clients."""

from __future__ import annotations

import os
from typing import AsyncGenerator



# Real client factory
from supabase import acreate_client
from supabase import AsyncClient
from app import SUPABASE_URL, SUPABASE_KEY, APP_ENV




async def get_supabase_async() -> AsyncGenerator[AsyncClient, None]:
    """FastAPI dependency that returns a **fresh** async Supabase client.

    Tests that set SUPABASE_URL to a special ``https://test.`` endpoint will
    receive a stub client that never touches the network.
    """

    if SUPABASE_URL and SUPABASE_URL.startswith("https://test."):
        # Lazy import to avoid pulling test-only code into production builds
        from importlib import import_module

        try:
            SupabaseStub = getattr(import_module("tests.supabase_stub"), "SupabaseStub")  # type: ignore[assignment]
        except ModuleNotFoundError as exc:  # pragma: no cover – production safety guard
            raise RuntimeError("Supabase test stub not found – ensure tests package contains supabase_stub.py") from exc

        client: AsyncClient = SupabaseStub()  # type: ignore[assignment]
        yield client
        return

    client = await acreate_client(SUPABASE_URL, SUPABASE_KEY)  # type: ignore[arg-type]
    try:
        yield client
    finally:
        # Close Supabase HTTPX session if the current library exposes a coroutine
        close_coro = getattr(client, "aclose", None)
        if callable(close_coro):
            await close_coro()          # modern supabase-py (>=2.2)
        # Older versions don’t leak badly on serverless cold-starts, so we skip.


# ---------------------------------------------------------------------------
# Token-based auth helpers (opaque D2 tokens only)
# ---------------------------------------------------------------------------

from fastapi import Header, Depends, HTTPException, status
from app.utils.security_utils import verify_api_token
from app.utils.security_utils import verify_supabase_jwt
from pydantic import BaseModel


class Actor(BaseModel):
    account_id: str
    token_id: str | None = None
    user_id: str | None = None


def _dev_account_id() -> str:
    return os.getenv("D2_DEV_ACCOUNT_ID", "dev_account")


async def require_token(
    authorization: str | None = Header(None),
    supabase = Depends(get_supabase_async),
):
    """Dependency that verifies a *read* (or admin) D2 token and returns account_id."""

    if authorization is None and APP_ENV == "development":
        return _dev_account_id()

    token = (authorization or "").split(" ")[-1]
    try:
        return await verify_api_token(token, supabase, admin_only=False)
    except HTTPException:
        raise


async def require_token_admin(
    authorization: str | None = Header(None),
    supabase = Depends(get_supabase_async),
):
    if authorization is None and APP_ENV == "development":
        return _dev_account_id()
    token = (authorization or "").split(" ")[-1]
    return await verify_api_token(token, supabase, admin_only=True)


# ---------------------------------------------------------------------------
# Mixed auth – either Supabase admin JWT  OR D2 admin token
# ---------------------------------------------------------------------------


async def require_account_admin(
    authorization: str | None = Header(None),
    supabase = Depends(get_supabase_async),
) -> str:
    """Return account_id when caller is admin via either auth mechanism."""

    if authorization is None and APP_ENV == "development":
        return _dev_account_id()

    token = (authorization or "").split(" ")[-1]

    # Try Supabase admin JWT first
    try:
        return await verify_supabase_jwt(token, admin_only=True)
    except HTTPException as exc:
        if exc.status_code not in {401, 403}:
            raise

    # Fallback to opaque D2 admin token
    return await verify_api_token(token, supabase, admin_only=True)


async def require_actor_admin(
    authorization: str | None = Header(None),
    supabase = Depends(get_supabase_async),
) -> Actor:
    """Return admin actor for the account with attribution (token_id/user_id)."""

    print(f"authorization: {authorization}")
    if authorization is None and APP_ENV == "development":
        dev_id = _dev_account_id()
        return Actor(account_id=dev_id, user_id=dev_id)

    token = (authorization or "").split(" ")[-1]

    # Try Supabase admin JWT first
    try:
        account_id = await verify_supabase_jwt(token, admin_only=True)
        return Actor(account_id=account_id, user_id=account_id)
    except HTTPException as exc:
        if exc.status_code not in {401, 403}:
            raise

    # Fallback to D2 admin token with details
    details = await verify_api_token(token, supabase, return_details=True)
    return Actor(account_id=details["account_id"], token_id=details.get("token_id"))