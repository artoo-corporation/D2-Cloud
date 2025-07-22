"""FastAPI dependency providers for external clients."""

from __future__ import annotations

import os
from typing import AsyncGenerator



# Real client factory
from supabase import acreate_client, AsyncClient
from app import SUPABASE_URL, SUPABASE_KEY




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
        # Ensure underlying HTTPX session is closed
        await client.aclose() 