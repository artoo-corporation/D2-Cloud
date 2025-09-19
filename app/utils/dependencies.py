"""FastAPI dependency providers for external clients."""

from __future__ import annotations

import os
from typing import AsyncGenerator
import asyncio



# Real client factory
from supabase import acreate_client
from supabase import AsyncClient
from app import SUPABASE_URL, SUPABASE_KEY, APP_ENV


_cached_client: AsyncClient | None = None
_cached_loop: asyncio.AbstractEventLoop | None = None


async def _get_cached_client() -> AsyncClient:
    """Return a cached Supabase async client tied to the current event loop.

    In serverless environments (AWS Lambda, Vercel, etc.) each invocation may run
    on a fresh event loop even when the Python process is reused.  Re-using an
    `AsyncClient` that was created on a *different* loop will raise
    `RuntimeError('Event loop is closed')` when its underlying httpx connection
    attempts I/O.  We therefore cache **per-loop** rather than per-process.
    """

    global _cached_client, _cached_loop

    current_loop = asyncio.get_running_loop()

    # If no cached client or loop changed/closed → create a new one
    if (
        _cached_client is None
        or _cached_loop is None
        or _cached_loop is not current_loop
        or _cached_loop.is_closed()
    ):
        _cached_client = await acreate_client(SUPABASE_URL, SUPABASE_KEY)  # type: ignore[arg-type]
        _cached_loop = current_loop

    return _cached_client


async def get_supabase_async() -> AsyncGenerator[AsyncClient, None]:
    """FastAPI dependency that returns a **fresh** async Supabase client.

    Tests that set ``SUPABASE_URL`` to a special ``https://test.`` endpoint will
    receive a stub client that never touches the network.
    """

    # Use stub client in test mode
    if SUPABASE_URL and SUPABASE_URL.startswith("https://test."):
        from importlib import import_module

        try:
            SupabaseStub = getattr(import_module("tests.supabase_stub"), "SupabaseStub")  # type: ignore[assignment]
        except ModuleNotFoundError as exc:  # pragma: no cover – production safety guard
            raise RuntimeError(
                "Supabase test stub not found – ensure tests package contains supabase_stub.py"
            ) from exc

        client: AsyncClient = SupabaseStub()  # type: ignore[assignment]
        yield client
        return

    # Reuse one shared async client (connection pool) across requests
    client = await _get_cached_client()
    yield client 