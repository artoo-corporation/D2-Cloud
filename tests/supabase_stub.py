from __future__ import annotations

"""No-op Supabase async client used by the test-suite.

Provides just enough surface area for helpers in ``app.utils.database`` to work
without hitting the real Supabase API.
"""

from typing import Any, List

__all__ = ["SupabaseStub"]


class _DummyResponse:  # noqa: D101
    data: List[Any] = []


class SupabaseStub:  # noqa: D101
    """Tiny stub replacing the real Supabase AsyncClient in tests."""

    # Query builder ------------------------------------------------------
    def table(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def select(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def insert(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def update(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def limit(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def order(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    # Filter helpers -----------------------------------------------------
    def in_(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def gt(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def lt(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def gte(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def lte(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def like(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def ilike(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def neq(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def eq(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":
        return self

    def is_(self, *_args: Any, **_kwargs: Any) -> "SupabaseStub":  # noqa: D401
        return self

    # Execute -------------------------------------------------------------
    async def execute(self, *_args: Any, **_kwargs: Any) -> _DummyResponse:  # noqa: D401
        return _DummyResponse() 