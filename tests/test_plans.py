import time
import pytest
from app.utils.plans import enforce_event_limits, enforce_bundle_poll
from tests.supabase_stub import SupabaseStub
from fastapi import HTTPException, status

ACCOUNT = "acct_test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class DummySupabase(SupabaseStub):
    """Supabase stub where the `table().select().execute()` chain yields data.

    We only need the minimal surface for query_one in plans helpers which
    ultimately calls `supabase.table(...).select(...).eq(...).execute()`.
    """

    _data: list[dict] = []

    def __init__(self, row: dict | None = None):
        self._data = [row] if row else []

    async def execute(self, *_, **__):  # noqa: D401 – stub method
        class _Resp:  # minimal response object
            def __init__(self, data):
                self.data = data

        return _Resp(self._data)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_size_cap(monkeypatch):
    """enforce_event_limits should raise 413 when payload size exceeds plan cap."""

    # Plan row with 100-byte batch cap
    supabase = DummySupabase({
        "name": "free",
        "max_batch_bytes": 100,
    })

    # Patch query_one to return our dummy row regardless of args
    async def _query_one(_supabase, *_a, **_k):
        return supabase._data[0]

    monkeypatch.setattr("app.utils.database.query_one", _query_one)

    big_payload = 101  # 1 byte over limit

    with pytest.raises(HTTPException) as exc:
        await enforce_event_limits(supabase, ACCOUNT, "free", big_payload)

    assert exc.value.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.asyncio
async def test_event_interval_throttle(monkeypatch):
    """Second call within ingest_interval should raise 429."""

    supabase = DummySupabase({
        "name": "essentials",
        "ingest_interval": 60,
    })

    async def _query_one(_supabase, *_a, **_k):
        return supabase._data[0]

    monkeypatch.setattr("app.utils.database.query_one", _query_one)

    # First call OK
    await enforce_event_limits(supabase, ACCOUNT, "essentials", 10)

    # Freeze time to simulate immediate retry
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)

    with pytest.raises(HTTPException) as exc:
        await enforce_event_limits(supabase, ACCOUNT, "essentials", 10)

    assert exc.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in exc.value.headers


def test_bundle_poll_throttle(monkeypatch):
    enforce_bundle_poll(ACCOUNT, 60)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    try:
        enforce_bundle_poll(ACCOUNT, 60)
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    else:
        assert False


def test_bundle_poll_dev_token_no_throttle(monkeypatch):
    """Dev tokens should bypass polling restrictions for local development."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    # Should NOT raise exception even with immediate retry
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])
    # Multiple rapid calls should work
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])


def test_bundle_poll_admin_token_no_throttle(monkeypatch):
    """Admin tokens should bypass polling restrictions."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["admin"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    # Should NOT raise exception even with immediate retry
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["admin"])


def test_bundle_poll_server_token_throttle(monkeypatch):
    """Server tokens should respect polling restrictions."""
    import pytest

    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["server"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)

    with pytest.raises(HTTPException) as exc:
        enforce_bundle_poll(ACCOUNT, 60, token_scopes=["server"])
    assert exc.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS


def test_bundle_poll_mixed_scopes_dev_wins(monkeypatch):
    """If token has both dev and server scopes, dev behavior should win."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev", "server"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    # Should NOT raise exception because dev scope is present
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev", "server"]) 