from __future__ import annotations

"""Pytest fixtures for FastAPI integration tests.

All external services (Supabase, HTTP requests, bcrypt) are stubbed/mocked so
we can exercise the request pipeline end-to-end without network or database
round-trips.
"""

import os
import sys
from pathlib import Path
import secrets
from hashlib import sha256
from typing import Any, Dict

import bcrypt
import pytest
from fastapi import FastAPI, HTTPException, status
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# Runtime env for the application
# ---------------------------------------------------------------------------

os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "test_key")
os.environ.setdefault("FRONTEND_ORIGIN", "https://dashboard.test")

# Ensure project root on PYTHONPATH so `import app` works when pytest is run
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Boot the app once
from app.main import create_app, limiter  # noqa: E402, WPS433

app: FastAPI = create_app()
client = TestClient(app)

# ---------------------------------------------------------------------------
# In-process token store used to simulate `api_tokens` table
# ---------------------------------------------------------------------------

_token_store: Dict[str, Dict[str, Any]] = {}


def _hash(token: str) -> str:
    """Return bcrypt(s ha256(token))."""

    digest = sha256(token.encode()).digest()
    return bcrypt.hashpw(digest, bcrypt.gensalt()).decode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture()
def api_client() -> TestClient:  # noqa: D401 – simple alias
    return client


@pytest.fixture()
def patch_verify(monkeypatch):  # noqa: D401
    """Patch verify_api_token to use the in-memory store."""

    from app.utils import security_utils as sec

    async def _verify(token: str, _supabase, admin_only: bool = False, *, return_scopes=False):  # noqa: ANN001
        row = _token_store.get(token)
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        if admin_only and "admin" not in row["scopes"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        return (row["account_id"], row["scopes"]) if return_scopes else row["account_id"]

    # Patch all call-sites that imported `verify_api_token` at import-time so they
    # now pick up our in-memory implementation.  We modify the attribute on the
    # *importing* modules as well as on the canonical `security_utils` module.

    from app.utils import dependencies as deps  # noqa: WPS433
    from app.utils import require_scope as scope_mod  # noqa: WPS433

    monkeypatch.setattr(sec, "verify_api_token", _verify, raising=True)
    monkeypatch.setattr(deps, "verify_api_token", _verify, raising=True)
    monkeypatch.setattr(scope_mod, "verify_api_token", _verify, raising=True)

    # -------------------------------------------------------------------
    # Supabase JWT verification – in tests we *always* fall back to the D2
    # token path unless the test overrides it explicitly.  We therefore stub
    # the helper to raise 401 so `require_account_admin` continues to the
    # fallback branch.  The stub keeps the *new* call-signature used by the
    # dependency layer (token: str, admin_only: bool = False).
    # -------------------------------------------------------------------

    async def _verify_jwt_stub(token: str, admin_only: bool = False):  # noqa: ANN001, D401
        from fastapi import HTTPException, status  # local import to avoid leak

        # Tests that need a positive JWT path will monkey-patch over this stub.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    monkeypatch.setattr(sec, "verify_supabase_jwt", _verify_jwt_stub, raising=True)
    monkeypatch.setattr(deps, "verify_supabase_jwt", _verify_jwt_stub, raising=True)
    yield


# ---------------------------------------------------------------------------
# Helper: create token rows in the stub table
# ---------------------------------------------------------------------------

def make_token(account_id: str, scopes: list[str]):  # noqa: D401
    raw = "d2_" + secrets.token_urlsafe(8)
    _token_store[raw] = {
        "token_id": secrets.token_hex(4),
        "account_id": account_id,
        "scopes": scopes,
        "token_sha256": _hash(raw),
    }
    return raw 