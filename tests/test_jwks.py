import os
from fastapi import FastAPI
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

os.environ.setdefault("FRONTEND_ORIGIN", "https://dashboard.test.com")
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "test_key")

from app.main import create_app  # noqa: E402  pylint: disable=wrong-import-position

app: FastAPI = create_app()
client = TestClient(app)

PUBLIC_JWKS_PATH = "/public/.well-known/jwks.json"


# ---------------------------------------------------------------------------
# Tests – Cache header & rate limiting
# ---------------------------------------------------------------------------


def test_public_jwks_has_cache_header():
    """JWKS endpoint should include strong Cache-Control header."""
    resp = client.get(PUBLIC_JWKS_PATH)
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "public, max-age=300, immutable"



def test_public_jwks_rate_limit():
    """The 61st request within a minute should be rate-limited (429)."""
    headers = {"X-Forwarded-For": "203.0.113.1"}
    for _ in range(60):
        ok_resp = client.get(PUBLIC_JWKS_PATH, headers=headers)
        assert ok_resp.status_code == 200

    blocked = client.get(PUBLIC_JWKS_PATH, headers=headers)
    assert blocked.status_code == 429 