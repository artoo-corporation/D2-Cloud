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

PRIVATE_PATH = "/"  # health-check route – no auth required
PUBLIC_JWKS_PATH = "/public/.well-known/jwks.json"


def _preflight(path: str, origin: str) -> "starlette.responses.Response":
    """Helper to craft a CORS pre-flight OPTIONS request."""
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "GET",
    }
    return client.options(path, headers=headers)


# ---------------------------------------------------------------------------
# Tests – Private API
# ---------------------------------------------------------------------------

def test_private_api_rejects_unlisted_origin():
    """An unlisted Origin must *not* receive CORS headers on private routes."""
    resp = _preflight(PRIVATE_PATH, "https://evil.example.com")
    assert "access-control-allow-origin" not in resp.headers


def test_private_api_allows_listed_origin():
    """A whitelisted Origin should receive the expected CORS headers."""
    origin = os.environ["FRONTEND_ORIGIN"]
    resp = _preflight(PRIVATE_PATH, origin)

    # Header echoes the request Origin
    assert resp.headers.get("access-control-allow-origin") == origin

    # Must include the allowed HTTP verbs
    allow_methods = resp.headers.get("access-control-allow-methods", "")
    for verb in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        assert verb in allow_methods


# ---------------------------------------------------------------------------
# Tests – Public JWKS
# ---------------------------------------------------------------------------

def test_public_jwks_allows_any_origin():
    """JWKS endpoint should always return wildcard CORS header."""
    resp = client.get(PUBLIC_JWKS_PATH, headers={"Origin": "https://random.site"})
    assert resp.headers.get("access-control-allow-origin") == "*" 