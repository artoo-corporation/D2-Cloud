import pytest
from tests.conftest import make_token, api_client, patch_verify
import json
from fastapi import status


ACCOUNT = "acct_test"
BASE = f"/v1/accounts/{ACCOUNT}/tokens"


# ---------------------------------------------------------------------------
# DB stubs – track `api_tokens` rows in process so routes reflect real state
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def patch_db_tokens(monkeypatch):  # noqa: D401
    """Stub Supabase CRUD helpers for the *api_tokens* table only."""

    from app.utils import database as db_mod  # noqa: WPS433
    from tests import conftest as _cft  # access the shared _token_store

    # In-memory table for tokens inserted via API --------------------------------
    _tokens_table: list[dict] = []

    # Generic noop response --------------------------------------------------
    class _Resp:  # noqa: D101, WPS306
        def __init__(self, rows=None):
            self.data = rows or []

    def _noop_resp(rows=None):  # helper to reduce boilerplate
        return _Resp(rows)

    # INSERT ----------------------------------------------------------------
    async def _insert(_sp, table_name, values, **kw):  # noqa: ANN001
        if table_name != "api_tokens":
            return _noop_resp()

        # Persist in mini table for listing
        _tokens_table.append({
            "token_id": values["token_id"],
            "scopes": values["scopes"],
            "expires_at": values.get("expires_at"),
            "revoked_at": values.get("revoked_at"),
        })
        return _noop_resp()

    # QUERY -----------------------------------------------------------------
    async def _query(_sp, table_name, filters=None, select_fields="*", **kw):  # noqa: ANN001
        if table_name != "api_tokens":
            return _noop_resp()

        # _token_count() asks for just the `id` column – respond with empty list
        # when probing so the bootstrap path still works.
        if select_fields == "id":
            return _noop_resp([])

        # merge rows from tokens_table (API-created) and _token_store (make_token)
        rows = _tokens_table.copy()
        rows.extend([
            {
                "token_id": r["token_id"],
                "scopes": r["scopes"],
                "expires_at": None,
                "revoked_at": r.get("revoked_at"),
            }
            for r in _cft._token_store.values()
        ])
        return _noop_resp(rows)

    # UPDATE ----------------------------------------------------------------
    async def _update(_sp, table_name, update_values=None, filters=None, **kw):  # noqa: ANN001
        if table_name != "api_tokens":
            return _noop_resp()
        token_id = (filters or {}).get("token_id")
        for r in _tokens_table:
            if r["token_id"] == token_id:
                r.update(update_values or {})
        return _noop_resp()

    monkeypatch.setattr(db_mod, "insert_data", _insert, raising=True)
    monkeypatch.setattr(db_mod, "query_data", _query, raising=True)
    monkeypatch.setattr(db_mod, "update_data", _update, raising=True)
    monkeypatch.setattr(db_mod, "query_one", lambda *_a, **_k: None, raising=True)

    yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_bootstrap_read_token(api_client, patch_verify):
    # No tokens yet – first POST returns a read token (scoped) – header required
    admin = make_token(ACCOUNT, ["admin"])
    resp = api_client.post(BASE, headers={"Authorization": f"Bearer {admin}"})
    assert resp.status_code == status.HTTP_201_CREATED
    body = resp.json()
    assert body["scopes"] == ["read"]


def test_admin_token_flow(api_client, patch_verify):
    # Create an admin token manually in the store then list & revoke
    admin = make_token(ACCOUNT, ["admin"])

    # list tokens
    resp = api_client.get(BASE, headers={"Authorization": f"Bearer {admin}"})
    assert resp.status_code == status.HTTP_200_OK

    tokens = resp.json()

    # If no tokens are present (store may be empty), create one through the API
    if not tokens:
        api_client.post(BASE, headers={"Authorization": f"Bearer {admin}"})
        tokens = api_client.get(BASE, headers={"Authorization": f"Bearer {admin}"}).json()

    token_id = tokens[0]["token_id"]

    # revoke
    resp = api_client.delete(f"{BASE}/{token_id}", headers={"Authorization": f"Bearer {admin}"})
    assert resp.status_code == status.HTTP_202_ACCEPTED 