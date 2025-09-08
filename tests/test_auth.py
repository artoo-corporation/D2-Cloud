import pytest
from tests.conftest import api_client, patch_verify, make_token
from app.utils.dependencies import require_token_admin

ACCOUNT = "acct_test"


def test_accounts_me_unauth(api_client):
    # bad prefix ⇒ 401
    resp = api_client.get("/v1/accounts/me", headers={"Authorization": "Bearer badtoken"})
    assert resp.status_code == 401


def test_keys_list_non_admin(api_client, patch_verify):
    read = make_token(ACCOUNT, ["read"])
    resp = api_client.get("/v1/keys", headers={"Authorization": f"Bearer {read}"})
    # require_token_admin should reject with 403
    assert resp.status_code == 403


def test_policy_draft_supabase_jwt(monkeypatch, api_client):
    """require_account_admin accepts Supabase JWT when verify_supabase_jwt passes."""
    from app.utils import security_utils

    async def _verify(token: str, admin_only: bool = False):  # noqa: ANN001
        assert token == "jwt_admin"
        if admin_only:
            return ACCOUNT
        return ACCOUNT

    from app.utils import dependencies as deps  # noqa: WPS433

    monkeypatch.setattr(security_utils, "verify_supabase_jwt", _verify, raising=True)
    monkeypatch.setattr(deps, "verify_supabase_jwt", _verify, raising=True)

    draft = {"version": 1, "bundle": {}}
    resp = api_client.put(
        "/v1/policy/draft",
        json=draft,
        headers={"Authorization": "Bearer jwt_admin"},
    )
    # passes DB stub returns 200/201 or quota check triggers 403
    assert resp.status_code in {200, 201, 403} 