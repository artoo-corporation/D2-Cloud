#!/usr/bin/env python3
"""One-shot rotation: AES master key (JWK_AES_KEY) ➜ re-encrypt JWKS ➜ generate new RSA key-pairs ➜ re-sign active policies.

Assumptions
-----------
• OLD key      = current value of ``JWK_AES_KEY`` (or ``OLD_JWK_AES_KEY`` env override)
• NEW key      = ``NEW_JWK_AES_KEY`` env or auto-generated 32-byte base64url string
• Supabase service-role creds present in ``SUPABASE_URL`` / ``SUPABASE_KEY``

Steps executed atomically in this order:
1. Re-encrypt every ``jwks_keys.private_jwk`` from OLD → NEW (same as ``rotate_jwk_aes_key.py``)
2. **For each tenant**:
   a. Generate fresh 2048-bit RSA key-pair, encrypt priv-key with *NEW* key & insert row (same as ``rotate_all_jwks.py``)
   b. Re-sign all *active* policies with the new ``kid`` (uses ``security_utils.resign_active_policies``)
3. Clear *all* ``api_tokens.token_lookup`` values (they depend on AES key pepper)
4. Print NEW key and summary

If any step fails we log and continue; nothing is deleted. Repeatable.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.utils.dependencies import get_supabase_async  # noqa: E402
from app.utils.database import query_many, update_data, insert_data  # noqa: E402
from app.utils.security_utils import (
    decrypt_private_jwk,
    encrypt_private_jwk,
    generate_rsa_jwk,
    resign_active_policies,
)  # noqa: E402

JWKS_TABLE = "jwks_keys"
ACCOUNTS_TABLE = "accounts"
API_TOKEN_TABLE = "api_tokens"

# ---------------------------------------------------------------------------
# helpers copied (light) from rotate_jwk_aes_key.py for self-containment
# ---------------------------------------------------------------------------

def _b64url_gen_32() -> str:
    key = os.urandom(32)
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


def _validate_key(key_str: str) -> None:
    pad_len = (4 - len(key_str) % 4) % 4
    padded = key_str + "=" * pad_len
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) != 32:
        raise ValueError("JWK_AES_KEY must decode to 32 bytes")


async def _clear_token_lookups(supabase) -> Dict[str, Any]:
    rows = await query_many(
        supabase,
        API_TOKEN_TABLE,
        match={},
        select_fields="token_id,token_lookup",
    ) or []
    to_clear = [r for r in rows if r.get("token_lookup")]
    for tok in to_clear:
        try:
            await update_data(
                supabase,
                API_TOKEN_TABLE,
                update_values={"token_lookup": None},
                filters={"token_id": tok["token_id"]},
            )
        except Exception as exc:  # noqa: BLE001
            print(f"⚠️  Failed to clear token_lookup {tok['token_id']}: {exc}")
    return {"total": len(rows), "cleared": len(to_clear)}


# ---------------------------------------------------------------------------
# rotation logic
# ---------------------------------------------------------------------------

async def _rotate_aes_key(old_key: str, new_key: str, supabase) -> Dict[str, Any]:
    """Re-encrypt every private_jwk from OLD → NEW key."""
    rows: List[Dict[str, Any]] = await query_many(
        supabase,
        JWKS_TABLE,
        match={},
        select_fields="id,account_id,private_jwk,kid",
    ) or []

    updated = 0
    errors: List[str] = []

    for row in rows:
        rid = row["id"]
        try:
            os.environ["JWK_AES_KEY"] = old_key
            plain = decrypt_private_jwk(row["private_jwk"])

            os.environ["JWK_AES_KEY"] = new_key
            new_blob = encrypt_private_jwk(plain)
            _ = decrypt_private_jwk(new_blob)  # verify

            await update_data(
                supabase,
                JWKS_TABLE,
                update_values={"private_jwk": new_blob},
                filters={"id": rid},
            )
            updated += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"id={rid} kid={row.get('kid')}: {exc}")
        finally:
            os.environ["JWK_AES_KEY"] = old_key  # restore for next loop

    return {"total": len(rows), "updated": updated, "errors": errors}


async def _rotate_jwks_and_resign(new_key: str, supabase) -> Dict[str, Any]:
    """Generate fresh RSA keys for each tenant & resign policies."""

    os.environ["JWK_AES_KEY"] = new_key  # ensure encryption uses NEW key
    accounts = await query_many(supabase, ACCOUNTS_TABLE, select_fields="id") or []

    rotated = 0
    resigned_total = 0
    errors: List[str] = []

    for acc in accounts:
        account_id = acc["id"]
        kid = str(uuid.uuid4())
        jwk_pair = generate_rsa_jwk()
        try:
            await insert_data(
                supabase,
                JWKS_TABLE,
                {
                    "account_id": account_id,
                    "kid": kid,
                    "public_jwk": jwk_pair["public"],
                    "private_jwk": encrypt_private_jwk(jwk_pair["private"]),
                },
            )
            rotated += 1

            # re-sign policies
            try:
                stats = await resign_active_policies(
                    account_id=account_id,
                    new_kid=kid,
                    rotation_id=str(uuid.uuid4()),
                    supabase=supabase,
                )
                resigned_total += stats.get("policies_resigned", 0)
            except Exception as e:  # noqa: BLE001
                errors.append(f"resign account {account_id}: {e}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"insert key for {account_id}: {exc}")

    return {
        "accounts": len(accounts),
        "keys_rotated": rotated,
        "policies_resigned": resigned_total,
        "errors": errors,
    }


async def main() -> None:  # noqa: D401
    old_key = os.getenv("OLD_JWK_AES_KEY") or os.getenv("JWK_AES_KEY")
    if not old_key:
        raise SystemExit("Set JWK_AES_KEY (or OLD_JWK_AES_KEY) with the current 32-byte key.")
    try:
        _validate_key(old_key)
    except Exception as exc:
        raise SystemExit(f"OLD_JWK_AES_KEY invalid: {exc}")

    new_key = os.getenv("NEW_JWK_AES_KEY") or _b64url_gen_32()
    try:
        _validate_key(new_key)
    except Exception as exc:
        raise SystemExit(f"NEW_JWK_AES_KEY invalid: {exc}")

    print("🔑 Starting FULL rotation …")

    async for supabase in get_supabase_async():
        print("📦 Step 1/3: AES key rotation of jwks_keys …")
        aes_stats = await _rotate_aes_key(old_key, new_key, supabase)
        print(f"   → rows: {aes_stats['total']}  updated: {aes_stats['updated']}")
        if aes_stats["errors"]:
            print("   ⚠️  Errors:")
            for err in aes_stats["errors"]:
                print(f"     - {err}")

        print("🔐 Step 2/3: RSA key-pair rotation & policy resign …")
        jwks_stats = await _rotate_jwks_and_resign(new_key, supabase)
        print(
            f"   → accounts: {jwks_stats['accounts']}  keys_rotated: {jwks_stats['keys_rotated']}  "
            f"policies_resigned: {jwks_stats['policies_resigned']}"
        )
        if jwks_stats["errors"]:
            print("   ⚠️  Errors:")
            for err in jwks_stats["errors"]:
                print(f"     - {err}")

        print("🧹 Step 3/3: Clearing token_lookup peppers …")
        cleared = await _clear_token_lookups(supabase)
        print(f"   → cleared {cleared['cleared']} / {cleared['total']} tokens")

        # close Supabase client cleanly
        close_coro = getattr(supabase, "aclose", None)
        if callable(close_coro):
            await close_coro()
        break  # get_supabase_async yields indefinitely; we only need one client

    print("✅ Rotation complete.")
    print("NEW_JWK_AES_KEY:")
    print(new_key)
    # optional local .env patch
    try:
        env_file = PROJECT_ROOT / ".env"
        lines: List[str] = []
        if env_file.exists():
            lines = env_file.read_text().splitlines(keepends=True)
        replaced = False
        for i, line in enumerate(lines):
            if line.strip().startswith("JWK_AES_KEY="):
                lines[i] = f'JWK_AES_KEY="{new_key}"\n'
                replaced = True
                break
        if not replaced:
            lines.append(f'JWK_AES_KEY="{new_key}"\n')
        env_file.write_text("".join(lines))
        print("✅ Local .env updated → remember to commit or secure appropriately")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️  Could not update .env locally: {exc}")

    print("\nNext steps:")
    print("1) Set JWK_AES_KEY in production to the value above")
    print("2) Restart the API")
    print("3) Monitor logs – first token/tenant use will be slower while lookup backfills")


if __name__ == "__main__":
    asyncio.run(main())
