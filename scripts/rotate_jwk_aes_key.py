"""Rotate the AES key used to encrypt JWKS private keys (JWK_AES_KEY).

This script:
- Reads OLD_JWK_AES_KEY from env (required)
- Uses NEW_JWK_AES_KEY from env, or generates one if missing
- Re-encrypts all rows in table `jwks_keys` from OLD to NEW
- Clears all `token_lookup` values (they become invalid with new AES key)
- Verifies each updated row can be decrypted with NEW only
- Prints the NEW_JWK_AES_KEY at the end for you to set in your service env

It DOES NOT rotate RSA JWKS keypairs and does NOT restart your service.

Usage:
  # From repo root (activating your venv)
  export OLD_JWK_AES_KEY="<current-key>"
  # Optional: provide your own new key; if omitted, one will be generated
  # export NEW_JWK_AES_KEY="<new-key>"
  python scripts/rotate_jwk_aes_key.py

After it completes successfully:
  - Local .env file is automatically updated
  - Set JWK_AES_KEY="<printed NEW key>" in your production/server env
  - Restart the API
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is on sys.path so "app" imports work even when executed directly
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.utils.dependencies import get_supabase_async  # noqa: E402
from app.utils.database import query_many, update_data  # noqa: E402
from app.utils.security_utils import decrypt_private_jwk, encrypt_private_jwk  # noqa: E402


def _b64url_gen_32() -> str:
    key = os.urandom(32)
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


def _validate_key(key_str: str) -> None:
    # Accept unpadded base64url; add padding for decode and check length
    padding_needed = (4 - len(key_str) % 4) % 4
    padded = key_str + "=" * padding_needed
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) != 32:
        raise ValueError("JWK_AES_KEY must decode to 32 bytes")


async def _clear_token_lookups(supabase) -> Dict[str, Any]:
    """Clear all token_lookup values since they become invalid after AES key rotation."""
    try:
        # First get all tokens that have token_lookup values
        tokens_with_lookup = await query_many(
            supabase,
            "api_tokens",
            match={},
            select_fields="token_id,token_lookup"
        )
        
        if not tokens_with_lookup:
            return {"cleared": True, "count": 0, "error": None}
        
        # Filter to only tokens that actually have token_lookup values
        tokens_to_clear = [t for t in tokens_with_lookup if t.get("token_lookup")]
        
        if not tokens_to_clear:
            return {"cleared": True, "count": 0, "error": None}
        
        # Clear token_lookup for each token individually
        cleared_count = 0
        for token in tokens_to_clear:
            try:
                await update_data(
                    supabase,
                    "api_tokens",
                    update_values={"token_lookup": None},
                    filters={"token_id": token["token_id"]}
                )
                cleared_count += 1
            except Exception as e:
                print(f"Warning: Failed to clear token_lookup for {token['token_id']}: {e}")
        
        return {"cleared": True, "count": cleared_count, "error": None}
    except Exception as e:
        return {"cleared": False, "count": 0, "error": str(e)}


async def _rotate_all_rows(old_key: str, new_key: str) -> Dict[str, Any]:
    # Use OLD to decrypt
    os.environ["JWK_AES_KEY"] = old_key
    supabase = await (get_supabase_async()).__anext__()

    rows: List[Dict[str, Any]] = await query_many(
        supabase,
        "jwks_keys",
        match={},
        select_fields="id,account_id,private_jwk,kid,created_at",
    ) or []

    updated = 0
    errors: List[str] = []

    for row in rows:
        rid = row.get("id")
        try:
            # Decrypt using OLD
            plain = decrypt_private_jwk(row["private_jwk"])  # may be plain or encrypted

            # Encrypt with NEW
            os.environ["JWK_AES_KEY"] = new_key
            new_blob = encrypt_private_jwk(plain)

            # Verify new blob can be decrypted with NEW only
            _ = decrypt_private_jwk(new_blob)

            # Persist
            await update_data(
                supabase,
                "jwks_keys",
                update_values={"private_jwk": new_blob},
                filters={"id": rid},
            )

            updated += 1

            # Switch back to OLD for next row's decrypt
            os.environ["JWK_AES_KEY"] = old_key
        except Exception as e:  # noqa: BLE001
            errors.append(f"id={rid} account_id={row.get('account_id')} kid={row.get('kid')}: {e}")
            # Always ensure we can proceed to next row with OLD set
            os.environ["JWK_AES_KEY"] = old_key

    # Best-effort close
    try:
        close_coro = getattr(supabase, "aclose", None)
        if callable(close_coro):
            await close_coro()
    except Exception:
        pass

    return {"total": len(rows), "updated": updated, "errors": errors}


async def main() -> None:
    # Prefer explicit OLD_JWK_AES_KEY, otherwise fall back to current app key
    old_key = os.getenv("OLD_JWK_AES_KEY") or os.getenv("JWK_AES_KEY")
    if not old_key:
        raise SystemExit("Set JWK_AES_KEY (or OLD_JWK_AES_KEY) in your environment so the script can decrypt existing rows.")

    try:
        _validate_key(old_key)
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"OLD_JWK_AES_KEY invalid: {e}")

    new_key = os.getenv("NEW_JWK_AES_KEY") or _b64url_gen_32()

    try:
        _validate_key(new_key)
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"NEW_JWK_AES_KEY invalid: {e}")

    print("Starting AES-key rotation for jwks_keys ...")
    result = await _rotate_all_rows(old_key, new_key)
    
    # Clear token_lookup values since they become invalid with new AES key
    print("\nClearing token_lookup values (they'll be backfilled on next use)...")
    supabase = await (get_supabase_async()).__anext__()
    try:
        lookup_result = await _clear_token_lookups(supabase)
        if lookup_result["cleared"]:
            count = lookup_result.get("count", 0)
            print(f"✅ Token lookup values cleared successfully ({count} tokens)")
        else:
            print(f"❌ Failed to clear token lookups: {lookup_result['error']}")
    finally:
        # Best-effort close
        try:
            close_coro = getattr(supabase, "aclose", None)
            if callable(close_coro):
                await close_coro()
        except Exception:
            pass

    print("\nDone.")
    print(f"Rows found:   {result['total']}")
    print(f"Rows updated: {result['updated']}")
    if result["errors"]:
        print("Errors:")
        for line in result["errors"]:
            print(f"  - {line}")

    print("\nNEW_JWK_AES_KEY:")
    print(new_key)
    
    # Automatically update local .env file
    try:
        env_file_path = PROJECT_ROOT / ".env"
        if env_file_path.exists():
            # Read current .env content
            with open(env_file_path, 'r') as f:
                lines = f.readlines()
            
            # Update or add JWK_AES_KEY
            updated = False
            for i, line in enumerate(lines):
                if line.strip().startswith('JWK_AES_KEY='):
                    lines[i] = f'JWK_AES_KEY="{new_key}"\n'
                    updated = True
                    break
            
            if not updated:
                lines.append(f'JWK_AES_KEY="{new_key}"\n')
            
            # Write back to .env file
            with open(env_file_path, 'w') as f:
                f.writelines(lines)
            
            print(f"✅ Local .env file updated with new JWK_AES_KEY")
        else:
            print("⚠️  No .env file found - you'll need to set the key manually")
    except Exception as e:
        print(f"⚠️  Failed to update .env file: {e}")
    
    print("\nNext steps:")
    print("1) Set JWK_AES_KEY in your PRODUCTION/SERVER environment:")
    print(f"   JWK_AES_KEY=\"{new_key}\"")
    print("2) Restart the API server")
    print("3) Expect one slow request per existing API token (we backfill token_lookup automatically)")
    print("\nNote: All token_lookup values were cleared to prevent stale lookups from causing slow requests.")


if __name__ == "__main__":
    asyncio.run(main())


