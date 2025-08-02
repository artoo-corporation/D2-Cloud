#!/usr/bin/env python3
"""Bulk-rotate RSA key-pairs for **every** tenant.

Scenario: you’ve replaced the `JWK_AES_KEY` master key and need to ensure all
private keys in `jwks_keys` are encrypted with the new master key – or you just
want a fresh rotation across the board.

Usage::

    # dry-run (no writes, just prints what would happen)
    python scripts/rotate_all_jwks.py --dry-run

    # real rotation
    python scripts/rotate_all_jwks.py

Requirements:
    • `SUPABASE_URL`, `SUPABASE_KEY` env vars for service-role access.
    • `JWK_AES_KEY` set to the **new** 32-byte base64url key.

The script:
    1. Iterates all rows in `accounts`.
    2. Generates a new 2048-bit RSA JWK pair.
    3. Encrypts the private key using the *current* `JWK_AES_KEY`.
    4. Inserts the new key into `jwks_keys` (old keys remain; sweeper will prune
       after the overlap window).

Safe to run multiple times; it always inserts a new key, never deletes.
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys
import uuid
from typing import Any

# Ensure project root is on PYTHONPATH so `import app.*` works when the script
# is executed directly (e.g. `python scripts/rotate_all_jwks.py`).
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.utils.dependencies import get_supabase_async  # noqa: E402
from app.utils.database import query_many, insert_data  # noqa: E402
from app.utils.security_utils import generate_rsa_jwk, encrypt_private_jwk  # noqa: E402

JWKS_TABLE = "jwks_keys"
ACCOUNTS_TABLE = "accounts"


async def _rotate_all(dry_run: bool) -> None:
    async for supabase in get_supabase_async():
        accounts = await query_many(supabase, ACCOUNTS_TABLE, select_fields="id")
        if not accounts:
            print("No accounts found – nothing to rotate")
            return

        for acc in accounts:
            account_id = acc["id"]
            kid = str(uuid.uuid4())
            jwk_pair = generate_rsa_jwk()

            if dry_run:
                print(f"[dry-run] Would insert new key for {account_id} kid={kid}")
                continue

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
            print(f"Rotated key for {account_id}: {kid}")


def main() -> None:  # noqa: D401
    parser = argparse.ArgumentParser(description="Rotate JWKS for every tenant")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without writing to DB")
    args = parser.parse_args()

    asyncio.run(_rotate_all(dry_run=args.dry_run))


if __name__ == "__main__":
    main() 