#!/usr/bin/env python3
"""Generate a 256-bit (32-byte) AES key for JWK encryption.

Usage::

    python scripts/generate_jwk_aes_key.py          # prints key to stdout
    python scripts/generate_jwk_aes_key.py -o .env  # appends `JWK_AES_KEY=<key>` to .env
    python scripts/generate_jwk_aes_key.py -c       # copy key to clipboard (needs pyperclip)

Run **once** in a secure environment, then store the key as the value of the
``JWK_AES_KEY`` environment variable in Vercel / CI secrets.  Losing this key
means losing access to all encrypted private JWK rows, so keep it safe.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path


def _generate_key() -> str:
    """Return a base-64url-encoded 32-byte random key (no padding)."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def main() -> None:  # noqa: D401
    parser = argparse.ArgumentParser(description="Generate AES-GCM key for JWK encryption")
    parser.add_argument("-o", "--output", type=Path, help="Append key to given file in .env format")
    parser.add_argument("-c", "--clipboard", action="store_true", help="Copy key to clipboard (requires pyperclip)")
    args = parser.parse_args()

    key = _generate_key()

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("a", encoding="utf-8") as fp:
            fp.write(f"JWK_AES_KEY={key}\n")
        print(f"Key appended to {args.output}")
    else:
        print(key)

    if args.clipboard:
        try:
            import pyperclip  # type: ignore

            pyperclip.copy(key)
            print("Key copied to clipboard")
        except ImportError:
            print("pyperclip not installed; cannot copy to clipboard", file=sys.stderr)


if __name__ == "__main__":
    main() 