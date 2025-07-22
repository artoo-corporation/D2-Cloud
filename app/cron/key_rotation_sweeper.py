from __future__ import annotations

"""Cron job: delete private RSA keys that are past the overlap window.

Run daily. The overlap window is 7 days by default (configurable via the
``JWK_OVERLAP_DAYS`` env var).
"""

import asyncio
import os
from datetime import datetime, timezone, timedelta

from app.utils.dependencies import get_supabase_async
from app.utils.database import query_data

JWKS_TABLE = "jwks_keys"


async def _run() -> None:
    overlap_days = int(os.getenv("JWK_OVERLAP_DAYS", "7"))
    cutoff = datetime.now(timezone.utc) - timedelta(days=overlap_days)
    cutoff_iso = cutoff.isoformat()

    async for supabase in get_supabase_async():
        resp = await query_data(
            supabase,
            JWKS_TABLE,
            filters={"expires_at": ("lte", cutoff_iso)},
            select_fields="id",
        )
        stale_ids = [row["id"] for row in getattr(resp, "data", []) or []]
        for pk in stale_ids:
            # Supabase Python client: delete row by primary key ID
            await supabase.table(JWKS_TABLE).delete().eq("id", pk).execute()


if __name__ == "__main__":
    asyncio.run(_run()) 