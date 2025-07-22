from __future__ import annotations

"""Cron job: mark policy versions as inactive when revocation_time < now().

   This script is *idempotent* and safe to run every minute. It relies on the
   same Supabase helper utilities as the API routes. Hook it up to Vercel Cron
   or Supabase scheduled functions with a command similar to::

       python -m app.cron.revoke_enforcer

   It exits with status-code 0 on success.
"""

import asyncio
from datetime import datetime, timezone

from app.utils.dependencies import get_supabase_async
from app.utils.database import update_data, query_data

POLICY_TABLE = "policies"


async def _run() -> None:
    async for supabase in get_supabase_async():
        now_iso = datetime.now(timezone.utc).isoformat()
        resp = await query_data(
            supabase,
            POLICY_TABLE,
            filters={"revocation_time": ("lte", now_iso), "is_draft": False},
            select_fields="id",
        )
        to_revoke = [row["id"] for row in getattr(resp, "data", []) or []]
        for pk in to_revoke:
            await update_data(
                supabase,
                POLICY_TABLE,
                update_values={"is_revoked": True},
                filters={"id": pk},
                error_message="Failed to mark policy revoked",
            )


if __name__ == "__main__":
    asyncio.run(_run()) 