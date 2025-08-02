from __future__ import annotations

"""Cron job: lock expired trial accounts.

Run daily (e.g. 01:00 UTC) to flip `plan` to *locked* when the trial window
has elapsed.  The enforcement also happens in-process via
`app.utils.plans.effective_plan`, but this job makes the change permanent so
queries (e.g. analytics) reflect the latest state.
"""

import asyncio
from datetime import timezone, datetime

from app.utils.dependencies import get_supabase_async
from app.utils.database import update_data, query_data

ACCOUNTS_TABLE = "accounts"


async def _run() -> None:
    async for supabase in get_supabase_async():
        resp = await query_data(
            supabase,
            ACCOUNTS_TABLE,
            filters={"plan": "trial", "trial_expires": ("lt", datetime.now(timezone.utc).isoformat())},
            select_fields="id",
        )
        to_lock = [row["id"] for row in getattr(resp, "data", []) or []]
        for pk in to_lock:
            await update_data(
                supabase,
                ACCOUNTS_TABLE,
                update_values={"plan": "locked"},
                filters={"id": pk},
                error_message="failed_to_lock_account",
            )


if __name__ == "__main__":
    asyncio.run(_run()) 