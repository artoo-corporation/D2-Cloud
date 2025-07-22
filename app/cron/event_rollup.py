from __future__ import annotations

"""Cron job: aggregate raw events into daily stats for billing.

This is a *stub* implementation because ClickHouse is accessed via Logflare‘s
HTTP API. The function demonstrates the expected shape and can be fleshed out
once schema/tables are finalised.
"""

import asyncio
import os
from datetime import datetime, timezone, timedelta

import httpx

LOGFLARE_ENDPOINT = os.getenv("LOGFLARE_HTTP_ENDPOINT", "https://api.logflare.app")
LOGFLARE_API_KEY = os.getenv("LOGFLARE_API_KEY")


async def _run() -> None:
    if not LOGFLARE_API_KEY:
        print("LOGFLARE_API_KEY not set – nothing to roll-up")
        return

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    date_str = yesterday.strftime("%Y-%m-%d")

    # Placeholder query – adapt to real ClickHouse schema
    sql = f"""
    INSERT INTO events_daily_stats
    SELECT account_id, toDate(ts) AS day, count() AS cnt
    FROM events_raw
    WHERE toDate(ts) = '{date_str}'
    GROUP BY account_id, day;
    """

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{LOGFLARE_ENDPOINT}/clickhouse",
            headers={"X-API-KEY": LOGFLARE_API_KEY},
            json={"query": sql},
        )
        resp.raise_for_status()
        print("Roll-up OK", resp.json())


if __name__ == "__main__":
    asyncio.run(_run()) 