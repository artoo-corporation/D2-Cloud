"""Cron job: off-load newly ingested events from Supabase → ClickHouse.

Flow:
1. Read the high-water mark (`export_state.last_ts`).
2. Fetch rows from `events_raw_parent` where `ingested_at > last_ts`.
3. Bulk-insert into ClickHouse via HTTP JSONEachRow.
4. Update `export_state.last_ts`.

Idempotent: if ClickHouse insert fails the checkpoint isn’t advanced, so data
will be retried on the next run.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, List

import httpx

from app.utils.dependencies import get_supabase_async
from app.utils.database import query_data, insert_data, update_data


# ---------------------------------------------------------------------------
# Configuration via env vars
# ---------------------------------------------------------------------------

CLICKHOUSE_ENDPOINT = os.getenv("CLICKHOUSE_HTTP_ENDPOINT")  # e.g. https://ch.example.com:8443
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD")

EVENTS_TABLE = "events"
EXPORT_STATE_TABLE = "export_state"


async def _get_last_ts(supabase) -> str:
    row = await query_data(
        supabase,
        EXPORT_STATE_TABLE,
        filters={},
        select_fields="last_ts",
        limit=1,
    )
    rows = getattr(row, "data", []) or []
    return (rows[0]["last_ts"] if rows else "1970-01-01T00:00:00+00:00")


async def _set_last_ts(supabase, ts: str) -> None:
    # Upsert with a known primary key (id = 1)
    resp = await query_data(supabase, EXPORT_STATE_TABLE, filters={"id": 1}, select_fields="id", limit=1)
    if getattr(resp, "data", []):
        await update_data(
            supabase,
            EXPORT_STATE_TABLE,
            update_values={"last_ts": ts},
            filters={"id": 1},
            error_message="Failed to persist export checkpoint",
        )
    else:
        await insert_data(
            supabase,
            EXPORT_STATE_TABLE,
            {"id": 1, "last_ts": ts},
        )


async def _ship_to_clickhouse(rows: List[dict[str, Any]]) -> None:
    if not CLICKHOUSE_ENDPOINT:
        print("CLICKHOUSE_HTTP_ENDPOINT not set – skipping export (dev mode)")
        return

    # Convert rows to JSONEachRow format (one JSON per line)
    payload = "\n".join(json.dumps(row) for row in rows)

    auth = None
    if CLICKHOUSE_USER and CLICKHOUSE_PASSWORD:
        auth = (CLICKHOUSE_USER, CLICKHOUSE_PASSWORD)

    async with httpx.AsyncClient(timeout=10, auth=auth) as client:
        resp = await client.post(
            f"{CLICKHOUSE_ENDPOINT}?query=INSERT%20INTO%20events_raw%20FORMAT%20JSONEachRow",
            content=payload,
            headers={"Content-Type": "text/plain"},
        )
        resp.raise_for_status()


async def _run() -> None:
    async for supabase in get_supabase_async():
        last_ts = await _get_last_ts(supabase)

        resp = await query_data(
            supabase,
            EVENTS_TABLE,
            filters={"ingested_at": ("gt", last_ts)},
            select_fields="account_id, occurred_at, event_type, payload, ingested_at",
            limit=None,
        )
        rows = getattr(resp, "data", []) or []
        if not rows:
            print("No new rows to export")
            return

        await _ship_to_clickhouse(rows)

        max_ts = max(r["ingested_at"] for r in rows)
        await _set_last_ts(supabase, max_ts)

        print(f"Exported {len(rows)} rows up to {max_ts}")


if __name__ == "__main__":
    asyncio.run(_run()) 