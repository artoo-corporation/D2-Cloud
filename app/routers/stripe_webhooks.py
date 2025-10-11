from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
from typing import Any, Dict

import stripe
from fastapi import APIRouter, HTTPException, Request, status, Depends

from app.utils.logger import logger
from app import APP_ENV
from app.utils.database import query_one, update_data
from app.utils.dependencies import get_supabase_async


public_router = APIRouter(prefix="/webhooks/stripe", tags=["webhooks"])


def _get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"missing_env_{name}")
    return value


@public_router.post("")
async def stripe_webhook(
    request: Request,
    supabase=Depends(get_supabase_async),
):
    """Public Stripe webhook endpoint.

    - Verifies Stripe-Signature using the endpoint secret (env STRIPE_WEBHOOK_SECRET)
    - Parses the incoming event JSON
    - Quickly returns 200 to avoid delivery timeouts; heavy work should run in background
    """

    # Configure Stripe API key for any follow-up fetches (e.g., retrieve customer)
    stripe.api_key = (
        _get_env("STRIPE_SECRET_KEY_DEV") if APP_ENV == "development" else _get_env("STRIPE_SECRET_KEY")
    )
    secret = _get_env("STRIPE_WEBHOOK_SECRET")

    # Read raw body first (must be unmodified for signature verification)
    raw_body = await request.body()
    sig_header = request.headers.get("Stripe-Signature")
    if not sig_header:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing_stripe_signature")

    # Verify signature and construct the event using Stripe's library
    try:
        event = stripe.Webhook.construct_event(
            payload=raw_body, sig_header=sig_header, secret=secret
        )
    except ValueError:
        # Invalid payload
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_json")
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="signature_verification_failed")

    # Event is a stripe.Event or dict-like
    event_type = getattr(event, "type", None) or (event.get("type") if isinstance(event, dict) else None)
    event_id = getattr(event, "id", None) or (event.get("id") if isinstance(event, dict) else None)

    logger.info(
        "stripe.webhook.received",
        extra={
            "event_type": event_type,
            "event_id": event_id,
        },
    )

    # Helpers -------------------------------------------------------------
    def _env_json_map(name: str) -> Dict[str, str]:
        try:
            raw = os.getenv(name)
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    async def _set_plan_by_email(email: str | None, new_plan: str) -> None:
        if not email:
            return
        # 1) Try users → account_id by user email
        user = await query_one(supabase, "users", match={"email": email})
        account_id: str | None = None
        if user:
            account_id = user.get("account_id")
        else:
            # 2) Try accounts.email fallback
            account = await query_one(supabase, "accounts", match={"email": email})
            if account:
                account_id = account.get("id")
        if not account_id:
            logger.info("stripe.webhook.account_not_found", extra={"email": email})
            return
        await update_data(
            supabase,
            "accounts",
            update_values={"plan_id": new_plan},
            filters={"id": account_id},
            error_message="account_plan_update_failed",
        )

    def _map_plan_from_subscription(sub: Dict[str, Any]) -> str | None:
        # Preferred: map by Price ID via env JSON (e.g., STRIPE_PRICE_PLAN_MAP='{"price_123":"essentials","price_456":"pro"}')
        price_map = _env_json_map("STRIPE_PRICE_PLAN_MAP")
        try:
            items = ((sub.get("items") or {}).get("data") or [])
            if items:
                price = (items[0].get("price") or {})
                price_id = price.get("id")
                if price_id and price_id in price_map:
                    return price_map[price_id]
                # Fallback: product metadata.plan
                product_id = price.get("product")
                if product_id:
                    prod = stripe.Product.retrieve(product_id)
                    plan_from_meta = (getattr(prod, "metadata", {}) or {}).get("plan")
                    if plan_from_meta in {"essentials", "pro", "enterprise"}:
                        return plan_from_meta
                    # Fallback on product name heuristics
                    name = getattr(prod, "name", "").lower()
                    if "essential" in name:
                        return "essentials"
                    if "pro" in name:
                        return "pro"
        except Exception:
            pass
        return None

    # Process subscription lifecycle synchronously (serverless-safe) ------
    try:
        data_object = None
        if isinstance(event, dict):
            data = event.get("data") or {}
            data_object = (data.get("object") if isinstance(data, dict) else None)
        else:
            try:
                data_object = event.data.object  # type: ignore[attr-defined]
            except Exception:
                data_object = None

        if event_type in ("customer.subscription.created", "customer.subscription.updated"):
            sub = data_object or {}
            status_val = sub.get("status")
            if status_val in ("active", "trialing"):
                desired_plan = _map_plan_from_subscription(sub)
                if desired_plan in {"essentials", "pro", "enterprise"}:
                    customer_id = sub.get("customer")
                    customer = stripe.Customer.retrieve(customer_id) if customer_id else None
                    email = getattr(customer, "email", None) if customer else None
                    await _set_plan_by_email(email, desired_plan)
        elif event_type == "customer.subscription.deleted":
            sub = data_object or {}
            customer_id = sub.get("customer")
            customer = stripe.Customer.retrieve(customer_id) if customer_id else None
            email = getattr(customer, "email", None) if customer else None
            await _set_plan_by_email(email, "free")
        else:
            logger.info("stripe.webhook.unhandled", extra={"event_type": event_type})
    except Exception as e:
        logger.info("stripe.webhook.handler_error", extra={"error": str(e), "event_type": event_type})

    return {"received": True}


