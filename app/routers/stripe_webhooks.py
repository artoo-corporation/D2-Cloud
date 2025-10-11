"""
Stripe Webhook Integration for Subscription Management

OVERVIEW:
=========
This module handles Stripe webhook events to automatically sync subscription changes
with user account plans in our system. It supports both modern thin events and legacy
snapshot events from Stripe's Event Destinations.

KEY FEATURES:
- Automatic plan updates when users subscribe/cancel
- Support for multiple event formats (thin events preferred)
- Robust error handling and logging
- Flexible plan mapping via metadata or environment variables

USE CASES IMPLEMENTED:
1. Subscription Created/Updated → Update account plan based on price metadata
2. Subscription Deleted → Revert account to "free" plan

STRIPE EVENT DESTINATIONS:
- Configure webhook URL in Stripe Dashboard → Webhooks
- Choose "Thin events" for better performance and data integrity
- Select events: customer.subscription.created, customer.subscription.updated, customer.subscription.deleted

REQUIRED ENVIRONMENT VARIABLES (configured in app/__init__.py):
- STRIPE_WEBHOOK_SECRET: Webhook signature verification secret
- STRIPE_SECRET_KEY: For API calls (prod/dev keys)
"""

from __future__ import annotations

import hmac
import hashlib
import time
from typing import Any, Dict

import stripe
from fastapi import APIRouter, HTTPException, Request, status, Depends

from app.utils.logger import logger
from app import APP_ENV, STRIPE_SECRET_KEY, STRIPE_SECRET_KEY_DEV, STRIPE_WEBHOOK_SECRET
from app.utils.database import query_one, update_data
from app.utils.dependencies import get_supabase_async


public_router = APIRouter(prefix="/webhooks/stripe", tags=["webhooks"])


@public_router.post("")
async def stripe_webhook(
    request: Request,
    supabase=Depends(get_supabase_async),
):
    """Public Stripe webhook endpoint for Event Destinations.

    This webhook handles subscription lifecycle events from Stripe to automatically
    update user account plans based on their subscription status.

    FLOW OVERVIEW:
    1. Receive webhook from Stripe (thin event or snapshot event)
    2. Verify webhook signature for security
    3. Extract event type and subscription data
    4. Map Stripe subscription to internal plan name
    5. Find account by customer email
    6. Update account plan in database
    7. Return success response

    Supports both thin events (v2.core.event) and legacy snapshot events.
    Thin events are preferred as they provide the most up-to-date data.

    IMPORTANT: Always returns 200 OK to prevent Stripe from retrying delivery.
    All errors are logged but don't affect the response.
    """

    # STEP 1: INITIALIZE STRIPE CONFIGURATION
    # ======================================
    # Configuration is loaded centrally in app/__init__.py for better organization
    # Set the Stripe API key based on environment (dev vs production)
    # This is needed for any follow-up API calls (like fetching customer details)
    stripe.api_key = STRIPE_SECRET_KEY_DEV if APP_ENV == "development" else STRIPE_SECRET_KEY
    # Get the webhook secret for signature verification
    secret = STRIPE_WEBHOOK_SECRET

    # STEP 2: RECEIVE AND VALIDATE WEBHOOK
    # ====================================
    # Read the raw request body (must be unmodified for signature verification)
    raw_body = await request.body()

    # Extract the Stripe signature header for verification
    sig_header = request.headers.get("Stripe-Signature")
    if not sig_header:
        # Reject requests without proper Stripe signature
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing_stripe_signature")

    # STEP 3: VERIFY SIGNATURE AND PARSE EVENT
    # ========================================
    # Use Stripe's library to verify the webhook signature and construct the event object
    # This ensures the webhook is actually from Stripe and hasn't been tampered with
    try:
        event_notification = stripe.Webhook.construct_event(
            payload=raw_body, sig_header=sig_header, secret=secret
        )
    except ValueError:
        # Invalid JSON payload - not a valid Stripe webhook
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_json")
    except stripe.error.SignatureVerificationError:
        # Signature doesn't match - could be a spoofed request
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="signature_verification_failed")

    # STEP 4: HANDLE EVENT FORMAT DIFFERENCES
    # ======================================
    # Stripe has two event formats:
    # - Thin events (v2.core.event): Lightweight notifications with just object IDs
    # - Snapshot events: Full object data included in the webhook payload
    #
    # Thin events are preferred because they guarantee up-to-date data and are smaller

    if hasattr(event_notification, 'object') and event_notification.object == "v2.core.event":
        # THIN EVENT PATH: Lightweight notification received
        # We need to fetch the complete event details from Stripe API
        try:
            # Fetch the full event object which contains additional context
            event = event_notification.fetch_event()
            event_type = event.type  # e.g., "customer.subscription.created"
            event_id = event.id      # Unique event identifier
        except Exception as e:
            # Failed to fetch complete event - log and reject
            logger.error("stripe.webhook.fetch_event_failed", extra={"error": str(e)})
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="failed_to_fetch_event")
    else:
        # SNAPSHOT EVENT PATH: Legacy format with full object data
        # Event data is already included in the webhook payload
        event = event_notification
        # Extract event type and ID (handle both object and dict formats)
        event_type = getattr(event, "type", None) or (event.get("type") if isinstance(event, dict) else None)
        event_id = getattr(event, "id", None) or (event.get("id") if isinstance(event, dict) else None)

    # STEP 5: LOG EVENT RECEIPT
    # =========================
    # Log that we successfully received and parsed the webhook
    # This helps with debugging and monitoring webhook delivery
    logger.info(
        "stripe.webhook.received",
        extra={
            "event_type": event_type,  # What type of event (subscription.created, etc.)
            "event_id": event_id,      # Stripe's unique event identifier
        },
    )

    # STEP 6: HELPER FUNCTIONS
    # ========================


    async def _set_plan_by_email(email: str | None, plan_id: str) -> None:
        """Update account plan for user with given email address.

        STRATEGY:
        1. First try to find user by email in 'users' table (most common case)
        2. If not found, try direct lookup in 'accounts' table (fallback)
        3. Update the account's plan_id with the plan UUID

        Args:
            email: Customer email from Stripe
            plan_id: Plan UUID to set (foreign key to plans.id)
        """
        if not email:
            return

        # STEP 6.1: FIND ACCOUNT ID BY EMAIL
        # =================================
        # Try to find the account associated with this email address
        account_id: str | None = None

        # Strategy 1: Look in users table first (user has account_id)
        user = await query_one(supabase, "users", match={"email": email})
        if user:
            account_id = user.get("account_id")
        else:
            # Strategy 2: Fallback to accounts table (account has email directly)
            account = await query_one(supabase, "accounts", match={"email": email})
            if account:
                account_id = account.get("id")

        if not account_id:
            # No account found for this email - log and exit
            logger.info("stripe.webhook.account_not_found", extra={"email": email})
            return

        # STEP 6.2: UPDATE ACCOUNT PLAN
        # ============================
        # Update the account's plan in the database
        await update_data(
            supabase,
            "accounts",
            update_values={"plan_id": plan_id},  # The plan UUID to set
            filters={"id": account_id},          # Which account to update
            error_message="account_plan_update_failed",  # Error message if update fails
        )

    async def _map_plan_from_subscription(sub, supabase) -> str | None:
        """Map Stripe subscription object to internal plan UUID.

        This function determines what plan UUID a Stripe subscription should map to
        by looking up the plan name in our plans table.

        MAPPING STRATEGY:
        1. Extract plan name from Stripe price metadata ("plan_name" field)
        2. Look up the corresponding plan UUID in our plans table
        3. Return the plan UUID for database updates

        Args:
            sub: Stripe subscription object (either Stripe object or dict)
            supabase: Database connection for plan lookup

        Returns:
            Plan UUID string or None if mapping fails
        """

        try:
            # STEP 1: EXTRACT PLAN NAME FROM STRIPE
            # ====================================
            plan_name = None

            # Get subscription items to find the price
            items = []
            if hasattr(sub, 'items') and hasattr(sub.items, 'data'):
                # THIN EVENT: Stripe object format
                items = sub.items.data
            elif isinstance(sub, dict):
                # SNAPSHOT EVENT: Dict format
                items = ((sub.get("items") or {}).get("data") or [])

            if items:
                # Get the price from the first subscription item
                first_item = items[0]
                price = None
                if hasattr(first_item, 'price'):
                    # THIN EVENT: Direct price object
                    price = first_item.price
                elif isinstance(first_item, dict):
                    # SNAPSHOT EVENT: Dict with price key
                    price = first_item.get("price") or {}

                if price:
                    # Extract plan name from price metadata
                    # This is set in Stripe Dashboard → Product → Pricing → Price → Metadata
                    price_metadata = None
                    if hasattr(price, 'metadata'):
                        # THIN EVENT: Direct metadata access
                        price_metadata = getattr(price, 'metadata', {}) or {}
                    elif isinstance(price, dict):
                        # SNAPSHOT EVENT: Dict metadata access
                        price_metadata = price.get("metadata") or {}

                    if price_metadata:
                        plan_name = price_metadata.get("plan_name")
                        if plan_name not in {"essentials", "pro", "enterprise"}:
                            plan_name = None  # Invalid plan name

            # STEP 2: LOOKUP PLAN UUID IN DATABASE
            # ===================================
            if plan_name:
                try:
                    # Query plans table to find UUID for this plan name
                    plan_record = await query_one(
                        supabase,
                        "plans",
                        match={"name": plan_name}
                    )
                    if plan_record:
                        return plan_record.get("id")  # Return the plan UUID

                except Exception as e:
                    logger.warning("stripe.webhook.plan_lookup_failed", extra={"error": str(e), "plan_name": plan_name})

        except Exception as e:
            # Log any errors in plan mapping but don't fail the webhook
            logger.warning("stripe.webhook.plan_mapping_failed", extra={"error": str(e)})

        # Return None if no mapping found
        return None

    async def _get_free_plan_id(supabase) -> str | None:
        """Get the UUID of the free plan from the database."""
        try:
            free_plan = await query_one(supabase, "plans", match={"name": "free"})
            return free_plan.get("id") if free_plan else None
        except Exception as e:
            logger.warning("stripe.webhook.free_plan_lookup_failed", extra={"error": str(e)})
            return None

    # STEP 8: MAIN EVENT PROCESSING
    # =============================
    # Process the subscription lifecycle events and update account plans accordingly

    try:
        # STEP 8.1: EXTRACT SUBSCRIPTION DATA
        # ==================================
        # Get the subscription object from the event (format depends on thin vs snapshot event)
        subscription = None

        if hasattr(event_notification, 'object') and event_notification.object == "v2.core.event":
            # THIN EVENT: Fetch the actual subscription object from Stripe API
            # This ensures we have the most up-to-date subscription data
            try:
                subscription = event_notification.fetch_related_object()
            except Exception as e:
                logger.error("stripe.webhook.fetch_related_object_failed", extra={"error": str(e), "event_type": event_type})
                # Continue processing - subscription might be None but we can handle it
        else:
            # SNAPSHOT EVENT: Extract subscription from the event data payload
            if isinstance(event, dict):
                # Event data structure: {"data": {"object": subscription_data}}
                data = event.get("data") or {}
                subscription = (data.get("object") if isinstance(data, dict) else None)
            else:
                # Stripe Event object with .data.object attribute
                try:
                    subscription = event.data.object  # type: ignore[attr-defined]
                except Exception:
                    subscription = None

        # STEP 8.2: PROCESS SUBSCRIPTION CREATED/UPDATED EVENTS
        # ===================================================
        # When a subscription is created or updated, check if it should trigger a plan change
        if event_type in ("customer.subscription.created", "customer.subscription.updated"):
            if subscription:
                # Check subscription status - only active/trialing subscriptions should update plans
                status_val = getattr(subscription, "status", None) or subscription.get("status")
                if status_val in ("active", "trialing"):
                    # Map the Stripe subscription to our internal plan UUID
                    plan_id = await _map_plan_from_subscription(subscription, supabase)
                    if plan_id:  # Valid plan UUID found
                        # STEP 8.2.1: GET CUSTOMER EMAIL
                        # =============================
                        # We need the customer's email to find their account
                        customer_id = getattr(subscription, "customer", None) or subscription.get("customer")
                        logger.info("stripe.webhook.extracting_customer", extra={"customer_id": customer_id, "subscription_id": getattr(subscription, "id", None)})
                        customer = None
                        if customer_id:
                            try:
                                # Fetch customer details from Stripe to get their email
                                customer = stripe.Customer.retrieve(customer_id)
                                logger.info("stripe.webhook.customer_fetched", extra={"customer_id": customer_id, "email": getattr(customer, "email", None)})
                            except Exception as e:
                                logger.error("stripe.webhook.customer_fetch_failed", extra={"error": str(e), "error_type": type(e).__name__, "customer_id": customer_id})

                        email = None
                        if customer:
                            # Extract email from customer object (works for both Stripe objects and dicts)
                            email = getattr(customer, "email", None)
                            logger.info("stripe.webhook.email_extracted", extra={"email": email})
                        else:
                            logger.warning("stripe.webhook.no_customer_object", extra={"customer_id": customer_id})

                        # STEP 8.2.2: UPDATE ACCOUNT PLAN
                        # ===============================
                        # Update the user's account with the plan UUID
                        if email and plan_id:
                            logger.info("stripe.webhook.updating_account", extra={"email": email, "plan_id": plan_id})
                            await _set_plan_by_email(email, plan_id)
                        else:
                            logger.warning("stripe.webhook.skipping_update", extra={"email": email, "plan_id": plan_id})

        # STEP 8.3: PROCESS SUBSCRIPTION DELETION EVENTS
        # =============================================
        # When a subscription is cancelled/deleted, revert the account to free plan
        elif event_type == "customer.subscription.deleted":
            if subscription:
                # Get the free plan UUID from database
                free_plan_id = await _get_free_plan_id(supabase)

                if free_plan_id:
                    # Get customer info for this cancelled subscription
                    customer_id = getattr(subscription, "customer", None) or subscription.get("customer")
                    customer = None
                    if customer_id:
                        try:
                            customer = stripe.Customer.retrieve(customer_id)
                        except Exception as e:
                            logger.error("stripe.webhook.customer_fetch_failed", extra={"error": str(e), "customer_id": customer_id})

                    email = None
                    if customer:
                        email = getattr(customer, "email", None)

                    # Revert account to free plan (cancellation)
                    await _set_plan_by_email(email, free_plan_id)

        # STEP 8.4: HANDLE UNSUPPORTED EVENT TYPES
        # =======================================
        # Log events we don't handle yet (for future expansion)
        else:
            logger.info("stripe.webhook.unhandled", extra={"event_type": event_type})

    except Exception as e:
        # STEP 8.5: CATCH-ALL ERROR HANDLING
        # =================================
        # Log any unexpected errors but don't fail the webhook
        # This ensures Stripe doesn't retry delivery for processing errors
        logger.error("stripe.webhook.handler_error", extra={"error": str(e), "event_type": event_type})

    # STEP 9: RETURN SUCCESS RESPONSE
    # ==============================
    # Always return 200 OK to tell Stripe we received the webhook successfully
    # This prevents Stripe from retrying the webhook delivery
    return {"received": True}


