"""Top-level package for D2 Cloud control-plane FastAPI application."""

__all__ = [
    "APP_ENV",
    "STRIPE_SECRET_KEY",
    "STRIPE_SECRET_KEY_DEV",
    "STRIPE_WEBHOOK_SECRET",
    "SUPABASE_URL",
    "SUPABASE_KEY",
]

from dotenv import load_dotenv
import os
load_dotenv()

# Environment variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase env vars not configured")

# Stripe configuration
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_SECRET_KEY_DEV = os.environ.get("STRIPE_SECRET_KEY_DEV")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

if not STRIPE_SECRET_KEY:
    raise RuntimeError("STRIPE_SECRET_KEY not configured")

if not STRIPE_WEBHOOK_SECRET:
    raise RuntimeError("STRIPE_WEBHOOK_SECRET not configured")

APP_ENV = os.getenv("APP_ENV", "production")
