"""Top-level package for D2 Cloud control-plane FastAPI application."""

__all__ = []

from dotenv import load_dotenv
import os
load_dotenv()

# Environment variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase env vars not configured")


APP_ENV = os.getenv("APP_ENV", "production")
