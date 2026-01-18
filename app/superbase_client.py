from supabase import create_client, Client
from .config import settings
import httpx

def get_supabase() -> Client:
    return create_client(
        settings.SUPABASE_PROJECT_URL,
        settings.SUPABASE_ANON_KEY,
    )

def get_supabase_admin() -> Client:
    return create_client(
        settings.SUPABASE_PROJECT_URL,
        settings.SUPABASE_SERVICE_ROLE_KEY,
    )