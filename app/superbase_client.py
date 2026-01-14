from supabase import create_client, Client
from .config import settings

'''
This instance of supabase will help to connect with supabase sdk(running locally)
'''
supabase: Client = create_client(
    settings.SUPABASE_PROJECT_URL,
    settings.SUPABASE_ANON_KEY
)

supabase_admin = create_client(
    settings.SUPABASE_PROJECT_URL,
    settings.SUPABASE_SERVICE_ROLE_KEY
)