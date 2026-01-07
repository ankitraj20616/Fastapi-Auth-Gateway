from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    '''
    This class will fetch all the enviorment variables from .env file
    '''
    SUPABASE_PROJECT_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_JWT_ISSUER: str
    SUPABASE_JWT_AUDIENCE: str
    SUPABASE_JWT_PUBLIC_KEY: str

    class Config:
        env_file= ".env"

settings = Settings()