from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    '''
    This class will fetch all the enviorment variables from .env file
    '''
    SUPABASE_PROJECT_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_JWT_ISSUER: str
    SUPABASE_JWT_AUDIENCE: str
    JWT_PRIVATE_KEY: str
    JWT_EXPIRES_IN: int
    JWT_REFRESH_EXPIRES_IN_DAYS: int
    SUPABASE_SERVICE_ROLE_KEY: str
    PROXY_TARGET_URL: str

    class Config:
        env_file= ".env"

settings = Settings()