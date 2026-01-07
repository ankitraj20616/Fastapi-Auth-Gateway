from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .superbase_client import supabase
from .config import settings


security = HTTPBearer()

def verify_supabase_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    '''
    Verify token by calling Supabase API
    '''
    token = credentials.credentials
    
    try:
        response = supabase.auth.get_user(token)
        if response and response.user:
            return {
                "sub": response.user.id,
                "email": response.user.email,
                "user_metadata": response.user.user_metadata,
                "role": response.user.role
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
    except Exception as e:
        print(f"Auth Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )