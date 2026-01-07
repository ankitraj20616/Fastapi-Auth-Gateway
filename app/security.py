from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from .config import settings
import json

security = HTTPBearer()

JWK_PUBLIC_KEY = json.load(settings.SUPABASE_JWT_PUBLIC_KEY)

def verify_supabase_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    '''
        This method will extract header from incoming request, and check for missing or malformed header
        then decode the payload from token and return it
    '''
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            JWK_PUBLIC_KEY,
            algorithms=["ES256"],
            audience= settings.SUPABASE_JWT_AUDIENCE,
            issuer= settings.SUPABASE_JWT_ISSUER,
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid or expire token!",
        )