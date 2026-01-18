from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from .config import settings
from .superbase_client import get_supabase_admin
import httpx


security = HTTPBearer()



def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Verify Supabase JWT token independently using ES256 algorithm.
    Dynamically fetches the correct public key based on the token's kid.
    """
    token = credentials.credentials
    
    try:
        payload = jwt.decode(
            token,
            settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256", "ES256"],
            audience=settings.SUPABASE_JWT_AUDIENCE,
            issuer=settings.SUPABASE_JWT_ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True
            },
            leeway=10
        )
        return {
            "sub": payload.get("sub"),
            "email": payload.get("email"),
            "role": payload.get("role"),
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "user_metadata": payload.get("user_metadata", {}),
            "app_metadata": payload.get("app_metadata", {}),
            "session_id": payload.get("session_id")
        }
        
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        print(f"Invalid audience. Expected: {settings.SUPABASE_JWT_AUDIENCE}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        print(f"Invalid issuer. Expected: {settings.SUPABASE_JWT_ISSUER}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidSignatureError as e:
        print(f"Signature verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
            detail="Invalid token: Signature verification failed",
        )
    except jwt.InvalidTokenError as e:
        print(f"Token validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        print(f"Unexpected auth error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    

def verify_user_in_supabase(
    payload: dict = Depends(verify_token)
):
    '''
    This function verify the jwt access token and then verify that user exists in the Supabase user table or not by making api call to Supabase admin.
    '''
    user_id = payload.get("sub")
    email = payload.get("email")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    url = f"{settings.SUPABASE_PROJECT_URL}/auth/v1/admin/users/{user_id}"

    headers = {
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": settings.SUPABASE_SERVICE_ROLE_KEY,
    }

    try:
        res = httpx.get(url, headers=headers, timeout=5)

        if res.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found in Supabase",
            )

        user = res.json()

        
        if email and user.get("email") != email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token email mismatch",
            )

        return payload

    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase auth service unreachable",
        )
