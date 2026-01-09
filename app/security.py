from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import json
import requests
from jwt.algorithms import ECAlgorithm
from functools import lru_cache
from datetime import datetime
from .config import settings
from .superbase_client import supabase_admin

security = HTTPBearer()


@lru_cache(maxsize=1)
def get_jwks():
    """
    Fetch JWKs from Supabase's well-known endpoint and cache them.
    This reduces API calls while keeping keys up-to-date.
    """
    try:
        jwks_url = f"{settings.SUPABASE_JWT_ISSUER}/.well-known/jwks.json"
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks = response.json()
        return jwks
    except requests.RequestException as e:
        print(f"Error fetching JWKs: {str(e)}")
        raise Exception(f"Failed to fetch JWKs from Supabase: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"Error parsing JWKs response: {str(e)}")
        raise Exception("Invalid JWKs response from Supabase")


def get_public_key_by_kid(kid: str):
    """
    Get the correct public key based on the token's kid (Key ID).
    This ensures we use the right key for signature verification.
    First tries to fetch from Supabase, then falls back to static key.
    """
    jwks = get_jwks()
    for jwk in jwks.get("keys", []):
    
        if jwk.get("kid") == kid:
            public_key = ECAlgorithm.from_jwk(json.dumps(jwk))
            return public_key
    
    raise Exception(f"No JWK found for kid: {kid}")


def get_token_kid(token: str):
    """
    Extract the Key ID (kid) from the JWT header without verification.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
        return unverified_header.get("kid")
    except Exception as e:
        print(f"Error extracting kid from token: {str(e)}")
        return None


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Verify Supabase JWT token independently using ES256 algorithm.
    Dynamically fetches the correct public key based on the token's kid.
    """
    token = credentials.credentials
    
    try:
        token_kid = get_token_kid(token)
        
        if not token_kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing kid in header",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
        public_key = get_public_key_by_kid(token_kid)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            audience=settings.SUPABASE_JWT_AUDIENCE,
            issuer=settings.SUPABASE_JWT_ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True
            }
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
            detail="Invalid token: Signature verification failed",
            headers={"WWW-Authenticate": "Bearer"},
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

def verify_with_supabase_admin(
    user=Depends(verify_token)
):
    """
    Authenticate user in Supabase from same token.
    """
    user_id = user["sub"]

    try:
        res = supabase_admin.auth.admin.get_user_by_id(user_id)

        if not res or not res.user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in Supabase"
            )

        return {
            "verified": True,
            "verified_by": "supabase-admin",
            "jwt_claims": user,
            "supabase_user": {
                "id": res.user.id,
                "email": res.user.email,
                "role": res.user.role,
                "user_metadata": res.user.user_metadata,
                "app_metadata": res.user.app_metadata,
                "created_at": res.user.created_at
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Supabase admin verification failed: {str(e)}"
        )