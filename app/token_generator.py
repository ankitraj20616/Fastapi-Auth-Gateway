from jwt.algorithms import ECAlgorithm
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import uuid
import json
from datetime import datetime, timezone, timedelta
from .config import settings


def load_private_key():
    '''
    This method will load the private key for signing tokens.
    The private key is in JWK format.
    '''
    try:
        if hasattr(settings, "JWT_PRIVATE_KEY"):
            private_jwk = json.loads(settings.JWT_PRIVATE_KEY)
            private_key = ECAlgorithm.from_jwk(json.dumps(private_jwk))
            kid = private_jwk.get("kid")
            return private_key, kid
        else:
            raise Exception("JWT_PRIVATE_KEY is not found in settings/.env")
    except Exception as e:
        print(f"Error in loading private key, error: {str(e)}")
        raise 

def generate_access_token(
    user_id: str,
    email: str,
    role: str = "authenticated",
    user_metadata: dict = None,
    app_metadata: dict = None,
    session_id: str = None,
    expires_in_seconds: int = settings.JWT_EXPIRES_IN
):
    '''
    This method will generate Supabase compatible access token.
    Args:
        user_id: The user's unique identifier
        email: User's email address
        role: User's role (default: "authenticated")
        user_metadata: Additional user metadata
        app_metadata: Application-specific metadata
        session_id: Session identifier
        expires_in_seconds: Token expiration time in seconds
    Returns:
        str: JWT access token
    '''
    try:
        private_key, kid = load_private_key()
        now = datetime.now(timezone.utc)
        exp_time = now + timedelta(seconds= expires_in_seconds)
        if not session_id:
            session_id = str(uuid.uuid4())
        if user_metadata is None:
            user_metadata = {
                "email": email,
                "email_verified": True,
                "phone_verified": False,
                "sub": user_id
            }            
        if app_metadata is None:
            app_metadata = {
                "provider": "email",
                "providers": ["email"]
            }
        payload = {
            "iss": settings.SUPABASE_JWT_ISSUER,  
            "sub": user_id, 
            "aud": settings.SUPABASE_JWT_AUDIENCE, 
            "exp": int(exp_time.timestamp()), 
            "iat": int(now.timestamp()), 
            "email": email,
            "phone": "",
            "app_metadata": app_metadata,
            "user_metadata": user_metadata,
            "role": role,
            "aal": "aal1",  
            "amr": [  
                {
                    "method": "password",
                    "timestamp": int(now.timestamp())
                }
            ],
            "session_id": session_id,
            "is_anonymous": False
        }
        token = jwt.encode(
            payload,
            private_key,
            algorithm= "ES256",
            headers= {"kid": kid}
        )
        return token
    except Exception as e:
        print(f"Error in generating access token: {str(e)}")
        raise

def generate_refresh_token(
    user_id: str,
    session_id: str = None,
    expires_in_days: int = settings.JWT_REFRESH_EXPIRES_IN_DAYS
):
    '''
    This method generates refresh token.
    Note:- Supabase refresh tokens are typically opaque tokens(random string) stored in database.
    This will generates a JWT-based refresh token.
    
    Args:
        user_id: The user's unique identifier
        session_id: Session identifier
        expires_in_days: Token expiration time in days
    
    Returns:
        str: JWT refresh token
    '''
    try:
        private_key, kid = load_private_key()
        now = datetime.now(timezone.utc)
        exp_time = now + timedelta(days= expires_in_days)
        if not session_id:
            session_id = str(uuid.uuid4())

        payload = {
            "iss": settings.SUPABASE_JWT_ISSUER,
            "sub": user_id,
            "aud": settings.SUPABASE_JWT_AUDIENCE,
            "exp": int(exp_time.timestamp()),
            "iat": int(now.timestamp()),
            "session_id": session_id,
            "token_type": "refresh"
        }
        token = jwt.encode(
            payload,
            private_key,
            algorithm="ES256",
            headers= {"kid": kid}
        )
        return token
    except Exception as e:
        print(f"Error generating refresh token: {str(e)}")
        raise

def generate_token_pair(
    user_id: str,
    email: str,
    role: str = "authenticated",
    user_metadata: dict = None,
    app_metadata: dict = None,
    access_token_expires_in: int = settings.JWT_EXPIRES_IN,
    refresh_token_expires_in_days: int = settings.JWT_REFRESH_EXPIRES_IN_DAYS
):
    '''
    This method will generate both access and refresh tokens at once, and returns a dict containing access_token, refresh_token, expires_in, and token_type
    '''
    try:
        session_id = str(uuid.uuid4())
        
        access_token = generate_access_token(
            user_id=user_id,
            email=email,
            role=role,
            user_metadata=user_metadata,
            app_metadata=app_metadata,
            session_id=session_id,
            expires_in_seconds=access_token_expires_in
        )
        
        refresh_token = generate_refresh_token(
            user_id=user_id,
            session_id=session_id,
            expires_in_days=refresh_token_expires_in_days
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": access_token_expires_in,
            "token_type": "bearer",
            "session_id": session_id
        }
    except Exception as e:
        print(f"Error generating token pair: {str(e)}")
        raise

def get_user_data_from_supabase(user_id: str, decoded):
    '''
    This method will fetch current logged in user data from supabase from user id , we need this data in generating new access token from refresh token for current logged in user.
    '''
    from .superbase_client import supabase
    email = decoded.get("email")
    user_metadata = decoded.get("user_metadata", {})
    app_metadata = decoded.get("app_metadata", {})
    role = decoded.get("role", "authenticated")

    try:
        user_response = supabase.auth.admin.get_user_by_id(user_id)

        if user_response and user_response.user:
            email = user_response.user.email
            user_metadata = user_response.user.user_metadata or user_metadata
            app_metadata = user_response.user.app_metadata or app_metadata
            role = user_response.user.role or role

    except Exception as e:
        print(f"Supabase admin fetch failed: {str(e)}")

    return {
        "email": email,
        "user_metadata": user_metadata,
        "app_metadata": app_metadata,
        "role": role
    }

def generate_access_token_from_refresh_token(refresh_token: str):
    '''
    This method will generate new access token from unexpired refresh token

    Args:
        refresh_token: The refresh token
    
    Returns:
        dict: New token pair
    '''
    try:
        private_key, kid = load_private_key()
        from .security import get_public_key_by_kid, get_token_kid
        token_kid = get_token_kid(refresh_token)
        
        decoded = jwt.decode(
            refresh_token,
            options={"verify_signature": False}  
        )
        
        if decoded.get("token_type") != "refresh":
            raise Exception("Not a refresh token")
        
        user_id = decoded.get("sub")
        session_id = decoded.get("session_id")
        data = get_user_data_from_supabase(user_id, decoded)
        
        access_token = generate_access_token(
            user_id=user_id,
            email=data.get("email"),
            role=data.get("role"),
            user_metadata=data.get("user_metadata"),
            app_metadata=data.get("app_metadata"),
            session_id=session_id,
            expires_in_seconds=3600
        )
        
        return {
            "access_token": access_token,
            "expires_in": 3600,
            "token_type": "bearer"
        }
        
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        raise


def generate_new_key_pair():
    '''
    This method will generate a new ES256 key pair in JWK format, use this method only for initial setup or key rotation.
    Store the generated key in .env file securely.
    This method return dict containing private_jwk and public_jwk
    '''
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    private_jwk = json.loads(
        ECAlgorithm.to_jwk(private_key, as_dict= False)
    )
    private_jwk['kid'] = kid
    private_jwk['use'] = "sig"
    private_jwk['alg'] = "ES256"

    public_jwk = json.loads(
        ECAlgorithm.to_jwk(public_key, as_dict= False)
    )
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "ES256"

    return {
        "private_jwk": private_jwk,
        "public_jwk": public_jwk,
        "kid": kid
    }