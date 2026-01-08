from fastapi import APIRouter, HTTPException, Depends, status
from .superbase_client import supabase
from .schemas import AuthRequest, SignupRequest, RefreshRequest
from .security import verify_token, verify_with_supabase_admin
from .token_generator import generate_token_pair, generate_access_token_from_refresh_token
from .config import settings

router = APIRouter(prefix="/auth", tags=["authentication routes"])


@router.post("/signup")
def signup(payload: SignupRequest):
    '''
    API route to handle new users and their registration process
    '''
    if payload.password != payload.confirm_password:
        raise HTTPException(status= status.HTTP_400_BAD_REQUEST, detail= "Password and confirm password missmatched!")
    response = supabase.auth.sign_up({
        "email": payload.email,
        "password": payload.password
    })
    if response.user is None:
        raise HTTPException(status = status.HTTP_400_BAD_REQUEST, detail= "Signup Failed!")
    return {
        "message": "User registered successfully",
        "user_id": response.user.id
    }


@router.post("/login")
def login(payload: AuthRequest):
    '''
    API route to handle the login process of user.
    '''
    
    response = supabase.auth.sign_in_with_password({
        "email": payload.email,
        "password": payload.password
    })
    if not response.user:
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid credentials"
        )
    try:
        tokens = generate_token_pair(
            user_id=response.user.id,
            email=response.user.email,
            role=response.user.role or "authenticated",
            user_metadata=response.user.user_metadata or {},
            app_metadata=response.user.app_metadata or {},
            access_token_expires_in= settings.JWT_EXPIRES_IN,  
            refresh_token_expires_in_days= settings.JWT_REFRESH_EXPIRES_IN_DAYS  
        )
        
        return tokens
        
    except Exception as e:
        print(f"Token generation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate tokens"
        )


@router.post("/refresh")
def refresh_token(payload: RefreshRequest):
    '''
    API route to generate new access token from refresh token(refresh token must not be expired)
    '''
    try:
        new_access_token = generate_access_token_from_refresh_token(payload.refresh_token)
        return new_access_token
    except Exception as e:
        print(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

@router.get("/protected")
def protected(user = Depends(verify_token)):
    '''
    Dummy api to check authorization process of protected api endpoint
    '''
    return {
        "message": "Access granted",
        "user_id": user.get("sub"),
        "email": user.get("email"),
        "role": user.get("role")
    }


@router.get("/verify-with-supabase")
def verify_with_supabase(
    result=Depends(verify_with_supabase_admin)
):
    return result