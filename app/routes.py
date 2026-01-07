from fastapi import APIRouter, HTTPException, Depends, status
from .superbase_client import supabase
from .schemas import AuthRequest, SignupRequest, RefreshRequest
from .security import verify_supabase_jwt


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
    if not response.session:
        raise HTTPException(
            status = status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid credentials"
        )
    return {
        "access_token": response.session.access_token,
        "refresh_token": response.session.refresh_token,
        "expires_in": response.session.expires_in,
        "token_type": "bearer"
    }


@router.post("/refresh")
def refresh_token(payload: RefreshRequest):
    '''
    API route to generate new access token from refresh token(refresh token must not be expired)
    '''
    response = supabase.auth.refresh_session(payload.refresh_token)
    if not response.session:
        raise HTTPException(
            status = status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid refresh token"
        )
    return {
        "access_token": response.session.access_token,
        "refresh_token": response.session.refresh_token,
        "expires_in": response.session.expires_in
    }

@router.get("/protected")
def protected(user = Depends(verify_supabase_jwt)):
    '''
    Dummy api to check authorization process of protected api endpoint
    '''
    return {
        "message": "Access granted",
        "user_id": user.get("sub"),
        "email": user.get("email"),
        "role": user.get("role")
    }
