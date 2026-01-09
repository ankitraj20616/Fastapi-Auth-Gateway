from fastapi import APIRouter, HTTPException, Depends, status, Request
from .superbase_client import supabase
from .schemas import AuthRequest, SignupRequest, RefreshRequest
from .security import verify_token, verify_with_supabase_admin
from .token_generator import generate_token_pair, generate_access_token_from_refresh_token
from .config import settings
from .cores import forward_authenticated_user

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
    '''
    Dummy api to check authorization process on Supabase of protected api endpoint using same token
    '''
    return result




@router.api_route(
    "/proxy/{target_path:path}",
    methods= ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
)
async def proxy_endpoint(
    request: Request,
    target_path: str,
    user: dict = Depends(verify_token)
):
    '''
    Universal proxy endpoint that forwards authenticated requests to another service.
    
    This endpoint:
        Validates user authentication via JWT token
        Forwards the request to PROXY_TARGET_URL with all original data intact
        Preserves headers, body, query parameters, and HTTP method
        Returns the target service's response as-is
    
    Usage Examples:
        GET /auth/proxy/posts/1
            forwards to TARGET_URL/posts/1
        
        POST /auth/proxy/posts
            forwards to TARGET_URL/posts
        
        PUT /auth/proxy/posts/123
            forwards to TARGET_URL/posts/123
    
    Headers added for downstream service:
        X-User-ID: User's ID from JWT
        X-User-Email: User's email from JWT
        X-User-Role: User's role from JWT
    '''
    if target_path.startswith('/'):
        target_path = target_path[1:]
    return await forward_authenticated_user(request, target_path, user)


@router.get("/proxy/health")
async def proxy_health():
    '''
    Simple test endpoint to verify proxy route is accessible
    '''
    return {
        "status": "ok",
        "target_url": settings.PROXY_TARGET_URL,
        "message": "Proxy server is running"
    }


@router.get("/proxy/proxy-test")
async def proxy_test(user: dict = Depends(verify_token)):
    '''
    Simple test endpoint to verify proxy route is accessible
    '''
    return {
        "message": "Proxy route is accessible",
        "user": user.get("email"),
        "test_url": f"{settings.PROXY_TARGET_URL}/posts/1"
    }