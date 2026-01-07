from pydantic import BaseModel, EmailStr

class AuthRequest(BaseModel):
    '''
    JSON schema that we need to pass while calling /login route
    '''
    email: EmailStr
    password: str

class SignupRequest(AuthRequest):
    '''
    JSON schema that we need to pass while calling /signup route
    '''
    confirm_password: str

class RefreshRequest(BaseModel):
    ''' 
    JSON schema that we need to pass while calling refresh /routes route to get new access token from refresh token
    '''
    refresh_token: str