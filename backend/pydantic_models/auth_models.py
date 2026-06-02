from pydantic import BaseModel


class GoogleAuthRequest(BaseModel):
    id_token: str


class SignupRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class SessionResponse(BaseModel):
    session_token: str
    token_type: str = "bearer"
    user: "UserResponse"


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    profile_pic: str | None = None
