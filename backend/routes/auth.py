from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from db.db import get_db
from db.models.user import User
from helper.auth_helper import verify_google_token, hash_password, verify_password, create_session, delete_session, get_current_user, security
from pydantic_models.auth_models import GoogleAuthRequest, SignupRequest, LoginRequest, SessionResponse, UserResponse

router = APIRouter()


@router.post("/signup")
def signup(data: SignupRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        name=data.name,
        email=data.email,
        password_hash=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    session_token = create_session(user.id)

    return SessionResponse(
        session_token=session_token,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            profile_pic=user.profile_pic,
        ),
    )


@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not user.password_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    session_token = create_session(user.id)

    return SessionResponse(
        session_token=session_token,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            profile_pic=user.profile_pic,
        ),
    )


@router.post("/google")
def google_auth(data: GoogleAuthRequest, db: Session = Depends(get_db)):
    info = verify_google_token(data.id_token)

    google_id = info["sub"]
    email = info["email"]
    name = info.get("name", "")
    profile_pic = info.get("picture")

    user = db.query(User).filter(User.google_id == google_id).first()
    if not user:
        user = User(
            name=name,
            email=email,
            google_id=google_id,
            profile_pic=profile_pic,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    session_token = create_session(user.id)

    return SessionResponse(
        session_token=session_token,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            profile_pic=user.profile_pic,
        ),
    )


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        profile_pic=current_user.profile_pic,
    )


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    delete_session(credentials.credentials)
    return {"message": "Logged out successfully"}
