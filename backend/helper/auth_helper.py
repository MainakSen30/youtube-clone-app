import json
import secrets
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from google.oauth2 import id_token
from google.auth.transport import requests
import bcrypt as _bcrypt
from sqlalchemy.orm import Session
from db.db import get_db
from db.models.user import User
from helper.redis import get_redis
from secret_keys import SecretKeys

security = HTTPBearer()
secret_keys = SecretKeys()


def verify_google_token(token: str) -> dict:
    try:
        info = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            secret_keys.GOOGLE_CLIENT_ID,
        )
        if info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid issuer",
            )
        return info
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


def create_session(user_id: int) -> str:
    redis_client = get_redis()
    session_token = secrets.token_urlsafe(32)
    ttl_seconds = secret_keys.SESSION_TTL_MINUTES * 60
    session_data = json.dumps({"user_id": user_id, "created_at": datetime.now(timezone.utc).isoformat()})
    redis_client.setex(f"session:{session_token}", ttl_seconds, session_data)
    return session_token


def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return _bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def delete_session(session_token: str) -> None:
    redis_client = get_redis()
    redis_client.delete(f"session:{session_token}")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    redis_client = get_redis()
    session_data = redis_client.get(f"session:{credentials.credentials}")
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    try:
        payload = json.loads(session_data)
        user_id = payload["user_id"]
    except (json.JSONDecodeError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session data",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user
