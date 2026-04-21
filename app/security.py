import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from app.config import settings
from app.redis import redis_manager


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    # Truncate to 72 bytes directly for bcrypt to avoid ValueError
    pwd_bytes = pwd_bytes[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode("utf-8")
    pwd_bytes = pwd_bytes[:72]
    return bcrypt.checkpw(pwd_bytes, hashed_password.encode("ascii"))


def generate_client_id() -> str:
    return secrets.token_urlsafe(32)


def generate_client_secret() -> str:
    return secrets.token_urlsafe(48)


def hash_client_secret(secret: str) -> str:
    pwd_bytes = secret.encode("utf-8")
    pwd_bytes = pwd_bytes[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("ascii")


def verify_client_secret(plain: str, hashed: str) -> bool:
    pwd_bytes = plain.encode("utf-8")
    pwd_bytes = pwd_bytes[:72]
    return bcrypt.checkpw(pwd_bytes, hashed.encode("ascii"))


def generate_authorization_code() -> str:
    return secrets.token_urlsafe(32)


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        return None


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "plain":
        return code_verifier == code_challenge
    elif method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return computed == code_challenge
    return False


# ---------------------------------------------------------------------------
# Session Token Handling (using JWT + Redis)
# ---------------------------------------------------------------------------
async def create_session_token(user_id: str) -> str:
    """
    Create a JWT specifically for session cookies and store user_id in Redis.
    This hides the user_id from the client and provides server-side control.
    """
    session_id = secrets.token_urlsafe(32)
    to_encode = {
        "jti": session_id,
        "type": "session"
    }
    # Session tokens expire according to a fixed duration
    expire = datetime.utcnow() + timedelta(seconds=settings.SESSION_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    
    # Store session info in Redis
    session_key = f"session:{session_id}"
    await redis_manager.set_json(session_key, {"user_id": str(user_id)}, expire=settings.SESSION_EXPIRE_SECONDS)
    
    return token


async def decode_session_token(token: str) -> Optional[str]:
    """
    Decodes the session JWT and returns the user_id from Redis.
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != "session":
            return None
        
        session_id = payload.get("jti")
        if not session_id:
            return None
            
        session_key = f"session:{session_id}"
        session_data = await redis_manager.get_json(session_key)
        if session_data:
            return session_data.get("user_id")
            
        return None
    except JWTError:
        return None


async def revoke_session(token: str):
    """Delete session from Redis"""
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        session_id = payload.get("jti")
        if session_id:
            await redis_manager.delete(f"session:{session_id}")
    except JWTError:
        pass


# ---------------------------------------------------------------------------
# Authorization Code Storage (using Redis)
# ---------------------------------------------------------------------------
async def store_auth_code(code: str, auth_data: dict):
    """Store authorization code data in Redis"""
    key = f"auth_code:{code}"
    await redis_manager.set_json(key, auth_data, expire=settings.AUTH_CODE_EXPIRE_SECONDS)


async def get_and_delete_auth_code(code: str) -> Optional[dict]:
    """Retrieve and immediately delete auth code data from Redis (one-time use)"""
    key = f"auth_code:{code}"
    auth_data = await redis_manager.get_json(key)
    if auth_data:
        await redis_manager.delete(key)
    return auth_data
