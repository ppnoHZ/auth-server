import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from app.config import settings


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
