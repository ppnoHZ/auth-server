from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import OAuthClient, OAuthToken, User
from app.security import decode_access_token, verify_client_secret
from app.time_utils import utc_now

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    token_result = await db.execute(
        select(OAuthToken).where(OAuthToken.access_token == credentials.credentials)
    )
    token_record = token_result.scalar_one_or_none()
    if token_record is not None:
        if token_record.revoked or token_record.expires_at <= utc_now():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked or expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if token_record.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token subject mismatch",
                headers={"WWW-Authenticate": "Bearer"},
            )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


async def authenticate_client(
    client_id: str, client_secret: str, db: AsyncSession
) -> OAuthClient:
    result = await db.execute(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    )
    client = result.scalar_one_or_none()
    if client is None or not verify_client_secret(client_secret, client.client_secret_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )
    return client
