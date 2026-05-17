from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.rate_limit import build_rate_limit_key, clear_failures, enforce_rate_limit, record_failure
from app.schemas import UserCreate, UserResponse
from app.security import hash_password
from app.user_validation import validate_email, validate_password, validate_username

router = APIRouter(prefix="/users", tags=["users"])


def _user_register_rate_limit_key(request: Request, username: str, email: str) -> str:
    client_host = request.client.host if request.client and request.client.host else "unknown"
    return build_rate_limit_key("user_register", client_host, username, email)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    rate_limit_key = _user_register_rate_limit_key(request, user_in.username, user_in.email)
    await enforce_rate_limit(
        rate_limit_key,
        settings.USER_REGISTER_RATE_LIMIT_ATTEMPTS,
        "Too many failed registration attempts",
    )

    try:
        normalized_username = validate_username(user_in.username)
        normalized_email = validate_email(user_in.email)
        validate_password(user_in.password)
    except ValueError as exc:
        await record_failure(rate_limit_key, settings.USER_REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Check uniqueness
    result = await db.execute(
        select(User).where((User.username == normalized_username) | (User.email == normalized_email))
    )
    if result.scalar_one_or_none():
        await record_failure(rate_limit_key, settings.USER_REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already exists")

    user = User(
        username=normalized_username,
        email=normalized_email,
        hashed_password=hash_password(user_in.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await clear_failures(rate_limit_key)
    return user


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
