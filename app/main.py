import io
import uuid
import random
import string
from urllib.parse import unquote, urlsplit
from fastapi import Depends, FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import User, OAuthClient, OAuthToken
from app.rate_limit import build_rate_limit_key, clear_failures, get_retry_after, record_failure
from app.routers import clients, oauth2, users
from app.routers.oauth2 import _enforce_same_origin_form
from app.security import hash_password, verify_password, create_session_token
from app.redis import redis_manager
from app.user_validation import validate_email, validate_password, validate_username

app = FastAPI(title="OAuth2 Authorization Server", version="1.0.0")
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(users.router)
app.include_router(clients.router)
app.include_router(oauth2.router)


def _normalize_next_url(next_url: str) -> str:
    if not next_url:
        return ""

    decoded = unquote(next_url).strip()
    if not decoded.startswith("/") or decoded.startswith("//"):
        return ""

    parsed = urlsplit(decoded)
    if parsed.scheme or parsed.netloc:
        return ""

    return decoded


def _client_ip(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def _login_rate_limit_key(request: Request, username: str) -> str:
    return build_rate_limit_key("login", _client_ip(request), username)


def _register_rate_limit_key(request: Request) -> str:
    return build_rate_limit_key("register", _client_ip(request))


# ---------------------------------------------------------------------------
# Register pages (top-level /register)
# ---------------------------------------------------------------------------
@app.get("/captcha/{captcha_id}", include_in_schema=False)
async def generate_captcha(captcha_id: str):
    from captcha.image import ImageCaptcha
    # Only keep simple letters and numbers to avoid confusion (like O and 0, or I and 1)
    chars = "ABCDEFGHJKLMNPRSTUVWXYZ23456789"
    code = ''.join(random.choices(chars, k=4))
    
    # Store the captcha text in Redis mapped to the captcha_id
    await redis_manager.set_json(f"captcha:{captcha_id}", code.lower(), expire=300)
    
    image = ImageCaptcha(width=160, height=60)
    data = image.generate(code)
    return StreamingResponse(io.BytesIO(data.getvalue()), media_type="image/png")


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_page(request: Request):
    captcha_id = str(uuid.uuid4())
    return templates.TemplateResponse(
        name="register.html", 
        request=request, 
        context={"captcha_id": captcha_id}
    )


@app.post("/register", include_in_schema=False)
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    captcha_id: str = Form(...),
    captcha_code: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    register_key = _register_rate_limit_key(request)
    retry_after = await get_retry_after(register_key, settings.REGISTER_RATE_LIMIT_ATTEMPTS)
    if retry_after > 0:
        return templates.TemplateResponse(
            name="register.html",
            request=request,
            context={
                "error": f"尝试过于频繁，请在 {retry_after} 秒后重试",
                "captcha_id": str(uuid.uuid4()),
                "username": username,
                "email": email,
                "captcha_code": captcha_code,
            },
            status_code=429,
        )

    form_context = {
        "username": username,
        "email": email,
        "captcha_code": captcha_code,
    }

    # Verify captcha first
    expected_code = await redis_manager.get_json(f"captcha:{captcha_id}")
    if expected_code is None:
        await record_failure(register_key, settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "验证码已过期，请刷新重试", "captcha_id": str(uuid.uuid4()), **form_context},
        )
    
    # Optional: Delete to prevent reuse
    await redis_manager.delete(f"captcha:{captcha_id}")
    
    if captcha_code.lower() != expected_code:
        await record_failure(register_key, settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "验证码错误，请重新输入", "captcha_id": str(uuid.uuid4()), **form_context},
        )

    try:
        normalized_username = validate_username(username)
        normalized_email = validate_email(email)
        validate_password(password)
    except ValueError as exc:
        await record_failure(register_key, settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="register.html",
            request=request,
            context={"error": str(exc), "captcha_id": str(uuid.uuid4()), **form_context},
        )

    if password != confirm_password:
        await record_failure(register_key, settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "两次输入的密码不一致", "captcha_id": str(uuid.uuid4()), **form_context},
        )

    result = await db.execute(
        select(User).where((User.username == normalized_username) | (User.email == normalized_email))
    )
    if result.scalar_one_or_none():
        await record_failure(register_key, settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "用户名或邮箱已被注册", "captcha_id": str(uuid.uuid4()), **form_context},
        )

    user = User(username=normalized_username, email=normalized_email, hashed_password=hash_password(password))
    db.add(user)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        await record_failure(register_key, settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "注册失败，请稍后再试", "captcha_id": str(uuid.uuid4()), **form_context},
        )

    await clear_failures(register_key)
    return templates.TemplateResponse(
        name="register.html", request=request,
        context={"success": "注册成功！您现在可以登录了。"},
    )


# ---------------------------------------------------------------------------
# Login pages (top-level /login)
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    # Get the raw query string to preserve all parameters in 'next'
    query_params = dict(request.query_params)
    next_url = query_params.get("next", "")
    
    # If there are other parameters besides 'next', they might be part of the next URL's own queries
    # but FastAPI/Starlette split them. We need to reconstruct the full next URL if it was passed 
    # as ?next=/path?a=1&b=2 (which arrives as next=/path?a=1 AND b=2)
    raw_query = request.url.query
    if "next=" in raw_query:
        # Extract everything after "next="
        parts = raw_query.split("next=", 1)
        if len(parts) > 1:
            next_url = parts[1]

    return templates.TemplateResponse(
        name="login.html",
        request=request,
        context={"next": _normalize_next_url(next_url)},
    )


@app.post("/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _enforce_same_origin_form(request)

    login_key = _login_rate_limit_key(request, username)
    retry_after = await get_retry_after(login_key, settings.LOGIN_RATE_LIMIT_ATTEMPTS)
    if retry_after > 0:
        return templates.TemplateResponse(
            name="login.html",
            request=request,
            context={
                "next": _normalize_next_url(next),
                "error": f"Too many failed attempts. Try again in {retry_after} seconds.",
            },
            status_code=429,
        )

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(password, user.hashed_password):
        await record_failure(login_key, settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)
        return templates.TemplateResponse(
            name="login.html", request=request,
            context={"next": _normalize_next_url(next), "error": "Invalid username or password"},
        )

    await clear_failures(login_key)
    redirect_url = _normalize_next_url(next) or "/"
    response = RedirectResponse(url=redirect_url, status_code=302)
    
    # Use a session token instead of plain user id
    session_token = await create_session_token(user.id)
    
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=settings.SESSION_EXPIRE_SECONDS,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, db: AsyncSession = Depends(get_db)):
    users_count = await db.scalar(select(func.count(User.id)))
    clients_count = await db.scalar(select(func.count(OAuthClient.id)))
    tokens_count = await db.scalar(select(func.count(OAuthToken.id)))

    # Count active vs revoked tokens
    active_tokens_count = await db.scalar(
        select(func.count(OAuthToken.id)).where(OAuthToken.revoked == False)
    )

    stats = {
        "users": users_count or 0,
        "clients": clients_count or 0,
        "total_tokens": tokens_count or 0,
        "active_tokens": active_tokens_count or 0,
    }

    return templates.TemplateResponse(
        name="index.html", 
        request=request, 
        context={"stats": stats}
    )
