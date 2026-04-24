import re
import io
import uuid
import random
import string
from fastapi import Depends, FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User, OAuthClient, OAuthToken
from app.routers import clients, oauth2, users
from app.security import hash_password, verify_password, create_session_token
from app.redis import redis_manager

app = FastAPI(title="OAuth2 Authorization Server", version="1.0.0")
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(users.router)
app.include_router(clients.router)
app.include_router(oauth2.router)


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
    # Verify captcha first
    expected_code = await redis_manager.get_json(f"captcha:{captcha_id}")
    if expected_code is None:
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "验证码已过期，请刷新重试", "captcha_id": str(uuid.uuid4())},
        )
    
    # Optional: Delete to prevent reuse
    await redis_manager.delete(f"captcha:{captcha_id}")
    
    if captcha_code.lower() != expected_code:
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "验证码错误，请重新输入", "captcha_id": str(uuid.uuid4())},
        )

    if not username or len(username) < 3 or len(username) > 50 or not re.match(r"^[a-zA-Z0-9_]+$", username):
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "用户名只能包含字母、数字和下划线，且长度必须在3-50个字符之间", "captcha_id": str(uuid.uuid4())},
        )
        
    if not email or len(email) > 100 or not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "请输入有效的电子邮件地址", "captcha_id": str(uuid.uuid4())},
        )
        
    if len(password) < 6 or len(password) > 100:
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "密码长度必须在6-100个字符之间", "captcha_id": str(uuid.uuid4())},
        )
        
    if not (any(c.islower() for c in password) and 
            any(c.isupper() for c in password) and 
            any(c.isdigit() for c in password) and 
            any(not c.isalnum() for c in password)):
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "密码必须包含大写字母、小写字母、数字和至少一个特殊字符", "captcha_id": str(uuid.uuid4())},
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "两次输入的密码不一致", "captcha_id": str(uuid.uuid4())},
        )

    result = await db.execute(
        select(User).where((User.username == username) | (User.email == email))
    )
    if result.scalar_one_or_none():
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "用户名或邮箱已被注册", "captcha_id": str(uuid.uuid4())},
        )

    user = User(username=username, email=email, hashed_password=hash_password(password))
    db.add(user)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        return templates.TemplateResponse(
            name="register.html", request=request,
            context={"error": "注册失败，请稍后再试", "captcha_id": str(uuid.uuid4())},
        )

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

    return templates.TemplateResponse(name="login.html", request=request, context={"next": next_url})


@app.post("/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            name="login.html", request=request,
            context={"next": next, "error": "Invalid username or password"},
        )

    from urllib.parse import unquote
    redirect_url = unquote(next) if next else "/"
    response = RedirectResponse(url=redirect_url, status_code=302)
    
    # Use a session token instead of plain user id
    session_token = await create_session_token(user.id)
    
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=3600,
        samesite="lax",
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
