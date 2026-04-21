import json
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import authenticate_client
from app.models import AuthorizationCode, OAuthClient, OAuthToken, User
from app.schemas import TokenIntrospectResponse, TokenResponse
from app.security import (
    create_access_token,
    decode_access_token,
    decode_session_token,
    generate_authorization_code,
    generate_refresh_token,
    hash_password,
    store_auth_code,
    get_and_delete_auth_code,
    verify_password,
    verify_pkce,
)

router = APIRouter(prefix="/oauth2", tags=["oauth2"])
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Helper: get logged-in user from session token cookie
# ---------------------------------------------------------------------------
async def _get_session_user_id(request: Request) -> Optional[str]:
    token = request.cookies.get("session_token")
    if not token:
        return None
    return await decode_session_token(token)


# ---------------------------------------------------------------------------
# GET /oauth2/authorize — show authorization page
# ---------------------------------------------------------------------------
@router.get("/authorize", response_class=HTMLResponse)
async def authorize_get(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(""),
    state: str = Query(""),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type, must be 'code'")

    # Validate client
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    allowed_uris = json.loads(client.redirect_uris)
    if redirect_uri not in allowed_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    if "authorization_code" not in json.loads(client.grant_types):
        raise HTTPException(status_code=400, detail="Client not allowed to use authorization_code grant")

    user_id = await _get_session_user_id(request)
    if not user_id:
        # Redirect to login, then come back. Use quote to ensure the entire URL with its params is treat as one string
        from urllib.parse import quote
        full_path = request.url.path + "?" + request.url.query
        return RedirectResponse(url=f"/login?next={quote(full_path)}", status_code=302)

    return templates.TemplateResponse(
        name="authorize.html", request=request,
        context={
            "client_name": client.client_name,
            "scope": scope,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge or "",
            "code_challenge_method": code_challenge_method or "",
        },
    )


# ---------------------------------------------------------------------------
# POST /oauth2/authorize — user confirms, generate code
# ---------------------------------------------------------------------------
@router.post("/authorize")
async def authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(""),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    approved: str = Form("false"),
    db: AsyncSession = Depends(get_db),
):
    user_id = await _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not logged in")

    if approved != "true":
        # User denied
        params = urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(url=f"{redirect_uri}?{params}", status_code=302)

    code = generate_authorization_code()
    auth_data = {
        "client_id": client_id,
        "user_id": user_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge or None,
        "code_challenge_method": code_challenge_method or None,
        "state": state,
    }
    await store_auth_code(code, auth_data)

    params = urlencode({"code": code, "state": state})
    return RedirectResponse(url=f"{redirect_uri}?{params}", status_code=302)


# ---------------------------------------------------------------------------
# POST /oauth2/token
# ---------------------------------------------------------------------------
@router.post("/token", response_model=TokenResponse)
async def token_endpoint(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    # Authenticate the client
    client = await authenticate_client(client_id, client_secret, db)
    allowed_grants = json.loads(client.grant_types)

    if grant_type not in allowed_grants:
        raise HTTPException(status_code=400, detail=f"Grant type '{grant_type}' not allowed for this client")

    if grant_type == "authorization_code":
        return await _handle_authorization_code(
            code, redirect_uri, client, code_verifier, db
        )
    elif grant_type == "client_credentials":
        return await _handle_client_credentials(client, scope, db)
    elif grant_type == "password":
        return await _handle_password(username, password, client, scope, db)
    elif grant_type == "refresh_token":
        return await _handle_refresh_token(refresh_token, client, db)
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


async def _handle_authorization_code(
    code: Optional[str],
    redirect_uri: Optional[str],
    client: OAuthClient,
    code_verifier: Optional[str],
    db: AsyncSession,
) -> TokenResponse:
    if not code or not redirect_uri:
        raise HTTPException(status_code=400, detail="code and redirect_uri are required")

    # Retrieve and delete from Redis (one-time use)
    auth_data = await get_and_delete_auth_code(code)
    if not auth_data:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    if auth_data["client_id"] != client.client_id:
        raise HTTPException(status_code=400, detail="Code was not issued to this client")
    if auth_data["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri mismatch")

    # PKCE verification
    if auth_data["code_challenge"]:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="code_verifier required for PKCE")
        if not verify_pkce(code_verifier, auth_data["code_challenge"], auth_data["code_challenge_method"] or "S256"):
            raise HTTPException(status_code=400, detail="PKCE verification failed")

    return await _issue_tokens(client.client_id, auth_data["user_id"], auth_data["scope"], db)


async def _handle_client_credentials(
    client: OAuthClient, scope: Optional[str], db: AsyncSession
) -> TokenResponse:
    final_scope = scope or client.scopes
    access_token = create_access_token({"sub": client.client_id, "type": "client"})
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    token_record = OAuthToken(
        access_token=access_token,
        token_type="bearer",
        client_id=client.client_id,
        user_id=None,
        scope=final_scope,
        expires_at=datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    db.add(token_record)
    await db.flush()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        scope=final_scope,
    )


async def _handle_password(
    username: Optional[str],
    password: Optional[str],
    client: OAuthClient,
    scope: Optional[str],
    db: AsyncSession,
) -> TokenResponse:
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="User is inactive")

    final_scope = scope or client.scopes
    return await _issue_tokens(client.client_id, user.id, final_scope, db)


async def _handle_refresh_token(
    refresh_token_value: Optional[str], client: OAuthClient, db: AsyncSession
) -> TokenResponse:
    if not refresh_token_value:
        raise HTTPException(status_code=400, detail="refresh_token is required")

    result = await db.execute(
        select(OAuthToken).where(OAuthToken.refresh_token == refresh_token_value)
    )
    token_record = result.scalar_one_or_none()

    if token_record is None or token_record.revoked:
        raise HTTPException(status_code=400, detail="Invalid or revoked refresh token")
    if token_record.client_id != client.client_id:
        raise HTTPException(status_code=400, detail="Refresh token was not issued to this client")
    if token_record.refresh_token_expires_at and token_record.refresh_token_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Refresh token expired")

    # Revoke old token
    token_record.revoked = True

    return await _issue_tokens(client.client_id, token_record.user_id, token_record.scope, db)


async def _issue_tokens(
    client_id: str, user_id: Optional[str], scope: str, db: AsyncSession
) -> TokenResponse:
    access_token = create_access_token({"sub": user_id, "client_id": client_id, "scope": scope})
    ref_token = generate_refresh_token()
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    token_record = OAuthToken(
        access_token=access_token,
        refresh_token=ref_token,
        token_type="bearer",
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        expires_at=datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        refresh_token_expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(token_record)
    await db.flush()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        refresh_token=ref_token,
        scope=scope,
    )


# ---------------------------------------------------------------------------
# POST /oauth2/revoke (RFC 7009)
# ---------------------------------------------------------------------------
@router.post("/revoke", status_code=200)
async def revoke_token(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    await authenticate_client(client_id, client_secret, db)

    # Try as access_token
    result = await db.execute(
        select(OAuthToken).where(OAuthToken.access_token == token)
    )
    token_record = result.scalar_one_or_none()

    if token_record is None:
        # Try as refresh_token
        result = await db.execute(
            select(OAuthToken).where(OAuthToken.refresh_token == token)
        )
        token_record = result.scalar_one_or_none()

    if token_record:
        token_record.revoked = True

    return {"msg": "ok"}


# ---------------------------------------------------------------------------
# POST /oauth2/introspect (RFC 7662)
# ---------------------------------------------------------------------------
@router.post("/introspect", response_model=TokenIntrospectResponse)
async def introspect_token(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    await authenticate_client(client_id, client_secret, db)

    result = await db.execute(
        select(OAuthToken).where(OAuthToken.access_token == token)
    )
    token_record = result.scalar_one_or_none()

    if token_record is None or token_record.revoked or token_record.expires_at < datetime.utcnow():
        return TokenIntrospectResponse(active=False)

    # Get username if user-bound token
    username = None
    if token_record.user_id:
        user_result = await db.execute(select(User).where(User.id == token_record.user_id))
        user = user_result.scalar_one_or_none()
        if user:
            username = user.username

    return TokenIntrospectResponse(
        active=True,
        scope=token_record.scope,
        client_id=token_record.client_id,
        username=username,
        exp=int(token_record.expires_at.timestamp()),
    )


# ---------------------------------------------------------------------------
# Login pages
# ---------------------------------------------------------------------------
