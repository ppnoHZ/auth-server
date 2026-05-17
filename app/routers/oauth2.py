import json
from datetime import timedelta
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import authenticate_client, get_current_user
from app.models import OAuthClient, OAuthToken, User
from app.rate_limit import build_rate_limit_key, clear_failures, enforce_rate_limit, record_failure
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
from app.time_utils import utc_now

router = APIRouter(prefix="/oauth2", tags=["oauth2"])
templates = Jinja2Templates(directory="app/templates")


def _append_redirect_params(redirect_uri: str, params: dict[str, str]) -> str:
    parsed = urlsplit(redirect_uri)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items.extend((key, value) for key, value in params.items() if value is not None)
    return urlunsplit(parsed._replace(query=urlencode(query_items)))


def _enforce_same_origin_form(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return

    origin_parts = urlsplit(origin)
    base_parts = urlsplit(str(request.base_url))
    if (
        origin_parts.scheme != base_parts.scheme
        or origin_parts.hostname != base_parts.hostname
        or origin_parts.port != base_parts.port
    ):
        raise HTTPException(status_code=403, detail="Cross-origin form submission blocked")


def _normalize_scope_string(scope: Optional[str]) -> str:
    if not scope:
        return ""
    normalized_scopes = []
    for item in scope.split():
        if item not in normalized_scopes:
            normalized_scopes.append(item)
    return " ".join(normalized_scopes)


def _validate_requested_scope(client: OAuthClient, requested_scope: Optional[str]) -> str:
    normalized_requested = _normalize_scope_string(requested_scope)
    allowed_scope_set = set(_normalize_scope_string(client.scopes).split())
    requested_scope_set = set(normalized_requested.split())

    if requested_scope_set and not requested_scope_set.issubset(allowed_scope_set):
        raise HTTPException(status_code=400, detail="Requested scope exceeds client permissions")

    return normalized_requested


def _password_grant_rate_limit_key(request: Request, client_id: str, username: Optional[str]) -> str:
    client_host = request.client.host if request.client and request.client.host else "unknown"
    return build_rate_limit_key("password_grant", client_host, client_id, username or "unknown")


async def _validate_authorization_request(
    client_id: str,
    redirect_uri: str,
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
    db: AsyncSession,
) -> OAuthClient:
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    allowed_uris = json.loads(client.redirect_uris)
    if redirect_uri not in allowed_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    if "authorization_code" not in json.loads(client.grant_types):
        raise HTTPException(status_code=400, detail="Client not allowed to use authorization_code grant")

    if code_challenge_method and code_challenge_method not in {"plain", "S256"}:
        raise HTTPException(status_code=400, detail="Unsupported code_challenge_method")
    if code_challenge and not code_challenge_method:
        code_challenge_method = "S256"
    if code_challenge_method and not code_challenge:
        raise HTTPException(status_code=400, detail="code_challenge required when code_challenge_method is provided")

    return client


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

    client = await _validate_authorization_request(
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        db,
    )
    normalized_scope = _validate_requested_scope(client, scope)

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
            "scope": normalized_scope,
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
    _enforce_same_origin_form(request)

    user_id = await _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not logged in")

    client = await _validate_authorization_request(
        client_id,
        redirect_uri,
        code_challenge or None,
        code_challenge_method or None,
        db,
    )
    normalized_scope = _validate_requested_scope(client, scope)

    if approved != "true":
        # User denied
        return RedirectResponse(
            url=_append_redirect_params(redirect_uri, {"error": "access_denied", "state": state}),
            status_code=302,
        )

    code = generate_authorization_code()
    auth_data = {
        "client_id": client_id,
        "user_id": user_id,
        "redirect_uri": redirect_uri,
        "scope": normalized_scope,
        "code_challenge": code_challenge or None,
        "code_challenge_method": code_challenge_method or None,
        "state": state,
    }
    await store_auth_code(code, auth_data)

    return RedirectResponse(
        url=_append_redirect_params(redirect_uri, {"code": code, "state": state}),
        status_code=302,
    )


# ---------------------------------------------------------------------------
# POST /oauth2/token
# ---------------------------------------------------------------------------
@router.post("/token", response_model=TokenResponse)
async def token_endpoint(
    request: Request,
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

    if grant_type == "password" and not settings.ALLOW_PASSWORD_GRANT:
        raise HTTPException(status_code=400, detail="Password grant is disabled")

    if grant_type == "authorization_code":
        return await _handle_authorization_code(
            code, redirect_uri, client, code_verifier, db
        )
    elif grant_type == "client_credentials":
        return await _handle_client_credentials(client, scope, db)
    elif grant_type == "password":
        return await _handle_password(request, username, password, client, scope, db)
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
    final_scope = _validate_requested_scope(client, scope or client.scopes)
    access_token = create_access_token({"sub": client.client_id, "type": "client"})
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    token_record = OAuthToken(
        access_token=access_token,
        token_type="bearer",
        client_id=client.client_id,
        user_id=None,
        scope=final_scope,
        expires_at=utc_now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
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
    request: Request,
    username: Optional[str],
    password: Optional[str],
    client: OAuthClient,
    scope: Optional[str],
    db: AsyncSession,
) -> TokenResponse:
    rate_limit_key = _password_grant_rate_limit_key(request, client.client_id, username)
    await enforce_rate_limit(
        rate_limit_key,
        settings.PASSWORD_GRANT_RATE_LIMIT_ATTEMPTS,
        "Too many failed password grant attempts",
    )

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(password, user.hashed_password):
        await record_failure(rate_limit_key, settings.PASSWORD_GRANT_RATE_LIMIT_WINDOW_SECONDS)
        raise HTTPException(status_code=400, detail="Invalid username or password")
    if not user.is_active:
        await record_failure(rate_limit_key, settings.PASSWORD_GRANT_RATE_LIMIT_WINDOW_SECONDS)
        raise HTTPException(status_code=400, detail="User is inactive")

    await clear_failures(rate_limit_key)
    final_scope = _validate_requested_scope(client, scope or client.scopes)
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
    if token_record.refresh_token_expires_at and token_record.refresh_token_expires_at < utc_now():
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
        expires_at=utc_now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        refresh_token_expires_at=utc_now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
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
    client = await authenticate_client(client_id, client_secret, db)

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

    if token_record and token_record.client_id == client.client_id:
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
    client = await authenticate_client(client_id, client_secret, db)

    result = await db.execute(
        select(OAuthToken).where(OAuthToken.access_token == token)
    )
    token_record = result.scalar_one_or_none()

    if (
        token_record is None
        or token_record.client_id != client.client_id
        or token_record.revoked
        or token_record.expires_at < utc_now()
    ):
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
# GET /oauth2/userinfo — OpenID Connect-style userinfo
# ---------------------------------------------------------------------------
@router.get("/userinfo")
async def userinfo(current_user: User = Depends(get_current_user)):
    return {
        "sub": current_user.id,
        "preferred_username": current_user.username,
        "email": current_user.email,
    }


# ---------------------------------------------------------------------------
# Login pages
# ---------------------------------------------------------------------------
