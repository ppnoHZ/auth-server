import json

from typing import List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.client_validation import (
    VALID_GRANT_TYPES,
    validate_client_name,
    validate_grant_types,
    validate_redirect_uris,
    validate_scopes,
)
from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models import OAuthClient, User
from app.schemas import ClientCreate, ClientCreateResponse, ClientResponse
from app.security import generate_client_id, generate_client_secret, hash_client_secret

router = APIRouter(prefix="/clients", tags=["clients"])
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Register client page (UI)
# ---------------------------------------------------------------------------
@router.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_client_page(request: Request):
    # This requires user to be logged in via session cookie
    # Since we don't have a global dependency for HTML routes yet, we check cookie manually or use redirect
    from app.routers.oauth2 import _get_session_user_id
    user_id = await _get_session_user_id(request)
    if not user_id:
        from urllib.parse import quote
        full_path = request.url.path + ("?" + request.url.query if request.url.query else "")
        return RedirectResponse(url=f"/login?next={quote(full_path)}", status_code=302)
    
    return templates.TemplateResponse(
        name="register_client.html",
        request=request,
        context={"allow_password_grant": settings.ALLOW_PASSWORD_GRANT},
    )


@router.post("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_client_submit(
    request: Request,
    client_name: str = Form(...),
    redirect_uris: str = Form(...),
    grant_types: List[str] = Form(...),
    scopes: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    from app.routers.oauth2 import _enforce_same_origin_form, _get_session_user_id
    _enforce_same_origin_form(request)
    user_id = await _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not logged in")

    form_context = {
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "scopes": scopes or "",
        "selected_grant_types": grant_types,
        "allow_password_grant": settings.ALLOW_PASSWORD_GRANT,
    }

    try:
        normalized_name = validate_client_name(client_name)
        normalized_grant_types = validate_grant_types(grant_types)
        uri_list = validate_redirect_uris(
            [u.strip() for u in redirect_uris.split("\n") if u.strip()],
            normalized_grant_types,
        )
        normalized_scopes = validate_scopes(scopes or "")
    except HTTPException as exc:
        return templates.TemplateResponse(
            name="register_client.html",
            request=request,
            context={"error": exc.detail, **form_context},
            status_code=exc.status_code,
        )

    raw_secret = generate_client_secret()
    client_id = generate_client_id()
    
    client = OAuthClient(
        client_id=client_id,
        client_secret_hash=hash_client_secret(raw_secret),
        client_name=normalized_name,
        redirect_uris=json.dumps(uri_list),
        grant_types=json.dumps(normalized_grant_types),
        scopes=normalized_scopes,
        owner_id=user_id,
    )
    db.add(client)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        return templates.TemplateResponse(
            name="register_client.html", request=request,
            context={"error": "Failed to create client. Please try again.", **form_context}
        )

    return templates.TemplateResponse(
        name="register_client.html", request=request,
        context={
            "success": True,
            "client_id": client_id,
            "client_secret": raw_secret,
            "allow_password_grant": settings.ALLOW_PASSWORD_GRANT,
        }
    )


@router.post("/", response_model=ClientCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_client(
    client_in: ClientCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    normalized_name = validate_client_name(client_in.client_name)
    normalized_grant_types = validate_grant_types(client_in.grant_types)
    normalized_redirect_uris = validate_redirect_uris(client_in.redirect_uris, normalized_grant_types)
    normalized_scopes = validate_scopes(client_in.scopes)

    raw_secret = generate_client_secret()
    client = OAuthClient(
        client_id=generate_client_id(),
        client_secret_hash=hash_client_secret(raw_secret),
        client_name=normalized_name,
        redirect_uris=json.dumps(normalized_redirect_uris),
        grant_types=json.dumps(normalized_grant_types),
        scopes=normalized_scopes,
        owner_id=current_user.id,
    )
    db.add(client)
    await db.flush()
    await db.refresh(client)

    return ClientCreateResponse(
        id=client.id,
        client_id=client.client_id,
        client_secret=raw_secret,
        client_name=client.client_name,
        redirect_uris=json.loads(client.redirect_uris),
        grant_types=json.loads(client.grant_types),
        scopes=client.scopes,
        created_at=client.created_at,
    )


@router.get("/", response_model=list[ClientResponse])
async def list_clients(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OAuthClient).where(OAuthClient.owner_id == current_user.id)
    )
    clients = result.scalars().all()
    return [
        ClientResponse(
            id=c.id,
            client_id=c.client_id,
            client_name=c.client_name,
            redirect_uris=json.loads(c.redirect_uris),
            grant_types=json.loads(c.grant_types),
            scopes=c.scopes,
            created_at=c.created_at,
        )
        for c in clients
    ]
