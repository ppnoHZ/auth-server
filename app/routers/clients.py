import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models import OAuthClient, User
from app.schemas import ClientCreate, ClientCreateResponse, ClientResponse
from app.security import generate_client_id, generate_client_secret, hash_client_secret

router = APIRouter(prefix="/clients", tags=["clients"])


@router.post("/", response_model=ClientCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_client(
    client_in: ClientCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    valid_grant_types = {"authorization_code", "client_credentials", "password", "refresh_token"}
    for gt in client_in.grant_types:
        if gt not in valid_grant_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid grant type: {gt}",
            )

    raw_secret = generate_client_secret()
    client = OAuthClient(
        client_id=generate_client_id(),
        client_secret_hash=hash_client_secret(raw_secret),
        client_name=client_in.client_name,
        redirect_uris=json.dumps(client_in.redirect_uris),
        grant_types=json.dumps(client_in.grant_types),
        scopes=client_in.scopes,
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
