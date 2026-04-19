import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    resp = await client.post("/users/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "secret123",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "testuser"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_user(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "dupuser", "email": "dup@example.com", "password": "pass",
    })
    resp = await client.post("/users/register", json={
        "username": "dupuser", "email": "dup2@example.com", "password": "pass",
    })
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_password_grant(client: AsyncClient):
    # Register user
    await client.post("/users/register", json={
        "username": "pwduser", "email": "pwd@example.com", "password": "mypassword",
    })

    # Get access token to create a client
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "pwduser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    # Create OAuth client
    resp = await client.post("/clients/", json={
        "client_name": "Test App",
        "redirect_uris": ["http://localhost/callback"],
        "grant_types": ["password", "refresh_token"],
        "scopes": "read write",
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    client_data = resp.json()
    cid = client_data["client_id"]
    csecret = client_data["client_secret"]

    # Password grant
    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "pwduser",
        "password": "mypassword",
        "client_id": cid,
        "client_secret": csecret,
    })
    assert resp.status_code == 200
    token_data = resp.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "bearer"

    # Use access token to get /users/me
    resp = await client.get("/users/me", headers={
        "Authorization": f"Bearer {token_data['access_token']}"
    })
    assert resp.status_code == 200
    assert resp.json()["username"] == "pwduser"


@pytest.mark.asyncio
async def test_client_credentials_grant(client: AsyncClient):
    # Register user and get token
    await client.post("/users/register", json={
        "username": "ccuser", "email": "cc@example.com", "password": "pass",
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "ccuser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    # Create client with client_credentials grant
    resp = await client.post("/clients/", json={
        "client_name": "Service App",
        "redirect_uris": [],
        "grant_types": ["client_credentials"],
        "scopes": "read",
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    client_data = resp.json()

    # Client credentials grant
    resp = await client.post("/oauth2/token", data={
        "grant_type": "client_credentials",
        "client_id": client_data["client_id"],
        "client_secret": client_data["client_secret"],
    })
    assert resp.status_code == 200
    token_data = resp.json()
    assert "access_token" in token_data
    assert token_data.get("refresh_token") is None


@pytest.mark.asyncio
async def test_refresh_token_grant(client: AsyncClient):
    # Register and setup
    await client.post("/users/register", json={
        "username": "rtuser", "email": "rt@example.com", "password": "pass",
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "rtuser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "RT App",
        "redirect_uris": ["http://localhost/callback"],
        "grant_types": ["password", "refresh_token"],
    }, headers={"Authorization": f"Bearer {token}"})
    client_data = resp.json()
    cid = client_data["client_id"]
    csecret = client_data["client_secret"]

    # Get initial tokens via password grant
    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "rtuser",
        "password": "pass",
        "client_id": cid,
        "client_secret": csecret,
    })
    token_data = resp.json()
    old_refresh = token_data["refresh_token"]

    # Refresh
    resp = await client.post("/oauth2/token", data={
        "grant_type": "refresh_token",
        "refresh_token": old_refresh,
        "client_id": cid,
        "client_secret": csecret,
    })
    assert resp.status_code == 200
    new_data = resp.json()
    assert new_data["access_token"] != token_data["access_token"]
    assert new_data["refresh_token"] != old_refresh

    # Old refresh token should be revoked
    resp = await client.post("/oauth2/token", data={
        "grant_type": "refresh_token",
        "refresh_token": old_refresh,
        "client_id": cid,
        "client_secret": csecret,
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_token_revoke(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "revuser", "email": "rev@example.com", "password": "pass",
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "revuser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "Rev App",
        "redirect_uris": [],
        "grant_types": ["password", "refresh_token"],
    }, headers={"Authorization": f"Bearer {token}"})
    client_data = resp.json()
    cid = client_data["client_id"]
    csecret = client_data["client_secret"]

    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "revuser",
        "password": "pass",
        "client_id": cid,
        "client_secret": csecret,
    })
    token_data = resp.json()

    # Revoke
    resp = await client.post("/oauth2/revoke", data={
        "token": token_data["access_token"],
        "client_id": cid,
        "client_secret": csecret,
    })
    assert resp.status_code == 200

    # Introspect should show inactive
    resp = await client.post("/oauth2/introspect", data={
        "token": token_data["access_token"],
        "client_id": cid,
        "client_secret": csecret,
    })
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_introspect_active_token(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "introuser", "email": "intro@example.com", "password": "pass",
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "introuser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "Intro App",
        "redirect_uris": [],
        "grant_types": ["password"],
    }, headers={"Authorization": f"Bearer {token}"})
    client_data = resp.json()
    cid = client_data["client_id"]
    csecret = client_data["client_secret"]

    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "introuser",
        "password": "pass",
        "client_id": cid,
        "client_secret": csecret,
    })
    token_data = resp.json()

    resp = await client.post("/oauth2/introspect", data={
        "token": token_data["access_token"],
        "client_id": cid,
        "client_secret": csecret,
    })
    assert resp.status_code == 200
    intro = resp.json()
    assert intro["active"] is True
    assert intro["username"] == "introuser"
