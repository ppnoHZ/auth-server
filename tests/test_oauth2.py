import pytest
from httpx import AsyncClient

from app.config import settings
from app.routers import oauth2 as oauth2_router
from app.routers import users as users_router


STRONG_PASSWORD = "StrongPass1!"


@pytest.fixture
def enable_password_grant(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "ALLOW_PASSWORD_GRANT", True)


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    resp = await client.post("/users/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": STRONG_PASSWORD,
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "testuser"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_user(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "dupuser", "email": "dup@example.com", "password": STRONG_PASSWORD,
    })
    resp = await client.post("/users/register", json={
        "username": "dupuser", "email": "dup2@example.com", "password": STRONG_PASSWORD,
    })
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_user_rejects_weak_password(client: AsyncClient):
    resp = await client.post("/users/register", json={
        "username": "weakuser",
        "email": "weak@example.com",
        "password": "weakpass",
    })

    assert resp.status_code == 400
    assert resp.json()["detail"] == "密码必须包含大写字母、小写字母、数字和至少一个特殊字符"


@pytest.mark.asyncio
async def test_register_user_rate_limit_returns_429(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_enforce_rate_limit(_key: str, _max_attempts: int, _detail: str) -> None:
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="Too many failed registration attempts")

    monkeypatch.setattr(users_router, "enforce_rate_limit", fake_enforce_rate_limit)

    resp = await client.post("/users/register", json={
        "username": "limituser",
        "email": "limit@example.com",
        "password": STRONG_PASSWORD,
    })

    assert resp.status_code == 429
    assert resp.json()["detail"] == "Too many failed registration attempts"


@pytest.mark.asyncio
async def test_password_grant(client: AsyncClient, enable_password_grant):
    # Register user
    await client.post("/users/register", json={
        "username": "pwduser", "email": "pwd@example.com", "password": STRONG_PASSWORD,
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
        "password": STRONG_PASSWORD,
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
        "username": "ccuser", "email": "cc@example.com", "password": STRONG_PASSWORD,
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
async def test_create_client_rejects_insecure_public_redirect_uri(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "rediruser",
        "email": "redir@example.com",
        "password": STRONG_PASSWORD,
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "rediruser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "Insecure App",
        "redirect_uris": ["http://example.com/callback"],
        "grant_types": ["authorization_code"],
        "scopes": "openid",
    }, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Public redirect URIs must use https"


@pytest.mark.asyncio
async def test_create_client_rejects_redirect_uri_fragment(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "fraguser",
        "email": "frag@example.com",
        "password": STRONG_PASSWORD,
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "fraguser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "Fragment App",
        "redirect_uris": ["https://example.com/callback#fragment"],
        "grant_types": ["authorization_code"],
        "scopes": "openid",
    }, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Redirect URI must not contain a fragment"


@pytest.mark.asyncio
async def test_refresh_token_grant(client: AsyncClient, enable_password_grant):
    # Register and setup
    await client.post("/users/register", json={
        "username": "rtuser", "email": "rt@example.com", "password": STRONG_PASSWORD,
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
        "password": STRONG_PASSWORD,
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
async def test_token_revoke(client: AsyncClient, enable_password_grant):
    await client.post("/users/register", json={
        "username": "revuser", "email": "rev@example.com", "password": STRONG_PASSWORD,
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
        "password": STRONG_PASSWORD,
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

    resp = await client.get("/users/me", headers={
        "Authorization": f"Bearer {token_data['access_token']}"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_introspect_active_token(client: AsyncClient, enable_password_grant):
    await client.post("/users/register", json={
        "username": "introuser", "email": "intro@example.com", "password": STRONG_PASSWORD,
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
        "password": STRONG_PASSWORD,
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


@pytest.mark.asyncio
async def test_client_cannot_revoke_another_clients_token(client: AsyncClient, enable_password_grant):
    await client.post("/users/register", json={
        "username": "owneruser",
        "email": "owner@example.com",
        "password": STRONG_PASSWORD,
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "owneruser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "App One",
        "redirect_uris": ["http://localhost/one"],
        "grant_types": ["password", "refresh_token"],
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    client_one = resp.json()

    resp = await client.post("/clients/", json={
        "client_name": "App Two",
        "redirect_uris": ["http://localhost/two"],
        "grant_types": ["password", "refresh_token"],
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    client_two = resp.json()

    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "owneruser",
        "password": STRONG_PASSWORD,
        "client_id": client_one["client_id"],
        "client_secret": client_one["client_secret"],
    })
    assert resp.status_code == 200
    issued_token = resp.json()["access_token"]

    resp = await client.post("/oauth2/revoke", data={
        "token": issued_token,
        "client_id": client_two["client_id"],
        "client_secret": client_two["client_secret"],
    })
    assert resp.status_code == 200

    resp = await client.post("/oauth2/introspect", data={
        "token": issued_token,
        "client_id": client_one["client_id"],
        "client_secret": client_one["client_secret"],
    })
    assert resp.status_code == 200
    assert resp.json()["active"] is True

    resp = await client.post("/oauth2/introspect", data={
        "token": issued_token,
        "client_id": client_two["client_id"],
        "client_secret": client_two["client_secret"],
    })
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_authorize_post_rejects_tampered_redirect_uri(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    await client.post("/users/register", json={
        "username": "authuser",
        "email": "auth@example.com",
        "password": "StrongPass1!",
    })

    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import OAuthClient, User
    from app.security import generate_client_id, generate_client_secret, hash_client_secret

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "authuser"))
        user = result.scalar_one()
        oauth_client = OAuthClient(
            client_id=generate_client_id(),
            client_secret_hash=hash_client_secret(generate_client_secret()),
            client_name="Tamper Test App",
            redirect_uris='["http://localhost/callback"]',
            grant_types='["authorization_code"]',
            scopes="openid profile",
            owner_id=user.id,
        )
        db.add(oauth_client)
        await db.commit()
        await db.refresh(oauth_client)

    async def fake_session_user_id(_request):
        return user.id

    monkeypatch.setattr(oauth2_router, "_get_session_user_id", fake_session_user_id)

    resp = await client.post("/oauth2/authorize", data={
        "client_id": oauth_client.client_id,
        "redirect_uri": "http://evil.example/callback",
        "scope": "openid profile",
        "state": "abc123",
        "code_challenge": "challenge",
        "code_challenge_method": "S256",
        "approved": "true",
    })

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid redirect_uri"


@pytest.mark.asyncio
async def test_authorize_post_rejects_cross_origin_form(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    await client.post("/users/register", json={
        "username": "originuser",
        "email": "origin@example.com",
        "password": "StrongPass1!",
    })

    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import OAuthClient, User
    from app.security import generate_client_id, generate_client_secret, hash_client_secret

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "originuser"))
        user = result.scalar_one()
        oauth_client = OAuthClient(
            client_id=generate_client_id(),
            client_secret_hash=hash_client_secret(generate_client_secret()),
            client_name="Origin Test App",
            redirect_uris='["http://localhost/callback"]',
            grant_types='["authorization_code"]',
            scopes="openid profile",
            owner_id=user.id,
        )
        db.add(oauth_client)
        await db.commit()
        await db.refresh(oauth_client)

    async def fake_session_user_id(_request):
        return user.id

    monkeypatch.setattr(oauth2_router, "_get_session_user_id", fake_session_user_id)

    resp = await client.post("/oauth2/authorize", data={
        "client_id": oauth_client.client_id,
        "redirect_uri": "http://localhost/callback",
        "scope": "openid",
        "state": "state-1",
        "approved": "true",
    }, headers={"Origin": "http://evil.example"})

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Cross-origin form submission blocked"


@pytest.mark.asyncio
async def test_password_grant_rejects_scope_escalation(client: AsyncClient, enable_password_grant):
    await client.post("/users/register", json={
        "username": "scopeuser",
        "email": "scope@example.com",
        "password": STRONG_PASSWORD,
    })

    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "scopeuser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "Scoped App",
        "redirect_uris": ["http://localhost/callback"],
        "grant_types": ["password"],
        "scopes": "read profile",
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    client_data = resp.json()

    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "scopeuser",
        "password": STRONG_PASSWORD,
        "client_id": client_data["client_id"],
        "client_secret": client_data["client_secret"],
        "scope": "read admin",
    })

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Requested scope exceeds client permissions"


@pytest.mark.asyncio
async def test_authorize_get_rejects_scope_escalation(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "webscopeuser",
        "email": "webscope@example.com",
        "password": "StrongPass1!",
    })

    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import OAuthClient, User
    from app.security import generate_client_id, generate_client_secret, hash_client_secret

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "webscopeuser"))
        user = result.scalar_one()
        oauth_client = OAuthClient(
            client_id=generate_client_id(),
            client_secret_hash=hash_client_secret(generate_client_secret()),
            client_name="Scope Test App",
            redirect_uris='["http://localhost/callback"]',
            grant_types='["authorization_code"]',
            scopes="openid profile",
            owner_id=user.id,
        )
        db.add(oauth_client)
        await db.commit()
        await db.refresh(oauth_client)

    resp = await client.get("/oauth2/authorize", params={
        "response_type": "code",
        "client_id": oauth_client.client_id,
        "redirect_uri": "http://localhost/callback",
        "scope": "openid admin",
        "state": "xyz",
    })

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Requested scope exceeds client permissions"


@pytest.mark.asyncio
async def test_password_grant_rate_limit_returns_429(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    enable_password_grant,
):
    from types import SimpleNamespace

    async def fake_enforce_rate_limit(_key: str, _max_attempts: int, _detail: str) -> None:
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="Too many failed password grant attempts")

    async def fake_authenticate_client(_client_id: str, _client_secret: str, _db):
        return SimpleNamespace(client_id="client-id", grant_types='["password"]', scopes="")

    monkeypatch.setattr(oauth2_router, "enforce_rate_limit", fake_enforce_rate_limit)
    monkeypatch.setattr(oauth2_router, "authenticate_client", fake_authenticate_client)

    resp = await client.post("/oauth2/token", data={
        "grant_type": "password",
        "username": "rateuser",
        "password": "wrong",
        "client_id": "client-id",
        "client_secret": "client-secret",
    })

    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_create_client_rejects_password_grant_when_disabled(client: AsyncClient):
    await client.post("/users/register", json={
        "username": "disabledgrantuser",
        "email": "disabledgrant@example.com",
        "password": "StrongPass1!",
    })
    from app.security import create_access_token
    from tests.conftest import TestSessionLocal
    from sqlalchemy import select
    from app.models import User

    async with TestSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "disabledgrantuser"))
        user = result.scalar_one()
        token = create_access_token({"sub": user.id})

    resp = await client.post("/clients/", json={
        "client_name": "Disabled Grant App",
        "redirect_uris": ["http://localhost/callback"],
        "grant_types": ["password"],
        "scopes": "read",
    }, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Password grant is disabled"
