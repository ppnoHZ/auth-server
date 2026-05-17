import pytest
from httpx import AsyncClient

from app.config import settings
from app import main as main_module
from app.routers import oauth2 as oauth2_router


@pytest.mark.asyncio
async def test_dashboard_renders_updated_sections(client: AsyncClient):
    resp = await client.get("/")

    assert resp.status_code == 200
    assert "OAuth2 server dashboard" in resp.text
    assert "Quick actions" in resp.text
    assert "Register client app" in resp.text


@pytest.mark.asyncio
async def test_register_page_renders_accessible_form(client: AsyncClient):
    resp = await client.get("/register")

    assert resp.status_code == 200
    assert 'id="register-title"' in resp.text
    assert 'name="captcha_code"' in resp.text
    assert "Create your account" in resp.text


@pytest.mark.asyncio
async def test_register_validation_preserves_non_password_fields(client: AsyncClient):
    resp = await client.post(
        "/register",
        data={
            "username": "htmluser",
            "email": "html@example.com",
            "password": "short",
            "confirm_password": "short",
            "captcha_id": "missing-captcha",
            "captcha_code": "ABCD",
        },
    )

    assert resp.status_code == 200
    assert 'value="htmluser"' in resp.text
    assert 'value="html@example.com"' in resp.text
    assert 'value="ABCD"' in resp.text


@pytest.mark.asyncio
async def test_login_rejects_external_next_redirect(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_create_session_token(_user_id: str) -> str:
        return "session-token"

    async def fake_get_retry_after(_key: str, _max_attempts: int) -> int:
        return 0

    monkeypatch.setattr(main_module, "create_session_token", fake_create_session_token)
    monkeypatch.setattr(main_module, "get_retry_after", fake_get_retry_after)

    await client.post(
        "/users/register",
        json={
            "username": "safeuser",
            "email": "safe@example.com",
            "password": "Abcd1234!",
        },
    )

    resp = await client.post(
        "/login",
        data={
            "username": "safeuser",
            "password": "Abcd1234!",
            "next": "https://evil.example/phish",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


@pytest.mark.asyncio
async def test_client_register_rejects_cross_origin_form(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_session_user_id(_request):
        return "user-123"

    monkeypatch.setattr(oauth2_router, "_get_session_user_id", fake_session_user_id)

    resp = await client.post(
        "/clients/register",
        data={
            "client_name": "Cross Origin App",
            "redirect_uris": "http://localhost/callback",
            "grant_types": "authorization_code",
            "scopes": "openid",
        },
        headers={"Origin": "http://evil.example"},
    )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Cross-origin form submission blocked"


@pytest.mark.asyncio
async def test_login_rate_limit_returns_429(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_retry_after(_key: str, _max_attempts: int) -> int:
        return 30

    monkeypatch.setattr(main_module, "get_retry_after", fake_retry_after)

    resp = await client.post(
        "/login",
        data={
            "username": "safeuser",
            "password": "wrong",
            "next": "/",
        },
    )

    assert resp.status_code == 429
    assert "Too many failed attempts" in resp.text


@pytest.mark.asyncio
async def test_register_rate_limit_returns_429(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_retry_after(_key: str, _max_attempts: int) -> int:
        return 45

    monkeypatch.setattr(main_module, "get_retry_after", fake_retry_after)

    resp = await client.post(
        "/register",
        data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "captcha_id": "blocked-captcha",
            "captcha_code": "ABCD",
        },
    )

    assert resp.status_code == 429
    assert "45 秒后重试" in resp.text


@pytest.mark.asyncio
async def test_login_rejects_cross_origin_form(client: AsyncClient):
    resp = await client.post(
        "/login",
        data={
            "username": "safeuser",
            "password": "wrong",
            "next": "/",
        },
        headers={"Origin": "http://evil.example"},
    )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Cross-origin form submission blocked"


@pytest.mark.asyncio
async def test_client_register_page_rejects_insecure_redirect_uri(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_session_user_id(_request):
        return "user-123"

    monkeypatch.setattr(oauth2_router, "_get_session_user_id", fake_session_user_id)

    resp = await client.post(
        "/clients/register",
        data={
            "client_name": "Browser App",
            "redirect_uris": "http://example.com/callback",
            "grant_types": "authorization_code",
            "scopes": "openid",
        },
        headers={"Origin": "http://test"},
    )

    assert resp.status_code == 400
    assert "Public redirect URIs must use https" in resp.text


@pytest.mark.asyncio
async def test_client_register_page_hides_password_grant_by_default(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "ALLOW_PASSWORD_GRANT", False)

    async def fake_session_user_id(_request):
        return "user-123"

    monkeypatch.setattr(oauth2_router, "_get_session_user_id", fake_session_user_id)

    resp = await client.get("/clients/register")

    assert resp.status_code == 200
    assert 'value="password"' not in resp.text
    assert "Password grant is disabled by default" in resp.text
