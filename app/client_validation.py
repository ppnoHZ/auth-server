from urllib.parse import urlsplit

from fastapi import HTTPException, status

from app.config import settings


VALID_GRANT_TYPES = {"authorization_code", "client_credentials", "password", "refresh_token"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_client_name(client_name: str) -> str:
    normalized = client_name.strip()
    if not normalized or len(normalized) > 120:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client name must be between 1 and 120 characters",
        )
    return normalized


def validate_grant_types(grant_types: list[str]) -> list[str]:
    if not grant_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one grant type is required",
        )

    normalized: list[str] = []
    for grant_type in grant_types:
        if grant_type not in VALID_GRANT_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid grant type: {grant_type}",
            )
        if grant_type == "password" and not settings.ALLOW_PASSWORD_GRANT:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password grant is disabled",
            )
        if grant_type not in normalized:
            normalized.append(grant_type)
    return normalized


def validate_scopes(scopes: str) -> str:
    normalized_items: list[str] = []
    for item in scopes.split():
        if len(item) > 100 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in item):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scopes must contain visible ASCII characters only",
            )
        if item not in normalized_items:
            normalized_items.append(item)

    normalized = " ".join(normalized_items)
    if len(normalized) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scopes are too long",
        )
    return normalized


def _validate_single_redirect_uri(redirect_uri: str) -> str:
    normalized = redirect_uri.strip()
    parsed = urlsplit(normalized)

    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI cannot be empty")
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI must use http or https")
    if not parsed.netloc or not parsed.hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI must be absolute")
    if parsed.fragment:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI must not contain a fragment")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI must not include user info")

    hostname = parsed.hostname.lower()
    is_loopback = hostname in LOOPBACK_HOSTS
    if parsed.scheme != "https" and not is_loopback:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Public redirect URIs must use https",
        )

    return normalized


def validate_redirect_uris(redirect_uris: list[str], grant_types: list[str]) -> list[str]:
    normalized_grants = validate_grant_types(grant_types)
    requires_redirect = "authorization_code" in normalized_grants

    if requires_redirect and not redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="authorization_code clients require at least one redirect URI",
        )

    normalized_uris: list[str] = []
    for redirect_uri in redirect_uris:
        cleaned = _validate_single_redirect_uri(redirect_uri)
        if cleaned not in normalized_uris:
            normalized_uris.append(cleaned)

    if not requires_redirect and not normalized_uris:
        return []

    if not normalized_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one redirect URI is required",
        )

    return normalized_uris