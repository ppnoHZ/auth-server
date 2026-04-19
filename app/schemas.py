from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


# ---- User ----
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ---- OAuth Client ----
class ClientCreate(BaseModel):
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: str = ""


class ClientResponse(BaseModel):
    id: str
    client_id: str
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ClientCreateResponse(ClientResponse):
    client_secret: str  # only returned on creation


# ---- Token ----
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: str = ""


class TokenIntrospectResponse(BaseModel):
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    username: Optional[str] = None
    exp: Optional[int] = None


# ---- Login form ----
class LoginForm(BaseModel):
    username: str
    password: str
