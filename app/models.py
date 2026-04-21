import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(150), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    clients = relationship("OAuthClient", back_populates="owner")


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    client_id = Column(String(48), unique=True, nullable=False, index=True)
    client_secret_hash = Column(String(255), nullable=False)
    client_name = Column(String(120), nullable=False)
    redirect_uris = Column(Text, nullable=False)  # JSON array
    grant_types = Column(Text, nullable=False)  # JSON array
    scopes = Column(String(500), default="")
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="clients")


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    access_token = Column(String(500), nullable=False, index=True)
    refresh_token = Column(String(48), nullable=True, unique=True, index=True)
    token_type = Column(String(20), default="bearer")
    client_id = Column(String(48), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    scope = Column(String(500), default="")
    expires_at = Column(DateTime, nullable=False)
    refresh_token_expires_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
