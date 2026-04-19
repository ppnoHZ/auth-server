"""Generate DDL SQL from SQLAlchemy models."""
from sqlalchemy import create_engine
from sqlalchemy.schema import CreateTable

from app.database import Base
from app.models import AuthorizationCode, OAuthClient, OAuthToken, User  # noqa: F401

engine = create_engine("mysql+pymysql://", strategy="mock", executor=lambda *a, **kw: None)

if __name__ == "__main__":
    for table in Base.metadata.sorted_tables:
        print(CreateTable(table).compile(dialect=engine.dialect))
        print(";")
        print()
