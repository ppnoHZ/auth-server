from secrets import token_urlsafe

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "mysql+aiomysql://root:root@127.0.0.1:3306/oauth2_db"
    DATABASE_URL_SYNC: str = "mysql+pymysql://root:root@127.0.0.1:3306/oauth2_db"

    # JWT
    JWT_SECRET_KEY: str = token_urlsafe(64)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Authorization code
    AUTHORIZATION_CODE_EXPIRE_MINUTES: int = 10

    # Session
    SESSION_SECRET_KEY: str = token_urlsafe(64)

    # Redis (Added)
    REDIS_URL: str = "redis://localhost:6379/0"
    SESSION_EXPIRE_SECONDS: int = 3600
    AUTH_CODE_EXPIRE_SECONDS: int = 600

    # Rate limiting
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300
    REGISTER_RATE_LIMIT_ATTEMPTS: int = 8
    REGISTER_RATE_LIMIT_WINDOW_SECONDS: int = 600
    USER_REGISTER_RATE_LIMIT_ATTEMPTS: int = 8
    USER_REGISTER_RATE_LIMIT_WINDOW_SECONDS: int = 600
    PASSWORD_GRANT_RATE_LIMIT_ATTEMPTS: int = 5
    PASSWORD_GRANT_RATE_LIMIT_WINDOW_SECONDS: int = 300
    ALLOW_PASSWORD_GRANT: bool = False

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
