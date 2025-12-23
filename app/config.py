from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Project configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    db_mode: str = Field("sqlite", alias="DB_MODE")
    mysql_url: str = Field("sqlite:///./mysql.db", alias="MYSQL_URL")
    sqlserver_url: str = Field("sqlite:///./sqlserver.db", alias="SQLSERVER_URL")
    oracle_url: str = Field("sqlite:///./oracle.db", alias="ORACLE_URL")

    jwt_secret_key: str = Field("change-me", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")

    smtp_host: str = Field("smtp.example.com", alias="SMTP_HOST")
    smtp_port: int = Field(587, alias="SMTP_PORT")
    smtp_user: str = Field("user@example.com", alias="SMTP_USER")
    smtp_password: str = Field("changeme", alias="SMTP_PASSWORD")
    smtp_from: str = Field("noreply@example.com", alias="SMTP_FROM")

    app_base_url: str = Field("http://127.0.0.1:8006", alias="APP_BASE_URL")


@lru_cache
def get_settings() -> Settings:
    return Settings()
