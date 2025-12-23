from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Project configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    db_mode: str = Field("production", alias="DB_MODE")
    mysql_url: str = Field(
        "mysql+pymysql://user:password@localhost:3306/exam_paper_db", alias="MYSQL_URL"
    )
    sqlserver_url: str = Field(
        "mssql+pyodbc://sa:password@localhost\\SQLEXPRESS:1433/exam_paper_db?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes&schema=dbo",
        alias="SQLSERVER_URL",
    )
    oracle_url: str = Field(
        "oracle+cx_oracle://user:password@localhost:1521/?service_name=ORCLPDB",
        alias="ORACLE_URL",
    )

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
