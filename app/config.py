"""Application configuration and environment loading utilities."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database connection settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # MySQL settings
    mysql_user: str = Field("root")
    mysql_password: str = Field("")
    mysql_host: str = Field("localhost")
    mysql_port: int = Field(3306)
    mysql_db: str = Field("exam_paper_db")
    mysql_echo: bool = Field(False)

    # SQL Server settings
    sqlserver_user: str = Field("sa")
    sqlserver_password: str = Field("")
    sqlserver_host: str = Field("localhost\\SQLEXPRESS")
    sqlserver_port: int = Field(1433)
    sqlserver_db: str = Field("exam_paper_db")
    sqlserver_driver: str = Field("ODBC Driver 17 for SQL Server")
    sqlserver_schema: str = Field("dbo")
    sqlserver_trust_server_certificate: bool = Field(True)
    sqlserver_echo: bool = Field(False)

    # Oracle settings
    oracle_user: str = Field("exam_paper_db")
    oracle_password: str = Field("")
    oracle_host: str = Field("localhost")
    oracle_port: int = Field(1521)
    oracle_service_name: str = Field("ORCLPDB")
    oracle_echo: bool = Field(False)


settings = DatabaseSettings()
