"""Database session and engine management."""

from urllib.parse import quote_plus

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import settings

# 创建基础模型类
Base = declarative_base()


def _build_mysql_url() -> str:
    """构建 MySQL 连接 URL。"""

    password = quote_plus(settings.mysql_password)
    return (
        f"mysql+pymysql://{settings.mysql_user}:{password}"
        f"@{settings.mysql_host}:{settings.mysql_port}/{settings.mysql_db}"
    )


def _build_sqlserver_url() -> str:
    """构建 SQL Server 连接 URL。"""

    password = quote_plus(settings.sqlserver_password)
    driver = quote_plus(settings.sqlserver_driver)
    trust_cert = "yes" if settings.sqlserver_trust_server_certificate else "no"
    return (
        f"mssql+pyodbc://{settings.sqlserver_user}:{password}"
        f"@{settings.sqlserver_host}:{settings.sqlserver_port}/{settings.sqlserver_db}"
        f"?driver={driver}&TrustServerCertificate={trust_cert}&schema={settings.sqlserver_schema}"
    )


def _build_oracle_url() -> str:
    """构建 Oracle 连接 URL。"""

    password = quote_plus(settings.oracle_password)
    return (
        f"oracle+cx_oracle://{settings.oracle_user}:{password}"
        f"@{settings.oracle_host}:{settings.oracle_port}/?service_name={settings.oracle_service_name}"
    )


# 数据库连接配置
DATABASE_CONFIGS = {
    "mysql": {
        "url": _build_mysql_url(),
        "echo": settings.mysql_echo,
    },
    "sqlserver": {
        "url": _build_sqlserver_url(),
        "echo": settings.sqlserver_echo,
    },
    "oracle": {
        "url": _build_oracle_url(),
        "echo": settings.oracle_echo,
    },
}

# 创建数据库引擎
engines = {
    "mysql": create_engine(**DATABASE_CONFIGS["mysql"]),
    "sqlserver": create_engine(**DATABASE_CONFIGS["sqlserver"]),
    "oracle": create_engine(**DATABASE_CONFIGS["oracle"]),
}

# 故障模拟控制变量
SIMULATE_ORACLE_FAILURE = False

# 创建会话工厂
SessionLocal = {
    "mysql": sessionmaker(autocommit=False, autoflush=False, bind=engines["mysql"]),
    "sqlserver": sessionmaker(autocommit=False, autoflush=False, bind=engines["sqlserver"]),
    "oracle": sessionmaker(autocommit=False, autoflush=False, bind=engines["oracle"]),
}


def get_all_sessions():
    """生成器函数，返回所有数据库的会话"""

    sessions = {}
    try:
        for db_name, session_factory in SessionLocal.items():
            session = session_factory()
            sessions[db_name] = session
            yield session
    finally:
        # 关闭所有会话
        for session in sessions.values():
            session.close()


def get_session(db_name: str):
    """获取指定数据库的会话"""

    session = SessionLocal[db_name]()
    try:
        yield session
    finally:
        session.close()
