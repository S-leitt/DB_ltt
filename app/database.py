import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# 当前运行模式：production 或 sqlite（测试用）
DB_MODE = os.getenv("DB_MODE", "production").lower()
IS_SQLITE_MODE = DB_MODE == "sqlite"


def _build_database_configs():
    """构建数据库配置，支持SQLite测试模式。"""

    if IS_SQLITE_MODE:
        # 为每个目标库创建独立的SQLite数据库文件，避免依赖外部驱动
        return {
            db_name: {
                "url": f"sqlite:///./{db_name}.db",
                "echo": False,
                "connect_args": {"check_same_thread": False},
            }
            for db_name in ("mysql", "sqlserver", "oracle")
        }

    return {
        "mysql": {
            "url": "mysql+pymysql://root:Ltt!021366@localhost:3306/exam_paper_db",
            "echo": False,
        },
        "sqlserver": {
            "url": "mssql+pyodbc://sa:021366@localhost\\SAVER:1433/exam_paper_db?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes&schema=dbo",
            "echo": False,
        },
        "oracle": {
            "url": "oracle+cx_oracle://exam_paper_db:exam_paper_db@localhost:1521/?service_name=ORCLPDB",
            "echo": False,
        },
    }


# 创建基础模型类
Base = declarative_base()

# 数据库连接配置
DATABASE_CONFIGS = _build_database_configs()


def _create_engine(db_name: str):
    config = DATABASE_CONFIGS[db_name]
    return create_engine(
        config["url"],
        echo=config.get("echo", False),
        connect_args=config.get("connect_args", {}),
    )


# 创建数据库引擎
engines = {db_name: _create_engine(db_name) for db_name in DATABASE_CONFIGS}

# 故障模拟控制变量
SIMULATE_ORACLE_FAILURE = False

# 创建会话工厂
SessionLocal = {
    db_name: sessionmaker(autocommit=False, autoflush=False, bind=engine)
    for db_name, engine in engines.items()
}


def init_db():
    """初始化数据库结构（在SQLite测试模式下使用）。"""

    for engine in engines.values():
        Base.metadata.create_all(bind=engine)


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
