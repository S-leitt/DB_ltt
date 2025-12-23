from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# 创建基础模型类
Base = declarative_base()

# 数据库连接配置
DATABASE_CONFIGS = {
    'mysql': {
        'url': 'mysql+pymysql://root:Ltt!021366@localhost:3306/exam_paper_db',
        'echo': False
    },
    'sqlserver': {
        'url': 'mssql+pyodbc://sa:021366@localhost\SAVER:1433/exam_paper_db?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes&schema=dbo',
        'echo': False
    },
    'oracle': {
        'url': 'oracle+cx_oracle://exam_paper_db:exam_paper_db@localhost:1521/?service_name=ORCLPDB',
        'echo': False
    }
}

# 创建数据库引擎
engines = {
    'mysql': create_engine(**DATABASE_CONFIGS['mysql']),
    'sqlserver': create_engine(**DATABASE_CONFIGS['sqlserver']),
    'oracle': create_engine(**DATABASE_CONFIGS['oracle'])
}

# 故障模拟控制变量
SIMULATE_ORACLE_FAILURE = False

# 创建会话工厂
SessionLocal = {
    'mysql': sessionmaker(autocommit=False, autoflush=False, bind=engines['mysql']),
    'sqlserver': sessionmaker(autocommit=False, autoflush=False, bind=engines['sqlserver']),
    'oracle': sessionmaker(autocommit=False, autoflush=False, bind=engines['oracle'])
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
