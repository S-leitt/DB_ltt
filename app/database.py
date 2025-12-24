import os
from typing import Dict

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from .config import get_settings

settings = get_settings()

# 当前运行模式：production 或 sqlite（测试用）
# 默认使用 sqlite，方便直接运行项目而无需额外数据库驱动
DB_MODE = settings.db_mode.lower()
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
            "url": settings.mysql_url,
            "echo": False,
        },
        "sqlserver": {
            "url": settings.sqlserver_url,
            "echo": False,
        },
        "oracle": {
            "url": settings.oracle_url,
            "echo": False,
        },
    }


# 创建基础模型类
Base = declarative_base()

# 数据库连接配置
DATABASE_CONFIGS = _build_database_configs()


def _create_engine(db_name: str):
    config = DATABASE_CONFIGS[db_name]
    connect_args = config.get("connect_args", {}).copy()

    if db_name == "oracle" and not IS_SQLITE_MODE:
        connect_args.setdefault("threaded", True)

    if db_name == "sqlserver" and not IS_SQLITE_MODE:
        try:
            import pyodbc  # noqa: F401
        except ModuleNotFoundError as exc:  # pragma: no cover - runtime guard
            raise RuntimeError(
                "未检测到pyodbc驱动，请先安装SQL Server ODBC驱动并确保pyodbc可用"
            ) from exc

    return create_engine(
        config["url"],
        echo=config.get("echo", False),
        connect_args=connect_args,
        pool_pre_ping=True,
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
        # 物理删除旧表，彻底解决表结构不匹配问题
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS T_SYNC_LOGS"))
        # 重新创建表结构
        Base.metadata.create_all(bind=engine)
        if not IS_SQLITE_MODE and "oracle" in engine.url.drivername:
            _init_oracle_sequences(engine)


def _init_oracle_sequences(engine):
    """初始化Oracle自增序列和触发器，如果不存在则创建。"""
    sequence_templates = {
        "T_USERS": "SEQ_USERS_ID",
        "T_QUESTIONS": "SEQ_QUESTIONS_ID",
        "T_EXAMS": "SEQ_EXAMS_ID",
        "T_SCORES": "SEQ_SCORES_ID",
        "T_SYNC_LOGS": "SEQ_SYNC_LOGS_ID",
    }

    trigger_template = (
        "CREATE OR REPLACE TRIGGER {trigger}\n"
        "BEFORE INSERT ON {table}\n"
        "FOR EACH ROW\n"
        "WHEN (NEW.id IS NULL)\n"
        "BEGIN\n"
        "  SELECT {sequence}.NEXTVAL INTO :NEW.id FROM dual;\n"
        "END;"
    )

    with engine.connect() as conn:
        for table, sequence in sequence_templates.items():
            try:
                conn.execute(text(f"CREATE SEQUENCE {sequence} START WITH 1 INCREMENT BY 1"))
            except Exception:
                pass
            trigger_name = f"TRG_{table}_BI"
            try:
                conn.execute(text(trigger_template.format(trigger=trigger_name, table=table, sequence=sequence)))
            except Exception:
                pass


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


def _ensure_schema(engine):
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    if not existing_tables:
        Base.metadata.create_all(bind=engine)
        if "oracle" in engine.url.drivername:
            _init_oracle_sequences(engine)


def check_connectivity() -> Dict[str, Dict[str, str]]:
    """Check connectivity for all configured databases and return status map."""

    results: Dict[str, Dict[str, str]] = {} 
    for name, engine in engines.items():
        try:
            _ensure_schema(engine)
            with engine.connect() as conn:
                if name == "oracle" and not IS_SQLITE_MODE:
                    conn.execute(text("SELECT 1 FROM DUAL"))
                else:
                    conn.execute(text("SELECT 1"))
            results[name] = {"status": "UP", "message": "连接正常"}
        except Exception as exc:
            results[name] = {"status": "DOWN", "message": str(exc)}

    _print_connectivity_table(results)
    return results


def _print_connectivity_table(results: Dict[str, Dict[str, str]]):
    headers = ["Database", "Status", "Message"]
    rows = [[name, info["status"], info["message"]] for name, info in results.items()]
    col_widths = [max(len(str(cell)) for cell in column) for column in zip(headers, *rows)] if rows else [len(h) for h in headers]

    def fmt_row(row):
        return " | ".join(str(cell).ljust(width) for cell, width in zip(row, col_widths))

    separator = "-+-|".join("-" * width for width in col_widths)
    print(fmt_row(headers))
    print(separator)
    for row in rows:
        print(fmt_row(row))


def init_questions_data():
    """初始化T_QUESTIONS表数据：清空旧数据并插入初始题目"""
    from uuid import uuid4
    from .models import Question
    
    # 初始题目数据
    questions_data = [
        {
            "content": "下列哪个是Python的正确注释方式？",
            "answer": "# 这是单行注释",
            "score": 10.0
        },
        {
            "content": "SQL中用于查询数据的关键字是？",
            "answer": "SELECT",
            "score": 10.0
        },
        {
            "content": "HTTP协议中用于请求资源的常用方法有哪些？",
            "answer": "GET, POST, PUT, DELETE",
            "score": 15.0
        },
        {
            "content": "什么是ORM框架？",
            "answer": "对象关系映射框架，用于在关系数据库和面向对象编程语言之间建立映射",
            "score": 15.0
        },
        {
            "content": "简述RESTful API的设计原则",
            "answer": "使用HTTP方法、资源标识符、无状态通信、统一接口等",
            "score": 20.0
        },
        {
            "content": "Python中列表和元组的主要区别是什么？",
            "answer": "列表是可变的，元组是不可变的",
            "score": 10.0
        },
        {
            "content": "什么是事务？",
            "answer": "数据库操作的一个执行单元，要么全部成功，要么全部失败",
            "score": 10.0
        },
        {
            "content": "简述CORS的作用",
            "answer": "跨域资源共享，允许浏览器向不同源的服务器发送请求",
            "score": 10.0
        }
    ]
    
    for db_name, session_factory in SessionLocal.items():
        try:
            session = session_factory()
            
            # 清空T_QUESTIONS表
            session.execute(text("DELETE FROM T_QUESTIONS"))
            session.commit()
            print(f"[{db_name}] 已清空T_QUESTIONS表旧数据")
            
            # 插入新数据
            inserted_count = 0
            for q_data in questions_data:
                question = Question(
                    guid=str(uuid4()),
                    content=q_data["content"],
                    answer=q_data["answer"],
                    score=q_data["score"]
                )
                session.add(question)
                inserted_count += 1
            
            session.commit()
            print(f"[{db_name}] 成功插入{inserted_count}条题目数据")
            
        except Exception as e:
            session.rollback()
            print(f"[{db_name}] 初始化数据失败: {str(e)}")
        finally:
            session.close()
