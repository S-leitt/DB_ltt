from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Text
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = 'T_USERS'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False, default='VIEWER')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Question(Base):
    __tablename__ = 'T_QUESTIONS'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    guid = Column(String(50), unique=True, index=True, nullable=False)
    content = Column(String(500), nullable=False)
    answer = Column(String(200), nullable=False)
    score = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Exam(Base):
    __tablename__ = 'T_EXAMS'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    name = Column(String(100), nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Score(Base):
    __tablename__ = 'T_SCORES'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    user_id = Column(Integer, ForeignKey('T_USERS.id'), nullable=False)
    exam_id = Column(Integer, ForeignKey('T_EXAMS.id'), nullable=False)
    score_value = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class SyncLog(Base):
    __tablename__ = 'T_SYNC_LOGS'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    source_db = Column(String(20), nullable=False)  # 数据最初写入的库
    target_db = Column(String(20), nullable=False)  # 目标库
    operation_type = Column(String(10), nullable=False)  # 操作类型: INSERT, UPDATE, DELETE
    event_type = Column(String(50), nullable=False)
    sync_status = Column(String(20), nullable=False, default='PENDING')  # 状态: PENDING, SUCCESS, FAILED
    error_msg = Column(String(500), nullable=True)
    payload = Column(Text, nullable=True)  # 存储要同步的数据内容
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class ExamPaper(Base):
    __tablename__ = 'T_EXAM_PAPERS'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    exam_id = Column(Integer, ForeignKey('T_EXAMS.id'), nullable=False)
    paper_name = Column(String(100), nullable=False)
    total_score = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class PaperQuestion(Base):
    __tablename__ = 'T_PAPER_QUESTIONS'
    __table_args__ = {
        'extend_existing': True
    }
    
    id = Column(Integer, primary_key=True, autoincrement=True, mssql_identity_start=1, mssql_identity_increment=1)
    paper_id = Column(Integer, ForeignKey('T_EXAM_PAPERS.id'), nullable=False)
    question_id = Column(Integer, ForeignKey('T_QUESTIONS.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
