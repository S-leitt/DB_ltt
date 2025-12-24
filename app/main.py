from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from emails import Message
from emails.smtp import SMTP
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .config import get_settings
from .database import (
    engines,
    get_session,
    SIMULATE_ORACLE_FAILURE,
    init_db,
    IS_SQLITE_MODE,
    check_connectivity,
    Base,
)
from .sync_decorator import CrossDBManager
from .models import Question, Score, SyncLog, User
from sqlalchemy.orm import Session
from sqlalchemy import text
import hashlib
import json

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(
    title="多数据库同步系统",
    description="考试组卷系统的多数据库同步服务",
    version="1.0.0"
)

# 启动时打印所有路由
@app.on_event("startup")
async def print_routes():
    if IS_SQLITE_MODE:
        # 测试模式下自动创建SQLite表结构，保证接口可直接运行
        init_db()

    check_connectivity()

    print("=== 已注册的路由表 ===")
    for route in app.routes:
        if hasattr(route, "path") and hasattr(route, "methods"):
            print(f"路径: {route.path}, 方法: {route.methods}")
    print("====================")



# 配置CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允许所有来源，生产环境请限制具体域名
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有方法
    allow_headers=["*"],  # 允许所有头部
)

class ConnectionTestResult(BaseModel):
    """连接测试结果模型"""
    status: str
    message: str

# Pydantic模型定义
class QuestionCreate(BaseModel):
    """创建题目模型"""
    content: str
    answer: str
    score: float
    guid: Optional[str] = None

class QuestionResponse(QuestionCreate):
    """题目响应模型"""
    id: int
    guid: str
    
    class Config:
        from_attributes = True

class QuestionUpdate(BaseModel):
    """更新题目模型"""
    content: str
    answer: str
    score: float

class QuestionCreateRequest(BaseModel):
    """创建题目请求模型，包含target_dbs列表"""
    question: QuestionCreate
    target_dbs: List[str]

class QuestionUpdateRequest(BaseModel):
    """更新题目请求模型，包含target_dbs列表"""
    question: QuestionUpdate
    target_dbs: List[str]

class ScoreUpdate(BaseModel):
    """更新成绩模型"""
    score_value: float

class ScoreCreateRequest(BaseModel):
    """创建成绩请求模型，包含target_dbs列表"""
    user_id: int
    exam_id: int
    score_value: float
    target_dbs: List[str]
    
class SyncLogResponse(BaseModel):
    """同步日志响应模型"""
    id: int
    event_type: str
    status: str
    error_msg: Optional[str]
    created_at: str
    
    class Config:
        from_attributes = True

class UserStats(BaseModel):
    """用户统计模型"""
    user_id: int
    username: str
    avg_score: float
    exam_count: int

class LoginRequest(BaseModel):
    """登录请求模型"""
    username: str
    password: str

class LoginResponse(BaseModel):
    """登录响应模型"""
    token: str
    username: str
    role: str

class TokenData(BaseModel):
    """Token数据模型"""
    username: str
    role: str

class ScoreCreate(BaseModel):
    """创建成绩模型"""
    user_id: int
    exam_id: int
    score_value: float


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    # 将datetime对象转换为Unix时间戳（整数），避免JSON序列化错误
    to_encode.update({"exp": int(expire.timestamp())})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        print(f"Current request user role: {role}")  # 添加调试日志
        if username is None:
            raise HTTPException(status_code=401, detail="无效的令牌")
        if role is None:
            raise HTTPException(status_code=401, detail="令牌中缺少角色信息")
        token_data = TokenData(username=username, role=role)
    except JWTError as e:
        print(f"JWT 解码错误: {str(e)}")  # 添加调试日志
        raise HTTPException(status_code=401, detail=f"无法验证令牌: {str(e)}")

    # 处理内存中生成的admin和guest用户，跳过数据库查询
    if username == "admin" or username == "guest":
        # 创建一个模拟的User对象
        print(f"Using shadow account: {username}, role: {role}")  # 添加调试日志
        # 确保role是字符串类型
        role_str = str(role)
        return User(
            id=1 if username == "admin" else 2,
            username=username,
            email=f"{username}@example.com",
            password_hash="",
            role=role_str
        )
    
    # 原有的数据库验证逻辑，用于其他用户
    print(f"Using database user: {username}")  # 添加调试日志
    session = next(get_session("mysql"))
    try:
        user = get_user_by_username(session, token_data.username)
        if user is None:
            raise HTTPException(status_code=401, detail="用户不存在")
        print(f"Database user found: {user.username}, role: {user.role}")  # 添加调试日志
        return user
    finally:
        session.close()
class SimulateFaultRequest(BaseModel):
    """模拟故障请求模型"""
    enable: bool


class RepairRequest(BaseModel):
    source_db: str
    target_dbs: List[str]
    guid: str

class ScoreSyncRequest(BaseModel):
    source_db: str
    user_id: int
    exam_id: int
    target_dbs: List[str] = []


@app.post("/api/auth/login", response_model=LoginResponse)
def login(request: LoginRequest):
    # 硬编码的admin账号判断，跳过数据库验证
    if request.username == "admin" and request.password == "admin123":
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        token = create_access_token(
            data={"sub": "admin", "role": "admin"}, expires_delta=access_token_expires
        )
        return LoginResponse(token=token, username="admin", role="admin")
    # 硬编码的guest账号判断，跳过数据库验证
    elif request.username == "guest" and request.password == "guest123":
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        token = create_access_token(
            data={"sub": "guest", "role": "guest"}, expires_delta=access_token_expires
        )
        return LoginResponse(token=token, username="guest", role="guest")
    
    # 原有的数据库验证逻辑保留，用于其他用户
    session = next(get_session("mysql"))
    try:
        user = get_user_by_username(session, request.username)
        if not user or not verify_password(request.password, user.password_hash):
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        token = create_access_token(
            data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
        )
        return LoginResponse(token=token, username=user.username, role=user.role)
    finally:
        session.close()


@app.get("/api/auth/me", response_model=LoginResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    dummy_token = ""
    return LoginResponse(token=dummy_token, username=current_user.username, role=current_user.role)

@app.post("/api/simulate-fault")
def simulate_fault(request: SimulateFaultRequest):
    """
    模拟Oracle数据库写入失败
    
    Args:
        request: 包含enable参数的请求体
            - enable: True（开启故障模拟）/ False（关闭故障模拟）
    """
    from .database import SIMULATE_ORACLE_FAILURE as oracle_failure_flag
    
    # 修改全局变量
    import app.database
    app.database.SIMULATE_ORACLE_FAILURE = request.enable
    
    status = "enabled" if request.enable else "disabled"
    return {
        "status": "success",
        "message": f"Oracle故障模拟已{status}",
        "current_state": request.enable
    }


def _queue_failure_email(background_tasks: BackgroundTasks, subject: str, html: str):
    def _send():
        message = Message(subject=subject, html=html, mail_from=settings.smtp_from)
        smtp = SMTP(
            host=settings.smtp_host,
            port=settings.smtp_port,
            user=settings.smtp_user,
            password=settings.smtp_password,
            tls=True,
        )
        smtp.send(message, recipients=[settings.smtp_user])

    background_tasks.add_task(_send)





@app.post("/api/sync/repair")
def repair_sync(request: RepairRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user)):
    if request.source_db not in engines:
        raise HTTPException(status_code=400, detail="无效的源数据库")

    source_session = next(get_session(request.source_db))
    try:
        source_question = source_session.query(Question).filter(Question.guid == request.guid).first()
        if not source_question:
            raise HTTPException(status_code=404, detail="源数据库未找到该GUID")

        failures = []
        for target in request.target_dbs:
            if target not in engines or target == request.source_db:
                continue
            target_session = next(get_session(target))
            try:
                target_question = target_session.query(Question).filter(Question.guid == request.guid).first()
                if not target_question:
                    target_question = Question(
                        guid=source_question.guid,
                        content=source_question.content,
                        answer=source_question.answer,
                        score=source_question.score,
                    )
                    target_session.add(target_question)
                else:
                    target_question.content = source_question.content
                    target_question.answer = source_question.answer
                    target_question.score = source_question.score
                target_session.commit()
            except Exception as exc:
                target_session.rollback()
                failures.append({"target": target, "error": str(exc)})
            finally:
                target_session.close()

        if failures:
            html_error = """
                <h3>同步修复失败</h3>
                <p>以下目标库修复失败：</p>
                <ul>
            """
            for fail in failures:
                html_error += f"<li>{fail['target']}: {fail['error']}</li>"
            html_error += "</ul>"

            _queue_failure_email(background_tasks, "同步修复失败", html_error)
            return {"status": "partial", "failures": failures}

        return {"status": "success"}
    finally:
        source_session.close()

@app.post("/test-connection", response_model=Dict[str, ConnectionTestResult])
def test_connection():
    """测试所有数据库连接"""
    results = {}
    
    for db_name, engine in engines.items():
        try:
            # 测试连接 - 使用text()包装SQL语句
            with engine.connect() as conn:
                # 针对不同数据库使用不同的测试语句
                if db_name == 'oracle' and not IS_SQLITE_MODE:
                    # Oracle需要FROM子句
                    conn.execute(text("SELECT 1 FROM DUAL"))
                else:
                    # MySQL、SQL Server和SQLite支持SELECT 1语法
                    conn.execute(text("SELECT 1"))
            results[db_name] = ConnectionTestResult(
                status="success",
                message=f"成功连接到{db_name}数据库"
            )
        except Exception as e:
            results[db_name] = ConnectionTestResult(
                status="error",
                message=f"连接{db_name}数据库失败: {str(e)}"
            )
    
    return results

# 为HTML文件提供特殊路由
@app.get("/")
def root():
    return FileResponse("index.html")

@app.get("/login.html")
def login_page():
    return FileResponse("login.html")

@app.get("/index.html")
def index_page():
    return FileResponse("index.html")

# 数据库操作函数
def create_question(db: Session, question: QuestionCreate):
    """创建题目"""
    # 从question对象中提取所有字段，包括guid
    question_data = question.dict()
    db_question = Question(**question_data)
    db.add(db_question)
    db.flush()
    return db_question

def create_score(db: Session, score: ScoreCreate):
    """创建成绩"""
    # 获取当前会话的数据库引擎名称
    db_name = db.bind.url.drivername
    
    # 特殊处理Oracle数据库的数据类型
    if 'oracle' in db_name:
        # 对于Oracle数据库，显式处理数据类型和日期字段
        try:
            # 使用SQLAlchemy的func.now()确保日期字段有有效值，避免触发器验证失败
            from sqlalchemy import func
            
            # 创建Score对象，不设置updated_at（由Oracle触发器自动处理）
            db_score = Score(
                user_id=score.user_id,
                exam_id=score.exam_id,
                score_value=score.score_value,
                created_at=func.now(),
                updated_at=func.now()  # 显式设置updated_at，避免传递NULL值
            )
            db.add(db_score)
            db.flush()
            return db_score
        except Exception as e:
            print(f"Oracle特定处理失败: {str(e)}")
            # 打印详细错误信息，便于调试
            import traceback
            traceback.print_exc()
            # 如果Oracle特定处理失败，尝试使用原始SQL语句
            try:
                # 使用原始SQL插入，避免ORM自动处理的问题
                result = db.execute(
                    text("INSERT INTO T_SCORES (user_id, exam_id, score_value, created_at, updated_at) VALUES (:user_id, :exam_id, :score_value, SYSDATE, SYSDATE) RETURNING id INTO :id"),
                    {
                        'user_id': score.user_id,
                        'exam_id': score.exam_id,
                        'score_value': score.score_value,
                        'id': None
                    }
                )
                db.commit()
                # 创建一个模拟的Score对象返回
                return Score(
                    id=result.lastrowid,
                    user_id=score.user_id,
                    exam_id=score.exam_id,
                    score_value=score.score_value
                )
            except Exception as raw_e:
                print(f"Oracle原始SQL处理失败: {str(raw_e)}")
                traceback.print_exc()
                raise
    else:
        # 其他数据库使用默认方式
        db_score = Score(**score.dict())
        db.add(db_score)
        db.flush()
        return db_score

def update_score(db: Session, score_id: int, score_update: ScoreUpdate):
    """更新成绩"""
    db_score = db.query(Score).filter(Score.id == score_id).first()
    if not db_score:
        raise HTTPException(status_code=404, detail="Score not found")
    db_score.score_value = score_update.score_value
    return db_score

def delete_score(db: Session, score_id: int):
    """删除成绩"""
    db_score = db.query(Score).filter(Score.id == score_id).first()
    if not db_score:
        raise HTTPException(status_code=404, detail="Score not found")
    db.delete(db_score)
    return {"status": "success", "message": "Score deleted successfully"}

def update_question(db: Session, question_guid: str, question_update: QuestionUpdate):
    """更新题目"""
    db_question = db.query(Question).filter(Question.guid == question_guid).first()
    if not db_question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    db_question.content = question_update.content
    db_question.answer = question_update.answer
    db_question.score = question_update.score
    return db_question

# 同步写入接口
@app.post("/questions", response_model=Dict)
def create_question_sync(question: QuestionCreate):
    """同时向三个库新增题目"""
    return CrossDBManager.sync_write(create_question)(question)

@app.post("/scores", response_model=Dict)
def create_score_sync(score: ScoreCreate):
    """同时向三个库新增成绩"""
    return CrossDBManager.sync_write(create_score)(score)

@app.put("/scores/{score_id}", response_model=Dict)
def update_score_sync(score_id: int, score_update: ScoreUpdate):
    """同时更新三个库的成绩"""
    return CrossDBManager.sync_write(update_score)(score_id, score_update)

@app.delete("/scores/{score_id}", response_model=Dict)
def delete_score_sync(score_id: int):
    """同时从三个库删除成绩"""
    return CrossDBManager.sync_write(delete_score)(score_id)

@app.put("/questions/{question_guid}", response_model=Dict)
def update_question_sync(question_guid: str, question_update: QuestionUpdate):
    """同时更新三个库的题目"""
    return CrossDBManager.sync_write(update_question)(question_guid, question_update)

@app.get("/sync-health", response_model=Dict[str, List[SyncLogResponse]])
def get_sync_health(limit: int = 10):
    """查询最近的同步异常记录"""
    results = {}
    
    for db_name in engines.keys():
        db = next(get_session(db_name))
        try:
            # 查询最近的同步日志，按创建时间倒序
            logs = db.query(SyncLog)\
                     .filter(SyncLog.sync_status == "error")\
                     .order_by(SyncLog.created_at.desc())\
                     .limit(limit)\
                     .all()
            
            # 转换为响应模型
            log_responses = []
            for log in logs:
                log_responses.append(SyncLogResponse(
                    id=log.id,
                    event_type=log.event_type,
                    status=log.status,
                    error_msg=log.error_msg,
                    created_at=log.created_at.isoformat() if log.created_at else ""
                ))
            
            results[db_name] = log_responses
        finally:
            db.close()
    
    return results

# 定义同步统计模型
class SyncStats(BaseModel):
    success_count: int
    failed_count: int
    pending_count: int
    total_count: int
    success_rate: float

@app.get("/api/stats", response_model=Dict[str, SyncStats])
def get_stats():
    """获取同步统计信息，统计T_SYNC_LOGS表中status='SUCCESS'和status='FAILED'的比例"""
    results = {}
    
    # 针对不同数据库编写适配的原生SQL，统计SUCCESS和FAILED的数量
    sql_queries = {
        'mysql': """
            SELECT 
                SUM(CASE WHEN sync_status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN sync_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN sync_status = 'PENDING' THEN 1 ELSE 0 END) as pending_count,
                COUNT(*) as total_count
            FROM T_SYNC_LOGS
        """,
        'sqlserver': """
            SELECT
                SUM(CASE WHEN sync_status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN sync_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN sync_status = 'PENDING' THEN 1 ELSE 0 END) as pending_count,
                COUNT(*) as total_count
            FROM T_SYNC_LOGS
        """,
        'oracle': """
            SELECT
                SUM(CASE WHEN sync_status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN sync_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN sync_status = 'PENDING' THEN 1 ELSE 0 END) as pending_count,
                COUNT(*) as total_count
            FROM T_SYNC_LOGS
        """
    }
    
    for db_name, engine in engines.items():
        try:
            with engine.connect() as conn:
                sql = sql_queries[db_name]
                result = conn.execute(text(sql))
                row = result.fetchone()
                
                # 计算成功率
                success_count = int(row.success_count) if row.success_count else 0
                failed_count = int(row.failed_count) if row.failed_count else 0
                pending_count = int(row.pending_count) if row.pending_count else 0
                total_count = int(row.total_count) if row.total_count else 0
                success_rate = success_count / total_count if total_count > 0 else 0.0
                
                # 创建同步统计对象
                sync_stats = SyncStats(
                    success_count=success_count,
                    failed_count=failed_count,
                    pending_count=pending_count,
                    total_count=total_count,
                    success_rate=success_rate
                )
                
                results[db_name] = sync_stats
        except Exception as e:
            # 如果查询失败，返回默认值
            results[db_name] = SyncStats(
                success_count=0,
                failed_count=0,
                pending_count=0,
                total_count=0,
                success_rate=0.0
            )
    
    return results

@app.get("/questions/search", response_model=Dict[str, List[QuestionResponse]])
def search_questions(
    content: Optional[str] = None,
    score_min: Optional[float] = None,
    score_max: Optional[float] = None,
    limit: int = 100
):
    """
    多条件检索API，支持content模糊搜索和score区间查询
    
    Args:
        content: 题目内容模糊搜索关键词
        score_min: 最低分数
        score_max: 最高分数
        limit: 返回结果数量限制
    """
    results = {}
    
    for db_name in engines.keys():
        try:
            # 获取数据库会话
            db = next(get_session(db_name))
            
            # 构建查询条件
            query = db.query(Question)
            
            # 添加模糊搜索条件
            if content:
                # 针对不同数据库使用不同的模糊查询语法
                if db_name == 'mysql' or db_name == 'sqlserver':
                    query = query.filter(Question.content.like(f"%{content}%"))
                elif db_name == 'oracle':
                    # Oracle使用LIKE和UPPER函数实现不区分大小写的模糊查询
                    query = query.filter(Question.content.like(f"%{content}%"))
            
            # 添加分数区间查询条件
            if score_min is not None:
                query = query.filter(Question.score >= score_min)
            if score_max is not None:
                query = query.filter(Question.score <= score_max)
            
            # 限制结果数量
            query = query.limit(limit)
            
            # 执行查询
            questions = query.all()
            
            # 转换为响应模型
            question_responses = [QuestionResponse.model_validate(question) for question in questions]
            results[db_name] = question_responses
        finally:
            db.close()
    
    return results

@app.delete("/cleanup")
def cleanup_test_data():
    """清空三个数据库中的测试数据，方便重新开始干净的测试"""
    results = {}
    
    # 需要清理的表列表，按依赖关系排序（先删除外键依赖的表，再删除主表）
    tables_to_clean = ['T_SCORES', 'T_EXAMS', 'T_QUESTIONS', 'T_USERS', 'T_SYNC_LOGS']
    
    for db_name in engines.keys():
        session = next(get_session(db_name))
        try:
            print(f"DEBUG: 正在清空 {db_name} 的测试数据...")
            
            # 禁用外键检查（MySQL和SQL Server）
            if db_name == 'mysql':
                session.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
            elif db_name == 'sqlserver':
                session.execute(text("ALTER TABLE T_SCORES NOCHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_EXAMS NOCHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_QUESTIONS NOCHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_USERS NOCHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_SYNC_LOGS NOCHECK CONSTRAINT ALL"))
            
            # 依次清空每个表
            for table in tables_to_clean:
                try:
                    print(f"DEBUG: 清空 {db_name}.{table} 表...")
                    # 针对不同数据库使用不同的清空语法
                    if db_name == 'oracle':
                        # Oracle不支持TRUNCATE TABLE带CASCADE，使用DELETE
                        session.execute(text(f"DELETE FROM {table}"))
                    else:
                        # MySQL和SQL Server支持TRUNCATE TABLE
                        session.execute(text(f"TRUNCATE TABLE {table}"))
                    print(f"DEBUG: 清空 {db_name}.{table} 表成功")
                except Exception as e:
                    print(f"ERROR: 清空 {db_name}.{table} 表失败 - {str(e)}")
            
            # 重新启用外键检查
            if db_name == 'mysql':
                session.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
            elif db_name == 'sqlserver':
                session.execute(text("ALTER TABLE T_SCORES CHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_EXAMS CHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_QUESTIONS CHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_USERS CHECK CONSTRAINT ALL"))
                session.execute(text("ALTER TABLE T_SYNC_LOGS CHECK CONSTRAINT ALL"))
            
            session.commit()
            results[db_name] = {'status': 'success', 'message': f'已成功清空 {db_name} 的测试数据'}
            print(f"DEBUG: 清空 {db_name} 测试数据成功")
        except Exception as e:
            session.rollback()
            results[db_name] = {'status': 'error', 'message': str(e)}
            print(f"ERROR: 清空 {db_name} 测试数据失败 - {str(e)}")
        finally:
            session.close()
    
    return results


@app.delete("/init-questions")
def init_questions():
    """清空三个数据库中T_QUESTIONS表的所有旧数据，并重置自增ID序列"""
    results = {}
    
    for db_name in engines.keys():
        session = next(get_session(db_name))
        try:
            print(f"DEBUG: 正在初始化 {db_name} 的T_QUESTIONS表...")
            
            # 禁用外键检查（MySQL和SQL Server）
            if db_name == 'mysql':
                session.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
            elif db_name == 'sqlserver':
                session.execute(text("ALTER TABLE T_SCORES NOCHECK CONSTRAINT ALL"))
            
            # 清空T_QUESTIONS表
            if db_name == 'oracle':
                # Oracle使用DELETE
                session.execute(text("DELETE FROM T_QUESTIONS"))
                # 重置Oracle序列
                session.execute(text("ALTER SEQUENCE T_QUESTIONS_ID_SEQ RESTART START WITH 1"))
            elif db_name == 'mysql':
                # MySQL使用TRUNCATE TABLE，自动重置自增ID
                session.execute(text("TRUNCATE TABLE T_QUESTIONS"))
            elif db_name == 'sqlserver':
                # SQL Server使用TRUNCATE TABLE，自动重置自增ID
                session.execute(text("TRUNCATE TABLE T_QUESTIONS"))
            
            # 重新启用外键检查
            if db_name == 'mysql':
                session.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
            elif db_name == 'sqlserver':
                session.execute(text("ALTER TABLE T_SCORES CHECK CONSTRAINT ALL"))
            
            session.commit()
            results[db_name] = {'status': 'success', 'message': f'已成功初始化 {db_name} 的T_QUESTIONS表'}
            print(f"DEBUG: 初始化 {db_name} 的T_QUESTIONS表成功")
        except Exception as e:
            session.rollback()
            results[db_name] = {'status': 'error', 'message': str(e)}
            print(f"ERROR: 初始化 {db_name} 的T_QUESTIONS表失败 - {str(e)}")
        finally:
            session.close()
    
    return results

@app.get("/db/status")
def get_db_status():
    """检查并返回三个数据库的连接状态和各表数据量"""
    results = {}
    
    for db_name in engines.keys():
        try:
            session = next(get_session(db_name))
            try:
                # 检查连接状态
                if db_name == 'oracle':
                    session.execute(text("SELECT 1 FROM DUAL"))
                else:
                    session.execute(text("SELECT 1"))
                
                # 获取各表数据量
                tables = ['T_USERS', 'T_QUESTIONS', 'T_EXAMS', 'T_SCORES', 'T_SYNC_LOGS']
                table_counts = {}
                
                for table in tables:
                    try:
                        result = session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        table_counts[table] = result.scalar()
                    except Exception as e:
                        table_counts[table] = f"ERROR: {str(e)}"
                
                results[db_name] = {
                    'status': 'success',
                    'message': '连接成功',
                    'table_counts': table_counts
                }
            finally:
                session.close()
        except Exception as e:
            results[db_name] = {
                'status': 'error',
                'message': f'连接失败: {str(e)}',
                'table_counts': {}
            }
    
    return results

@app.get("/api/sync/logs")
def get_sync_logs(limit: int = 50):
    """获取最近的同步日志"""
    results = {}
    
    # 只查询MySQL数据库的日志，因为日志只写入MySQL
    db_name = 'mysql'
    try:
        session = next(get_session(db_name))
        try:
            # 查询最近的同步日志，按创建时间倒序，不添加额外过滤条件
            logs = session.query(SyncLog)
            logs = logs.order_by(SyncLog.created_at.desc())
            logs = logs.limit(limit).all()
            
            # 转换为字典列表
            log_list = []
            for log in logs:
                log_list.append({
                    'id': log.id,
                    'event_type': log.event_type,
                    'status': log.sync_status,
                    'error_msg': log.error_msg,
                    'created_at': log.created_at.isoformat() if log.created_at else None,
                    'source_db': log.source_db,
                    'target_db': log.target_db,
                    'payload': log.payload
                })
            
            results[db_name] = {
                'status': 'success',
                'logs': log_list
            }
        finally:
            session.close()
    except Exception as e:
        results[db_name] = {
            'status': 'error',
            'message': f'获取日志失败: {str(e)}',
            'logs': []
        }
    
    return results

# ---------------- API V2 接口 ----------------

@app.get("/api/db_status")
def get_api_db_status():
    """
    返回数据库连接状态和T_QUESTIONS、T_SCORES表的数据行数
    """
    results = {
        'mysql': {
            'status': 'offline',
            'question_count': 0,
            'score_count': 0
        },
        'sqlserver': {
            'status': 'offline',
            'question_count': 0,
            'score_count': 0
        },
        'oracle': {
            'status': 'offline',
            'question_count': 0,
            'score_count': 0
        }
    }
    
    for db_name in engines.keys():
        try:
            session = next(get_session(db_name))
            try:
                # 检查连接
                if db_name == 'oracle':
                    session.execute(text("SELECT 1 FROM DUAL"))
                else:
                    session.execute(text("SELECT 1"))
                
                # 获取T_QUESTIONS表行数
                result = session.execute(text("SELECT COUNT(*) FROM T_QUESTIONS"))
                question_count = result.scalar()
                
                # 获取T_SCORES表行数
                result = session.execute(text("SELECT COUNT(*) FROM T_SCORES"))
                score_count = result.scalar()
                
                results[db_name] = {
                    'status': 'online',
                    'question_count': question_count,
                    'score_count': score_count
                }
            finally:
                session.close()
        except Exception as e:
            results[db_name] = {
                'status': 'offline',
                'question_count': 0,
                'score_count': 0,
                'error': str(e)
            }
    
    return results

@app.get("/api/questions")
def get_api_questions(
    content: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    limit: int = 10,
    offset: int = 0
):
    """
    返回题目列表，支持分页和关键词搜索
    
    Args:
        content: 题目内容模糊查询（LIKE）
        min_score: 最低分数
        max_score: 最高分数
        limit: 每页返回的题目数量，默认10
        offset: 偏移量，默认0
    """
    questions = []
    total = 0
    
    try:
        # 从MySQL获取题目（作为主库）
        session = next(get_session('mysql'))
        try:
            # 构建查询
            query = session.query(Question)
            
            # 应用过滤条件
            if content:
                query = query.filter(Question.content.like(f"%{content}%"))
            
            if min_score is not None:
                query = query.filter(Question.score >= min_score)
            
            if max_score is not None:
                query = query.filter(Question.score <= max_score)
            
            # 获取总数
            total = query.count()
            
            # 应用分页
            query = query.limit(limit).offset(offset)
            
            # 执行查询
            db_questions = query.all()
            
            for q in db_questions:
                questions.append({
                    'question_id': q.id,
                    'question_guid': q.guid,
                    'question_content': q.content,
                    'question_answer': q.answer,
                    'question_score': q.score,
                    'highest_score': None,
                    'last_respondent': None,
                    'question_updated_at': q.updated_at.isoformat() if q.updated_at else None
                })
        finally:
            session.close()
    except Exception as e:
        # 如果MySQL失败，尝试从其他数据库获取
        for db_name in ['sqlserver', 'oracle']:
            try:
                session = next(get_session(db_name))
                try:
                    # 构建查询
                    query = session.query(Question)
                    
                    # 应用过滤条件
                    if content:
                        query = query.filter(Question.content.like(f"%{content}%"))
                    
                    if min_score is not None:
                        query = query.filter(Question.score >= min_score)
                    
                    if max_score is not None:
                        query = query.filter(Question.score <= max_score)
                    
                    # 获取总数
                    total = query.count()
                    
                    # 应用分页
                    query = query.limit(limit).offset(offset)
                    
                    # 执行查询
                    db_questions = query.all()
                    
                    for q in db_questions:
                        questions.append({
                            'question_id': q.id,
                            'question_guid': getattr(q, 'guid', None),
                            'question_content': q.content,
                            'question_answer': q.answer,
                            'question_score': q.score,
                            'highest_score': None,
                            'last_respondent': None,
                            'question_updated_at': q.updated_at.isoformat() if q.updated_at else None
                        })
                    break  # 如果成功获取，退出循环
                finally:
                    session.close()
            except Exception as e:
                continue
    
    return {"questions": questions, "total": total}

@app.get("/api/questions/search")
def search_questions(
    content: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
):
    """
    多条件检索题目
    
    Args:
        content: 题目内容模糊查询（LIKE）
        min_score: 最低分数
        max_score: 最高分数
        start_time: 开始时间（格式：YYYY-MM-DD HH:MM:SS）
        end_time: 结束时间（格式：YYYY-MM-DD HH:MM:SS）
    """
    questions = []
    
    try:
        # 从MySQL获取题目（作为主库）
        session = next(get_session('mysql'))
        try:
            query = session.query(Question)
            
            # 应用过滤条件
            if content:
                query = query.filter(Question.content.like(f"%{content}%"))
            
            if min_score is not None:
                query = query.filter(Question.score >= min_score)
            
            if max_score is not None:
                query = query.filter(Question.score <= max_score)
            
            if start_time:
                query = query.filter(Question.updated_at >= start_time)
            
            if end_time:
                query = query.filter(Question.updated_at <= end_time)
            
            db_questions = query.all()
            
            for q in db_questions:
                questions.append({
                    'question_id': q.id,
                    'question_guid': q.guid,
                    'question_content': q.content,
                    'question_answer': q.answer,
                    'question_score': q.score,
                    'highest_score': None,
                    'last_respondent': None,
                    'question_updated_at': q.updated_at.isoformat() if q.updated_at else None
                })
        finally:
            session.close()
    except Exception as e:
        # 如果MySQL失败，尝试从其他数据库获取
        for db_name in ['sqlserver', 'oracle']:
            try:
                session = next(get_session(db_name))
                try:
                    query = session.query(Question)
                    
                    # 应用过滤条件
                    if content:
                        query = query.filter(Question.content.like(f"%{content}%"))
                    
                    if min_score is not None:
                        query = query.filter(Question.score >= min_score)
                    
                    if max_score is not None:
                        query = query.filter(Question.score <= max_score)
                    
                    if start_time:
                        query = query.filter(Question.updated_at >= start_time)
                    
                    if end_time:
                        query = query.filter(Question.updated_at <= end_time)
                    
                    db_questions = query.all()
                    
                    for q in db_questions:
                        questions.append({
                            'question_id': q.id,
                            'question_guid': getattr(q, 'guid', None),
                            'question_content': q.content,
                            'question_answer': q.answer,
                            'question_score': q.score,
                            'highest_score': None,
                            'last_respondent': None,
                            'question_updated_at': q.updated_at.isoformat() if q.updated_at else None
                        })
                    break  # 如果成功获取，退出循环
                finally:
                    session.close()
            except Exception as e:
                continue
    
    return {"questions": questions}

@app.get("/api/data/complex-list")
def get_complex_list():
    """
    复杂管理接口
    
    SQL逻辑：找出每个分类下分数最高的一道题
    JOIN逻辑：连接T_QUESTIONS和T_SYNC_LOGS，展示每条数据的最新同步状态
    
    注意：由于Question模型没有分类字段，这里简化为返回所有题目的最高分
    由于SyncLog没有与Question相关的外键，这里只展示最新的同步状态
    """
    try:
        # 从MySQL获取数据
        session = next(get_session('mysql'))
        try:
            # 找出分数最高的题目
            highest_score_questions = session.query(Question).order_by(Question.score.desc()).limit(10).all()
            
            # 获取最新的同步状态
            latest_sync_log = session.query(SyncLog).order_by(SyncLog.created_at.desc()).first()
            
            # 构建响应数据
            result = {
                'highest_score_questions': [],
                'latest_sync_status': None
            }
            
            # 添加高分题目
            for q in highest_score_questions:
                result['highest_score_questions'].append({
                    'id': q.id,
                    'content': q.content,
                    'answer': q.answer,
                    'score': q.score,
                    'created_at': q.created_at.isoformat() if q.created_at else None
                })
            
            # 添加最新同步状态
            if latest_sync_log:
                result['latest_sync_status'] = {
                    'event_type': latest_sync_log.event_type,
                    'status': latest_sync_log.status,
                    'error_msg': latest_sync_log.error_msg,
                    'created_at': latest_sync_log.created_at.isoformat() if latest_sync_log.created_at else None
                }
            
            return result
        finally:
            session.close()
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/questions/details")
def get_questions_details():
    """
    全量详情接口：使用LEFT JOIN连接T_QUESTIONS、T_SCORES和T_USERS
    
    展示：题目-最高分-最后答题人的关联视图
    即使题目没有成绩记录，也要显示出来
    """
    details = []
    
    try:
        # 从MySQL获取数据（作为主库）
        session = next(get_session('mysql'))
        try:
            # 使用原生SQL实现复杂的LEFT JOIN查询
            sql = """
                SELECT 
                    q.id AS question_id,
                    q.guid AS question_guid,
                    q.content AS question_content,
                    q.answer AS question_answer,
                    q.score AS question_score,
                    MAX(s.score_value) AS highest_score,
                    u.username AS last_respondent,
                    q.updated_at AS question_updated_at
                FROM T_QUESTIONS q
                LEFT JOIN T_SCORES s ON q.id = s.question_id
                LEFT JOIN T_USERS u ON s.user_id = u.id
                GROUP BY q.id, q.guid, q.content, q.answer, q.score, q.updated_at, u.username
                ORDER BY q.id
            """
            
            result = session.execute(text(sql))
            
            for row in result:
                details.append({
                    'question_id': row.question_id,
                    'question_guid': row.question_guid,
                    'question_content': row.question_content,
                    'question_answer': row.question_answer,
                    'question_score': row.question_score,
                    'highest_score': row.highest_score,
                    'last_respondent': row.last_respondent,
                    'question_updated_at': row.question_updated_at.isoformat() if row.question_updated_at else None
                })
        finally:
            session.close()
    except Exception as e:
        # 如果MySQL失败，尝试从其他数据库获取
        for db_name in ['sqlserver', 'oracle']:
            try:
                session = next(get_session(db_name))
                try:
                    # 使用原生SQL实现复杂的LEFT JOIN查询，适配不同数据库
                    if db_name == 'sqlserver':
                        sql = """
                            SELECT 
                                q.id AS question_id,
                                q.guid AS question_guid,
                                q.content AS question_content,
                                q.answer AS question_answer,
                                q.score AS question_score,
                                MAX(s.score_value) AS highest_score,
                                u.username AS last_respondent,
                                q.updated_at AS question_updated_at
                            FROM T_QUESTIONS q
                            LEFT JOIN T_SCORES s ON q.id = s.question_id
                            LEFT JOIN T_USERS u ON s.user_id = u.id
                            GROUP BY q.id, q.guid, q.content, q.answer, q.score, q.updated_at, u.username
                            ORDER BY q.id
                        """
                    elif db_name == 'oracle':
                        sql = """
                            SELECT 
                                q.id AS question_id,
                                q.content AS question_content,
                                q.answer AS question_answer,
                                q.score AS question_score,
                                MAX(s.score_value) AS highest_score,
                                u.username AS last_respondent,
                                q.updated_at AS question_updated_at
                            FROM T_QUESTIONS q
                            LEFT JOIN T_SCORES s ON q.id = s.question_id
                            LEFT JOIN T_USERS u ON s.user_id = u.id
                            GROUP BY q.id, q.content, q.answer, q.score, q.updated_at, u.username
                            ORDER BY q.id
                        """
                    else:
                        continue
                    
                    result = session.execute(text(sql))
                    
                    for row in result:
                        details.append({
                            'question_id': row.question_id,
                            'question_content': row.question_content,
                            'question_answer': row.question_answer,
                            'question_score': row.question_score,
                            'highest_score': row.highest_score,
                            'last_respondent': row.last_respondent,
                            'question_updated_at': row.question_updated_at.isoformat() if row.question_updated_at else None
                        })
                    break  # 如果成功获取，退出循环
                finally:
                    session.close()
            except Exception as e:
                continue
    
    return {"details": details}

@app.get("/api/scores")
def get_api_scores():
    """
    获取学生成绩数据列表
    
    使用JOIN连接t_scores和t_users表，返回指定字段
    返回字段：id, user_id, username (从t_users获取), exam_id, score_value, created_at
    """
    scores = []
    
    try:
        # 从MySQL获取数据（作为主库）
        session = next(get_session('mysql'))
        try:
            # 使用原生SQL实现LEFT JOIN查询，确保即使找不到用户名也能返回成绩记录
            sql = """
                SELECT 
                    s.id,
                    s.user_id,
                    u.username,
                    s.exam_id,
                    s.score_value,
                    s.created_at
                FROM T_SCORES s
                LEFT JOIN T_USERS u ON s.user_id = u.id
                ORDER BY s.created_at DESC
            """
            
            result = session.execute(text(sql))
            
            for row in result:
                scores.append({
                    'id': row.id,
                    'user_id': row.user_id,
                    'username': row.username,
                    'exam_id': row.exam_id,
                    'score_value': row.score_value,
                    'created_at': row.created_at.isoformat() if row.created_at else None
                })
        finally:
            session.close()
    except Exception as e:
        print(f"Error getting scores: {e}")
    
    return {"scores": scores}

@app.get("/api/scores/check-sync")
def check_scores_sync():
    """
    对比MySQL、Oracle、SQL Server三个库中t_scores表的数据差异
    
    对比依据：使用user_id和exam_id作为联合唯一标识
    返回结果：告知前端哪些成绩记录是"三库一致"的，哪些是"仅存在于某库"或"分值不一致"的
    """
    # 获取所有数据库名称
    db_names = list(engines.keys())
    
    # 从每个数据库获取成绩数据
    all_scores = {}
    for db_name in db_names:
        try:
            session = next(get_session(db_name))
            try:
                # 使用原生SQL获取成绩数据
                sql = """
                    SELECT 
                        s.id,
                        s.user_id,
                        u.username,
                        s.exam_id,
                        s.score_value,
                        s.created_at
                    FROM T_SCORES s
                    LEFT JOIN T_USERS u ON s.user_id = u.id
                """
                
                result = session.execute(text(sql))
                scores = []
                for row in result:
                    scores.append({
                        'id': row.id,
                        'user_id': row.user_id,
                        'username': row.username,
                        'exam_id': row.exam_id,
                        'score_value': row.score_value,
                        'created_at': row.created_at.isoformat() if row.created_at else None,
                        'db_name': db_name
                    })
                all_scores[db_name] = scores
            finally:
                session.close()
        except Exception as e:
            print(f"Error getting scores from {db_name}: {e}")
            all_scores[db_name] = []
    
    # 构建联合唯一标识到分数的映射
    # 格式：{(user_id, exam_id): {db_name: score_value, ...}}
    score_mapping = {}
    for db_name, scores in all_scores.items():
        for score in scores:
            key = (score['user_id'], score['exam_id'])
            if key not in score_mapping:
                score_mapping[key] = {
                    'user_id': score['user_id'],
                    'username': score['username'],
                    'exam_id': score['exam_id'],
                    'scores_by_db': {}
                }
            # 更新用户名（如果存在）
            if score['username']:
                score_mapping[key]['username'] = score['username']
            # 添加数据库分数
            score_mapping[key]['scores_by_db'][db_name] = score['score_value']
    
    # 分析差异
    result = []
    for key, data in score_mapping.items():
        # 确定同步状态
        db_count = len(data['scores_by_db'])
        score_values = list(data['scores_by_db'].values())
        all_same_score = all(score == score_values[0] for score in score_values)
        
        status = ""
        if db_count == 3 and all_same_score:
            status = "synced"  # 三库一致
        elif db_count < 3 or not all_same_score:
            status = "diff"  # 存在差异
        else:
            status = "unknown"  # 未知状态
        
        result.append({
            'user_id': data['user_id'],
            'username': data['username'],
            'exam_id': data['exam_id'],
            'status': status,
            'scores_by_db': data['scores_by_db'],
            'present_in_dbs': list(data['scores_by_db'].keys())
        })
    
    return {
        "status": "success",
        "data": result,
        "db_names": db_names
    }

@app.post("/api/scores")
def create_api_score(request: ScoreCreateRequest, current_user: User = Depends(get_current_user)):
    """
    添加成绩记录
    
    接收user_id, exam_id, score_value并写入到指定的数据库中
    """
    # 检查用户权限，只允许admin角色执行写入操作
    if current_user.role != "admin":
        print(f"拒绝操作：当前角色为 [{current_user.role}]，需要的角色为 [admin]")
        raise HTTPException(status_code=403, detail="只有管理员账号有权修改数据")
    
    # 验证目标数据库
    for db_name in request.target_dbs:
        if db_name not in engines:
            raise HTTPException(status_code=400, detail=f"无效的目标数据库: {db_name}")
    
    try:
        results = {}
        failed_dbs = []
        
        # 创建ScoreCreate对象
        score = ScoreCreate(
            user_id=request.user_id,
            exam_id=request.exam_id,
            score_value=request.score_value
        )
        
        # 动态写入到指定的数据库中
        for db_name in request.target_dbs:
            try:
                # 获取数据库会话
                session = next(get_session(db_name))
                try:
                    # 执行数据库操作
                    result = create_score(session, score)
                    # 提交事务
                    session.commit()
                    results[db_name] = {
                        "status": "success",
                        "result": result.__dict__ if hasattr(result, '__dict__') else result
                    }
                except Exception as e:
                    # 回滚事务
                    session.rollback()
                    # 记录失败信息
                    results[db_name] = {
                        "status": "failed",
                        "error": str(e)
                    }
                    failed_dbs.append(db_name)
                    print(f"ERROR: 在 {db_name} 上执行操作失败: {str(e)}")
                    # 打印详细的错误信息，用于调试
                    import traceback
                    traceback.print_exc()
                finally:
                    # 关闭会话
                    session.close()
            except Exception as e:
                # 记录会话获取失败信息
                results[db_name] = {
                    "status": "failed",
                    "error": f"无法获取数据库会话: {str(e)}"
                }
                failed_dbs.append(db_name)
                print(f"ERROR: 无法获取 {db_name} 数据库会话: {str(e)}")
                # 打印详细的错误信息，用于调试
                import traceback
                traceback.print_exc()
        
        if failed_dbs:
            return {
                "status": "partial",
                "message": f"成绩添加部分成功，{len(request.target_dbs) - len(failed_dbs)}个数据库成功，{len(failed_dbs)}个数据库失败",
                "results": results,
                "failed_dbs": failed_dbs
            }
        else:
            return {
                "status": "success",
                "message": "成绩添加成功",
                "results": results
            }
    except Exception as e:
        print(f"Error creating score: {e}")
        # 打印详细的错误信息，用于调试
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"添加成绩失败: {str(e)}")

@app.delete("/api/scores/{id}")
def delete_api_score(id: int, current_user: User = Depends(get_current_user)):
    """
    删除指定成绩记录
    
    根据ID删除指定成绩记录，同步删除所有数据库中的记录
    """
    # 检查用户权限，只允许admin角色执行删除操作
    if current_user.role != "admin":
        print(f"拒绝操作：当前角色为 [{current_user.role}]，需要的角色为 [admin]")
        raise HTTPException(status_code=403, detail="只有管理员账号有权修改数据")
    
    try:
        # 调用同步删除函数
        result = delete_score_sync(id)
        return {"status": "success", "message": "成绩删除成功", "result": result}
    except Exception as e:
        print(f"Error deleting score: {e}")
        raise HTTPException(status_code=500, detail=f"删除成绩失败: {str(e)}")

@app.post("/api/scores/sync")
def sync_scores(request: ScoreSyncRequest, current_user: User = Depends(get_current_user)):
    """
    手动同步成绩记录
    
    允许用户点击同步按钮，将选中的成绩记录从当前库强制推送到其他缺少的数据库中
    同步成功后，必须向t_sync_logs写入一条类型为SCORE_SYNC的真实日志
    """
    # 检查用户权限，只允许admin角色执行同步操作
    if current_user.role != "admin":
        print(f"拒绝操作：当前角色为 [{current_user.role}]，需要的角色为 [admin]")
        raise HTTPException(status_code=403, detail="只有管理员账号有权执行同步操作")
    
    # 验证源数据库
    if request.source_db not in engines:
        raise HTTPException(status_code=400, detail="无效的源数据库")
    
    # 验证目标数据库
    if not request.target_dbs:
        # 如果没有指定目标数据库，则同步到所有其他数据库
        request.target_dbs = [db for db in engines.keys() if db != request.source_db]
    else:
        # 验证目标数据库是否有效
        for db in request.target_dbs:
            if db not in engines:
                raise HTTPException(status_code=400, detail=f"无效的目标数据库: {db}")
    
    # 从源数据库获取成绩记录
    source_session = next(get_session(request.source_db))
    try:
        # 使用原生SQL查询，确保获取到完整的成绩记录
        sql = """
            SELECT 
                s.id,
                s.user_id,
                s.exam_id,
                s.score_value,
                s.created_at
            FROM T_SCORES s
            WHERE s.user_id = :user_id AND s.exam_id = :exam_id
        """
        
        result = source_session.execute(text(sql), {
            'user_id': request.user_id,
            'exam_id': request.exam_id
        })
        
        source_score = result.fetchone()
        if not source_score:
            raise HTTPException(status_code=404, detail="源数据库中未找到该成绩记录")
    finally:
        source_session.close()
    
    # 执行同步操作
    results = {}
    failed_dbs = []
    
    for target_db in request.target_dbs:
        if target_db == request.source_db:
            continue
        
        try:
            target_session = next(get_session(target_db))
            try:
                # 检查目标数据库中是否已存在该成绩记录
                check_sql = """
                    SELECT id FROM T_SCORES 
                    WHERE user_id = :user_id AND exam_id = :exam_id
                """
                
                check_result = target_session.execute(text(check_sql), {
                    'user_id': request.user_id,
                    'exam_id': request.exam_id
                })
                
                existing_score = check_result.fetchone()
                
                if existing_score:
                    # 更新现有记录
                    update_sql = """
                        UPDATE T_SCORES 
                        SET score_value = :score_value, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = :user_id AND exam_id = :exam_id
                    """
                    
                    target_session.execute(text(update_sql), {
                        'score_value': source_score.score_value,
                        'user_id': request.user_id,
                        'exam_id': request.exam_id
                    })
                    operation_type = "UPDATE"
                else:
                    # 插入新记录
                    insert_sql = """
                        INSERT INTO T_SCORES (user_id, exam_id, score_value, created_at, updated_at)
                        VALUES (:user_id, :exam_id, :score_value, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """
                    
                    target_session.execute(text(insert_sql), {
                        'user_id': request.user_id,
                        'exam_id': request.exam_id,
                        'score_value': source_score.score_value
                    })
                    operation_type = "INSERT"
                
                # 提交事务
                target_session.commit()
                
                # 记录同步日志
                payload = {
                    'user_id': request.user_id,
                    'exam_id': request.exam_id,
                    'score_value': source_score.score_value
                }
                
                CrossDBManager.record_sync_task(
                    source_db=request.source_db,
                    target_db=target_db,
                    operation_type=operation_type,
                    event_type="SCORE_SYNC",
                    payload=payload
                )
                
                results[target_db] = {
                    "status": "success",
                    "message": f"成绩记录已成功{operation_type}到{target_db}数据库"
                }
            except Exception as e:
                target_session.rollback()
                results[target_db] = {
                    "status": "failed",
                    "error": str(e)
                }
                failed_dbs.append(target_db)
            finally:
                target_session.close()
        except Exception as e:
            results[target_db] = {
                "status": "failed",
                "error": f"无法连接到目标数据库: {str(e)}"
            }
            failed_dbs.append(target_db)
    
    return {
        "status": "partial" if failed_dbs else "success",
        "results": results,
        "failed_dbs": failed_dbs,
        "message": f"同步操作已完成，成功同步到{len(request.target_dbs) - len(failed_dbs)}个数据库，{len(failed_dbs)}个数据库同步失败"
    }

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password by comparing hashed values"""
    return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

@app.post("/api/login")
def login(login_data: LoginRequest):
    """用户登录"""
    # 查找用户
    user = None
    
    for db_name in engines.keys():
        try:
            session = next(get_session(db_name))
            try:
                user = session.query(User).filter(User.username == login_data.username).first()
                if user:
                    break
            finally:
                session.close()
        except Exception:
            continue
    
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    # Simple token implementation (in production, use JWT or proper token system)
    token = hashlib.sha256((user.username + user.role).encode()).hexdigest()
    return {"token": token, "username": user.username, "role": user.role}

@app.post("/api/questions")
def create_api_question(request: QuestionCreateRequest, current_user: User = Depends(get_current_user)):
    """添加新题目，支持指定目标数据库
    - 直接写入被勾选的数据库
    - 对于未勾选的数据库，创建待同步任务"""
    # 检查用户权限，guest用户无权修改数据
    if current_user.role == "guest":
        raise HTTPException(status_code=403, detail="访客账号无权修改数据")
    
    result = {
        "status": "success",
        "direct_writes": [],
        "pending_tasks": []
    }
    
    # 获取所有可用数据库
    all_dbs = list(engines.keys())
    # 获取被勾选的数据库
    selected_dbs = request.target_dbs
    # 获取未被勾选的数据库
    pending_dbs = [db for db in all_dbs if db not in selected_dbs]
    
    # 生成唯一GUID
    import uuid
    generated_guid = str(uuid.uuid4())
    
    # 直接写入被勾选的数据库
    for db_name in selected_dbs:
        try:
            db = next(get_session(db_name))
            try:
                # 准备题目数据
                question_data = request.question.dict()
                question_data['guid'] = generated_guid
                
                # 创建题目
                db_question = Question(**question_data)
                db.add(db_question)
                db.commit()
                db.refresh(db_question)
                
                result["direct_writes"].append({
                    "db": db_name,
                    "status": "success"
                })
            finally:
                db.close()
        except Exception as e:
            result["direct_writes"].append({
                "db": db_name,
                "status": "error",
                "error": str(e)
            })
    
    # 为未勾选的数据库创建待同步任务
    for db_name in pending_dbs:
        try:
            # 准备payload数据
            payload = {
                "guid": generated_guid,
                "content": request.question.content,
                "answer": request.question.answer,
                "score": request.question.score
            }
            
            # 记录同步任务
            log_id = CrossDBManager.record_sync_task(
                source_db="mysql",  # 假设主库是MySQL
                target_db=db_name,
                operation_type="INSERT",
                event_type="question_create",
                payload=payload
            )
            
            result["pending_tasks"].append({
                "db": db_name,
                "log_id": log_id,
                "status": "pending"
            })
        except Exception as e:
            result["pending_tasks"].append({
                "db": db_name,
                "status": "error",
                "error": str(e)
            })
    
    return result

@app.put("/api/questions/{question_guid}")
def update_api_question(question_guid: str, request: QuestionUpdateRequest):
    """更新题目，支持指定目标数据库
    - 直接写入被勾选的数据库
    - 对于未勾选的数据库，创建待同步任务"""
    result = {
        "status": "success",
        "direct_writes": [],
        "pending_tasks": []
    }
    
    # 获取所有可用数据库
    all_dbs = list(engines.keys())
    # 获取被勾选的数据库
    selected_dbs = request.target_dbs
    # 获取未被勾选的数据库
    pending_dbs = [db for db in all_dbs if db not in selected_dbs]
    
    # 直接更新被勾选的数据库
    for db_name in selected_dbs:
        try:
            db = next(get_session(db_name))
            try:
                # 直接更新题目
                db_question = update_question(db, question_guid, request.question)
                db.commit()
                
                result["direct_writes"].append({
                    "db": db_name,
                    "status": "success"
                })
            finally:
                db.close()
        except Exception as e:
            result["direct_writes"].append({
                "db": db_name,
                "status": "error",
                "error": str(e)
            })
    
    # 为未勾选的数据库创建待同步任务
    for db_name in pending_dbs:
        try:
            # 准备payload数据
            payload = {
                "guid": question_guid,
                "content": request.question.content,
                "answer": request.question.answer,
                "score": request.question.score
            }
            
            # 记录同步任务
            log_id = CrossDBManager.record_sync_task(
                source_db="mysql",  # 假设主库是MySQL
                target_db=db_name,
                operation_type="UPDATE",
                event_type="question_update",
                payload=payload
            )
            
            result["pending_tasks"].append({
                "db": db_name,
                "log_id": log_id,
                "status": "pending"
            })
        except Exception as e:
            result["pending_tasks"].append({
                "db": db_name,
                "status": "error",
                "error": str(e)
            })
    
    return result

@app.delete("/api/questions/{question_guid}")
def delete_api_question(question_guid: str, current_user: User = Depends(get_current_user)):
    """删除题目，同步删除所有数据库中的相同GUID题目"""
    # 检查用户权限，guest用户无权修改数据
    if current_user.role == "guest":
        raise HTTPException(status_code=403, detail="访客账号无权修改数据")
    
    result = {
        "status": "success",
        "deleted_dbs": [],
        "failed_dbs": []
    }
    
    # 获取所有可用数据库
    all_dbs = list(engines.keys())
    
    # 直接删除所有数据库中的题目
    for db_name in all_dbs:
        try:
            db = next(get_session(db_name))
            try:
                # 查询要删除的题目
                question = db.query(Question).filter(Question.guid == question_guid).first()
                if question:
                    # 删除题目
                    db.delete(question)
                    db.commit()
                    result["deleted_dbs"].append(db_name)
            finally:
                db.close()
        except Exception as e:
            result["failed_dbs"].append({
                "db": db_name,
                "error": str(e)
            })
    
    # 如果所有数据库都删除失败，返回失败状态
    if len(result["failed_dbs"]) == len(all_dbs):
        result["status"] = "error"
    
    return result

@app.get("/api/sync/check")
def check_sync_status():
    """检测三个数据库中T_QUESTIONS表的差异"""
    # 用于存储每个数据库中的题目，以content的MD5作为唯一标识
    db_questions = {}
    all_dbs = list(engines.keys())
    
    # 获取每个数据库中的题目
    for db_name in all_dbs:
        try:
            db = next(get_session(db_name))
            try:
                questions = db.query(Question).all()
                db_questions[db_name] = {}
                for q in questions:
                    # 使用content的MD5作为唯一标识
                    content_md5 = hashlib.md5(q.content.encode()).hexdigest()
                    db_questions[db_name][content_md5] = {
                        'id': q.id,
                        'guid': q.guid,
                        'content': q.content,
                        'answer': q.answer,
                        'score': q.score
                    }
            finally:
                db.close()
        except Exception as e:
            return {
                "status": "error",
                "message": f"获取{db_name}数据库题目失败: {str(e)}"
            }
    
    # 找出所有唯一的题目标识
    all_question_keys = set()
    for db in all_dbs:
        all_question_keys.update(db_questions[db].keys())
    
    # 检测差异
    differences = []
    for key in all_question_keys:
        present_in = []
        missing_in = []
        question_data = None
        
        for db in all_dbs:
            if key in db_questions[db]:
                present_in.append(db)
                if not question_data:
                    question_data = db_questions[db][key]
            else:
                missing_in.append(db)
        
        # 如果题目在某些库中缺失，记录差异
        if missing_in:
            differences.append({
                'key': key,
                'question': question_data,
                'present_in': present_in,
                'missing_in': missing_in
            })
    
    return {
        "status": "success",
        "total_differences": len(differences),
        "differences": differences
    }

class RepairSyncRequest(BaseModel):
    """修复同步请求模型"""
    db_name: str
    event_type: str

@app.post("/api/sync/execute/{log_id}")
def execute_sync_task(log_id: int):
    """执行同步任务
    - 读取日志中的payload和operation_type
    - 将数据写入target_db
    - 更新日志状态为SUCCESS
    """
    try:
        # 调用CrossDBManager执行同步任务
        success = CrossDBManager.execute_sync_task(log_id)
        
        if success:
            return {
                "status": "success",
                "message": f"同步任务 {log_id} 执行成功"
            }
        else:
            return {
                "status": "error",
                "message": f"同步任务 {log_id} 执行失败"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"执行同步任务失败: {str(e)}"
        }

@app.post("/api/sync/execute")
def execute_manual_sync():
    """执行手动同步，将缺失的题目数据从源库同步到目标库"""
    # 1. 先检测差异
    sync_check_result = check_sync_status()
    
    if sync_check_result["status"] == "error":
        return sync_check_result
    
    differences = sync_check_result["differences"]
    if not differences:
        return {
            "status": "success",
            "message": "所有数据库数据已完全同步"
        }
    
    # 2. 执行同步操作
    sync_results = {
        "total_sync": len(differences),
        "success_count": 0,
        "failed_count": 0,
        "details": []
    }
    
    # 3. 记录同步日志
    sync_log = None
    mysql_session = next(get_session('mysql'))
    
    try:
        # 遍历所有差异记录
        for diff in differences:
            # 源库：选择第一个存在该题目的数据库
            source_db = diff["present_in"][0]
            # 题目数据
            question_data = diff["question"]
            
            # 同步到所有缺失的数据库
            for target_db in diff["missing_in"]:
                try:
                    # 获取源库和目标库会话
                    source_session = next(get_session(source_db))
                    target_session = next(get_session(target_db))
                    
                    try:
                        # 检查目标库中是否已存在该题目（幂等性）
                        content_md5 = diff["key"]
                        existing_question = None
                        
                        # 遍历目标库中的题目，检查是否已存在相同content的题目
                        all_target_questions = target_session.query(Question).all()
                        for q in all_target_questions:
                            if hashlib.md5(q.content.encode()).hexdigest() == content_md5:
                                existing_question = q
                                break
                        
                        if not existing_question:
                            # 从源库获取完整题目数据
                            source_question = source_session.query(Question).filter(Question.guid == question_data["guid"]).first()
                            
                            if source_question:
                                # 插入到目标库
                                new_question = Question(
                                    guid=source_question.guid,
                                    content=source_question.content,
                                    answer=source_question.answer,
                                    score=source_question.score
                                )
                                target_session.add(new_question)
                                target_session.commit()
                                
                                # 记录单条同步成功日志
                                try:
                                    sync_log_entry = SyncLog(
                                        source_db=source_db,
                                        target_db=target_db,
                                        operation_type="INSERT",
                                        event_type="manual_sync",
                                        sync_status="SUCCESS",
                                        payload=json.dumps({
                                            "question_id": source_question.id,
                                            "question_guid": source_question.guid,
                                            "question_content": source_question.content[:20] + "..."
                                        }),
                                        created_at=datetime.now()
                                    )
                                    mysql_session.add(sync_log_entry)
                                    mysql_session.commit()
                                    print(f"DEBUG: 成功写入同步日志到MySQL: {source_db} -> {target_db}")
                                except Exception as log_error:
                                    print(f"ERROR: 写入同步成功日志失败: {str(log_error)}")
                                    mysql_session.rollback()
                                
                                sync_results["success_count"] += 1
                                sync_results["details"].append({
                                    "question": source_question.content[:20] + "...",
                                    "source_db": source_db,
                                    "target_db": target_db,
                                    "status": "success"
                                })
                        else:
                            # 已存在，跳过（幂等性）
                            sync_results["success_count"] += 1
                            sync_results["details"].append({
                                "question": question_data["content"][:20] + "...",
                                "source_db": source_db,
                                "target_db": target_db,
                                "status": "skipped"  # 已存在，跳过
                            })
                    finally:
                        source_session.close()
                        target_session.close()
                except Exception as e:
                    # 记录单条同步失败日志
                    try:
                        sync_log_entry = SyncLog(
                            source_db=source_db,
                            target_db=target_db,
                            operation_type="INSERT",
                            event_type="manual_sync",
                            sync_status="FAILED",
                            error_msg=str(e),
                            payload=json.dumps({
                                "question_guid": question_data["guid"],
                                "question_content": question_data["content"][:20] + "..."
                            }),
                            created_at=datetime.now()
                        )
                        mysql_session.add(sync_log_entry)
                        mysql_session.commit()
                        print(f"DEBUG: 成功写入同步失败日志到MySQL: {source_db} -> {target_db}")
                    except Exception as log_error:
                        print(f"ERROR: 写入同步失败日志失败: {str(log_error)}")
                        mysql_session.rollback()
                    
                    sync_results["failed_count"] += 1
                    sync_results["details"].append({
                        "question": question_data["content"][:20] + "...",
                        "source_db": source_db,
                        "target_db": target_db,
                        "status": "failed",
                        "error": str(e)
                    })
        
        # 记录同步完成日志
        try:
            sync_log = SyncLog(
                source_db="manual",
                target_db=",".join(engines.keys()),
                operation_type="INSERT",
                event_type="manual_sync",
                sync_status="SUCCESS" if sync_results["failed_count"] == 0 else "PARTIAL",
                error_msg="",
                payload=json.dumps({
                    "total_sync": sync_results["total_sync"],
                    "success_count": sync_results["success_count"],
                    "failed_count": sync_results["failed_count"]
                }),
                created_at=datetime.now()
            )
            mysql_session.add(sync_log)
            mysql_session.commit()
            print(f"DEBUG: 成功写入同步完成日志到MySQL")
        except Exception as log_error:
            print(f"ERROR: 写入同步完成日志失败: {str(log_error)}")
            mysql_session.rollback()
        
        return {
            "status": "success",
            "message": f"手动同步完成，成功同步 {sync_results['success_count']} 条，失败 {sync_results['failed_count']} 条",
            "results": sync_results
        }
    except Exception as e:
        mysql_session.rollback()
        return {
            "status": "error",
            "message": f"手动同步失败: {str(e)}"
        }
    finally:
        mysql_session.close()

@app.post("/api/repair-sync")
def repair_sync(request: RepairSyncRequest):
    """
    一键修复同步功能：将MySQL的数据同步到指定数据库
    
    Args:
        request: 修复请求参数
            - db_name: 要修复的数据库名称 (oracle/sqlserver)
            - event_type: 事件类型
    """
    db_name = request.db_name
    
    # 验证数据库名称
    if db_name not in ['oracle', 'sqlserver']:
        raise HTTPException(status_code=400, detail="无效的数据库名称，只能是oracle或sqlserver")
    
    try:
        # 从MySQL获取所有数据
        mysql_session = next(get_session('mysql'))
        try:
            from .models import User, Exam, Question, Score
            
            # 获取所有表的数据
            mysql_users = mysql_session.query(User).all()
            mysql_exams = mysql_session.query(Exam).all()
            mysql_questions = mysql_session.query(Question).all()
            mysql_scores = mysql_session.query(Score).all()
        finally:
            mysql_session.close()
        
        # 连接目标数据库
        target_session = next(get_session(db_name))
        try:
            # 处理外键约束（如果有）
            if db_name == 'sqlserver':
                # SQL Server禁用所有约束
                target_session.execute(text("ALTER TABLE T_SCORES NOCHECK CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_EXAMS NOCHECK CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_QUESTIONS NOCHECK CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_USERS NOCHECK CONSTRAINT ALL"))
            elif db_name == 'oracle':
                # Oracle禁用外键约束（如果有）
                target_session.execute(text("ALTER TABLE T_SCORES DISABLE CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_EXAMS DISABLE CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_QUESTIONS DISABLE CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_USERS DISABLE CONSTRAINT ALL"))
            
            # 清空目标数据库的所有相关表（按依赖顺序）
            tables_to_truncate = ['T_SCORES', 'T_EXAMS', 'T_QUESTIONS', 'T_USERS']
            
            for table in tables_to_truncate:
                if db_name == 'oracle':
                    target_session.execute(text(f"DELETE FROM {table}"))
                else:
                    target_session.execute(text(f"TRUNCATE TABLE {table}"))
            
            # 重新插入MySQL的数据（按依赖顺序）
            sync_count = 0
            
            # 1. 插入用户数据
            for user in mysql_users:
                target_user = User(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    password_hash=user.password_hash,
                    role=user.role,
                    created_at=user.created_at,
                    updated_at=user.updated_at
                )
                target_session.add(target_user)
                sync_count += 1
            
            # 2. 插入题目数据
            for question in mysql_questions:
                target_question = Question(
                    id=question.id,
                    guid=question.guid,
                    content=question.content,
                    answer=question.answer,
                    score=question.score,
                    created_at=question.created_at,
                    updated_at=question.updated_at
                )
                target_session.add(target_question)
                sync_count += 1
            
            # 3. 插入试卷数据
            for exam in mysql_exams:
                target_exam = Exam(
                    id=exam.id,
                    name=exam.name,
                    start_time=exam.start_time,
                    end_time=exam.end_time,
                    created_at=exam.created_at,
                    updated_at=exam.updated_at
                )
                target_session.add(target_exam)
                sync_count += 1
            
            # 4. 插入成绩数据
            for score in mysql_scores:
                target_score = Score(
                    id=score.id,
                    user_id=score.user_id,
                    exam_id=score.exam_id,
                    score_value=score.score_value,
                    created_at=score.created_at,
                    updated_at=score.updated_at
                )
                target_session.add(target_score)
                sync_count += 1
            
            # 恢复外键约束
            if db_name == 'sqlserver':
                target_session.execute(text("ALTER TABLE T_USERS CHECK CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_QUESTIONS CHECK CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_EXAMS CHECK CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_SCORES CHECK CONSTRAINT ALL"))
            elif db_name == 'oracle':
                target_session.execute(text("ALTER TABLE T_USERS ENABLE CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_QUESTIONS ENABLE CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_EXAMS ENABLE CONSTRAINT ALL"))
                target_session.execute(text("ALTER TABLE T_SCORES ENABLE CONSTRAINT ALL"))
            
            # 提交事务
            target_session.commit()
            
            return {
                "status": "success",
                "message": f"成功将MySQL数据同步到{db_name}数据库",
                "sync_count": sync_count
            }
        except Exception as e:
            target_session.rollback()
            raise HTTPException(status_code=500, detail=f"同步数据失败: {str(e)}")
        finally:
            target_session.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"修复同步失败: {str(e)}")

@app.get("/api/reports/summary")
def get_reports_summary():
    """
    获取试卷汇总报告
    """
    results = {}
    
    for db_name in engines.keys():
        try:
            session = next(get_session(db_name))
            try:
                # 使用原生SQL进行多表连接查询
                if db_name == 'mysql':
                    sql = """SELECT 
                        ep.paper_name,
                        COUNT(pq.question_id) as total_questions,
                        ep.total_score
                    FROM T_EXAM_PAPERS ep
                    LEFT JOIN T_PAPER_QUESTIONS pq ON ep.id = pq.paper_id
                    GROUP BY ep.id, ep.paper_name, ep.total_score
                    ORDER BY ep.id"""
                elif db_name == 'sqlserver':
                    sql = """SELECT 
                        ep.paper_name,
                        COUNT(pq.question_id) as total_questions,
                        ep.total_score
                    FROM T_EXAM_PAPERS ep
                    LEFT JOIN T_PAPER_QUESTIONS pq ON ep.id = pq.paper_id
                    GROUP BY ep.id, ep.paper_name, ep.total_score
                    ORDER BY ep.id"""
                else:  # oracle
                    sql = """SELECT 
                        ep.paper_name,
                        COUNT(pq.question_id) as total_questions,
                        ep.total_score
                    FROM T_EXAM_PAPERS ep
                    LEFT JOIN T_PAPER_QUESTIONS pq ON ep.id = pq.paper_id
                    GROUP BY ep.id, ep.paper_name, ep.total_score
                    ORDER BY ep.id"""
                
                result = session.execute(text(sql))
                summary = []
                for row in result:
                    summary.append({
                        "paper_name": row[0],
                        "total_questions": row[1],
                        "total_score": float(row[2])
                    })
                
                results[db_name] = {
                    "status": "success",
                    "summary": summary
                }
            finally:
                session.close()
        except Exception as e:
            results[db_name] = {
                "status": "error",
                "message": f"获取报告失败: {str(e)}"
            }


@app.get("/api/reports/student-scores")
def get_student_scores_report():
    """
    获取学生成绩分析报告
    
    使用多表连接（JOIN T_USERS, T_SCORES, T_EXAMS）来展示：
    - 学生姓名
    - 试卷名
    - 得分
    - 该次同步的状态
    """
    results = {}
    
    for db_name in engines.keys():
        try:
            session = next(get_session(db_name))
            try:
                # 使用原生SQL进行多表连接查询
                if db_name == 'mysql':
                    sql = """SELECT 
                        u.username AS student_name,
                        ep.paper_name AS exam_name,
                        s.score_value AS score,
                        sl.status AS sync_status
                    FROM T_SCORES s
                    JOIN T_USERS u ON s.user_id = u.id
                    JOIN T_EXAM_PAPERS ep ON s.paper_id = ep.id
                    LEFT JOIN T_SYNC_LOGS sl ON s.id = sl.record_id AND sl.event_type = 'update_score'
                    ORDER BY u.username, ep.paper_name"""
                elif db_name == 'sqlserver':
                    sql = """SELECT 
                        u.username AS student_name,
                        ep.paper_name AS exam_name,
                        s.score_value AS score,
                        sl.status AS sync_status
                    FROM T_SCORES s
                    JOIN T_USERS u ON s.user_id = u.id
                    JOIN T_EXAM_PAPERS ep ON s.paper_id = ep.id
                    LEFT JOIN T_SYNC_LOGS sl ON s.id = sl.record_id AND sl.event_type = 'update_score'
                    ORDER BY u.username, ep.paper_name"""
                else:  # oracle
                    sql = """SELECT 
                        u.username AS student_name,
                        ep.paper_name AS exam_name,
                        s.score_value AS score,
                        sl.status AS sync_status
                    FROM T_SCORES s
                    JOIN T_USERS u ON s.user_id = u.id
                    JOIN T_EXAM_PAPERS ep ON s.paper_id = ep.id
                    LEFT JOIN T_SYNC_LOGS sl ON s.id = sl.record_id AND sl.event_type = 'update_score'
                    ORDER BY u.username, ep.paper_name"""
                
                result = session.execute(text(sql))
                scores_report = []
                for row in result:
                    scores_report.append({
                        "student_name": row.student_name,
                        "exam_name": row.exam_name,
                        "score": float(row.score) if row.score else 0.0,
                        "sync_status": row.sync_status if row.sync_status else "unknown"
                    })
                
                results[db_name] = {
                    "status": "success",
                    "scores_report": scores_report
                }
            finally:
                session.close()
        except Exception as e:
            results[db_name] = {
                "status": "error",
                "message": f"获取报告失败: {str(e)}"
            }    
    
    return results
