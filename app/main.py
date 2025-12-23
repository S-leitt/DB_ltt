from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, List, Optional
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .database import engines, get_session, SIMULATE_ORACLE_FAILURE
from .sync_decorator import CrossDBManager
from .models import Question, Score, SyncLog, User
from sqlalchemy.orm import Session
from sqlalchemy import text
import hashlib

app = FastAPI(
    title="多数据库同步系统",
    description="考试组卷系统的多数据库同步服务",
    version="1.0.0"
)

# 启动时打印所有路由
@app.on_event("startup")
async def print_routes():
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

class SimulateFaultRequest(BaseModel):
    """模拟故障请求模型"""
    enable: bool

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

@app.post("/test-connection", response_model=Dict[str, ConnectionTestResult])
def test_connection():
    """测试所有数据库连接"""
    results = {}
    
    for db_name, engine in engines.items():
        try:
            # 测试连接 - 使用text()包装SQL语句
            with engine.connect() as conn:
                # 针对不同数据库使用不同的测试语句
                if db_name == 'oracle':
                    # Oracle需要FROM子句
                    conn.execute(text("SELECT 1 FROM DUAL"))
                else:
                    # MySQL和SQL Server支持SELECT 1语法
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

def update_score(db: Session, score_id: int, score_update: ScoreUpdate):
    """更新成绩"""
    db_score = db.query(Score).filter(Score.id == score_id).first()
    if not db_score:
        raise HTTPException(status_code=404, detail="Score not found")
    db_score.score_value = score_update.score_value
    return db_score

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

@app.put("/scores/{score_id}", response_model=Dict)
def update_score_sync(score_id: int, score_update: ScoreUpdate):
    """同时更新三个库的成绩"""
    return CrossDBManager.sync_write(update_score)(score_id, score_update)

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
                     .filter(SyncLog.status == "error")\
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
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                COUNT(*) as total_count
            FROM T_SYNC_LOGS
        """,
        'sqlserver': """
            SELECT 
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                COUNT(*) as total_count
            FROM T_SYNC_LOGS
        """,
        'oracle': """
            SELECT 
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
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
                total_count = int(row.total_count) if row.total_count else 0
                success_rate = success_count / total_count if total_count > 0 else 0.0
                
                # 创建同步统计对象
                sync_stats = SyncStats(
                    success_count=success_count,
                    failed_count=failed_count,
                    total_count=total_count,
                    success_rate=success_rate
                )
                
                results[db_name] = sync_stats
        except Exception as e:
            # 如果查询失败，返回默认值
            results[db_name] = SyncStats(
                success_count=0,
                failed_count=0,
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
    
    for db_name in engines.keys():
        try:
            session = next(get_session(db_name))
            try:
                # 查询最近的同步日志，按创建时间倒序
                logs = session.query(SyncLog)
                logs = logs.order_by(SyncLog.created_at.desc())
                logs = logs.limit(limit).all()
                
                # 转换为字典列表
                log_list = []
                for log in logs:
                    log_list.append({
                        'id': log.id,
                        'event_type': log.event_type,
                        'status': log.status,
                        'error_msg': log.error_msg,
                        'created_at': log.created_at.isoformat() if log.created_at else None
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
    """返回数据库连接状态和T_QUESTIONS表的数据行数"""
    results = {
        'mysql': {
            'status': 'offline',
            'question_count': 0
        },
        'sqlserver': {
            'status': 'offline',
            'question_count': 0
        },
        'oracle': {
            'status': 'offline',
            'question_count': 0
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
                count = result.scalar()
                
                results[db_name] = {
                    'status': 'online',
                    'question_count': count
                }
            finally:
                session.close()
        except Exception as e:
            results[db_name] = {
                'status': 'offline',
                'question_count': 0,
                'error': str(e)
            }
    
    return results

@app.get("/api/questions")
def get_api_questions():
    """
    返回所有题目列表
    """
    questions = []
    
    try:
        # 从MySQL获取题目（作为主库）
        session = next(get_session('mysql'))
        try:
            db_questions = session.query(Question).all()
            for q in db_questions:
                questions.append({
                    'id': q.id,
                    'guid': q.guid,
                    'content': q.content,
                    'answer': q.answer,
                    'score': q.score,
                    'created_at': q.created_at.isoformat() if q.created_at else None,
                    'updated_at': q.updated_at.isoformat() if q.updated_at else None
                })
        finally:
            session.close()
    except Exception as e:
        # 如果MySQL失败，尝试从其他数据库获取
        for db_name in ['sqlserver', 'oracle']:
            try:
                session = next(get_session(db_name))
                try:
                    db_questions = session.query(Question).all()
                    for q in db_questions:
                        questions.append({
                            'id': q.id,
                            'content': q.content,
                            'answer': q.answer,
                            'score': q.score,
                            'created_at': q.created_at.isoformat() if q.created_at else None,
                            'updated_at': q.updated_at.isoformat() if q.updated_at else None
                        })
                    break  # 如果成功获取，退出循环
                finally:
                    session.close()
            except Exception as e:
                continue
    
    return {"questions": questions}

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
                    'id': q.id,
                    'content': q.content,
                    'answer': q.answer,
                    'score': q.score,
                    'created_at': q.created_at.isoformat() if q.created_at else None,
                    'updated_at': q.updated_at.isoformat() if q.updated_at else None
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
                            'id': q.id,
                            'content': q.content,
                            'answer': q.answer,
                            'score': q.score,
                            'created_at': q.created_at.isoformat() if q.created_at else None,
                            'updated_at': q.updated_at.isoformat() if q.updated_at else None
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
def create_api_question(request: QuestionCreateRequest):
    """添加新题目，支持指定目标数据库
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
                db_question = create_question(db, request.question)
                db_question.guid = generated_guid
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
                "status": "failed",
                "message": f"同步任务 {log_id} 执行失败，详情请查看日志"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"执行同步任务失败: {str(e)}"
        }

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
