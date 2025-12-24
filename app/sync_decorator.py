# 2.0版本：手动触发同步模式
from functools import wraps
from typing import Callable, Any
from sqlalchemy.orm import Session
from .database import get_session
from .models import SyncLog
from datetime import datetime
import json

class CrossDBManager:
    """
    跨数据库操作管理器，实现手动触发同步模式
    """
    
    @staticmethod
    def sync_write(func):
        """
        同步写入装饰器，用于在多个数据库上执行相同的操作
        
        Args:
            func: 要执行的数据库操作函数
            
        Returns:
            装饰后的函数，执行结果为包含各数据库执行结果的字典
        """
        from functools import wraps
        from .database import engines, get_session
        import traceback
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            results = {}
            failed = []
            
            # 打印输入参数，方便调试
            print(f"sync_write调用，参数: args={args}, kwargs={kwargs}")
            
            for db_name in engines.keys():
                try:
                    print(f"正在尝试向数据库 {db_name} 写入数据...")
                    # 获取数据库会话
                    session = next(get_session(db_name))
                    try:
                        # 执行数据库操作
                        print(f"{db_name}: 执行数据库操作...")
                        
                        # Oracle特定的调试信息
                        if 'oracle' in db_name:
                            print(f"{db_name}: 检测到Oracle数据库，准备执行操作...")
                            # 打印当前会话的数据库连接信息
                            from sqlalchemy import text
                            conn_info = session.execute(text("SELECT SYS_CONTEXT('USERENV','DB_NAME') AS db_name, SYS_CONTEXT('USERENV','SESSION_USER') AS username FROM DUAL")).fetchone()
                            print(f"{db_name}: 数据库连接信息 - 数据库名: {conn_info.db_name}, 用户名: {conn_info.username}")
                        
                        result = func(session, *args, **kwargs)
                        # 提交事务
                        print(f"{db_name}: 提交事务...")
                        session.commit()
                        results[db_name] = {
                            "status": "success",
                            "result": result.__dict__ if hasattr(result, '__dict__') else result
                        }
                        print(f"{db_name}: 写入成功!")
                        
                        # Oracle特定的成功信息
                        if 'oracle' in db_name:
                            print(f"{db_name}: Oracle写入操作已成功提交")
                    except Exception as e:
                        # 回滚事务
                        session.rollback()
                        # 记录失败信息
                        results[db_name] = {
                            "status": "failed",
                            "error": str(e)
                        }
                        failed.append(db_name)
                        print(f"ERROR: 在 {db_name} 上执行操作失败: {str(e)}")
                        # 打印详细的错误堆栈
                        print(f"详细错误信息:")
                        traceback.print_exc()
                    finally:
                        # 关闭会话
                        session.close()
                        print(f"{db_name}: 会话已关闭")
                except Exception as e:
                    # 记录会话获取失败信息
                    results[db_name] = {
                        "status": "failed",
                        "error": f"无法获取数据库会话: {str(e)}"
                    }
                    failed.append(db_name)
                    print(f"ERROR: 无法获取 {db_name} 数据库会话: {str(e)}")
                    # 打印详细的错误堆栈
                    print(f"详细错误信息:")
                    traceback.print_exc()
            
            # 返回结果，包含成功和失败的数据库信息
            return {
                "status": "partial" if failed else "success",
                "results": results,
                "failed_dbs": failed
            }
        
        return wrapper
    
    @staticmethod
    def record_sync_task(source_db: str, target_db: str, operation_type: str, event_type: str, payload: dict):
        """
        在T_SYNC_LOGS中记录待同步任务
        
        Args:
            source_db: 数据最初写入的库
            target_db: 目标库
            operation_type: 操作类型: INSERT, UPDATE, DELETE
            event_type: 事件类型
            payload: 要同步的数据内容
        """
        # 使用MySQL作为记录日志的主库
        mysql_session = next(get_session('mysql'))
        try:
            # 创建同步日志记录
            sync_log = SyncLog(
                source_db=source_db,
                target_db=target_db,
                operation_type=operation_type,
                event_type=event_type,
                sync_status='PENDING',  # 初始状态为待同步
                payload=json.dumps(payload),  # 存储为JSON字符串
                created_at=datetime.now()
            )
            
            mysql_session.add(sync_log)
            mysql_session.commit()
            return sync_log.id
        except Exception as e:
            mysql_session.rollback()
            print(f"ERROR: 记录同步任务日志失败: {str(e)}")
            # 不中断主逻辑，返回None
            return None
        finally:
            mysql_session.close()
    
    @staticmethod
    def execute_sync_task(log_id: int):
        """
        执行同步任务
        
        Args:
            log_id: 同步日志ID
            
        Returns:
            bool: 同步是否成功
        """
        # 从MySQL获取同步日志
        mysql_session = next(get_session('mysql'))
        try:
            sync_log = mysql_session.query(SyncLog).filter(SyncLog.id == log_id).first()
            if not sync_log:
                print(f"ERROR: 同步日志ID {log_id} 不存在")
                return False
            
            if sync_log.sync_status != 'PENDING':
                print(f"ERROR: 同步日志ID {log_id} 状态不是待同步")
                return False
            
            # 获取目标库会话
            target_session = next(get_session(sync_log.target_db))
            try:
                # 解析payload
                payload = json.loads(sync_log.payload)
                
                # 根据event_type执行不同的同步操作
                if sync_log.target_db == 'oracle':
                    # Oracle数据库特殊处理，打印原始SQL语句
                    print(f"Oracle同步操作: {sync_log.operation_type} {sync_log.event_type}")
                    print(f"Payload: {payload}")
                    
                    if sync_log.event_type == 'QUESTION_SYNC':
                        # 题目同步
                        if sync_log.operation_type == 'INSERT':
                            # 执行插入操作，使用原始SQL
                            from sqlalchemy import text
                            print(f"Oracle原始SQL: INSERT INTO T_QUESTIONS (guid, content, answer, score, created_at, updated_at) VALUES (:guid, :content, :answer, :score, SYSDATE, SYSDATE)")
                            target_session.execute(text("INSERT INTO T_QUESTIONS (guid, content, answer, score, created_at, updated_at) VALUES (:guid, :content, :answer, :score, SYSDATE, SYSDATE)"), {
                                'guid': payload['guid'],
                                'content': payload['content'],
                                'answer': payload['answer'],
                                'score': payload['score']
                            })
                        elif sync_log.operation_type == 'UPDATE':
                            # 执行更新操作，使用原始SQL
                            from sqlalchemy import text
                            print(f"Oracle原始SQL: UPDATE T_QUESTIONS SET content = :content, answer = :answer, score = :score, updated_at = SYSDATE WHERE guid = :guid")
                            target_session.execute(text("UPDATE T_QUESTIONS SET content = :content, answer = :answer, score = :score, updated_at = SYSDATE WHERE guid = :guid"), {
                                'guid': payload['guid'],
                                'content': payload['content'],
                                'answer': payload['answer'],
                                'score': payload['score']
                            })
                        elif sync_log.operation_type == 'DELETE':
                            # 执行删除操作，使用原始SQL
                            from sqlalchemy import text
                            print(f"Oracle原始SQL: DELETE FROM T_QUESTIONS WHERE guid = :guid")
                            target_session.execute(text("DELETE FROM T_QUESTIONS WHERE guid = :guid"), {
                                'guid': payload['guid']
                            })
                    elif sync_log.event_type == 'SCORE_SYNC':
                        # 成绩同步
                        if sync_log.operation_type == 'INSERT':
                            # 执行插入操作，使用原始SQL
                            from sqlalchemy import text
                            print(f"Oracle原始SQL: INSERT INTO T_SCORES (user_id, exam_id, score_value, created_at, updated_at) VALUES (:user_id, :exam_id, :score_value, SYSDATE, SYSDATE)")
                            target_session.execute(text("INSERT INTO T_SCORES (user_id, exam_id, score_value, created_at, updated_at) VALUES (:user_id, :exam_id, :score_value, SYSDATE, SYSDATE)"), {
                                'user_id': payload['user_id'],
                                'exam_id': payload['exam_id'],
                                'score_value': payload['score_value']
                            })
                        elif sync_log.operation_type == 'UPDATE':
                            # 执行更新操作，使用原始SQL
                            from sqlalchemy import text
                            print(f"Oracle原始SQL: UPDATE T_SCORES SET score_value = :score_value, updated_at = SYSDATE WHERE user_id = :user_id AND exam_id = :exam_id")
                            result = target_session.execute(text("UPDATE T_SCORES SET score_value = :score_value, updated_at = SYSDATE WHERE user_id = :user_id AND exam_id = :exam_id"), {
                                'user_id': payload['user_id'],
                                'exam_id': payload['exam_id'],
                                'score_value': payload['score_value']
                            })
                            
                            # 如果更新行数为0，执行插入操作
                            if result.rowcount == 0:
                                print(f"Oracle原始SQL: INSERT INTO T_SCORES (user_id, exam_id, score_value, created_at, updated_at) VALUES (:user_id, :exam_id, :score_value, SYSDATE, SYSDATE)")
                                target_session.execute(text("INSERT INTO T_SCORES (user_id, exam_id, score_value, created_at, updated_at) VALUES (:user_id, :exam_id, :score_value, SYSDATE, SYSDATE)"), {
                                    'user_id': payload['user_id'],
                                    'exam_id': payload['exam_id'],
                                    'score_value': payload['score_value']
                                })
                else:
                    # 其他数据库使用ORM方式
                    if sync_log.event_type == 'QUESTION_SYNC':
                        # 题目同步
                        if sync_log.operation_type == 'INSERT':
                            # 执行插入操作
                            from .models import Question
                            question = Question(
                                guid=payload['guid'],
                                content=payload['content'],
                                answer=payload['answer'],
                                score=payload['score']
                            )
                            target_session.add(question)
                        elif sync_log.operation_type == 'UPDATE':
                            # 执行更新操作
                            from .models import Question
                            question = target_session.query(Question).filter(Question.guid == payload['guid']).first()
                            if not question:
                                raise ValueError(f"题目GUID {payload['guid']} 在目标库中不存在")
                            
                            question.content = payload['content']
                            question.answer = payload['answer']
                            question.score = payload['score']
                        elif sync_log.operation_type == 'DELETE':
                            # 执行删除操作
                            from .models import Question
                            question = target_session.query(Question).filter(Question.guid == payload['guid']).first()
                            if question:
                                target_session.delete(question)
                    elif sync_log.event_type == 'SCORE_SYNC':
                        # 成绩同步
                        if sync_log.operation_type == 'INSERT':
                            # 执行插入操作
                            from .models import Score
                            score = Score(
                                user_id=payload['user_id'],
                                exam_id=payload['exam_id'],
                                score_value=payload['score_value']
                            )
                            target_session.add(score)
                        elif sync_log.operation_type == 'UPDATE':
                            # 执行更新操作
                            from .models import Score
                            score = target_session.query(Score).filter(
                                Score.user_id == payload['user_id'],
                                Score.exam_id == payload['exam_id']
                            ).first()
                            if not score:
                                # 如果记录不存在，则执行插入操作
                                score = Score(
                                    user_id=payload['user_id'],
                                    exam_id=payload['exam_id'],
                                    score_value=payload['score_value']
                                )
                                target_session.add(score)
                            else:
                                score.score_value = payload['score_value']
                
                # 提交事务
                target_session.commit()
                
                # 更新同步日志状态为成功
                try:
                    sync_log.sync_status = 'SUCCESS'
                    mysql_session.commit()
                except Exception as log_error:
                    mysql_session.rollback()
                    print(f"ERROR: 更新同步日志状态为成功失败: {str(log_error)}")
                
                return True
            except Exception as e:
                target_session.rollback()
                # 更新同步日志状态为失败
                try:
                    sync_log.sync_status = 'FAILED'
                    sync_log.error_msg = str(e)
                    mysql_session.commit()
                except Exception as log_error:
                    mysql_session.rollback()
                    print(f"ERROR: 更新同步日志状态为失败失败: {str(log_error)}")
                return False
            finally:
                target_session.close()
        except Exception as e:
            mysql_session.rollback()
            print(f"ERROR: 执行同步任务失败: {str(e)}")
            return False
        finally:
            mysql_session.close()
