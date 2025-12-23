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
            raise e
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
                raise ValueError(f"同步日志ID {log_id} 不存在")
            
            if sync_log.sync_status != 'PENDING':
                raise ValueError(f"同步日志ID {log_id} 状态不是待同步")
            
            # 获取目标库会话
            target_session = next(get_session(sync_log.target_db))
            try:
                # 解析payload
                payload = json.loads(sync_log.payload)
                
                # 根据operation_type执行不同操作
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
                
                # 提交事务
                target_session.commit()
                
                # 更新同步日志状态为成功
                sync_log.sync_status = 'SUCCESS'
                mysql_session.commit()
                
                return True
            except Exception as e:
                target_session.rollback()
                # 更新同步日志状态为失败
                sync_log.sync_status = 'FAILED'
                sync_log.error_msg = str(e)
                mysql_session.commit()
                return False
            finally:
                target_session.close()
        except Exception as e:
            mysql_session.rollback()
            raise e
        finally:
            mysql_session.close()
