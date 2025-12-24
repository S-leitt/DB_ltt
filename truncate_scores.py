from app.database import get_session
from sqlalchemy import text

# 遍历所有数据库，执行TRUNCATE TABLE T_SCORES命令
databases = ['mysql', 'sqlserver', 'oracle']

for db_name in databases:
    try:
        session = next(get_session(db_name))
        try:
            # 执行TRUNCATE命令
            session.execute(text('TRUNCATE TABLE T_SCORES'))
            session.commit()
            print(f'Successfully truncated T_SCORES in {db_name}')
        except Exception as e:
            # 如果TRUNCATE失败，尝试使用DELETE FROM
            print(f'TRUNCATE failed in {db_name}, trying DELETE FROM: {e}')
            session.rollback()
            session.execute(text('DELETE FROM T_SCORES'))
            session.commit()
            print(f'Successfully deleted all records from T_SCORES in {db_name}')
        finally:
            session.close()
    except Exception as e:
        print(f'Error connecting to {db_name}: {e}')
