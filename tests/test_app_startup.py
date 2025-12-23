import os
import sys
from pathlib import Path

# 确保项目根目录在导入路径中
sys.path.append(str(Path(__file__).resolve().parents[1]))

# 使用SQLite测试模式，避免外部数据库依赖
os.environ["DB_MODE"] = "sqlite"

from app.main import app, test_connection, root


def test_root_served():
    """根路径能返回主页文件。"""
    response = root()
    assert response.path.endswith("index.html")


def test_connection_check_succeeds_in_sqlite_mode():
    """SQLite 模式下连接测试返回成功状态。"""
    results = test_connection()

    for db_name in ("mysql", "sqlserver", "oracle"):
        assert db_name in results
        assert results[db_name].status == "success"
