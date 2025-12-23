"""Test configuration ensuring the repository root is importable."""
import sys
import os
from pathlib import Path

# 使用SQLite测试模式隔离单元测试，避免依赖真实数据库驱动
os.environ.setdefault("DB_MODE", "sqlite")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
