#!/usr/bin/env python3
"""Test database connectivity for all configured databases."""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import check_connectivity, engines, IS_SQLITE_MODE
from app.config import get_settings

def main():
    print("=== 数据库连接测试 ===")
    print(f"运行模式: {'SQLite测试模式' if IS_SQLITE_MODE else '生产模式'}")
    print()
    
    # 打印数据库配置
    settings = get_settings()
    print("数据库配置:")
    print(f"  MySQL URL: {settings.mysql_url}")
    print(f"  SQL Server URL: {settings.sqlserver_url}")
    print(f"  Oracle URL: {settings.oracle_url}")
    print()
    
    # 检查连接
    print("正在测试数据库连接...")
    results = check_connectivity()
    
    # 总结结果
    print()
    print("=== 连接测试总结 ===")
    all_ok = True
    for name, info in results.items():
        status = "✅" if info["status"] == "UP" else "❌"
        print(f"{status} {name}: {info['message']}")
        if info["status"] != "UP":
            all_ok = False
    
    print()
    if all_ok:
        print("🎉 所有数据库连接成功!")
    else:
        print("⚠️  部分数据库连接失败，请检查配置。")
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())