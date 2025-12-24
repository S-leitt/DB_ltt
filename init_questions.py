#!/usr/bin/env python3
"""
临时脚本：初始化三个数据库中的T_QUESTIONS表数据
"""

import sys
import os

# 将项目根目录添加到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import init_questions_data

if __name__ == "__main__":
    print("开始初始化T_QUESTIONS表数据...")
    print("=" * 50)
    init_questions_data()
    print("=" * 50)
    print("初始化完成！")
