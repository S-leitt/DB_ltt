# 多数据库同步系统

该项目提供基于 FastAPI 的多数据库同步示例。默认启用 SQLite 测试模式，克隆后无需外部数据库即可直接运行和执行单元测试。

## 快速开始

1. 创建并激活虚拟环境（可选）。
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 启动应用：
   ```bash
   uvicorn app.main:app --reload
   ```

> 说明：默认 `DB_MODE` 为 `sqlite`，会在当前目录创建独立的 SQLite 文件，方便本地调试。

## 连接真实数据库

如需连接 MySQL、SQL Server、Oracle，将环境变量设置为生产模式：

```bash
export DB_MODE=production
```

根据实际情况在 `app/database.py` 中调整连接字符串及驱动依赖。

## 运行测试

```bash
pytest -q
```

测试会自动在 SQLite 模式下运行，无需外部数据库。
