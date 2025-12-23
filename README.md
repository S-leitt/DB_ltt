# 多数据库同步系统

该项目提供基于 FastAPI 的多数据库同步示例。默认启用 SQLite 测试模式，克隆后无需外部数据库即可直接运行和执行单元测试。

## 快速启动（Quick Start）

1. 复制环境变量模板：`cp .env.example .env`，填写数据库连接、JWT 密钥和 SMTP 信息。
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 启动应用：
   ```bash
   uvicorn app.main:app --reload --port 8006
   ```
4. 浏览器访问 `http://127.0.0.1:8006/login.html`，默认账户 `admin/admin123`。首次启动会自动建表、自检连接并初始化 Oracle 序列/触发器。

## 功能概览
- 三库同步（MySQL、SQL Server、Oracle）与健康检查。
- JWT 鉴权及前端自动注入 Authorization 头。
- 数据仲裁者界面支持跨库修复，失败自动邮件告警。
- 动态报表（Chart.js）展示同步待处理比例。

## 连接真实数据库

将 `DB_MODE` 设置为 `production` 后使用 `.env` 中的连接字符串：
```bash
export DB_MODE=production
```
确认 `.env` 已配置对应驱动和账户。

## 常见问题排查（Troubleshooting）
- **Oracle 驱动报错**：确保安装 `cx_Oracle`，并配置 Oracle Instant Client（Linux 可通过 `LD_LIBRARY_PATH` 指向安装目录）。
- **SQL Server 连接失败或提示缺少驱动**：安装 `ODBC Driver 17 for SQL Server` 及 `pyodbc`，并在连接字符串中保留 `TrustServerCertificate=yes` 以避免自签证书导致的 TLS 报错。
- **首次运行表或序列不存在**：应用启动会自动执行 `Base.metadata.create_all()` 并尝试创建 Oracle 序列/触发器，如失败请检查数据库账户权限。

## 运行测试

```bash
pytest -q
```

测试会自动在 SQLite 模式下运行，无需外部数据库。
