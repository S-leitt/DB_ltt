# 多数据库同步系统（FastAPI）

FastAPI 驱动的多数据库同步示例，覆盖 MySQL、SQL Server 与 Oracle。应用会在启动时读取真实表结构，支持同步写入、健康检查、故障模拟、同步仲裁与邮件告警，附带可直接访问的前端页面。

## 功能亮点
- **三库同写 + 延迟同步**：新增/更新/删除题目时可选择立即写入的目标库，同时为未选库记录同步任务，支持手动补偿执行。  
- **同步仲裁与修复**：对比各库数据差异、手动指定源库一键修复，并在失败时发送邮件通知。  
- **运行状态可视化**：健康检查、同步日志、待处理比例与复杂报表（Chart.js），支持数据库连接状态与表数据量快照。  
- **安全与可观测性**：JWT 登录鉴权、默认管理员自动创建，启动时打印路由清单并自检数据库连接。  
- **测试友好**：`sqlite` 模式下自动创建本地数据库文件与 Oracle 序列/触发器，便于离线验证。

## 目录结构
- `app/main.py`：主要 API（v1/v2）、同步逻辑、邮件告警与前端静态文件路由。
- `app/database.py`：数据库引擎配置、SQLite 模式支持、健康检查。
- `app/models.py`：SQLAlchemy 模型（用户、题目、试卷、成绩、同步日志等）。
- `app/sync_decorator.py`：跨库同步管理器，负责同步任务记录与执行。
- `index.html` / `login.html`：内置前端登录与可视化界面。

## 环境准备
1. 复制并填写环境变量：
   ```bash
   cp .env.example .env
   # 按需修改数据库连接、JWT 密钥与 SMTP 信息
   ```
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

### 关键环境变量
| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `DB_MODE` | `production` 使用真实库；`sqlite` 生成本地 SQLite 文件（无外部依赖） | `production` |
| `MYSQL_URL` | MySQL 连接串 | `mysql+pymysql://user:password@localhost:3306/exam_paper_db` |
| `SQLSERVER_URL` | SQL Server 连接串（需 ODBC Driver 17 + pyodbc） | `mssql+pyodbc://...` |
| `ORACLE_URL` | Oracle 连接串（需 cx_Oracle + Instant Client） | `oracle+cx_oracle://...` |
| `JWT_SECRET_KEY` / `JWT_ALGORITHM` / `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT 配置 | `change-me` / `HS256` / `60` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` | 邮件告警配置 | 示例值 |
| `APP_BASE_URL` | 前端访问地址（用于邮件中的跳转链接） | `http://127.0.0.1:8006` |

## 启动方式
### 连接真实数据库
```bash
uvicorn app.main:app --reload --port 8006
```
启动后访问 `http://127.0.0.1:8006/login.html`，默认账号 `admin/admin123` 会在应用启动时自动创建。应用会执行健康检查并确保 Oracle 序列/触发器存在。

### 本地快速验证（SQLite）
无需外部数据库或驱动，设置环境变量并启动：
```bash
export DB_MODE=sqlite
uvicorn app.main:app --reload --port 8006
```
会在项目根目录生成 `mysql.db`、`sqlserver.db`、`oracle.db` 文件，表结构与序列/触发器自动创建。

## 常用 API
- `POST /api/auth/login` & `GET /api/auth/me`：JWT 登录与鉴权校验。
- `POST /api/v2/questions` / `PUT /api/v2/questions/{guid}` / `DELETE /api/v2/questions/{guid}`：按目标库写入/更新/删除题目，未选库生成同步任务。
- `POST /api/v2/sync/tasks/{log_id}/execute`：手动执行待同步任务。
- `GET /api/v2/db/status`：数据库连接状态与各表行数快照。
- `GET /api/arbiter/{guid}`、`POST /api/sync/repair`：数据仲裁与跨库修复。
- `POST /api/simulate-fault`：模拟 Oracle 写入故障，验证补偿与告警链路。

## 测试
默认使用 SQLite 隔离环境运行：
```bash
pytest -q
```
如需连接真实数据库，请确保 `.env` 填写完备且驱动已安装。

## 常见问题
- **Oracle 驱动报错**：安装 `cx_Oracle` 并配置 Oracle Instant Client（Linux 使用 `LD_LIBRARY_PATH` 指向安装目录）。
- **SQL Server 连接失败或缺少驱动**：安装 `ODBC Driver 17 for SQL Server` 与 `pyodbc`，连接串保留 `TrustServerCertificate=yes` 以避免自签证书 TLS 报错。
- **首次运行表或序列不存在**：启动时会自动建表并初始化 Oracle 序列/触发器，失败多半源自数据库权限不足。
