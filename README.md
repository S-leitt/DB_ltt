# Database configuration

Database connection information is loaded from environment variables via Pydantic Settings. Copy `.env.example` to `.env` for local development or testing, then adjust the placeholder values as needed. Avoid storing production secrets in the repository.

## Required variables

### MySQL
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `MYSQL_HOST`
- `MYSQL_PORT` (default `3306`)
- `MYSQL_DB`
- `MYSQL_ECHO` (default `false`)

### SQL Server
- `SQLSERVER_USER`
- `SQLSERVER_PASSWORD`
- `SQLSERVER_HOST`
- `SQLSERVER_PORT` (default `1433`)
- `SQLSERVER_DB`
- `SQLSERVER_DRIVER` (default `ODBC Driver 17 for SQL Server`)
- `SQLSERVER_SCHEMA` (default `dbo`)
- `SQLSERVER_TRUST_SERVER_CERTIFICATE` (default `true`)
- `SQLSERVER_ECHO` (default `false`)

### Oracle
- `ORACLE_USER`
- `ORACLE_PASSWORD`
- `ORACLE_HOST`
- `ORACLE_PORT` (default `1521`)
- `ORACLE_SERVICE_NAME` (default `ORCLPDB`)
- `ORACLE_ECHO` (default `false`)

All values have sensible defaults for development, so missing variables will fall back to local connection strings. Test and development environments should rely on `.env.example` rather than embedding real secrets.
