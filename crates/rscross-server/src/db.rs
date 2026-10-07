//! 数据库层：sqlx 封装，兼容 SQLite 与 MySQL

use chrono::Utc;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{MySqlPool, SqlitePool};

use rscross_common::crypto;
use rscross_common::error::{AppError, AppResult};

use crate::config::ServerConfig;

/// 数据库类型
pub enum Database {
    Sqlite(SqlitePool),
    Mysql(MySqlPool),
}

impl Database {
    /// 依据配置建立连接
    pub async fn new(cfg: &ServerConfig) -> AppResult<Self> {
        match cfg.inner.db_type.as_str() {
            "sqlite" => {
                let path = &cfg.inner.sqlite_path;
                if let Some(parent) = std::path::Path::new(path).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            AppError::msg(format!("创建数据目录失败: {e}"))
                        })?;
                    }
                }
                let url = format!("sqlite://{path}?mode=rwc");
                let pool = SqlitePoolOptions::new()
                    .max_connections(5)
                    .connect(&url)
                    .await
                    .map_err(|e| AppError::msg(format!("连接 SQLite 失败: {e}")))?;
                Ok(Database::Sqlite(pool))
            }
            "mysql" => {
                let pool = MySqlPoolOptions::new()
                    .max_connections(20)
                    .connect(&cfg.inner.mysql_dsn)
                    .await
                    .map_err(|e| AppError::msg(format!("连接 MySQL 失败: {e}")))?;
                Ok(Database::Mysql(pool))
            }
            other => Err(AppError::Config(format!("不支持的数据库类型: {other}"))),
        }
    }

    /// 取得 SQLite 连接池
    pub fn sqlite_pool(&self) -> Option<&SqlitePool> {
        match self {
            Database::Sqlite(p) => Some(p),
            _ => None,
        }
    }

    pub fn mysql_pool(&self) -> Option<&MySqlPool> {
        match self {
            Database::Mysql(p) => Some(p),
            _ => None,
        }
    }

    pub fn is_sqlite(&self) -> bool {
        matches!(self, Database::Sqlite(_))
    }

    pub fn is_mysql(&self) -> bool {
        matches!(self, Database::Mysql(_))
    }

    /// 执行建表语句
    pub async fn execute_batch(&self, sql: &str) -> AppResult<()> {
        match self {
            Database::Sqlite(p) => {
                // SQLite 不支持一条语句多表，逐条执行
                for stmt in split_statements(sql) {
                    sqlx::query(&stmt)
                        .execute(p)
                        .await
                        .map_err(|e| AppError::msg(format!("执行建表失败: {e}\nSQL: {stmt}")))?;
                }
                Ok(())
            }
            Database::Mysql(p) => {
                sqlx::raw_sql(sql)
                    .execute(p)
                    .await
                    .map_err(|e| AppError::msg(format!("执行建表失败: {e}")))?;
                Ok(())
            }
        }
    }

    /// 初始化默认数据：默认管理员、系统配置
    pub async fn init_default_data(&self) -> AppResult<()> {
        // 默认管理员
        let exists: i64 = match self {
            Database::Sqlite(p) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM system_users")
                    .fetch_one(p)
                    .await
                    .unwrap_or(0)
            }
            Database::Mysql(p) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM system_users")
                    .fetch_one(p)
                    .await
                    .unwrap_or(0)
            }
        };

        if exists == 0 {
            let hash = crypto::hash_password("admin")?;
            let now = Utc::now();
            match self {
                Database::Sqlite(p) => {
                    sqlx::query(
                        "INSERT INTO system_users
                         (code, allow_edit, allow_del, version, created_at, updated_at,
                          username, password, role, email, status, balance, traffic_limit,
                          tunnel_limit, allow_node, allow_client, level, inviter_code,
                          checkin_enabled)
                         VALUES (?, 1, 1, 1, ?, ?, 'admin', ?, 'admin', '', 1, 0, -1, 0, 1, 1, 0, '', 0)",
                    )
                    .bind(rscross_common::util::uuid_v4())
                    .bind(now)
                    .bind(now)
                    .bind(&hash)
                    .execute(p)
                    .await?;
                }
                Database::Mysql(p) => {
                    sqlx::query(
                        "INSERT INTO system_users
                         (code, allow_edit, allow_del, version, created_at, updated_at,
                          username, password, role, email, status, balance, traffic_limit,
                          tunnel_limit, allow_node, allow_client, level, inviter_code,
                          checkin_enabled)
                         VALUES (?, 1, 1, 1, ?, ?, 'admin', ?, 'admin', '', 1, 0, -1, 0, 1, 1, 0, '', 0)",
                    )
                    .bind(rscross_common::util::uuid_v4())
                    .bind(now)
                    .bind(now)
                    .bind(&hash)
                    .execute(p)
                    .await?;
                }
            }
            tracing::info!("已创建默认管理员账号 admin / admin");
        }

        // 默认系统配置
        self.seed_config(config_key_pair("site_name", "rscross", "base"))
            .await?;
        self.seed_config(config_key_pair("register_enable", "false", "base"))
            .await?;
        self.seed_config(config_key_pair("email_enable", "false", "email"))
            .await?;
        self.seed_config(config_key_pair("gost_p2p", "true", "gost"))
            .await?;

        Ok(())
    }

    /// 插入默认配置（已存在则跳过）
    async fn seed_config(&self, (key, value, group): (&str, &str, &str)) -> AppResult<()> {
        let now = Utc::now();
        let code = rscross_common::util::uuid_v4();
        let sql = "INSERT INTO system_configs
                   (code, allow_edit, allow_del, version, created_at, updated_at, name, value, `group`)
                   SELECT ?, 1, 1, 1, ?, ?, ?, ?, ?
                   WHERE NOT EXISTS (SELECT 1 FROM system_configs WHERE name = ?)";

        match self {
            Database::Sqlite(p) => {
                sqlx::query(sql)
                    .bind(&code).bind(now).bind(now)
                    .bind(key).bind(value).bind(group).bind(key)
                    .execute(p).await?;
            }
            Database::Mysql(p) => {
                sqlx::query(sql)
                    .bind(&code).bind(now).bind(now)
                    .bind(key).bind(value).bind(group).bind(key)
                    .execute(p).await?;
            }
        }
        Ok(())
    }
}

fn config_key_pair(key: &str, value: &str, group: &str) -> (&str, &str, &str) {
    (key, value, group)
}

/// 拆分 SQL 语句（SQLite 不支持多语句一次执行）
fn split_statements(sql: &str) -> Vec<String> {
    sql.split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.chars().all(|c| c.is_whitespace() || c == '-'))
        .map(|s| s.to_string())
        .collect()
}

/// 建表 DDL（SQLite 与 MySQL 通用部分）
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS system_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    email VARCHAR(255) NOT NULL DEFAULT '',
    status INT NOT NULL DEFAULT 1,
    balance BIGINT NOT NULL DEFAULT 0,
    traffic_limit BIGINT NOT NULL DEFAULT -1,
    tunnel_limit INT NOT NULL DEFAULT 0,
    allow_node INT NOT NULL DEFAULT 1,
    allow_client INT NOT NULL DEFAULT 1,
    level INT NOT NULL DEFAULT 0,
    inviter_code VARCHAR(100) NOT NULL DEFAULT '',
    checkin_enabled INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_username ON system_users(username);

CREATE TABLE IF NOT EXISTS system_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(100) NOT NULL,
    value TEXT NOT NULL,
    `group` VARCHAR(64) NOT NULL DEFAULT 'base'
);
CREATE INDEX IF NOT EXISTS idx_configs_name ON system_configs(name);

CREATE TABLE IF NOT EXISTS system_notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    type VARCHAR(32) NOT NULL DEFAULT 'notice',
    status INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS system_user_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    user_code VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS system_user_checkins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    user_code VARCHAR(100) NOT NULL,
    date VARCHAR(32) NOT NULL,
    amount BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS gost_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    `key` VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    status INT NOT NULL DEFAULT 1,
    enable INT NOT NULL DEFAULT 1,
    node_limit INT NOT NULL DEFAULT 0,
    remark TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_clients_key ON gost_clients(`key`);

CREATE TABLE IF NOT EXISTS gost_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    `key` VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL DEFAULT '',
    ip VARCHAR(255) NOT NULL DEFAULT '',
    port VARCHAR(32) NOT NULL DEFAULT '7000',
    http_port VARCHAR(32) NOT NULL DEFAULT '8080',
    protocol VARCHAR(32) NOT NULL DEFAULT 'tcp',
    status INT NOT NULL DEFAULT 1,
    enable INT NOT NULL DEFAULT 1,
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    max_pool_count INT NOT NULL DEFAULT 5,
    allow_domain_matcher INT NOT NULL DEFAULT 0,
    p2p_disable_forward INT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT 0,
    bandwidth_usage BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_key ON gost_nodes(`key`);

CREATE TABLE IF NOT EXISTS gost_node_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    config_type VARCHAR(32) NOT NULL DEFAULT 'client',
    content TEXT NOT NULL,
    content_type VARCHAR(32) NOT NULL DEFAULT 'yaml',
    status INT NOT NULL DEFAULT 1,
    name VARCHAR(255) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS gost_auths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    tunnel_code VARCHAR(100) NOT NULL,
    user VARCHAR(255) NOT NULL DEFAULT '',
    password VARCHAR(255) NOT NULL DEFAULT '',
    status INT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_auths_tunnel ON gost_auths(tunnel_code);

CREATE TABLE IF NOT EXISTS gost_client_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    target_ip VARCHAR(64) NOT NULL DEFAULT '',
    target_port VARCHAR(32) NOT NULL DEFAULT '',
    target_https INT NOT NULL DEFAULT 0,
    domain_prefix VARCHAR(255) NOT NULL DEFAULT '',
    custom_domain VARCHAR(255) NOT NULL DEFAULT '',
    custom_cert TEXT NOT NULL DEFAULT '',
    custom_key TEXT NOT NULL DEFAULT '',
    custom_force_https INT NOT NULL DEFAULT 0,
    custom_domain_matcher INT NOT NULL DEFAULT 0,
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    enable INT NOT NULL DEFAULT 1,
    status INT NOT NULL DEFAULT 1,
    use_encryption INT NOT NULL DEFAULT 1,
    use_compression INT NOT NULL DEFAULT 0,
    pool_count INT NOT NULL DEFAULT 0,
    limiter INT NOT NULL DEFAULT 0,
    limiter_total BIGINT NOT NULL DEFAULT 0,
    limiter_usage BIGINT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT -1,
    tunnel_limit INT NOT NULL DEFAULT 0,
    max_conns INT NOT NULL DEFAULT 0,
    expire_days INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hosts_client ON gost_client_hosts(client_code);

CREATE TABLE IF NOT EXISTS gost_client_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    target_ip VARCHAR(64) NOT NULL DEFAULT '',
    target_port VARCHAR(32) NOT NULL DEFAULT '',
    port VARCHAR(32) NOT NULL DEFAULT '',
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    enable INT NOT NULL DEFAULT 1,
    status INT NOT NULL DEFAULT 1,
    use_encryption INT NOT NULL DEFAULT 1,
    use_compression INT NOT NULL DEFAULT 0,
    pool_count INT NOT NULL DEFAULT 0,
    limiter INT NOT NULL DEFAULT 0,
    proxy_protocol INT NOT NULL DEFAULT 0,
    limiter_total BIGINT NOT NULL DEFAULT 0,
    limiter_usage BIGINT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT -1,
    tunnel_limit INT NOT NULL DEFAULT 0,
    max_conns INT NOT NULL DEFAULT 0,
    expire_days INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_forwards_client ON gost_client_forwards(client_code);

CREATE TABLE IF NOT EXISTS gost_client_tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    target_ip VARCHAR(64) NOT NULL DEFAULT '',
    target_port VARCHAR(32) NOT NULL DEFAULT '',
    vkey VARCHAR(64) NOT NULL DEFAULT '',
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    enable INT NOT NULL DEFAULT 1,
    status INT NOT NULL DEFAULT 1,
    use_encryption INT NOT NULL DEFAULT 1,
    use_compression INT NOT NULL DEFAULT 0,
    pool_count INT NOT NULL DEFAULT 0,
    limiter INT NOT NULL DEFAULT 0,
    limiter_total BIGINT NOT NULL DEFAULT 0,
    limiter_usage BIGINT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT -1,
    tunnel_limit INT NOT NULL DEFAULT 0,
    max_conns INT NOT NULL DEFAULT 0,
    expire_days INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tunnels_client ON gost_client_tunnels(client_code);

CREATE TABLE IF NOT EXISTS gost_client_p2_ps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    target_ip VARCHAR(64) NOT NULL DEFAULT '',
    target_port VARCHAR(32) NOT NULL DEFAULT '',
    vkey VARCHAR(64) NOT NULL DEFAULT '',
    forward INT NOT NULL DEFAULT 1,
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    enable INT NOT NULL DEFAULT 1,
    status INT NOT NULL DEFAULT 1,
    use_encryption INT NOT NULL DEFAULT 1,
    use_compression INT NOT NULL DEFAULT 0,
    pool_count INT NOT NULL DEFAULT 0,
    limiter INT NOT NULL DEFAULT 0,
    limiter_total BIGINT NOT NULL DEFAULT 0,
    limiter_usage BIGINT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT -1,
    tunnel_limit INT NOT NULL DEFAULT 0,
    max_conns INT NOT NULL DEFAULT 0,
    expire_days INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_p2ps_client ON gost_client_p2_ps(client_code);

CREATE TABLE IF NOT EXISTS gost_client_proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    port VARCHAR(32) NOT NULL DEFAULT '',
    auth_user VARCHAR(255) NOT NULL DEFAULT '',
    auth_pwd VARCHAR(255) NOT NULL DEFAULT '',
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    enable INT NOT NULL DEFAULT 1,
    status INT NOT NULL DEFAULT 1,
    use_encryption INT NOT NULL DEFAULT 1,
    use_compression INT NOT NULL DEFAULT 0,
    pool_count INT NOT NULL DEFAULT 0,
    limiter INT NOT NULL DEFAULT 0,
    limiter_total BIGINT NOT NULL DEFAULT 0,
    limiter_usage BIGINT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT -1,
    tunnel_limit INT NOT NULL DEFAULT 0,
    max_conns INT NOT NULL DEFAULT 0,
    expire_days INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_proxies_client ON gost_client_proxies(client_code);

CREATE TABLE IF NOT EXISTS frp_client_cfgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    content_type VARCHAR(32) NOT NULL DEFAULT 'yaml',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    enable INT NOT NULL DEFAULT 1,
    status INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS gost_obs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    allow_edit INT NOT NULL DEFAULT 1,
    allow_del INT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    type VARCHAR(64) NOT NULL DEFAULT '',
    date VARCHAR(32) NOT NULL DEFAULT '',
    input_bytes BIGINT NOT NULL DEFAULT 0,
    output_bytes BIGINT NOT NULL DEFAULT 0,
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    node_code VARCHAR(100) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_obs_date ON gost_obs(date);
CREATE INDEX IF NOT EXISTS idx_obs_user ON gost_obs(user_code);

CREATE TABLE IF NOT EXISTS gost_node_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    domain VARCHAR(255) NOT NULL DEFAULT '',
    status INT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS gost_node_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    port BIGINT NOT NULL DEFAULT 0,
    status INT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodeports_port ON gost_node_ports(port);

CREATE TABLE IF NOT EXISTS gost_node_binds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(100) NOT NULL UNIQUE,
    node_code VARCHAR(100) NOT NULL DEFAULT '',
    user_code VARCHAR(100) NOT NULL DEFAULT '',
    client_code VARCHAR(100) NOT NULL DEFAULT '',
    status INT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_binds_client ON gost_node_binds(client_code);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_statements() {
        let sql = "CREATE TABLE a (id INT); -- comment\nCREATE TABLE b (id INT);";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("CREATE TABLE a"));
        assert!(stmts[1].contains("CREATE TABLE b"));
    }

    #[test]
    fn test_schema_has_all_tables() {
        for t in [
            "system_users",
            "system_configs",
            "gost_clients",
            "gost_nodes",
            "gost_client_hosts",
            "gost_client_forwards",
            "gost_client_tunnels",
            "gost_client_p2_ps",
            "gost_client_proxies",
            "gost_auths",
            "gost_obs",
        ] {
            assert!(SCHEMA.contains(t), "schema 缺少表 {t}");
        }
    }
}
