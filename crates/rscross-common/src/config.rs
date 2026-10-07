//! 配置解析：YAML / 环境变量 / 命令行

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// 服务端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 监听地址
    #[serde(default = "default_address")]
    pub address: String,
    /// 运行模式：dev / prod
    #[serde(default = "default_mode")]
    pub mode: String,
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 数据库类型：sqlite / mysql
    #[serde(default = "default_db_type")]
    pub db_type: String,
    /// SQLite 数据文件路径
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,
    /// MySQL DSN，db_type=mysql 时必填
    #[serde(default)]
    pub mysql_dsn: String,
    /// JWT 签名密钥
    #[serde(default)]
    pub jwt_secret: String,
    /// 管理后台访问路径前缀
    #[serde(default = "default_base_path")]
    pub base_path: String,
    /// 是否允许注册
    #[serde(default)]
    pub allow_register: bool,
    /// 是否开启 gzip
    #[serde(default = "default_true")]
    pub enable_gzip: bool,
}

fn default_address() -> String {
    ":8080".to_string()
}
fn default_mode() -> String {
    "prod".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_db_type() -> String {
    "sqlite".to_string()
}
fn default_sqlite_path() -> String {
    "data/gostc.db".to_string()
}
fn default_base_path() -> String {
    String::new()
}
fn default_true() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            mode: default_mode(),
            log_level: default_log_level(),
            db_type: default_db_type(),
            sqlite_path: default_sqlite_path(),
            mysql_dsn: String::new(),
            jwt_secret: String::new(),
            base_path: default_base_path(),
            allow_register: false,
            enable_gzip: default_true(),
        }
    }
}

impl ServerConfig {
    /// 校验配置的内在一致性
    pub fn validate(&self) -> AppResult<()> {
        if self.db_type == "mysql" && self.mysql_dsn.is_empty() {
            return Err(AppError::Config(
                "db_type 为 mysql 时必须提供 mysql_dsn".to_string(),
            ));
        }
        if self.db_type != "mysql" && self.db_type != "sqlite" {
            return Err(AppError::Config(format!(
                "不支持的 db_type: {}，仅支持 sqlite / mysql",
                self.db_type
            )));
        }
        Ok(())
    }

    /// 开发模式
    pub fn is_dev(&self) -> bool {
        self.mode == "dev"
    }
}

/// 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 服务端地址，形如 127.0.0.1:8080
    #[serde(default)]
    pub addr: String,
    /// 连接密钥
    #[serde(default)]
    pub key: String,
    /// 是否启用 TLS
    #[serde(default)]
    pub tls: bool,
    /// 是否以节点模式运行
    #[serde(default)]
    pub node: bool,
    /// 代理服务地址（自定义域名网关）
    #[serde(default)]
    pub proxy_base_url: String,
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            key: String::new(),
            tls: false,
            node: false,
            proxy_base_url: String::new(),
            log_level: default_log_level(),
        }
    }
}

/// 加载配置：默认值 -> 配置文件 -> 环境变量覆盖
pub fn load_server_config(path: Option<&str>) -> AppResult<ServerConfig> {
    let mut cfg = match path {
        Some(p) => {
            let content = std::fs::read_to_string(p)
                .map_err(|e| AppError::Config(format!("读取配置文件 {p} 失败: {e}")))?;
            // 优先 YAML，失败再试 TOML
            serde_yaml::from_str::<ServerConfig>(&content)
                .or_else(|_| toml::from_str::<ServerConfig>(&content))
                .map_err(|e| AppError::Config(format!("解析配置文件 {p} 失败: {e}")))?
        }
        None => ServerConfig::default(),
    };

    apply_env_overrides(&mut cfg);
    cfg.validate()?;

    if cfg.jwt_secret.is_empty() {
        // 开发模式下允许自动生成，生产模式要求显式配置
        if cfg.is_dev() {
            cfg.jwt_secret = crate::util::random_hex(32);
            tracing::warn!("未配置 jwt_secret，已自动生成（重启后 token 会失效）");
        } else {
            return Err(AppError::Config(
                "生产模式必须配置 jwt_secret".to_string(),
            ));
        }
    }

    Ok(cfg)
}

fn apply_env_overrides(cfg: &mut ServerConfig) {
    if let Ok(v) = std::env::var("RSC_ADDRESS") {
        cfg.address = v;
    }
    if let Ok(v) = std::env::var("RSC_MODE") {
        cfg.mode = v;
    }
    if let Ok(v) = std::env::var("RSC_LOG_LEVEL") {
        cfg.log_level = v;
    }
    if let Ok(v) = std::env::var("RSC_DB_TYPE") {
        cfg.db_type = v;
    }
    if let Ok(v) = std::env::var("RSC_SQLITE_PATH") {
        cfg.sqlite_path = v;
    }
    if let Ok(v) = std::env::var("RSC_MYSQL_DSN") {
        cfg.mysql_dsn = v;
    }
    if let Ok(v) = std::env::var("RSC_JWT_SECRET") {
        cfg.jwt_secret = v;
    }
    if let Ok(v) = std::env::var("RSC_BASE_PATH") {
        cfg.base_path = v;
    }
    if let Ok(v) = std::env::var("RSC_ALLOW_REGISTER") {
        cfg.allow_register = v == "1" || v.eq_ignore_ascii_case("true");
    }
}
