//! `rscross-config`：服务端 / 客户端配置文件模型。
//!
//! 约定：
//! - 所有字段都带 `#[serde(default)]`，因此**部分配置**的 TOML 也能加载，
//!   缺省项回落到 `Default`，避免升级时炸掉旧配置文件。
//! - [`ServerFile::validate`] / [`ClientFile::validate`] 是唯一的语义校验入口，
//!   启动时调用一次，失败即拒绝启动（fail-fast）。

use std::path::{Path, PathBuf};

use rscross_common::{Error, PathPolicy, Result};
use serde::{Deserialize, Serialize};

/// 服务端配置文件。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerFile {
    /// 基础信息与监听地址。
    pub server: ServerSection,
    /// 反向隧道（FerroTunnel）参数。
    pub tunnel: TunnelSection,
    /// 公网入口参数。
    pub ingress: IngressSection,
    /// 控制台与初始管理员。
    pub admin: AdminSection,
    /// 持久化。
    pub database: DatabaseSection,
    /// 鉴权策略。
    pub auth: AuthSection,
    /// 日志。
    pub log: LogSection,
    /// P2P（Iroh）参数。
    pub p2p: P2pSection,
    /// 全局限额。
    pub limits: LimitsSection,
}

/// 服务端基础信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    /// 节点显示名，用于控制台与多节点区分。
    pub name: String,
    /// 管理 API 与控制台监听地址。
    pub admin_bind: String,
    /// 公网入口（HTTP / TCP）监听地址。
    pub ingress_bind: String,
    /// FerroTunnel 反向隧道控制面监听地址。
    pub tunnel_bind: String,
    /// 对外可达地址，形如 `https://t.example.com`，用于生成接入命令。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 超过该时长未收到心跳即标记离线（秒）。
    pub offline_after_secs: u64,
    /// 关闭时等待任务收敛的最长时间（秒）。
    pub shutdown_grace_secs: u64,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            name: "rscross".to_string(),
            admin_bind: format!("0.0.0.0:{}", rscross_common::DEFAULT_ADMIN_PORT),
            ingress_bind: format!("0.0.0.0:{}", rscross_common::DEFAULT_INGRESS_PORT),
            tunnel_bind: format!("0.0.0.0:{}", rscross_common::DEFAULT_TUNNEL_PORT),
            public_url: None,
            heartbeat_secs: rscross_common::DEFAULT_HEARTBEAT_SECS,
            offline_after_secs: 45,
            shutdown_grace_secs: 10,
        }
    }
}

/// 反向隧道（FerroTunnel）参数。
///
/// 字段与 `ferrotunnel::common::{LimitsConfig, RateLimitConfig, TlsConfig}` 一一对应，
/// 由 `rscross-transport` 在启动时转换。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TunnelSection {
    /// FerroTunnel 的服务端 token（客户端与控制面共享）。
    ///
    /// 见 `docs/ARCHITECTURE.md`「已知边界」：FerroTunnel 目前只支持单一服务端 token，
    /// 因此该值只作为**传输层握手凭证**，业务身份由 rscross 自己的 agent token 承担。
    pub token: String,
    /// 单帧最大长度（字节）。
    pub max_frame_bytes: u64,
    /// 服务端最大并发会话数。
    pub max_sessions: usize,
    /// 单会话最大并发流数。
    pub max_streams_per_session: usize,
    /// 单会话最大在途帧数。
    pub max_inflight_frames: usize,
    /// 最大 token 长度。
    pub max_token_len: usize,
    /// 每秒新建流上限（0 表示不限）。
    pub rate_streams_per_sec: u32,
    /// 每秒字节上限（0 表示不限）。
    pub rate_bytes_per_sec: u64,
    /// 令牌桶突发倍数。
    pub rate_burst_factor: u32,
    /// HTTP 上游响应超时（秒）。
    pub http_response_timeout_secs: u64,
    /// 是否对隧道链路启用 TLS 1.3。
    pub tls_enabled: bool,
    /// 服务端证书路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    /// 服务端私钥路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
    /// CA 证书路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca_path: Option<String>,
    /// 允许客户端自动重连。
    pub auto_reconnect: bool,
    /// 重连间隔（毫秒）。
    pub reconnect_delay_ms: u64,
    /// 握手超时（秒）。
    pub startup_timeout_secs: u64,
}

impl Default for TunnelSection {
    fn default() -> Self {
        Self {
            token: String::new(),
            max_frame_bytes: 16 * 1024 * 1024,
            max_sessions: 1000,
            max_streams_per_session: 256,
            max_inflight_frames: 1024,
            max_token_len: 512,
            rate_streams_per_sec: 200,
            rate_bytes_per_sec: 32 * 1024 * 1024,
            rate_burst_factor: 2,
            http_response_timeout_secs: 60,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            auto_reconnect: true,
            reconnect_delay_ms: 3000,
            startup_timeout_secs: 30,
        }
    }
}

/// 公网入口参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct IngressSection {
    /// 是否启用 HTTP/HTTPS 入口（按 Host 路由）。
    pub enable_http: bool,
    /// 是否启用 TCP/UDP 端口映射入口。
    pub enable_port: bool,
    /// TCP/UDP 允许分配的公网端口范围。
    pub port_range: String,
    /// HTTP 路由的默认域名后缀，例如 `t.example.com`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_domain: Option<String>,
}

impl Default for IngressSection {
    fn default() -> Self {
        Self {
            enable_http: true,
            enable_port: true,
            port_range: "20000-30000".to_string(),
            default_domain: None,
        }
    }
}

/// 控制台与初始管理员。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminSection {
    /// 首次启动时创建的管理员用户名。
    pub initial_user: String,
    /// 首次启动时创建的管理员密码；留空则随机生成并打印到日志。
    pub initial_password: String,
    /// 会话有效期（小时）。
    pub session_ttl_hours: u64,
    /// 是否允许在控制台修改服务端配置。
    pub allow_config_edit: bool,
}

impl Default for AdminSection {
    fn default() -> Self {
        Self {
            initial_user: "admin".to_string(),
            initial_password: String::new(),
            session_ttl_hours: 12,
            allow_config_edit: true,
        }
    }
}

/// 持久化参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSection {
    /// SQLite 文件路径。
    pub path: String,
    /// 连接忙等待（毫秒）。
    pub busy_timeout_ms: u32,
    /// 是否开启 WAL。
    pub wal: bool,
    /// 流量采样保留天数。
    pub traffic_retention_days: u32,
    /// 日志保留天数。
    pub log_retention_days: u32,
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            path: "rscross.db".to_string(),
            busy_timeout_ms: 5000,
            wal: true,
            traffic_retention_days: 30,
            log_retention_days: 7,
        }
    }
}

/// 鉴权策略。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// 是否允许自助注册客户端（关闭后必须由控制台签发接入凭证）。
    pub allow_self_enroll: bool,
    /// 接入令牌有效期（分钟）。
    pub enroll_token_ttl_minutes: u64,
    /// agent token 有效期（小时），0 表示不过期。
    pub agent_token_ttl_hours: u64,
    /// 登录失败锁定阈值（次数），0 表示不锁定。
    pub login_max_attempts: u32,
    /// 锁定时长（分钟）。
    pub login_lock_minutes: u64,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            allow_self_enroll: false,
            enroll_token_ttl_minutes: 30,
            agent_token_ttl_hours: 0,
            login_max_attempts: 5,
            login_lock_minutes: 15,
        }
    }
}

/// 日志参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LogSection {
    /// 日志级别 / EnvFilter 表达式。
    pub level: String,
    /// 输出格式：`text` 或 `json`。
    pub format: String,
    /// 内存环形缓冲容量（控制台「日志」页实时读取）。
    pub ring_capacity: usize,
    /// 是否把日志落库（便于历史检索，代价是写放大）。
    pub persist: bool,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: "info,rscross=debug".to_string(),
            format: "text".to_string(),
            ring_capacity: 2000,
            persist: false,
        }
    }
}

/// P2P（Iroh）参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct P2pSection {
    /// 是否启用 Iroh 节点。
    pub enabled: bool,
    /// 路径选择策略。
    pub policy: PathPolicy,
    /// Relay 模式：`n0`（官方公共中继）/ `custom`（自建）/ `disabled`。
    pub relay_mode: String,
    /// 自建 Relay 地址列表。
    pub relay_urls: Vec<String>,
    /// 是否启用 DNS/Pkarr 地址发现（`presets::N0` 自带）。
    pub address_lookup: bool,
    /// 节点私钥持久化路径；留空表示每次启动随机生成。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key_file: Option<String>,
}

impl Default for P2pSection {
    fn default() -> Self {
        Self {
            enabled: true,
            policy: PathPolicy::Auto,
            relay_mode: "n0".to_string(),
            relay_urls: Vec::new(),
            address_lookup: true,
            secret_key_file: None,
        }
    }
}

/// 全局限额。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    /// 最大客户端数（0 = 不限）。
    pub max_clients: u32,
    /// 单客户端最大隧道数。
    pub max_tunnels_per_client: u32,
    /// 默认每隧道限速（Kbps，0 = 不限）。
    pub default_rate_limit_kbps: u32,
    /// 默认每隧道最大并发连接数。
    pub default_conn_limit: u32,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_clients: 0,
            max_tunnels_per_client: 20,
            default_rate_limit_kbps: 0,
            default_conn_limit: 512,
        }
    }
}

impl ServerFile {
    /// 校验语义正确性。启动前必须调用。
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("server.admin_bind", &self.server.admin_bind),
            ("server.ingress_bind", &self.server.ingress_bind),
            ("server.tunnel_bind", &self.server.tunnel_bind),
        ] {
            value
                .parse::<std::net::SocketAddr>()
                .map_err(|e| Error::config(format!("{name} 不是合法的监听地址({value}): {e}")))?;
        }

        if self.server.heartbeat_secs == 0 {
            return Err(Error::config("server.heartbeat_secs 必须大于 0"));
        }
        if self.server.offline_after_secs <= self.server.heartbeat_secs {
            return Err(Error::config(
                "server.offline_after_secs 必须大于 server.heartbeat_secs，否则节点会持续抖动",
            ));
        }
        if self.tunnel.token.trim().is_empty() {
            return Err(Error::config(
                "tunnel.token 不能为空：它是 FerroTunnel 的握手凭证",
            ));
        }
        if self.tunnel.max_frame_bytes == 0 {
            return Err(Error::config("tunnel.max_frame_bytes 必须大于 0"));
        }
        if self.tunnel.max_frame_bytes > u64::from(u32::MAX) {
            return Err(Error::config(
                "tunnel.max_frame_bytes 不能超过 u32::MAX：FerroTunnel 的 LimitsConfig 不接受",
            ));
        }
        // FerroTunnel 要求速率限制的每个值都非零，否则 build() 直接报错。
        if self.tunnel.rate_streams_per_sec == 0
            || self.tunnel.rate_bytes_per_sec == 0
            || self.tunnel.rate_burst_factor == 0
        {
            return Err(Error::config(
                "tunnel.rate_* 均不能为 0（FerroTunnel 会拒绝零值速率限制）",
            ));
        }
        if self.tunnel.rate_bytes_per_sec > u64::from(u32::MAX) {
            return Err(Error::config(
                "tunnel.rate_bytes_per_sec 不能超过 u32::MAX：FerroTunnel 的限流器按 u32 计数",
            ));
        }
        if self.tunnel.http_response_timeout_secs == 0 {
            return Err(Error::config("tunnel.http_response_timeout_secs 必须大于 0"));
        }
        if self.tunnel.tls_enabled
            && (self.tunnel.tls_cert_path.is_none() || self.tunnel.tls_key_path.is_none())
        {
            return Err(Error::config(
                "启用 tunnel.tls_enabled 时必须同时提供 tls_cert_path 与 tls_key_path",
            ));
        }
        if self.database.path.trim().is_empty() {
            return Err(Error::config("database.path 不能为空"));
        }
        parse_port_range(&self.ingress.port_range)?;

        match self.log.format.as_str() {
            "text" | "json" => {}
            other => {
                return Err(Error::config(format!(
                    "log.format 只能是 text 或 json，实际为 {other}"
                )))
            }
        }
        if self.log.ring_capacity == 0 {
            return Err(Error::config("log.ring_capacity 必须大于 0"));
        }

        match self.p2p.relay_mode.as_str() {
            "n0" | "disabled" => {}
            "custom" => {
                if self.p2p.relay_urls.is_empty() {
                    return Err(Error::config(
                        "p2p.relay_mode = custom 时必须提供至少一个 p2p.relay_urls",
                    ));
                }
            }
            other => {
                return Err(Error::config(format!(
                    "p2p.relay_mode 只能是 n0 / custom / disabled，实际为 {other}"
                )))
            }
        }

        if self.limits.max_tunnels_per_client == 0 {
            return Err(Error::config("limits.max_tunnels_per_client 必须大于 0"));
        }
        if self.database.traffic_retention_days == 0 {
            return Err(Error::config("database.traffic_retention_days 必须大于 0"));
        }
        Ok(())
    }

    /// 从文件加载。
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("读取配置文件 {} 失败: {e}", path.display())))?;
        let parsed: Self = toml::from_str(&raw)
            .map_err(|e| Error::config(format!("解析配置文件 {} 失败: {e}", path.display())))?;
        Ok(parsed)
    }

    /// 加载并校验；文件不存在时用默认值创建。
    pub fn load_or_init(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let cfg = if path.exists() {
            Self::load(path)?
        } else {
            let mut cfg = Self::default();
            cfg.tunnel.token = crate::random_token_hex(32);
            cfg.save(path)?;
            tracing::info!(path = %path.display(), "已生成默认服务端配置");
            cfg
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// 写回文件。
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::config(format!("创建目录 {} 失败: {e}", parent.display()))
                })?;
            }
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| Error::config(format!("序列化配置失败: {e}")))?;
        std::fs::write(path, text)
            .map_err(|e| Error::config(format!("写入配置文件 {} 失败: {e}", path.display())))?;
        Ok(())
    }
}

/// 客户端配置文件。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientFile {
    /// 客户端基础信息。
    pub client: ClientSection,
    /// 反向隧道传输参数（token 由注册时下发，本地可留空）。
    pub tunnel: TunnelSection,
    /// 日志。
    pub log: LogSection,
    /// P2P（Iroh）参数。
    pub p2p: P2pSection,
    /// 静态声明的隧道；控制面下发的动态隧道优先级更高。
    pub tunnels: Vec<TunnelDecl>,
}

/// 客户端基础信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientSection {
    /// 节点展示名。
    pub name: String,
    /// 管理 API 地址，例如 `http://1.2.3.4:7800`。
    pub server_url: String,
    /// FerroTunnel 控制面地址，例如 `1.2.3.4:7835`。
    pub tunnel_server: String,
    /// 数据目录（保存 client_id、agent token、iroh 私钥）。
    pub state_dir: String,
    /// 预置接入令牌（控制台签发）；留空则读取 state_dir/enroll.token。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enroll_token: Option<String>,
    /// agent token（首次注册后自动写入 state_dir/agent.token）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_token: Option<String>,
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            name: hostname_or_default(),
            server_url: format!("http://127.0.0.1:{}", rscross_common::DEFAULT_ADMIN_PORT),
            tunnel_server: format!("127.0.0.1:{}", rscross_common::DEFAULT_TUNNEL_PORT),
            state_dir: "rscross-client-state".to_string(),
            enroll_token: None,
            agent_token: None,
        }
    }
}

/// 一条隧道的静态声明。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TunnelDecl {
    /// 隧道名（同一客户端内唯一）。
    pub name: String,
    /// 承载协议。
    pub proto: rscross_common::TunnelProto,
    /// 本地目标地址，例如 `127.0.0.1:8080`。
    pub local_addr: String,
    /// TCP/UDP 时希望占用的公网端口；为空则由服务端分配。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    /// HTTP 路由使用的 Host。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// HTTP 路由的路径前缀。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// 是否启用。
    pub enabled: bool,
}

impl Default for TunnelDecl {
    fn default() -> Self {
        Self {
            name: String::new(),
            proto: rscross_common::TunnelProto::Tcp,
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: None,
            host: None,
            path_prefix: None,
            enabled: true,
        }
    }
}

impl TunnelDecl {
    /// 构造一条最小的 TCP 隧道声明。
    pub fn tcp(name: impl Into<String>, local_addr: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local_addr: local_addr.into(),
            ..Default::default()
        }
    }
}

impl ClientFile {
    /// 校验语义正确性。
    pub fn validate(&self) -> Result<()> {
        let url = &self.client.server_url;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(Error::config(format!(
                "client.server_url 必须以 http:// 或 https:// 开头，实际为 {url}"
            )));
        }
        if self.client.tunnel_server.trim().is_empty() {
            return Err(Error::config("client.tunnel_server 不能为空"));
        }
        if self.client.state_dir.trim().is_empty() {
            return Err(Error::config("client.state_dir 不能为空"));
        }
        if self.log.format != "text" && self.log.format != "json" {
            return Err(Error::config("log.format 只能是 text 或 json"));
        }

        let mut seen = std::collections::HashSet::new();
        for t in &self.tunnels {
            if t.name.trim().is_empty() {
                return Err(Error::config("tunnels[].name 不能为空"));
            }
            if !seen.insert(t.name.as_str()) {
                return Err(Error::config(format!("隧道名重复: {}", t.name)));
            }
            t.local_addr.parse::<std::net::SocketAddr>().map_err(|e| {
                Error::config(format!("隧道 {} 的 local_addr 非法: {e}", t.name))
            })?;
            if t.proto.needs_remote_port() && t.remote_port == Some(0) {
                return Err(Error::config(format!("隧道 {} 的 remote_port 不能为 0", t.name)));
            }
        }
        Ok(())
    }

    /// 从文件加载。
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("读取配置文件 {} 失败: {e}", path.display())))?;
        let parsed: Self = toml::from_str(&raw)
            .map_err(|e| Error::config(format!("解析配置文件 {} 失败: {e}", path.display())))?;
        Ok(parsed)
    }

    /// 加载并校验；文件不存在时用默认值创建。
    pub fn load_or_init(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let cfg = if path.exists() {
            Self::load(path)?
        } else {
            let cfg = Self::default();
            cfg.save(path)?;
            tracing::info!(path = %path.display(), "已生成默认客户端配置");
            cfg
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// 写回文件。
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::config(format!("创建目录 {} 失败: {e}", parent.display()))
                })?;
            }
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| Error::config(format!("序列化配置失败: {e}")))?;
        std::fs::write(path, text)
            .map_err(|e| Error::config(format!("写入配置文件 {} 失败: {e}", path.display())))?;
        Ok(())
    }
}

/// 解析 `20000-30000` 形式的端口范围。
pub fn parse_port_range(raw: &str) -> Result<(u16, u16)> {
    let (lo, hi) = raw
        .split_once('-')
        .ok_or_else(|| Error::config(format!("端口范围必须形如 20000-30000，实际为 {raw}")))?;
    let lo: u16 = lo
        .trim()
        .parse()
        .map_err(|e| Error::config(format!("端口范围下界非法: {e}")))?;
    let hi: u16 = hi
        .trim()
        .parse()
        .map_err(|e| Error::config(format!("端口范围上界非法: {e}")))?;
    if lo == 0 || hi < lo {
        return Err(Error::config(format!("端口范围非法: {raw}")));
    }
    Ok((lo, hi))
}

/// 生成密码学随机 token 的十六进制表示。
///
/// 这里直接调用 `getrandom`（经由 `rand::rngs::OsRng`），不依赖任何上层 API。
pub fn random_token_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut buf = vec![0u8; bytes];
    rng.fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// 十六进制编码（内部小工具，避免为一行代码引入 `hex` 依赖到 config crate）。
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 默认 state 目录的绝对化处理。
pub fn state_dir_path(raw: &str) -> PathBuf {
    PathBuf::from(raw)
}

fn hostname_or_default() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "rscross-client".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_server_config_is_valid() {
        let mut cfg = ServerFile::default();
        cfg.tunnel.token = "t".repeat(16);
        cfg.validate().expect("默认配置应当合法");
    }

    #[test]
    fn offline_threshold_must_exceed_heartbeat() {
        let mut cfg = ServerFile::default();
        cfg.tunnel.token = "x".to_string();
        cfg.server.heartbeat_secs = 30;
        cfg.server.offline_after_secs = 30;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn custom_relay_requires_urls() {
        let mut cfg = ServerFile::default();
        cfg.tunnel.token = "x".to_string();
        cfg.p2p.relay_mode = "custom".to_string();
        assert!(cfg.validate().is_err());
        cfg.p2p.relay_urls = vec!["https://relay.example.com".to_string()];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn port_range_parsing() {
        assert_eq!(parse_port_range("20000-30000").expect("ok"), (20000, 30000));
        assert!(parse_port_range("30000-20000").is_err());
        assert!(parse_port_range("nope").is_err());
    }

    #[test]
    fn partial_toml_falls_back_to_defaults() {
        let raw = r#"
[server]
admin_bind = "127.0.0.1:7800"

[tunnel]
token = "abcdef"
"#;
        let cfg: ServerFile = toml::from_str(raw).expect("部分配置可解析");
        assert_eq!(cfg.server.admin_bind, "127.0.0.1:7800");
        // 未提供的字段回落默认值
        assert_eq!(cfg.server.ingress_bind, ServerSection::default().ingress_bind);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn duplicate_tunnel_names_rejected() {
        let mut cfg = ClientFile::default();
        cfg.tunnels.push(TunnelDecl::tcp("a", "127.0.0.1:1"));
        cfg.tunnels.push(TunnelDecl::tcp("a", "127.0.0.1:2"));
        assert!(cfg.validate().is_err());
    }
}
