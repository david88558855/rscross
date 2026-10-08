//! `rscross-config`：三种角色的配置文件模型。
//!
//! | 文件 | 角色 | 说明 |
//! |---|---|---|
//! | [`ConsoleFile`] | 控制台（独立二进制 **或** 服务端内嵌） | 管理面：监听、数据库、鉴权策略、日志、全局限额、入口策略 |
//! | [`NodeFile`]   | 服务端节点 | 数据面：反向隧道监听、公网入口监听、Iroh 参数、控制台地址 |
//! | [`ClientFile`] | 内网客户端 | 控制台地址、状态目录、Iroh 参数、静态隧道声明 |
//!
//! 约定：
//! - 所有字段 `#[serde(default)]`，部分配置的 TOML 也能加载，升级不炸旧文件；
//! - `Option` 字段带 `skip_serializing_if`，保证默认配置能被 TOML 正确序列化回来；
//! - `deny_unknown_fields` 让拼写错误在启动时报出，而不是被静默忽略；
//! - `validate()` 是唯一的语义校验入口，启动时调用一次，失败即拒绝启动。

use std::path::{Path, PathBuf};

use rscross_common::{Error, PathPolicy, Result};
use serde::{Deserialize, Serialize};

// ============================================================ 控制台

/// 独立控制台 / 内嵌控制台的配置文件。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleFile {
    /// 基础信息与监听。
    pub console: ConsoleSection,
    /// 控制台管理员。
    pub admin: AdminSection,
    /// 持久化。
    pub database: DatabaseSection,
    /// 鉴权策略。
    pub auth: AuthSection,
    /// 日志。
    pub log: LogSection,
    /// 全局限额。
    pub limits: LimitsSection,
    /// 公网入口策略（端口池、默认域名）。
    pub ingress: IngressPolicy,
}

/// 控制台基础信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleSection {
    /// 显示名。
    pub name: String,
    /// 管理 API 与 Web 控制台监听地址。
    pub bind: String,
    /// 对外可达地址，用于生成接入命令（例如 `https://panel.example.com`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// 节点 / 客户端的心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 超过该时长未心跳即判定离线（秒）。
    pub offline_after_secs: u64,
    /// 关停时等待任务收敛的最长时间（秒）。
    pub shutdown_grace_secs: u64,
}

impl Default for ConsoleSection {
    fn default() -> Self {
        Self {
            name: "rscross-console".to_string(),
            bind: format!("0.0.0.0:{}", rscross_common::DEFAULT_CONSOLE_PORT),
            public_url: None,
            heartbeat_secs: rscross_common::DEFAULT_HEARTBEAT_SECS,
            offline_after_secs: 45,
            shutdown_grace_secs: 10,
        }
    }
}

/// 控制台管理员与会话。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminSection {
    /// 首次启动时创建的管理员用户名。
    pub initial_user: String,
    /// 首次启动时创建的管理员密码；留空则随机生成并打印到标准错误输出。
    pub initial_password: String,
    /// 会话有效期（小时）。
    pub session_ttl_hours: u64,
    /// 是否允许在控制台修改配置。
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
            path: "rscross-console.db".to_string(),
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
    /// 是否允许不带接入令牌自助注册客户端。
    ///
    /// 打开时新客户端会被分配到控制台里**唯一**的节点；有多个节点时该开关无意义
    /// （无法确定归属），此时仍要求令牌。
    pub allow_self_enroll: bool,
    /// 接入令牌有效期（分钟）。
    pub enroll_token_ttl_minutes: u64,
    /// agent / node token 有效期（小时），0 表示不过期。
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

/// 全局限额。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    /// 最大服务端节点数（0 = 不限）。
    pub max_nodes: u32,
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
            max_nodes: 0,
            max_clients: 0,
            max_tunnels_per_client: 20,
            default_rate_limit_kbps: 0,
            default_conn_limit: 512,
        }
    }
}

/// 公网入口策略。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct IngressPolicy {
    /// 允许分配给 TCP/UDP 隧道的端口范围。
    pub port_range: String,
    /// HTTP 路由的默认域名后缀，例如 `t.example.com`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_domain: Option<String>,
}

impl Default for IngressPolicy {
    fn default() -> Self {
        Self {
            port_range: "20000-30000".to_string(),
            default_domain: None,
        }
    }
}

impl ConsoleFile {
    /// 校验语义正确性。启动前必须调用。
    pub fn validate(&self) -> Result<()> {
        parse_socket_addr(&self.console.bind, "console.bind")?;

        if self.console.heartbeat_secs == 0 {
            return Err(Error::config("console.heartbeat_secs 必须大于 0"));
        }
        if self.console.offline_after_secs <= self.console.heartbeat_secs {
            return Err(Error::config(
                "console.offline_after_secs 必须大于 console.heartbeat_secs，否则节点会持续抖动",
            ));
        }
        if self.database.path.trim().is_empty() {
            return Err(Error::config("database.path 不能为空"));
        }
        if self.database.traffic_retention_days == 0 {
            return Err(Error::config("database.traffic_retention_days 必须大于 0"));
        }
        check_log(&self.log)?;
        parse_port_range(&self.ingress.port_range)?;

        if self.limits.max_tunnels_per_client == 0 {
            return Err(Error::config("limits.max_tunnels_per_client 必须大于 0"));
        }
        Ok(())
    }

    /// 从文件加载。
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        load_toml(path)
    }

    /// 加载并校验；文件不存在时用默认值创建。
    pub fn load_or_init(path: impl AsRef<Path>) -> Result<Self> {
        load_or_init_toml(path, "控制台", |cfg: &Self| cfg.validate())
    }

    /// 写回文件。
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        write_toml(self, path)
    }
}

// ============================================================ 服务端节点

/// 服务端节点配置文件。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NodeFile {
    /// 节点基础信息。
    pub node: NodeSection,
    /// 反向隧道（FerroTunnel）参数，token 由控制台下发。
    pub tunnel: TunnelSection,
    /// P2P（Iroh）参数。
    pub p2p: P2pSection,
    /// 日志。
    pub log: LogSection,
}

/// 节点基础信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NodeSection {
    /// 节点展示名。
    pub name: String,
    /// 控制台形态：`embedded`（本进程内嵌，单机自用）/ `managed`（加入远端控制台）。
    pub control_mode: String,
    /// `managed` 模式下的控制台地址，例如 `http://1.2.3.4:7800`。
    pub console_url: String,
    /// 状态目录（保存节点身份与 Iroh 私钥）。
    pub state_dir: String,
    /// `managed` 模式下控制台签发的一次性接入令牌。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enroll_token: Option<String>,
    /// 已注册后缓存的节点 token（一般由程序写入 state_dir，不手填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_token: Option<String>,
    /// 对外可达主机名/IP，用于生成客户端接入地址；留空则由控制台按观测到的出口 IP 推导。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    /// 反向隧道控制面监听地址。
    pub tunnel_bind: String,
    /// 公网入口监听地址。
    pub ingress_bind: String,
    /// `embedded` 模式下的控制台配置文件路径（默认 `<state_dir>/console.toml`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_config: Option<String>,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            name: hostname_or_default(),
            control_mode: "embedded".to_string(),
            console_url: format!("http://127.0.0.1:{}", rscross_common::DEFAULT_CONSOLE_PORT),
            state_dir: "rscross-node-state".to_string(),
            enroll_token: None,
            node_token: None,
            public_host: None,
            tunnel_bind: format!("0.0.0.0:{}", rscross_common::DEFAULT_TUNNEL_PORT),
            ingress_bind: format!("0.0.0.0:{}", rscross_common::DEFAULT_INGRESS_PORT),
            console_config: None,
        }
    }
}

impl NodeFile {
    /// 校验语义正确性。
    pub fn validate(&self) -> Result<()> {
        if self.node.name.trim().is_empty() {
            return Err(Error::config("node.name 不能为空"));
        }
        match self.node.control_mode.as_str() {
            "embedded" | "managed" => {}
            other => {
                return Err(Error::config(format!(
                    "node.control_mode 只能是 embedded 或 managed，实际为 {other}"
                )))
            }
        }
        if self.node.control_mode == "managed" {
            let url = &self.node.console_url;
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(Error::config(format!(
                    "managed 模式下 node.console_url 必须以 http:// 或 https:// 开头，实际为 {url}"
                )));
            }
        }
        parse_socket_addr(&self.node.tunnel_bind, "node.tunnel_bind")?;
        parse_socket_addr(&self.node.ingress_bind, "node.ingress_bind")?;

        if self.node.state_dir.trim().is_empty() {
            return Err(Error::config("node.state_dir 不能为空"));
        }
        check_tunnel(&self.tunnel)?;
        check_p2p(&self.p2p)?;
        check_log(&self.log)?;
        Ok(())
    }

    /// 是否使用内嵌控制台。
    pub fn is_embedded(&self) -> bool {
        self.node.control_mode == "embedded"
    }

    /// 从文件加载。
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        load_toml(path)
    }

    /// 加载并校验；文件不存在时用默认值创建。
    pub fn load_or_init(path: impl AsRef<Path>) -> Result<Self> {
        load_or_init_toml(path, "服务端节点", |cfg: &Self| cfg.validate())
    }

    /// 写回文件。
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        write_toml(self, path)
    }
}

// ============================================================ 内网客户端

/// 内网客户端配置文件。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientFile {
    /// 客户端基础信息。
    pub client: ClientSection,
    /// 反向隧道传输参数（token 由控制台下发，本地可留空）。
    pub tunnel: TunnelSection,
    /// P2P（Iroh）参数。
    pub p2p: P2pSection,
    /// 日志。
    pub log: LogSection,
    /// 静态声明的隧道（控制面下发优先）。
    pub tunnels: Vec<TunnelDecl>,
}

/// 客户端基础信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientSection {
    /// 节点展示名。
    pub name: String,
    /// 控制台地址，例如 `http://1.2.3.4:7800`。
    pub console_url: String,
    /// 数据目录（保存 client_id、agent token、iroh 私钥）。
    pub state_dir: String,
    /// 控制台签发的一次性接入令牌。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enroll_token: Option<String>,
    /// agent token（首次注册后由程序写入 state_dir）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_token: Option<String>,
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            name: hostname_or_default(),
            console_url: format!("http://127.0.0.1:{}", rscross_common::DEFAULT_CONSOLE_PORT),
            state_dir: "rscross-client-state".to_string(),
            enroll_token: None,
            agent_token: None,
        }
    }
}

impl ClientFile {
    /// 校验语义正确性。
    pub fn validate(&self) -> Result<()> {
        let url = &self.client.console_url;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(Error::config(format!(
                "client.console_url 必须以 http:// 或 https:// 开头，实际为 {url}"
            )));
        }
        if self.client.state_dir.trim().is_empty() {
            return Err(Error::config("client.state_dir 不能为空"));
        }
        check_tunnel(&self.tunnel)?;
        check_p2p(&self.p2p)?;
        check_log(&self.log)?;

        let mut seen = std::collections::HashSet::new();
        for t in &self.tunnels {
            if t.name.trim().is_empty() {
                return Err(Error::config("tunnels[].name 不能为空"));
            }
            if !seen.insert(t.name.as_str()) {
                return Err(Error::config(format!("隧道名重复: {}", t.name)));
            }
            t.local_addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| Error::config(format!("隧道 {} 的 local_addr 非法: {e}", t.name)))?;
        }
        Ok(())
    }

    /// 从文件加载。
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        load_toml(path)
    }

    /// 加载并校验；文件不存在时用默认值创建。
    pub fn load_or_init(path: impl AsRef<Path>) -> Result<Self> {
        load_or_init_toml(path, "客户端", |cfg: &Self| cfg.validate())
    }

    /// 写回文件。
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        write_toml(self, path)
    }
}

// ============================================================ 公共小节

/// 反向隧道（FerroTunnel）参数。
///
/// 字段与 `ferrotunnel::common::{LimitsConfig, RateLimitConfig, TlsConfig}` 一一对应，
/// 由 `rscross-transport` 在启动时转换。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TunnelSection {
    /// FerroTunnel 握手 token。节点侧与客户端侧一般由控制台下发；
    /// 不经控制台手工部署时可以在这里填写。
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
    /// 每秒新建流上限（FerroTunnel 要求非零）。
    pub rate_streams_per_sec: u32,
    /// 每秒字节上限（FerroTunnel 要求非零且不超过 u32::MAX）。
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
    /// 节点私钥持久化路径；留空表示使用 state_dir 下的默认位置。
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

/// 一条隧道的静态声明（客户端本地配置用）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TunnelDecl {
    /// 隧道名（同一客户端内唯一）。
    pub name: String,
    /// 承载协议。
    pub proto: rscross_common::TunnelProto,
    /// 本地目标地址。
    pub local_addr: String,
    /// 公网端口。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    /// HTTP 路由 Host。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// HTTP 路径前缀。
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
pub fn random_token_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut buf = vec![0u8; bytes];
    rng.fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// 十六进制编码（避免为一行代码给 config crate 引入 `hex` 依赖）。
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 把 state 目录字符串解析为 `PathBuf`。
pub fn state_dir_path(raw: &str) -> PathBuf {
    PathBuf::from(raw)
}

// ------------------------------------------------------------ 内部工具

fn parse_socket_addr(raw: &str, field: &str) -> Result<std::net::SocketAddr> {
    raw.parse::<std::net::SocketAddr>()
        .map_err(|e| Error::config(format!("{field} 不是合法的监听地址({raw}): {e}")))
}

fn check_log(log: &LogSection) -> Result<()> {
    match log.format.as_str() {
        "text" | "json" => {}
        other => {
            return Err(Error::config(format!(
                "log.format 只能是 text 或 json，实际为 {other}"
            )))
        }
    }
    if log.ring_capacity == 0 {
        return Err(Error::config("log.ring_capacity 必须大于 0"));
    }
    Ok(())
}

fn check_tunnel(tunnel: &TunnelSection) -> Result<()> {
    if tunnel.max_frame_bytes == 0 {
        return Err(Error::config("tunnel.max_frame_bytes 必须大于 0"));
    }
    if tunnel.max_frame_bytes > u64::from(u32::MAX) {
        return Err(Error::config(
            "tunnel.max_frame_bytes 不能超过 u32::MAX：FerroTunnel 的 LimitsConfig 不接受",
        ));
    }
    // FerroTunnel 要求速率限制的每个值都非零，否则 build() 直接报错。
    if tunnel.rate_streams_per_sec == 0
        || tunnel.rate_bytes_per_sec == 0
        || tunnel.rate_burst_factor == 0
    {
        return Err(Error::config(
            "tunnel.rate_* 均不能为 0（FerroTunnel 会拒绝零值速率限制）",
        ));
    }
    if tunnel.rate_bytes_per_sec > u64::from(u32::MAX) {
        return Err(Error::config(
            "tunnel.rate_bytes_per_sec 不能超过 u32::MAX：FerroTunnel 的限流器按 u32 计数",
        ));
    }
    if tunnel.http_response_timeout_secs == 0 {
        return Err(Error::config("tunnel.http_response_timeout_secs 必须大于 0"));
    }
    if tunnel.tls_enabled && (tunnel.tls_cert_path.is_none() || tunnel.tls_key_path.is_none()) {
        return Err(Error::config(
            "启用 tunnel.tls_enabled 时必须同时提供 tls_cert_path 与 tls_key_path",
        ));
    }
    Ok(())
}

fn check_p2p(p2p: &P2pSection) -> Result<()> {
    match p2p.relay_mode.as_str() {
        "n0" | "disabled" => {}
        "custom" => {
            if p2p.relay_urls.is_empty() {
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
    Ok(())
}

fn load_toml<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::config(format!("读取配置文件 {} 失败: {e}", path.display())))?;
    toml::from_str(&raw)
        .map_err(|e| Error::config(format!("解析配置文件 {} 失败: {e}", path.display())))
}

fn load_or_init_toml<T, F>(path: impl AsRef<Path>, label: &str, validate: F) -> Result<T>
where
    T: serde::de::DeserializeOwned + Serialize + Default,
    F: FnOnce(&T) -> Result<()>,
{
    let path = path.as_ref();
    let cfg = if path.exists() {
        load_toml(path)?
    } else {
        let cfg = T::default();
        write_toml(&cfg, path)?;
        tracing::info!(path = %path.display(), label, "已生成默认配置");
        cfg
    };
    validate(&cfg)?;
    Ok(cfg)
}

fn write_toml<T: Serialize>(value: &T, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::config(format!("创建目录 {} 失败: {e}", parent.display())))?;
        }
    }
    let text =
        toml::to_string_pretty(value).map_err(|e| Error::config(format!("序列化配置失败: {e}")))?;
    std::fs::write(path, text)
        .map_err(|e| Error::config(format!("写入配置文件 {} 失败: {e}", path.display())))?;
    Ok(())
}

fn hostname_or_default() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "rscross".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_default_is_valid() {
        ConsoleFile::default().validate().expect("默认控制台配置应当合法");
    }

    #[test]
    fn node_default_is_valid() {
        NodeFile::default().validate().expect("默认节点配置应当合法");
    }

    #[test]
    fn client_default_is_valid() {
        ClientFile::default().validate().expect("默认客户端配置应当合法");
    }

    #[test]
    fn managed_mode_requires_http_console_url() {
        let mut cfg = NodeFile::default();
        cfg.node.control_mode = "managed".to_string();
        cfg.node.console_url = "1.2.3.4:7800".to_string();
        assert!(cfg.validate().is_err());

        cfg.node.console_url = "http://1.2.3.4:7800".to_string();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn embedded_mode_does_not_require_console_url() {
        let mut cfg = NodeFile::default();
        cfg.node.control_mode = "embedded".to_string();
        cfg.node.console_url = String::new();
        assert!(cfg.validate().is_ok(), "内嵌模式不依赖远端控制台地址");
        assert!(cfg.is_embedded());
    }

    #[test]
    fn unknown_control_mode_rejected() {
        let mut cfg = NodeFile::default();
        cfg.node.control_mode = "whatever".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn offline_threshold_must_exceed_heartbeat() {
        let mut cfg = ConsoleFile::default();
        cfg.console.heartbeat_secs = 30;
        cfg.console.offline_after_secs = 30;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn custom_relay_requires_urls() {
        let mut cfg = NodeFile::default();
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
[console]
bind = "127.0.0.1:7800"
"#;
        let cfg: ConsoleFile = toml::from_str(raw).expect("部分配置可解析");
        assert_eq!(cfg.console.bind, "127.0.0.1:7800");
        assert_eq!(
            cfg.console.heartbeat_secs,
            ConsoleSection::default().heartbeat_secs
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn default_configs_roundtrip_through_toml() {
        // 守「--print-default-config 与 save() 不会因为 None 字段而失败」
        for text in [
            toml::to_string_pretty(&ConsoleFile::default()).expect("console 应可序列化"),
            toml::to_string_pretty(&NodeFile::default()).expect("node 应可序列化"),
            toml::to_string_pretty(&ClientFile::default()).expect("client 应可序列化"),
        ] {
            assert!(!text.is_empty());
            assert!(!text.contains("null"));
        }
    }

    #[test]
    fn duplicate_tunnel_names_rejected() {
        let mut cfg = ClientFile::default();
        cfg.tunnels.push(TunnelDecl::tcp("a", "127.0.0.1:1"));
        cfg.tunnels.push(TunnelDecl::tcp("a", "127.0.0.1:2"));
        assert!(cfg.validate().is_err());
    }
}
