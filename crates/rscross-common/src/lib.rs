//! `rscross-common`：全工程共享的错误类型、ID、协议常量与控制面 DTO。
//!
//! 设计原则：
//! 1. 该 crate **不依赖** iroh / ferrotunnel / rusqlite，保证错误类型在任意层都能安全使用；
//!    外部库的错误统一通过 [`Error::transport`] / [`Error::store`] 等构造器降级为字符串。
//! 2. 所有跨进程传输的结构体都实现 `serde`，便于在 HTTP / JSON / SQLite 之间复用。

use serde::{Deserialize, Serialize};

/// 全工程统一 `Result`。
pub type Result<T> = std::result::Result<T, Error>;

/// 全工程统一错误类型。
///
/// 分层的变体便于在日志与 API 响应里快速定位故障域，
/// 同时避免 `rscross-common` 引入底层依赖。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 配置解析 / 校验失败。
    #[error("配置错误: {0}")]
    Config(String),

    /// 通用 I/O 失败。
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 序列化 / 反序列化失败。
    #[error("JSON 错误: {0}")]
    Json(#[from] serde_json::Error),

    /// 传输层（Iroh / FerroTunnel）失败。
    #[error("传输层错误: {0}")]
    Transport(String),

    /// 持久化层失败。
    #[error("存储错误: {0}")]
    Store(String),

    /// 认证 / 鉴权失败。
    #[error("鉴权错误: {0}")]
    Auth(String),

    /// 对外 API 语义错误（带 HTTP 状态码语义）。
    #[error("接口错误: {0}")]
    Api(String),

    /// 其它内部错误。
    #[error("内部错误: {0}")]
    Internal(String),
}

impl Error {
    /// 构造配置错误。
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// 降级包装传输层错误（`iroh::endpoint::ConnectError`、`ferrotunnel::TunnelError` 等）。
    pub fn transport(err: impl std::fmt::Display) -> Self {
        Self::Transport(err.to_string())
    }

    /// 降级包装存储层错误（`rusqlite::Error` 等）。
    pub fn store(err: impl std::fmt::Display) -> Self {
        Self::Store(err.to_string())
    }

    /// 构造鉴权错误。
    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    /// 构造接口错误。
    pub fn api(msg: impl Into<String>) -> Self {
        Self::Api(msg.into())
    }

    /// 构造内部错误。
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// 该错误是否属于「可重试」类别（客户端退避重连时使用）。
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Transport(_) | Self::Store(_))
    }

    /// 稳定的错误码，供 API 响应与前端提示使用。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_error",
            Self::Io(_) => "io_error",
            Self::Json(_) => "json_error",
            Self::Transport(_) => "transport_error",
            Self::Store(_) => "store_error",
            Self::Auth(_) => "auth_error",
            Self::Api(_) => "api_error",
            Self::Internal(_) => "internal_error",
        }
    }
}

/// 编译期注入的版本号。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Iroh 控制面 ALPN（服务端 ← 客户端的心跳 / 配置下发）。
pub const ALPN_RSROSS_CONTROL: &[u8] = b"rscross/control/1";

/// Iroh 数据面 ALPN（把公网连接通过 P2P 直连投递给目标客户端）。
pub const ALPN_RSROSS_DATA: &[u8] = b"rscross/data/1";

/// 默认隧道控制面端口（与 FerroTunnel 默认值保持一致，便于排障）。
pub const DEFAULT_TUNNEL_PORT: u16 = 7835;

/// 默认公网入口端口。
pub const DEFAULT_INGRESS_PORT: u16 = 8081;

/// 默认控制台 / 管理 API 端口。
pub const DEFAULT_CONSOLE_PORT: u16 = 7800;

/// 默认保活间隔（秒）。
pub const DEFAULT_HEARTBEAT_SECS: u64 = 15;

/// 客户端 ID。使用 UUID v4，序列化为字符串。
pub type ClientId = uuid::Uuid;

/// 隧道 ID。
pub type TunnelId = uuid::Uuid;

/// 隧道承载协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProto {
    /// 原始 TCP 端口映射。
    Tcp,
    /// HTTP（按 Host / 路径前缀路由）。
    Http,
    /// HTTPS（TLS 终结在服务端）。
    Https,
    /// UDP 端口映射。
    Udp,
}

impl TunnelProto {
    /// 是否存在「服务端监听端口」这一维度。
    pub fn needs_remote_port(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }

    /// 是否是 HTTP 类（走 Host 路由而非固定端口）。
    pub fn is_http_family(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    /// 小写标识。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Https => "https",
            Self::Udp => "udp",
        }
    }
}

impl std::fmt::Display for TunnelProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 数据面路径类型 —— 由 [`crate::PathKind`] 语义决定优先级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    /// Iroh QUIC 打洞直连（不过公网服务器）。
    P2p,
    /// Iroh Relay 中继。
    IrohRelay,
    /// FerroTunnel 反向隧道中继（默认回退路径）。
    FerryRelay,
}

impl PathKind {
    /// 该路径是否消耗服务端出口带宽。
    pub fn uses_server_bandwidth(self) -> bool {
        !matches!(self, Self::P2p)
    }

    /// 排序权重，越小越优先。
    pub fn priority(self) -> u8 {
        match self {
            Self::P2p => 0,
            Self::IrohRelay => 1,
            Self::FerryRelay => 2,
        }
    }
}

impl std::fmt::Display for PathKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::P2p => "p2p",
            Self::IrohRelay => "iroh-relay",
            Self::FerryRelay => "ferry-relay",
        };
        f.write_str(s)
    }
}

/// 路径选择策略（控制台可配置，随配置下发到客户端）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathPolicy {
    /// 自动：优先 P2P，失败降级中继。
    Auto,
    /// 强制 P2P：打洞失败即报错，不落中继（用于合规要求流量不过第三方的场景）。
    P2pOnly,
    /// 强制中继：全部流量走服务端，便于审计与限速。
    RelayOnly,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self::Auto
    }
}

impl PathPolicy {
    /// 小写标识，用于 API 与审计。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::P2pOnly => "p2p-only",
            Self::RelayOnly => "relay-only",
        }
    }
}

impl std::fmt::Display for PathPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 客户端在线状态（由心跳与隧道状态推导）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientStatus {
    /// 已注册，尚未收到心跳。
    Pending,
    /// 心跳正常。
    Online,
    /// 心跳超时。
    Offline,
    /// 被管理员禁用。
    Disabled,
}

impl ClientStatus {
    /// 小写标识，用于数据库与 API。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Disabled => "disabled",
        }
    }

    /// 从数据库字符串恢复。
    pub fn from_db(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "offline" => Self::Offline,
            "disabled" => Self::Disabled,
            _ => Self::Pending,
        }
    }
}

/// 客户端上报的运行时信息。
///
/// 结构体级别的 `#[serde(default)]`：允许心跳只带部分字段
/// （老版本客户端、精简上报、手工 curl 调试都依赖这一点）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientRuntime {    /// 客户端版本号。
    pub version: String,
    /// 操作系统。
    pub os: String,
    /// CPU 架构。
    pub arch: String,
    /// Iroh EndpointId（公钥），未启用 P2P 时为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    /// Iroh EndpointAddr 的 JSON 序列化形式，服务端据此发起直连。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// 节点公网出口 IP（由服务端在心跳请求里回填，客户端只读）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
}

/// 服务端**节点**上报的运行时信息。
///
/// 与控制台是两次心跳（`ClientRuntime` 是客户端 → 控制台，本结构是节点 → 控制台），
/// 两者字段高度相似但不合并：节点额外要汇报数据面监听端口，客户端要汇报被分配的节点。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeRuntime {
    /// 节点进程版本。
    pub version: String,
    /// 操作系统。
    pub os: String,
    /// CPU 架构。
    pub arch: String,
    /// Iroh EndpointId（公钥），未启用 P2P 时为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    /// Iroh EndpointAddr 的 JSON 形式，控制台据此下发给客户端做直连。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// 反向隧道控制面实际监听端口。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_port: Option<u16>,
    /// 公网入口实际监听端口。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_port: Option<u16>,
    /// 节点声明的对外主机名；留空则由控制台按观测到的出口 IP 推导。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
}

/// 客户端被分配到的服务端节点（数据面坐标）。
///
/// 独立控制台管理多个节点时，客户端必须知道「我的反向隧道该连哪台节点」，
/// 因此控制台在注册/心跳响应里都带上这份信息。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeEndpoint {
    /// 节点 ID。
    pub node_id: String,
    /// 节点名。
    pub name: String,
    /// 反向隧道控制面地址，形如 `1.2.3.4:7835`。
    pub tunnel_server: String,
    /// 该节点的 FerroTunnel 握手 token。
    pub tunnel_token: String,
    /// 节点 Iroh EndpointId。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    /// 节点 Iroh 寻址信息（JSON），用于直连该节点。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
}

/// 控制面下发给客户端的隧道定义。
///
/// 刻意不复用数据库实体：客户端**不应**把 `rusqlite` 打进静态二进制。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesiredTunnel {    /// 隧道 ID。
    pub id: String,
    /// 隧道名（同一客户端内唯一）。
    pub name: String,
    /// 承载协议。
    pub proto: TunnelProto,
    /// 本地目标地址。
    pub local_addr: String,
    /// 公网端口（tcp/udp）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    /// HTTP Host（http/https）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// HTTP 路径前缀。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// 是否启用。
    pub enabled: bool,
    /// 限速（Kbps，0 = 不限）。
    pub rate_limit_kbps: u32,
    /// 并发连接上限（0 = 不限）。
    pub conn_limit: u32,
}

impl DesiredTunnel {
    /// 反向隧道 + P2P 数据面共用的**路由键**。
    ///
    /// - HTTP 类隧道按 `Host` 路由（与服务端 FerroTunnel ingress 的匹配规则一致）；
    /// - TCP/UDP 按隧道名路由（固定端口映射场景下列名唯一即可）。
    ///
    /// 服务端与客户端必须用同一函数计算，否则会出现「隧道建立了但流量投递不到」。
    pub fn route_key(&self) -> String {
        if self.proto.is_http_family() {
            self.host
                .as_deref()
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .unwrap_or(self.name.as_str())
                .to_string()
        } else {
            self.name.clone()
        }
    }
}

/// 统一时间戳工具（RFC3339，UTC）。
pub mod time {
    use chrono::{DateTime, SecondsFormat, Utc};

    /// 当前 UTC 时间。
    pub fn now() -> DateTime<Utc> {
        Utc::now()
    }

    /// 格式化为 RFC3339（毫秒精度），用于数据库与 API。
    pub fn to_rfc3339(ts: DateTime<Utc>) -> String {
        ts.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    /// 当前时间的 RFC3339 字符串。
    pub fn now_rfc3339() -> String {
        to_rfc3339(now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_priority_puts_direct_first() {
        assert!(PathKind::P2p.priority() < PathKind::IrohRelay.priority());
        assert!(PathKind::IrohRelay.priority() < PathKind::FerryRelay.priority());
        assert!(!PathKind::P2p.uses_server_bandwidth());
        assert!(PathKind::FerryRelay.uses_server_bandwidth());
    }

    #[test]
    fn tunnel_proto_roundtrip() {
        for p in [
            TunnelProto::Tcp,
            TunnelProto::Http,
            TunnelProto::Https,
            TunnelProto::Udp,
        ] {
            let s = serde_json::to_string(&p).expect("serialize");
            let back: TunnelProto = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(p, back);
        }
    }

    #[test]
    fn client_status_db_roundtrip() {
        for s in [
            ClientStatus::Pending,
            ClientStatus::Online,
            ClientStatus::Offline,
            ClientStatus::Disabled,
        ] {
            assert_eq!(ClientStatus::from_db(s.as_str()), s);
        }
    }

    #[test]
    fn error_code_is_stable() {
        assert_eq!(Error::config("x").code(), "config_error");
        assert_eq!(Error::transport("x").code(), "transport_error");
        assert!(Error::transport("boom").is_retryable());
        assert!(!Error::auth("boom").is_retryable());
    }

    #[test]
    fn route_key_matches_ferrotunnel_host_routing() {
        let http = DesiredTunnel {
            id: "1".into(),
            name: "web".into(),
            proto: TunnelProto::Http,
            local_addr: "127.0.0.1:8080".into(),
            remote_port: None,
            host: Some("a.example.com".into()),
            path_prefix: None,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
        };
        assert_eq!(http.route_key(), "a.example.com");

        let tcp = DesiredTunnel {
            proto: TunnelProto::Tcp,
            host: Some("ignored.example.com".into()),
            ..http.clone()
        };
        assert_eq!(tcp.route_key(), "web", "TCP 隧道按名字路由，忽略 Host");

        let http_no_host = DesiredTunnel {
            host: None,
            ..http
        };
        assert_eq!(http_no_host.route_key(), "web", "缺 Host 时回落到名字");
    }

    #[test]
    fn desired_tunnel_roundtrips_through_json() {
        let t = DesiredTunnel {
            id: "id".into(),
            name: "n".into(),
            proto: TunnelProto::Udp,
            local_addr: "127.0.0.1:53".into(),
            remote_port: Some(20530),
            host: None,
            path_prefix: Some("/api".into()),
            enabled: true,
            rate_limit_kbps: 100,
            conn_limit: 64,
        };
        let json = serde_json::to_string(&t).expect("ser");
        let back: DesiredTunnel = serde_json::from_str(&json).expect("de");
        assert_eq!(t, back);
    }
}
