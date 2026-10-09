//! `rscross-common`：全工程共享的错误类型、ID、协议常量与控制面 DTO。
//!
//! 设计原则：
//! 1. 该 crate **不依赖** iroh / ferrotunnel / rusqlite，保证错误类型在任意层都能安全使用；
//!    外部库的错误统一通过 [`Error::transport`] / [`Error::store`] 等构造器降级为字符串。
//! 2. 所有跨进程传输的结构体都实现 `serde`，便于在 HTTP / JSON / SQLite 之间复用。

use serde::{Deserialize, Serialize};

/// 跨平台「等待进程该退出了」的关停信号。
///
/// 由 `runtime` feature 启用；见模块文档里关于 Windows 为何不能只监听 Ctrl+C 的说明。
#[cfg(feature = "runtime")]
pub mod signal;

pub mod console;
pub mod control;

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

/// 访问端 ALPN（私有 / P2P 隧道的访问端向节点申请通道）。
///
/// 与数据面 ALPN 分开，是因为两者语义不同：
/// - 数据面：**节点 → 客户端**投递，首部是隧道路由键；
/// - 访问端：**访问端 → 节点**申请，首部是访问密钥（节点据此判定它有权访问哪条隧道）。
/// 混用同一个 ALPN 会让节点无法区分「我是被投递方」还是「我要申请投递」。
pub const ALPN_RSROSS_ACCESS: &[u8] = b"rscross/access/1";

/// 隧道访问密钥的前缀。
///
/// 前缀不只是好看：访问密钥会在浏览器、聊天工具、终端之间来回搬运，
/// 一个可辨认的形状能让人一眼看出「这是 rscross 的访问密钥」而不是别的口令。
pub const ACCESS_KEY_PREFIX: &str = "rsv_";

/// 访问密钥中十六进制部分的位数（即 `rsv_` 之后的部分）。
///
/// 为什么是 16 位：这个密钥要被人从控制台抄到另一台机器的终端里执行，
/// 长度直接决定它会不会被抄错。16 位十六进制 = 64 bit 熵，
/// 配合 [`/api/v1/access/resolve`] 的失败限流，穷举在现实时间内不可行。
///
/// 注意：这里只约束**新签发**的密钥。历史密钥（更长的）依然可用 ——
/// 校验是精确匹配，不做长度过滤，否则升级后旧密钥会突然失效。
pub const ACCESS_KEY_HEX_LEN: usize = 16;

/// 判断访问密钥的**形状**是否正确（不判断它是否真实存在）。
///
/// 之所以要把「形状」与「存在」分开：访问端把用户的输入原样发给节点时，
/// 节点只会回一句「密钥无效」—— 用户无法区分「我抄错了」和「隧道还没生效」。
/// 形状检查在客户端本地就能做，可以立刻把问题指向用户自己。
pub fn access_key_shape_ok(key: &str) -> bool {
    let Some(rest) = key.strip_prefix(ACCESS_KEY_PREFIX) else {
        return false;
    };
    rest.len() == ACCESS_KEY_HEX_LEN && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 默认隧道控制面端口（与 FerroTunnel 默认值保持一致，便于排障）。
pub const DEFAULT_TUNNEL_PORT: u16 = 7835;

/// 默认公网入口端口。
pub const DEFAULT_INGRESS_PORT: u16 = 8081;

/// 内嵌控制台 / 服务端节点自带管理 API 的默认端口。
///
/// 单机自用时服务端进程内嵌控制台，用这个端口。
pub const DEFAULT_CONSOLE_PORT: u16 = 7800;

/// 独立中央控制台（`rscross-console`）的默认端口。
///
/// 刻意与内嵌端口区分：两种形态同时跑在一台机器上（例如先用内嵌自测，
/// 再起一个中央控制台汇聚多节点）时不会互相抢占；从端口号也能一眼
/// 判断浏览器连的是哪一套控制台。
pub const DEFAULT_CENTRAL_CONSOLE_PORT: u16 = 7700;

/// 默认保活间隔（秒）。
pub const DEFAULT_HEARTBEAT_SECS: u64 = 15;

/// 客户端 ID。使用 UUID v4，序列化为字符串。
pub type ClientId = uuid::Uuid;

/// 隧道 ID。
pub type TunnelId = uuid::Uuid;

/// 隧道用途分类。
///
/// 分类不只是标签，它决定**访问入口形态**与**数据面通道**：
///
/// | 类型 | 访问入口 | 访问密钥 | 首选路径 |
/// |---|---|---|---|
/// | `Domain` 域名解析 | 节点 HTTP 入口，按 `Host` 路由 | 无 | FerroTunnel 中继 |
/// | `Port` 端口转发 | 节点监听公网端口 | 无 | Iroh 直连优先，失败回退中继 |
/// | `Private` 私有隧道 | 访问端本地监听，不暴露公网端口 | 必需 | 节点转发 |
/// | `P2p` P2P 隧道 | 访问端本地监听，不暴露公网端口 | 必需 | 点对点直连（可配中继回退） |
///
/// 「私有隧道」与「P2P 隧道」的差别只有一处：P2P 优先打洞直连、直连成功后
/// 不占服务端带宽；私有隧道固定经节点转发。这与 gostc 的语义一致
/// （P2P 隧道「可以实现和私有隧道一样的效果…但是可以 P2P 直连」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelKind {
    /// 域名解析：公网域名 → 内网服务。
    Domain,
    /// 端口转发：公网端口 → 内网服务（默认值，与历史数据兼容）。
    #[default]
    Port,
    /// 私有隧道：访问端凭密钥自建本地入口，流量经节点转发。
    Private,
    /// P2P 隧道：同私有隧道，但优先点对点直连。
    P2p,
}

impl TunnelKind {
    /// 小写标识（同时也是 API / 数据库里的取值）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Port => "port",
            Self::Private => "private",
            Self::P2p => "p2p",
        }
    }

    /// 中文名（日志与前端展示）。
    pub fn label(self) -> &'static str {
        match self {
            Self::Domain => "域名解析",
            Self::Port => "端口转发",
            Self::Private => "私有隧道",
            Self::P2p => "P2P 隧道",
        }
    }

    /// 解析标识；接受若干常见别名，便于手写 API 调用。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "domain" | "dns" | "host" => Some(Self::Domain),
            "port" | "forward" | "port_forward" => Some(Self::Port),
            "private" | "secret" => Some(Self::Private),
            "p2p" | "peer" | "p2p_tunnel" => Some(Self::P2p),
            _ => None,
        }
    }

    /// 全部取值（前端下拉、文档与测试用）。
    pub fn all() -> [Self; 4] {
        [Self::Domain, Self::Port, Self::Private, Self::P2p]
    }

    /// 是否需要访问密钥（私有 / P2P 隧道靠它建立访问端入口）。
    pub fn needs_access_key(self) -> bool {
        matches!(self, Self::Private | Self::P2p)
    }

    /// 是否暴露公网端口（域名解析走 HTTP 入口，不需要端口）。
    pub fn exposes_public_port(self) -> bool {
        matches!(self, Self::Port)
    }

    /// 是否优先走点对点直连。
    pub fn prefers_direct(self) -> bool {
        matches!(self, Self::P2p)
    }

    /// 该类型允许的承载协议。
    ///
    /// P2P 只支持 TCP：UDP 在 QUIC 流上没有天然的连接边界，先把一个语义
    /// 做正确比铺开支持更重要（gostc 的 P2P 隧道同样只支持 TCP）。
    pub fn allows_proto(self, proto: TunnelProto) -> bool {
        match self {
            Self::Domain => proto.is_http_family(),
            Self::Port | Self::Private => proto.needs_remote_port(),
            Self::P2p => matches!(proto, TunnelProto::Tcp),
        }
    }

    /// 允许的协议文案（写进校验错误里，让人一次就知道该填什么）。
    pub fn allowed_protos_label(self) -> &'static str {
        match self {
            Self::Domain => "http / https",
            Self::Port | Self::Private => "tcp / udp",
            Self::P2p => "tcp",
        }
    }

    /// 由协议推导分类（老调用方不带 `kind` 时的兜底）。
    pub fn infer_from_proto(proto: TunnelProto) -> Self {
        if proto.is_http_family() {
            Self::Domain
        } else {
            Self::Port
        }
    }

    /// 数据面是否已接入。
    ///
    /// - 域名解析：FerroTunnel 自带的 HTTP 入口，按 `Host` 路由。
    /// - 端口转发：节点侧自建的 TCP ingress（**UDP 尚未实现**，
    ///   见 [`Self::proto_ready`]）。
    /// - 私有隧道：访问端 [`crate::ALPN_RSROSS_ACCESS`] 握手 + 节点中继。
    /// - P2P 隧道：同上，但优先点对点直连，失败可按配置回退中继。
    ///
    /// 前端据此决定是否显示「待接入」角标。全部接入后它恒为 `true`，
    /// 保留这个函数的价值在于：将来某类数据面被回退时，UI 会自动重新标注，
    /// 不需要再去改前端。
    pub fn data_plane_ready(self) -> bool {
        matches!(self, Self::Domain | Self::Port | Self::Private | Self::P2p)
    }

    /// 「分类 + 协议」这个组合的数据面是否已接入。
    ///
    /// 比 [`Self::data_plane_ready`] 更细一层：端口转发的 UDP 入口还没做，
    /// 所以「配置能保存」不等于「流量能转发」。前端据此把话说清楚，
    /// 不让人建完 UDP 隧道才发现不通。
    pub fn proto_ready(self, proto: TunnelProto) -> bool {
        match (self, proto) {
            (Self::Port, TunnelProto::Udp) => false,
            _ => self.data_plane_ready(),
        }
    }
}

impl std::fmt::Display for TunnelKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
    /// 控制台显式配置的**服务端地址**（形如 `1.2.3.4:7835` 或 `node.example.com）。
    ///
    /// 优先于 `tunnel_server` 的自动推导。之所以需要它：内嵌形态下节点
    /// 自己拿不到公网出口 IP，自动推导会回落到 `127.0.0.1`，客户端照着连就
    /// 连到本机去了 —— 这类故障在日志上完全看不出来。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_addr: Option<String>,
    /// 该节点承载流量时使用的传输协议（`tcp` / `udp` / `quic` / `kcp` / `ws` / `wss`）。
    #[serde(default)]
    pub transport: String,
}

/// 客户端实际用来连接服务端的地址。
///
/// 单独抽出来是因为「自动推导」与「管理员显式配置」两条来源必须收在一个地方，
/// 否则调用方会各自实现一遍优先级，迟早不一致。
impl NodeEndpoint {
    /// 客户端连服务端时用的地址：显式配置优先，其次自动推导。
    pub fn connect_addr(&self) -> &str {
        match self.public_addr.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            Some(v) => v,
            None => self.tunnel_server.as_str(),
        }
    }
}

/// 控制面下发给客户端的隧道定义。
///
/// 刻意不复用数据库实体：客户端**不应**把 `rusqlite` 打进静态二进制。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesiredTunnel {
    /// 隧道 ID。
    pub id: String,
    /// 隧道名（同一客户端内唯一）。
    pub name: String,
    /// 用途分类，决定客户端如何承载这条隧道。
    #[serde(default)]
    pub kind: TunnelKind,
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
    /// 访问密钥（私有 / P2P 隧道）。
    ///
    /// 访问端凭它向节点申请一条到目标内网服务的通道，因此它等价于密码，
    /// 只下发给**归属客户端**（客户端需要它来校验来访者），不进入公开列表。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,
    /// P2P 隧道在直连失败时是否允许回退到服务器中继。
    #[serde(default = "default_true")]
    pub allow_relay: bool,
    /// 是否启用。
    pub enabled: bool,
    /// 限速（Kbps，0 = 不限）。
    pub rate_limit_kbps: u32,
    /// 并发连接上限（0 = 不限）。
    pub conn_limit: u32,
}

/// serde 默认值：允许中继回退（宁可通而不快，也不要直接不通）。
fn default_true() -> bool {
    true
}

/// 节点侧承载的一条隧道。
///
/// 节点不参与业务语义，它只需要知道「这条隧道的流量往哪个客户端投递、
/// 用哪个路由键」，以及（对私有 / P2P）访问端凭密钥查询时能拿到客户端坐标。
/// 隧道定义与下发给客户端的**完全一致**，两侧路由键算法同源 —— 否则会出现
/// 「隧道建立了但流量投递不到」。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeTunnelPlan {
    /// 隧道定义。
    pub tunnel: DesiredTunnel,
    /// 归属客户端 ID。
    pub client_id: String,
    /// 归属客户端名（日志用）。
    pub client_name: String,
    /// 归属客户端的 Iroh 坐标（JSON）。
    ///
    /// 客户端还没上报时为 `None`：此时节点无法主动投递（端口转发会拒绝连接、
    /// 访问端只能走中继），节点会跳过并说明原因，而不是假装隧道可用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_endpoint: Option<String>,
}

/// 客户端上报给控制台的日志条目。
///
/// 控制台侧会把它转成内部 `LogEvent` 落进环形缓冲与数据库，
/// 因此这里的字段名要与控制台的 `LogEvent` 对齐（由 e2e 用真实二进制校验）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientLogEntry {
    /// 级别：`info` / `warn` / `error`。
    pub level: String,
    /// 日志正文。
    pub message: String,
    /// 目标模块；留空则由控制台按客户端名补一个。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// 产生时间（RFC3339）；留空则由控制台补当前时间。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
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
            kind: TunnelKind::Domain,
            proto: TunnelProto::Http,
            local_addr: "127.0.0.1:8080".into(),
            remote_port: None,
            host: Some("a.example.com".into()),
            path_prefix: None,
            access_key: None,
            allow_relay: true,
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
            kind: TunnelKind::P2p,
            proto: TunnelProto::Tcp,
            local_addr: "127.0.0.1:53".into(),
            remote_port: None,
            host: None,
            path_prefix: None,
            access_key: Some("rsv_abc".into()),
            allow_relay: false,
            enabled: true,
            rate_limit_kbps: 100,
            conn_limit: 64,
        };
        let json = serde_json::to_string(&t).expect("ser");
        let back: DesiredTunnel = serde_json::from_str(&json).expect("de");
        assert_eq!(t, back);
    }

    #[test]
    fn tunnel_kind_roundtrips_and_parses_aliases() {
        for k in TunnelKind::all() {
            let json = serde_json::to_string(&k).expect("ser");
            assert_eq!(json, format!("\"{}\"", k.as_str()));
            let back: TunnelKind = serde_json::from_str(&json).expect("de");
            assert_eq!(back, k);
            assert_eq!(TunnelKind::parse(k.as_str()), Some(k));
        }
        // 便于手写 API 调用的别名
        assert_eq!(TunnelKind::parse("DNS"), Some(TunnelKind::Domain));
        assert_eq!(TunnelKind::parse(" port_forward "), Some(TunnelKind::Port));
        assert_eq!(TunnelKind::parse("peer"), Some(TunnelKind::P2p));
        assert_eq!(TunnelKind::parse("nope"), None);
    }

    #[test]
    fn tunnel_kind_default_is_port_for_backward_compat() {
        // 历史数据没有 kind 列，必须兜底成「端口转发」而不是解析失败。
        assert_eq!(TunnelKind::default(), TunnelKind::Port);
        let json = r#"{"id":"1","name":"web","proto":"http","local_addr":"127.0.0.1:80",
            "enabled":true,"rate_limit_kbps":0,"conn_limit":0}"#;
        let t: DesiredTunnel = serde_json::from_str(json).expect("老格式必须能解析");
        assert_eq!(t.kind, TunnelKind::Port);
        assert!(t.allow_relay, "缺字段时默认允许中继回退");
        assert_eq!(t.access_key, None);
    }

    #[test]
    fn tunnel_kind_dictates_allowed_protocols() {
        // 域名解析只能是 HTTP 家族
        assert!(TunnelKind::Domain.allows_proto(TunnelProto::Http));
        assert!(TunnelKind::Domain.allows_proto(TunnelProto::Https));
        assert!(!TunnelKind::Domain.allows_proto(TunnelProto::Tcp));
        // 端口转发 / 私有隧道按端口，不要 Host
        assert!(TunnelKind::Port.allows_proto(TunnelProto::Tcp));
        assert!(TunnelKind::Port.allows_proto(TunnelProto::Udp));
        assert!(!TunnelKind::Port.allows_proto(TunnelProto::Http));
        assert!(TunnelKind::Private.allows_proto(TunnelProto::Udp));
        assert!(!TunnelKind::Private.allows_proto(TunnelProto::Http));
        // P2P 只支持 TCP：UDP 在 QUIC 流上没有连接边界
        assert!(TunnelKind::P2p.allows_proto(TunnelProto::Tcp));
        assert!(!TunnelKind::P2p.allows_proto(TunnelProto::Udp));
    }

    #[test]
    fn only_private_and_p2p_need_access_key() {
        assert!(!TunnelKind::Domain.needs_access_key());
        assert!(!TunnelKind::Port.needs_access_key());
        assert!(TunnelKind::Private.needs_access_key());
        assert!(TunnelKind::P2p.needs_access_key());
        // 只有端口转发会在节点上开公网端口
        assert!(TunnelKind::Port.exposes_public_port());
        assert!(!TunnelKind::Domain.exposes_public_port());
        assert!(!TunnelKind::Private.exposes_public_port());
        assert!(!TunnelKind::P2p.exposes_public_port());
        // 只有 P2P 优先直连
        assert!(TunnelKind::P2p.prefers_direct());
        assert!(!TunnelKind::Private.prefers_direct());
    }

    #[test]
    fn every_tunnel_kind_has_a_data_plane() {
        // 四类都已接入：域名解析走 FerroTunnel 的 HTTP 入口、端口转发走节点侧自建
        // TCP ingress、私有 / P2P 走访问端 + 节点中继（P2P 优先直连）。
        // 这个断言的用途是：将来某类数据面被回退时，这里会立刻变红。
        for kind in TunnelKind::all() {
            assert!(kind.data_plane_ready(), "{kind} 的数据面应为已接入");
        }
    }

    #[test]
    fn udp_port_forwarding_is_declared_unavailable() {
        // 端口转发的入口是自己写的 TCP listener，UDP 还没做。
        // 「能保存」与「能转发」必须区分开，否则用户建完 UDP 隧道只会一脸茫然。
        assert!(!TunnelKind::Port.proto_ready(TunnelProto::Udp));
        assert!(TunnelKind::Port.proto_ready(TunnelProto::Tcp));
        // 其余组合跟随分类状态
        assert!(TunnelKind::Domain.proto_ready(TunnelProto::Http));
        assert!(TunnelKind::Private.proto_ready(TunnelProto::Tcp));
        assert!(TunnelKind::P2p.proto_ready(TunnelProto::Tcp));
    }
}
