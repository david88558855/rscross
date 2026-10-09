//! 持久化实体（与 SQLite 表一一对应，同时作为控制面 API 的响应结构）。

use serde::{Deserialize, Serialize};

/// 用户记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    /// 用户 ID。
    pub id: String,
    /// 登录名。
    pub username: String,
    /// 密码哈希（`salt:hash`，十六进制）。**不对外序列化**。
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// 角色：`admin` / `viewer`。
    pub role: String,
    /// 是否禁用。
    pub disabled: bool,
    /// 创建时间。
    pub created_at: String,
    /// 最近登录时间。
    pub last_login_at: Option<String>,
}

/// 会话记录（只存 token 的 SHA-256 摘要）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    /// token 摘要。
    pub token_hash: String,
    /// 所属用户。
    pub user_id: String,
    /// 创建时间。
    pub created_at: String,
    /// 过期时间。
    pub expires_at: String,
    /// User-Agent。
    pub user_agent: Option<String>,
}

/// 服务端节点记录（控制台管理的「节点」）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    /// 节点 ID。
    pub id: String,
    /// 展示名（唯一）。
    pub name: String,
    /// 状态：`pending` / `online` / `offline` / `disabled`。
    pub status: String,
    /// node token 摘要。**不对外序列化**。
    #[serde(skip_serializing)]
    pub node_token_hash: String,
    /// FerroTunnel 握手 token。节点与归属该节点的客户端都要用它，
    /// 因此必须以可读回的形式保存（仅管理员接口可见）。
    pub tunnel_token: String,
    /// 对外主机名（管理员可覆盖）。
    pub public_host: Option<String>,
    /// 控制台显式配置的**服务端地址**：客户端据此连接服务端。
    ///
    /// 优先于自动推导出的 `tunnel_server`。需要它的原因：内嵌形态下节点
    /// 拿不到自己的公网出口 IP，自动推导会回落到 `127.0.0.1`，
    /// 客户端照着连就连到本机去了 —— 日志上完全看不出来。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_addr: Option<String>,
    /// 对外可见的介绍（新建自建节点时填写，纯展示）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 该节点承载流量时使用的传输协议（`tcp` / `udp` / `quic` / `kcp` / `ws` / `wss`）。
    pub transport: String,
    /// P2P 直连失败时是否允许回退到该节点中继（默认开启）。
    pub allow_relay: bool,
    /// 反向隧道控制面监听端口（节点上报）。
    pub tunnel_port: Option<i64>,
    /// 公网入口监听端口（节点上报）。
    pub ingress_port: Option<i64>,
    /// 节点进程版本。
    pub version: Option<String>,
    /// 操作系统。
    pub os: Option<String>,
    /// CPU 架构。
    pub arch: Option<String>,
    /// Iroh EndpointId。
    pub endpoint_id: Option<String>,
    /// Iroh EndpointAddr（JSON）。
    pub endpoint_addr: Option<String>,
    /// 控制台观测到的出口 IP。
    pub public_ip: Option<String>,
    /// 最近心跳。
    pub last_seen_at: Option<String>,
    /// 最近一次错误。
    pub last_error: Option<String>,
    /// 创建时间。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
    /// 是否禁用。
    pub disabled: bool,
}

impl NodeRecord {
    /// 客户端接入该节点时使用的地址：`tunnel_server`。
    ///
    /// 优先级：管理员配置的 `public_host` > 控制台观测到的 `public_ip` > `127.0.0.1`。
    /// 端口优先用节点上报值，其次回落到默认端口。
    pub fn tunnel_server(&self) -> String {
        let host = self
            .public_host
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .or(self.public_ip.as_deref())
            .unwrap_or("127.0.0.1");
        let port = self
            .tunnel_port
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(rscross_common::DEFAULT_TUNNEL_PORT);
        format!("{host}:{port}")
    }
}

/// 客户端（内网节点）记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    /// 客户端 ID。
    pub id: String,
    /// 归属的服务端节点。
    pub node_id: Option<String>,
    /// 展示名（唯一）。
    pub name: String,
    /// 在线状态。
    pub status: String,
    /// agent token 摘要。**不对外序列化**。
    #[serde(skip_serializing)]
    pub agent_token_hash: String,
    /// 客户端版本。
    pub version: Option<String>,
    /// 操作系统。
    pub os: Option<String>,
    /// CPU 架构。
    pub arch: Option<String>,
    /// Iroh EndpointId。
    pub endpoint_id: Option<String>,
    /// Iroh EndpointAddr（JSON）。
    pub endpoint_addr: Option<String>,
    /// 出口公网 IP。
    pub public_ip: Option<String>,
    /// 最近心跳。
    pub last_seen_at: Option<String>,
    /// 最近一次错误。
    pub last_error: Option<String>,
    /// 创建时间。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
    /// 是否禁用。
    pub disabled: bool,
}

/// 接入令牌记录（客户端用；可绑定到某个节点）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollTokenRecord {
    /// token 摘要。
    pub token_hash: String,
    /// 绑定的服务端节点。
    pub node_id: Option<String>,
    /// 绑定的客户端名（可空，表示由客户端自报）。
    pub client_name: Option<String>,
    /// 签发人。
    pub created_by: Option<String>,
    /// 创建时间。
    pub created_at: String,
    /// 过期时间。
    pub expires_at: String,
    /// 使用时间。
    pub used_at: Option<String>,
    /// 使用该令牌注册出的客户端 ID。
    pub used_client_id: Option<String>,
}

/// 隧道记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRecord {
    /// 隧道 ID。
    pub id: String,
    /// 归属客户端。
    pub client_id: String,
    /// 隧道名（同一客户端内唯一）。
    pub name: String,
    /// 用途分类（`domain` / `port` / `private` / `p2p`）。
    pub kind: String,
    /// 协议。
    pub proto: String,
    /// 本地目标地址。
    pub local_addr: String,
    /// 公网端口。
    pub remote_port: Option<i64>,
    /// HTTP Host。
    pub host: Option<String>,
    /// HTTP 路径前缀。
    pub path_prefix: Option<String>,
    /// 访问密钥（私有 / P2P 隧道）。等价于密码，只在管理端展示。
    pub access_key: Option<String>,
    /// P2P 隧道在直连失败时是否允许回退到服务器中继。
    pub allow_relay: bool,
    /// 是否启用。
    pub enabled: bool,
    /// 限速（Kbps，0 = 不限）。
    pub rate_limit_kbps: i64,
    /// 连接数上限（0 = 不限）。
    pub conn_limit: i64,
    /// 创建时间。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
}

/// 流量采样点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPoint {
    /// 时间戳。
    pub ts: String,
    /// 隧道 ID。
    pub tunnel_id: String,
    /// 客户端 ID。
    pub client_id: String,
    /// 归属节点 ID。
    pub node_id: Option<String>,
    /// 路径类型（`p2p` / `iroh-relay` / `ferry-relay`）。
    pub path: String,
    /// 入向字节。
    pub bytes_in: i64,
    /// 出向字节。
    pub bytes_out: i64,
    /// 连接数。
    pub conns: i64,
}

/// 日志记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// 自增 ID（内存环形缓冲里为序号）。
    pub id: i64,
    /// 时间戳。
    pub ts: String,
    /// 级别。
    pub level: String,
    /// 目标模块。
    pub target: Option<String>,
    /// 正文。
    pub message: String,
    /// 关联客户端。
    pub client_id: Option<String>,
    /// 关联隧道。
    pub tunnel_id: Option<String>,
}

/// 审计记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// 自增 ID。
    pub id: i64,
    /// 时间戳。
    pub ts: String,
    /// 操作人。
    pub user_id: Option<String>,
    /// 动作。
    pub action: String,
    /// 目标对象。
    pub target: Option<String>,
    /// 详情。
    pub detail: Option<String>,
    /// 来源 IP。
    pub ip: Option<String>,
}

/// 概览统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverviewStats {
    /// 服务端节点总数。
    pub nodes_total: i64,
    /// 在线服务端节点数。
    pub nodes_online: i64,
    /// 客户端总数。
    pub clients_total: i64,
    /// 在线客户端数。
    pub clients_online: i64,
    /// 隧道总数。
    pub tunnels_total: i64,
    /// 已启用隧道数。
    pub tunnels_enabled: i64,
    /// 24 小时入向字节。
    pub bytes_in_24h: i64,
    /// 24 小时出向字节。
    pub bytes_out_24h: i64,
    /// 24 小时连接数。
    pub conns_24h: i64,
    /// 24 小时 P2P 直连字节。
    pub bytes_direct_24h: i64,
    /// 24 小时中继字节。
    pub bytes_relayed_24h: i64,
}
