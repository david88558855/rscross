//! 控制台 ↔ 客户端 / 服务端节点的 **WebSocket 控制面协议**。
//!
//! ## 为什么把主协议从 HTTP 改成 WebSocket
//!
//! 原来的控制面是「客户端每 15 秒发一次 HTTPS 请求，控制台在响应里带下发」。
//! 它有两个硬伤：
//!
//! 1. **控制台无法主动推送**。改一条隧道配置，最坏要等一个心跳周期才生效；
//!    控制台页面上也看不到「已下发 / 待下发」，只能干等。
//! 2. **每次心跳都要付一次完整 TLS 握手 + HTTP 头的开销**，
//!    而心跳体通常只有几十字节。
//!
//! 改成常连的 WS 之后，配置下发变成一次主动 push，实时生效；心跳退化为一条轻帧。
//!
//! ## 兼容性
//!
//! REST 路由**保留不动**：控制台前端仍走 HTTP，老版本客户端也还能注册。
//!
//! ## 帧格式
//!
//! 一条连接上可以并发多个请求，靠 `id` 配对：
//!
//! - [`ControlRequest`]：客户端 → 控制台（带 `id`）
//! - [`ControlResponse`]：控制台 → 客户端（带回同一个 `id`）
//! - [`ControlPush`]：控制台 → 客户端的主动下发（无 `id`，不需要响应）
//!
//! 握手走的就是 `Hello` / `Welcome` 这一对 Request / Response，
//! 只是不带业务载荷 —— 少一处特例就少一处漂移。

use serde::{Deserialize, Serialize};

use crate::{
    ClientLogEntry, ClientRuntime, DesiredTunnel, NodeEndpoint, NodeRuntime, NodeTunnelPlan,
};

/// 重导出，便于调用方只引一个模块。
pub use crate::console::{ConsolePlan, ConsoleScheme};

/// 控制面协议版本。本端只与同版本通信，不一致直接报错。
pub const CONTROL_VERSION: u32 = 1;

/// 连接建立超时（秒）。
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

/// 等待单次响应的超时（秒）。
///
/// 心跳一次可能携带数百条日志，所以给得比普通请求宽一些。
pub const REQUEST_TIMEOUT_SECS: u64 = 30;

/// 心跳间隔下限（秒）。控制台下发更小的值时按此执行，避免一个笔误打垮控制台。
pub const MIN_HEARTBEAT_SECS: u64 = 5;

/// 心跳间隔上限（秒）。超过则按此值，避免控制台因收不到心跳而误判离线。
pub const MAX_HEARTBEAT_SECS: u64 = 300;

/// 连接角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// 内网客户端。
    Agent,
    /// 服务端节点（数据面）。
    Node,
}

impl Role {
    /// 字符串形式。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Node => "node",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// 客户端 → 控制台。
///
/// 每条请求都带 `id`，控制台把同一个 `id` 带回；客户端据此把响应分发给等待者。
/// 因此一条连接上可以并发多个请求（比如心跳与日志上报交错），
/// 而不需要为每种交互各开一条连接。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlRequest {
    /// 连接建立后的第一条消息：版本协商。
    Hello {
        /// 请求序号。
        id: u64,
        /// 本端支持的协议版本。
        version: u32,
    },

    /// 客户端注册。
    Enroll {
        /// 请求序号。
        id: u64,
        /// 一次性接入令牌；首次注册后客户端改用 `agent_token`。
        token: Option<String>,
        /// 期望的客户端名；留空则由控制台生成。
        name: Option<String>,
        /// 运行时信息。
        runtime: ClientRuntime,
    },

    /// 客户端心跳。
    Heartbeat {
        /// 请求序号。
        id: u64,
        /// agent token。
        token: String,
        /// 运行时信息。
        runtime: ClientRuntime,
    },

    /// 客户端上报日志。
    PushLogs {
        /// 请求序号。
        id: u64,
        /// agent token。
        token: String,
        /// 日志条目。
        entries: Vec<ClientLogEntry>,
    },

    /// 服务端节点注册。
    NodeEnroll {
        /// 请求序号。
        id: u64,
        /// 一次性接入令牌。
        token: Option<String>,
        /// 期望的节点名。
        name: Option<String>,
        /// 运行时信息。
        runtime: NodeRuntime,
    },

    /// 服务端节点心跳。
    NodeHeartbeat {
        /// 请求序号。
        id: u64,
        /// node token。
        token: String,
        /// 运行时信息。
        runtime: NodeRuntime,
    },

    /// 服务端节点查询自身记录。
    NodeSelf {
        /// 请求序号。
        id: u64,
        /// node token。
        token: String,
    },
}

impl ControlRequest {
    /// 取出请求 id（响应要用它配对）。
    pub fn id(&self) -> u64 {
        match self {
            Self::Hello { id, .. }
            | Self::Enroll { id, .. }
            | Self::Heartbeat { id, .. }
            | Self::PushLogs { id, .. }
            | Self::NodeEnroll { id, .. }
            | Self::NodeHeartbeat { id, .. }
            | Self::NodeSelf { id, .. } => *id,
        }
    }
}

/// 控制台 → 客户端 / 服务端节点：对请求的响应。
///
/// `id` 必须与对应请求的 `id` 一致 —— 客户端靠它把响应分发给等待者。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    /// 版本协商成功。
    Welcome {
        /// 请求序号。
        id: u64,
        /// 控制台采用的协议版本。
        version: u32,
    },
    /// 客户端注册成功。
    Enrolled {
        /// 请求序号。
        id: u64,
        /// 客户端 ID。
        client_id: String,
        /// 客户端名。
        name: String,
        /// agent token（之后每次心跳都要带上）。
        agent_token: String,
        /// 心跳间隔（秒）。
        heartbeat_secs: u64,
        /// 控制台对外地址。
        public_url: Option<String>,
        /// 归属节点（数据面坐标）。
        node: NodeEndpoint,
        /// 初始隧道列表。
        tunnels: Vec<DesiredTunnel>,
    },
    /// 客户端心跳应答。
    Heartbeat {
        /// 请求序号。
        id: u64,
        /// 下一次心跳间隔（秒），已夹到合法区间。
        heartbeat_secs: u64,
        /// 控制台当前时间（RFC3339）。
        server_time: String,
        /// 控制台观测到的出口 IP。
        public_ip: Option<String>,
        /// 归属节点；`None` 表示已被解绑或节点被删除，客户端应停掉隧道。
        node: Option<NodeEndpoint>,
        /// 期望的隧道配置（声明式收敛的依据）。
        tunnels: Vec<DesiredTunnel>,
    },
    /// 隧道列表应答（客户端）。
    Tunnels {
        /// 请求序号。
        id: u64,
        /// 隧道列表。
        tunnels: Vec<DesiredTunnel>,
    },
    /// 服务端节点注册成功。
    NodeEnrolled {
        /// 请求序号。
        id: u64,
        /// 节点 ID。
        node_id: String,
        /// 节点名。
        name: String,
        /// node token（之后每次心跳都要带上）。
        node_token: String,
        /// 当前生效的 FerroTunnel 握手 token（节点据此感知轮换）。
        tunnel_token: String,
        /// 心跳间隔（秒）。
        heartbeat_secs: u64,
        /// 控制台对外地址。
        public_url: Option<String>,
        /// 初始隧道编排。
        tunnels: Vec<NodeTunnelPlan>,
    },
    /// 服务端节点心跳应答。
    NodeHeartbeat {
        /// 请求序号。
        id: u64,
        /// 下一次心跳间隔（秒），已夹到合法区间。
        heartbeat_secs: u64,
        /// 控制台当前时间（RFC3339）。
        server_time: String,
        /// 控制台观测到的出口 IP。
        public_ip: Option<String>,
        /// 当前生效的 FerroTunnel 握手 token（便于节点感知轮换）。
        tunnel_token: String,
        /// 本节点要承载的隧道编排。
        tunnels: Vec<NodeTunnelPlan>,
    },
    /// 日志上报应答。
    LogsAccepted {
        /// 请求序号。
        id: u64,
        /// 实际入库的条数（上限 500，超出部分被丢弃）。
        accepted: usize,
    },
    /// 成功应答（无额外载荷时用这个）。
    Ok {
        /// 请求序号。
        id: u64,
    },
    /// 失败。
    ///
    /// `id` 为 0 表示这条错误不对应任何请求（连接级问题，比如版本协商失败）。
    Error {
        /// 请求序号。
        id: u64,
        /// 机器可读的错误码。
        code: String,
        /// 人类可读的说明。
        message: String,
    },
    /// 服务端节点自身记录。
    ///
    /// 用 `serde_json::Value` 而不是具体的 `NodeRecord`：`NodeRecord` 属于
    /// store crate（含仅内部可见的 `node_token_hash`），不能出现在传输协议里 ——
    /// 那会让协议依赖持久化层，schema 一改协议就跟着变。
    NodeSelf {
        /// 请求序号。
        id: u64,
        /// 节点记录（已剔除内部字段）。
        node: serde_json::Value,
    },
}

impl ControlResponse {
    /// 是否成功。
    pub fn is_ok(&self) -> bool {
        !matches!(self, Self::Error { .. })
    }

    /// 成功应答。
    pub fn ok(id: u64) -> Self {
        Self::Ok { id }
    }

    /// 失败应答。
    pub fn error(id: u64, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            id,
            code: code.into(),
            message: message.into(),
        }
    }
}

/// 控制台**主动**下发的消息（不对应任何请求）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlPush {
    /// 控制台侧的配置已变更。
    ConfigUpdated {
        /// 期望的隧道配置（当前归属该客户端的全部启用隧道）。
        tunnels: Vec<DesiredTunnel>,
    },
}
