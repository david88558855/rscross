//! rscross-tunnel —— rscross 自研内网穿透内核
//!
//! 完全独立实现的穿透协议栈，不依赖任何外部项目，
//! 与 gostc / frp 的协议互不兼容：
//! - [`msg`]：控制流消息（登录、代理注册、工作连接请求）
//! - [`config`]：配置模型（节点侧 / 客户端侧 / 各类隧道）
//! - [`server`]：节点侧服务（部署在公网节点，运行 HubServer）
//! - [`client`]：客户端侧代理（部署在内网，运行 AgentService）
//! - [`transport`]：数据传输通道（加密、压缩、限速）
//! - [`vhost`]：域名分发
//! - [`nathole`]：P2P 打洞

pub mod client;
pub mod config;
pub mod msg;
pub mod nathole;
pub mod proxy;
pub mod server;
pub mod transport;
pub mod vhost;

pub use client::{AgentService, ServiceRegistry};
pub use config::{ClientConfig, ProxyBaseConfig, ServerConfig};
pub use msg::*;
pub use proxy::{ProxyEntry, ProxyRegistry};
pub use server::HubServer;

/// 协议版本，随实现演进递增
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// 隧道类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ProxyType {
    /// TCP 端口转发
    Tcp,
    /// UDP 端口转发
    Udp,
    /// HTTP 域名代理
    Http,
    /// HTTPS 域名代理
    Https,
    /// 私有隧道（STCP）
    Stcp,
    /// 私有隧道（SUDP）
    Sudp,
    /// P2P 打洞（XTCP）
    Xtcp,
}

impl ProxyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyType::Tcp => "tcp",
            ProxyType::Udp => "udp",
            ProxyType::Http => "http",
            ProxyType::Https => "https",
            ProxyType::Stcp => "stcp",
            ProxyType::Sudp => "sudp",
            ProxyType::Xtcp => "xtcp",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(ProxyType::Tcp),
            "udp" => Some(ProxyType::Udp),
            "http" => Some(ProxyType::Http),
            "https" => Some(ProxyType::Https),
            "stcp" => Some(ProxyType::Stcp),
            "sudp" => Some(ProxyType::Sudp),
            "xtcp" => Some(ProxyType::Xtcp),
            _ => None,
        }
    }

    /// 是否为域名型代理（走 vhost 分发）
    pub fn is_vhost(&self) -> bool {
        matches!(self, ProxyType::Http | ProxyType::Https)
    }

    /// 是否为 UDP 型代理
    pub fn is_udp(&self) -> bool {
        matches!(self, ProxyType::Udp | ProxyType::Sudp)
    }
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
