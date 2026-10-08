//! 节点与控制台之间的链路。
//!
//! 两种形态的差别只在这里，上层（[`crate::node`]）完全无感：
//!
//! | 形态 | 实现 | 走网络吗 |
//! |---|---|---|
//! | `embedded`（单机） | 直接调用进程内的 [`ControlPlane`] | ❌ 纯函数调用 |
//! | `managed`（多节点） | [`NodeApiClient`] 走 HTTP | ✅ 连中央控制台 |
//!
//! 「不走网络」不只是省一跳：内嵌模式下没有 `enroll_token` 的概念，
//! 也就不存在「自己给自己发一个 token 再拿去鉴权」这种绕圈设计。

use rscross_common::{Error, NodeRuntime, Result};
use rscross_control::ControlPlane;

use rscross_control::node_client::NodeApiClient;

use crate::identity::NodeIdentity;

/// 一次心跳的结果。
#[derive(Debug, Clone)]
pub struct HeartbeatOutcome {
    /// 下一次心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 控制台当前生效的 FerroTunnel 握手 token（可能已被轮换）。
    pub tunnel_token: String,
    /// 控制台观测到的出口 IP（仅 managed 模式有值）。
    pub public_ip: Option<String>,
}

/// 控制台链路。
pub enum ControlLink {
    /// 单机自用：控制台就在本进程里。
    Embedded {
        /// 控制面句柄。
        plane: ControlPlane,
    },
    /// 多节点汇聚：控制台是远端独立进程。
    Http {
        /// 控制面 HTTP 客户端。
        client: NodeApiClient,
    },
}

impl std::fmt::Debug for ControlLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.describe())
    }
}

impl ControlLink {
    /// 人类可读的形态描述（写进日志与心跳响应，便于排障）。
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Embedded { .. } => "embedded-console",
                    Self::Http { .. } => "remote-console",
        }
    }

    /// 内嵌形态的构造。
    pub fn embedded(plane: ControlPlane) -> Self {
        Self::Embedded { plane }
    }

    /// 远端形态的构造。
    pub fn remote(console_url: &str) -> Result<Self> {
        Ok(Self::Http {
            client: NodeApiClient::new(console_url)?,
        })
    }

    /// 注册（或在内嵌形态下「确保本机节点存在」），返回可持久化的身份。
    ///
    /// - `enroll_token`：managed 形态必填（控制台在「服务端节点」页签发）；
    ///   内嵌形态忽略它。
    /// - `public_host`：仅内嵌形态使用 —— 远端控制台能观测到节点的出口 IP，
    ///   而内嵌进程只看到 127.0.0.1。
    pub async fn enroll(
        &self,
        enroll_token: Option<&str>,
        name: &str,
        public_host: Option<String>,
        runtime: &NodeRuntime,
    ) -> Result<NodeIdentity> {
        match self {
            Self::Embedded { plane } => {
                let (record, token) = plane.ensure_node(name, None, public_host).await?;
                tracing::info!(
                    node = %record.name,
                    id = %record.id,
                    "内嵌控制台已就绪，本进程以节点身份注册"
                );
                Ok(NodeIdentity {
                    node_id: Some(record.id),
                    node_token: Some(token),
                    name: Some(record.name),
                    tunnel_token: Some(record.tunnel_token),
                    heartbeat_secs: None,
                })
            }
                    Self::Http { client } => {
                let token = enroll_token
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
                        Error::config(
                            "managed 模式需要 node.enroll_token（在中央控制台的「服务端节点」页签发）",
                        )
                    })?;

                let response = client.enroll(token, name, runtime).await?;
                tracing::info!(
                    node = %response.name,
                    id = %response.node_id,
                    console = %client.base(),
                    "已注册到中央控制台"
                );
                Ok(NodeIdentity {
                    node_id: Some(response.node_id),
                    node_token: Some(token.to_string()),
                    name: Some(response.name),
                    tunnel_token: Some(response.tunnel_token),
                    heartbeat_secs: Some(response.heartbeat_secs),
                })
            }
        }
    }

    /// 发送一次心跳。
    pub async fn heartbeat(
        &self,
        identity: &NodeIdentity,
        runtime: &NodeRuntime,
    ) -> Result<HeartbeatOutcome> {
        match self {
            Self::Embedded { plane } => {
                let node_id = identity
                    .node_id
                    .as_deref()
                    .ok_or_else(|| Error::internal("内嵌模式下缺少 node_id"))?;
                let response = plane.heartbeat(node_id, runtime, None).await?;
                Ok(HeartbeatOutcome {
                    heartbeat_secs: response.heartbeat_secs,
                    tunnel_token: response.tunnel_token,
                    public_ip: response.public_ip,
                })
            }
                    Self::Http { client } => {
                let token = identity
                    .node_token
                    .as_deref()
                    .ok_or_else(|| Error::internal("缺少 node token"))?;
                let response = client.heartbeat(token, runtime).await?;
                Ok(HeartbeatOutcome {
                    heartbeat_secs: response.heartbeat_secs,
                    tunnel_token: response.tunnel_token,
                    public_ip: response.public_ip,
                })
            }
        }
    }
}
