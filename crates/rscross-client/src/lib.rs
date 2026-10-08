//! `rscross-client`：内网节点的常驻进程。
//!
//! 职责（与需求 1 的角色划分对应）：
//! 1. **注册**：用控制台签发的一次性令牌换取长期 `agent_token` + FerroTunnel 握手 token。
//! 2. **反向隧道**：为每条下发的隧道起一个 FerroTunnel `Client`，穿透 NAT 连到服务端。
//! 3. **P2P 服务**：绑定 Iroh 节点并在 `ALPN_DATA` 上接受直连流，转发到本地服务。
//! 4. **心跳**：周期上报运行时信息（含 Iroh `EndpointId` / `EndpointAddr`）并拉取期望配置。
//!
//! 崩溃恢复：控制面/中继/直连三类外部依赖全部按「本地退避重试 + 不退出进程」处理；
//! 隧道的增删改由心跳循环里的 `TunnelManager::reconcile` 收敛。

pub mod access;
pub mod agent;
pub mod api;
pub mod identity;
pub mod logsink;

pub use access::AccessArgs;
pub use agent::{run, run_with_args, Args, Command};
pub use identity::{Identity, StateDir};
