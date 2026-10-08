//! `rscross-server`：**服务端节点**（数据面）。
//!
//! 无论哪种部署形态，本进程都以「节点」身份工作：向控制台注册 → 心跳 → 承载反向隧道。
//! 区别只在于控制台跑在哪里：
//!
//! - `--embedded`（默认）：**单机自用**。本进程内嵌一个完整的控制面（含 Web 控制台），
//!   内网客户端直接连这台机器的控制台地址即可。此时进程内同时有控制面与数据面。
//! - `--managed`：**多节点汇聚**。加入远端 `rscross-console`，由它统一下发配置。
//!
//! 进程内任务：
//! 1. 控制台 HTTP（仅 embedded）/ 控制台 HTTP 客户端（仅 managed）
//! 2. FerroTunnel 中继服务端（反向隧道控制面 + 公网入口）
//! 3. Iroh 节点 + `ALPN_CONTROL` 处理器（让客户端能真正建立 P2P 直连并被判真）
//! 4. 心跳循环（上报运行时信息、感知 tunnel token 轮换）
//! 5. 信号监听 → `CancellationToken` → 各任务收敛

pub mod identity;
pub mod link;
pub mod node;

pub use identity::{NodeIdentity, NodeStateDir};
pub use link::{ControlLink, HeartbeatOutcome};
pub use node::{run_node, NodeArgs};
