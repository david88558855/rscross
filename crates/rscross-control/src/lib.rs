//! `rscross-control`：**控制面**。
//!
//! 控制面同时服务于两种部署形态，代码只有一份：
//!
//! | 形态 | 承载进程 | 场景 |
//! |---|---|---|
//! | **独立控制台** | `rscross-console` 二进制 | 多节点汇聚：N 台公网服务端 + M 个内网客户端都注册到这里 |
//! | **内嵌控制台** | `rscross-server`（`control_mode = embedded`） | 单机自用：一台机器同时跑数据面与控制台 |
//!
//! 三种身份的心跳各自独立：
//! - **服务端节点** 用 `X-Rscross-Node`（`rsn_` token）
//! - **内网客户端** 用 `X-Rscross-Agent`（`rsa_` token）
//! - **管理员** 用会话 token（Bearer 或 Cookie）
//!
//! 重要边界：控制面**不依赖 iroh / ferrotunnel**。它只负责编排与记录，
//! 数据面完全建立在节点与客户端之间 —— 这让独立控制台二进制保持轻量。

pub mod api;
pub mod bootstrap;
pub mod console;
pub mod error;
pub mod logbus;
pub mod plane;
pub mod state;

#[cfg(feature = "http-client")]
pub mod node_client;

pub use bootstrap::{
    build_plane, console_default_config, ensure_initial_admin, init_logging, run_console,
    run_console_with, wait_for_signal, ConsoleArgs,
};
pub use api::nodes::NodeTunnelPlan;
pub use error::ApiError;
pub use logbus::{LogBus, LogEvent};
pub use plane::ControlPlane;
pub use state::AppState;
