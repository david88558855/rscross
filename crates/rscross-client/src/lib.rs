//! rscross-client —— rscross 节点与客户端运行时
//!
//! 通过 WebSocket RPC 连接服务端，接收配置指令并驱动 穿透内核。

pub mod config;
pub mod events;
pub mod node;
pub mod registry;
pub mod state;
pub mod visitor;

use std::sync::Arc;

use anyhow::Result;

use rscross_common::rpc::RpcClient;

use crate::node::Node;
use crate::registry::ServiceRegistry;

/// 全局运行状态
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::ClientConfig>,
    pub key: String,
    /// 服务端 WebSocket 地址
    pub ws_url: String,
    /// 服务端 HTTP 地址
    pub http_url: String,
    /// 隧道服务集合
    pub services: Arc<ServiceRegistry>,
    /// 全局状态标记
    pub state: Arc<state::StateStore>,
}

/// 依据地址与 TLS 设置生成服务端 URL
pub fn build_urls(addr: &str, tls: bool) -> (String, String) {
    let scheme = if tls { "https" } else { "http" };
    let ws_scheme = if tls { "wss" } else { "ws" };
    let addr = addr.trim();
    // 允许用户直接填完整 URL
    if addr.starts_with("http://") || addr.starts_with("https://") {
        let rest = addr
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let (s, w) = if addr.starts_with("https://") {
            ("https", "wss")
        } else {
            ("http", "ws")
        };
        return (format!("{s}://{rest}"), format!("{w}://{rest}"));
    }
    (
        format!("{scheme}://{addr}"),
        format!("{ws_scheme}://{addr}"),
    )
}

/// 启动客户端
pub async fn run() -> Result<()> {
    let cfg = config::ClientConfig::load()?;
    rscross_common::logger::init(None, &cfg.log_level, true)?;

    if cfg.key.is_empty() {
        anyhow::bail!("请通过 -key 指定连接密钥");
    }
    if cfg.addr.is_empty() {
        anyhow::bail!("请通过 -addr 指定服务端地址");
    }

    let (http_url, ws_url) = build_urls(&cfg.addr, cfg.tls);

    tracing::info!(
        "rscross-client v{} 启动中，模式 {}，服务端 {}",
        rscross_common::VERSION,
        if cfg.node { "节点" } else { "客户端" },
        http_url
    );

    let key = cfg.key.clone();
    let state = AppState {
        config: Arc::new(cfg),
        key: key.clone(),
        ws_url: ws_url.clone(),
        http_url,
        services: Arc::new(ServiceRegistry::new()),
        state: Arc::new(state::StateStore::new()),
    };

    // 节点模式走 Node 运行时，客户端模式走 Client 运行时
    let node = Node::new(state.clone());
    node.run().await
}

/// 建立 RPC 连接并启动分发
pub async fn connect(state: &AppState) -> Result<(RpcClient, rscross_common::rpc::DispatchHandle)> {
    let url = format!("{}/rpc/ws", state.ws_url);
    let client = RpcClient::connect(&url, &state.key)
        .await
        .map_err(|e| anyhow::anyhow!("连接服务端失败: {e}"))?;

    tracing::info!("已连接服务端: {url}");

    // 克隆一份给事件处理，分发循环独立运行
    let mut dispatch_client = RpcClient::connect(&url, &state.key)
        .await
        .map_err(|e| anyhow::anyhow!("建立推送通道失败: {e}"))?;
    events::register_handlers(&mut dispatch_client, state);

    let handle = dispatch_client.start_dispatch();
    Ok((client, handle))
}
