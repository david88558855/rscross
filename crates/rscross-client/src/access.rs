//! 访问端：凭访问密钥在**访问者一侧**建立到内网服务的入口。
//!
//! 与常驻客户端的区别：
//! - 常驻客户端跑在**内网**一侧，把服务暴露到节点上（域名解析 / 端口转发）；
//! - 访问端跑在**访问者**一侧，暴露的是本机监听地址 ——
//!   访问 `127.0.0.1:8080` 就等于访问内网服务，而内网侧不需要对外开放任何端口。
//!
//! 两条路径（由节点在握手应答里定夺）：
//! - `relay`：私有隧道，流量经节点转发；
//! - `p2p`：P2P 隧道，先尝试与客户端点对点直连；直连失败且隧道允许回退时，
//!   在同一条与节点的 QUIC 连接上再开一条流走中继，**不需要重新握手**。

use std::net::SocketAddr;
use std::time::Duration;

use rscross_common::{Error, Result};
use rscross_transport::{bridge_tcp_to_stream, decode_addr, AccessSession, P2pNode, P2pOptions};
use tokio::net::{TcpListener, TcpStream};

use crate::api::ApiClient;

/// 访问端命令行参数。
#[derive(Debug, clap::Args)]
pub struct AccessArgs {
    /// 控制台地址，例如 `http://1.2.3.4:7700`。
    #[arg(long, env = "RSROSS_CONSOLE")]
    pub console: String,
    /// 隧道访问密钥（在控制台「隧道管理」里复制，`rsv_` 前缀）。
    #[arg(long, env = "RSROSS_ACCESS_KEY")]
    pub key: String,
    /// 本地监听地址：访问它即访问内网服务。
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: String,
    /// 直连客户端的最长等待时间（秒）；超时后按隧道的回退策略处理。
    #[arg(long, default_value = "8")]
    pub direct_timeout_secs: u64,
    /// 日志级别。
    #[arg(long, env = "RSROSS_LOG")]
    pub log_level: Option<String>,
}

/// 运行访问端（长驻，直到 Ctrl+C 或进程被杀）。
pub async fn run(args: AccessArgs) -> Result<()> {
    init_tracing(&args);

    let listen: SocketAddr = args.listen.parse().map_err(|e| {
        Error::config(format!("--listen 非法（应形如 127.0.0.1:8080）: {e}"))
    })?;

    // ---- 1. 凭访问密钥换取节点坐标 ----
    //
    // 访问端不知道隧道挂在哪台节点上，而把节点地址编码进密钥会让密钥又长又难维护；
    // 「用密钥换坐标」是这里最自然的选择（访问端本来就要能访问控制台）。
    let api = ApiClient::new(&args.console)?;
    let resolved = api.resolve_access(&args.key).await?;
    tracing::info!(
        tunnel = %resolved.tunnel_name,
        kind = %resolved.kind,
        proto = %resolved.proto,
        node = %resolved.node_name,
        mode = %resolved.mode,
        "已取得隧道信息"
    );

    // ---- 2. 本地监听 ----
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| Error::config(format!("监听 {listen} 失败（端口被占用？）: {e}")))?;

    // ---- 3. 自己的 Iroh 节点（临时身份：访问端不需要被别人连）----
    let p2p_section = rscross_config::P2pSection::default();
    let node = P2pNode::bind(P2pOptions::from_section(&p2p_section, None)).await?;
    node.wait_online().await;

    // ---- 4. 与节点握手 ----
    let node_addr = decode_addr(&resolved.node_endpoint)?;
    let session = AccessSession::connect(&node, &node_addr, &args.key).await?;

    tracing::info!(
        listen = %listen,
        tunnel = %resolved.tunnel_name,
        path = %session.mode(),
        "访问端已就绪：访问上面的地址即访问内网服务（Ctrl+C 退出）"
    );

    // ---- 5. 接受本地连接 ----
    let direct_timeout = Duration::from_secs(args.direct_timeout_secs.max(1));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "接受本地连接失败");
                continue;
            }
        };
        let node = node.clone();
        let session = session.clone();
        tokio::spawn(async move {
            if let Err(err) = serve(tcp, node, session, direct_timeout).await {
                tracing::warn!(peer = %peer, error = %err, "转发失败");
            }
        });
    }
}

/// 处理一条本地连接：按会话模式选择直连或中继。
async fn serve(
    tcp: TcpStream,
    node: P2pNode,
    session: AccessSession,
    direct_timeout: Duration,
) -> Result<()> {
    // P2P 隧道：先试直连 —— 直连成功就不消耗服务端带宽。
    if session.mode() == "p2p" {
        match session.dial_client(&node, direct_timeout).await {
            Ok(stream) => {
                tracing::debug!("与客户端直连成功");
                return bridge_tcp_to_stream(tcp, stream).await.map(|_| ());
            }
            Err(err) if session.allow_relay() => {
                tracing::warn!(error = %err, "直连客户端失败，回退到节点中继");
            }
            Err(err) => {
                return Err(Error::transport(format!(
                    "直连客户端失败，且该隧道不允许中继回退: {err}"
                )));
            }
        }
    }

    // 私有隧道，或 P2P 直连失败后的回退：向节点再开一条流走中继。
    let stream = session.open_relay().await?;
    bridge_tcp_to_stream(tcp, stream).await.map(|_| ())
}

/// 访问端自己的日志初始化（不上报控制台，本地打印即可）。
fn init_tracing(args: &AccessArgs) {
    let level = args.log_level.clone().unwrap_or_else(|| "info".to_string());
    let filter = tracing_subscriber::EnvFilter::try_new(&level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
