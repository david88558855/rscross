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
use tokio_util::sync::CancellationToken;

/// 与节点握手的重试窗口（秒）。
///
/// 隧道配置经心跳下发（默认 15 秒一次），给到 90 秒足以跨过数个周期；
/// 同时它也是「密钥真的不对」时用户需要等待的上限。
const CONNECT_TIMEOUT_SECS: u64 = 90;

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

impl AccessArgs {
    /// 校验访问密钥的**形状**（不判断它是否真实存在）。
    ///
    /// 放在本地做，是为了把「抄错了」与「隧道没生效」区分开：直接发给节点的话，
    /// 两种情况的回复都是同一句「访问密钥无效」，用户无从下手。
    fn check_key_shape(&self) -> Result<()> {
        let key = self.key.trim();
        if rscross_common::access_key_shape_ok(key) {
            return Ok(());
        }
        // 密钥长度是最容易出错的地方（漏抄一位、把 O 当成 0），
        // 所以提示里给出期望形状与实际长度，而不只是「格式不对」。
        let expected = format!(
            "{} 加 {} 位十六进制（共 {} 位）",
            rscross_common::ACCESS_KEY_PREFIX,
            rscross_common::ACCESS_KEY_HEX_LEN,
            rscross_common::ACCESS_KEY_PREFIX.len() + rscross_common::ACCESS_KEY_HEX_LEN
        );
        if key.is_empty() {
            return Err(Error::config(format!("未提供访问密钥（应为 {expected}）")));
        }
        // 历史密钥比现在长，仍可能被使用；这一档给的是「形状差一点」的提示。
        if !key.starts_with(rscross_common::ACCESS_KEY_PREFIX) {
            return Err(Error::config(format!(
                "访问密钥应以 {} 开头（收到的长度 {}）。请确认复制的是「访问密钥」而不是别的令牌",
                rscross_common::ACCESS_KEY_PREFIX,
                key.len()
            )));
        }
        Err(Error::config(format!(
            "访问密钥格式不对：应为 {expected}，收到的长度是 {}。\
             请注意十六进制里没有字母 o/i/l，常见是漏抄或多抄了一位",
            key.len()
        )))
    }
}

/// 运行访问端（长驻，直到 Ctrl+C 或进程被杀）。
pub async fn run(args: AccessArgs) -> Result<()> {
    init_tracing(&args);
    args.check_key_shape()?;

    let listen: SocketAddr = args
        .listen
        .parse()
        .map_err(|e| Error::config(format!("--listen 非法（应形如 127.0.0.1:8080）: {e}")))?;

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

    // ---- 4. 与节点握手（带重试）----
    let node_addr = decode_addr(&resolved.node_endpoint)?;
    let session = AccessSession::connect_with_retry(
        &node,
        &node_addr,
        &args.key,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .await?;

    tracing::info!(
        listen = %listen,
        tunnel = %resolved.tunnel_name,
        path = %session.mode(),
        "访问端已就绪：访问上面的地址即访问内网服务（Ctrl+C 退出）"
    );

    // ---- 5. 接受本地连接（收到关停信号就退出）----
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let token = shutdown.clone();
        async move {
            // 与常驻客户端共用同一份实现：Windows 上还要接住 Ctrl+Break /
            // 控制台关闭 / 注销 / 关机，否则关窗口时进程会被强制结束。
            rscross_common::signal::wait_for_shutdown().await;
            tracing::warn!("收到退出信号，正在关闭访问端");
            token.cancel();
        }
    });

    let direct_timeout = Duration::from_secs(args.direct_timeout_secs.max(1));
    loop {
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "接受本地连接失败");
                    continue;
                }
            },
        };
        let node = node.clone();
        let session = session.clone();
        tokio::spawn(async move {
            if let Err(err) = serve(tcp, node, session, direct_timeout).await {
                tracing::warn!(peer = %peer, error = %err, "转发失败");
            }
        });
    }

    // 显式关闭 Iroh 节点：否则会打出
    // 「Endpoint dropped without calling Endpoint::close. Aborting ungracefully.」
    // 这条警告，看起来像出了故障，其实只是没优雅退出。
    node.close().await;
    tracing::info!("访问端已退出");
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(key: &str) -> AccessArgs {
        AccessArgs {
            console: "http://127.0.0.1:7800".into(),
            key: key.into(),
            listen: "127.0.0.1:8080".into(),
            direct_timeout_secs: 8,
            log_level: None,
        }
    }

    #[test]
    fn key_shape_is_checked_locally_so_typos_are_not_blamed_on_the_tunnel() {
        // 这是本轮改动的核心动机：密钥从 32 位缩到 16 位之后，
        // 「漏抄一位」比「隧道还没生效」更像常见故障，必须在本地就说清楚。
        let good = format!(
            "{}{}",
            rscross_common::ACCESS_KEY_PREFIX,
            "a".repeat(rscross_common::ACCESS_KEY_HEX_LEN)
        );
        args_with(&good).check_key_shape().expect("合法形状应通过");

        // 少一位（漏抄）
        let short = &good[..good.len() - 1];
        let err = args_with(short)
            .check_key_shape()
            .expect_err("少一位必须被拦下");
        assert!(err.to_string().contains("格式不对"), "{err}");
        assert!(
            err.to_string().contains("16 位"),
            "提示要给出期望形状: {err}"
        );

        // 多一位（多抄）
        assert!(args_with(&format!("{good}0")).check_key_shape().is_err());

        // 前缀不对：提示要指向「复制错了东西」，而不是「格式不对」
        // 下面这串是客户端令牌的形状（rsa_ + 16 位），长度对但不是访问密钥。
        let err = args_with("rsa_0123456789abcdef")
            .check_key_shape()
            .expect_err("前缀不对必须被拦下");
        assert!(err.to_string().contains("rsv_"), "{err}");
        assert!(
            err.to_string().contains("访问密钥"),
            "提示要指出该复制哪个值: {err}"
        );

        // 空值
        let err = args_with("").check_key_shape().expect_err("空值必须被拦下");
        assert!(err.to_string().contains("未提供"), "{err}");
    }

    #[test]
    fn key_with_surrounding_whitespace_is_accepted() {
        // 从终端复制粘贴常常带一个尾巴空格或换行，这不该是用户的错。
        let good = format!(
            "  {}{}  ",
            rscross_common::ACCESS_KEY_PREFIX,
            "b".repeat(rscross_common::ACCESS_KEY_HEX_LEN)
        );
        args_with(&good)
            .check_key_shape()
            .expect("两侧空白应被忽略");
    }
}
