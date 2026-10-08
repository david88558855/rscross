//! 服务端节点运行时。
//!
//! 启动顺序（每一步都在日志里留下明确的成败痕迹，便于排障）：
//! 1. 载入节点配置 → 打开状态目录
//! 2. 初始化日志（与控制面共用一套 `tracing` + 环形缓冲）
//! 3. 按 `control_mode` 建立控制台链路：内嵌控制台起 HTTP，或连远端中央控制台
//! 4. 绑定 Iroh 节点，注册 `ALPN_CONTROL`（让客户端能真正建立直连并被判真）
//! 5. 向控制台注册 → 拿到 `tunnel_token`
//! 6. 启动 FerroTunnel 中继服务端（反向隧道控制面 + 公网入口）
//! 7. 心跳循环 + 信号监听 → 优雅关停

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use rscross_common::{Error, NodeRuntime, Result};
use rscross_config::{ConsoleFile, NodeFile};
use rscross_control::{build_plane, init_logging, wait_for_signal, ControlPlane, LogBus};
use rscross_transport::{
    load_or_create_secret_key, NodeInfoHandler, P2pNode, P2pOptions, RelayServer,
};
use tokio_util::sync::CancellationToken;

use crate::identity::{NodeIdentity, NodeStateDir};
use crate::link::ControlLink;

/// 心跳失败后的指数退避上限。
const MAX_BACKOFF_SECS: u64 = 60;

/// 命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "rscross-server",
    version,
    about = "rscross 服务端节点：单机内嵌控制台，或加入中央控制台"
)]
pub struct NodeArgs {
    /// 配置文件路径（不存在时自动生成默认配置）。
    #[arg(short, long, default_value = "rscross-server.toml", env = "RSROSS_SERVER_CONFIG")]
    pub config: PathBuf,
    /// 节点名。
    #[arg(long)]
    pub name: Option<String>,
    /// 加入远端中央控制台（多节点汇聚）。
    #[arg(long)]
    pub managed: bool,
    /// 单机自用：本进程内嵌控制台。
    #[arg(long)]
    pub embedded: bool,
    /// 中央控制台地址，例如 `http://1.2.3.4:7800`。
    #[arg(long, env = "RSROSS_CONSOLE")]
    pub console: Option<String>,
    /// 中央控制台签发的节点令牌（`rsn_` 前缀）。
    #[arg(long, env = "RSROSS_ENROLL_TOKEN")]
    pub enroll_token: Option<String>,
    /// 状态目录（保存节点身份、Iroh 私钥、内嵌控制台数据）。
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// 内嵌控制台配置文件路径。
    #[arg(long)]
    pub console_config: Option<PathBuf>,
    /// 反向隧道控制面监听地址。
    #[arg(long)]
    pub tunnel_bind: Option<String>,
    /// 公网入口监听地址。
    #[arg(long)]
    pub ingress_bind: Option<String>,
    /// 对外可达主机名/IP，用于生成客户端接入地址。
    #[arg(long, env = "RSROSS_PUBLIC_HOST")]
    pub public_host: Option<String>,
    /// 关闭 P2P（只走 FerroTunnel 中继）。
    #[arg(long)]
    pub no_p2p: bool,
    /// 覆盖日志级别。
    #[arg(long)]
    pub log_level: Option<String>,
    /// 只校验配置后退出。
    #[arg(long)]
    pub check: bool,
    /// 打印默认配置后退出。
    #[arg(long)]
    pub print_default_config: bool,
}

/// 入口。
pub async fn run_node() -> Result<()> {
    let args = NodeArgs::parse();
    run_with_args(args).await
}

/// 用给定参数启动。
pub async fn run_with_args(args: NodeArgs) -> Result<()> {
    if args.print_default_config {
        let text = toml::to_string_pretty(&NodeFile::default())
            .map_err(|e| Error::config(format!("序列化默认配置失败: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    let mut cfg = NodeFile::load_or_init(&args.config)?;
    apply_overrides(&mut cfg, &args);
    cfg.validate()?;

    if args.check {
        println!(
            "配置校验通过: {} （control_mode = {}）",
            args.config.display(),
            cfg.node.control_mode
        );
        // 「浏览器打不开控制台」时，这条输出能立刻区分是「页面没打进二进制」
        // 还是「网络/安全组问题」。
        if cfg.is_embedded() {
            println!("内嵌控制台前端: {}", rscross_control::console::diagnose());
            // 端口是最容易对不上号的一项：「打不开控制台」有一大半是访问了另一个端口。
            println!(
                "内嵌控制台默认端口: {}（独立中央控制台是 {}；如需修改，用 --console-config 或 node.console_config 指定配置文件）",
                rscross_common::DEFAULT_CONSOLE_PORT,
                rscross_common::DEFAULT_CENTRAL_CONSOLE_PORT
            );
        } else {
            println!("控制台形态: managed（前端由远端控制台提供，本机不内嵌页面）");
        }
        return Ok(());
    }

    run_configured(cfg, args).await
}

fn apply_overrides(cfg: &mut NodeFile, args: &NodeArgs) {
    // 两个开关同时给出时以 --managed 为准（更明确地表达「加入中央控制台」）。
    if args.managed {
        cfg.node.control_mode = "managed".to_string();
    } else if args.embedded {
        cfg.node.control_mode = "embedded".to_string();
    }
    if let Some(v) = args.name.clone() {
        cfg.node.name = v;
    }
    if let Some(v) = args.console.clone() {
        cfg.node.console_url = v;
    }
    if let Some(v) = args.enroll_token.clone() {
        cfg.node.enroll_token = Some(v);
    }
    if let Some(v) = args.tunnel_bind.clone() {
        cfg.node.tunnel_bind = v;
    }
    if let Some(v) = args.ingress_bind.clone() {
        cfg.node.ingress_bind = v;
    }
    if let Some(v) = args.public_host.clone() {
        cfg.node.public_host = Some(v);
    }
    if let Some(v) = args.log_level.clone() {
        cfg.log.level = v;
    }
    if args.no_p2p {
        cfg.p2p.enabled = false;
    }
}

async fn run_configured(cfg: NodeFile, args: NodeArgs) -> Result<()> {
    let state_dir = NodeStateDir::open(
        args.state_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(&cfg.node.state_dir)),
    )?;

    // 日志必须在其它初始化之前就绪，否则控制台「日志」页会缺开头。
    let bus = LogBus::new(cfg.log.ring_capacity);
    init_logging(&cfg.log, bus.clone());

    tracing::info!(
        version = rscross_common::VERSION,
        node = %cfg.node.name,
        mode = %cfg.node.control_mode,
        config = %args.config.display(),
        state_dir = %state_dir.root().display(),
        "rscross-server 启动中"
    );

    let shutdown = CancellationToken::new();
    let grace = Duration::from_secs(10);

    // ---- 1. 控制台链路 ----
    let (link, console_task) = if cfg.is_embedded() {
        let (plane, handle) =
            start_embedded_console(&cfg, &args, &state_dir, bus.clone(), &shutdown).await?;
        (ControlLink::embedded(plane), Some(handle))
    } else {
        tracing::info!(console = %cfg.node.console_url, "以 managed 形态加入中央控制台");
        (ControlLink::remote(&cfg.node.console_url)?, None)
    };

    // ---- 2. Iroh 节点 ----
    let p2p = build_p2p(&cfg, &state_dir).await;
    let node_router = p2p.as_ref().map(|node| {
        node.spawn_router(
            rscross_transport::ALPN_CONTROL,
            NodeInfoHandler::new(
                cfg.node.name.clone(),
                format!(
                    "tunnel={} ingress={}",
                    cfg.node.tunnel_bind, cfg.node.ingress_bind
                ),
            ),
        )
    });

    // ---- 3. 注册 ----
    let public_host = cfg
        .node
        .public_host
        .clone()
        .filter(|h| !h.trim().is_empty())
        .or_else(detect_public_host);
    if let Some(host) = public_host.as_deref() {
        tracing::info!(public_host = %host, "节点对外主机名（用于生成客户端接入地址）");
    }

    let enroll_token = args
        .enroll_token
        .clone()
        .or_else(|| cfg.node.enroll_token.clone())
        .or_else(|| state_dir.load_enroll_token());

    let mut identity = state_dir.load_identity();
    let needs_enroll = cfg.is_embedded() || !identity.is_registered();

    if needs_enroll {
        identity = enroll_with_retry(
            &link,
            enroll_token.as_deref(),
            &cfg,
            public_host.clone(),
            &p2p,
            &shutdown,
        )
        .await?;
        state_dir.save_identity(&identity)?;
        state_dir.clear_enroll_token();
    } else {
        tracing::info!(
            node_id = identity.node_id.as_deref().unwrap_or("-"),
            node = identity.name.as_deref().unwrap_or("-"),
            "复用已持久化的节点身份"
        );
    }

    // 立刻发一次心跳，把数据面端口 / EndpointId / 出口 IP 落到控制台。
    // 不做这一步会有真实竞态：客户端可能在节点第一次心跳之前就注册，
    // 那时控制台算不出 `tunnel_server`，客户端会连到错误的端口。
    match link
        .heartbeat(&identity, &runtime_info(&cfg, &p2p))
        .await
    {
        Ok(_) => tracing::debug!("首次心跳已发送"),
        Err(err) => tracing::warn!(error = %err, "首次心跳失败，将在心跳循环中重试"),
    }

    // ---- 4. FerroTunnel 中继服务端 ----
    let mut tunnel_section = cfg.tunnel.clone();
    if let Some(token) = identity
        .tunnel_token
        .as_deref()
        .filter(|t| !t.trim().is_empty())
    {
        tunnel_section.token = token.to_string();
    }

    let tunnel_bind = parse_addr(&cfg.node.tunnel_bind, "node.tunnel_bind")?;
    let ingress_bind = parse_addr(&cfg.node.ingress_bind, "node.ingress_bind")?;

    let relay_task = match RelayServer::build(tunnel_bind, ingress_bind, &tunnel_section) {
        Ok(relay) => {
            let token = shutdown.clone();
            Some(tokio::spawn(async move {
                if let Err(err) = relay.run(token).await {
                    tracing::error!(error = %err, "FerroTunnel 中继退出");
                }
            }))
        }
        Err(err) => {
            tracing::error!(error = %err, "FerroTunnel 中继构建失败，反向隧道路径不可用");
            None
        }
    };

    // ---- 5. 心跳 ----
    let heartbeat_task = tokio::spawn({
        let link_identity = identity.clone();
        let cfg = cfg.clone();
        let p2p = p2p.clone();
        let state_dir = state_dir.clone();
        let shutdown = shutdown.clone();
        async move {
            heartbeat_loop(link, link_identity, cfg, p2p, state_dir, shutdown).await;
        }
    });

    tracing::info!(
        node = %cfg.node.name,
        tunnel = %tunnel_bind,
        ingress = %ingress_bind,
        "服务端节点已就绪（Ctrl+C 退出）"
    );

    // ---- 6. 等待退出 ----
    wait_for_signal().await;
    tracing::warn!("收到退出信号，开始优雅关停");
    shutdown.cancel();

    for (name, handle) in [("heartbeat", heartbeat_task)] {
        match tokio::time::timeout(grace, handle).await {
            Ok(Ok(())) => tracing::debug!(task = name, "任务已退出"),
            Ok(Err(err)) => tracing::warn!(task = name, error = %err, "任务 panic"),
            Err(_) => tracing::warn!(task = name, "任务未在宽限期内退出"),
        }
    }
    if let Some(handle) = relay_task {
        let _ = tokio::time::timeout(grace, handle).await;
    }
    if let Some(router) = node_router {
        if let Err(err) = router.shutdown().await {
            tracing::warn!(error = %err, "关闭 Iroh accept 循环失败");
        }
    }
    if let Some(node) = p2p.as_ref() {
        node.close().await;
    }
    if let Some(handle) = console_task {
        match tokio::time::timeout(grace, handle).await {
            Ok(Ok(())) => tracing::debug!("内嵌控制台已退出"),
            Ok(Err(err)) => tracing::warn!(error = %err, "内嵌控制台 panic"),
            Err(_) => tracing::warn!("内嵌控制台未在宽限期内退出"),
        }
    }

    tracing::info!("rscross-server 已退出");
    Ok(())
}

/// 启动内嵌控制台：返回控制面句柄与后台任务。
async fn start_embedded_console(
    cfg: &NodeFile,
    args: &NodeArgs,
    state_dir: &NodeStateDir,
    bus: LogBus,
    shutdown: &CancellationToken,
) -> Result<(ControlPlane, tokio::task::JoinHandle<()>)> {
    let console_path = args
        .console_config
        .clone()
        .unwrap_or_else(|| state_dir.console_config_path());

    let existed = console_path.exists();
    let mut console_cfg = ConsoleFile::load_or_init(&console_path)?;
    if !existed {
        // 首次生成时把数据库放进状态目录，避免污染当前工作目录。
        console_cfg.console.name = format!("{}-console", cfg.node.name);
        console_cfg.database.path = state_dir.console_db_path().to_string_lossy().to_string();
        console_cfg.save(&console_path)?;
    }

    let addr: SocketAddr = console_cfg
        .console
        .bind
        .parse()
        .map_err(|e| Error::config(format!("console.bind 非法: {e}")))?;

    let plane = build_plane(
        console_cfg,
        console_path.clone(),
        bus,
        true,
        shutdown.clone(),
    )
    .await?;
    let listener = ControlPlane::bind(addr).await?;

    tracing::info!(
        console = %format!("http://{addr}"),
        config = %console_path.display(),
        "已启用内嵌控制台（单机自用形态）"
    );

    let serving = plane.clone();
    let cancel = shutdown.clone();
    let handle = tokio::spawn(async move {
        if let Err(err) = serving.serve(listener, cancel).await {
            tracing::error!(error = %err, "内嵌控制台退出");
        }
    });

    Ok((plane, handle))
}

async fn build_p2p(cfg: &NodeFile, state_dir: &NodeStateDir) -> Option<P2pNode> {
    if !cfg.p2p.enabled {
        tracing::info!("p2p.enabled = false，跳过 Iroh 节点初始化");
        return None;
    }

    let key_path = cfg
        .p2p
        .secret_key_file
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.node_key_path());

    let secret_key = match load_or_create_secret_key(&key_path) {
        Ok(key) => Some(key),
        Err(err) => {
            tracing::warn!(error = %err, "节点私钥不可用，本次使用临时身份（重启后会变化）");
            None
        }
    };

    match P2pNode::bind(P2pOptions::from_section(&cfg.p2p, secret_key)).await {
        Ok(node) => {
            match tokio::time::timeout(Duration::from_secs(15), node.wait_online()).await {
                Ok(()) => tracing::info!(endpoint_id = %node.id_string(), "Iroh 节点已上线"),
                Err(_) => tracing::warn!(
                    endpoint_id = %node.id_string(),
                    "等待 Iroh 上线超时（网络受限？），直连路径暂不可用"
                ),
            }
            Some(node)
        }
        Err(err) => {
            tracing::error!(error = %err, "Iroh 节点绑定失败，本次只提供中继路径");
            None
        }
    }
}

async fn enroll_with_retry(
    link: &ControlLink,
    token: Option<&str>,
    cfg: &NodeFile,
    public_host: Option<String>,
    p2p: &Option<P2pNode>,
    shutdown: &CancellationToken,
) -> Result<NodeIdentity> {
    if let ControlLink::Http { .. } = link {
        if token.is_none() {
            tracing::warn!(
                "没有节点令牌，无法加入中央控制台；请在控制台「服务端节点」页签发后用 --enroll-token 启动"
            );
        }
    }

    let mut attempt: u32 = 0;
    loop {
        let runtime = runtime_info(cfg, p2p);
        match link
            .enroll(token, &cfg.node.name, public_host.clone(), &runtime)
            .await
        {
            Ok(identity) => return Ok(identity),
            Err(err) => {
                // 鉴权失败重试无意义，直接给出可操作的提示。
                if err.to_string().contains("401") {
                    return Err(Error::auth(format!(
                        "节点注册被拒绝（令牌无效或已轮换）：{err}。请在中央控制台「服务端节点」页重新签发令牌"
                    )));
                }
                attempt = attempt.saturating_add(1);
                let delay = backoff_delay(attempt);
                tracing::warn!(
                    error = %err,
                    retry_in_secs = delay.as_secs(),
                    "节点注册失败，稍后重试"
                );
                if !sleep_or_cancel(shutdown, delay).await {
                    return Err(Error::internal("等待退出信号时中断了注册"));
                }
            }
        }
    }
}

async fn heartbeat_loop(
    link: ControlLink,
    mut identity: NodeIdentity,
    cfg: NodeFile,
    p2p: Option<P2pNode>,
    state_dir: NodeStateDir,
    shutdown: CancellationToken,
) {
    let mut interval = identity
        .heartbeat_secs
        .unwrap_or(rscross_common::DEFAULT_HEARTBEAT_SECS)
        .max(3);
    let mut failures: u32 = 0;

    loop {
        let runtime = runtime_info(&cfg, &p2p);
        match link.heartbeat(&identity, &runtime).await {
            Ok(outcome) => {
                failures = 0;
                interval = outcome.heartbeat_secs.max(3);
                if identity.tunnel_token.as_deref() != Some(outcome.tunnel_token.as_str()) {
                    // FerroTunnel 的 relay 只在启动时读取 token，因此这里只能提示重启。
                    tracing::warn!(
                        "控制台下发的隧道 token 与本地不一致；已持久化，重启服务端后生效"
                    );
                    identity.tunnel_token = Some(outcome.tunnel_token);
                    if let Err(err) = state_dir.save_identity(&identity) {
                        tracing::warn!(error = %err, "持久化节点身份失败");
                    }
                }
                tracing::debug!(node = %cfg.node.name, "节点心跳成功");
            }
            Err(err) => {
                failures = failures.saturating_add(1);
                tracing::warn!(
                    error = %err,
                    consecutive = failures,
                    "节点心跳失败，控制台可能不可达"
                );
            }
        }

        let secs = if failures == 0 {
            interval
        } else {
            interval
                .saturating_mul(u64::from(failures.min(5)))
                .min(MAX_BACKOFF_SECS * 5)
        };
        if !sleep_or_cancel(&shutdown, Duration::from_secs(secs)).await {
            break;
        }
    }
}

fn runtime_info(cfg: &NodeFile, p2p: &Option<P2pNode>) -> NodeRuntime {
    NodeRuntime {
        version: rscross_common::VERSION.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        endpoint_id: p2p.as_ref().map(|node| node.id_string()),
        endpoint_addr: p2p.as_ref().and_then(|node| node.addr_json().ok()),
        tunnel_port: cfg
            .node
            .tunnel_bind
            .parse::<SocketAddr>()
            .ok()
            .map(|a| a.port()),
        ingress_port: cfg
            .node
            .ingress_bind
            .parse::<SocketAddr>()
            .ok()
            .map(|a| a.port()),
        public_host: cfg.node.public_host.clone(),
    }
}

/// 猜测本机对外 IP：向一个外部地址 `connect`（UDP 不产生任何报文）后读本地地址。
///
/// 失败（沙箱 / 纯离线）时返回 `None`，由控制台回落到观测到的出口 IP。
fn detect_public_host() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // 只做路由决策，不会真的发包。
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip.to_string())
}

fn parse_addr(raw: &str, field: &str) -> Result<SocketAddr> {
    raw.parse::<SocketAddr>()
        .map_err(|e| Error::config(format!("{field} 不是合法的监听地址({raw}): {e}")))
}

/// 可被关停信号打断的 sleep。返回 `false` 表示需要退出。
pub(crate) async fn sleep_or_cancel(shutdown: &CancellationToken, delay: Duration) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

/// 指数退避（1、2、4、8…秒，上限 [`MAX_BACKOFF_SECS`]）。
pub(crate) fn backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    let secs = 1u64 << shift;
    Duration::from_secs(secs.min(MAX_BACKOFF_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> NodeArgs {
        NodeArgs {
            config: PathBuf::from("x"),
            name: None,
            managed: false,
            embedded: false,
            console: None,
            enroll_token: None,
            state_dir: None,
            console_config: None,
            tunnel_bind: None,
            ingress_bind: None,
            public_host: None,
            no_p2p: false,
            log_level: None,
            check: false,
            print_default_config: false,
        }
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_delay(1).as_secs(), 1);
        assert_eq!(backoff_delay(2).as_secs(), 2);
        assert_eq!(backoff_delay(3).as_secs(), 4);
        assert_eq!(backoff_delay(7).as_secs(), 60);
        assert_eq!(backoff_delay(100).as_secs(), 60);
    }

    #[test]
    fn cli_overrides_win_over_config() {
        let mut cfg = NodeFile::default();
        cfg.node.control_mode = "embedded".to_string();
        let mut args = base_args();
        args.managed = true;
        args.console = Some("http://10.0.0.1:7800".to_string());
        args.enroll_token = Some("rsn_a".to_string());
        args.public_host = Some("t.example.com".to_string());
        args.no_p2p = true;

        apply_overrides(&mut cfg, &args);
        assert_eq!(cfg.node.control_mode, "managed");
        assert_eq!(cfg.node.console_url, "http://10.0.0.1:7800");
        assert_eq!(cfg.node.enroll_token.as_deref(), Some("rsn_a"));
        assert_eq!(cfg.node.public_host.as_deref(), Some("t.example.com"));
        assert!(!cfg.p2p.enabled);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn embedded_flag_beats_config() {
        let mut cfg = NodeFile::default();
        cfg.node.control_mode = "managed".to_string();
        let mut args = base_args();
        args.embedded = true;
        apply_overrides(&mut cfg, &args);
        assert_eq!(cfg.node.control_mode, "embedded");
        assert!(cfg.validate().is_ok(), "内嵌形态不要求 console_url");
    }

    #[test]
    fn parse_addr_rejects_garbage() {
        assert!(parse_addr("nope", "x").is_err());
        assert!(parse_addr("127.0.0.1:0", "x").is_ok());
    }
}
