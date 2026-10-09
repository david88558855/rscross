//! 客户端主运行时：注册、心跳、隧道收敛、P2P 探测、日志上报。
//!
//! 关键设计：**客户端只与控制台对话**。它拿不到也不需要「服务端节点地址」的配置项
//! —— 归属节点由控制台在注册/心跳响应里下发。因此把客户端从节点 A 迁到节点 B，
//! 只需要在控制台改一行归属，客户端在下一个心跳周期自动收敛。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rscross_common::{ClientRuntime, DesiredTunnel, Error, NodeEndpoint, Result, TunnelKind};
use rscross_config::{ClientFile, TunnelSection};
use rscross_transport::{
    probe_control, P2pDataHandler, P2pNode, P2pOptions, PathProbe, PathSelector, RelayTunnelClient,
    TunnelTargets,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::api::{ApiClient, EnrollRequest, HeartbeatRequest};
use crate::identity::{Identity, StateDir};
use crate::logsink::{LogSink, LogSinkLayer};

/// 注册失败后的指数退避上限。
const MAX_BACKOFF_SECS: u64 = 60;
/// 客户端日志上报周期。
const LOG_FLUSH_SECS: u64 = 30;
/// 单次上报的日志条数上限。
const LOG_FLUSH_BATCH: usize = 100;
/// P2P 直连探测周期。
const P2P_PROBE_SECS: u64 = 60;

/// 命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "rscross-client",
    version,
    about = "rscross 客户端：把内网服务通过反向隧道 / P2P 直连暴露出去"
)]
pub struct Args {
    /// 子命令。不带子命令时按「常驻客户端」运行 ——
    /// 既有的 `rscross-client --console ... --enroll-token ...` 用法完全不变。
    #[command(subcommand)]
    pub command: Option<Command>,

    /// 配置文件路径（不存在时自动生成默认配置）。
    #[arg(
        short,
        long,
        default_value = "rscross-client.toml",
        env = "RSROSS_CLIENT_CONFIG"
    )]
    pub config: PathBuf,
    /// 控制台地址，例如 `http://1.2.3.4:7800`。
    #[arg(long, env = "RSROSS_CONSOLE")]
    pub console: Option<String>,
    /// 控制台签发的一次性接入令牌。
    #[arg(long, env = "RSROSS_ENROLL_TOKEN")]
    pub enroll_token: Option<String>,
    /// 节点名。
    #[arg(long)]
    pub name: Option<String>,
    /// 状态目录（保存身份与节点私钥）。
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// 覆盖日志级别。
    #[arg(long)]
    pub log_level: Option<String>,
    /// 只校验配置后退出。
    #[arg(long)]
    pub check: bool,
    /// 打印默认配置后退出。
    #[arg(long)]
    pub print_default_config: bool,
    /// 强制关闭 P2P（只走中继）。
    #[arg(long)]
    pub no_p2p: bool,
}

/// 控制面传输方式。
///
/// 由 `--console` 的 scheme 决定，不额外配置 —— 让「写什么地址」唯一决定
/// 「怎么连」，省掉一个需要和地址保持同步的开关。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlTransport {
    /// 控制面 WebSocket（主协议）。一条连接上可并发心跳与日志上报。
    WebSocket,
    /// 传统 REST（兼容路径）。控制台只提供 HTTP 入口时使用。
    Http,
}

/// 子命令。
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// 访问端：凭访问密钥在本机建立到内网服务的入口（私有 / P2P 隧道）。
    ///
    /// 与常驻客户端相反 —— 它在「访问者」一侧跑，暴露本机监听地址，
    /// 内网侧因此不需要对外开放任何端口。
    Access(crate::access::AccessArgs),
}

/// 入口（解析命令行）。
pub async fn run() -> Result<()> {
    let args = Args::parse();
    run_with_args(args).await
}

/// 用给定参数启动。
pub async fn run_with_args(args: Args) -> Result<()> {
    // 子命令优先：访问端与常驻客户端是两种完全不同的运行形态，
    // 放在同一二进制里是为了不把发布物从三个变成四个。
    if let Some(Command::Access(access)) = args.command {
        return crate::access::run(access).await;
    }

    if args.print_default_config {
        let text = toml::to_string_pretty(&ClientFile::default())
            .map_err(|e| Error::config(format!("序列化默认配置失败: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    let mut cfg = ClientFile::load_or_init(&args.config)?;
    if let Some(v) = args.console.clone() {
        cfg.client.console_url = v;
    }
    if let Some(v) = args.name.clone() {
        cfg.client.name = v;
    }
    if let Some(v) = args.log_level.clone() {
        cfg.log.level = v;
    }
    if args.no_p2p {
        cfg.p2p.enabled = false;
    }
    cfg.validate()?;

    if args.check {
        println!("配置校验通过: {}", args.config.display());
        return Ok(());
    }

    let state_dir = StateDir::open(
        args.state_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(&cfg.client.state_dir)),
    )?;

    let sink = LogSink::new(512);
    init_tracing(&cfg.log, sink.clone());

    tracing::info!(
        version = rscross_common::VERSION,
        config = %args.config.display(),
        state_dir = %state_dir.root().display(),
        console = %cfg.client.console_url,
        "rscross-client 启动中"
    );

    // ---- 0. 解析控制台地址 ----
    //
    // 先做发现再选传输：`--console` 的写法直接决定用 WS 还是 REST，
    // 而「地址算错了」和「连不上」是两种故障 —— 先把地址定下来，
    // 后面每一步失败时日志里都有一个确定的地址可对照。
    let console = crate::discover::discover(&cfg.client.console_url).await?;
    tracing::info!(
        spec = %console.spec,
        scheme = ?console.scheme,
        authority = %console.authority,
        hops = console.hops,
        discovered = console.discovered.as_deref().unwrap_or("-"),
        "控制台地址已解析"
    );

    // 用哪种传输由 scheme 决定：ws/wss 与 txt:// 走控制面 WebSocket（主协议），
    // http/https 保留为兼容路径（仍走 REST）。
    let transport = match console.scheme {
        rscross_common::console::ConsoleScheme::Ws
        | rscross_common::console::ConsoleScheme::Wss
        | rscross_common::console::ConsoleScheme::Txt => {
            tracing::info!(url = %console.ws_url, "控制面走 WebSocket（主协议）");
            ControlTransport::WebSocket
        }
        rscross_common::console::ConsoleScheme::Http
        | rscross_common::console::ConsoleScheme::Https => {
            tracing::info!(base = %console.spec, "控制面走 HTTP（兼容路径）");
            ControlTransport::Http
        }
    };

    // WS 传输在这里就建连：连不上要在启动阶段失败并说清地址，
    // 而不是让每个循环各自重试、每次都报一次同样的错。
    let socket = match transport {
        ControlTransport::WebSocket => Some(
            crate::wsclient::ControlSocket::connect(
                rscross_common::control::Role::Agent,
                &console.ws_url,
            )
            .await?,
        ),
        ControlTransport::Http => None,
    };
    if let Some(s) = &socket {
        tracing::info!(url = %s.url(), "控制面 WebSocket 已建立");
    }

    let api = ApiClient::from_console(&console)?;
    let shutdown = CancellationToken::new();

    // ---- 1. Iroh 节点（先建，注册时要把 EndpointId 一并上报）----
    let p2p = build_p2p(&cfg, &state_dir).await;

    // ---- 2. 注册 ----
    let mut identity = state_dir.load_identity();
    let provided_token = args
        .enroll_token
        .clone()
        .or_else(|| cfg.client.enroll_token.clone())
        .or_else(|| state_dir.load_enroll_token());

    if identity.agent_token.is_none() {
        identity.agent_token = cfg
            .client
            .agent_token
            .clone()
            .filter(|t| !t.trim().is_empty());
    }

    if !identity.is_registered() {
        identity =
            register_with_retry(&api, &state_dir, &cfg, provided_token, &p2p, &shutdown).await?;
    } else {
        tracing::info!(
            client_id = identity.client_id.as_deref().unwrap_or("-"),
            name = identity.name.as_deref().unwrap_or("-"),
            node = identity
                .node
                .as_ref()
                .map(|n| n.name.as_str())
                .unwrap_or("未分配"),
            "复用已持久化的客户端身份"
        );
    }

    let agent_token = identity
        .agent_token
        .clone()
        .expect("注册成功后必然存在 agent token");

    // ---- 3. P2P 数据面：接受对端开来的直连流 ----
    let targets = TunnelTargets::new();
    let router = p2p.as_ref().map(|node| {
        node.spawn_router(
            rscross_transport::ALPN_DATA,
            P2pDataHandler::new(targets.clone(), Duration::from_secs(5)),
        )
    });

    // ---- 4. 后台任务 ----
    let heartbeat_secs = identity
        .heartbeat_secs
        .unwrap_or(rscross_common::DEFAULT_HEARTBEAT_SECS)
        .max(3);

    let heartbeat_task = tokio::spawn({
        let api = api.clone();
        let shutdown = shutdown.clone();
        let token = agent_token.clone();
        let p2p = p2p.clone();
        let targets = targets.clone();
        let section = cfg.tunnel.clone();
        let identity = identity.clone();
        async move {
            heartbeat_loop(
                api,
                token,
                heartbeat_secs,
                section,
                targets,
                p2p,
                identity,
                shutdown,
            )
            .await;
        }
    });

    let probe_task = p2p.as_ref().and_then(|_| {
        identity.node.clone().map(|node| {
            let p2p = p2p.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { p2p_probe_loop(p2p, node, shutdown).await })
        })
    });

    let log_task = {
        let api = api.clone();
        let shutdown = shutdown.clone();
        let token = agent_token.clone();
        let sink = sink.clone();
        tokio::spawn(async move { log_flush_loop(api, token, sink, shutdown).await })
    };

    tracing::info!("客户端已就绪，等待退出信号（Ctrl+C）");
    wait_for_signal().await;
    shutdown.cancel();

    for (name, handle) in [
        ("heartbeat", Some(heartbeat_task)),
        ("p2p-probe", probe_task),
        ("log-flush", Some(log_task)),
    ] {
        if let Some(handle) = handle {
            match tokio::time::timeout(Duration::from_secs(10), handle).await {
                Ok(Ok(())) => tracing::debug!(task = name, "任务已退出"),
                Ok(Err(err)) => tracing::warn!(task = name, error = %err, "任务 panic"),
                Err(_) => tracing::warn!(task = name, "任务未在宽限期内退出"),
            }
        }
    }

    if let Some(router) = router {
        if let Err(err) = router.shutdown().await {
            tracing::warn!(error = %err, "关闭 Iroh accept 循环失败");
        }
    }
    if let Some(node) = p2p.as_ref() {
        node.close().await;
    }

    tracing::info!("rscross-client 已退出");
    Ok(())
}

async fn build_p2p(cfg: &ClientFile, state_dir: &StateDir) -> Option<P2pNode> {
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

    let secret_key = match rscross_transport::load_or_create_secret_key(&key_path) {
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
                    "等待 Iroh 上线超时，直连可能退化为中继"
                ),
            }
            Some(node)
        }
        Err(err) => {
            tracing::error!(error = %err, "Iroh 节点绑定失败，本次只使用反向隧道");
            None
        }
    }
}

async fn register_with_retry(
    api: &ApiClient,
    state_dir: &StateDir,
    cfg: &ClientFile,
    provided_token: Option<String>,
    p2p: &Option<P2pNode>,
    shutdown: &CancellationToken,
) -> Result<Identity> {
    if provided_token.is_none() {
        tracing::warn!(
            "没有可用的接入令牌，尝试自助注册（需要控制台 auth.allow_self_enroll = true）"
        );
    }

    let mut attempt: u32 = 0;
    loop {
        let request = EnrollRequest {
            token: provided_token.clone(),
            name: Some(cfg.client.name.clone()),
            runtime: runtime_info(p2p),
        };

        match api.enroll(&request).await {
            Ok(response) => {
                let identity = Identity {
                    client_id: Some(response.client_id.clone()),
                    agent_token: Some(response.agent_token.clone()),
                    name: Some(response.name.clone()),
                    heartbeat_secs: Some(response.heartbeat_secs),
                    node: Some(response.node.clone()),
                };
                state_dir.save_identity(&identity)?;
                state_dir.clear_enroll_token();

                tracing::info!(
                    client_id = %response.client_id,
                    name = %response.name,
                    node = %response.node.name,
                    tunnel_server = %response.node.tunnel_server,
                    public_url = response.public_url.as_deref().unwrap_or("-"),
                    "注册成功"
                );
                return Ok(identity);
            }
            Err(err) => {
                // 鉴权类错误重试没有意义（令牌错 / 已用过），直接失败并给出可操作的提示。
                if err.to_string().contains("401") {
                    return Err(Error::auth(format!(
                        "注册被拒绝（接入令牌无效或已使用）：{err}。请在控制台重新签发令牌"
                    )));
                }
                attempt = attempt.saturating_add(1);
                let delay = backoff_delay(attempt);
                tracing::warn!(error = %err, retry_in_secs = delay.as_secs(), "注册失败，稍后重试");
                if !sleep_or_cancel(shutdown, delay).await {
                    return Err(Error::internal("等待退出信号时中断了注册"));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn heartbeat_loop(
    api: ApiClient,
    agent_token: String,
    initial_heartbeat_secs: u64,
    section: TunnelSection,
    targets: TunnelTargets,
    p2p: Option<P2pNode>,
    identity: Identity,
    shutdown: CancellationToken,
) {
    let mut interval = initial_heartbeat_secs.max(3);
    let mut failures: u32 = 0;
    let mut manager = TunnelManager::new(section, targets.clone());

    // 用注册时下发的节点坐标先跑一次收敛，避免等到第一次心跳才有隧道。
    manager.reconcile(identity.node.clone(), Vec::new()).await;

    loop {
        let request = HeartbeatRequest {
            runtime: runtime_info(&p2p),
        };

        match api.heartbeat(&agent_token, &request).await {
            Ok(response) => {
                failures = 0;
                interval = response.heartbeat_secs.max(3);
                manager.reconcile(response.node, response.tunnels).await;
                tracing::debug!(
                    tunnels = manager.running_count(),
                    p2p_streams = targets.len(),
                    "心跳成功"
                );
            }
            Err(err) => {
                failures = failures.saturating_add(1);
                tracing::warn!(
                    error = %err,
                    consecutive = failures,
                    "心跳失败，控制台可能不可达"
                );
            }
        }

        // 心跳失败时逐步退避，但不超过 5 倍间隔，避免控制台恢复后长期失联。
        let sleep_secs = if failures == 0 {
            interval
        } else {
            interval
                .saturating_mul(u64::from(failures.min(5)))
                .min(MAX_BACKOFF_SECS * 5)
        };

        if !sleep_or_cancel(&shutdown, Duration::from_secs(sleep_secs)).await {
            break;
        }
    }

    manager.shutdown_all().await;
}

/// P2P 直连探测：定期真的建一条 QUIC 连接到归属节点，并把结果喂给路径选择器。
///
/// 为什么不能省：TCP 连得上不代表打洞成功；只有真的建立了 QUIC 连接才算直连可用。
/// 结果会写进日志（成功一次 INFO，之后失败 WARN），因此控制台的「日志」页能看到。
async fn p2p_probe_loop(p2p: Option<P2pNode>, node: NodeEndpoint, shutdown: CancellationToken) {
    let Some(endpoint) = p2p else { return };
    let Some(addr_raw) = node.endpoint_addr.clone() else {
        tracing::debug!("控制台未下发节点寻址信息，跳过 P2P 探测");
        return;
    };
    let remote = match rscross_transport::decode_addr(&addr_raw) {
        Ok(addr) => addr,
        Err(err) => {
            tracing::warn!(error = %err, "节点寻址信息无法解析，跳过 P2P 探测");
            return;
        }
    };

    let selector = PathSelector::new(rscross_common::PathPolicy::Auto);
    let mut reported_success = false;

    loop {
        let started = std::time::Instant::now();
        let probe = match probe_control(endpoint.endpoint(), &remote, Duration::from_secs(10)).await
        {
            Ok(_reply) => {
                let rtt = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                PathProbe::ok(rtt)
            }
            Err(err) => PathProbe::failed(err.to_string()),
        };

        if probe.ok {
            if !reported_success {
                tracing::info!(
                    node = %node.name,
                    rtt_ms = probe.rtt_ms.unwrap_or(0),
                    "与归属节点建立 P2P 直连成功"
                );
                reported_success = true;
            }
        } else {
            tracing::warn!(
                node = %node.name,
                error = probe.error.as_deref().unwrap_or("-"),
                "与归属节点无法直连，隧道流量走中继"
            );
        }

        selector.observe(&probe);
        let choice = selector.choose();
        tracing::debug!(path = %choice.kind, reason = choice.reason, "当前数据面路径偏好");

        if !sleep_or_cancel(&shutdown, Duration::from_secs(P2P_PROBE_SECS)).await {
            break;
        }
    }
}

async fn log_flush_loop(
    api: ApiClient,
    agent_token: String,
    sink: Arc<LogSink>,
    shutdown: CancellationToken,
) {
    loop {
        if !sleep_or_cancel(&shutdown, Duration::from_secs(LOG_FLUSH_SECS)).await {
            break;
        }
        if sink.is_empty() {
            continue;
        }
        let batch = sink.drain(LOG_FLUSH_BATCH);
        if batch.is_empty() {
            continue;
        }
        match api.push_logs(&agent_token, &batch).await {
            Ok(accepted) => tracing::debug!(sent = batch.len(), accepted, "已上报客户端日志"),
            Err(err) => {
                tracing::debug!(error = %err, "客户端日志上报失败，本轮丢弃");
            }
        }
    }
}

/// 隧道收敛器：让本地运行的 FerroTunnel 客户端集合与「控制台期望配置」一致。
///
/// 它同时负责响应**归属节点变化**：换节点等价于「全部隧道重建」，
/// 这正是「在控制台把客户端迁到另一台节点」的实现方式。
struct TunnelManager {
    section: TunnelSection,
    targets: TunnelTargets,
    node: Option<NodeEndpoint>,
    running: HashMap<String, RunningTunnel>,
    /// 已提示过「该类隧道数据面尚未接入」的隧道 ID。
    ///
    /// 心跳每 15 秒一次，没有这个去重就会把日志刷满——而刷屏的告警等于没有告警。
    reported_unsupported: HashSet<String>,
}

struct RunningTunnel {
    name: String,
    route_key: String,
    local_addr: String,
    client: RelayTunnelClient,
}

impl TunnelManager {
    fn new(section: TunnelSection, targets: TunnelTargets) -> Self {
        Self {
            section,
            targets,
            node: None,
            running: HashMap::new(),
            reported_unsupported: HashSet::new(),
        }
    }

    fn running_count(&self) -> usize {
        self.running.len()
    }

    async fn reconcile(&mut self, node: Option<NodeEndpoint>, desired: Vec<DesiredTunnel>) {
        // 0) 归属节点变化（含「被解绑」）→ 全部重建
        if !same_node(self.node.as_ref(), node.as_ref()) {
            match node.as_ref() {
                Some(n) => tracing::info!(
                    node = %n.name,
                    tunnel_server = %n.tunnel_server,
                    "归属节点已变更，重建全部隧道"
                ),
                None => tracing::warn!("控制台未分配归属节点，停止全部隧道"),
            }
            self.shutdown_all().await;
            self.node = node.clone();
        }

        let Some(node) = node else {
            self.targets.replace_all(Vec::new());
            return;
        };

        let mut section = self.section.clone();
        section.token = node.tunnel_token.clone();
        if section.token.trim().is_empty() {
            tracing::warn!(node = %node.name, "节点未下发隧道 token，无法建立反向隧道");
            return;
        }

        // 两条承载路径，客户端只负责其中一半：
        //
        // - 域名解析：客户端主动外连，用 FerroTunnel 反向隧道把本地服务挂到
        //   节点的 HTTP 入口上（FerroTunnel 自己知道本地地址，不需要 targets）；
        // - 端口转发：入口在节点侧（节点监听公网端口并主动向客户端开流），
        //   客户端只要把「路由键 → 本地地址」登记进 targets，等节点来连即可。
        //
        // 无论走哪条路径，路由键都必须用 `DesiredTunnel::route_key()` 计算 ——
        // 两侧算法不同就会出现「隧道建立了但流量投递不到」。
        let mut wanted: HashMap<String, DesiredTunnel> = HashMap::new();
        let mut targets_wanted: Vec<(String, String)> = Vec::new();
        let mut present: HashSet<String> = HashSet::new();

        for tunnel in desired {
            present.insert(tunnel.id.clone());

            if tunnel.kind == TunnelKind::Domain {
                wanted.insert(tunnel.id.clone(), tunnel);
                continue;
            }

            // 节点侧要根据这个键来开流，所以先登记，与数据面是否就绪无关：
            // 这样访问端上线后不需要再改客户端。
            targets_wanted.push((tunnel.route_key(), tunnel.local_addr.clone()));

            if !tunnel.kind.data_plane_ready() {
                if self.reported_unsupported.insert(tunnel.id.clone()) {
                    tracing::warn!(
                        tunnel = %tunnel.name,
                        kind = %tunnel.kind,
                        category = tunnel.kind.label(),
                        "该分类还需要访问端（rscross-client access）才能访问；配置已保存，届时无需改动客户端"
                    );
                }
            }
        }
        self.reported_unsupported.retain(|id| present.contains(id));

        // 1) 停止：已被删除，或本地地址/路由键发生变化需要重建
        let mut to_stop: Vec<String> = Vec::new();
        for (id, current) in &self.running {
            match wanted.get(id) {
                None => to_stop.push(id.clone()),
                Some(target) => {
                    if current.local_addr != target.local_addr
                        || current.route_key != target.route_key()
                    {
                        to_stop.push(id.clone());
                    }
                }
            }
        }
        for id in to_stop {
            if let Some(mut run) = self.running.remove(&id) {
                self.targets.remove(&run.route_key);
                if let Err(err) = run.client.shutdown().await {
                    tracing::warn!(tunnel = %run.name, error = %err, "停止隧道时出错");
                } else {
                    tracing::info!(tunnel = %run.name, "隧道已停止");
                }
            }
        }

        // 2) 启动：新增，或因上一步被停止而需要重建
        for (id, target) in wanted {
            if self.running.contains_key(&id) {
                continue;
            }
            let route_key = target.route_key();
            let mut client = match RelayTunnelClient::build(
                route_key.clone(),
                node.tunnel_server.clone(),
                target.local_addr.clone(),
                &section,
            ) {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!(tunnel = %target.name, error = %err, "隧道配置非法，跳过");
                    continue;
                }
            };

            let start_result = client.start().await;
            if let Err(err) = start_result {
                tracing::warn!(
                    tunnel = %target.name,
                    error = %err,
                    "隧道建立失败，下轮心跳重试"
                );
                continue;
            }

            self.targets
                .set(route_key.clone(), target.local_addr.clone());
            tracing::info!(
                tunnel = %target.name,
                proto = %target.proto,
                local = %target.local_addr,
                route = %route_key,
                node = %node.name,
                "隧道已建立"
            );
            self.running.insert(
                id,
                RunningTunnel {
                    name: target.name.clone(),
                    route_key,
                    local_addr: target.local_addr.clone(),
                    client,
                },
            );
        }

        // 投递目标表整体替换（幂等）。放在最后：启动循环里的 `targets.set`
        // 只覆盖本次新建的隧道，这里一次性对齐「控制面期望」与「本地登记」。
        self.targets.replace_all(targets_wanted);
    }

    async fn shutdown_all(&mut self) {
        let ids: Vec<String> = self.running.keys().cloned().collect();
        for id in ids {
            if let Some(mut run) = self.running.remove(&id) {
                self.targets.remove(&run.route_key);
                if let Err(err) = run.client.shutdown().await {
                    tracing::debug!(tunnel = %run.name, error = %err, "关闭隧道时出错");
                }
            }
        }
    }
}

fn same_node(a: Option<&NodeEndpoint>, b: Option<&NodeEndpoint>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.node_id == b.node_id
                && a.tunnel_server == b.tunnel_server
                && a.tunnel_token == b.tunnel_token
        }
        _ => false,
    }
}

fn runtime_info(p2p: &Option<P2pNode>) -> ClientRuntime {
    ClientRuntime {
        version: rscross_common::VERSION.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        endpoint_id: p2p.as_ref().map(|node| node.id_string()),
        endpoint_addr: p2p.as_ref().and_then(|node| node.addr_json().ok()),
        public_ip: None,
    }
}

/// 指数退避（1、2、4、8…秒，上限 [`MAX_BACKOFF_SECS`]）。
fn backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    let secs = 1u64 << shift;
    Duration::from_secs(secs.min(MAX_BACKOFF_SECS))
}

/// 可被关停信号打断的 sleep。返回 `false` 表示需要退出。
async fn sleep_or_cancel(shutdown: &CancellationToken, delay: Duration) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

fn init_tracing(cfg: &rscross_config::LogSection, sink: Arc<LogSink>) {
    let filter = EnvFilter::try_new(&cfg.level).unwrap_or_else(|err| {
        eprintln!("日志过滤表达式非法（{}），回退到 info: {err}", cfg.level);
        EnvFilter::new("info")
    });
    let sink_layer = LogSinkLayer::new(sink);

    if cfg.format == "json" {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json().with_target(true))
            .with(sink_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .with(sink_layer)
            .init();
    }
}

async fn wait_for_signal() {
    // 与 control 共用同一份实现：Windows 上除了 Ctrl+C 还要接住
    // Ctrl+Break / 控制台关闭 / 注销 / 关机。复制两份必然漂移，
    // 而漂移的后果是「某个平台在某个进程里关不掉」。
    rscross_common::signal::wait_for_shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rscross_common::{TunnelKind, TunnelProto};

    fn node(id: &str, server: &str, token: &str) -> NodeEndpoint {
        NodeEndpoint {
            node_id: id.to_string(),
            name: id.to_string(),
            tunnel_server: server.to_string(),
            tunnel_token: token.to_string(),
            endpoint_id: None,
            endpoint_addr: None,
            public_addr: None,
            transport: "tcp".to_string(),
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
    fn node_change_is_detected_on_any_field() {
        let a = node("n1", "10.0.0.1:7835", "t1");
        assert!(same_node(Some(&a), Some(&a.clone())));

        let mut b = a.clone();
        b.tunnel_server = "10.0.0.2:7835".to_string();
        assert!(!same_node(Some(&a), Some(&b)), "换节点地址要重建隧道");

        let mut c = a.clone();
        c.tunnel_token = "t2".to_string();
        assert!(!same_node(Some(&a), Some(&c)), "换 token 要重建隧道");

        assert!(!same_node(Some(&a), None), "被解绑要停止隧道");
        assert!(same_node(None, None));
    }

    #[test]
    fn route_key_follows_protocol() {
        let http = DesiredTunnel {
            id: "1".into(),
            name: "web".into(),
            kind: TunnelKind::Domain,
            proto: TunnelProto::Http,
            local_addr: "127.0.0.1:8080".into(),
            remote_port: None,
            host: Some("a.example.com".into()),
            path_prefix: None,
            access_key: None,
            allow_relay: true,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
        };
        assert_eq!(http.route_key(), "a.example.com");
    }

    #[tokio::test]
    async fn manager_without_node_keeps_targets_empty() {
        let targets = TunnelTargets::new();
        let mut manager = TunnelManager::new(TunnelSection::default(), targets.clone());
        manager.reconcile(None, Vec::new()).await;
        assert_eq!(manager.running_count(), 0);
        assert!(targets.is_empty());
    }
}
