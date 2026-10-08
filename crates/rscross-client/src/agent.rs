//! 客户端主运行时：注册、心跳、隧道收敛、日志上报。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rscross_common::{ClientRuntime, DesiredTunnel, Error, Result};
use rscross_config::{ClientFile, TunnelSection};
use rscross_transport::{P2pDataHandler, P2pNode, P2pOptions, RelayTunnelClient, TunnelTargets};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::api::{ApiClient, EnrollRequest, HeartbeatRequest};
use crate::identity::{Identity, P2pSettings, StateDir};
use crate::logsink::{LogSink, LogSinkLayer};

/// 心跳失败后的指数退避上限。
const MAX_BACKOFF_SECS: u64 = 60;
/// 客户端日志上报周期。
const LOG_FLUSH_SECS: u64 = 30;
/// 单次上报的日志条数上限。
const LOG_FLUSH_BATCH: usize = 100;

/// 命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "rscross-client",
    version,
    about = "rscross 客户端：把内网服务通过反向隧道 / P2P 直连暴露出去"
)]
pub struct Args {
    /// 配置文件路径（不存在时自动生成默认配置）。
    #[arg(short, long, default_value = "rscross-client.toml", env = "RSROSS_CLIENT_CONFIG")]
    pub config: PathBuf,
    /// 控制面地址，例如 `http://1.2.3.4:7800`。
    #[arg(long, env = "RSROSS_SERVER")]
    pub server: Option<String>,
    /// FerroTunnel 控制面地址，例如 `1.2.3.4:7835`。
    #[arg(long)]
    pub tunnel_server: Option<String>,
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
    /// 强制关闭 P2P（只走 FerroTunnel 中继）。
    #[arg(long)]
    pub no_p2p: bool,
}

/// 入口（解析命令行）。
pub async fn run() -> Result<()> {
    let args = Args::parse();
    run_with_args(args).await
}

/// 用给定参数启动。
pub async fn run_with_args(args: Args) -> Result<()> {
    if args.print_default_config {
        let text = toml::to_string_pretty(&ClientFile::default())
            .map_err(|e| Error::config(format!("序列化默认配置失败: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    let mut cfg = ClientFile::load_or_init(&args.config)?;
    if let Some(v) = args.server.clone() {
        cfg.client.server_url = v;
    }
    if let Some(v) = args.tunnel_server.clone() {
        cfg.client.tunnel_server = v;
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

    let state_root = args
        .state_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(&cfg.client.state_dir));
    let state_dir = StateDir::open(state_root)?;

    let sink = LogSink::new(512);
    init_tracing(&cfg, sink.clone());

    tracing::info!(
        version = rscross_common::VERSION,
        config = %args.config.display(),
        state_dir = %state_dir.root().display(),
        server = %cfg.client.server_url,
        "rscross-client 启动中"
    );

    let api = ApiClient::new(&cfg.client.server_url)?;
    let shutdown = CancellationToken::new();

    // ---- 1. Iroh 节点（先建，注册时要把 EndpointId 一并上报）----
    let p2p = build_p2p(&cfg, &state_dir).await;

    // ---- 2. 注册（拿 agent token）----
    let mut identity = state_dir.load_identity();
    let provided_token = args
        .enroll_token
        .clone()
        .or_else(|| cfg.client.enroll_token.clone())
        .or_else(|| state_dir.load_enroll_token());

    let explicit_agent_token = cfg
        .client
        .agent_token
        .clone()
        .filter(|t| !t.trim().is_empty());

    if identity.agent_token.is_none() {
        identity.agent_token = explicit_agent_token;
    }

    if identity.agent_token.is_none() {
        register_with_retry(
            &api,
            &state_dir,
            &mut identity,
            &cfg,
            provided_token,
            &p2p,
            &shutdown,
        )
        .await?;
    }

    let agent_token = identity
        .agent_token
        .clone()
        .expect("注册成功后必然存在 agent token");

    // ---- 3. 反向隧道参数（token 以服务端下发为准）----
    let mut tunnel_section = cfg.tunnel.clone();
    if let Some(token) = identity.tunnel_token.clone() {
        if !token.trim().is_empty() {
            tunnel_section.token = token;
        }
    }
    let tunnel_server = identity
        .tunnel_server
        .clone()
        .unwrap_or_else(|| cfg.client.tunnel_server.clone());

    if tunnel_section.token.trim().is_empty() {
        tracing::warn!("未获得 FerroTunnel 握手 token，反向隧道路径将不可用（请检查服务端 tunnel.token）");
    }

    // ---- 4. P2P 数据面：接受服务端/对端开来的直连流 ----
    let targets = TunnelTargets::new();
    let router = p2p.as_ref().map(|node| {
        node.spawn_router(
            rscross_transport::ALPN_DATA,
            P2pDataHandler::new(targets.clone(), Duration::from_secs(5)),
        )
    });
    if let Some(info) = identity.p2p.as_ref() {
        tracing::info!(
            enabled = info.enabled,
            policy = %info.policy,
            server_endpoint = info.server_endpoint_id.as_deref().unwrap_or("-"),
            "P2P 参数已从控制面同步"
        );
    }

    // ---- 5. 后台任务 ----
    let heartbeat_secs = identity
        .heartbeat_secs
        .unwrap_or(rscross_common::DEFAULT_HEARTBEAT_SECS)
        .max(3);

    let heartbeat_task = {
        let api = api.clone();
        let shutdown = shutdown.clone();
        let token = agent_token.clone();
        let p2p = p2p.clone();
        let targets = targets.clone();
        tokio::spawn(async move {
            heartbeat_loop(
                api,
                token,
                heartbeat_secs,
                tunnel_server,
                tunnel_section,
                targets,
                p2p,
                shutdown,
            )
            .await;
        })
    };

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

    let _ = heartbeat_task.await;
    let _ = log_task.await;

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
            tracing::warn!(error = %err, "节点私钥不可用，本次运行将使用临时身份（重启后会变化）");
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
            tracing::error!(error = %err, "Iroh 节点绑定失败，本次运行只使用反向隧道");
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_with_retry(
    api: &ApiClient,
    state_dir: &StateDir,
    identity: &mut Identity,
    cfg: &ClientFile,
    provided_token: Option<String>,
    p2p: &Option<P2pNode>,
    shutdown: &CancellationToken,
) -> Result<()> {
    if provided_token.is_none() {
        tracing::warn!("没有可用的接入令牌，尝试自助注册（需要服务端 auth.allow_self_enroll = true）");
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
                identity.client_id = Some(response.client_id.clone());
                identity.agent_token = Some(response.agent_token.clone());
                identity.heartbeat_secs = Some(response.heartbeat_secs);
                identity.tunnel_server = Some(response.tunnel_server.clone());
                identity.tunnel_token = Some(response.tunnel_token.clone());
                identity.name = Some(cfg.client.name.clone());
                identity.p2p = Some(P2pSettings {
                    enabled: response.p2p.enabled,
                    policy: response.p2p.policy.clone(),
                    server_endpoint_id: response.p2p.server_endpoint_id.clone(),
                    server_endpoint_addr: response.p2p.server_endpoint_addr.clone(),
                    relay_mode: response.p2p.relay_mode.clone(),
                    address_lookup: response.p2p.address_lookup,
                });
                state_dir.save_identity(identity)?;
                state_dir.clear_enroll_token();

                tracing::info!(
                    client_id = %response.client_id,
                    name = %cfg.client.name,
                    public_url = response.public_url.as_deref().unwrap_or("-"),
                    "注册成功"
                );
                return Ok(());
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
    tunnel_server: String,
    tunnel_section: TunnelSection,
    targets: TunnelTargets,
    p2p: Option<P2pNode>,
    shutdown: CancellationToken,
) {
    let mut interval = initial_heartbeat_secs.max(3);
    let mut manager = TunnelManager::new(tunnel_server, tunnel_section, targets.clone());
    let mut consecutive_failures: u32 = 0;

    // 先立即做一次，不等第一个 tick。
    loop {
        let request = HeartbeatRequest {
            runtime: runtime_info(&p2p),
        };

        match api.heartbeat(&agent_token, &request).await {
            Ok(response) => {
                consecutive_failures = 0;
                if response.heartbeat_secs.max(3) != interval {
                    tracing::debug!(
                        from = interval,
                        to = response.heartbeat_secs,
                        "按控制面要求调整心跳间隔"
                    );
                    interval = response.heartbeat_secs.max(3);
                }
                manager.reconcile(response.tunnels).await;
                tracing::debug!(
                    tunnels = manager.running_count(),
                    p2p_peers = targets.len(),
                    "心跳成功"
                );
            }
            Err(err) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                tracing::warn!(
                    error = %err,
                    consecutive = consecutive_failures,
                    "心跳失败，控制面可能不可达"
                );
            }
        }

        // 心跳失败时逐步退避，但不超过 5 倍间隔，避免控制面恢复后长期失联。
        let sleep_secs = if consecutive_failures == 0 {
            interval
        } else {
            let bounded = interval.saturating_mul(u64::from(consecutive_failures.min(5)));
            bounded.min(MAX_BACKOFF_SECS * 5)
        };

        if !sleep_or_cancel(&shutdown, Duration::from_secs(sleep_secs)).await {
            break;
        }
    }

    manager.shutdown_all().await;
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

/// 隧道收敛器：让本地运行的 FerroTunnel 客户端集合与「期望配置」一致。
struct TunnelManager {
    server_addr: String,
    section: TunnelSection,
    targets: TunnelTargets,
    running: HashMap<String, RunningTunnel>,
}

struct RunningTunnel {
    name: String,
    route_key: String,
    local_addr: String,
    client: RelayTunnelClient,
}

impl TunnelManager {
    fn new(server_addr: String, section: TunnelSection, targets: TunnelTargets) -> Self {
        Self {
            server_addr,
            section,
            targets,
            running: HashMap::new(),
        }
    }

    fn running_count(&self) -> usize {
        self.running.len()
    }

    async fn reconcile(&mut self, desired: Vec<DesiredTunnel>) {
        let wanted: HashMap<String, DesiredTunnel> = desired
            .into_iter()
            .map(|tunnel| (tunnel.id.clone(), tunnel))
            .collect();

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
                self.server_addr.clone(),
                target.local_addr.clone(),
                &self.section,
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

            self.targets.set(route_key.clone(), target.local_addr.clone());
            tracing::info!(
                tunnel = %target.name,
                proto = %target.proto,
                local = %target.local_addr,
                route = %route_key,
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
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(error = %err, "无法注册 SIGTERM 处理，仅监听 Ctrl+C");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rscross_common::TunnelProto;

    fn tunnel(id: &str, name: &str, local: &str) -> DesiredTunnel {
        DesiredTunnel {
            id: id.to_string(),
            name: name.to_string(),
            proto: TunnelProto::Tcp,
            local_addr: local.to_string(),
            remote_port: None,
            host: None,
            path_prefix: None,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
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
    fn tunnel_manager_tracks_targets() {
        let targets = TunnelTargets::new();
        let manager = TunnelManager::new(
            "127.0.0.1:7835".to_string(),
            TunnelSection::default(),
            targets.clone(),
        );
        assert_eq!(manager.running_count(), 0);
        assert!(targets.is_empty());
        assert_eq!(tunnel("1", "a", "127.0.0.1:1").route_key(), "a");
    }
}
