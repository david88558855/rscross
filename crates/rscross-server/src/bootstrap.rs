//! 启动流程、任务编排与优雅关停。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rscross_auth::{hash_password, LoginThrottle};
use rscross_common::{Error, Result};
use rscross_config::ServerFile;
use rscross_store::Store;
use rscross_transport::{P2pNode, P2pOptions, PathSelector, RelayServer};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::api::router;
use crate::logbus::LogBus;
use crate::state::AppState;

/// 命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "rscross-server",
    version,
    about = "rscross 服务端：反向隧道中继 + P2P 直连调度 + Web 控制台"
)]
pub struct Args {
    /// 配置文件路径（不存在时自动生成默认配置）。
    #[arg(short, long, default_value = "rscross-server.toml", env = "RSROSS_SERVER_CONFIG")]
    pub config: PathBuf,
    /// 覆盖管理 API / 控制台监听地址。
    #[arg(long)]
    pub admin_bind: Option<String>,
    /// 覆盖公网入口监听地址（FerroTunnel HTTP ingress）。
    #[arg(long)]
    pub ingress_bind: Option<String>,
    /// 覆盖反向隧道控制面监听地址。
    #[arg(long)]
    pub tunnel_bind: Option<String>,
    /// 覆盖日志级别。
    #[arg(long)]
    pub log_level: Option<String>,
    /// 只生成 / 校验配置后退出。
    #[arg(long)]
    pub check: bool,
    /// 打印默认配置到标准输出后退出。
    #[arg(long)]
    pub print_default_config: bool,
}

/// 入口。
pub async fn run() -> Result<()> {
    let args = Args::parse();
    run_with_args(args).await
}

/// 用给定参数启动（便于集成测试直接调用）。
pub async fn run_with_args(args: Args) -> Result<()> {
    if args.print_default_config {
        let text = toml::to_string_pretty(&ServerFile::default())
            .map_err(|e| Error::config(format!("序列化默认配置失败: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    let mut cfg = ServerFile::load_or_init(&args.config)?;
    if let Some(v) = args.admin_bind.clone() {
        cfg.server.admin_bind = v;
    }
    if let Some(v) = args.ingress_bind.clone() {
        cfg.server.ingress_bind = v;
    }
    if let Some(v) = args.tunnel_bind.clone() {
        cfg.server.tunnel_bind = v;
    }
    if let Some(v) = args.log_level.clone() {
        cfg.log.level = v;
    }
    cfg.validate()?;

    if args.check {
        println!("配置校验通过: {}", args.config.display());
        return Ok(());
    }

    // 日志必须在其它一切之前就绪，才能捕获后续所有初始化日志。
    let bus = LogBus::new(cfg.log.ring_capacity);
    init_tracing(&cfg, bus.clone());

    tracing::info!(
        version = rscross_common::VERSION,
        config = %args.config.display(),
        "rscross-server 启动中"
    );

    let store = Store::open(
        &cfg.database.path,
        cfg.database.wal,
        cfg.database.busy_timeout_ms,
        cfg.log.persist,
    )?;
    ensure_initial_admin(&store, &cfg).await?;

    // Iroh 节点：失败不阻塞控制台，但会明确降级（路径策略只剩中继）。
    let p2p = match build_p2p(&cfg).await {
        Ok(node) => node,
        Err(err) => {
            tracing::error!(error = %err, "Iroh 节点初始化失败，本次运行将只使用 FerroTunnel 中继路径");
            None
        }
    };

    let shutdown = CancellationToken::new();
    let state = AppState {
        store: store.clone(),
        config: Arc::new(tokio::sync::RwLock::new(cfg.clone())),
        config_path: Arc::new(args.config.clone()),
        started_at: rscross_common::time::now(),
        throttle: Arc::new(LoginThrottle::new()),
        logs: bus.clone(),
        p2p,
        path_selector: Arc::new(PathSelector::new(cfg.p2p.policy)),
        shutdown: shutdown.clone(),
    };

    let mut tasks: Vec<(&'static str, tokio::task::JoinHandle<()>)> = Vec::new();

    // ---- 1. FerroTunnel 中继服务端 ----
    let ingress_bind = parse_addr(&cfg.server.ingress_bind, "server.ingress_bind")?;
    let tunnel_bind = parse_addr(&cfg.server.tunnel_bind, "server.tunnel_bind")?;
    match RelayServer::build(tunnel_bind, ingress_bind, &cfg.tunnel) {
        Ok(relay) => {
            let token = shutdown.clone();
            tasks.push((
                "ferrotunnel-relay",
                tokio::spawn(async move {
                    if let Err(err) = relay.run(token).await {
                        tracing::error!(error = %err, "FerroTunnel 中继退出");
                    }
                }),
            ));
        }
        Err(err) => {
            tracing::error!(error = %err, "FerroTunnel 中继构建失败，反向隧道路径不可用");
        }
    }

    // ---- 2. 内务循环 ----
    let housekeeping_state = state.clone();
    tasks.push((
        "housekeeping",
        tokio::spawn(async move { housekeeping(housekeeping_state).await }),
    ));

    // ---- 3. 日志落库 ----
    if cfg.log.persist {
        let persist_state = state.clone();
        tasks.push((
            "log-persist",
            tokio::spawn(async move { persist_logs(persist_state).await }),
        ));
    }

    // ---- 4. 信号监听 ----
    let signal_token = shutdown.clone();
    tasks.push((
        "signal",
        tokio::spawn(async move {
            wait_for_signal().await;
            tracing::warn!("收到退出信号，开始优雅关停");
            signal_token.cancel();
        }),
    ));

    // ---- 5. HTTP 服务（放最后，绑定失败能立刻返回错误）----
    let admin_addr = parse_addr(&cfg.server.admin_bind, "server.admin_bind")?;
    let listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .map_err(|e| Error::config(format!("绑定 {admin_addr} 失败: {e}")))?;
    let bound = listener
        .local_addr()
        .map_err(|e| Error::config(format!("读取实际监听地址失败: {e}")))?;

    tracing::info!(
        console = %format!("http://{bound}"),
        ingress = %ingress_bind,
        tunnel = %tunnel_bind,
        "控制台已就绪"
    );

    let http_state = state.clone();
    let app = router().with_state(http_state);
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown({
        let token = shutdown.clone();
        async move { token.cancelled().await }
    });

    if let Err(err) = serve.await {
        tracing::error!(error = %err, "HTTP 服务异常退出");
    }

    // HTTP 退出后，等待其它任务收敛。
    let grace = Duration::from_secs(cfg.server.shutdown_grace_secs.max(1));
    for (name, handle) in tasks {
        match tokio::time::timeout(grace, handle).await {
            Ok(Ok(())) => tracing::debug!(task = name, "任务已退出"),
            Ok(Err(err)) => tracing::warn!(task = name, error = %err, "任务 panic"),
            Err(_) => tracing::warn!(task = name, "任务未在宽限期内退出，强制放弃等待"),
        }
    }

    if let Some(node) = state.p2p.as_ref() {
        node.close().await;
    }

    tracing::info!("rscross-server 已退出");
    Ok(())
}

fn init_tracing(cfg: &ServerFile, bus: LogBus) {
    let filter = EnvFilter::try_new(&cfg.log.level).unwrap_or_else(|err| {
        eprintln!("日志过滤表达式非法（{}），回退到 info: {err}", cfg.log.level);
        EnvFilter::new("info")
    });
    let bus_layer = bus.layer();

    if cfg.log.format == "json" {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(false),
            )
            .with(bus_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .with(bus_layer)
            .init();
    }
}

async fn build_p2p(cfg: &ServerFile) -> Result<Option<P2pNode>> {
    if !cfg.p2p.enabled {
        tracing::info!("p2p.enabled = false，跳过 Iroh 节点初始化");
        return Ok(None);
    }

    let secret_key = match cfg.p2p.secret_key_file.as_deref() {
        Some(path) if !path.trim().is_empty() => Some(rscross_transport::load_or_create_secret_key(
            std::path::Path::new(path),
        )?),
        _ => None,
    };

    let node = P2pNode::bind(P2pOptions::from_section(&cfg.p2p, secret_key)).await?;

    // 上线等待不能无限期：没有外网时应当降级而不是卡死启动。
    match tokio::time::timeout(Duration::from_secs(15), node.wait_online()).await {
        Ok(()) => tracing::info!(endpoint_id = %node.id_string(), "Iroh 节点已上线"),
        Err(_) => tracing::warn!(
            endpoint_id = %node.id_string(),
            "等待 Iroh 上线超时（网络受限？），直连路径暂不可用，将回退中继"
        ),
    }

    Ok(Some(node))
}

async fn ensure_initial_admin(store: &Store, cfg: &ServerFile) -> Result<()> {
    if store.count_users().await? > 0 {
        return Ok(());
    }

    let generated = cfg.admin.initial_password.trim().is_empty();
    let password = if generated {
        rscross_config::random_token_hex(9)
    } else {
        cfg.admin.initial_password.clone()
    };

    let hash = {
        let password = password.clone();
        tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(|e| Error::internal(format!("初始管理员密码哈希任务失败: {e}")))??
    };

    store
        .create_user(cfg.admin.initial_user.clone(), hash, "admin".to_string())
        .await?;

    if generated {
        // 生成的密码只出现在标准错误输出，不进入环形缓冲与数据库，
        // 避免任何已登录用户从「日志」页读到它。
        eprintln!();
        eprintln!("============================================================");
        eprintln!(" 已创建初始管理员账号，请立即登录并修改密码");
        eprintln!("   用户名: {}", cfg.admin.initial_user);
        eprintln!("   密  码: {password}");
        eprintln!("============================================================");
        eprintln!();
        tracing::warn!(user = %cfg.admin.initial_user, "已创建初始管理员，密码请见进程标准错误输出");
    } else {
        tracing::warn!(user = %cfg.admin.initial_user, "已按配置创建初始管理员");
    }

    Ok(())
}

async fn housekeeping(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut rounds: u64 = 0;

    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            _ = ticker.tick() => {}
        }

        rounds += 1;
        let cfg = state.config_snapshot().await;

        let cutoff = rscross_common::time::to_rfc3339(
            rscross_common::time::now()
                - chrono::Duration::seconds(cfg.server.offline_after_secs as i64),
        );
        match state.store.mark_stale_clients_offline(cutoff).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "标记超时客户端为离线"),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "离线判定失败"),
        }

        if let Err(err) = state.store.purge_expired_sessions().await {
            tracing::warn!(error = %err, "清理过期会话失败");
        }
        state.throttle.sweep();

        // 保留期清理每小时一次即可。
        if rounds % 240 == 0 {
            if let Err(err) = state
                .store
                .purge_old_data(
                    cfg.database.traffic_retention_days,
                    cfg.database.log_retention_days,
                )
                .await
            {
                tracing::warn!(error = %err, "保留期清理失败");
            }
        }
    }
}

async fn persist_logs(state: AppState) {
    let mut rx = state.logs.subscribe();
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            received = rx.recv() => match received {
                Ok(event) => {
                    let entry = rscross_store::LogEntry {
                        id: 0,
                        ts: event.ts,
                        level: event.level,
                        target: Some(event.target),
                        message: event.message,
                        client_id: None,
                        tunnel_id: None,
                    };
                    if let Err(err) = state.store.insert_log(entry).await {
                        tracing::warn!(error = %err, "日志落库失败");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "日志订阅落后，已丢弃部分事件");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
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

fn parse_addr(raw: &str, field: &str) -> Result<SocketAddr> {
    raw.parse::<SocketAddr>()
        .map_err(|e| Error::config(format!("{field} 不是合法的监听地址({raw}): {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_rejects_garbage() {
        assert!(parse_addr("nope", "x").is_err());
        assert!(parse_addr("127.0.0.1:0", "x").is_ok());
    }

    #[test]
    fn default_config_passes_validation_after_token_fill() {
        let mut cfg = ServerFile::default();
        cfg.tunnel.token = rscross_config::random_token_hex(32);
        cfg.validate().expect("默认配置 + token 应当合法");
    }
}
