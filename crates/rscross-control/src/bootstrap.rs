//! 控制台进程的装配逻辑。
//!
//! 独立二进制 [`run_console`] 与「服务端内嵌模式」共用 [`build_plane`] 与 [`init_logging`]，
//! 保证两种形态的初始化顺序、初始管理员策略、日志行为完全一致。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rscross_auth::{hash_password, LoginThrottle};
use rscross_common::{Error, Result};
use rscross_config::{ConsoleFile, LogSection};
use rscross_store::Store;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::logbus::LogBus;
use crate::plane::ControlPlane;
use crate::state::AppState;

/// 独立控制台命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "rscross-console",
    version,
    about = "rscross 独立控制台：汇聚多个服务端节点与内网客户端"
)]
pub struct ConsoleArgs {
    /// 配置文件路径（不存在时自动生成默认配置）。
    #[arg(
        short,
        long,
        default_value = "rscross-console.toml",
        env = "RSROSS_CONSOLE_CONFIG"
    )]
    pub config: PathBuf,
    /// 覆盖监听地址。
    #[arg(long)]
    pub bind: Option<String>,
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

/// 独立控制台入口。
pub async fn run_console() -> Result<()> {
    let args = ConsoleArgs::parse();
    run_console_with(args).await
}

/// `--print-default-config` 打印的默认配置。
///
/// 抽成函数并加单测，是因为这里曾经用 `ConsoleFile::default()`（7800），
/// 而首次启动生成的是 `central_default()`（7700）—— 打印与实际生成的端口不一致，
/// 用户照着打印结果改配置就会对不上。由 e2e 断言抓出，现在用单测兜住。
pub fn console_default_config() -> ConsoleFile {
    ConsoleFile::central_default()
}

/// 用给定参数启动独立控制台（便于测试直接调用）。
pub async fn run_console_with(args: ConsoleArgs) -> Result<()> {
    if args.print_default_config {
        let text = toml::to_string_pretty(&console_default_config())
            .map_err(|e| Error::config(format!("序列化默认配置失败: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    // 独立中央控制台：默认端口 7700，与内嵌控制台（7800）区分。
    // 两者可能同时跑在一台机器上，且端口号本身就能提示浏览器连的是哪一套。
    let mut cfg = ConsoleFile::load_or_init_central(&args.config)?;
    if let Some(v) = args.bind.clone() {
        cfg.console.bind = v;
    }
    if let Some(v) = args.log_level.clone() {
        cfg.log.level = v;
    }
    cfg.validate()?;

    if args.check {
        println!("配置校验通过: {}", args.config.display());
        println!("控制台前端: {}", crate::console::diagnose());
        return Ok(());
    }

    let bus = LogBus::new(cfg.log.ring_capacity);
    init_logging(&cfg.log, bus.clone());

    tracing::info!(
        version = rscross_common::VERSION,
        config = %args.config.display(),
        "rscross-console 启动中"
    );

    let shutdown = CancellationToken::new();
    let plane = build_plane(
        cfg.clone(),
        args.config.clone(),
        bus,
        false,
        shutdown.clone(),
    )
    .await?;

    let addr: SocketAddr = cfg
        .console
        .bind
        .parse()
        .map_err(|e| Error::config(format!("console.bind 非法: {e}")))?;
    let listener = ControlPlane::bind(addr).await?;

    // 信号监听与 HTTP 服务并行；信号触发后 cancel 让 serve 优雅退出。
    let signal = tokio::spawn({
        let token = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::warn!("收到退出信号，开始优雅关停");
            token.cancel();
        }
    });

    plane.serve(listener, shutdown.clone()).await?;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), signal).await;

    tracing::info!("rscross-console 已退出");
    Ok(())
}

/// 装配控制面：打开数据库、创建初始管理员、构造共享状态。
///
/// `embedded = true` 时表示控制台跑在服务端进程里（单机自用）。
pub async fn build_plane(
    cfg: ConsoleFile,
    config_path: PathBuf,
    bus: LogBus,
    embedded: bool,
    shutdown: CancellationToken,
) -> Result<ControlPlane> {
    let store = Store::open(
        &cfg.database.path,
        cfg.database.wal,
        cfg.database.busy_timeout_ms,
        cfg.log.persist,
    )?;
    ensure_initial_admin(&store, &cfg).await?;

    let state = AppState {
        store,
        config: Arc::new(tokio::sync::RwLock::new(cfg)),
        config_path: Arc::new(config_path),
        started_at: rscross_common::time::now(),
        throttle: Arc::new(LoginThrottle::new()),
        logs: bus,
        shutdown,
        embedded,
    };
    Ok(ControlPlane::new(state))
}

/// 初始化 `tracing`：stdout（text/json）+ 控制面日志环形缓冲。
pub fn init_logging(section: &LogSection, bus: LogBus) {
    let filter = EnvFilter::try_new(&section.level).unwrap_or_else(|err| {
        eprintln!(
            "日志过滤表达式非法（{}），回退到 info: {err}",
            section.level
        );
        EnvFilter::new("info")
    });
    let bus_layer = bus.layer();

    if section.format == "json" {
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

/// 首次启动时创建管理员。
///
/// 生成的密码**只走标准错误输出**，不经过 `tracing`，因此不会进入环形缓冲或数据库
/// —— 否则任何已登录用户都能从控制台「日志」页读到它。
pub async fn ensure_initial_admin(store: &Store, cfg: &ConsoleFile) -> Result<()> {
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
        eprintln!();
        eprintln!("============================================================");
        eprintln!(" 已创建控制台管理员账号，请立即登录并修改密码");
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

/// 等待 SIGINT / SIGTERM。
pub async fn wait_for_signal() {
    // 具体监听哪些信号由 common 决定：Windows 上除了 Ctrl+C 还要接住
    // Ctrl+Break / 控制台关闭 / 注销 / 关机 —— 只监听 Ctrl+C 时，
    // 「停止服务」「结束任务」「注销」都会变成强制结束，SQLite 来不及收尾。
    rscross_common::signal::wait_for_shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printed_default_config_matches_what_startup_generates() {
        // 独立中央控制台：打印出来的默认端口必须是 7700，
        // 且与 `load_or_init_central` 首次生成的一致（同一来源）。
        let printed = console_default_config();
        assert_eq!(printed.bind_port(), Some(7700));
        assert_eq!(
            printed.console.bind,
            ConsoleFile::central_default().console.bind,
            "打印的默认配置必须与启动时生成的同源"
        );

        // 内嵌控制台的默认值不受影响
        assert_eq!(ConsoleFile::default().bind_port(), Some(7800));
        assert_ne!(printed.bind_port(), ConsoleFile::default().bind_port());
    }
}
