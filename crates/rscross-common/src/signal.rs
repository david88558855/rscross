//! 跨平台的「等待进程该退出了」信号。
//!
//! 为什么放在 common：`rscross-control`（控制台 / 服务端节点）与
//! `rscross-client` 都需要它，而这两者之间没有依赖关系 —— 复制两份必然漂移，
//! 而漂移的后果是「某个平台在某个进程里关不掉」。
//!
//! common 默认保持零外部依赖（见 `Cargo.toml`），所以本模块由 `runtime`
//! feature 启用，只有需要它的二进制才打开。

/// 等待任意一个「该退出了」的信号，返回后调用方应尽快完成优雅关停。
///
/// - **Unix**：`SIGTERM` 或 `SIGINT`（Ctrl+C）。注册 SIGTERM 失败时降级为只等 Ctrl+C。
/// - **Windows**：除了 Ctrl+C，还监听 Ctrl+Break、控制台关闭（点窗口的 ×、
///   任务管理器结束任务）、用户注销、系统关机。
///
/// Windows 那几项不是锦上添花：把一个程序当服务跑时，「停止服务」「注销」
/// 「关机」走的都是后面这些事件。只监听 Ctrl+C 的话，这些场景下进程会被
/// **强制结束** —— SQLite 的写事务没来得及收尾，日志也可能丢尾部。
///
/// 注意：Windows 对「控制台关闭 / 注销 / 关机」这几个事件只给进程很短的
/// 收尾时间（约 5 秒），因此调用方的关停逻辑不能依赖更长的宽限期。
#[cfg(feature = "runtime")]
pub async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!(error = %err, "无法注册 SIGTERM 处理，仅监听 Ctrl+C");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(windows)]
    {
        use std::future::pending;
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};

        // 注册失败不致命：能拿到几个就用几个，降级即可。
        let mut sigint = ctrl_c().ok();
        let mut sigbreak = ctrl_break().ok();
        let mut sigclose = ctrl_close().ok();
        let mut siglogoff = ctrl_logoff().ok();
        let mut sigshutdown = ctrl_shutdown().ok();

        if sigint.is_none() && sigbreak.is_none() && sigclose.is_none() {
            tracing::warn!(
                "无法注册任何关停信号处理，本进程只能被强制结束；\
                 若以服务方式运行，建议改为注册为控制台服务或用外部 watchdog"
            );
            pending::<()>().await;
            return;
        }

        // 展开成一个「该源存在就等它，不存在就永久挂起」的 future，
        // 这样 `select!` 里就不用手写五遍 None 分支。
        macro_rules! wait_on {
            ($opt:expr) => {
                async {
                    match $opt.as_mut() {
                        Some(stream) => {
                            stream.recv().await;
                        }
                        None => pending::<()>().await,
                    }
                }
            };
        }

        tokio::select! {
            _ = wait_on!(sigint) => {}
            _ = wait_on!(sigbreak) => {}
            _ = wait_on!(sigclose) => {}
            _ = wait_on!(siglogoff) => {}
            _ = wait_on!(sigshutdown) => {}
        }
    }

    // 既不是 Unix 也不是 Windows 的平台：只能等 Ctrl+C。
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
