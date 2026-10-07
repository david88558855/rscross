//! 日志初始化：控制台 + 按天滚动文件

use std::path::Path;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// 初始化全局日志
///
/// - `log_dir`：日志目录，传 `None` 则只输出到控制台
/// - `level`：日志级别（trace/debug/info/warn/error）
/// - `to_stdout`：是否输出到标准输出（容器环境建议开启）
pub fn init(log_dir: Option<&Path>, level: &str, to_stdout: bool) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    // 过滤掉框架内部的噪音日志
    let filter = filter
        .add_directive("hyper=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("sqlx::query=info".parse()?)
        .add_directive("tower_http=info".parse()?)
        .add_directive("rsc=info".parse()?);

    let console_layer = fmt::layer()
        .with_target(true)
        .with_ansi(to_stdout);

    match log_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let file_name = dir.join("rsc.log");
            let file_layer = tracing_appender::rolling::daily(dir, "rsc.log");

            tracing_subscriber::registry()
                .with(filter)
                .with(console_layer)
                .with(
                    fmt::layer()
                        .with_writer(file_layer)
                        .with_ansi(false)
                        .with_target(true),
                )
                .try_init()?;
            tracing::info!("日志已初始化，文件: {}", file_name.display());
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(console_layer)
                .try_init()?;
        }
    }

    Ok(())
}
