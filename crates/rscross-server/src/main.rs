//! rscross-server 入口

use clap::Parser;

/// rscross 服务端
#[derive(Parser, Debug)]
#[command(name = "rscross-server", version, about = "rscross 服务端")]
struct Args {
    /// 配置文件路径
    #[arg(short, long)]
    config: Option<String>,

    /// 覆盖监听地址
    #[arg(short = 'a', long)]
    address: Option<String>,

    /// 覆盖日志级别
    #[arg(short = 'l', long)]
    log_level: Option<String>,

    /// 开发者模式，输出到控制台
    #[arg(short = 'd', long, default_value_t = false)]
    dev: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // 命令行覆盖
    if let Some(a) = &args.address {
        std::env::set_var("RSC_ADDRESS", a);
    }
    if let Some(l) = &args.log_level {
        std::env::set_var("RSC_LOG_LEVEL", l);
    }
    if args.dev {
        std::env::set_var("RSC_MODE", "dev");
    }
    if let Some(c) = &args.config {
        std::env::set_var("RSC_CONFIG", c);
    }

    if let Err(e) = rscross_server::run().await {
        eprintln!("启动失败: {e}");
        std::process::exit(1);
    }
}
