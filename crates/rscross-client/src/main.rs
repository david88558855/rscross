//! rscross-client 入口

use clap::{Parser, Subcommand};

/// rscross 节点 / 客户端
#[derive(Parser, Debug)]
#[command(name = "rscross-client", version, about = "rscross 节点与客户端")]
struct Args {
    /// 服务端地址
    #[arg(short = 'a', long, default_value = "")]
    addr: String,

    /// 连接密钥
    #[arg(short = 'k', long, default_value = "")]
    key: String,

    /// 是否启用 TLS
    #[arg(long, default_value_t = false)]
    tls: bool,

    /// 以节点模式运行
    #[arg(short = 's', long, default_value_t = false)]
    node: bool,

    /// 代理服务地址（自定义域名网关）
    #[arg(long, default_value = "")]
    proxy: String,

    /// 日志级别
    #[arg(short = 'l', long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 访问私有隧道
    Visit {
        /// 目标地址，如 127.0.0.1:80
        #[arg(short = 't', long)]
        target: String,
        /// 隧道密钥
        #[arg(short = 'k', long)]
        vkey: String,
        /// 本地监听地址
        #[arg(short = 'l', long, default_value = "127.0.0.1:6000")]
        bind: String,
    },
    /// 打印版本信息
    Version,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(Command::Version) = args.command {
        println!("rscross-client v{}", rscross_common::VERSION);
        return;
    }

    // 访客模式
    if let Some(Command::Visit { target, vkey, bind }) = args.command {
        let services = std::sync::Arc::new(rscross_client::registry::ServiceRegistry::new());
        let visitor =
            rscross_client::visitor::Visitor::new(&target, &vkey, &bind, &args.addr, services);
        if let Err(e) = std::sync::Arc::new(visitor).run().await {
            eprintln!("访客启动失败: {e}");
            std::process::exit(1);
        }
        return;
    }

    // 注入配置
    std::env::set_var("RSC_ADDR", &args.addr);
    std::env::set_var("RSC_KEY", &args.key);
    std::env::set_var("RSC_TLS", if args.tls { "1" } else { "0" });
    std::env::set_var("RSC_NODE", if args.node { "1" } else { "0" });
    std::env::set_var("RSC_LOG_LEVEL", &args.log_level);
    if !args.proxy.is_empty() {
        std::env::set_var("RSC_PROXY_BASE_URL", &args.proxy);
    }

    if let Err(e) = rscross_client::run().await {
        eprintln!("启动失败: {e}");
        std::process::exit(1);
    }
}
