//! `rscross-server` 可执行入口。

#[tokio::main]
async fn main() {
    if let Err(err) = rscross_server::run_node().await {
        eprintln!("rscross-server 启动失败: {err}");
        std::process::exit(1);
    }
}
