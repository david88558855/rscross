//! `rscross-client` 可执行入口。

#[tokio::main]
async fn main() {
    if let Err(err) = rscross_client::run().await {
        eprintln!("rscross-client 启动失败: {err}");
        std::process::exit(1);
    }
}
