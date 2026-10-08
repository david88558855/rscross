//! `rscross-console` 可执行入口：**独立控制台**（多节点汇聚形态）。
//!
//! 单机自用不需要单独跑它 —— `rscross-server --embedded` 会在同一个进程里内嵌同样的控制面。

#[tokio::main]
async fn main() {
    if let Err(err) = rscross_control::run_console().await {
        eprintln!("rscross-console 启动失败: {err}");
        std::process::exit(1);
    }
}
