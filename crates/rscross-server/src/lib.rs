//! rscross-server —— rscross 服务端
//!
//! 提供管理后台 API、节点调度与穿透控制面。

pub mod api;
pub mod assets;
pub mod config;
pub mod db;
pub mod engine;
pub mod model;
pub mod rpc;

use anyhow::Result;

/// 服务端上下文，全局共享
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::ServerConfig>,
    pub db: Arc<db::Database>,
    pub engine: Arc<engine::EngineRegistry>,
    pub cache: Arc<rpc::Cache>,
}

use std::sync::Arc;

use crate::db::Database;

/// 启动服务端
pub async fn run() -> Result<()> {
    let cfg = config::ServerConfig::load()?;
    rscross_common::logger::init(
        Some(std::path::Path::new("logs")),
        &cfg.log_level,
        true,
    )?;

    tracing::info!(
        "rscross-server v{} 启动中，模式 {}",
        rscross_common::VERSION,
        cfg.mode
    );

    let db = Arc::new(Database::new(&cfg).await?);
    let engine = Arc::new(engine::EngineRegistry::new());
    let cache = Arc::new(rpc::Cache::new());

    let state = AppState {
        config: Arc::new(cfg),
        db,
        engine,
        cache,
    };

    // 初始化默认数据
    state.db.init_default_data().await?;
    state.engine.sync_all(&state.db).await;

    let addr = rscross_common::util::resolve_bind_addr(&state.config.address)?;
    tracing::info!("HTTP 服务监听于 {addr}");

    api::serve(addr, state).await
}
