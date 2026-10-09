//! 概览、流量、日志、审计与配置 API。

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use rscross_config::ConsoleFile;
use rscross_store::{LogEntry, TrafficBucket};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::logbus::LogEvent;
use crate::state::AppState;

/// 配置中 token 字段的掩码。
pub const TOKEN_MASK: &str = "****";

/// `GET /api/v1/health`（免鉴权，供探活 / 负载均衡使用）
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let uptime = (rscross_common::time::now() - state.started_at).num_seconds();
    Json(serde_json::json!({
        "ok": true,
        "name": "rscross-console",
        "version": rscross_common::VERSION,
        "embedded": state.embedded,
        "started_at": rscross_common::time::to_rfc3339(state.started_at),
        "uptime_secs": uptime,
        "console_assets": crate::console::asset_count(),
    }))
}

/// 概览响应。
#[derive(Debug, Serialize)]
pub struct OverviewResponse {
    /// 数据库统计（节点 / 客户端 / 隧道 / 流量）。
    #[serde(flatten)]
    pub stats: rscross_store::OverviewStats,
    /// 最近 24 小时按小时聚合的流量。
    pub series: Vec<TrafficBucket>,
    /// 本控制台是否是内嵌形态。
    pub embedded: bool,
}

/// `GET /api/v1/overview`
pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OverviewResponse>, ApiError> {
    state.require_user(&headers).await?;
    let stats = state.store.overview().await.map_err(ApiError::from)?;
    let series = state
        .store
        .traffic_series(24)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(OverviewResponse {
        stats,
        series,
        embedded: state.embedded,
    }))
}

/// 流量趋势查询。
#[derive(Debug, Deserialize)]
pub struct TrafficQuery {
    /// 回溯小时数。
    pub hours: Option<i64>,
}

/// `GET /api/v1/traffic`
pub async fn traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<Vec<TrafficBucket>>, ApiError> {
    state.require_user(&headers).await?;
    let hours = query.hours.unwrap_or(24).clamp(1, 24 * 30);
    let series = state
        .store
        .traffic_series(hours)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(series))
}

/// 日志查询。
#[derive(Debug, Deserialize)]
pub struct LogQuery {
    /// 级别过滤（不区分大小写）。
    pub level: Option<String>,
    /// 关键字。
    pub q: Option<String>,
    /// 条数。
    pub limit: Option<usize>,
    /// `live`（内存环，默认）或 `db`（历史）。
    pub source: Option<String>,
}

/// 日志响应。
#[derive(Debug, Serialize)]
pub struct LogResponse {
    /// 来源。
    pub source: String,
    /// 环形缓冲容量。
    pub capacity: usize,
    /// 记录（最新在前）。
    pub entries: Vec<LogEntry>,
}

/// `GET /api/v1/logs`
pub async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Result<Json<LogResponse>, ApiError> {
    state.require_user(&headers).await?;
    let limit = query.limit.unwrap_or(200).clamp(1, 2000);
    let source = query.source.as_deref().unwrap_or("live");

    if source == "db" {
        let entries = state
            .store
            .query_logs(query.level.clone(), query.q.clone(), limit as i64)
            .await
            .map_err(ApiError::from)?;
        return Ok(Json(LogResponse {
            source: "db".to_string(),
            capacity: state.logs.capacity(),
            entries,
        }));
    }

    let live = state
        .logs
        .recent(limit, query.level.as_deref(), query.q.as_deref());
    let entries = live
        .into_iter()
        .map(|e: LogEvent| LogEntry {
            id: e.seq as i64,
            ts: e.ts,
            level: e.level,
            target: Some(e.target),
            message: e.message,
            client_id: None,
            tunnel_id: None,
        })
        .collect();

    Ok(Json(LogResponse {
        source: "live".to_string(),
        capacity: state.logs.capacity(),
        entries,
    }))
}

/// 审计查询。
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// 条数。
    pub limit: Option<i64>,
}

/// `GET /api/v1/audit`
pub async fn audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<rscross_store::AuditEntry>>, ApiError> {
    state.require_user(&headers).await?;
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    let entries = state
        .store
        .list_audit(limit)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(entries))
}

/// `GET /api/v1/config`
pub async fn get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.require_admin(&headers).await?;
    let cfg = state.config_snapshot().await;
    Ok(Json(serde_json::json!({
        "config": cfg,
        "config_path": state.config_path.display().to_string(),
        "readonly": !cfg.admin.allow_config_edit,
        "embedded": state.embedded,
    })))
}

/// `PUT /api/v1/config`
///
/// 语义：整份替换。控制台配置里没有需要掩码的秘密字段，
/// 但仍保留 `allow_config_edit` 开关以便托管场景锁定配置。
pub async fn put_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(next): Json<ConsoleFile>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let current = state.config_snapshot().await;

    if !current.admin.allow_config_edit {
        return Err(ApiError::forbidden(
            "配置已被锁定（admin.allow_config_edit = false）",
        ));
    }

    state.replace_config(next).await.map_err(ApiError::from)?;
    state
        .audit(
            Some(&user.id),
            "update_config",
            Some(state.config_path.display().to_string()),
            None,
            &headers,
        )
        .await;
    tracing::warn!("控制台配置已更新；监听地址类变更需要重启进程生效");
    Ok(Json(serde_json::json!({ "ok": true })))
}
