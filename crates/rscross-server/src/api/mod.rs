//! 控制台与 Agent 的 HTTP API。

pub mod agent;
pub mod auth;
pub mod client;
pub mod misc;

use axum::routing::{get, patch, post};
use axum::Router;
use rscross_common::DesiredTunnel;
use rscross_store::TunnelRecord;

use crate::console;
use crate::state::AppState;

/// Agent 认证头。
pub const AGENT_HEADER: &str = "x-rscross-agent";

/// 组装路由。
///
/// 注意：
/// - 同一路径的多个方法必须写在**同一个** `MethodRouter` 上（`get(a).post(b)`），
///   分成两次 `.route()` 会让 axum 在启动时 panic。
/// - 这里**不注册**通配路由，全部交给 [`console::fallback`] 处理，
///   这样 `/api/v1/未知路径` 才会返回 JSON 404 而不是被 SPA 首页吞掉。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/health", get(misc::health))
        // 控制台认证
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/password", post(auth::change_password))
        // 概览 / 报表
        .route("/api/v1/overview", get(misc::overview))
        .route("/api/v1/traffic", get(misc::traffic))
        // 客户端
        .route("/api/v1/clients", get(client::list_clients).post(client::create_client))
        .route(
            "/api/v1/clients/{id}",
            get(client::get_client)
                .patch(client::patch_client)
                .delete(client::delete_client),
        )
        .route(
            "/api/v1/clients/{id}/tunnels",
            get(client::list_client_tunnels).post(client::create_tunnel),
        )
        // 隧道
        .route("/api/v1/tunnels", get(client::list_tunnels))
        .route(
            "/api/v1/tunnels/{id}",
            patch(client::patch_tunnel).delete(client::delete_tunnel),
        )
        // 审计 / 日志 / 配置
        .route("/api/v1/logs", get(misc::logs))
        .route("/api/v1/audit", get(misc::audit_log))
        .route("/api/v1/config", get(misc::get_config).put(misc::put_config))
        // Agent（内网节点）
        .route("/api/v1/agent/enroll", post(agent::enroll))
        .route("/api/v1/agent/heartbeat", post(agent::heartbeat))
        .route("/api/v1/agent/tunnels", get(agent::tunnels))
        .route("/api/v1/agent/logs", post(agent::push_logs))
        .fallback(console::fallback)
}

/// 把数据库里的隧道记录转成「下发给客户端」的形态。
///
/// - 只保留启用项；
/// - 协议字符串无法识别时跳过并告警（而不是让整个心跳失败）；
/// - 客户端不依赖 `rusqlite`，所以这里做一次 DTO 转换。
pub fn desired_tunnels(records: Vec<TunnelRecord>) -> Vec<DesiredTunnel> {
    records
        .into_iter()
        .filter(|t| t.enabled)
        .filter_map(|t| {
            let Some(proto) = parse_proto(&t.proto) else {
                tracing::warn!(tunnel = %t.name, proto = %t.proto, "隧道协议无法识别，跳过下发");
                return None;
            };
            Some(DesiredTunnel {
                id: t.id,
                name: t.name,
                proto,
                local_addr: t.local_addr,
                remote_port: t.remote_port.and_then(|p| u16::try_from(p).ok()),
                host: t.host,
                path_prefix: t.path_prefix,
                enabled: t.enabled,
                rate_limit_kbps: u32::try_from(t.rate_limit_kbps.max(0)).unwrap_or(0),
                conn_limit: u32::try_from(t.conn_limit.max(0)).unwrap_or(0),
            })
        })
        .collect()
}

/// 校验隧道协议字符串。
pub fn parse_proto(raw: &str) -> Option<rscross_common::TunnelProto> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(rscross_common::TunnelProto::Tcp),
        "http" => Some(rscross_common::TunnelProto::Http),
        "https" => Some(rscross_common::TunnelProto::Https),
        "udp" => Some(rscross_common::TunnelProto::Udp),
        _ => None,
    }
}

/// 归一化并校验客户端名（用于唯一索引与展示）。
pub fn normalize_name(raw: &str) -> Result<String, crate::error::ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(crate::error::ApiError::bad_request("名称不能为空"));
    }
    if name.len() > 64 {
        return Err(crate::error::ApiError::bad_request("名称不能超过 64 个字符"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(crate::error::ApiError::bad_request(
            "名称只能包含字母、数字、'-'、'_'、'.'",
        ));
    }
    Ok(name.to_string())
}
