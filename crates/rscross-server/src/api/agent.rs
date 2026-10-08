//! Agent（内网节点）侧 API：注册、心跳、拉取隧道、上报日志。
//!
//! 鉴权方式与控制台不同：Agent 用 `X-Rscross-Agent: <agent_token>`，
//! 服务端只存 token 的 SHA-256 摘要。

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use rscross_auth::{new_agent_token, token_hash};
use rscross_common::{ClientRuntime, DesiredTunnel};
use rscross_store::ClientRecord;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::api::AGENT_HEADER;
use crate::error::ApiError;
use crate::state::AppState;

/// 注册请求。
#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// 控制台签发的接入令牌（`auth.allow_self_enroll = true` 时可省略）。
    pub token: Option<String>,
    /// 期望的节点名。
    pub name: Option<String>,
    /// 运行时信息。
    #[serde(default)]
    pub runtime: ClientRuntime,
}

/// 注册响应。
#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    /// 分配到的客户端 ID。
    pub client_id: String,
    /// agent token（明文，仅此一次返回）。
    pub agent_token: String,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// FerroTunnel 控制面地址。
    pub tunnel_server: String,
    /// FerroTunnel 握手 token。
    pub tunnel_token: String,
    /// 服务端对外地址。
    pub public_url: Option<String>,
    /// P2P 参数。
    pub p2p: P2pInfo,
    /// 已下发的隧道列表。
    pub tunnels: Vec<DesiredTunnel>,
}

/// P2P 参数（下发给客户端）。
#[derive(Debug, Clone, Serialize)]
pub struct P2pInfo {
    /// 是否启用。
    pub enabled: bool,
    /// 路径策略。
    pub policy: String,
    /// 服务端节点 ID。
    pub server_endpoint_id: Option<String>,
    /// 服务端寻址信息（JSON）。
    pub server_endpoint_addr: Option<String>,
    /// Relay 模式。
    pub relay_mode: String,
    /// 是否启用地址发现。
    pub address_lookup: bool,
}

/// 心跳请求。
#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    /// 运行时信息。
    #[serde(default)]
    pub runtime: ClientRuntime,
}

/// 心跳响应。
#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    /// 下一次心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 服务端当前时间。
    pub server_time: String,
    /// 服务端观测到的出口 IP。
    pub public_ip: Option<String>,
    /// P2P 参数。
    pub p2p: P2pInfo,
    /// 期望的隧道配置（客户端据此收敛本地 FerroTunnel 客户端）。
    pub tunnels: Vec<DesiredTunnel>,
}

/// 客户端上报的单条日志。
#[derive(Debug, Deserialize)]
pub struct ClientLogEntry {
    /// 级别。
    pub level: String,
    /// 正文。
    pub message: String,
    /// 目标模块。
    pub target: Option<String>,
}

/// `POST /api/v1/agent/enroll`
pub async fn enroll(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let cfg = state.config_snapshot().await;
    let raw_token = req.token.as_deref().unwrap_or("").trim().to_string();

    let enroll = if raw_token.is_empty() {
        if !cfg.auth.allow_self_enroll {
            return Err(ApiError::unauthorized(
                "需要有效的接入令牌（服务端已关闭自助注册）",
            ));
        }
        None
    } else {
        let hash = token_hash(&raw_token);
        let rec = state
            .store
            .find_enroll_token(&hash)
            .await
            .map_err(ApiError::from)?;
        let Some(rec) = rec else {
            return Err(ApiError::unauthorized("接入令牌无效"));
        };
        if rec.used_at.is_some() {
            return Err(ApiError::unauthorized("接入令牌已被使用"));
        }
        if rec.expires_at < rscross_common::time::now_rfc3339() {
            return Err(ApiError::unauthorized("接入令牌已过期"));
        }
        Some(rec)
    };

    if cfg.limits.max_clients > 0 {
        let count = state.store.count_clients().await.map_err(ApiError::from)?;
        if count >= i64::from(cfg.limits.max_clients) {
            return Err(ApiError::forbidden(format!(
                "客户端数量已达上限 {}",
                cfg.limits.max_clients
            )));
        }
    }

    let desired_name = enroll
        .as_ref()
        .and_then(|e| e.client_name.clone())
        .or_else(|| req.name.clone())
        .unwrap_or_else(|| format!("node-{}", short_id()));

    let name = unique_name(&state, desired_name).await?;

    let agent_token = new_agent_token();
    let client_id = uuid::Uuid::new_v4().to_string();
    let now = rscross_common::time::now_rfc3339();

    state
        .store
        .insert_client(ClientRecord {
            id: client_id.clone(),
            name: name.clone(),
            status: rscross_common::ClientStatus::Pending.as_str().to_string(),
            agent_token_hash: token_hash(&agent_token),
            version: non_empty(&req.runtime.version),
            os: non_empty(&req.runtime.os),
            arch: non_empty(&req.runtime.arch),
            endpoint_id: non_empty_opt(&req.runtime.endpoint_id),
            endpoint_addr: non_empty_opt(&req.runtime.endpoint_addr),
            public_ip: Some(peer.ip().to_string()),
            last_seen_at: None,
            last_error: None,
            created_at: now.clone(),
            updated_at: now,
        })
        .await
        .map_err(ApiError::from)?;

    if let Some(rec) = &enroll {
        if let Err(err) = state
            .store
            .consume_enroll_token(&rec.token_hash, &client_id)
            .await
        {
            // 令牌竞态：回滚已创建的客户端，避免留下「无名孤儿」
            let _ = state.store.delete_client(&client_id).await;
            return Err(ApiError::from(err));
        }
    }

    let tunnels = state
        .store
        .list_tunnels_of_client(&client_id)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(
        client = %name,
        id = %client_id,
        peer = %peer,
        os = req.runtime.os,
        arch = req.runtime.arch,
        "客户端已注册"
    );

    Ok(Json(EnrollResponse {
        client_id,
        agent_token,
        heartbeat_secs: cfg.server.heartbeat_secs,
        tunnel_server: public_tunnel_addr(&cfg),
        tunnel_token: cfg.tunnel.token.clone(),
        public_url: cfg.server.public_url.clone(),
        p2p: p2p_info(&state, &cfg),
        tunnels: crate::api::desired_tunnels(tunnels),
    }))
}

/// `POST /api/v1/agent/heartbeat`
pub async fn heartbeat(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let (cfg, client) = authenticate_agent(&state, &headers).await?;

    state
        .store
        .touch_client(
            client.id.clone(),
            rscross_store::ClientRuntimePatch {
                version: non_empty_opt(&req.runtime.version),
                os: non_empty_opt(&req.runtime.os),
                arch: non_empty_opt(&req.runtime.arch),
                endpoint_id: non_empty_opt(&req.runtime.endpoint_id),
                endpoint_addr: non_empty_opt(&req.runtime.endpoint_addr),
                public_ip: Some(peer.ip().to_string()),
            },
        )
        .await
        .map_err(ApiError::from)?;

    let tunnels = state
        .store
        .list_tunnels_of_client(&client.id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(HeartbeatResponse {
        heartbeat_secs: cfg.server.heartbeat_secs,
        server_time: rscross_common::time::now_rfc3339(),
        public_ip: Some(peer.ip().to_string()),
        p2p: p2p_info(&state, &cfg),
        tunnels: crate::api::desired_tunnels(tunnels),
    }))
}

/// `GET /api/v1/agent/tunnels`
pub async fn tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DesiredTunnel>>, ApiError> {
    let (_cfg, client) = authenticate_agent(&state, &headers).await?;
    let tunnels = state
        .store
        .list_tunnels_of_client(&client.id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(crate::api::desired_tunnels(tunnels)))
}

/// `POST /api/v1/agent/logs`
pub async fn push_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(entries): Json<Vec<ClientLogEntry>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (_cfg, client) = authenticate_agent(&state, &headers).await?;
    let mut accepted = 0usize;

    for entry in entries.into_iter().take(500) {
        let level = entry.level.to_uppercase();
        let event = crate::logbus::LogEvent {
            seq: 0,
            ts: rscross_common::time::now_rfc3339(),
            level: level.clone(),
            target: entry
                .target
                .unwrap_or_else(|| format!("rscross-client/{}", client.name)),
            message: entry.message.clone(),
        };
        state.logs.push(event);
        if let Err(err) = state
            .store
            .insert_log(rscross_store::LogEntry {
                id: 0,
                ts: rscross_common::time::now_rfc3339(),
                level,
                target: Some(format!("rscross-client/{}", client.name)),
                message: entry.message,
                client_id: Some(client.id.clone()),
                tunnel_id: None,
            })
            .await
        {
            tracing::warn!(error = %err, "客户端日志落库失败");
        }
        accepted += 1;
    }

    Ok(Json(serde_json::json!({ "accepted": accepted })))
}

async fn authenticate_agent(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(rscross_config::ServerFile, ClientRecord), ApiError> {
    let token = headers
        .get(AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::unauthorized("缺少 X-Rscross-Agent 头"))?;

    let client = state
        .store
        .find_client_by_token_hash(&token_hash(token))
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("agent token 无效"))?;

    if client.disabled {
        return Err(ApiError::forbidden("客户端已被禁用"));
    }

    let cfg = state.config_snapshot().await;
    Ok((cfg, client))
}

fn p2p_info(state: &AppState, cfg: &rscross_config::ServerFile) -> P2pInfo {
    let enabled = state.p2p.is_some() && cfg.p2p.enabled;
    P2pInfo {
        enabled,
        policy: state.path_selector.policy().as_str().to_string(),
        server_endpoint_id: state.p2p.as_ref().map(|node| node.id_string()),
        server_endpoint_addr: state
            .p2p
            .as_ref()
            .and_then(|node| node.addr_json().ok()),
        relay_mode: cfg.p2p.relay_mode.clone(),
        address_lookup: cfg.p2p.address_lookup,
    }
}

fn public_tunnel_addr(cfg: &rscross_config::ServerFile) -> String {
    let host = cfg
        .server
        .public_url
        .as_deref()
        .map(|url| {
            let no_scheme = url.split("://").nth(1).unwrap_or(url);
            let host_port = no_scheme.split('/').next().unwrap_or(no_scheme);
            host_port.split(':').next().unwrap_or(host_port).to_string()
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            cfg.server
                .tunnel_bind
                .parse::<SocketAddr>()
                .map(|a| {
                    if a.ip().is_unspecified() {
                        "127.0.0.1".to_string()
                    } else {
                        a.ip().to_string()
                    }
                })
                .unwrap_or_else(|_| "127.0.0.1".to_string())
        });

    let port = cfg
        .server
        .tunnel_bind
        .parse::<SocketAddr>()
        .map(|a| a.port())
        .unwrap_or(rscross_common::DEFAULT_TUNNEL_PORT);

    format!("{host}:{port}")
}

/// 名称去重：`name`、`name-2`、`name-3`… 最多尝试 20 次。
async fn unique_name(state: &AppState, desired: String) -> Result<String, ApiError> {
    let existing: std::collections::HashSet<String> = state
        .store
        .list_clients()
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .map(|c| c.name)
        .collect();

    if !existing.contains(&desired) {
        return Ok(desired);
    }
    for suffix in 2..=20 {
        let candidate = format!("{desired}-{suffix}");
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(format!("名称 {desired} 及其派生名均已被占用")))
}

fn non_empty(value: &str) -> Option<String> {
    non_empty_opt(&Some(value.to_string()))
}

fn non_empty_opt(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}
