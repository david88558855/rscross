//! 内网客户端侧 API：注册、心跳、拉取隧道、上报日志。
//!
//! 鉴权方式是 `X-Rscross-Agent: <agent_token>`；控制台只存 token 的 SHA-256 摘要。
//! **客户端归属哪个服务端节点**由注册时使用的接入令牌决定，之后每次心跳都会把
//! 该节点的数据面坐标（`tunnel_server` / `tunnel_token` / `EndpointAddr`）回带，
//! 因此控制台可以在不重启客户端的情况下完成「迁移到另一台节点」。

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use rscross_auth::{new_agent_token, token_hash};
use rscross_common::{ClientRuntime, DesiredTunnel, NodeEndpoint};
use rscross_store::{ClientRecord, ClientRuntimePatch, EnrollTokenRecord};
use serde::{Deserialize, Serialize};

use crate::api::nodes::{node_endpoint, resolve_node};
use crate::api::{desired_tunnels, header_token, AGENT_HEADER};
use crate::error::ApiError;
use crate::state::AppState;

/// 注册请求。
#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// 控制台签发的接入令牌（`auth.allow_self_enroll = true` 且只有一个节点时可省略）。
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
    /// 客户端名。
    pub name: String,
    /// agent token 明文（**只返回一次**）。
    pub agent_token: String,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 控制台对外地址。
    pub public_url: Option<String>,
    /// 归属的服务端节点（数据面坐标）。
    pub node: NodeEndpoint,
    /// 已下发的隧道列表。
    pub tunnels: Vec<DesiredTunnel>,
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
    /// 控制台当前时间。
    pub server_time: String,
    /// 控制台观测到的出口 IP。
    pub public_ip: Option<String>,
    /// 归属节点；为 `None` 表示该客户端已被解绑或节点被删除，
    /// 客户端应当停掉本地反向隧道。
    pub node: Option<NodeEndpoint>,
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

    let enroll: Option<EnrollTokenRecord> = if raw_token.is_empty() {
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
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::unauthorized("接入令牌无效"))?;
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

    // 归属节点：令牌里指定的优先，否则在「只有一个节点」时自动选中。
    let node = resolve_node(&state, enroll.as_ref().and_then(|e| e.node_id.as_deref())).await?;

    let desired_name = enroll
        .as_ref()
        .and_then(|e| e.client_name.clone())
        .or_else(|| req.name.clone())
        .unwrap_or_else(|| format!("client-{}", short_id()));

    let name = unique_client_name(&state, desired_name).await?;
    let agent_token = new_agent_token();
    let client_id = uuid::Uuid::new_v4().to_string();
    let now = rscross_common::time::now_rfc3339();

    state
        .store
        .insert_client(ClientRecord {
            id: client_id.clone(),
            node_id: Some(node.id.clone()),
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
        node = %node.name,
        peer = %peer,
        os = req.runtime.os,
        arch = req.runtime.arch,
        "客户端已注册"
    );

    Ok(Json(EnrollResponse {
        client_id,
        name,
        agent_token,
        heartbeat_secs: cfg.console.heartbeat_secs,
        public_url: cfg.console.public_url.clone(),
        node: node_endpoint(&node),
        tunnels: desired_tunnels(tunnels),
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
            ClientRuntimePatch {
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

    // 归属节点可能被删除/禁用：两种情况都要让客户端停掉隧道，而不是继续黑跑。
    let node = match client.node_id.as_deref() {
        Some(id) => match state.store.find_node(id).await.map_err(ApiError::from)? {
            Some(node) if !node.disabled => Some(node_endpoint(&node)),
            Some(node) => {
                tracing::warn!(client = %client.name, node = %node.name, "归属节点已被禁用，通知客户端下线");
                None
            }
            None => {
                tracing::warn!(client = %client.name, node_id = %id, "归属节点已被删除，通知客户端下线");
                None
            }
        },
        None => None,
    };

    let tunnels = if node.is_some() {
        desired_tunnels(
            state
                .store
                .list_tunnels_of_client(&client.id)
                .await
                .map_err(ApiError::from)?,
        )
    } else {
        Vec::new()
    };

    Ok(Json(HeartbeatResponse {
        heartbeat_secs: cfg.console.heartbeat_secs,
        server_time: rscross_common::time::now_rfc3339(),
        public_ip: Some(peer.ip().to_string()),
        node,
        tunnels,
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
    Ok(Json(desired_tunnels(tunnels)))
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
        let target = entry
            .target
            .clone()
            .unwrap_or_else(|| format!("rscross-client/{}", client.name));

        state.logs.push(crate::logbus::LogEvent {
            seq: 0,
            ts: rscross_common::time::now_rfc3339(),
            level: level.clone(),
            target: target.clone(),
            message: entry.message.clone(),
        });

        if let Err(err) = state
            .store
            .insert_log(rscross_store::LogEntry {
                id: 0,
                ts: rscross_common::time::now_rfc3339(),
                level,
                target: Some(target),
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

/// 客户端鉴权。
pub async fn authenticate_agent(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(rscross_config::ConsoleFile, ClientRecord), ApiError> {
    let token = header_token(headers, AGENT_HEADER)
        .ok_or_else(|| ApiError::unauthorized("缺少 X-Rscross-Agent 头"))?;

    let client = state
        .store
        .find_client_by_token_hash(&token_hash(&token))
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("agent token 无效"))?;

    if client.disabled {
        return Err(ApiError::forbidden("客户端已被禁用"));
    }

    let cfg = state.config_snapshot().await;
    Ok((cfg, client))
}

async fn unique_client_name(state: &AppState, desired: String) -> Result<String, ApiError> {
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
    for suffix in 2..=50 {
        let candidate = format!("{desired}-{suffix}");
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(format!(
        "名称 {desired} 及其派生名均已被占用"
    )))
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty_opt(value: &Option<String>) -> Option<String> {
    value.as_deref().and_then(non_empty)
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}
