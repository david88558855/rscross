//! 服务端节点：控制台侧的管理 API + 节点侧的注册/心跳 API。
//!
//! 两套接口写在同一个模块里，因为它们共享同一批「节点供给」逻辑
//! （[`provision_node`] / [`apply_node_heartbeat`]）。这样内嵌模式可以直接调用这些函数，
//! 不必绕一圈 HTTP 再走鉴权。

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use rscross_auth::{new_node_token, token_hash};
use rscross_common::{NodeEndpoint, NodeRuntime};
use rscross_config::ConsoleFile;
use rscross_store::{NodePatch, NodeRecord, NodeRuntimePatch};
use serde::{Deserialize, Serialize};

use crate::api::{header_token, map_store_conflict, normalize_name, NODE_HEADER};
use crate::error::ApiError;
use crate::state::AppState;

// ============================================================ 节点供给

/// 控制台对外地址（用于生成接入命令）。
pub fn console_url_of(cfg: &ConsoleFile) -> String {
    if let Some(url) = cfg.console.public_url.as_deref() {
        let trimmed = url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    match cfg.console.bind.parse::<SocketAddr>() {
        Ok(addr) => {
            let host = if addr.ip().is_unspecified() {
                "127.0.0.1".to_string()
            } else {
                addr.ip().to_string()
            };
            format!("http://{host}:{}", addr.port())
        }
        Err(_) => format!("http://127.0.0.1:{}", rscross_common::DEFAULT_CONSOLE_PORT),
    }
}

/// 生成节点接入命令。
pub fn node_command(cfg: &ConsoleFile, name: &str, token: &str) -> String {
    format!(
        "rscross-server --managed --console {} --name {name} --enroll-token {token}",
        console_url_of(cfg)
    )
}

/// 创建一个节点并签发 node token。返回 `(记录, token 明文)`。
///
/// 明文只在此刻存在；库里只留 SHA-256 摘要。
pub async fn provision_node(
    state: &AppState,
    name: String,
    public_host: Option<String>,
    tunnel_token: Option<String>,
    created_by: Option<String>,
) -> Result<(NodeRecord, String), ApiError> {
    let cfg = state.config_snapshot().await;
    if cfg.limits.max_nodes > 0 {
        let count = state.store.count_nodes().await.map_err(ApiError::from)?;
        if count >= i64::from(cfg.limits.max_nodes) {
            return Err(ApiError::forbidden(format!(
                "节点数量已达上限 {}",
                cfg.limits.max_nodes
            )));
        }
    }

    let name = unique_node_name(state, name).await?;
    let token = new_node_token();
    let tunnel_token = tunnel_token
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| rscross_config::random_token_hex(32));
    let now = rscross_common::time::now_rfc3339();

    let record = NodeRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        status: rscross_common::ClientStatus::Pending.as_str().to_string(),
        node_token_hash: token_hash(&token),
        tunnel_token,
        public_host,
        tunnel_port: None,
        ingress_port: None,
        version: None,
        os: None,
        arch: None,
        endpoint_id: None,
        endpoint_addr: None,
        public_ip: None,
        last_seen_at: None,
        last_error: None,
        created_at: now.clone(),
        updated_at: now,
        disabled: false,
    };

    state
        .store
        .insert_node(record.clone())
        .await
        .map_err(map_store_conflict)?;

    tracing::info!(node = %record.name, id = %record.id, created_by = created_by.as_deref().unwrap_or("-"), "已创建服务端节点");

    Ok((record, token))
}

/// 轮换节点 token，返回新的明文。
pub async fn rotate_token(state: &AppState, node_id: &str) -> Result<String, ApiError> {
    let node = state
        .store
        .find_node(node_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;

    let token = new_node_token();
    // 复用 update 通道：这里直接改 token 摘要需要 store 支持，因此借助 patch 结构体不可行，
    // 改为「删掉再插回同一 id」不现实，遂在 store 侧提供专用方法。
    state
        .store
        .set_node_token_hash(&node.id, &token_hash(&token))
        .await
        .map_err(ApiError::from)?;

    tracing::warn!(node = %node.name, "节点 token 已轮换，旧 token 立即失效");
    Ok(token)
}

async fn unique_node_name(state: &AppState, desired: String) -> Result<String, ApiError> {
    let name = normalize_name(&desired)?;
    let existing: std::collections::HashSet<String> = state
        .store
        .list_nodes()
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .map(|n| n.name)
        .collect();

    if !existing.contains(&name) {
        return Ok(name);
    }
    for suffix in 2..=50 {
        let candidate = format!("{name}-{suffix}");
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(format!("名称 {name} 及其派生名均已被占用")))
}

/// 把节点记录转成客户端要用的数据面坐标。
pub fn node_endpoint(node: &NodeRecord) -> NodeEndpoint {
    NodeEndpoint {
        node_id: node.id.clone(),
        name: node.name.clone(),
        tunnel_server: node.tunnel_server(),
        tunnel_token: node.tunnel_token.clone(),
        endpoint_id: node.endpoint_id.clone(),
        endpoint_addr: node.endpoint_addr.clone(),
    }
}

/// 为客户端解析归属节点。
///
/// - 指定了 `node_id` → 必须是存在且启用的节点；
/// - 未指定且控制台里只有一个节点 → 自动选中（单机内嵌场景的默认行为）；
/// - 其余情况 → 报错，要求显式指定。
pub async fn resolve_node(
    state: &AppState,
    node_id: Option<&str>,
) -> Result<NodeRecord, ApiError> {
    if let Some(id) = node_id {
        let node = state
            .store
            .find_node(id)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::not_found("指定的服务端节点不存在"))?;
        if node.disabled {
            return Err(ApiError::forbidden(format!("节点 {} 已被禁用", node.name)));
        }
        return Ok(node);
    }

    let nodes = state.store.list_nodes().await.map_err(ApiError::from)?;
    match nodes.len() {
        0 => Err(ApiError::bad_request(
            "控制台里还没有服务端节点，请先创建节点并启动服务端",
        )),
        1 => {
            let node = nodes.into_iter().next().expect("len == 1");
            if node.disabled {
                return Err(ApiError::forbidden(format!("节点 {} 已被禁用", node.name)));
            }
            Ok(node)
        }
        _ => Err(ApiError::bad_request(
            "控制台里有多个服务端节点，必须在接入令牌里指定归属节点",
        )),
    }
}

// ============================================================ 管理侧 API

/// 创建节点请求。
#[derive(Debug, Deserialize)]
pub struct CreateNodeRequest {
    /// 节点名。
    pub name: String,
    /// 对外主机名（用于生成客户端接入地址），留空则用控制台观测到的出口 IP。
    pub public_host: Option<String>,
    /// 自定义 FerroTunnel 握手 token，留空则自动生成。
    pub tunnel_token: Option<String>,
}

/// 创建节点响应。
#[derive(Debug, Serialize)]
pub struct CreateNodeResponse {
    /// 节点记录。
    pub node: NodeRecord,
    /// node token 明文（**只返回一次**）。
    pub node_token: String,
    /// 在目标机器上执行的接入命令。
    pub command: String,
}

/// `GET /api/v1/nodes`
pub async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NodeRecord>>, ApiError> {
    state.require_user(&headers).await?;
    let nodes = state.store.list_nodes().await.map_err(ApiError::from)?;
    Ok(Json(nodes))
}

/// `POST /api/v1/nodes`
pub async fn create_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateNodeRequest>,
) -> Result<Json<CreateNodeResponse>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let cfg = state.config_snapshot().await;

    let (node, token) = provision_node(
        &state,
        req.name,
        req.public_host.filter(|s| !s.trim().is_empty()),
        req.tunnel_token,
        Some(user.username.clone()),
    )
    .await?;

    state
        .audit(
            Some(&user.id),
            "create_node",
            Some(node.name.clone()),
            Some(format!("id={}", node.id)),
            &headers,
        )
        .await;

    Ok(Json(CreateNodeResponse {
        command: node_command(&cfg, &node.name, &token),
        node,
        node_token: token,
    }))
}

/// `GET /api/v1/nodes/{id}`
pub async fn get_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.require_user(&headers).await?;
    let node = state
        .store
        .find_node(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;
    let clients = state
        .store
        .list_clients_of_node(&id)
        .await
        .map_err(ApiError::from)?;
    let tunnels = state
        .store
        .list_tunnels_of_node(&id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({
        "node": node,
        "endpoint": node_endpoint(&node),
        "clients": clients,
        "tunnels": tunnels,
    })))
}

/// 修改节点请求。
#[derive(Debug, Deserialize)]
pub struct PatchNodeRequest {
    /// 新名称。
    pub name: Option<String>,
    /// 对外主机名（传空字符串表示清空）。
    pub public_host: Option<String>,
    /// 启用 / 禁用。
    pub disabled: Option<bool>,
}

/// `PATCH /api/v1/nodes/{id}`
pub async fn patch_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<PatchNodeRequest>,
) -> Result<Json<NodeRecord>, ApiError> {
    let user = state.require_admin(&headers).await?;

    let name = match req.name.as_deref() {
        Some(raw) => Some(normalize_name(raw)?),
        None => None,
    };
    let public_host = req
        .public_host
        .as_deref()
        .map(|v| Some(v.trim().to_string()).filter(|s| !s.is_empty()));

    if name.is_some() || public_host.is_some() {
        state
            .store
            .update_node(NodePatch {
                id: id.clone(),
                name,
                public_host,
            })
            .await
            .map_err(map_store_conflict)?;
    }

    if let Some(disabled) = req.disabled {
        state
            .store
            .set_node_disabled(&id, disabled)
            .await
            .map_err(ApiError::from)?;
        state
            .audit(
                Some(&user.id),
                if disabled { "disable_node" } else { "enable_node" },
                Some(id.clone()),
                None,
                &headers,
            )
            .await;
    }

    let node = state
        .store
        .find_node(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;
    Ok(Json(node))
}

/// `DELETE /api/v1/nodes/{id}`
pub async fn delete_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let node = state
        .store
        .find_node(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;

    state.store.delete_node(&id).await.map_err(ApiError::from)?;
    state
        .audit(
            Some(&user.id),
            "delete_node",
            Some(node.name),
            Some("其下客户端已解除归属但保留".to_string()),
            &headers,
        )
        .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /api/v1/nodes/{id}/token`
pub async fn rotate_node_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let cfg = state.config_snapshot().await;
    let node = state
        .store
        .find_node(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;

    let token = rotate_token(&state, &id).await?;
    state
        .audit(
            Some(&user.id),
            "rotate_node_token",
            Some(node.name.clone()),
            None,
            &headers,
        )
        .await;

    Ok(Json(serde_json::json!({
        "node_token": token,
        "command": node_command(&cfg, &node.name, &token),
    })))
}

// ============================================================ 节点侧 API

/// 节点注册请求。
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeEnrollRequest {
    /// node token（`rsn_` 前缀）。
    pub token: String,
    /// 期望名称（仅用于日志；实际名称由控制台决定）。
    pub name: Option<String>,
    /// 运行时信息。
    #[serde(default)]
    pub runtime: NodeRuntime,
}

/// 节点注册响应。
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeEnrollResponse {
    /// 节点 ID。
    pub node_id: String,
    /// 节点名。
    pub name: String,
    /// 该节点的 FerroTunnel 握手 token。
    pub tunnel_token: String,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 控制台对外地址。
    pub public_url: Option<String>,
}

/// 节点心跳请求。
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeHeartbeatRequest {
    /// 运行时信息。
    #[serde(default)]
    pub runtime: NodeRuntime,
}

/// 节点心跳响应。
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeHeartbeatResponse {
    /// 下一次心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 控制台当前时间。
    pub server_time: String,
    /// 控制台观测到的出口 IP。
    pub public_ip: Option<String>,
    /// 当前生效的 FerroTunnel 握手 token（便于节点感知轮换）。
    pub tunnel_token: String,
}

/// `POST /api/v1/node/enroll`
pub async fn node_enroll(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<NodeEnrollRequest>,
) -> Result<Json<NodeEnrollResponse>, ApiError> {
    let cfg = state.config_snapshot().await;
    let token = req.token.trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized("缺少节点令牌"));
    }

    let node = state
        .store
        .find_node_by_token_hash(&token_hash(token))
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("节点令牌无效"))?;

    if node.disabled {
        return Err(ApiError::forbidden("节点已被禁用"));
    }

    // 注册即视为首个心跳，顺带把版本/平台/EndpointId 落库。
    apply_node_heartbeat(&state, &node.id, &req.runtime, Some(peer.ip().to_string())).await?;

    tracing::info!(
        node = %node.name,
        id = %node.id,
        peer = %peer,
        reported = req.name.as_deref().unwrap_or("-"),
        "服务端节点已注册"
    );

    Ok(Json(NodeEnrollResponse {
        node_id: node.id,
        name: node.name,
        tunnel_token: node.tunnel_token,
        heartbeat_secs: cfg.console.heartbeat_secs,
        public_url: cfg.console.public_url.clone(),
    }))
}

/// `POST /api/v1/node/heartbeat`
pub async fn node_heartbeat(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<NodeHeartbeatRequest>,
) -> Result<Json<NodeHeartbeatResponse>, ApiError> {
    let node = authenticate_node(&state, &headers).await?;
    Ok(Json(
        apply_node_heartbeat(&state, &node.id, &req.runtime, Some(peer.ip().to_string())).await?,
    ))
}

/// `GET /api/v1/node/self`
pub async fn node_self(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NodeRecord>, ApiError> {
    let node = authenticate_node(&state, &headers).await?;
    Ok(Json(node))
}

/// 节点鉴权（HTTP 路径）。内嵌模式不走这里。
pub async fn authenticate_node(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<NodeRecord, ApiError> {
    let token = header_token(headers, NODE_HEADER)
        .ok_or_else(|| ApiError::unauthorized("缺少 X-Rscross-Node 头"))?;
    let node = state
        .store
        .find_node_by_token_hash(&token_hash(&token))
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("节点令牌无效"))?;
    if node.disabled {
        return Err(ApiError::forbidden("节点已被禁用"));
    }
    Ok(node)
}

/// 落地一次节点心跳，并组装响应。
///
/// HTTP 处理器与内嵌控制台**共用**这段逻辑，避免两条路径出现行为差异。
pub async fn apply_node_heartbeat(
    state: &AppState,
    node_id: &str,
    runtime: &NodeRuntime,
    public_ip: Option<String>,
) -> Result<NodeHeartbeatResponse, ApiError> {
    let cfg = state.config_snapshot().await;

    state
        .store
        .touch_node(
            node_id.to_string(),
            NodeRuntimePatch {
                version: non_empty(&runtime.version),
                os: non_empty(&runtime.os),
                arch: non_empty(&runtime.arch),
                endpoint_id: non_empty_opt(&runtime.endpoint_id),
                endpoint_addr: non_empty_opt(&runtime.endpoint_addr),
                public_ip,
                tunnel_port: runtime.tunnel_port.map(i64::from),
                ingress_port: runtime.ingress_port.map(i64::from),
            },
        )
        .await
        .map_err(ApiError::from)?;

    let node = state
        .store
        .find_node(node_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;

    Ok(NodeHeartbeatResponse {
        heartbeat_secs: cfg.console.heartbeat_secs,
        server_time: rscross_common::time::now_rfc3339(),
        public_ip: node.public_ip.clone(),
        tunnel_token: node.tunnel_token.clone(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_url_prefers_public_url() {
        let mut cfg = ConsoleFile::default();
        cfg.console.public_url = Some("https://panel.example.com/".to_string());
        assert_eq!(console_url_of(&cfg), "https://panel.example.com");

        cfg.console.public_url = None;
        cfg.console.bind = "0.0.0.0:7800".to_string();
        assert_eq!(console_url_of(&cfg), "http://127.0.0.1:7800");

        cfg.console.bind = "10.0.0.5:7900".to_string();
        assert_eq!(console_url_of(&cfg), "http://10.0.0.5:7900");
    }

    #[test]
    fn node_command_mentions_managed_mode() {
        let cfg = ConsoleFile::default();
        let cmd = node_command(&cfg, "node-1", "rsn_abc");
        assert!(cmd.contains("--managed"));
        assert!(cmd.contains("--name node-1"));
        assert!(cmd.contains("--enroll-token rsn_abc"));
    }

    #[test]
    fn node_endpoint_uses_reported_coordinates() {
        let node = NodeRecord {
            id: "n1".to_string(),
            name: "node-1".to_string(),
            status: "online".to_string(),
            node_token_hash: "h".to_string(),
            tunnel_token: "tt".to_string(),
            public_host: None,
            tunnel_port: Some(17835),
            ingress_port: None,
            version: None,
            os: None,
            arch: None,
            endpoint_id: Some("aa".repeat(32)),
            endpoint_addr: Some("{}".to_string()),
            public_ip: Some("203.0.113.5".to_string()),
            last_seen_at: None,
            last_error: None,
            created_at: String::new(),
            updated_at: String::new(),
            disabled: false,
        };
        let ep = node_endpoint(&node);
        assert_eq!(ep.tunnel_server, "203.0.113.5:17835");
        assert_eq!(ep.tunnel_token, "tt");
        assert_eq!(ep.endpoint_id.as_deref(), Some("aa".repeat(32).as_str()));
    }
}
