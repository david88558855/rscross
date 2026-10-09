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

/// 重导出：节点隧道计划属于网络传输 DTO，定义在 common，这里保持历史路径可用。
pub use rscross_common::NodeTunnelPlan;

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
#[allow(clippy::too_many_arguments)]
pub async fn provision_node(
    state: &AppState,
    name: String,
    tunnel_token: Option<String>,
    created_by: Option<String>,
) -> Result<(NodeRecord, String), ApiError> {
    provision_node_with(state, name, tunnel_token, created_by, NodeExtras::default()).await
}

/// 「新增自建节点」表单的其余配置项。
#[derive(Debug, Default, Clone)]
pub struct NodeExtras {
    /// 介绍。
    pub description: Option<String>,
    /// 服务端地址。
    pub public_addr: Option<String>,
    /// 传输协议。
    pub transport: Option<String>,
    /// P2P 中继回退开关。
    pub allow_relay: Option<bool>,
}

/// 带完整配置项的节点开通。`provision_node` 保留给只需要最小参数的调用方
/// （例如测试与 CLI 引导）。
pub async fn provision_node_with(
    state: &AppState,
    name: String,
    tunnel_token: Option<String>,
    created_by: Option<String>,
    extras: NodeExtras,
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
        // 再校验一次：CLI 引导等调用方不经过 HTTP 层，不能绕过格式检查。
        public_addr: normalize_public_addr(extras.public_addr.as_deref())?,
        description: normalize_description(extras.description.as_deref())?,
        transport: extras
            .transport
            .unwrap_or_else(|| DEFAULT_TRANSPORT.to_string()),
        // 默认开启：直连失败还能走中继，比「连不上」好。
        allow_relay: extras.allow_relay.unwrap_or(true),
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
    Err(ApiError::conflict(format!(
        "名称 {name} 及其派生名均已被占用"
    )))
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
        public_addr: node.public_addr.clone(),
        transport: if node.transport.is_empty() {
            DEFAULT_TRANSPORT.to_string()
        } else {
            node.transport.clone()
        },
    }
}

/// 为客户端解析归属节点。
///
/// - 指定了 `node_id` → 必须是存在且启用的节点；
/// - 未指定且控制台里只有一个节点 → 自动选中（单机内嵌场景的默认行为）；
/// - 其余情况 → 报错，要求显式指定。
pub async fn resolve_node(state: &AppState, node_id: Option<&str>) -> Result<NodeRecord, ApiError> {
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
    /// 自定义 FerroTunnel 握手 token，留空则自动生成。
    pub tunnel_token: Option<String>,
    /// 对外可见的介绍（纯展示）。
    pub description: Option<String>,
    /// 服务端地址：客户端据此连接控制面，形如 `ws://<IP>:7800`。
    /// 留空则由客户端自己用 `--console` 传入的地址。
    pub public_addr: Option<String>,
    /// 传输协议，留空默认 `tcp`。
    pub transport: Option<String>,
    /// P2P 直连失败时是否回退中继，默认开启。
    pub allow_relay: Option<bool>,
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

    let (node, token) = provision_node_with(
        &state,
        req.name,
        req.tunnel_token,
        Some(user.username.clone()),
        NodeExtras {
            description: normalize_description(req.description.as_deref())?,
            public_addr: normalize_public_addr(req.public_addr.as_deref())?,
            transport: normalize_transport(req.transport.as_deref())?,
            allow_relay: req.allow_relay,
        },
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

    // 先把命令拼好，避免下面把 node / token 移动进结构体后再去借用它们。
    let command = node_command(&cfg, &node.name, &token);

    Ok(Json(CreateNodeResponse {
        command,
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

/// 自建节点可选的传输协议。
///
/// 白名单而不是自由字符串：这是要写进配置文件并影响实际连接方式的字段，
/// 拼错一个字符会变成「节点上线了但隧道全不通」，而且日志里看不出原因。
///
/// **不含 `udp`**：UDP 的入口需要内核层面的端口转发，在NAT 后基本不可用，
/// 配上去只会得到一个「节点在线但 UDP 隧道全不通」的状态。TCP 侧的行为
/// 对 UDP 业务已经足够（穿透工具本来就是为TCP 设计的）。
pub const TRANSPORTS: &[&str] = &["tcp", "quic", "kcp", "ws", "wss"];

/// 默认传输协议。
pub const DEFAULT_TRANSPORT: &str = "tcp";

/// 校验传输协议；空串按未设置处理（返回 `None`）。
fn normalize_transport(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(v) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let lower = v.to_ascii_lowercase();
    if TRANSPORTS.contains(&lower.as_str()) {
        Ok(Some(lower))
    } else {
        Err(ApiError::bad_request(format!(
            "不支持的传输协议 {v:?}，可选：{}",
            TRANSPORTS.join(" / ")
        )))
    }
}

/// 介绍的最大长度。
///
/// 200 字足够写清「哪台机器、什么线路、带宽多少」，再长就没人看了 ——
/// 而没人看的字段会诱使人往里塞密码、密钥这类必须另找地方存的东西。
pub const MAX_DESCRIPTION: usize = 200;

/// 校验并规范化介绍。空串按「清空」处理（返回 `None`）。
pub fn normalize_description(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(text) = raw.map(str::trim) else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    // 按字符数而不是字节数：中文一个字占 3 字节，按字节算会让 70 个汉字就超限。
    let chars = text.chars().count();
    if chars > MAX_DESCRIPTION {
        return Err(ApiError::bad_request(format!(
            "介绍不能超过 {MAX_DESCRIPTION} 个字（当前 {chars} 个）"
        )));
    }
    Ok(Some(text.to_string()))
}

/// 校验并规范化「服务端地址」。
///
/// 这是**客户端要连的控制面地址**，完整形态带 scheme，例如：
///
/// - `ws://203.0.113.9:7800`
/// - `wss://node1.example.com/api/v1/control/ws`
///
/// 刻意复用 [`rscross_common::console`] 的 scheme 判定，不在这里另写一套 ——
/// `--console` 参数与本字段最终都要交给同一段解析逻辑，两处规则一旦漂移，
/// 就会出现「命令行能连、控制台配的地址不能连」。
///
/// 只接受 `ws://` / `wss://`：`http://` 入口虽然也能被客户端跟随 307 发现，
/// 但那是「用户自己填 --console 时的便利」，不该固化进配置 ——
///
/// 配置里的地址应当是**最终**那个，不再依赖一次重定向。
pub fn normalize_public_addr(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(text) = raw.map(str::trim) else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    if text.chars().any(char::is_whitespace) {
        return Err(ApiError::bad_request("服务端地址不能包含空格"));
    }

    let addr = rscross_common::console::plan_console_address(text).map_err(|_| {
        ApiError::bad_request(format!(
            "服务端地址必须以 ws:// 或 wss:// 开头，例如 ws://203.0.113.9:7800（实际为 {text:?}）"
        ))
    })?;

    match addr.scheme {
        rscross_common::console::ConsoleScheme::Ws
        | rscross_common::console::ConsoleScheme::Wss => {}
        _ => {
            return Err(ApiError::bad_request(format!(
                "服务端地址必须以 ws:// 或 wss:// 开头（实际是 {}://）",
                text.split("://").next().unwrap_or("?")
            )))
        }
    }
    Ok(Some(text.to_string()))
}

/// 修改节点请求。
#[derive(Debug, Deserialize)]
pub struct PatchNodeRequest {
    /// 新名称。
    pub name: Option<String>,
    /// 启用 / 禁用。
    pub disabled: Option<bool>,
    /// 对外可见的介绍（传空字符串表示清空）。
    pub description: Option<String>,
    /// 服务端地址（传空字符串表示清空）。
    pub public_addr: Option<String>,
    /// 传输协议。
    pub transport: Option<String>,
    /// P2P 直连失败时是否回退中继。
    pub allow_relay: Option<bool>,
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
    // 传空串 = 清空；不传 = 不改；传非法值 = 400。
    //
    // 这里刻意让校验错误冒出来而不是 `unwrap_or(None)` —— 后者会把
    // 「地址写错了」悄悄变成「清空地址」，用户以为自己改了配置，
    // 实际是把它删了。
    let public_addr = match req.public_addr.as_deref() {
        Some(v) => Some(normalize_public_addr(Some(v))?),
        None => None,
    };
    let description = match req.description.as_deref() {
        Some(v) => Some(normalize_description(Some(v))?),
        None => None,
    };
    let transport = normalize_transport(req.transport.as_deref())?;

    if name.is_some()
        || public_host.is_some()
        || public_addr.is_some()
        || description.is_some()
        || transport.is_some()
        || req.allow_relay.is_some()
    {
        state
            .store
            .update_node(NodePatch {
                id: id.clone(),
                name,
                // 表单不再提供「对外主机」，编辑时也不动它 ——
                // 那列由内嵌形态的启动流程自动维护。
                public_host: None,
                public_addr,
                description,
                transport,
                allow_relay: req.allow_relay,
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
                if disabled {
                    "disable_node"
                } else {
                    "enable_node"
                },
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
    /// node token —— 之后每次心跳都要带上它。
    ///
    /// 每次注册都重新签发：这样「令牌泄漏」的影响范围限于单个连接，
    /// 而不是长期有效。丢失 token 的节点重新注册即可，不影响数据面。
    pub node_token: String,
    /// 该节点的 FerroTunnel 握手 token。
    pub tunnel_token: String,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 控制台对外地址。
    pub public_url: Option<String>,
    /// 首次心跳就已算出的隧道编排（省掉一轮往返）。
    #[serde(default)]
    pub tunnels: Vec<NodeTunnelPlan>,
}

/// 节点心跳请求。
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeHeartbeatRequest {
    /// 运行时信息。
    #[serde(default)]
    pub runtime: NodeRuntime,
}

/// 节点侧要承载的一条隧道。
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
    /// 本节点当前要承载的隧道。
    ///
    /// 「端口转发」据此开公网端口监听；私有 / P2P 据此响应访问端的密钥查询。
    /// 域名解析虽然走 FerroTunnel 的 HTTP 入口，也一并下发（节点侧统计与排障要用）。
    #[serde(default)]
    pub tunnels: Vec<NodeTunnelPlan>,
}

/// `POST /api/v1/node/enroll`
///
/// HTTP 入口。业务逻辑在 [`node_enroll_inner`]，WebSocket 帧路径复用同一份。
pub async fn node_enroll(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<NodeEnrollRequest>,
) -> Result<Json<NodeEnrollResponse>, ApiError> {
    let resp = node_enroll_inner(
        &state,
        &req.token,
        req.name.clone(),
        req.runtime.clone(),
        peer.ip(),
    )
    .await?;
    Ok(Json(resp))
}

/// 节点注册的真正实现（HTTP 与 WS 共用）。
pub(crate) async fn node_enroll_inner(
    state: &AppState,
    token: &str,
    name: Option<String>,
    runtime: NodeRuntime,
    peer_ip: std::net::IpAddr,
) -> Result<NodeEnrollResponse, ApiError> {
    let cfg = state.config_snapshot().await;
    let token = token.trim();
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

    // 注册即视为首个心跳，顺带把版本/平台/EndpointId 落库；
    // 顺带把这次心跳算出的隧道编排一起返回，省掉一轮往返。
    let beat = apply_node_heartbeat(state, &node.id, &runtime, Some(peer_ip.to_string())).await?;

    tracing::info!(
        node = %node.name,
        id = %node.id,
        peer = %peer_ip,
        reported = name.as_deref().unwrap_or("-"),
        "服务端节点已注册"
    );

    Ok(NodeEnrollResponse {
        node_id: node.id,
        name: node.name,
        node_token: token.to_string(),
        tunnel_token: node.tunnel_token,
        heartbeat_secs: beat.heartbeat_secs,
        public_url: cfg.console.public_url.clone(),
        tunnels: beat.tunnels,
    })
}

/// `POST /api/v1/node/heartbeat`
pub async fn node_heartbeat(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<NodeHeartbeatRequest>,
) -> Result<Json<NodeHeartbeatResponse>, ApiError> {
    let resp = node_heartbeat_inner(&state, &headers, req.runtime, peer.ip()).await?;
    Ok(Json(resp))
}

/// 节点心跳的真正实现（HTTP 与 WS 共用）。
pub(crate) async fn node_heartbeat_inner(
    state: &AppState,
    headers: &HeaderMap,
    runtime: NodeRuntime,
    peer_ip: std::net::IpAddr,
) -> Result<NodeHeartbeatResponse, ApiError> {
    let node = authenticate_node(state, headers).await?;
    apply_node_heartbeat(state, &node.id, &runtime, Some(peer_ip.to_string())).await
}

/// `GET /api/v1/node/self`
pub async fn node_self(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NodeRecord>, ApiError> {
    let node = node_self_inner(&state, &headers).await?;
    Ok(Json(node))
}

/// 节点查询自身记录（HTTP 与 WS 共用）。
pub(crate) async fn node_self_inner(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<NodeRecord, ApiError> {
    authenticate_node(state, headers).await
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

    let tunnels = collect_node_plans(state, node_id).await?;

    Ok(NodeHeartbeatResponse {
        heartbeat_secs: cfg.console.heartbeat_secs,
        server_time: rscross_common::time::now_rfc3339(),
        public_ip: node.public_ip.clone(),
        tunnel_token: node.tunnel_token.clone(),
        tunnels,
    })
}

/// 汇总某节点需要承载的隧道（含归属客户端的 Iroh 坐标）。
///
/// 用的是与客户端下发同一个 [`crate::api::desired_tunnels`]：只保留启用项、
/// 校验协议与访问密钥。两侧走同一段转换逻辑，才不会出现「客户端建了、节点不知道」。
async fn collect_node_plans(
    state: &AppState,
    node_id: &str,
) -> Result<Vec<NodeTunnelPlan>, ApiError> {
    let clients = state
        .store
        .list_clients_of_node(node_id)
        .await
        .map_err(ApiError::from)?;

    let mut plans = Vec::new();
    for client in clients {
        // 被禁用的客户端整条不下发：它的隧道本来就不该工作。
        if client.disabled {
            continue;
        }
        let records = state
            .store
            .list_tunnels_of_client(&client.id)
            .await
            .map_err(ApiError::from)?;
        for tunnel in crate::api::desired_tunnels(records) {
            plans.push(NodeTunnelPlan {
                tunnel,
                client_id: client.id.clone(),
                client_name: client.name.clone(),
                client_endpoint: client.endpoint_addr.clone(),
            });
        }
    }
    plans.sort_by(|a, b| a.tunnel.name.cmp(&b.tunnel.name));
    Ok(plans)
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
    fn public_addr_accepts_ws_and_wss_console_urls() {
        for good in [
            "ws://203.0.113.9:7800",
            "wss://node1.example.com",
            "wss://node1.example.com:443",
            "WS://203.0.113.9:7800",
            "ws://[2001:db8::1]:7800",
        ] {
            let got = normalize_public_addr(Some(good)).expect(good);
            assert_eq!(got.as_deref(), Some(good));
        }
        // 空串 / 未填 = 不覆盖，让客户端用命令行 --console 的地址
        assert_eq!(normalize_public_addr(Some("  ")).expect("空串"), None);
        assert_eq!(normalize_public_addr(None).expect("未填"), None);
    }

    #[test]
    fn public_addr_rejects_non_ws_forms() {
        // 只接受 ws/wss。http:// 虽然客户端能跟随 307 发现，但那是命令行
        // 填法的便利；配置里应该存最终地址，不再依赖一次重定向。
        for bad in [
            "http://203.0.113.9:7800",
            "https://node1.example.com",
            "203.0.113.9:7800",
            "node1.example.com",
            "ftp://x",
            "ws://",
            "ws://host:0",
            "ws://host:70000",
            "ws://host:abc",
            "ws://host:7800/path",
            "has space",
        ] {
            let err = normalize_public_addr(Some(bad)).expect_err(bad);
            assert_eq!(
                err.status,
                axum::http::StatusCode::BAD_REQUEST,
                "{bad:?} 应返回 400"
            );
        }
    }

    #[test]
    fn transport_whitelist_rejects_typos() {
        assert_eq!(
            normalize_transport(Some("WSS"))
                .expect("大小写不敏感")
                .as_deref(),
            Some("wss")
        );
        assert!(normalize_transport(Some(""))
            .expect("空串=未设置")
            .is_none());
        // sctp / typo 必须被拒 —— 它拼错后的表现是「节点上线了但隧道全不通」
        assert!(normalize_transport(Some("sctp")).is_err());
        // udp 已从白名单移除：UDP 入口需要内核层端口转发，NAT 后基本不可用，
        // 配上去只会得到「节点在线但 UDP 隧道全不通」
        assert!(normalize_transport(Some("udp")).is_err());
        assert!(!TRANSPORTS.contains(&"udp"));
        assert!(
            normalize_transport(Some("tcp ")).is_ok(),
            "两端空白应被容忍"
        );
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
            public_addr: None,
            description: None,
            transport: "tcp".to_string(),
            allow_relay: true,
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
