//! 访问端接入 API（免鉴权，凭访问密钥换取节点坐标）。
//!
//! 为什么需要这个接口：访问端（`rscross-client access --key ...`）手里只有一枚访问密钥，
//! 它不知道隧道挂在哪台节点上。把节点地址编码进密钥会让密钥又长又难维护；而访问端
//! 本来就要能访问控制台（与客户端一致，同样是 `--console`），所以「用密钥换坐标」最自然。
//!
//! 安全边界：访问密钥等价于密码，拿到它的人本来就有权访问该内网服务，
//! 这个接口只是把「去哪连」告诉它，不额外泄露数据。对无效密钥**统一返回 401**，
//! 不区分「密钥不存在」与「隧道已停用」，避免接口被用来探测密钥是否存在。

use axum::extract::State;
use axum::Json;
use rscross_common::TunnelKind;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;

/// `POST /api/v1/access/resolve` 请求。
#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    /// 隧道访问密钥（`rsv_` 前缀）。
    pub access_key: String,
    /// 可选：同时校验隧道 ID，防止把 A 的密钥配到 B 的隧道上却毫无提示。
    #[serde(default)]
    pub tunnel_id: Option<String>,
}

/// 访问端所需的全部信息。
#[derive(Debug, Serialize)]
pub struct ResolveResponse {
    /// 隧道 ID。
    pub tunnel_id: String,
    /// 隧道名（访问端日志用）。
    pub tunnel_name: String,
    /// 用途分类。
    pub kind: String,
    /// 协议。
    pub proto: String,
    /// 投递给客户端时使用的路由键（与节点、客户端两侧同源）。
    pub tunnel_key: String,
    /// 归属节点名。
    pub node_name: String,
    /// 归属节点的 Iroh 坐标（JSON）。
    pub node_endpoint: String,
    /// 建议路径：`p2p`（直连客户端）或 `relay`（经节点转发）。
    ///
    /// 这只是「建议」，最终由节点在握手应答里定夺 —— 节点才知道客户端的
    /// Iroh 坐标此刻是否可用。
    pub mode: String,
    /// 直连失败时是否允许回退到节点转发。
    pub allow_relay: bool,
}

/// `POST /api/v1/access/resolve`
pub async fn resolve(
    State(state): State<AppState>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>, ApiError> {
    let key = req.access_key.trim();
    if key.is_empty() {
        return Err(ApiError::unauthorized("缺少访问密钥"));
    }

    let Some(tunnel) = state
        .store
        .find_tunnel_by_access_key(key)
        .await
        .map_err(ApiError::from)?
    else {
        tracing::warn!("访问端使用了无效的访问密钥");
        return Err(ApiError::unauthorized("访问密钥无效或隧道已下线"));
    };

    if let Some(expected) = req
        .tunnel_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if expected != tunnel.id {
            return Err(ApiError::unauthorized("访问密钥与该隧道不匹配"));
        }
    }

    let kind = TunnelKind::parse(&tunnel.kind).unwrap_or_default();
    if !kind.needs_access_key() {
        // 这里返回 400 而不是 401 是安全的：能走到这行说明密钥是对的，
        // 只是在提示「这类隧道不用密钥访问」，没有泄露任何未知信息。
        return Err(ApiError::bad_request(format!(
            "{} 不使用访问密钥：请改用它的域名或公网端口访问",
            kind.label()
        )));
    }

    // 复用与下发同一段转换：它已经过滤了「未启用」「协议非法」「缺访问密钥」三种情况，
    // 所以这里拿不到值就等价于「隧道当前不可用」，统一按 401 处理。
    let desired = crate::api::desired_tunnels(vec![tunnel.clone()])
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::unauthorized("隧道已停用或配置无效"))?;

    let client = state
        .store
        .find_client(&tunnel.client_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("隧道的归属客户端已删除"))?;
    if client.disabled {
        return Err(ApiError::unauthorized("隧道的归属客户端已被禁用"));
    }

    let node_id = client
        .node_id
        .as_deref()
        .ok_or_else(|| ApiError::conflict("归属客户端尚未分配到服务端节点"))?;
    let node = state
        .store
        .find_node(node_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::conflict("归属节点不存在"))?;
    let node_endpoint = node
        .endpoint_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ApiError::conflict("归属节点尚未上报 Iroh 坐标（它可能刚启动），请稍后重试")
        })?
        .to_string();

    let mode = if kind.prefers_direct() { "p2p" } else { "relay" };
    tracing::info!(
        tunnel = %tunnel.name,
        kind = %kind,
        node = %node.name,
        mode,
        "访问端已换取节点坐标"
    );

    Ok(Json(ResolveResponse {
        tunnel_id: tunnel.id,
        tunnel_name: tunnel.name,
        kind: kind.as_str().to_string(),
        proto: desired.proto.as_str().to_string(),
        tunnel_key: desired.route_key(),
        node_name: node.name,
        node_endpoint,
        mode: mode.to_string(),
        allow_relay: tunnel.allow_relay,
    }))
}
