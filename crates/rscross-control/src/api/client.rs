//! 客户端与隧道的管理 API（控制台侧）。

use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use rscross_auth::{new_access_key, new_enroll_token, token_hash};
use rscross_common::TunnelKind;
use rscross_config::{parse_port_range, ConsoleFile};
use rscross_store::{ClientRecord, EnrollTokenRecord, TunnelPatch, TunnelRecord};
use serde::{Deserialize, Serialize};

use crate::api::misc::TOKEN_MASK;
use crate::api::nodes::{console_url_of, resolve_node, resolve_node_optional};
use crate::api::{map_store_conflict, normalize_name, parse_proto, ROLE_ADMIN};
use crate::error::ApiError;
use crate::state::AppState;

/// 掩掉非管理员不该看到的隧道访问密钥。
///
/// 访问密钥等价于「进入该内网服务的凭据」，且 `/api/v1/access/resolve`
/// 免鉴权 —— 只读角色能看到隧道存在，但不该拿到能直接用的钥匙。
fn mask_tunnel_secrets(tunnel: &mut TunnelRecord) {
    if tunnel.access_key.is_some() {
        tunnel.access_key = Some(TOKEN_MASK.to_string());
    }
}

// ------------------------------------------------------------------ 客户端

/// 创建（预登记）客户端请求。
#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    /// 期望的节点名（留空则用随机名）。
    pub name: Option<String>,
    /// 归属的服务端节点；控制台只有单个节点时可不填。
    pub node_id: Option<String>,
    /// 接入令牌有效期（分钟），默认取配置。
    pub ttl_minutes: Option<u64>,
}

/// 创建客户端响应。
#[derive(Debug, Serialize)]
pub struct CreateClientResponse {
    /// 一次性接入令牌明文（只在此处返回一次）。
    pub enroll_token: String,
    /// 过期时间。
    pub expires_at: String,
    /// 归属节点 ID；`null` 表示暂未指定（客户端先注册、之后再改派）。
    pub node_id: Option<String>,
    /// 归属节点名；`null` 同上。
    pub node_name: Option<String>,
    /// 可直接复制执行的接入命令。
    pub command: String,
}

/// 修改客户端请求。
#[derive(Debug, Deserialize)]
pub struct PatchClientRequest {
    /// 新名称。
    pub name: Option<String>,
    /// 启用 / 禁用。
    pub disabled: Option<bool>,
    /// 改派归属节点；空字符串表示解除归属。
    pub node_id: Option<String>,
}

/// `GET /api/v1/clients`
pub async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ClientRecord>>, ApiError> {
    state.require_user(&headers).await?;
    let clients = state.store.list_clients().await.map_err(ApiError::from)?;
    Ok(Json(clients))
}

/// `GET /api/v1/clients/{id}`
pub async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_user(&headers).await?;
    let client = state
        .store
        .find_client(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("客户端不存在"))?;
    let mut tunnels = state
        .store
        .list_tunnels_of_client(&id)
        .await
        .map_err(ApiError::from)?;
    if user.role != ROLE_ADMIN {
        for tunnel in tunnels.iter_mut() {
            mask_tunnel_secrets(tunnel);
        }
    }
    let node = match client.node_id.as_deref() {
        Some(node_id) => state
            .store
            .find_node(node_id)
            .await
            .map_err(ApiError::from)?,
        None => None,
    };
    Ok(Json(serde_json::json!({
        "client": client,
        "node": node,
        "tunnels": tunnels,
    })))
}

/// `POST /api/v1/clients` —— 签发接入令牌（客户端记录在 agent 注册时创建）。
pub async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<CreateClientResponse>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let cfg = state.config_snapshot().await;

    // 归属节点是**可选的**：控制台里还没有节点、或用户想稍后再分配，
    // 都不该拦住「先把客户端登记进来」。这条路径过去会报
    // 「控制台里还没有服务端节点」，把节点变成了创建客户端的前置条件。
    let node = resolve_node_optional(&state, req.node_id.as_deref()).await?;

    let name = match req.name.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(normalize_name(raw)?),
        _ => None,
    };

    let ttl = req
        .ttl_minutes
        .unwrap_or(cfg.auth.enroll_token_ttl_minutes)
        .clamp(1, 24 * 60);

    let token = new_enroll_token();
    let now = rscross_common::time::now();
    let expires_at = rscross_common::time::to_rfc3339(now + chrono::Duration::minutes(ttl as i64));

    state
        .store
        .insert_enroll_token(EnrollTokenRecord {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: token_hash(&token),
            // 明文一并入库，供之后在「待接入」列表里重新复制命令。
            // 只留摘要的话，这条令牌关掉弹窗就等于作废了。
            token_plain: Some(token.clone()),
            node_id: node.as_ref().map(|n| n.id.clone()),
            client_name: name.clone(),
            created_by: Some(user.username.clone()),
            created_at: rscross_common::time::to_rfc3339(now),
            expires_at: expires_at.clone(),
            used_at: None,
            used_client_id: None,
        })
        .await
        .map_err(ApiError::from)?;

    let command = build_enroll_command(&cfg, name.as_deref(), &token);

    state
        .audit(
            Some(&user.id),
            "issue_enroll_token",
            name.clone(),
            Some(format!(
                "归属节点={} 有效期={ttl}分钟",
                node.as_ref().map(|n| n.name.as_str()).unwrap_or("未指定")
            )),
            &headers,
        )
        .await;

    Ok(Json(CreateClientResponse {
        enroll_token: token,
        expires_at,
        node_id: node.as_ref().map(|n| n.id.clone()),
        node_name: node.as_ref().map(|n| n.name.clone()),
        command,
    }))
}

/// 「待接入」列表里的一行。
///
/// 与 `EnrollTokenRecord` 的区别：这是**面向界面**的视图 —— 摘要在内、
/// 明文在内，但只以「可直接复制的命令」这一种形态出去。
#[derive(Debug, Serialize)]
pub struct EnrollTokenView {
    /// 条目 ID（撤销与复制命令都靠它定位）。
    pub id: String,
    /// 归属节点 ID；`null` 表示尚未指定。
    pub node_id: Option<String>,
    /// 归属节点名；对应节点已被删除时为 `null`。
    pub node_name: Option<String>,
    /// 预设的客户端名；`null` 表示由客户端注册时自报。
    pub client_name: Option<String>,
    /// 签发人。
    pub created_by: Option<String>,
    /// 签发时间。
    pub created_at: String,
    /// 过期时间。
    pub expires_at: String,
    /// 是否已过期。
    pub expired: bool,
    /// 可直接复制执行的接入命令；升级前签发的老令牌为 `null`（明文未留存）。
    pub command: Option<String>,
}

/// `GET /api/v1/enroll-tokens`
///
/// 列出**尚未被使用**的客户端接入令牌 —— 也就是「已经创建、但还没接进来」
/// 的客户端。控制台的客户端列表靠它把这类条目也显示出来：否则用户签发完
/// 令牌、关掉弹窗，列表里空空如也，只能怀疑自己刚才那步没成功。
pub async fn list_enroll_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<EnrollTokenView>>, ApiError> {
    state.require_admin(&headers).await?;
    let cfg = state.config_snapshot().await;
    let tokens = state
        .store
        .list_enroll_tokens()
        .await
        .map_err(ApiError::from)?;

    // 令牌里只存了 node_id，节点名要现查（节点被删掉时留空，不报错 ——
    // 列表少一列好过整页 500）。
    let node_names: std::collections::HashMap<String, String> = state
        .store
        .list_nodes()
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .map(|n| (n.id, n.name))
        .collect();

    let now = rscross_common::time::now_rfc3339();
    let views = tokens
        .into_iter()
        .map(|t| EnrollTokenView {
            // `expires_at` 与 `now` 都出自 `time::to_rfc3339`：固定宽度的 UTC
            // （毫秒 + `Z`），字典序即时间序。与 enroll 时的过期判定用同一套
            // 比较方式，避免两处给出互相矛盾的结论。
            expired: t.expires_at < now,
            node_name: t
                .node_id
                .as_deref()
                .and_then(|id| node_names.get(id).cloned()),
            command: t
                .token_plain
                .as_deref()
                .filter(|p| !p.is_empty())
                .map(|p| build_enroll_command(&cfg, t.client_name.as_deref(), p)),
            id: t.id,
            node_id: t.node_id,
            client_name: t.client_name,
            created_by: t.created_by,
            created_at: t.created_at,
            expires_at: t.expires_at,
        })
        .collect();
    Ok(Json(views))
}

/// `DELETE /api/v1/enroll-tokens/{id}`
///
/// 撤销一条还没被用掉的接入令牌 —— 命令随即失效。
pub async fn revoke_enroll_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let token = state
        .store
        .find_enroll_token_by_id(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("接入令牌不存在"))?;

    state
        .store
        .revoke_enroll_token(&id)
        .await
        .map_err(ApiError::from)?;

    state
        .audit(
            Some(&user.id),
            "revoke_enroll_token",
            token.client_name.clone(),
            Some(format!("id={id}")),
            &headers,
        )
        .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `PATCH /api/v1/clients/{id}`
pub async fn patch_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchClientRequest>,
) -> Result<Json<ClientRecord>, ApiError> {
    let user = state.require_admin(&headers).await?;

    if let Some(raw) = req.name.as_deref() {
        let name = normalize_name(raw)?;
        state
            .store
            .rename_client(&id, &name)
            .await
            .map_err(map_store_conflict)?;
        state
            .audit(
                Some(&user.id),
                "rename_client",
                Some(id.clone()),
                Some(name),
                &headers,
            )
            .await;
    }

    if let Some(raw) = req.node_id.as_deref() {
        let node_id = raw.trim();
        if node_id.is_empty() {
            state
                .store
                .reassign_client(&id, None)
                .await
                .map_err(ApiError::from)?;
            state
                .audit(
                    Some(&user.id),
                    "detach_client_node",
                    Some(id.clone()),
                    None,
                    &headers,
                )
                .await;
        } else {
            // 改派前先确认目标节点存在且启用
            let node = resolve_node(&state, Some(node_id)).await?;
            state
                .store
                .reassign_client(&id, Some(&node.id))
                .await
                .map_err(ApiError::from)?;
            state
                .audit(
                    Some(&user.id),
                    "reassign_client_node",
                    Some(id.clone()),
                    Some(format!("→ {}", node.name)),
                    &headers,
                )
                .await;
        }
    }

    if let Some(disabled) = req.disabled {
        state
            .store
            .set_client_disabled(&id, disabled)
            .await
            .map_err(ApiError::from)?;
        state
            .audit(
                Some(&user.id),
                if disabled {
                    "disable_client"
                } else {
                    "enable_client"
                },
                Some(id.clone()),
                None,
                &headers,
            )
            .await;
    }

    let client = state
        .store
        .find_client(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("客户端不存在"))?;
    Ok(Json(client))
}

/// `DELETE /api/v1/clients/{id}`
pub async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let existed = state
        .store
        .find_client(&id)
        .await
        .map_err(ApiError::from)?
        .is_some();
    if !existed {
        return Err(ApiError::not_found("客户端不存在"));
    }
    state
        .store
        .delete_client(&id)
        .await
        .map_err(ApiError::from)?;
    state
        .audit(Some(&user.id), "delete_client", Some(id), None, &headers)
        .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// -------------------------------------------------------------------- 隧道

/// 创建隧道请求。
#[derive(Debug, Deserialize)]
pub struct CreateTunnelRequest {
    /// 隧道名（同一客户端内唯一）。
    pub name: String,
    /// 用途分类：`domain` / `port` / `private` / `p2p`。
    ///
    /// 留空时按 `proto` 推导（http/https → domain，tcp/udp → port），
    /// 这样老的调用方式仍然可用。
    pub kind: Option<String>,
    /// 协议：tcp / http / https / udp。
    pub proto: String,
    /// 本地目标地址。
    pub local_addr: String,
    /// 公网端口（仅「端口转发」；留空则从端口池自动分配）。
    pub remote_port: Option<i64>,
    /// HTTP 路由 Host（仅「域名解析」；留空则由 default_domain 推导）。
    pub host: Option<String>,
    /// HTTP 路径前缀。
    pub path_prefix: Option<String>,
    /// P2P 隧道在直连失败时是否允许回退到服务器中继（默认允许）。
    pub allow_relay: Option<bool>,
    /// 是否启用。
    pub enabled: Option<bool>,
    /// 限速（Kbps，0 = 不限）。
    pub rate_limit_kbps: Option<i64>,
    /// 并发连接上限（0 = 不限）。
    pub conn_limit: Option<i64>,
}

/// 修改隧道请求（字段可空表示不改）。
#[derive(Debug, Deserialize)]
pub struct PatchTunnelRequest {
    /// 名称。
    pub name: Option<String>,
    /// 本地地址。
    pub local_addr: Option<String>,
    /// 公网端口。
    pub remote_port: Option<i64>,
    /// Host。
    pub host: Option<String>,
    /// 路径前缀。
    pub path_prefix: Option<String>,
    /// P2P 隧道是否允许中继回退。
    pub allow_relay: Option<bool>,
    /// 启用状态。
    pub enabled: Option<bool>,
    /// 限速。
    pub rate_limit_kbps: Option<i64>,
    /// 连接上限。
    pub conn_limit: Option<i64>,
}

/// `GET /api/v1/tunnels`
pub async fn list_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TunnelRecord>>, ApiError> {
    let user = state.require_user(&headers).await?;
    let admin = user.role == ROLE_ADMIN;
    let mut tunnels = state.store.list_tunnels().await.map_err(ApiError::from)?;
    if !admin {
        for tunnel in tunnels.iter_mut() {
            mask_tunnel_secrets(tunnel);
        }
    }
    Ok(Json(tunnels))
}

/// `GET /api/v1/clients/{id}/tunnels`
pub async fn list_client_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<TunnelRecord>>, ApiError> {
    let user = state.require_user(&headers).await?;
    let admin = user.role == ROLE_ADMIN;
    let mut tunnels = state
        .store
        .list_tunnels_of_client(&id)
        .await
        .map_err(ApiError::from)?;
    if !admin {
        for tunnel in tunnels.iter_mut() {
            mask_tunnel_secrets(tunnel);
        }
    }
    Ok(Json(tunnels))
}

/// `POST /api/v1/clients/{id}/tunnels`
pub async fn create_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(req): Json<CreateTunnelRequest>,
) -> Result<Json<TunnelRecord>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let cfg = state.config_snapshot().await;

    // 客户端记录后面要用（决定端口池按哪个节点算），所以这里取出来而不是
    // 只判个存在性。
    let Some(client) = state
        .store
        .find_client(&client_id)
        .await
        .map_err(ApiError::from)?
    else {
        return Err(ApiError::not_found("客户端不存在"));
    };

    let name = normalize_name(&req.name)?;
    let proto = parse_proto(&req.proto)
        .ok_or_else(|| ApiError::bad_request("proto 只能是 tcp / http / https / udp"))?;

    // 分类决定「入口形态 + 必填字段 + 数据面通道」。先定分类再校验协议组合，
    // 否则会出现「填了 Host 但协议是 tcp」这类自相矛盾的配置。
    let kind = match req.kind.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => TunnelKind::parse(raw)
            .ok_or_else(|| ApiError::bad_request("kind 只能是 domain / port / private / p2p"))?,
        // 不带 kind 的调用方（老前端 / 脚本）按协议推导，行为与之前一致
        None => TunnelKind::infer_from_proto(proto),
    };
    if !kind.allows_proto(proto) {
        return Err(ApiError::bad_request(format!(
            "{} 不支持 {} 协议（可用：{}）",
            kind.label(),
            proto,
            kind.allowed_protos_label()
        )));
    }

    let local_addr = req.local_addr.trim().to_string();
    local_addr.parse::<SocketAddr>().map_err(|e| {
        ApiError::bad_request(format!("local_addr 非法（应形如 127.0.0.1:8080）: {e}"))
    })?;

    let existing = state
        .store
        .list_tunnels_of_client(&client_id)
        .await
        .map_err(ApiError::from)?;
    if existing.len() >= cfg.limits.max_tunnels_per_client as usize {
        return Err(ApiError::conflict(format!(
            "该客户端的隧道数已达上限 {}",
            cfg.limits.max_tunnels_per_client
        )));
    }
    if existing.iter().any(|t| t.name == name) {
        return Err(ApiError::conflict(format!("隧道名已存在: {name}")));
    }

    // 各分类的「入口参数」完全不同：
    // - 域名解析：要 Host（必要时由 default_domain 推导），不要端口
    // - 端口转发：要公网端口（可自动分配），不要 Host
    // - 私有 / P2P：不暴露公网入口，改为签发访问密钥
    let (remote_port, host, access_key) = match kind {
        TunnelKind::Domain => {
            let host = match req.host.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(h) => h.to_string(),
                None => match cfg.ingress.default_domain.as_deref() {
                    Some(domain) => format!("{}.{}", name, domain.trim_start_matches('.')),
                    None => {
                        return Err(ApiError::bad_request(
                            "域名解析需要 host，或先在配置里设置 ingress.default_domain",
                        ))
                    }
                },
            };
            (None, Some(host), None)
        }
        TunnelKind::Port => {
            // 端口池按「该客户端所属节点」取，而不是一律用全局配置。
            let (lo, hi) = resolve_port_pool(&state, client.node_id.as_deref(), &cfg).await?;
            let port = match req.remote_port {
                Some(p) => p,
                None => allocate_port(lo, hi, &existing)?,
            };
            if port < i64::from(lo) || port > i64::from(hi) {
                return Err(ApiError::bad_request(format!(
                    "remote_port 必须落在 {lo}-{hi} 区间内（该客户端所属节点的端口池）"
                )));
            }
            if existing.iter().any(|t| t.remote_port == Some(port)) {
                return Err(ApiError::conflict(format!("公网端口已被占用: {port}")));
            }
            (Some(port), None, None)
        }
        TunnelKind::Private | TunnelKind::P2p => {
            // 这两类不暴露公网入口（访问端凭密钥在自己那边监听），因此顺手填的
            // remote_port / host 一定是误解，直接拒绝比静默忽略更不容易踩坑。
            if req.remote_port.is_some() {
                return Err(ApiError::bad_request(format!(
                    "{} 不分配公网端口，请去掉 remote_port",
                    kind.label()
                )));
            }
            if req
                .host
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty())
            {
                return Err(ApiError::bad_request(format!(
                    "{} 不走 Host 路由，请去掉 host",
                    kind.label()
                )));
            }
            (None, None, Some(rscross_auth::new_access_key()))
        }
    };
    let allow_relay = req.allow_relay.unwrap_or(true);

    let now = rscross_common::time::now_rfc3339();
    let record = TunnelRecord {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: client_id.clone(),
        name: name.clone(),
        kind: kind.as_str().to_string(),
        proto: proto.as_str().to_string(),
        local_addr: local_addr.clone(),
        remote_port,
        host: host.clone(),
        // 路径前缀只对域名解析有意义，其余分类一律留空，免得配置里躺着看不懂的字段
        path_prefix: match kind {
            TunnelKind::Domain => req.path_prefix.clone().filter(|s| !s.trim().is_empty()),
            _ => None,
        },
        access_key,
        allow_relay,
        enabled: req.enabled.unwrap_or(true),
        rate_limit_kbps: req
            .rate_limit_kbps
            .unwrap_or(i64::from(cfg.limits.default_rate_limit_kbps))
            .max(0),
        conn_limit: req
            .conn_limit
            .unwrap_or(i64::from(cfg.limits.default_conn_limit))
            .max(0),
        created_at: now.clone(),
        updated_at: now,
    };

    state
        .store
        .insert_tunnel(record.clone())
        .await
        .map_err(map_store_conflict)?;
    state
        .audit(
            Some(&user.id),
            "create_tunnel",
            Some(format!("{}:{}", record.client_id, record.name)),
            Some(format!(
                "kind={} proto={} ← {}{}",
                kind,
                proto,
                local_addr,
                if record.access_key.is_some() {
                    "（已签发访问密钥）"
                } else {
                    ""
                }
            )),
            &headers,
        )
        .await;
    tracing::info!(
        tunnel = %record.name,
        kind = %kind,
        proto = %record.proto,
        local = %record.local_addr,
        "隧道已创建，等待客户端心跳生效"
    );

    Ok(Json(record))
}

/// `PATCH /api/v1/tunnels/{id}`
pub async fn patch_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchTunnelRequest>,
) -> Result<Json<TunnelRecord>, ApiError> {
    let user = state.require_admin(&headers).await?;

    let existing = state
        .store
        .find_tunnel(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("隧道不存在"))?;

    if let Some(raw) = req.local_addr.as_deref() {
        raw.trim()
            .parse::<SocketAddr>()
            .map_err(|e| ApiError::bad_request(format!("local_addr 非法: {e}")))?;
    }

    let patch = TunnelPatch {
        id: id.clone(),
        name: match req.name.as_deref() {
            Some(raw) => Some(normalize_name(raw)?),
            None => None,
        },
        proto: None,
        local_addr: req.local_addr.as_ref().map(|s| s.trim().to_string()),
        remote_port: req.remote_port.map(Some),
        host: req.host.clone().map(Some),
        path_prefix: req.path_prefix.clone().map(Some),
        // 访问密钥不走 PATCH：轮换是独立动作（见 `rotate_access_key`），
        // 混在通用补丁里容易在「只想改个名字」时顺手把密钥清掉。
        access_key: None,
        allow_relay: req.allow_relay,
        enabled: req.enabled,
        rate_limit_kbps: req.rate_limit_kbps.map(|v| v.max(0)),
        conn_limit: req.conn_limit.map(|v| v.max(0)),
    };

    state
        .store
        .update_tunnel(patch)
        .await
        .map_err(map_store_conflict)?;
    state
        .audit(
            Some(&user.id),
            "update_tunnel",
            Some(format!("{}:{}", existing.client_id, existing.name)),
            None,
            &headers,
        )
        .await;

    let updated = state
        .store
        .find_tunnel(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("隧道不存在"))?;
    Ok(Json(updated))
}

/// `DELETE /api/v1/tunnels/{id}`
pub async fn delete_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let existing = state
        .store
        .find_tunnel(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("隧道不存在"))?;
    state
        .store
        .delete_tunnel(&id)
        .await
        .map_err(ApiError::from)?;
    state
        .audit(
            Some(&user.id),
            "delete_tunnel",
            Some(format!("{}:{}", existing.client_id, existing.name)),
            None,
            &headers,
        )
        .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /api/v1/tunnels/{id}/access-key` —— 轮换访问密钥。
///
/// 只对私有 / P2P 隧道有意义。密钥外泄时的处置动作：轮换后旧密钥立即失效，
/// 访问端必须换用新密钥重新建立本地入口。
pub async fn rotate_access_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TunnelRecord>, ApiError> {
    let user = state.require_admin(&headers).await?;
    let existing = state
        .store
        .find_tunnel(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("隧道不存在"))?;

    let kind = TunnelKind::parse(&existing.kind).unwrap_or_default();
    if !kind.needs_access_key() {
        return Err(ApiError::bad_request(format!(
            "{} 不使用访问密钥，无需轮换",
            kind.label()
        )));
    }

    let key = new_access_key();
    state
        .store
        .update_tunnel(TunnelPatch {
            id: id.clone(),
            access_key: Some(Some(key)),
            ..Default::default()
        })
        .await
        .map_err(ApiError::from)?;

    state
        .audit(
            Some(&user.id),
            "rotate_tunnel_access_key",
            Some(format!("{}:{}", existing.client_id, existing.name)),
            Some(format!("kind={kind}")),
            &headers,
        )
        .await;
    tracing::warn!(tunnel = %existing.name, "已轮换隧道访问密钥，旧密钥立即失效");

    let updated = state
        .store
        .find_tunnel(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("隧道不存在"))?;
    Ok(Json(updated))
}

/// 从给定端口池里挑一个尚未被占用的端口。
///
/// 端口池由调用方传入（见 `resolve_port_pool`），不在这里读全局配置 ——
/// 否则「节点单独配了端口池」这件事会在自动分配这条路径上被静默忽略，
/// 用户只会看到端口落在自己没放行的区间里。
fn allocate_port(lo: u16, hi: u16, existing: &[TunnelRecord]) -> Result<i64, ApiError> {
    let used: std::collections::HashSet<i64> =
        existing.iter().filter_map(|t| t.remote_port).collect();
    for port in lo..=hi {
        let as_i64 = i64::from(port);
        if !used.contains(&as_i64) {
            return Ok(as_i64);
        }
    }
    Err(ApiError::conflict(format!(
        "端口池 {lo}-{hi} 已耗尽，请扩大该节点的端口池（未单独设置时改全局 ingress.port_range）"
    )))
}

/// 决定某个客户端可用的公网端口池。
///
/// 优先用**该客户端所属节点**的配置：节点常分布在不同云厂商，各自安全组
/// 放行的端口段并不一致，只有一份全局配置时总有一边「隧道建成了、外面却连
/// 不进来」，而症状只出现在访问端，控制台上完全看不出所以然。
///
/// 节点没配、或客户端尚未归属任何节点时，回落到全局 `ingress.port_range`。
async fn resolve_port_pool(
    state: &AppState,
    node_id: Option<&str>,
    cfg: &ConsoleFile,
) -> Result<(u16, u16), ApiError> {
    if let Some(node_id) = node_id {
        if let Some(node) = state
            .store
            .find_node(node_id)
            .await
            .map_err(ApiError::from)?
        {
            if let Some(raw) = node.port_range.as_deref().filter(|r| !r.trim().is_empty()) {
                match parse_port_range(raw) {
                    Ok(pool) => return Ok(pool),
                    // 库里可能存着早期版本写进去的非法值（那时这一列还没有校验）。
                    // 此时**不能**直接报错 —— 那会让该节点上的隧道彻底建不出来，
                    // 而用户手上只有一句「端口池非法」，无从下手。回落到全局并留下
                    // 日志，比让功能完全不可用要好。
                    Err(e) => tracing::warn!(
                        node = %node.name,
                        range = raw,
                        error = %e,
                        "节点端口池配置非法，已回落到全局 ingress.port_range"
                    ),
                }
            }
        }
    }
    parse_port_range(&cfg.ingress.port_range).map_err(ApiError::from)
}

/// 生成客户端接入命令。
///
/// 客户端只与控制台对话；数据面坐标（连哪台服务端节点）由控制台在注册响应里下发，
/// 因此命令里**不需要**出现节点地址 —— 这也让「把客户端迁到另一台节点」不需要改客户端配置。
fn build_enroll_command(cfg: &ConsoleFile, name: Option<&str>, token: &str) -> String {
    let console = console_url_of(cfg);
    match name {
        Some(name) => {
            format!("rscross-client --console {console} --name {name} --enroll-token {token}")
        }
        // 没填客户端名时**整段省略 `--name`**，而不是塞一个 `<节点名>` 占位符：
        // 那对尖括号在 shell 里是「输入重定向」，用户复制粘贴会立刻撞上
        // `syntax error near unexpected token`，且报错位置在命令中段，
        // 很难联想到是控制台生成的文案有问题。省略后由客户端自报名称，
        // 也正好对应表单上「留空则注册时自动命名」的提示。
        None => format!("rscross-client --console {console} --enroll-token {token}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_allocation_skips_used() {
        let existing = vec![TunnelRecord {
            id: "t".into(),
            client_id: "c".into(),
            name: "a".into(),
            kind: "port".into(),
            proto: "tcp".into(),
            local_addr: "127.0.0.1:1".into(),
            remote_port: Some(20000),
            host: None,
            path_prefix: None,
            access_key: None,
            allow_relay: true,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }];
        assert_eq!(
            allocate_port(20000, 30000, &existing).expect("allocate"),
            20001
        );
    }

    #[test]
    fn allocate_port_honours_the_given_pool_and_reports_exhaustion() {
        // 端口池是按节点传进来的：自动分配必须落在该区间内，
        // 否则「节点配了端口池」在自动分配这条路径上会被静默忽略。
        let existing = vec![TunnelRecord {
            id: "t".into(),
            client_id: "c".into(),
            name: "a".into(),
            kind: "port".into(),
            proto: "tcp".into(),
            local_addr: "127.0.0.1:1".into(),
            remote_port: Some(45000),
            host: None,
            path_prefix: None,
            access_key: None,
            allow_relay: true,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }];
        assert_eq!(
            allocate_port(45000, 45010, &existing).expect("allocate"),
            45001,
            "应从给定池里挑，而不是全局默认的 20000 起"
        );

        // 池只有两个端口且都被占了 → 必须报错，不能越界往外分。
        let full = vec![
            TunnelRecord {
                remote_port: Some(45000),
                ..existing[0].clone()
            },
            TunnelRecord {
                remote_port: Some(45001),
                ..existing[0].clone()
            },
        ];
        assert!(allocate_port(45000, 45001, &full).is_err());
    }

    #[test]
    fn enroll_command_targets_console_not_node() {
        let mut cfg = ConsoleFile::default();
        cfg.console.public_url = Some("https://panel.example.com".to_string());
        let cmd = build_enroll_command(&cfg, Some("node-1-laptop"), "rse_abc");
        assert!(cmd.contains("--console https://panel.example.com"));
        assert!(cmd.contains("--name node-1-laptop"));
        assert!(cmd.contains("--enroll-token rse_abc"));
        assert!(
            !cmd.contains("--tunnel-server"),
            "客户端不应被要求手填节点地址：归属由控制台下发"
        );
    }

    #[test]
    fn enroll_command_without_name_is_copy_paste_safe() {
        // 没填名字时不能出现 `<节点名>` 这类占位符：尖括号在 shell 里是重定向，
        // 用户复制粘贴会直接报语法错。这条钉住命令必须是「原样可执行」的。
        let cfg = ConsoleFile::default();
        let cmd = build_enroll_command(&cfg, None, "rse_abc");
        assert!(!cmd.contains("--name"), "未命名时不该出现 --name：{cmd}");
        assert!(!cmd.contains('<') && !cmd.contains('>'), "命令里不该有尖括号：{cmd}");
        assert!(cmd.contains("--enroll-token rse_abc"));
    }
}
