//! 客户端与隧道管理 API。

use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use rscross_auth::{new_enroll_token, token_hash};
use rscross_config::{parse_port_range, ServerFile};
use rscross_store::{ClientRecord, EnrollTokenRecord, TunnelPatch, TunnelRecord};
use serde::{Deserialize, Serialize};

use crate::api::{normalize_name, parse_proto};
use crate::error::ApiError;
use crate::state::AppState;

// ------------------------------------------------------------------ 客户端

/// 创建（预登记）客户端请求。
#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    /// 期望的节点名（留空则用随机名）。
    pub name: Option<String>,
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
    state.require_user(&headers).await?;
    let client = state
        .store
        .find_client(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("客户端不存在"))?;
    let tunnels = state
        .store
        .list_tunnels_of_client(&id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({
        "client": client,
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
    let expires_at = rscross_common::time::to_rfc3339(
        now + chrono::Duration::minutes(ttl as i64),
    );

    state
        .store
        .insert_enroll_token(EnrollTokenRecord {
            token_hash: token_hash(&token),
            client_name: name.clone(),
            created_by: Some(user.username.clone()),
            created_at: rscross_common::time::to_rfc3339(now),
            expires_at: expires_at.clone(),
            used_at: None,
            used_client_id: None,
        })
        .await
        .map_err(ApiError::from)?;

    let command = build_enroll_command(
        &cfg,
        name.as_deref().unwrap_or("<节点名>"),
        &token,
    );

    state
        .audit(
            Some(&user.id),
            "issue_enroll_token",
            name.clone(),
            Some(format!("有效期 {ttl} 分钟")),
            &headers,
        )
        .await;

    Ok(Json(CreateClientResponse {
        enroll_token: token,
        expires_at,
        command,
    }))
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
            .audit(Some(&user.id), "rename_client", Some(id.clone()), Some(name), &headers)
            .await;
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
                if disabled { "disable_client" } else { "enable_client" },
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
    state.store.delete_client(&id).await.map_err(ApiError::from)?;
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
    /// 协议：tcp / http / https / udp。
    pub proto: String,
    /// 本地目标地址。
    pub local_addr: String,
    /// 公网端口（tcp/udp 必填；留空则从端口池自动分配）。
    pub remote_port: Option<i64>,
    /// HTTP 路由 Host（http/https 必填或由默认域名推导）。
    pub host: Option<String>,
    /// HTTP 路径前缀。
    pub path_prefix: Option<String>,
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
    state.require_user(&headers).await?;
    let tunnels = state.store.list_tunnels().await.map_err(ApiError::from)?;
    Ok(Json(tunnels))
}

/// `GET /api/v1/clients/{id}/tunnels`
pub async fn list_client_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<TunnelRecord>>, ApiError> {
    state.require_user(&headers).await?;
    let tunnels = state
        .store
        .list_tunnels_of_client(&id)
        .await
        .map_err(ApiError::from)?;
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

    let client = state
        .store
        .find_client(&client_id)
        .await
        .map_err(ApiError::from)?;
    if client.is_none() {
        return Err(ApiError::not_found("客户端不存在"));
    }

    let name = normalize_name(&req.name)?;
    let proto = parse_proto(&req.proto)
        .ok_or_else(|| ApiError::bad_request("proto 只能是 tcp / http / https / udp"))?;
    let local_addr = req.local_addr.trim().to_string();
    local_addr
        .parse::<SocketAddr>()
        .map_err(|e| ApiError::bad_request(format!("local_addr 非法（应形如 127.0.0.1:8080）: {e}")))?;

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

    let (remote_port, host) = if proto.needs_remote_port() {
        let port = match req.remote_port {
            Some(p) => p,
            None => allocate_port(&cfg, &existing)?,
        };
        let (lo, hi) = parse_port_range(&cfg.ingress.port_range).map_err(ApiError::from)?;
        if port < i64::from(lo) || port > i64::from(hi) {
            return Err(ApiError::bad_request(format!(
                "remote_port 必须落在 {lo}-{hi} 区间内"
            )));
        }
        if existing.iter().any(|t| t.remote_port == Some(port)) {
            return Err(ApiError::conflict(format!("公网端口已被占用: {port}")));
        }
        (Some(port), None)
    } else {
        let host = match req.host.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(h) => Some(h.to_string()),
            None => match cfg.ingress.default_domain.as_deref() {
                Some(domain) => Some(format!("{}.{}", name, domain.trim_start_matches('.'))),
                None => {
                    return Err(ApiError::bad_request(
                        "http/https 隧道需要 host，或先在配置里设置 ingress.default_domain",
                    ))
                }
            },
        };
        (None, host)
    };

    let now = rscross_common::time::now_rfc3339();
    let record = TunnelRecord {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: client_id.clone(),
        name: name.clone(),
        proto: proto.as_str().to_string(),
        local_addr: local_addr.clone(),
        remote_port,
        host: host.clone(),
        path_prefix: req
            .path_prefix
            .clone()
            .filter(|s| !s.trim().is_empty()),
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
            Some(format!("{} ← {}", proto, local_addr)),
            &headers,
        )
        .await;
    tracing::info!(
        tunnel = %record.name,
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

fn allocate_port(cfg: &ServerFile, existing: &[TunnelRecord]) -> Result<i64, ApiError> {
    let (lo, hi) = parse_port_range(&cfg.ingress.port_range).map_err(ApiError::from)?;
    let used: std::collections::HashSet<i64> =
        existing.iter().filter_map(|t| t.remote_port).collect();
    for port in lo..=hi {
        let as_i64 = i64::from(port);
        if !used.contains(&as_i64) {
            return Ok(as_i64);
        }
    }
    Err(ApiError::conflict(format!(
        "端口池 {lo}-{hi} 已耗尽，请扩大 ingress.port_range"
    )))
}

/// 把「唯一约束冲突」翻译成 409，其余保持原样。
fn map_store_conflict(err: rscross_common::Error) -> ApiError {
    let text = err.to_string();
    if text.contains("UNIQUE") || text.contains("constraint") {
        ApiError::conflict("名称或端口与已有记录冲突")
    } else {
        ApiError::from(err)
    }
}

/// 生成客户端接入命令。
fn build_enroll_command(cfg: &ServerFile, name: &str, token: &str) -> String {
    let api = cfg
        .server
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", cfg.server.admin_bind));

    let host = public_host(cfg);
    let tunnel_port = cfg
        .server
        .tunnel_bind
        .parse::<SocketAddr>()
        .map(|a| a.port())
        .unwrap_or(rscross_common::DEFAULT_TUNNEL_PORT);

    format!(
        "rscross-client --server {api} --tunnel-server {host}:{tunnel_port} --name {name} --enroll-token {token}"
    )
}

fn public_host(cfg: &ServerFile) -> String {
    if let Some(url) = cfg.server.public_url.as_deref() {
        let no_scheme = url.split("://").nth(1).unwrap_or(url);
        let host_port = no_scheme.split('/').next().unwrap_or(no_scheme);
        let host = host_port.split(':').next().unwrap_or(host_port);
        if !host.is_empty() {
            return host.to_string();
        }
    }
    cfg.server
        .admin_bind
        .parse::<SocketAddr>()
        .map(|a| {
            if a.ip().is_unspecified() {
                "127.0.0.1".to_string()
            } else {
                a.ip().to_string()
            }
        })
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_allocation_skips_used() {
        let cfg = ServerFile::default();
        let existing = vec![TunnelRecord {
            id: "t".into(),
            client_id: "c".into(),
            name: "a".into(),
            proto: "tcp".into(),
            local_addr: "127.0.0.1:1".into(),
            remote_port: Some(20000),
            host: None,
            path_prefix: None,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }];
        let port = allocate_port(&cfg, &existing).expect("allocate");
        assert_eq!(port, 20001);
    }

    #[test]
    fn public_host_prefers_public_url() {
        let mut cfg = ServerFile::default();
        cfg.server.public_url = Some("https://tunnel.example.com/".to_string());
        assert_eq!(public_host(&cfg), "tunnel.example.com");

        cfg.server.public_url = None;
        cfg.server.admin_bind = "0.0.0.0:7800".to_string();
        assert_eq!(public_host(&cfg), "127.0.0.1");

        cfg.server.admin_bind = "10.0.0.5:7800".to_string();
        assert_eq!(public_host(&cfg), "10.0.0.5");
    }

    #[test]
    fn enroll_command_contains_endpoint_and_token() {
        let mut cfg = ServerFile::default();
        cfg.server.public_url = Some("https://t.example.com".to_string());
        let cmd = build_enroll_command(&cfg, "node-1", "rse_abc");
        assert!(cmd.contains("--server https://t.example.com"));
        assert!(cmd.contains("--name node-1"));
        assert!(cmd.contains("--enroll-token rse_abc"));
        assert!(cmd.contains(":7835"));
    }
}
