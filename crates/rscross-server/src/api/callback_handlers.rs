//! 节点侧 HTTP 回调：节点服务 将 Login / NewProxy / NewWorkConn 等事件回调到此
//!
//! 这些接口在原项目中也由节点侧 HubServer 通过 HTTP 调用，是 穿透内核与控制面之间的关键纽带。

use axum::body::Bytes;
use axum::extract::State;
use axum::Json;
use serde_json::json;

use rscross_common::response::ApiResponse;

use crate::AppState;

/// 节点回调统一响应
fn ok() -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse::ok(json!({"status": "success"})))
}

fn fail(msg: &str) -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse::fail(
        rscross_common::ErrorCode::Failed,
        msg,
    ))
}

/// Login 回调：节点服务校验客户端令牌
pub async fn node_auth_callback(State(state): State<AppState>, body: Bytes) -> Json<ApiResponse<serde_json::Value>> {
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail("invalid payload"),
    };

    let Some(metas) = payload.get("metadatas") else {
        return fail("missing metadatas");
    };
    let Some(node_code) = metas.get("user").and_then(|v| v.as_str()) else {
        return fail("missing user");
    };

    let Some(pool) = state.db.sqlite_pool() else {
        return fail("database unavailable");
    };

    // node_code 即用户 token
    let valid: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gost_nodes WHERE code = ? AND status = 1",
    )
    .bind(node_code)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if valid == 0 {
        return fail("node not found or disabled");
    }
    ok()
}

/// NewProxy 回调：新代理注册通知
pub async fn node_proxy_callback(
    State(state): State<AppState>,
    body: Bytes,
) -> Json<ApiResponse<serde_json::Value>> {
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail("invalid payload"),
    };

    let Some(pool) = state.db.sqlite_pool() else {
        return fail("database unavailable");
    };

    if let Some(name) = payload.get("name").and_then(|v| v.as_str()) {
        // 记录隧道归属，便于流量统计
        let code = name.split('_').next().unwrap_or(name);
        if let Ok(Some(row)) = sqlx::query_as::<_, (String, String, String)>(
            "SELECT user_code, client_code, node_code FROM gost_client_hosts WHERE code = ?",
        )
        .bind(code)
        .fetch_optional(pool)
        .await
        {
            state.cache.set_tunnel_info(crate::rpc::TunnelInfo {
                code: code.to_string(),
                user_code: row.0,
                client_code: row.1,
                node_code: row.2,
            });
        }
        tracing::debug!(name, "隧道注册回调");
    }
    ok()
}

/// CloseProxy 回调
pub async fn node_close_callback() -> Json<ApiResponse<serde_json::Value>> {
    ok()
}

/// Ping 回调
pub async fn node_ping_callback() -> Json<ApiResponse<serde_json::Value>> {
    ok()
}

/// NewWorkConn 回调：请求建立工作连接
pub async fn node_workconn_callback(
    State(state): State<AppState>,
    body: Bytes,
) -> Json<ApiResponse<serde_json::Value>> {
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail("invalid payload"),
    };

    if let Some(pool) = state.db.sqlite_pool() {
        if let Some(name) = payload.get("name").and_then(|v| v.as_str()) {
            let code = name.split('_').next().unwrap_or(name);
            let _ = sqlx::query("UPDATE gost_obs SET updated_at = ? WHERE type = ?")
                .bind(chrono::Utc::now())
                .bind(code)
                .execute(pool)
                .await;
        }
    }
    let _ = &state;
    ok()
}

/// NewUserConn 回调：用户连接建立
pub async fn node_userconn_callback() -> Json<ApiResponse<serde_json::Value>> {
    ok()
}
