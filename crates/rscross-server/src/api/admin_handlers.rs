//! 管理接口：管理员视角的全部数据操作

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use rscross_common::error::{AppError, AppResult};
use rscross_common::response::{ApiResponse, PageQuery};

use super::normal_handlers::OpReq;
use crate::api::{json_result, UserAuth};
use crate::AppState;

// ==================== 仪表盘 ====================

pub async fn admin_dashboard_count(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let count = |sql: &'static str| async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(pool)
                .await
                .unwrap_or(0)
        };
        Ok(json!({
            "userCount": count("SELECT COUNT(*) FROM system_users").await,
            "clientCount": count("SELECT COUNT(*) FROM gost_clients").await,
            "nodeCount": count("SELECT COUNT(*) FROM gost_nodes").await,
            "hostCount": count("SELECT COUNT(*) FROM gost_client_hosts").await,
            "forwardCount": count("SELECT COUNT(*) FROM gost_client_forwards").await,
            "tunnelCount": count("SELECT COUNT(*) FROM gost_client_tunnels").await,
            "p2pCount": count("SELECT COUNT(*) FROM gost_client_p2_ps").await,
            "onlineClients": state.cache.stats().0,
            "onlineNodes": state.cache.stats().1,
        }))
    }
    .await;
    Json(result.into()).into_response()
}

/// 通用流量统计
async fn obs_aggregate(
    state: &AppState,
    group_by: &str,
    limit: i64,
) -> AppResult<serde_json::Value> {
    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
    let (i_col, o_col, g_col) = match group_by {
        "user" => ("user_code", "input_bytes", "user_code"),
        "node" => ("node_code", "input_bytes", "node_code"),
        "client" => ("client_code", "input_bytes", "client_code"),
        "host" => ("'host'", "input_bytes", "type"),
        "forward" => ("'forward'", "input_bytes", "type"),
        _ => ("date", "input_bytes", "date"),
    };
    let sql = format!(
        "SELECT {g_col} AS k, COALESCE(SUM({i_col}),0), COALESCE(SUM(output_bytes),0)
         FROM gost_obs GROUP BY {g_col} ORDER BY 2 DESC LIMIT {limit}"
    );
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(&sql).fetch_all(pool).await?;
    Ok(json!({
        "list": rows.iter().map(|(k, i, o)| json!({
            "key": k,
            "inputBytes": i, "outputBytes": o,
            "inputText": rscross_common::util::human_bytes(*i as u64),
            "outputText": rscross_common::util::human_bytes(*o as u64),
        })).collect::<Vec<_>>()
    }))
}

pub async fn admin_dashboard_user_obs(State(state): State<AppState>) -> Response {
    json_result(obs_aggregate(&state, "user", 20).await)
}

pub async fn admin_dashboard_node_obs(State(state): State<AppState>) -> Response {
    json_result(obs_aggregate(&state, "node", 20).await)
}

pub async fn admin_dashboard_client_obs_date(State(state): State<AppState>) -> Response {
    json_result(obs_aggregate(&state, "client", 20).await)
}

pub async fn admin_dashboard_host_obs_date(State(state): State<AppState>) -> Response {
    json_result(obs_aggregate(&state, "host", 20).await)
}

pub async fn admin_dashboard_forward_obs_date(State(state): State<AppState>) -> Response {
    json_result(obs_aggregate(&state, "forward", 20).await)
}

pub async fn admin_dashboard_tunnel_obs_date(State(state): State<AppState>) -> Response {
    json_result(obs_aggregate(&state, "tunnel", 20).await)
}

async fn obs_by_date(state: &AppState, user_code: Option<&str>) -> AppResult<serde_json::Value> {
    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
    let (sql, bind): (String, Option<String>) = match user_code {
        Some(u) => (
            "SELECT date, COALESCE(SUM(input_bytes),0), COALESCE(SUM(output_bytes),0)
             FROM gost_obs WHERE user_code = ? GROUP BY date ORDER BY date LIMIT 30"
                .to_string(),
            Some(u.to_string()),
        ),
        None => (
            "SELECT date, COALESCE(SUM(input_bytes),0), COALESCE(SUM(output_bytes),0)
             FROM gost_obs GROUP BY date ORDER BY date LIMIT 30"
                .to_string(),
            None,
        ),
    };
    let rows: Vec<(String, i64, i64)> = match bind {
        Some(b) => sqlx::query_as(&sql).bind(b).fetch_all(pool).await?,
        None => sqlx::query_as(&sql).fetch_all(pool).await?,
    };
    Ok(json!({
        "list": rows.iter().map(|(d, i, o)| json!({
            "date": d, "inputBytes": i, "outputBytes": o,
            "inputText": rscross_common::util::human_bytes(*i as u64),
            "outputText": rscross_common::util::human_bytes(*o as u64),
        })).collect::<Vec<_>>()
    }))
}

pub async fn admin_dashboard_user_obs_date(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    Json(
        obs_by_date(&state, q.get("userCode").map(|s| s.as_str()))
            .await
            .into(),
    )
    .into_response()
}

pub async fn admin_dashboard_node_obs_date(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    Json(
        obs_by_date(&state, q.get("nodeCode").map(|s| s.as_str()))
            .await
            .into(),
    )
    .into_response()
}

// ==================== 客户端 ====================

pub async fn admin_client_list(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String, String, String, i32, i32, String)> = sqlx::query_as(
            "SELECT code, `key`, name, user_code, status, enable, updated_at
                 FROM gost_clients ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "key": r.1, "name": r.2, "userCode": r.3,
                "status": r.4, "enable": r.5, "updatedAt": r.6,
                "online": state.cache.is_client_online(&r.0),
            })).collect::<Vec<_>>()
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_client_page(
    State(state): State<AppState>,
    Json(q): Json<PageQuery>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gost_clients")
            .fetch_one(pool)
            .await?;
        let rows: Vec<(String, String, String, String, i32)> = sqlx::query_as(
            "SELECT code, `key`, name, user_code, status FROM gost_clients
             ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(q.page_size() as i64)
        .bind(q.offset() as i64)
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "key": r.1, "name": r.2, "userCode": r.3, "status": r.4,
            })).collect::<Vec<_>>(),
            "total": total, "page": q.page(), "pageSize": q.page_size(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_client_create(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let key = rscross_common::util::generate_key();
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO gost_clients
             (code, allow_edit, allow_del, version, created_at, updated_at, `key`, name,
              user_code, status, enable, node_limit, remark)
             VALUES (?, 1, 1, 1, ?, ?, ?, ?, ?, 1, 1, 1, '')",
        )
        .bind(&code)
        .bind(now)
        .bind(now)
        .bind(&key)
        .bind(if req.name.is_empty() {
            "未命名客户端"
        } else {
            &req.name
        })
        .bind(&req.client_code)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code, "key": key }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_client_delete(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        state.engine.stop(&req.code, "管理员删除");
        for t in [
            "gost_client_hosts",
            "gost_client_forwards",
            "gost_client_tunnels",
            "gost_client_p2_ps",
            "gost_client_proxies",
        ] {
            sqlx::query(&format!("DELETE FROM {t} WHERE client_code = ?"))
                .bind(&req.code)
                .execute(pool)
                .await?;
        }
        sqlx::query("DELETE FROM gost_clients WHERE code = ?")
            .bind(&req.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_client_logger_page(
    State(_state): State<AppState>,
    Json(_q): Json<PageQuery>,
) -> Response {
    Json(ApiResponse::ok(
        json!({"list": [], "total": 0, "page": 1, "pageSize": 20}),
    ))
    .into_response()
}

pub async fn admin_node_logger_page(
    State(_state): State<AppState>,
    Json(_q): Json<PageQuery>,
) -> Response {
    Json(ApiResponse::ok(
        json!({"list": [], "total": 0, "page": 1, "pageSize": 20}),
    ))
    .into_response()
}

// ==================== 节点 ====================

pub async fn admin_node_list(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            i32,
            i32,
            String,
        )> = sqlx::query_as(
            "SELECT code, `key`, name, ip, port, http_port, status, enable, user_code
                 FROM gost_nodes ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "key": r.1, "name": r.2, "ip": r.3, "port": r.4,
                "httpPort": r.5, "status": r.6, "enable": r.7, "userCode": r.8,
                "online": state.cache.is_node_online(&r.0),
            })).collect::<Vec<_>>()
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_page(State(state): State<AppState>, Json(q): Json<PageQuery>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gost_nodes")
            .fetch_one(pool)
            .await?;
        let rows: Vec<(String, String, String, String, i32)> = sqlx::query_as(
            "SELECT code, `key`, name, ip, status FROM gost_nodes
             ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(q.page_size() as i64)
        .bind(q.offset() as i64)
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "key": r.1, "name": r.2, "ip": r.3, "status": r.4,
            })).collect::<Vec<_>>(),
            "total": total, "page": q.page(), "pageSize": q.page_size(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_create(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let key = rscross_common::util::generate_key();
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO gost_nodes
             (code, allow_edit, allow_del, version, created_at, updated_at, `key`, name, ip,
              port, http_port, protocol, status, enable, user_code, max_pool_count,
              allow_domain_matcher, p2p_disable_forward, bandwidth_limit, bandwidth_usage)
             VALUES (?, 1, 1, 1, ?, ?, ?, ?, ?, ?, ?, 'tcp', 1, 1, ?, 5, 0, 0, 0, 0)",
        )
        .bind(&code)
        .bind(now)
        .bind(now)
        .bind(&key)
        .bind(if req.name.is_empty() {
            "未命名节点"
        } else {
            &req.name
        })
        .bind(&req.target_ip)
        .bind(if req.port.is_empty() {
            "7000"
        } else {
            &req.port
        })
        .bind(if req.target_port.is_empty() {
            "8080"
        } else {
            &req.target_port
        })
        .bind(&req.client_code)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code, "key": key }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_update(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let affected = sqlx::query(
            "UPDATE gost_nodes SET name = ?, ip = ?, port = ?, http_port = ?,
             enable = ?, updated_at = ? WHERE code = ?",
        )
        .bind(&req.name)
        .bind(&req.target_ip)
        .bind(&req.port)
        .bind(&req.target_port)
        .bind(req.enable.unwrap_or(1))
        .bind(chrono::Utc::now())
        .bind(&req.code)
        .execute(pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::not_found("节点不存在"));
        }
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_delete(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        state.engine.remove(&req.code);
        for t in [
            "gost_client_hosts",
            "gost_client_forwards",
            "gost_client_tunnels",
            "gost_client_p2_ps",
            "gost_client_proxies",
        ] {
            sqlx::query(&format!("DELETE FROM {t} WHERE node_code = ?"))
                .bind(&req.code)
                .execute(pool)
                .await?;
        }
        sqlx::query("DELETE FROM gost_nodes WHERE code = ?")
            .bind(&req.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_query(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT code, `key`, name, ip FROM gost_nodes WHERE code = ? OR `key` = ?",
        )
        .bind(&req.code)
        .bind(&req.code)
        .fetch_optional(pool)
        .await?;
        match row {
            Some(r) => Ok(json!({
                "code": r.0, "key": r.1, "name": r.2, "ip": r.3,
                "online": state.cache.is_node_online(&r.0),
            })),
            None => Err(AppError::not_found("节点不存在")),
        }
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_clean_port(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let removed = sqlx::query("DELETE FROM gost_node_ports WHERE status = 0")
            .execute(pool)
            .await?
            .rows_affected();
        Ok(json!({ "removed": removed }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_rule_list(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT code, domain FROM gost_node_domains WHERE status = 1")
                .fetch_all(pool)
                .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({"code": r.0, "domain": r.1})).collect::<Vec<_>>()
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_bind_update(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO gost_node_binds
             (code, node_code, user_code, client_code, status, created_at, updated_at)
             VALUES (?, ?, '', ?, 1, ?, ?)",
        )
        .bind(&code)
        .bind(&req.node_code)
        .bind(&req.client_code)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 节点配置 ====================

pub async fn admin_node_config_list(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT code, name, content, content_type FROM gost_node_configs ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "name": r.1, "content": r.2, "contentType": r.3,
            })).collect::<Vec<_>>()
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_config_page(
    State(state): State<AppState>,
    Json(q): Json<PageQuery>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gost_node_configs")
            .fetch_one(pool)
            .await?;
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT code, name, content_type FROM gost_node_configs
             ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(q.page_size() as i64)
        .bind(q.offset() as i64)
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "name": r.1, "contentType": r.2,
            })).collect::<Vec<_>>(),
            "total": total, "page": q.page(), "pageSize": q.page_size(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_config_create(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO gost_node_configs
             (code, allow_edit, allow_del, version, created_at, updated_at, config_type,
              content, content_type, status, name, user_code)
             VALUES (?, 1, 1, 1, ?, ?, 'node', ?, ?, 1, ?, ?)",
        )
        .bind(&code)
        .bind(now)
        .bind(now)
        .bind(&req.content)
        .bind(if req.content_type.is_empty() {
            "yaml"
        } else {
            &req.content_type
        })
        .bind(if req.name.is_empty() {
            "未命名配置"
        } else {
            &req.name
        })
        .bind(&req.client_code)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_config_update(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let affected = sqlx::query(
            "UPDATE gost_node_configs SET name = ?, content = ?, content_type = ?,
             updated_at = ? WHERE code = ?",
        )
        .bind(&req.name)
        .bind(&req.content)
        .bind(&req.content_type)
        .bind(chrono::Utc::now())
        .bind(&req.code)
        .execute(pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::not_found("配置不存在"));
        }
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_node_config_delete(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        sqlx::query("DELETE FROM gost_node_configs WHERE code = ?")
            .bind(&req.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 隧道管理（管理员） ====================

macro_rules! admin_tunnel_list {
    ($name:ident, $table:literal) => {
        pub async fn $name(State(state): State<AppState>) -> Response {
            let result: AppResult<serde_json::Value> = async {
                let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
                let rows: Vec<(String, String, String, String, String, String, i32)> =
                    sqlx::query_as(&format!(
                        "SELECT code, name, target_ip, target_port, user_code, client_code, enable
                         FROM {} ORDER BY id DESC", $table
                    ))
                    .fetch_all(pool)
                    .await?;
                Ok(json!({
                    "list": rows.iter().map(|r| json!({
                        "code": r.0, "name": r.1, "targetIp": r.2, "targetPort": r.3,
                        "userCode": r.4, "clientCode": r.5, "enable": r.6,
                    })).collect::<Vec<_>>()
                }))
            }
            .await;
            Json(result.into()).into_response()
        }
    };
}

macro_rules! admin_tunnel_page {
    ($name:ident, $table:literal) => {
        pub async fn $name(State(state): State<AppState>, Json(q): Json<PageQuery>) -> Response {
            let result: AppResult<serde_json::Value> = async {
                let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
                let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {}", $table))
                    .fetch_one(pool)
                    .await?;
                let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(&format!(
                    "SELECT code, name, target_ip, target_port, user_code FROM {}
                     ORDER BY id DESC LIMIT ? OFFSET ?", $table
                ))
                .bind(q.page_size() as i64)
                .bind(q.offset() as i64)
                .fetch_all(pool)
                .await?;
                Ok(json!({
                    "list": rows.iter().map(|r| json!({
                        "code": r.0, "name": r.1, "targetIp": r.2,
                        "targetPort": r.3, "userCode": r.4,
                    })).collect::<Vec<_>>(),
                    "total": total, "page": q.page(), "pageSize": q.page_size(),
                }))
            }
            .await;
            Json(result.into()).into_response()
        }
    };
}

macro_rules! admin_tunnel_config {
    ($name:ident, $table:literal) => {
        pub async fn $name(
            State(state): State<AppState>,
            Json(req): Json<OpReq>,
        ) -> Response {
            let result: AppResult<serde_json::Value> = async {
                let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
                let client_code: Option<String> = sqlx::query_scalar(&format!(
                    "SELECT client_code FROM {} WHERE code = ?", $table
                ))
                .bind(&req.code)
                .fetch_optional(pool)
                .await?;
                let Some(cc) = client_code else {
                    return Err(AppError::not_found("隧道不存在"));
                };
                crate::rpc::dispatch_all_client_config(&state, &cc).await;
                Ok(json!({ "success": true }))
            }
            .await;
            Json(result.into()).into_response()
        }
    };
}

macro_rules! admin_tunnel_delete {
    ($name:ident, $table:literal) => {
        pub async fn $name(
            State(state): State<AppState>,
            Json(req): Json<OpReq>,
        ) -> Response {
            let result: AppResult<serde_json::Value> = async {
                let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
                let client_code: Option<String> = sqlx::query_scalar(&format!(
                    "SELECT client_code FROM {} WHERE code = ?", $table
                ))
                .bind(&req.code)
                .fetch_optional(pool)
                .await?;
                sqlx::query(&format!("DELETE FROM {} WHERE code = ?", $table))
                    .bind(&req.code)
                    .execute(pool)
                    .await?;
                sqlx::query("DELETE FROM gost_auths WHERE tunnel_code = ?")
                    .bind(&req.code)
                    .execute(pool)
                    .await?;
                if let Some(cc) = client_code {
                    if let Some(svc) = state.engine.agent(&cc) {
                        let _ = svc.remove_proxy(&req.code).await;
                    }
                }
                Ok(json!({ "success": true }))
            }
            .await;
            Json(result.into()).into_response()
        }
    };
}

admin_tunnel_list!(admin_host_list, "gost_client_hosts");
admin_tunnel_page!(admin_host_page, "gost_client_hosts");
admin_tunnel_config!(admin_host_config, "gost_client_hosts");
admin_tunnel_delete!(admin_host_delete, "gost_client_hosts");

admin_tunnel_list!(admin_forward_list, "gost_client_forwards");
admin_tunnel_page!(admin_forward_page, "gost_client_forwards");
admin_tunnel_config!(admin_forward_config, "gost_client_forwards");
admin_tunnel_delete!(admin_forward_delete, "gost_client_forwards");

admin_tunnel_list!(admin_tunnel_list, "gost_client_tunnels");
admin_tunnel_page!(admin_tunnel_page, "gost_client_tunnels");
admin_tunnel_config!(admin_tunnel_config, "gost_client_tunnels");
admin_tunnel_delete!(admin_tunnel_delete, "gost_client_tunnels");

admin_tunnel_list!(admin_p2p_list, "gost_client_p2_ps");
admin_tunnel_page!(admin_p2p_page, "gost_client_p2_ps");
admin_tunnel_config!(admin_p2p_config, "gost_client_p2_ps");
admin_tunnel_delete!(admin_p2p_delete, "gost_client_p2_ps");

admin_tunnel_list!(admin_proxy_list, "gost_client_proxies");
admin_tunnel_page!(admin_proxy_page, "gost_client_proxies");
admin_tunnel_config!(admin_proxy_config, "gost_client_proxies");
admin_tunnel_delete!(admin_proxy_delete, "gost_client_proxies");

pub async fn admin_host_create(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    super::normal_handlers::normal_host_create(State(state), Json(req)).await
}

pub async fn admin_host_update(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    super::normal_handlers::normal_host_update(State(state), Json(req)).await
}

pub async fn admin_forward_create(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    super::normal_handlers::normal_forward_create(State(state), Json(req)).await
}

pub async fn admin_tunnel_create(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    super::normal_handlers::normal_tunnel_create(State(state), Json(req)).await
}

pub async fn admin_tunnel_update(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    super::normal_handlers::normal_tunnel_update(State(state), Json(req)).await
}

pub async fn admin_p2p_create(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    super::normal_handlers::normal_p2p_create(State(state), Json(req)).await
}

pub async fn admin_p2p_update(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    super::normal_handlers::normal_p2p_update(State(state), Json(req)).await
}

// ==================== 系统用户 ====================

pub async fn admin_user_list(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String, String, i32, i64, i32)> = sqlx::query_as(
            "SELECT code, username, role, status, balance, tunnel_limit
             FROM system_users ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "username": r.1, "role": r.2,
                "status": r.3, "balance": r.4, "tunnelLimit": r.5,
            })).collect::<Vec<_>>()
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_user_page(State(state): State<AppState>, Json(q): Json<PageQuery>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM system_users")
            .fetch_one(pool)
            .await?;
        let rows: Vec<(String, String, String, i32)> = sqlx::query_as(
            "SELECT code, username, role, status FROM system_users
             ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(q.page_size() as i64)
        .bind(q.offset() as i64)
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "username": r.1, "role": r.2, "status": r.3,
            })).collect::<Vec<_>>(),
            "total": total, "page": q.page(), "pageSize": q.page_size(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_user_create(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        if req.password.len() < 6 {
            return Err(AppError::invalid("密码长度不能少于 6 位"));
        }
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM system_users WHERE username = ?")
                .bind(&req.name)
                .fetch_one(pool)
                .await?;
        if exists > 0 {
            return Err(AppError::Conflict("用户名已存在".to_string()));
        }
        let hash = rscross_common::crypto::hash_password(&req.password)?;
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO system_users
             (code, allow_edit, allow_del, version, created_at, updated_at, username, password,
              role, email, status, balance, traffic_limit, tunnel_limit, allow_node, allow_client,
              level, inviter_code, checkin_enabled)
             VALUES (?, 1, 1, 1, ?, ?, ?, ?, ?, ?, 1, 0, -1, 3, 1, 1, 0, '', 0)",
        )
        .bind(&code)
        .bind(now)
        .bind(now)
        .bind(&req.name)
        .bind(&hash)
        .bind(if req.client_code.is_empty() {
            "user"
        } else {
            &req.client_code
        })
        .bind(&req.content)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_user_update(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let affected = sqlx::query(
            "UPDATE system_users SET username = ?, role = ?, status = ?,
             balance = ?, tunnel_limit = ?, updated_at = ? WHERE code = ?",
        )
        .bind(&req.name)
        .bind(if req.client_code.is_empty() {
            "user"
        } else {
            &req.client_code
        })
        .bind(req.enable.unwrap_or(1))
        .bind(0i64)
        .bind(req.limiter.unwrap_or(0))
        .bind(chrono::Utc::now())
        .bind(&req.code)
        .execute(pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::not_found("用户不存在"));
        }
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_user_delete(State(state): State<AppState>, Json(req): Json<OpReq>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        // 保护默认管理员
        let role: Option<String> =
            sqlx::query_scalar("SELECT role FROM system_users WHERE code = ?")
                .bind(&req.code)
                .fetch_optional(pool)
                .await?;
        if role.as_deref() == Some("admin") {
            let admins: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM system_users WHERE role = 'admin'")
                    .fetch_one(pool)
                    .await?;
            if admins <= 1 {
                return Err(AppError::Forbidden("不能删除唯一的管理员".to_string()));
            }
        }
        sqlx::query("DELETE FROM system_users WHERE code = ?")
            .bind(&req.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 系统配置 ====================

async fn config_by_group(state: &AppState, group: &str) -> AppResult<serde_json::Value> {
    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT name, value FROM system_configs WHERE `group` = ?")
            .bind(group)
            .fetch_all(pool)
            .await?;
    let mut m = serde_json::Map::new();
    for (k, v) in rows {
        m.insert(k, json!(v));
    }
    Ok(json!({ "config": m }))
}

pub async fn admin_config_base(State(state): State<AppState>) -> Response {
    json_result(config_by_group(&state, "base").await)
}

pub async fn admin_config_gost(State(state): State<AppState>) -> Response {
    json_result(config_by_group(&state, "gost").await)
}

pub async fn admin_config_email(State(state): State<AppState>) -> Response {
    json_result(config_by_group(&state, "email").await)
}

// ==================== 公告 ====================

pub async fn admin_notice_list(State(state): State<AppState>) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String, String, i32)> = sqlx::query_as(
            "SELECT code, title, content, status FROM system_notices ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "title": r.1, "content": r.2, "status": r.3,
            })).collect::<Vec<_>>()
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_notice_page(
    State(state): State<AppState>,
    Json(q): Json<PageQuery>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM system_notices")
            .fetch_one(pool)
            .await?;
        let rows: Vec<(String, String, String, i32)> = sqlx::query_as(
            "SELECT code, title, content, status FROM system_notices
             ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(q.page_size() as i64)
        .bind(q.offset() as i64)
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "title": r.1, "content": r.2, "status": r.3,
            })).collect::<Vec<_>>(),
            "total": total, "page": q.page(), "pageSize": q.page_size(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_notice_create(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO system_notices
             (code, allow_edit, allow_del, version, created_at, updated_at, title, content,
              type, status)
             VALUES (?, 1, 1, 1, ?, ?, ?, ?, 'notice', 1)",
        )
        .bind(&code)
        .bind(now)
        .bind(now)
        .bind(&req.name)
        .bind(&req.content)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_notice_update(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let affected = sqlx::query(
            "UPDATE system_notices SET title = ?, content = ?, status = ?, updated_at = ?
             WHERE code = ?",
        )
        .bind(&req.name)
        .bind(&req.content)
        .bind(req.enable.unwrap_or(1))
        .bind(chrono::Utc::now())
        .bind(&req.code)
        .execute(pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::not_found("公告不存在"));
        }
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn admin_notice_delete(
    State(state): State<AppState>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        sqlx::query("DELETE FROM system_notices WHERE code = ?")
            .bind(&req.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

/// 保留：避免未使用告警
#[allow(dead_code)]
fn _unused(_: &UserAuth) {}
