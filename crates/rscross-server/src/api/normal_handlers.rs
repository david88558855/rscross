//! 普通用户接口：作用域限定为当前登录用户的数据

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use rscross_common::error::{AppError, AppResult};
use rscross_common::response::{ApiResponse, PageData, PageQuery};

use crate::api::UserAuth;
use crate::AppState;

/// 通用操作请求
#[derive(Debug, Default, Deserialize)]
pub struct OpReq {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub target_ip: String,
    #[serde(default)]
    pub target_port: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub target_https: i32,
    #[serde(default)]
    pub domain_prefix: String,
    #[serde(default)]
    pub custom_domain: String,
    #[serde(default)]
    pub custom_cert: String,
    #[serde(default)]
    pub custom_key: String,
    #[serde(default)]
    pub custom_force_https: i32,
    #[serde(default)]
    pub custom_domain_matcher: i32,
    #[serde(default)]
    pub node_code: String,
    #[serde(default)]
    pub client_code: String,
    #[serde(default)]
    pub enable: Option<i32>,
    #[serde(default)]
    pub use_encryption: Option<i32>,
    #[serde(default)]
    pub use_compression: Option<i32>,
    #[serde(default)]
    pub pool_count: Option<i32>,
    #[serde(default)]
    pub limiter: Option<i32>,
    #[serde(default)]
    pub proxy_protocol: Option<i32>,
    #[serde(default)]
    pub vkey: Option<String>,
    #[serde(default)]
    pub forward: Option<i32>,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub old_password: String,
    #[serde(default)]
    pub new_password: String,
}

impl OpReq {
    /// 校验目标 IP
    pub fn validate_target(&self) -> AppResult<()> {
        rscross_common::util::validate_target_ip(&self.target_ip)?;
        let p = rscross_common::util::str_must_int(&self.target_port);
        if !rscross_common::util::is_valid_port(p) {
            return Err(AppError::invalid("内网端口不合法"));
        }
        Ok(())
    }

    /// 校验目标端口（转发用）
    pub fn validate_remote_port(&self) -> AppResult<()> {
        let p = rscross_common::util::str_must_int(&self.port);
        if !rscross_common::util::is_valid_port(p) {
            return Err(AppError::invalid("外部端口不合法"));
        }
        Ok(())
    }
}

/// SQL 绑定值类型
enum SqlBind {
    Text(String),
    Int(i64),
    Time(chrono::DateTime<chrono::Utc>),
}

/// 校验当前用户存在
fn me(ext: &axum::http::Extensions) -> AppResult<UserAuth> {
    ext.get::<UserAuth>()
        .cloned()
        .ok_or(AppError::Unauthorized)
}

/// 分页查询辅助
fn page<T>(list: Vec<T>, total: i64, q: &PageQuery) -> Response {
    let data = PageData::new(list, total as u64, q);
    ApiResponse::ok(json!({
        "list": data.list,
        "total": data.total,
        "page": data.page,
        "pageSize": data.page_size,
    }))
    .into_response()
}

// ==================== 仪表盘 ====================

pub async fn normal_dashboard(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        let (input, output): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(input_bytes),0), COALESCE(SUM(output_bytes),0)
             FROM gost_obs WHERE user_code = ? AND date = ?",
        )
        .bind(&user.code)
        .bind(&date)
        .fetch_one(pool)
        .await?;

        let tunnel_count: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM gost_client_hosts WHERE user_code = ?)
                  + (SELECT COUNT(*) FROM gost_client_forwards WHERE user_code = ?)
                  + (SELECT COUNT(*) FROM gost_client_tunnels WHERE user_code = ?)
                  + (SELECT COUNT(*) FROM gost_client_p2_ps WHERE user_code = ?)",
        )
        .bind(&user.code)
        .bind(&user.code)
        .bind(&user.code)
        .bind(&user.code)
        .fetch_one(pool)
        .await?;

        Ok(json!({
            "inputBytes": input,
            "outputBytes": output,
            "totalBytes": input + output,
            "inputText": rscross_common::util::human_bytes(input as u64),
            "outputText": rscross_common::util::human_bytes(output as u64),
            "tunnelCount": tunnel_count,
        }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 客户端 ====================

pub async fn normal_client_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<serde_json::Value> = sqlx::query_as::<_, (i64, String, String, String, i32, i32, i32)>(
            "SELECT id, code, `key`, name, status, enable, node_limit
             FROM gost_clients WHERE user_code = ? ORDER BY id",
        )
        .bind(&user.code)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(id, code, key, name, status, enable, node_limit)| {
            let online = state.cache.is_client_online(&code);
            json!({
                "id": id, "code": code, "key": key, "name": name,
                "status": status, "enable": enable, "nodeLimit": node_limit,
                "online": online,
                "version": state.cache.client_version(&code),
            })
        })
        .collect();
        Ok(json!({ "list": rows }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_client_create(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        // 检查数量限制
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let limit: i64 = sqlx::query_scalar("SELECT tunnel_limit FROM system_users WHERE code = ?")
            .bind(&user.code)
            .fetch_optional(pool)
            .await?
            .unwrap_or(3);
        if limit > 0 {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gost_clients WHERE user_code = ?")
                .bind(&user.code)
                .fetch_one(pool)
                .await?;
            if count >= limit {
                return Err(AppError::Conflict(format!("客户端数量已达上限 {limit}")));
            }
        }

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
        .bind(if req.name.is_empty() { "未命名客户端" } else { &req.name })
        .bind(&user.code)
        .execute(pool)
        .await?;

        Ok(json!({ "code": code, "key": key }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_client_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        // 校验归属
        let owner: Option<String> =
            sqlx::query_scalar("SELECT user_code FROM gost_clients WHERE code = ?")
                .bind(&req.code)
                .fetch_optional(pool)
                .await?;
        if owner.as_deref() != Some(user.code.as_str()) {
            return Err(AppError::Forbidden("无权删除该客户端".to_string()));
        }

        state.engine.stop(&req.code, "客户端已删除");

        // 级联删除隧道
        for t in ["gost_client_hosts", "gost_client_forwards", "gost_client_tunnels", "gost_client_p2_ps", "gost_client_proxies"] {
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

// ==================== 域名隧道 ====================

/// 域名隧道列表
pub async fn normal_host_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    Json(list_tunnels(&state, &user.code, "gost_client_hosts").await.into()).into_response()
}

pub async fn normal_host_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(q): Json<PageQuery>,
) -> Response {
    page_tunnels(&state, &user.code, "gost_client_hosts", q).await
}

pub async fn normal_host_create(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    create_tunnel(&state, &user.code, "gost_client_hosts", req).await
}

pub async fn normal_host_update(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    update_tunnel(&state, &user.code, "gost_client_hosts", req).await
}

pub async fn normal_host_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    config_tunnel(&state, &user.code, "gost_client_hosts", &req.code).await
}

pub async fn normal_host_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    delete_tunnel(&state, &user.code, "gost_client_hosts", &req.code).await
}

// ==================== 端口转发 ====================

pub async fn normal_forward_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    Json(list_tunnels(&state, &user.code, "gost_client_forwards").await.into()).into_response()
}

pub async fn normal_forward_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(q): Json<PageQuery>,
) -> Response {
    page_tunnels(&state, &user.code, "gost_client_forwards", q).await
}

pub async fn normal_forward_create(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    create_tunnel(&state, &user.code, "gost_client_forwards", req).await
}

pub async fn normal_forward_update(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    update_tunnel(&state, &user.code, "gost_client_forwards", req).await
}

pub async fn normal_forward_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    config_tunnel(&state, &user.code, "gost_client_forwards", &req.code).await
}

pub async fn normal_forward_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    delete_tunnel(&state, &user.code, "gost_client_forwards", &req.code).await
}

// ==================== 私有隧道 ====================

pub async fn normal_tunnel_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    Json(list_tunnels(&state, &user.code, "gost_client_tunnels").await.into()).into_response()
}

pub async fn normal_tunnel_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(q): Json<PageQuery>,
) -> Response {
    page_tunnels(&state, &user.code, "gost_client_tunnels", q).await
}

pub async fn normal_tunnel_create(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    create_tunnel(&state, &user.code, "gost_client_tunnels", req).await
}

pub async fn normal_tunnel_update(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    update_tunnel(&state, &user.code, "gost_client_tunnels", req).await
}

pub async fn normal_tunnel_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    config_tunnel(&state, &user.code, "gost_client_tunnels", &req.code).await
}

pub async fn normal_tunnel_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    delete_tunnel(&state, &user.code, "gost_client_tunnels", &req.code).await
}

// ==================== P2P ====================

pub async fn normal_p2p_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    Json(list_tunnels(&state, &user.code, "gost_client_p2_ps").await.into()).into_response()
}

pub async fn normal_p2p_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(q): Json<PageQuery>,
) -> Response {
    page_tunnels(&state, &user.code, "gost_client_p2_ps", q).await
}

pub async fn normal_p2p_create(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    create_tunnel(&state, &user.code, "gost_client_p2_ps", req).await
}

pub async fn normal_p2p_update(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    update_tunnel(&state, &user.code, "gost_client_p2_ps", req).await
}

pub async fn normal_p2p_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    config_tunnel(&state, &user.code, "gost_client_p2_ps", &req.code).await
}

pub async fn normal_p2p_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    delete_tunnel(&state, &user.code, "gost_client_p2_ps", &req.code).await
}

// ==================== 代理隧道 ====================

pub async fn normal_proxy_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    Json(list_tunnels(&state, &user.code, "gost_client_proxies").await.into()).into_response()
}

pub async fn normal_proxy_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(q): Json<PageQuery>,
) -> Response {
    page_tunnels(&state, &user.code, "gost_client_proxies", q).await
}

pub async fn normal_proxy_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    config_tunnel(&state, &user.code, "gost_client_proxies", &req.code).await
}

pub async fn normal_proxy_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    delete_tunnel(&state, &user.code, "gost_client_proxies", &req.code).await
}

// ==================== 节点 ====================

pub async fn normal_node_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<serde_json::Value> =
            sqlx::query_as::<_, (String, String, String, String, String, i32)>(
                "SELECT code, name, ip, port, http_port, status FROM gost_nodes
                 WHERE user_code = ? AND status = 1 ORDER BY id",
            )
            .bind(&user.code)
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|(code, name, ip, port, http_port, status)| {
                json!({
                    "code": code, "name": name, "ip": ip, "port": port,
                    "httpPort": http_port, "status": status,
                    "online": state.cache.is_node_online(&code),
                })
            })
            .collect();
        Ok(json!({ "list": rows }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_node_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT code, name, content FROM gost_node_configs WHERE user_code = ?",
        )
        .bind(&user.code)
        .fetch_all(pool)
        .await?;
        Ok(json!({ "list": rows }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 自定义配置 ====================

pub async fn normal_cfg_list(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<serde_json::Value> = sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT code, name, content, content_type FROM frp_client_cfgs WHERE user_code = ?",
        )
        .bind(&user.code)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(code, name, content, ct)| json!({
            "code": code, "name": name, "content": content, "contentType": ct
        }))
        .collect();
        Ok(json!({ "list": rows }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_cfg_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(q): Json<PageQuery>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<serde_json::Value> = sqlx::query_as::<_, (String, String, String)>(
            "SELECT code, name, content_type FROM frp_client_cfgs
             WHERE user_code = ? ORDER BY id DESC",
        )
        .bind(&user.code)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(code, name, ct)| json!({"code": code, "name": name, "contentType": ct}))
        .collect();
        Ok(json!({ "list": rows, "total": rows.len(), "page": 1, "pageSize": q.page_size() }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_cfg_create(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO frp_client_cfgs
             (code, allow_edit, allow_del, version, created_at, updated_at, name, content,
              content_type, client_code, user_code, enable, status)
             VALUES (?, 1, 1, 1, ?, ?, ?, ?, ?, ?, ?, 1, 1)",
        )
        .bind(&code)
        .bind(now)
        .bind(now)
        .bind(if req.name.is_empty() { "未命名配置" } else { &req.name })
        .bind(&req.content)
        .bind(if req.content_type.is_empty() { "yaml" } else { &req.content_type })
        .bind(&req.client_code)
        .bind(&user.code)
        .execute(pool)
        .await?;
        Ok(json!({ "code": code }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_cfg_update(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let affected = sqlx::query(
            "UPDATE frp_client_cfgs SET name = ?, content = ?, content_type = ?, updated_at = ?
             WHERE code = ? AND user_code = ?",
        )
        .bind(&req.name)
        .bind(&req.content)
        .bind(&req.content_type)
        .bind(chrono::Utc::now())
        .bind(&req.code)
        .bind(&user.code)
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

pub async fn normal_cfg_config(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let _ = &user;
    let result: AppResult<serde_json::Value> = async {
        if let Some(svc) = state.engine.tunnel 客户端(&req.client_code) {
            let _ = svc.stop();
        }
        Ok(json!({ "success": true, "message" => "配置已生效" }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_cfg_delete(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        sqlx::query("DELETE FROM frp_client_cfgs WHERE code = ? AND user_code = ?")
            .bind(&req.code)
            .bind(&user.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 其他 ====================

pub async fn normal_client_logger() -> Response {
    (StatusCode::OK, Json(json!({"code": 0, "msg": "success", "data": {"list": []}}))).into_response()
}

pub async fn normal_obs_page(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(_q): Json<PageQuery>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT date, COALESCE(SUM(input_bytes),0), COALESCE(SUM(output_bytes),0)
             FROM gost_obs WHERE user_code = ? GROUP BY date ORDER BY date DESC LIMIT 30",
        )
        .bind(&user.code)
        .fetch_all(pool)
        .await?;
        Ok(json!({
            "list": rows.iter().map(|(d, i, o)| json!({
                "date": d, "inputBytes": i, "outputBytes": o,
                "inputText": rscross_common::util::human_bytes(*i as u64),
                "outputText": rscross_common::util::human_bytes(*o as u64),
            })).collect::<Vec<_>>(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_notice(State(state): State<AppState>) -> Response {
    super::public_handlers::public_notice(State(state)).await
}

pub async fn normal_user_info(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let row: Option<(String, String, String, i64, i32, i32)> = sqlx::query_as(
            "SELECT username, email, role, balance, tunnel_limit, status
             FROM system_users WHERE code = ?",
        )
        .bind(&user.code)
        .fetch_optional(pool)
        .await?;
        match row {
            Some((username, email, role, balance, tunnel_limit, status)) => Ok(json!({
                "code": user.code, "username": username, "email": email, "role": role,
                "balance": balance, "tunnelLimit": tunnel_limit, "status": status,
            })),
            None => Err(AppError::not_found("用户不存在")),
        }
    }
    .await;
    Json(result.into()).into_response()
}

pub async fn normal_user_reset(
    State(state): State<AppState>,
    Extension(user): Extension<UserAuth>,
    Json(req): Json<OpReq>,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        if req.new_password.len() < 6 {
            return Err(AppError::invalid("新密码长度不能少于 6 位"));
        }
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let hash: Option<String> =
            sqlx::query_scalar("SELECT password FROM system_users WHERE code = ?")
                .bind(&user.code)
                .fetch_optional(pool)
                .await?;
        let hash = hash.ok_or_else(|| AppError::not_found("用户不存在"))?;
        if !rscross_common::crypto::verify_password(&req.old_password, &hash) {
            return Err(AppError::invalid("原密码错误"));
        }
        let new_hash = rscross_common::crypto::hash_password(&req.new_password)?;
        sqlx::query("UPDATE system_users SET password = ?, updated_at = ? WHERE code = ?")
            .bind(new_hash)
            .bind(chrono::Utc::now())
            .bind(&user.code)
            .execute(pool)
            .await?;
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

// ==================== 通用隧道操作 ====================

/// 列出隧道
async fn list_tunnels(state: &AppState, user_code: &str, table: &str) -> AppResult<serde_json::Value> {
    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
    let sql = format!(
        "SELECT code, name, target_ip, target_port, node_code, client_code, enable, status
         FROM {table} WHERE user_code = ? ORDER BY id DESC"
    );
    let rows: Vec<(String, String, String, String, String, String, i32, i32)> =
        sqlx::query_as(&sql).bind(user_code).fetch_all(pool).await?;

    Ok(json!({
        "list": rows.iter().map(|r| json!({
            "code": r.0, "name": r.1, "targetIp": r.2, "targetPort": r.3,
            "nodeCode": r.4, "clientCode": r.5, "enable": r.6, "status": r.7,
        })).collect::<Vec<_>>()
    }))
}

/// 分页列出隧道
async fn page_tunnels(state: &AppState, user_code: &str, table: &str, q: PageQuery) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

        let mut where_parts = vec!["user_code = ?".to_string()];
        if let Some(kw) = &q.keyword {
            if !kw.is_empty() {
                where_parts.push("(name LIKE ? OR target_ip LIKE ?)".to_string());
            }
        }
        let where_sql = where_parts.join(" AND ");

        let count_sql = format!("SELECT COUNT(*) FROM {table} WHERE {where_sql}");
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(user_code);
        if let Some(kw) = &q.keyword {
            if !kw.is_empty() {
                let like = format!("%{kw}%");
                count_q = count_q.bind(&like).bind(&like);
            }
        }
        let total = count_q.fetch_one(pool).await?;

        let list_sql = format!(
            "SELECT code, name, target_ip, target_port, node_code, client_code, enable, status
             FROM {table} WHERE {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
        );
        let mut list_q = sqlx::query_as::<_, (String, String, String, String, String, String, i32, i32)>(&list_sql)
            .bind(user_code);
        if let Some(kw) = &q.keyword {
            if !kw.is_empty() {
                let like = format!("%{kw}%");
                list_q = list_q.bind(&like).bind(&like);
            }
        }
        let rows = list_q
            .bind(q.page_size() as i64)
            .bind(q.offset() as i64)
            .fetch_all(pool)
            .await?;

        Ok(json!({
            "list": rows.iter().map(|r| json!({
                "code": r.0, "name": r.1, "targetIp": r.2, "targetPort": r.3,
                "nodeCode": r.4, "clientCode": r.5, "enable": r.6, "status": r.7,
            })).collect::<Vec<_>>(),
            "total": total,
            "page": q.page(),
            "pageSize": q.page_size(),
        }))
    }
    .await;
    Json(result.into()).into_response()
}

/// 创建隧道
async fn create_tunnel(
    state: &AppState,
    user_code: &str,
    table: &str,
    req: OpReq,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        req.validate_target()?;
        if req.node_code.is_empty() {
            return Err(AppError::invalid("请选择节点"));
        }
        if req.client_code.is_empty() {
            return Err(AppError::invalid("请选择客户端"));
        }

        // 转发类需校验外部端口
        if table == "gost_client_forwards" {
            req.validate_remote_port()?;
        }

        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let code = rscross_common::util::uuid_v4();
        let now = chrono::Utc::now();

        // 公共列与绑定值
        let mut cols: Vec<&str> = vec![
            "code", "allow_edit", "allow_del", "version", "created_at", "updated_at",
            "name", "target_ip", "target_port", "node_code", "client_code", "user_code",
            "enable", "status", "use_encryption", "use_compression", "pool_count", "limiter",
            "limiter_total", "limiter_usage", "bandwidth_limit", "tunnel_limit", "max_conns",
            "expire_days",
        ];
        // 值统一走参数绑定，杜绝拼接注入
        let mut binds: Vec<SqlBind> = vec![
            SqlBind::Text(code.clone()),
            SqlBind::Int(1),
            SqlBind::Int(1),
            SqlBind::Int(1),
            SqlBind::Time(now),
            SqlBind::Time(now),
            SqlBind::Text(if req.name.is_empty() {
                "未命名".to_string()
            } else {
                req.name.clone()
            }),
            SqlBind::Text(req.target_ip.clone()),
            SqlBind::Text(req.target_port.clone()),
            SqlBind::Text(req.node_code.clone()),
            SqlBind::Text(req.client_code.clone()),
            SqlBind::Text(user_code.to_string()),
            SqlBind::Int(req.enable.unwrap_or(1)),
            SqlBind::Int(1),
            SqlBind::Int(req.use_encryption.unwrap_or(1)),
            SqlBind::Int(req.use_compression.unwrap_or(0)),
            SqlBind::Int(req.pool_count.unwrap_or(0)),
            SqlBind::Int(req.limiter.unwrap_or(0)),
            SqlBind::Int(0),
            SqlBind::Int(0),
            SqlBind::Int(-1),
            SqlBind::Int(0),
            SqlBind::Int(0),
            SqlBind::Int(0),
        ];

        // 各表特有列
        match table {
            "gost_client_hosts" => {
                cols.extend_from_slice(&[
                    "target_https", "domain_prefix", "custom_domain", "custom_cert",
                    "custom_key", "custom_force_https", "custom_domain_matcher",
                ]);
                binds.extend_from_slice(&[
                    SqlBind::Int(req.target_https),
                    SqlBind::Text(req.domain_prefix.clone()),
                    SqlBind::Text(req.custom_domain.clone()),
                    SqlBind::Text(req.custom_cert.clone()),
                    SqlBind::Text(req.custom_key.clone()),
                    SqlBind::Int(req.custom_force_https),
                    SqlBind::Int(req.custom_domain_matcher),
                ]);
            }
            "gost_client_forwards" => {
                cols.extend_from_slice(&["port", "proxy_protocol"]);
                binds.extend_from_slice(&[
                    SqlBind::Text(req.port.clone()),
                    SqlBind::Int(req.proxy_protocol.unwrap_or(0)),
                ]);
            }
            "gost_client_tunnels" | "gost_client_p2_ps" => {
                cols.push("vkey");
                binds.push(SqlBind::Text(String::new()));
                if table == "gost_client_p2_ps" {
                    cols.push("forward");
                    binds.push(SqlBind::Int(req.forward.unwrap_or(1)));
                }
            }
            "gost_client_proxies" => {
                cols.extend_from_slice(&["port", "auth_user", "auth_pwd"]);
                binds.extend_from_slice(&[
                    SqlBind::Text(req.port.clone()),
                    SqlBind::Text(req.name.clone()),
                    SqlBind::Text("rscross".to_string()),
                ]);
            }
            _ => {}
        }

        // 列名为静态白名单，逐一校验
        for c in &cols {
            if !c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                return Err(AppError::msg("非法列名"));
            }
        }

        let placeholders = (1..=binds.len())
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("INSERT INTO {table} ({}) VALUES ({placeholders})", cols.join(", "));

        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = match b {
                SqlBind::Text(s) => q.bind(s.clone()),
                SqlBind::Int(i) => q.bind(*i),
                SqlBind::Time(t) => q.bind(*t),
            };
        }
        q.execute(pool)
            .await
            .map_err(|e| AppError::msg(format!("创建失败: {e}")))?;

        // 生成认证信息
        sqlx::query(
            "INSERT INTO gost_auths
             (code, allow_edit, allow_del, version, created_at, updated_at, tunnel_code, user, password, status)
             VALUES (?, 1, 1, 1, ?, ?, ?, ?, ?, 1)",
        )
        .bind(rscross_common::util::uuid_v4())
        .bind(now)
        .bind(now)
        .bind(&code)
        .bind(rscross_common::util::random_hex(8))
        .bind(rscross_common::util::random_hex(8))
        .execute(pool)
        .await?;

        // 私有隧道生成访客密钥
        if table == "gost_client_tunnels" || table == "gost_client_p2_ps" {
            let vkey = rscross_common::util::generate_vkey();
            let _ = sqlx::query(&format!("UPDATE {table} SET vkey = ? WHERE code = ?"))
                .bind(&vkey)
                .bind(&code)
                .execute(pool)
                .await;
            return Ok(json!({ "code": code, "vkey": vkey }));
        }

        Ok(json!({ "code": code }))
    }
    .await;
    Json(result.into()).into_response()
}

/// 更新隧道
async fn update_tunnel(
    state: &AppState,
    user_code: &str,
    table: &str,
    req: OpReq,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        req.validate_target()?;
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

        let affected = sqlx::query(&format!(
            "UPDATE {table} SET name = ?, target_ip = ?, target_port = ?, enable = ?,
             use_encryption = ?, use_compression = ?, limiter = ?, updated_at = ?
             WHERE code = ? AND user_code = ?"
        ))
        .bind(&req.name)
        .bind(&req.target_ip)
        .bind(&req.target_port)
        .bind(req.enable.unwrap_or(1))
        .bind(req.use_encryption.unwrap_or(1))
        .bind(req.use_compression.unwrap_or(0))
        .bind(req.limiter.unwrap_or(0))
        .bind(chrono::Utc::now())
        .bind(&req.code)
        .bind(user_code)
        .execute(pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::not_found("隧道不存在或无权操作"));
        }
        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

/// 下发隧道配置
async fn config_tunnel(
    state: &AppState,
    user_code: &str,
    table: &str,
    code: &str,
) -> Response {
    let _ = table;
    let result: AppResult<serde_json::Value> = async {
        // 查隧道归属的客户端
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let client_code: Option<String> = sqlx::query_scalar(&format!(
            "SELECT client_code FROM {table} WHERE code = ? AND user_code = ?"
        ))
        .bind(code)
        .bind(user_code)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("隧道不存在"))?;

        if !state.engine.is_running(&client_code) {
            return Err(AppError::msg("客户端不在线，配置将在上线后自动生效"));
        }

        crate::rpc::dispatch_all_client_config(state, &client_code).await;
        Ok(json!({ "success": true, "message" => "配置已下发" }))
    }
    .await;
    Json(result.into()).into_response()
}

/// 删除隧道
async fn delete_tunnel(
    state: &AppState,
    user_code: &str,
    table: &str,
    code: &str,
) -> Response {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

        // 先取 client_code 以便下发移除
        let client_code: Option<String> = sqlx::query_scalar(&format!(
            "SELECT client_code FROM {table} WHERE code = ? AND user_code = ?"
        ))
        .bind(code)
        .bind(user_code)
        .fetch_optional(pool)
        .await?;

        sqlx::query(&format!("DELETE FROM {table} WHERE code = ? AND user_code = ?"))
            .bind(code)
            .bind(user_code)
            .execute(pool)
            .await?;

        sqlx::query("DELETE FROM gost_auths WHERE tunnel_code = ?")
            .bind(code)
            .execute(pool)
            .await?;

        // 通知客户端移除代理
        if let Some(cc) = client_code {
            if let Some(svc) = state.engine.tunnel 客户端(&cc) {
                let _ = svc.remove_proxy(code).await;
            }
        }

        Ok(json!({ "success": true }))
    }
    .await;
    Json(result.into()).into_response()
}

/// SQL 字符串转义（值统一用参数绑定，此处仅兜底）
fn escape(s: &str) -> String {
    s.replace('\'', "''")
}
