//! 认证接口：登录、注册、令牌校验

use axum::extract::State;
use axum::Json;
use serde::Deserialize;

use rscross_common::crypto::{self, JwtPayload};
use rscross_common::error::{AppError, AppResult};
use rscross_common::response::ApiResponse;

use crate::AppState;

/// 登录请求
#[derive(Debug, Deserialize)]
pub struct LoginReq {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

/// 注册请求
#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub code: String,
}

/// 重置密码请求
#[derive(Debug, Deserialize)]
pub struct ResetReq {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub old_password: String,
    #[serde(default)]
    pub new_password: String,
}

/// 登录
pub async fn auth_login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Json<ApiResponse<serde_json::Value>> {
    Json(login_handler(state, req).await.into())
}

async fn login_handler(state: AppState, req: LoginReq) -> AppResult<serde_json::Value> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(AppError::invalid("请输入用户名和密码"));
    }

    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

    let row: Option<(String, String, String, i32)> = sqlx::query_as(
        "SELECT code, password, role, status FROM system_users WHERE username = ?",
    )
    .bind(&req.username)
    .fetch_optional(pool)
    .await?;

    let Some((code, hash, role, status)) = row else {
        return Err(AppError::invalid("用户名或密码错误"));
    };

    if status != 1 {
        return Err(AppError::Forbidden("账号已被封禁".to_string()));
    }

    if !crypto::verify_password(&req.password, &hash) {
        return Err(AppError::invalid("用户名或密码错误"));
    }

    let now = chrono::Utc::now().timestamp();
    let payload = JwtPayload {
        code: code.clone(),
        role: role.clone(),
        iat: now,
        exp: now + 7 * 24 * 3600,
    };
    let token = crypto::jwt_encode(&payload, &state.config.inner.jwt_secret)?;

    Ok(serde_json::json!({
        "token": token,
        "code": code,
        "role": role,
        "username": req.username,
    }))
}

/// 令牌校验
pub async fn auth_check(State(state): State<AppState>) -> Json<ApiResponse<serde_json::Value>> {
    let result = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let _: () = sqlx::query("SELECT 1").execute(pool).await?;
        Ok::<_, AppError>(serde_json::json!({"valid": true}))
    }
    .await;
    Json(result.into())
}

/// 注册
pub async fn auth_register(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Json<ApiResponse<serde_json::Value>> {
    Json(register_handler(state, req).await.into())
}

async fn register_handler(state: AppState, req: RegisterReq) -> AppResult<serde_json::Value> {
    // 检查是否开放注册
    let enabled = get_config_value(&state, "register_enable")
        .await
        .unwrap_or_else(|| "false".to_string());
    if enabled != "true" && enabled != "1" {
        return Err(AppError::Forbidden("当前未开放注册".to_string()));
    }

    if req.username.len() < 3 || req.username.len() > 32 {
        return Err(AppError::invalid("用户名长度需在 3-32 之间"));
    }
    if req.password.len() < 6 {
        return Err(AppError::invalid("密码长度不能少于 6 位"));
    }

    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

    // 用户名唯一性
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM system_users WHERE username = ?")
        .bind(&req.username)
        .fetch_one(pool)
        .await?;
    if exists > 0 {
        return Err(AppError::Conflict("用户名已存在".to_string()));
    }

    let hash = crypto::hash_password(&req.password)?;
    let now = chrono::Utc::now();
    let code = rscross_common::util::uuid_v4();

    sqlx::query(
        "INSERT INTO system_users
         (code, allow_edit, allow_del, version, created_at, updated_at, username, password,
          role, email, status, balance, traffic_limit, tunnel_limit, allow_node, allow_client,
          level, inviter_code, checkin_enabled)
         VALUES (?, 1, 1, 1, ?, ?, ?, ?, 'user', ?, 1, 0, -1, 3, 1, 1, 0, '', 0)",
    )
    .bind(&code)
    .bind(now)
    .bind(now)
    .bind(&req.username)
    .bind(&hash)
    .bind(&req.email)
    .execute(pool)
    .await?;

    Ok(serde_json::json!({"code": code, "username": req.username}))
}

/// 重置密码
pub async fn auth_reset(
    State(state): State<AppState>,
    Json(req): Json<ResetReq>,
) -> Json<ApiResponse<serde_json::Value>> {
    let result = async {
        if req.new_password.len() < 6 {
            return Err(AppError::invalid("新密码长度不能少于 6 位"));
        }
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let hash: Option<String> =
            sqlx::query_scalar("SELECT password FROM system_users WHERE code = ?")
                .bind(&req.code)
                .fetch_optional(pool)
                .await?;
        let hash = hash.ok_or_else(|| AppError::invalid("用户不存在"))?;
        if !crypto::verify_password(&req.old_password, &hash) {
            return Err(AppError::invalid("原密码错误"));
        }
        let new_hash = crypto::hash_password(&req.new_password)?;
        sqlx::query("UPDATE system_users SET password = ?, updated_at = ? WHERE code = ?")
            .bind(new_hash)
            .bind(chrono::Utc::now())
            .bind(&req.code)
            .execute(pool)
            .await?;
        Ok(serde_json::json!({"success": true}))
    }
    .await;
    Json(result.into())
}

/// 读取系统配置值
pub async fn get_config_value(state: &AppState, name: &str) -> Option<String> {
    let pool = state.db.sqlite_pool()?;
    sqlx::query_scalar("SELECT value FROM system_configs WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}
