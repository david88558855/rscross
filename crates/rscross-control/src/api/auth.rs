//! 控制台认证：登录 / 注册 / 登出 / 当前用户 / 改密。

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rscross_auth::{hash_password, issue_session, token_hash, verify_password};
use rscross_config::ConsoleFile;
use rscross_store::UserRecord;
use serde::{Deserialize, Serialize};

use crate::api::{map_store_conflict, normalize_name, validate_password, ROLE_VIEWER};
use crate::error::ApiError;
use crate::state::{AppState, SESSION_COOKIE};

/// 登录请求。
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
}

/// 自助注册请求。
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// 期望的登录名。
    pub username: String,
    /// 密码。
    pub password: String,
}

/// 用户视图（不含任何敏感字段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserView {
    /// 用户 ID。
    pub id: String,
    /// 登录名。
    pub username: String,
    /// 角色。
    pub role: String,
    /// 是否禁用。
    #[serde(default)]
    pub disabled: bool,
    /// 创建时间。
    #[serde(default)]
    pub created_at: String,
    /// 最近登录时间。
    pub last_login_at: Option<String>,
}

/// 登录响应。
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// 会话 token（也通过 HttpOnly Cookie 下发）。
    pub token: String,
    /// 过期时间。
    pub expires_at: String,
    /// 当前用户。
    pub user: UserView,
}

/// 改密请求。
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    /// 当前密码。
    pub current_password: String,
    /// 新密码（至少 6 位）。
    pub new_password: String,
}

/// 把用户记录转成对外视图。
pub fn view(user: &UserRecord) -> UserView {
    UserView {
        id: user.id.clone(),
        username: user.username.clone(),
        role: user.role.clone(),
        disabled: user.disabled,
        created_at: user.created_at.clone(),
        last_login_at: user.last_login_at.clone(),
    }
}

/// 把 Argon2 校验放到阻塞线程池，避免占满 async worker。
pub(crate) async fn verify_password_offloaded(
    password: String,
    stored: String,
) -> Result<bool, ApiError> {
    tokio::task::spawn_blocking(move || verify_password(&password, &stored))
        .await
        .map_err(|e| ApiError::internal(format!("密码校验任务失败: {e}")))
}

/// 把 Argon2 哈希放到阻塞线程池。
pub(crate) async fn hash_password_offloaded(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::internal(format!("密码哈希任务失败: {e}")))?
        .map_err(ApiError::from)
}

/// 签发会话、下发 Cookie，并组装与登录一致的响应体。
///
/// 登录与注册共用：两条路径拿到的登录态**必须**完全一样，
/// 否则会出现「注册完能进控制台、但刷新就掉线」这类只在一条路径上出现的怪问题。
pub(crate) async fn issue_login_response(
    state: &AppState,
    cfg: &ConsoleFile,
    user: &UserRecord,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let session = issue_session(
        &state.store,
        &user.id,
        cfg.admin.session_ttl_hours,
        user_agent,
    )
    .await?;

    let max_age = cfg.admin.session_ttl_hours.max(1) * 3600;
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        session.token
    );
    let cookie_value = HeaderValue::from_str(&cookie)
        .map_err(|e| ApiError::internal(format!("会话 Cookie 生成失败: {e}")))?;

    let mut response = Json(LoginResponse {
        token: session.token,
        expires_at: session.expires_at,
        user: view(user),
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie_value);
    Ok(response)
}

/// `POST /api/v1/auth/login`
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let cfg = state.config_snapshot().await;
    let username = req.username.trim().to_string();
    if username.is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request("用户名与密码不能为空"));
    }

    let throttle_key = format!(
        "{}|{}",
        username,
        AppState::client_ip(&headers).unwrap_or_else(|| "unknown".to_string())
    );
    if let Some(remain) = state.throttle.locked_for(&throttle_key) {
        // 自己拼文案：429 的意思是「试得太频繁」，不该带上「鉴权错误: 」前缀。
        return Err(ApiError::too_many_requests(format!(
            "登录已锁定，请 {remain} 秒后再试"
        )));
    }

    let Some(user) = state
        .store
        .find_user_by_name(&username)
        .await
        .map_err(ApiError::from)?
    else {
        state.throttle.record_failure(
            &throttle_key,
            cfg.auth.login_max_attempts,
            cfg.auth.login_lock_minutes,
        );
        state
            .audit(None, "login_failed", Some(username), None, &headers)
            .await;
        return Err(ApiError::unauthorized("用户名或密码错误"));
    };

    if user.disabled {
        return Err(ApiError::forbidden("用户已被禁用"));
    }

    let ok = verify_password_offloaded(req.password.clone(), user.password_hash.clone()).await?;
    if !ok {
        state.throttle.record_failure(
            &throttle_key,
            cfg.auth.login_max_attempts,
            cfg.auth.login_lock_minutes,
        );
        state
            .audit(
                None,
                "login_failed",
                Some(username),
                Some("密码不匹配".to_string()),
                &headers,
            )
            .await;
        return Err(ApiError::unauthorized("用户名或密码错误"));
    }

    state.throttle.record_success(&throttle_key);

    state
        .store
        .touch_login(&user.id)
        .await
        .map_err(ApiError::from)?;
    state
        .audit(
            Some(&user.id),
            "login",
            Some(user.username.clone()),
            None,
            &headers,
        )
        .await;

    issue_login_response(&state, &cfg, &user, &headers).await
}

/// `POST /api/v1/auth/register` —— 自助注册。
///
/// 受 `admin.allow_registration` 控制（默认关闭）。新账号一律是 `viewer`：
/// 自助注册不应该能拿到管理权限，否则「开放注册」就等于「开放控制台」。
/// 需要管理员账号时，由现有管理员在「配置 → 用户管理」里创建。
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Response, ApiError> {
    let cfg = state.config_snapshot().await;
    if !cfg.admin.allow_registration {
        return Err(ApiError::forbidden(
            "自助注册已关闭（admin.allow_registration = false）；请让管理员在「配置 → 用户管理」里创建账号",
        ));
    }

    let username = normalize_name(&req.username).map_err(|_| {
        ApiError::bad_request("用户名只能包含字母、数字、'-'、'_'、'.'，且不超过 64 个字符")
    })?;
    validate_password(&req.password)?;

    if state
        .store
        .find_user_by_name(&username)
        .await
        .map_err(ApiError::from)?
        .is_some()
    {
        return Err(ApiError::conflict("用户名已被占用"));
    }

    let hash = hash_password_offloaded(req.password.clone()).await?;
    let user = state
        .store
        .create_user(username, hash, ROLE_VIEWER.to_string())
        .await
        .map_err(map_store_conflict)?;

    state
        .audit(
            Some(&user.id),
            "register",
            Some(user.username.clone()),
            Some("自助注册（viewer）".to_string()),
            &headers,
        )
        .await;
    tracing::info!(user = %user.username, "新用户自助注册成功（角色 viewer）");

    issue_login_response(&state, &cfg, &user, &headers).await
}

/// `POST /api/v1/auth/logout`
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = AppState::session_token(&headers) {
        let hash = token_hash(&token);
        if let Err(err) = state.store.delete_session(&hash).await {
            tracing::warn!(error = %err, "删除会话失败");
        }
    }
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("rscross_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    Ok(response)
}

/// `GET /api/v1/auth/me`
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserView>, ApiError> {
    let user = state.require_user(&headers).await?;
    Ok(Json(view(&user)))
}

/// `POST /api/v1/auth/password`
pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state.require_user(&headers).await?;

    validate_password(&req.new_password)?;
    if req.new_password == req.current_password {
        return Err(ApiError::bad_request("新密码不能与当前密码相同"));
    }

    let ok =
        verify_password_offloaded(req.current_password.clone(), user.password_hash.clone()).await?;
    if !ok {
        state
            .audit(
                Some(&user.id),
                "change_password_failed",
                Some(user.username.clone()),
                Some("当前密码不匹配".to_string()),
                &headers,
            )
            .await;
        return Err(ApiError::unauthorized("当前密码不正确"));
    }

    let hash = hash_password_offloaded(req.new_password.clone()).await?;
    state
        .store
        .set_password(&user.id, hash)
        .await
        .map_err(ApiError::from)?;
    state
        .audit(
            Some(&user.id),
            "change_password",
            Some(user.username.clone()),
            None,
            &headers,
        )
        .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}
