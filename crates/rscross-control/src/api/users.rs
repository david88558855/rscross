//! 用户管理 API（仅管理员）。
//!
//! 为什么除了「自助注册」还要有这套接口：控制台默认关闭自助注册
//! （`admin.allow_registration = false`），而一个只有初始管理员、无法新增账号的
//! 系统等于没有多用户能力。管理员在配置页直接建号，是最常用、也最可控的路径。
//!
//! 两条硬约束：
//! - 新账号默认 `viewer`（最小权限），要提权必须显式传 `role = "admin"`；
//! - 不能让系统失去最后一个可用管理员 —— 否则控制台将永久无法管理。

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::auth::{hash_password_offloaded, view, UserView};
use crate::api::{
    map_store_conflict, normalize_name, normalize_role, validate_password, ROLE_ADMIN,
};
use crate::error::ApiError;
use crate::state::AppState;

/// 新建用户请求。
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    /// 登录名。
    pub username: String,
    /// 初始密码。
    pub password: String,
    /// 角色：`admin` / `viewer`，缺省 `viewer`。
    pub role: Option<String>,
}

/// 修改用户请求（字段缺省表示不改）。
#[derive(Debug, Deserialize)]
pub struct PatchUserRequest {
    /// 禁用 / 启用。
    pub disabled: Option<bool>,
    /// 角色。
    pub role: Option<String>,
    /// 重置密码（不需要原密码 —— 这是管理员操作）。
    pub password: Option<String>,
}

/// 删除结果。
#[derive(Debug, Serialize)]
pub struct OkResponse {
    /// 固定为 `true`。
    pub ok: bool,
}

/// `GET /api/v1/users`
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserView>>, ApiError> {
    state.require_admin(&headers).await?;
    let users = state.store.list_users().await.map_err(ApiError::from)?;
    Ok(Json(users.iter().map(view).collect()))
}

/// `POST /api/v1/users`
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserView>, ApiError> {
    let actor = state.require_admin(&headers).await?;

    let username = normalize_name(&req.username).map_err(|_| {
        ApiError::bad_request("用户名只能包含字母、数字、'-'、'_'、'.'，且不超过 64 个字符")
    })?;
    validate_password(&req.password)?;
    let role = normalize_role(req.role.as_deref())?;

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
        .create_user(username, hash, role.clone())
        .await
        .map_err(map_store_conflict)?;

    state
        .audit(
            Some(&actor.id),
            "create_user",
            Some(user.username.clone()),
            Some(format!("role={role}")),
            &headers,
        )
        .await;
    tracing::info!(by = %actor.username, user = %user.username, role = %role, "管理员已创建用户");

    Ok(Json(view(&user)))
}

/// `PATCH /api/v1/users/{id}`
pub async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchUserRequest>,
) -> Result<Json<UserView>, ApiError> {
    let actor = state.require_admin(&headers).await?;

    let target = state
        .store
        .find_user_by_id(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;

    // 先把角色归一化并校验：非法角色要在「最后一个管理员」那套判断之前就 400，
    // 否则用户只是把角色名拼错，却会收到一句「至少要保留一个启用状态的管理员」。
    let new_role = match req.role.as_deref() {
        Some(_) => Some(normalize_role(req.role.as_deref())?),
        None => None,
    };

    // 会让目标失去管理员身份的操作（降级 / 禁用）需要先确认系统里
    // 还留有别的可用管理员，否则控制台会变成没人能管的孤岛。
    // 比较用归一化后的角色名，避免 "Admin" 这种大小写变体被当成「降级」。
    let demoting = new_role
        .as_deref()
        .map(|r| r != ROLE_ADMIN)
        .unwrap_or(false);
    if target.role == ROLE_ADMIN && !target.disabled && (demoting || req.disabled == Some(true)) {
        ensure_other_admin(&state, &target.id).await?;
    }

    if let Some(role) = new_role {
        state
            .store
            .set_user_role(&target.id, &role)
            .await
            .map_err(ApiError::from)?;
        state
            .audit(
                Some(&actor.id),
                "set_user_role",
                Some(target.username.clone()),
                Some(format!("role={role}")),
                &headers,
            )
            .await;
    }

    if let Some(disabled) = req.disabled {
        state
            .store
            .set_user_disabled(&target.id, disabled)
            .await
            .map_err(ApiError::from)?;
        if disabled {
            // 禁用后旧登录态必须立即失效，否则「禁用」只是阻止了下次登录。
            let purged = state
                .store
                .purge_user_sessions(&target.id)
                .await
                .map_err(ApiError::from)?;
            tracing::warn!(user = %target.username, sessions = purged, "用户已被禁用，其会话已清理");
        }
        state
            .audit(
                Some(&actor.id),
                if disabled {
                    "disable_user"
                } else {
                    "enable_user"
                },
                Some(target.username.clone()),
                None,
                &headers,
            )
            .await;
    }

    if let Some(password) = req.password.as_deref() {
        validate_password(password)?;
        let hash = hash_password_offloaded(password.to_string()).await?;
        state
            .store
            .set_password(&target.id, hash)
            .await
            .map_err(ApiError::from)?;
        let purged = state
            .store
            .purge_user_sessions(&target.id)
            .await
            .map_err(ApiError::from)?;
        state
            .audit(
                Some(&actor.id),
                "reset_user_password",
                Some(target.username.clone()),
                Some(format!("已清理 {purged} 个会话")),
                &headers,
            )
            .await;
        tracing::warn!(user = %target.username, "管理员已重置该用户密码");
    }

    let updated = state
        .store
        .find_user_by_id(&target.id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;
    Ok(Json(view(&updated)))
}

/// `DELETE /api/v1/users/{id}`
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<OkResponse>, ApiError> {
    let actor = state.require_admin(&headers).await?;

    let target = state
        .store
        .find_user_by_id(&id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;

    if target.id == actor.id {
        return Err(ApiError::bad_request("不能删除当前登录的账号"));
    }
    if target.role == ROLE_ADMIN && !target.disabled {
        ensure_other_admin(&state, &target.id).await?;
    }

    state
        .store
        .delete_user(&target.id)
        .await
        .map_err(ApiError::from)?;
    state
        .audit(
            Some(&actor.id),
            "delete_user",
            Some(target.username.clone()),
            None,
            &headers,
        )
        .await;

    Ok(Json(OkResponse { ok: true }))
}

/// 确认除 `keep_id` 外还有启用状态的管理员。
async fn ensure_other_admin(state: &AppState, keep_id: &str) -> Result<(), ApiError> {
    let all = state.store.list_users().await.map_err(ApiError::from)?;
    let others = all
        .iter()
        .filter(|u| u.id != keep_id && u.role == ROLE_ADMIN && !u.disabled)
        .count();
    if others == 0 {
        return Err(ApiError::bad_request(
            "至少要保留一个启用状态的管理员，否则控制台将无法管理",
        ));
    }
    Ok(())
}
