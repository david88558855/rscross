//! 服务端共享状态。

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{header, HeaderMap};
use rscross_auth::{extract_bearer, verify_session, LoginThrottle};
use rscross_common::{Error, Result};
use rscross_config::ServerFile;
use rscross_store::{Store, UserRecord};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::error::ApiError;
use crate::logbus::LogBus;

/// 会话 Cookie 名（控制台用）。
pub const SESSION_COOKIE: &str = "rscross_session";

/// 服务端全局状态。所有字段均可跨任务共享。
#[derive(Clone)]
pub struct AppState {
    /// 持久化句柄。
    pub store: Store,
    /// 运行期配置（可由控制台热修改）。
    pub config: Arc<RwLock<ServerFile>>,
    /// 配置文件路径。
    pub config_path: Arc<PathBuf>,
    /// 进程启动时间。
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// 登录限流。
    pub throttle: Arc<LoginThrottle>,
    /// 日志总线。
    pub logs: LogBus,
    /// Iroh 节点（`p2p.enabled = false` 时为 `None`）。
    pub p2p: Option<rscross_transport::P2pNode>,
    /// 路径选择器（服务端侧用于决定「直连投递还是走中继」）。
    pub path_selector: Arc<rscross_transport::PathSelector>,
    /// 全局关停信号。
    pub shutdown: CancellationToken,
}

impl AppState {
    /// 取一份配置快照。
    pub async fn config_snapshot(&self) -> ServerFile {
        self.config.read().await.clone()
    }

    /// 校验 + 落盘 + 生效。三者顺序固定：先校验，再落盘，最后换内存。
    pub async fn replace_config(&self, next: ServerFile) -> Result<()> {
        next.validate()?;
        next.save(self.config_path.as_ref())?;
        let mut guard = self.config.write().await;
        *guard = next;
        Ok(())
    }

    /// 从请求头里取会话 token：`Authorization: Bearer` / `X-Rscross-Token` / Cookie。
    pub fn session_token(headers: &HeaderMap) -> Option<String> {
        if let Some(token) = extract_bearer(headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())) {
            return Some(token);
        }
        if let Some(token) = headers
            .get("x-rscross-token")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(token.to_string());
        }
        cookie_token(headers)
    }

    /// 要求已登录，返回当前用户。
    pub async fn require_user(&self, headers: &HeaderMap) -> std::result::Result<UserRecord, ApiError> {
        let token = Self::session_token(headers)
            .ok_or_else(|| ApiError::unauthorized("缺少会话凭证"))?;
        let session = verify_session(&self.store, &token)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::unauthorized("会话无效或已过期"))?;
        let user = self
            .store
            .find_user_by_id(&session.user_id)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::unauthorized("用户不存在"))?;
        if user.disabled {
            return Err(ApiError::forbidden("用户已被禁用"));
        }
        Ok(user)
    }

    /// 要求管理员角色。
    pub async fn require_admin(&self, headers: &HeaderMap) -> std::result::Result<UserRecord, ApiError> {
        let user = self.require_user(headers).await?;
        if user.role != "admin" {
            return Err(ApiError::forbidden("需要管理员权限"));
        }
        Ok(user)
    }

    /// 请求来源 IP（优先 `X-Forwarded-For`，用于审计）。
    pub fn client_ip(headers: &HeaderMap) -> Option<String> {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.trim().to_string())
            })
    }

    /// 写一条审计记录（失败只记日志，不影响主流程）。
    pub async fn audit(
        &self,
        user_id: Option<&str>,
        action: &str,
        target: Option<String>,
        detail: Option<String>,
        headers: &HeaderMap,
    ) {
        let entry = rscross_store::AuditEntry {
            id: 0,
            ts: rscross_common::time::now_rfc3339(),
            user_id: user_id.map(str::to_string),
            action: action.to_string(),
            target,
            detail,
            ip: Self::client_ip(headers),
        };
        if let Err(err) = self.store.insert_audit(entry).await {
            tracing::warn!(error = %err, "写审计记录失败");
        }
    }

    /// 便捷：把外部错误转成「存储不可用」的 500。
    pub fn store_error(err: impl std::fmt::Display) -> ApiError {
        ApiError::from(Error::store(err))
    }
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(SESSION_COOKIE) {
            let value = value.trim_start_matches('=').trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn cookie_token_is_parsed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; rscross_session=abc123; b=2"),
        );
        assert_eq!(
            AppState::session_token(&headers).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn bearer_wins_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer tok1"));
        headers.insert(header::COOKIE, HeaderValue::from_static("rscross_session=tok2"));
        assert_eq!(AppState::session_token(&headers).as_deref(), Some("tok1"));
    }

    #[test]
    fn no_token_returns_none() {
        let headers = HeaderMap::new();
        assert!(AppState::session_token(&headers).is_none());
    }
}
