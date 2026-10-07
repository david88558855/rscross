//! 统一错误类型

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// 业务错误码，与前端约定保持一致
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 通用失败
    Failed = 0,
    /// 参数校验失败
    InvalidParams = 1,
    /// 未登录 / token 失效
    Unauthorized = 2,
    /// 无权限
    Forbidden = 3,
    /// 资源不存在
    NotFound = 4,
    /// 数据冲突
    Conflict = 5,
    /// 服务端异常
    Internal = 6,
}

impl ErrorCode {
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }

    pub fn message(&self) -> &'static str {
        match self {
            ErrorCode::Failed => "操作失败",
            ErrorCode::InvalidParams => "参数错误",
            ErrorCode::Unauthorized => "登录已失效，请重新登录",
            ErrorCode::Forbidden => "没有操作权限",
            ErrorCode::NotFound => "数据不存在",
            ErrorCode::Conflict => "数据冲突",
            ErrorCode::Internal => "服务异常",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Msg(String),

    #[error("{0}")]
    Invalid(String),

    #[error("未登录或登录已失效")]
    Unauthorized,

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error("配置错误: {0}")]
    Config(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    pub fn msg<S: Into<String>>(s: S) -> Self {
        AppError::Msg(s.into())
    }

    pub fn invalid<S: Into<String>>(s: S) -> Self {
        AppError::Invalid(s.into())
    }

    pub fn not_found<S: Into<String>>(s: S) -> Self {
        AppError::NotFound(s.into())
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            AppError::Invalid(_) | AppError::Config(_) => ErrorCode::InvalidParams,
            AppError::Unauthorized => ErrorCode::Unauthorized,
            AppError::Forbidden(_) => ErrorCode::Forbidden,
            AppError::NotFound(_) => ErrorCode::NotFound,
            AppError::Conflict(_) => ErrorCode::Conflict,
            AppError::Database(_) | AppError::Io(_) | AppError::Serde(_) | AppError::Other(_) => {
                ErrorCode::Internal
            }
            AppError::Msg(_) => ErrorCode::Failed,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.code();
        let msg = self.to_string();
        // 服务端异常记录完整错误链
        if matches!(code, ErrorCode::Internal) {
            tracing::error!(error = %self, "服务端异常");
        }
        let body = json!({
            "code": code.as_i32(),
            "msg": if msg.is_empty() { code.message() } else { &msg },
        });
        (StatusCode::OK, axum::Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
