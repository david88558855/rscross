//! API 错误类型：统一映射为 `{ "code": ..., "message": ... }`。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rscross_common::Error;
use serde::Serialize;

/// 控制台 / Agent API 的错误。
#[derive(Debug)]
pub struct ApiError {
    /// HTTP 状态码。
    pub status: StatusCode,
    /// 稳定的机器可读错误码。
    pub code: &'static str,
    /// 面向人的说明。
    pub message: String,
}

impl ApiError {
    /// 任意状态码。
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// 400。
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// 401。
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    /// 403。
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// 404。
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// 409。
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// 429。
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "too_many_requests", message)
    }

    /// 500。
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            message,
        )
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        let status = match &err {
            Error::Auth(_) => StatusCode::UNAUTHORIZED,
            Error::Config(_) | Error::Api(_) | Error::Json(_) => StatusCode::BAD_REQUEST,
            Error::Transport(_) => StatusCode::BAD_GATEWAY,
            Error::Io(_) | Error::Store(_) | Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            code: err.code(),
            message: err.to_string(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.status.as_u16())
    }
}

impl std::error::Error for ApiError {}
