//! 内嵌 Web 控制台静态资源。
//!
//! 前端源码在仓库根的 `web/` 目录，构建时由 `rust-embed` 打进二进制，
//! 因此**服务端产物仍是单一文件**（需求 3）。

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{extract::Path, Json};
use rust_embed::RustEmbed;

/// 编译期内嵌的前端资源。
#[derive(RustEmbed)]
#[folder = "../../web"]
struct WebAssets;

/// 资源清单（供 `/api/v1/health` 展示构建信息）。
pub fn asset_count() -> usize {
    WebAssets::iter().count()
}

/// 首页。
pub async fn index() -> Response {
    serve("index.html")
}

/// 具体静态文件；找不到就回落到 SPA 首页（支持 hash 路由刷新）。
pub async fn asset(Path(path): Path<String>) -> Response {
    serve(&path)
}

/// 未匹配路由：API 前缀返回 JSON 404，其余回落到 SPA。
pub async fn fallback(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "not_found",
                "message": format!("接口不存在: {path}"),
            })),
        )
            .into_response();
    }
    serve("index.html")
}

fn serve(path: &str) -> Response {
    let candidate = path.trim_start_matches('/');
    let candidate = if candidate.is_empty() {
        "index.html"
    } else {
        candidate
    };

    match WebAssets::get(candidate) {
        Some(file) => {
            let mime = mime_guess::from_path(candidate).first_or_octet_stream();
            let content_type = HeaderValue::from_str(mime.as_ref())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            ([(header::CONTENT_TYPE, content_type)], file.data.into_owned()).into_response()
        }
        None => missing(),
    }
}

fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"))],
        "控制台资源缺失（web/ 目录未被内嵌）".to_string(),
    )
        .into_response()
}
