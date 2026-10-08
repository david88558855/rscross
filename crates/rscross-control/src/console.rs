//! 内嵌 Web 控制台静态资源。
//!
//! 前端源码在仓库根的 `web/` 目录，构建时由 `rust-embed` 打进二进制，
//! 因此**服务端产物仍是单一文件**（需求 3）。
//!
//! 排障提示：前端「页面在浏览器里打不开」只有三种可能 ——
//! 1. 资源没被内嵌 → [`missing_assets`] 会直接点名，`--check` 也能自证；
//! 2. 监听地址 / 防火墙 / 云安全组不对 → 见 `ControlPlane::serve` 打印的可达地址；
//! 3. 前端自身渲染出错 → `/` 返回 200 但页面空白，需看浏览器控制台。
//! 第 1、2 种都能在服务器上一条命令排除，不必盲猜。

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rust_embed::RustEmbed;

/// 编译期内嵌的前端资源。
///
/// `folder` 相对 **crate 根**（`crates/rscross-control`）解析，`../../web` 即仓库根的 `web/`。
#[derive(RustEmbed)]
#[folder = "../../web"]
struct WebAssets;

/// 控制台页面正常展示所必需的资源。
///
/// 少任何一个都会让浏览器里「界面显示不出来」，因此启动时显式自检。
pub const REQUIRED_ASSETS: [&str; 3] = ["index.html", "app.js", "app.css"];

/// 资源清单（供 `/api/v1/health` 展示构建信息）。
pub fn asset_count() -> usize {
    WebAssets::iter().count()
}

/// 已内嵌资源的名字，按字典序排序。
pub fn asset_list() -> Vec<String> {
    let mut names: Vec<String> = WebAssets::iter().map(|name| name.to_string()).collect();
    names.sort();
    names
}

/// 缺失的必需资源；返回空表示控制台页面可用。
pub fn missing_assets() -> Vec<&'static str> {
    REQUIRED_ASSETS
        .iter()
        .copied()
        .filter(|name| WebAssets::get(name).is_none_or(|file| file.data.is_empty()))
        .collect()
}

/// 一行式自检结论，用于启动日志与 `--check`。
pub fn diagnose() -> String {
    let total = asset_count();
    let missing = missing_assets();
    if missing.is_empty() {
        format!("前端资源已内嵌（{total} 个文件），控制台页面可用")
    } else {
        format!(
            "前端资源缺失 {missing:?}（已内嵌 {total} 个文件）：浏览器打开只会看到 404 或空白，\
             请确认构建时仓库根的 web/ 目录存在且已被提交"
        )
    }
}

/// 首页。
pub async fn index() -> Response {
    serve("index.html")
}

/// 未匹配路由：API 前缀返回 JSON 404，其余回落到 SPA 首页。
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
    // 静态资源找不到时**刻意不回落到 index.html**：把 HTML 当 JS/CSS 交给浏览器，
    // 只会换来不知所云的 MIME 报错，反而把「资源缺失」误诊成「前端 bug」。
    if is_asset_like(path) {
        return serve(path);
    }
    serve("index.html")
}

/// 判断请求是否指向静态文件（末段带扩展名），而不是前端路由。
fn is_asset_like(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    matches!(
        last.rsplit_once('.'),
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty()
    )
}

/// 把请求路径规范化为内嵌资源的键。
///
/// 返回 `None` 表示路径非法。`rust-embed` 本身按精确路径查表已足够安全，
/// 这里再挡一道，避免将来换成磁盘读取时出现目录穿越。
fn normalize(path: &str) -> Option<String> {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if path
        .split('/')
        .any(|seg| seg == ".." || seg == "." || seg.contains('\\'))
    {
        return None;
    }
    Some(path.to_string())
}

fn serve(path: &str) -> Response {
    let Some(candidate) = normalize(path) else {
        return missing();
    };

    match WebAssets::get(&candidate) {
        Some(file) => {
            let mime = mime_guess::from_path(&candidate).first_or_octet_stream();
            let content_type = HeaderValue::from_str(mime.as_ref())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            (
                [
                    (header::CONTENT_TYPE, content_type),
                    // 内嵌资源随二进制变化，禁止缓存，避免升级后仍命中旧前端。
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("no-cache, must-revalidate"),
                    ),
                ],
                file.data.into_owned(),
            )
                .into_response()
        }
        None => missing(),
    }
}

fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        format!(
            "控制台资源缺失：{}\n若所有静态文件都 404，说明二进制构建时没有 web/ 目录",
            diagnose()
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn text_of(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("读取响应体");
        String::from_utf8_lossy(&bytes).to_string()
    }

    async fn content_type_of(resp: &Response) -> String {
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn required_assets_are_embedded_and_non_empty() {
        assert!(
            missing_assets().is_empty(),
            "缺少内嵌前端资源: {:?}（已内嵌: {:?}）",
            missing_assets(),
            asset_list()
        );
        for name in REQUIRED_ASSETS {
            let file = WebAssets::get(name).unwrap_or_else(|| panic!("{name} 缺失"));
            assert!(!file.data.is_empty(), "{name} 是空文件");
        }
    }

    #[test]
    fn index_html_mounts_spa_and_references_existing_assets() {
        let html = String::from_utf8(
            WebAssets::get("index.html")
                .expect("index.html")
                .data
                .into_owned(),
        )
        .expect("index.html 必须是 UTF-8");

        assert!(html.contains(r#"id="app""#), "index.html 缺少挂载点 #app");
        assert!(html.contains("/app.js"), "index.html 未引用 /app.js");
        assert!(html.contains("/app.css"), "index.html 未引用 /app.css");

        // 被引用的资源必须真的在包里，否则浏览器必然白屏。
        assert!(WebAssets::get("app.js").is_some(), "app.js 未内嵌");
        assert!(WebAssets::get("app.css").is_some(), "app.css 未内嵌");
    }

    #[test]
    fn app_js_calls_console_api() {
        let js = String::from_utf8(WebAssets::get("app.js").expect("app.js").data.into_owned())
            .expect("app.js 必须是 UTF-8");
        assert!(js.contains("/api/v1/"), "app.js 未调用控制台 API");
        assert!(js.contains("/api/v1/auth/login"), "app.js 缺少登录调用");
    }

    #[tokio::test]
    async fn root_serves_spa_index_html() {
        let resp = fallback(axum::http::Uri::from_static("/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = content_type_of(&resp).await;
        assert!(
            ct.contains("text/html"),
            "首页 Content-Type 应为 text/html，实际 {ct}"
        );
        assert!(text_of(resp).await.contains(r#"id="app""#), "首页缺少挂载点");
    }

    #[tokio::test]
    async fn static_assets_are_served_with_correct_content_type() {
        for (path, needle) in [("/app.js", "javascript"), ("/app.css", "css")] {
            // 用 `str::parse` 而不是 `Uri::from_str`：后者需要把 `std::str::FromStr`
            // 引入作用域，`http` crate 只给 HeaderValue/Method 提供了同名固有方法。
            let resp = fallback(path.parse().unwrap()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path} 应可访问");
            let ct = content_type_of(&resp).await;
            assert!(
                ct.contains(needle),
                "{path} 的 Content-Type 应含 {needle}，实际 {ct}"
            );
        }
    }

    #[tokio::test]
    async fn missing_static_asset_is_404_not_masked_as_html() {
        let resp = fallback(axum::http::Uri::from_static("/not-here.js")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let ct = content_type_of(&resp).await;
        assert!(
            ct.starts_with("text/plain"),
            "应为纯文本错误说明，实际 {ct}"
        );
        assert!(text_of(resp).await.contains("前端资源"));
    }

    #[tokio::test]
    async fn unknown_api_path_returns_json_404() {
        let resp = fallback(axum::http::Uri::from_static("/api/v1/nope")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = text_of(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).expect("应为 JSON");
        assert_eq!(value["code"], "not_found");
    }

    #[tokio::test]
    async fn spa_deep_link_falls_back_to_index() {
        let resp = fallback(axum::http::Uri::from_static("/tunnels")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(text_of(resp).await.contains(r#"id="app""#));
    }

    #[test]
    fn normalize_rejects_traversal_and_strips_query() {
        assert!(normalize("/../../etc/passwd").is_none());
        assert!(normalize("/a/../b").is_none());
        assert_eq!(normalize("/app.js?v=1").as_deref(), Some("app.js"));
        assert_eq!(normalize("/").as_deref(), Some("index.html"));
        assert_eq!(normalize("").as_deref(), Some("index.html"));
    }

    #[test]
    fn diagnose_reports_availability() {
        let text = diagnose();
        assert!(text.contains("前端资源"), "{text}");
        if missing_assets().is_empty() {
            assert!(text.contains("可用"), "{text}");
        }
    }
}
