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
pub async fn fallback(uri: axum::http::Uri, headers: axum::http::HeaderMap) -> Response {
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
    // 根路径同时服务两种用途，用 Accept 区分：
    //
    // - 客户端（不发 Accept: text/html）→ 307 到控制面 WebSocket 端点。
    //   这样 `http://host:7700` 能作为 `--console` 的发现入口。
    // - 浏览器（Accept 里含 text/html）→ 照常返回控制台页面。
    //
    // 分不清两者的话只能二选一：全给 307 会让浏览器用户一脸懵地跳到
    // WS 端点然后连接失败；全给页面则 http:// 入口没法用。
    // 只有**明确声明不要 HTML** 的请求才走 307。
    //
    // 判据刻意严格：`Accept: */*` 也算「要 HTML」。命令行工具、浏览器书签、
    // 健康检查全都发 `*/*` —— 把它们送去 WebSocket 端点会得到一个
    // 莫名其妙的 400（那里不是 HTTP 服务）。Windows 冒烟测试就是这么炸的：
    // 首页断言拿到 Bad Request。
    //
    // 反过来，客户端探测不发 Accept 时会落到 HTML 分支，拿不到 307 ——
    // 所以 discover.rs 那边显式带了 Accept: application/json。
    let wants_html = match headers.get(axum::http::header::ACCEPT).and_then(|v| v.to_str().ok()) {
        None => true,
        Some(accept) => accept.contains("text/html") || !accept.trim().is_empty(),
    };
    if path == "/" && !wants_html {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [(axum::http::header::LOCATION, rscross_common::console::CONTROL_WS_PATH)],
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

    /// 构造请求头。
    fn headers_with_accept(accept: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_str(accept).expect("accept"),
        );
        h
    }

    /// 浏览器式请求（Accept 含 text/html）。
    fn browser_headers() -> axum::http::HeaderMap {
        headers_with_accept("text/html,application/xhtml+xml")
    }

    /// 客户端式请求（显式声明不要 HTML —— 与 discover.rs 的探测请求一致）。
    fn client_headers() -> axum::http::HeaderMap {
        headers_with_accept("application/json")
    }

    #[tokio::test]
    async fn root_serves_spa_index_html() {
        let resp = fallback(
            axum::http::Uri::from_static("/"),
            browser_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = content_type_of(&resp).await;
        assert!(
            ct.contains("text/html"),
            "首页 Content-Type 应为 text/html，实际 {ct}"
        );
        assert!(
            text_of(resp).await.contains(r#"id="app""#),
            "首页缺少挂载点"
        );
    }

    #[tokio::test]
    async fn root_redirects_non_browsers_to_the_control_socket() {
        // 这是 `--console http://host:7700` 能用的前提：客户端请求根路径
        // 必须拿到 307 才能换到 WebSocket 地址。
        let resp = fallback(axum::http::Uri::from_static("/"), client_headers()).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(location, rscross_common::console::CONTROL_WS_PATH);
    }

    #[tokio::test]
    async fn accept_wildcard_still_serves_the_page() {
        // 命令行工具、浏览器书签、健康检查全都发 `Accept: */*`。
        // 把它们送去 WebSocket 端点会拿到一个「Bad Request」—— 那里不是
        // HTTP 服务。Windows 冒烟测试的首页断言就是这么炸的。
        let resp = fallback(
            axum::http::Uri::from_static("/"),
            headers_with_accept("*/*"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_accept_header_still_serves_the_page() {
        // 没发 Accept 的请求按「什么都想要」处理，返回页面而不是把它弹去
        // WebSocket 端点 —— 后者会让 curl / 浏览器书签这类访问一脸懵。
        let resp = fallback(axum::http::Uri::from_static("/"), axum::http::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn static_assets_are_served_with_correct_content_type() {
        for (path, needle) in [("/app.js", "javascript"), ("/app.css", "css")] {
            // 用 `str::parse` 而不是 `Uri::from_str`：后者需要把 `std::str::FromStr`
            // 引入作用域，`http` crate 只给 HeaderValue/Method 提供了同名固有方法。
            let resp = fallback(path.parse().unwrap(), client_headers()).await;
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
        let resp = fallback(axum::http::Uri::from_static("/not-here.js"), client_headers()).await;
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
        let resp = fallback(axum::http::Uri::from_static("/api/v1/nope"), client_headers()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = text_of(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).expect("应为 JSON");
        assert_eq!(value["code"], "not_found");
    }

    #[tokio::test]
    async fn spa_deep_link_falls_back_to_index() {
        let resp = fallback(axum::http::Uri::from_static("/tunnels"), client_headers()).await;
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
