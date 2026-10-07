//! 静态资源辅助：路径规范化与 MIME 推断
//!
//! 实际的资源打包由 `rscross-server` 通过 `include_dir` 完成，
//! 这里只保留与运行时无关的纯函数，便于测试与复用。

/// 路径规范化：防目录穿越
///
/// 空路径归一到 `index.html`，含 `..` 的路径一律回落到 `index.html`。
pub fn normalize(path: &str) -> String {
    let p = path.trim_start_matches('/');
    let p = if p.is_empty() { "index.html" } else { p };

    // 阻止 ..
    if p.split('/').any(|seg| seg == "..") {
        return "index.html".to_string();
    }
    p.to_string()
}

/// 依据扩展名推断 Content-Type
pub fn mime_of(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        "map" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// SPA 回退：非资源路径应返回 index.html
///
/// 静态资源（带扩展名）不存在时返回 `false`，交由调用方返回 404。
pub fn is_spa_route(path: &str) -> bool {
    let p = normalize(path);
    !p.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("/"), "index.html");
        assert_eq!(normalize(""), "index.html");
        assert_eq!(normalize("/assets/app.js"), "assets/app.js");
        // 目录穿越被拦截
        assert_eq!(normalize("/../../etc/passwd"), "index.html");
        assert_eq!(normalize("/a/../../b"), "index.html");
    }

    #[test]
    fn test_mime_of() {
        assert_eq!(mime_of("a.html"), "text/html; charset=utf-8");
        assert_eq!(mime_of("a.js"), "application/javascript; charset=utf-8");
        assert_eq!(mime_of("a.css"), "text/css; charset=utf-8");
        assert_eq!(mime_of("a.png"), "image/png");
        assert_eq!(mime_of("a.unknown"), "application/octet-stream");
    }

    #[test]
    fn test_is_spa_route() {
        // SPA 路由无扩展名
        assert!(is_spa_route("/login"));
        assert!(is_spa_route("/admin/client"));
        // 静态资源有扩展名
        assert!(!is_spa_route("/assets/app.js"));
        assert!(!is_spa_route("/favicon.ico"));
    }
}
