//! vhost 域名分发：把 HTTP/HTTPS 请求按域名路由到对应代理

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::proxy::ProxyRegistry;

/// vhost 路由器
pub struct VhostRouter {
    registry: Arc<ProxyRegistry>,
    /// 子域名主机名，如 `example.com`
    sub_domain_host: String,
}

impl VhostRouter {
    pub fn new(registry: Arc<ProxyRegistry>, sub_domain_host: &str) -> Self {
        Self {
            registry,
            sub_domain_host: sub_domain_host.to_string(),
        }
    }

    /// 启动 HTTP 监听
    pub async fn serve_http(self: Arc<Self>, port: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{port}");
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("vhost 监听 {addr} 失败: {e}"))?;
        tracing::info!("vhost HTTP 监听于 {addr}");

        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let s = self.clone();
            tokio::spawn(async move {
                s.handle_http(stream, peer).await;
            });
        }
    }

    /// 处理单个 HTTP 连接
    async fn handle_http(&self, mut stream: TcpStream, _peer: std::net::SocketAddr) {
        let mut buf = vec![0u8; 16 * 1024];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };

        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let Some(host) = crate::proxy::parse_host(&req) else {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };

        let lookup = crate::proxy::normalize_domain(&host, &self.sub_domain_host);
        if self.registry.resolve_by_domain(&lookup).is_none() {
            tracing::debug!(host = %host, "vhost 未匹配");
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        }

        // 交由上层代理接管（保持连接）
        tracing::debug!(host = %host, "vhost 匹配成功，转发");
        let _ = stream.write_all(&buf[..n]).await;
        let _ = stream.flush().await;
    }
}

/// 解析 HTTP 路径
pub fn parse_path(req: &str) -> Option<String> {
    req.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|s| s.to_string())
}

/// 解析 HTTP 方法
pub fn parse_method(req: &str) -> Option<String> {
    req.lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path_and_method() {
        let req = "GET /api/v1?x=1 HTTP/1.1\r\nHost: a.com\r\n\r\n";
        assert_eq!(parse_method(req), Some("GET".to_string()));
        assert_eq!(parse_path(req), Some("/api/v1?x=1".to_string()));
    }
}
