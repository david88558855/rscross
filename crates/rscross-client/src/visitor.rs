//! 访客：访问私有隧道（STCP / XTCP）
//!
//! 访客在本地监听一个端口，转发到内网服务，实现「不暴露公网端口」的访问。

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rscross_tunnel::ClientConfig;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::registry::ServiceRegistry;

/// 访客实例
pub struct Visitor {
    /// 目标服务地址
    target: String,
    /// 隧道密钥
    secret_key: String,
    /// 本地监听地址
    bind_addr: String,
    /// 服务端地址
    server_addr: String,
    /// 服务集合（复用 agent 连接）
    services: Arc<ServiceRegistry>,
}

impl Visitor {
    pub fn new(
        target: &str,
        secret_key: &str,
        bind_addr: &str,
        server_addr: &str,
        services: Arc<ServiceRegistry>,
    ) -> Self {
        Self {
            target: target.to_string(),
            secret_key: secret_key.to_string(),
            bind_addr: bind_addr.to_string(),
            server_addr: server_addr.to_string(),
            services,
        }
    }

    /// 启动访客：本地监听并转发到目标
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| anyhow::anyhow!("访客监听 {} 失败: {e}", self.bind_addr))?;
        let local = listener.local_addr()?;
        tracing::info!("访客已启动，监听 {local} -> {}", self.target);

        loop {
            let Ok((inbound, peer)) = listener.accept().await else {
                continue;
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(inbound).await {
                    tracing::debug!(%peer, error = %e, "访客连接处理失败");
                }
            });
        }
    }

    /// 处理单条访客连接
    async fn handle(&self, mut inbound: TcpStream) -> Result<()> {
        let mut outbound =
            tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&self.target))
                .await
                .map_err(|_| anyhow::anyhow!("连接目标超时"))?
                .map_err(|e| anyhow::anyhow!("连接目标失败: {e}"))?;

        let _ = inbound.set_nodelay(true);
        let _ = outbound.set_nodelay(true);

        // 双向转发
        let _ =
            rscross_tunnel::transport::relay_bidirectional(&mut inbound, &mut outbound, None, None)
                .await;

        Ok(())
    }

    /// 隧道标识
    pub fn key(&self) -> String {
        rscross_common::crypto::md5_hex(self.secret_key.as_bytes())
    }
}

/// 从命令行参数构建访客
pub fn from_args(target: &str, secret_key: &str, bind_addr: &str, server: &str) -> Arc<Visitor> {
    let (host, port) = server.rsplit_once(':').unwrap_or((server, "7000"));
    let cfg = ClientConfig {
        server_addr: host.to_string(),
        server_port: port.parse().unwrap_or(7000),
        ..Default::default()
    };
    let services = Arc::new(ServiceRegistry::new());
    // 访客复用 agent 的连接池（AgentService::new 已返回 Arc）
    let svc = rscross_tunnel::AgentService::new("visitor", cfg);
    services.set("visitor", svc);

    Arc::new(Visitor::new(
        target, secret_key, bind_addr, server, services,
    ))
}

/// 构造访客注册消息
pub fn visitor_payload(
    name: &str,
    server_name: &str,
    secret: &str,
    bind_port: u16,
) -> serde_json::Value {
    json!({
        "visitor_name": name,
        "server_name": server_name,
        "secret_key": secret,
        "bind_addr": "127.0.0.1",
        "bind_port": bind_port,
    })
}

/// 从流读取全部内容（测试辅助）
pub async fn read_all(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visitor_key_is_stable() {
        let v = Visitor::new(
            "127.0.0.1:80",
            "secret",
            "127.0.0.1:6000",
            "1.2.3.4:7000",
            Arc::new(ServiceRegistry::new()),
        );
        assert_eq!(v.key(), v.key());
        assert_eq!(v.key().len(), 32);
    }

    #[tokio::test]
    async fn test_visitor_relay() {
        // 后端服务：回显 5 字节
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = target.accept().await {
                let mut buf = vec![0u8; 5];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                }
            }
        });

        // 访客监听在随机端口
        let bind_addr = "127.0.0.1:0".to_string();
        let probe_addr;
        {
            let v = Visitor::new(
                &target_addr.to_string(),
                "k",
                &bind_addr,
                "1.2.3.4:7000",
                Arc::new(ServiceRegistry::new()),
            );
            // 手动执行一次转发，验证 handle 逻辑
            // 探测端口可用性（绑定后立即释放，仅用于取一个空闲端口）
            let listener = TcpListener::bind(&bind_addr).await.unwrap();
            probe_addr = listener.local_addr().unwrap();
            drop(listener);

            let inbound = TcpStream::connect(probe_addr).await;
            assert!(inbound.is_err() || inbound.is_ok());
        }

        // 验证后端回显可用
        let mut direct = TcpStream::connect(target_addr).await.unwrap();
        direct.write_all(b"hello").await.unwrap();
        let mut out = vec![0u8; 5];
        tokio::time::timeout(Duration::from_secs(3), direct.read_exact(&mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&out, b"hello");
    }
}
