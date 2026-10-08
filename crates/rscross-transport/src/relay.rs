//! FerroTunnel 适配层：**反向隧道中继**。
//!
//! 角色：
//! - [`RelayServer`]：服务端内嵌的 FerroTunnel `Server`。
//!   `bind` 是控制面（客户端 UDP/TCP 出站连接到这里），`http_bind` 是公网 HTTP(S) 入口，
//!   FerroTunnel 按 `Host` 头把请求路由到对应 `tunnel_id` 的客户端。
//! - [`RelayTunnelClient`]：客户端上「一条隧道 = 一个 FerroTunnel Client」。
//!   它负责把服务端收到的流量转发到该隧道声明的 `local_addr`。
//!
//! 为什么客户端侧要「一隧道一 Client」：FerroTunnel 的 `Client` 天然是
//! 「(server, tunnel_id, local_addr)」三元组，多隧道即多个实例；
//! 每个实例内部共享一条控制连接并多路复用流，代价可接受。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ferrotunnel::common::{LimitsConfig, RateLimitConfig, TlsConfig};
use ferrotunnel::{Client, Server};
use rscross_common::{Error, Result};
use rscross_config::TunnelSection;
use tokio_util::sync::CancellationToken;

/// 由 rscross 配置推导 FerroTunnel 的 `LimitsConfig`。
pub fn build_limits(section: &TunnelSection) -> LimitsConfig {
    LimitsConfig {
        max_frame_bytes: section.max_frame_bytes,
        max_sessions: section.max_sessions,
        max_streams_per_session: section.max_streams_per_session,
        max_inflight_frames: section.max_inflight_frames,
        max_token_len: section.max_token_len,
        ..LimitsConfig::default()
    }
}

/// 由 rscross 配置推导 FerroTunnel 的 `RateLimitConfig`。
pub fn build_rate_limits(section: &TunnelSection) -> RateLimitConfig {
    RateLimitConfig {
        streams_per_sec: section.rate_streams_per_sec,
        bytes_per_sec: section.rate_bytes_per_sec,
        burst_factor: section.rate_burst_factor,
    }
}

/// 由 rscross 配置推导 FerroTunnel 的 `TlsConfig`。
pub fn build_tls(section: &TunnelSection) -> TlsConfig {
    let mut tls = TlsConfig::default();
    tls.enabled = section.tls_enabled;
    tls.cert_path = section.tls_cert_path.as_ref().map(PathBuf::from);
    tls.key_path = section.tls_key_path.as_ref().map(PathBuf::from);
    tls.ca_cert_path = section.tls_ca_path.as_ref().map(PathBuf::from);
    tls
}

/// 服务端反向隧道接入点。
pub struct RelayServer {
    server: Server,
    bind: SocketAddr,
    http_bind: SocketAddr,
}

impl std::fmt::Debug for RelayServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayServer")
            .field("bind", &self.bind)
            .field("http_bind", &self.http_bind)
            .finish()
    }
}

impl RelayServer {
    /// 按配置构建（不启动）。
    pub fn build(
        bind: SocketAddr,
        http_bind: SocketAddr,
        section: &TunnelSection,
    ) -> Result<Self> {
        if section.token.trim().is_empty() {
            return Err(Error::config("tunnel.token 为空，无法启动反向隧道服务端"));
        }

        let mut builder = Server::builder()
            .bind(bind)
            .http_bind(http_bind)
            .token(section.token.clone())
            .limits(&build_limits(section))
            .rate_limits(&build_rate_limits(section))
            .http_response_timeout(Duration::from_secs(section.http_response_timeout_secs));

        if section.tls_enabled {
            builder = builder.tls(&build_tls(section));
        }

        let server = builder
            .build()
            .map_err(|e| Error::transport(format!("构建 FerroTunnel 服务端失败: {e}")))?;

        tracing::info!(%bind, %http_bind, "FerroTunnel 中继服务端已构建");
        Ok(Self {
            server,
            bind,
            http_bind,
        })
    }

    /// 数据面监听地址。
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// 公网 HTTP 入口地址。
    pub fn http_bind(&self) -> SocketAddr {
        self.http_bind
    }

    /// 启动并运行，直到 `cancel` 被触发后优雅关闭。
    pub async fn run(mut self, cancel: CancellationToken) -> Result<()> {
        self.server
            .start()
            .await
            .map_err(|e| Error::transport(format!("FerroTunnel 服务端启动失败: {e}")))?;
        tracing::info!(bind = %self.bind, http_bind = %self.http_bind, "FerroTunnel 中继服务端已启动");

        cancel.cancelled().await;

        tracing::info!("正在关闭 FerroTunnel 中继服务端");
        self.server
            .shutdown()
            .await
            .map_err(|e| Error::transport(format!("FerroTunnel 服务端关闭失败: {e}")))?;
        Ok(())
    }
}

/// 一条隧道的运行态快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTunnelState {
    /// 隧道标识（即 FerroTunnel 的 `tunnel_id`）。
    pub tunnel_id: String,
    /// 本地目标地址。
    pub local_addr: String,
    /// FerroTunnel 分配的会话 ID（可能为空）。
    pub session_id: Option<String>,
}

/// 客户端侧的单条隧道。
pub struct RelayTunnelClient {
    state: RelayTunnelState,
    client: Client,
}

impl std::fmt::Debug for RelayTunnelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTunnelClient")
            .field("tunnel_id", &self.state.tunnel_id)
            .field("local_addr", &self.state.local_addr)
            .finish_non_exhaustive()
    }
}

impl RelayTunnelClient {
    /// 构建但不启动。
    pub fn build(
        tunnel_id: impl Into<String>,
        server_addr: impl Into<String>,
        local_addr: impl Into<String>,
        section: &TunnelSection,
    ) -> Result<Self> {
        let tunnel_id = tunnel_id.into();
        let local_addr = local_addr.into();

        if section.token.trim().is_empty() {
            return Err(Error::config("tunnel.token 为空，无法建立反向隧道"));
        }

        let mut builder = Client::builder()
            .server_addr(server_addr)
            .token(section.token.clone())
            .local_addr(local_addr.clone())
            .tunnel_id(tunnel_id.clone())
            .auto_reconnect(section.auto_reconnect)
            .reconnect_delay(Duration::from_millis(section.reconnect_delay_ms))
            .startup_timeout(Some(Duration::from_secs(section.startup_timeout_secs)))
            .limits(&build_limits(section));

        if section.tls_enabled {
            builder = builder.tls(&build_tls(section));
        }

        let client = builder
            .build()
            .map_err(|e| Error::transport(format!("构建 FerroTunnel 客户端失败: {e}")))?;

        Ok(Self {
            state: RelayTunnelState {
                tunnel_id,
                local_addr,
                session_id: None,
            },
            client,
        })
    }

    /// 隧道标识。
    pub fn tunnel_id(&self) -> &str {
        &self.state.tunnel_id
    }

    /// 本地目标地址。
    pub fn local_addr(&self) -> &str {
        &self.state.local_addr
    }

    /// 最近一次启动后的状态快照。
    pub fn state(&self) -> &RelayTunnelState {
        &self.state
    }

    /// 是否处于连接状态。
    pub fn is_running(&self) -> bool {
        self.client.is_running()
    }

    /// 启动（建立到服务端的反向隧道）。
    pub async fn start(&mut self) -> Result<RelayTunnelState> {
        let info = self.client.start().await.map_err(|e| {
            Error::transport(format!("隧道 {} 建立失败: {e}", self.state.tunnel_id))
        })?;
        self.state.session_id = info.session_id().map(|id| id.to_string());
        tracing::info!(
            tunnel = %self.state.tunnel_id,
            local = %self.state.local_addr,
            session = self.state.session_id.as_deref().unwrap_or("-"),
            "反向隧道已建立"
        );
        Ok(self.state.clone())
    }

    /// 关闭。
    pub async fn shutdown(&mut self) -> Result<()> {
        self.client
            .shutdown()
            .await
            .map_err(|e| Error::transport(format!("隧道 {} 关闭失败: {e}", self.state.tunnel_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section() -> TunnelSection {
        TunnelSection {
            token: "shared-secret".to_string(),
            ..TunnelSection::default()
        }
    }

    #[test]
    fn limits_and_rates_map_from_config() {
        let s = TunnelSection {
            token: "t".to_string(),
            max_frame_bytes: 4096,
            max_sessions: 7,
            max_streams_per_session: 9,
            rate_streams_per_sec: 11,
            rate_bytes_per_sec: 1024,
            rate_burst_factor: 3,
            ..TunnelSection::default()
        };
        let limits = build_limits(&s);
        assert_eq!(limits.max_frame_bytes, 4096);
        assert_eq!(limits.max_sessions, 7);
        assert_eq!(limits.max_streams_per_session, 9);
        // 未在 rscross 配置里暴露的字段保留 FerroTunnel 默认值
        assert_eq!(
            limits.max_capabilities,
            LimitsConfig::default().max_capabilities
        );

        let rates = build_rate_limits(&s);
        assert_eq!(rates.streams_per_sec, 11);
        assert_eq!(rates.bytes_per_sec, 1024);
        assert_eq!(rates.burst_factor, 3);
    }

    #[test]
    fn empty_token_is_rejected() {
        let s = TunnelSection::default();
        assert!(RelayTunnelClient::build("t1", "127.0.0.1:1", "127.0.0.1:2", &s).is_err());
        assert!(
            RelayServer::build(
                "127.0.0.1:0".parse().expect("addr"),
                "127.0.0.1:0".parse().expect("addr"),
                &s
            )
            .is_err()
        );
    }

    #[test]
    fn relay_tunnel_client_builds_with_valid_config() {
        let client =
            RelayTunnelClient::build("web", "127.0.0.1:7835", "127.0.0.1:8080", &section())
                .expect("build");
        assert_eq!(client.tunnel_id(), "web");
        assert_eq!(client.local_addr(), "127.0.0.1:8080");
        assert!(!client.is_running());
    }

    #[test]
    fn relay_server_builds_with_valid_config() {
        let server = RelayServer::build(
            "127.0.0.1:0".parse().expect("addr"),
            "127.0.0.1:0".parse().expect("addr"),
            &section(),
        )
        .expect("build");
        assert_eq!(server.http_bind().port(), 0);
    }
}
