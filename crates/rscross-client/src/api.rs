//! 控制面 HTTP 客户端。
//!
//! **为什么不复用服务端的 DTO**：客户端刻意不依赖 `rscross-server`，
//! 否则会把 axum / rusqlite 一起拖进静态二进制。这里的结构体是服务端 JSON 的镜像，
//! 由 `tests/e2e/e2e.py` 用真实二进制做端到端校验（协议漂移会在 CI 暴露）。

use std::time::Duration;

use rscross_common::{ClientRuntime, DesiredTunnel, Error, Result};
use serde::{Deserialize, Serialize};

/// 注册请求。
#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    /// 一次性接入令牌。
    pub token: Option<String>,
    /// 期望的节点名。
    pub name: Option<String>,
    /// 运行时信息。
    pub runtime: ClientRuntime,
}

/// 服务端下发的 P2P 参数。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct P2pInfo {
    /// 是否启用。
    pub enabled: bool,
    /// 路径策略。
    pub policy: String,
    /// 服务端节点 ID。
    pub server_endpoint_id: Option<String>,
    /// 服务端寻址信息（JSON）。
    pub server_endpoint_addr: Option<String>,
    /// Relay 模式。
    pub relay_mode: String,
    /// 是否启用地址发现。
    pub address_lookup: bool,
}

/// 注册响应。
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    /// 分配的客户端 ID。
    pub client_id: String,
    /// agent token。
    pub agent_token: String,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// FerroTunnel 控制面地址。
    pub tunnel_server: String,
    /// FerroTunnel 握手 token。
    pub tunnel_token: String,
    /// 服务端对外地址。
    #[serde(default)]
    pub public_url: Option<String>,
    /// P2P 参数。
    #[serde(default)]
    pub p2p: P2pInfo,
    /// 初始隧道列表。
    #[serde(default)]
    pub tunnels: Vec<DesiredTunnel>,
}

/// 心跳请求。
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatRequest {
    /// 运行时信息。
    pub runtime: ClientRuntime,
}

/// 心跳响应。
#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatResponse {
    /// 下一次心跳间隔。
    pub heartbeat_secs: u64,
    /// 服务端时间。
    #[serde(default)]
    pub server_time: String,
    /// 服务端观测到的出口 IP。
    #[serde(default)]
    pub public_ip: Option<String>,
    /// P2P 参数。
    #[serde(default)]
    pub p2p: P2pInfo,
    /// 期望的隧道配置。
    #[serde(default)]
    pub tunnels: Vec<DesiredTunnel>,
}

/// 上报给服务端的日志条目。
#[derive(Debug, Clone, Serialize)]
pub struct ClientLogEntry {
    /// 级别。
    pub level: String,
    /// 正文。
    pub message: String,
    /// 目标模块。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

/// 控制面客户端。
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient").field("base", &self.base).finish()
    }
}

impl ApiClient {
    /// 用形如 `http://1.2.3.4:7800` 的地址创建。
    pub fn new(base: &str) -> Result<Self> {
        let base = base.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(Error::config(format!(
                "服务端地址必须以 http:// 或 https:// 开头: {base}"
            )));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(format!("rscross-client/{}", rscross_common::VERSION))
            .build()
            .map_err(Error::transport)?;
        Ok(Self { http, base })
    }

    /// 基础地址。
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `POST /api/v1/agent/enroll`
    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse> {
        let response = self
            .http
            .post(format!("{}/api/v1/agent/enroll", self.base))
            .json(req)
            .send()
            .await
            .map_err(Error::transport)?;
        decode(response).await
    }

    /// `POST /api/v1/agent/heartbeat`
    pub async fn heartbeat(
        &self,
        agent_token: &str,
        req: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse> {
        let response = self
            .http
            .post(format!("{}/api/v1/agent/heartbeat", self.base))
            .header("x-rscross-agent", agent_token)
            .json(req)
            .send()
            .await
            .map_err(Error::transport)?;
        decode(response).await
    }

    /// `POST /api/v1/agent/logs`
    pub async fn push_logs(&self, agent_token: &str, entries: &[ClientLogEntry]) -> Result<usize> {
        #[derive(Deserialize)]
        struct PushResponse {
            #[serde(default)]
            accepted: usize,
        }
        let response = self
            .http
            .post(format!("{}/api/v1/agent/logs", self.base))
            .header("x-rscross-agent", agent_token)
            .json(entries)
            .send()
            .await
            .map_err(Error::transport)?;
        let parsed: PushResponse = decode(response).await?;
        Ok(parsed.accepted)
    }
}

async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response.text().await.map_err(Error::transport)?;

    if !status.is_success() {
        let detail = serde_json::from_str::<ApiErrorBody>(&body)
            .ok()
            .map(|parsed| {
                if parsed.message.is_empty() {
                    parsed.code
                } else {
                    parsed.message
                }
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| body.chars().take(300).collect());
        return Err(Error::api(format!("控制面返回 {status}: {detail}")));
    }

    serde_json::from_str(&body)
        .map_err(|e| Error::api(format!("控制面响应解析失败: {e}; body={body}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_is_normalized() {
        let c = ApiClient::new("http://127.0.0.1:7800/").expect("ok");
        assert_eq!(c.base(), "http://127.0.0.1:7800");
    }

    #[test]
    fn base_url_requires_scheme() {
        assert!(ApiClient::new("127.0.0.1:7800").is_err());
    }
}
