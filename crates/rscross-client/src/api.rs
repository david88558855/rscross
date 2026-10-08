//! 控制面 HTTP 客户端。
//!
//! **为什么不复用控制面的 DTO**：客户端刻意不依赖 `rscross-control`，
//! 否则会把 axum / rusqlite 一起拖进静态二进制。这里的结构体是控制面 JSON 的镜像，
//! 由 `tests/e2e/e2e.py` 用真实二进制做端到端校验（协议漂移会在 CI 暴露）。

use std::time::Duration;

use rscross_common::{ClientRuntime, DesiredTunnel, Error, NodeEndpoint, Result};
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

/// 注册响应。
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    /// 分配的客户端 ID。
    pub client_id: String,
    /// 客户端名。
    pub name: String,
    /// agent token。
    pub agent_token: String,
    /// 心跳间隔（秒）。
    pub heartbeat_secs: u64,
    /// 控制台对外地址。
    #[serde(default)]
    pub public_url: Option<String>,
    /// 归属的服务端节点（数据面坐标）。
    pub node: NodeEndpoint,
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
    /// 控制台时间。
    #[serde(default)]
    pub server_time: String,
    /// 控制台观测到的出口 IP。
    #[serde(default)]
    pub public_ip: Option<String>,
    /// 归属节点；`None` 表示已被解绑或节点被删除，客户端应停掉隧道。
    #[serde(default)]
    pub node: Option<NodeEndpoint>,
    /// 期望的隧道配置。
    #[serde(default)]
    pub tunnels: Vec<DesiredTunnel>,
}

/// 上报给控制台的日志条目。
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
                "控制台地址必须以 http:// 或 https:// 开头: {base}"
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
        return Err(Error::api(format!("控制台返回 {status}: {detail}")));
    }

    serde_json::from_str(&body)
        .map_err(|e| Error::api(format!("控制台响应解析失败: {e}; body={body}")))
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

    #[test]
    fn heartbeat_parses_detached_node() {
        // 节点被删除时控制台会回 node: null；客户端必须能解析而不是崩在反序列化上。
        let raw = r#"{
            "heartbeat_secs": 15,
            "server_time": "2026-01-01T00:00:00.000Z",
            "public_ip": null,
            "node": null,
            "tunnels": []
        }"#;
        let parsed: HeartbeatResponse = serde_json::from_str(raw).expect("解析");
        assert!(parsed.node.is_none());
        assert!(parsed.tunnels.is_empty());
    }

    #[test]
    fn heartbeat_parses_node_coordinates() {
        let raw = r#"{
            "heartbeat_secs": 15,
            "node": {
                "node_id": "n1",
                "name": "node-1",
                "tunnel_server": "203.0.113.9:7835",
                "tunnel_token": "tt",
                "endpoint_id": "aa",
                "endpoint_addr": "{}"
            },
            "tunnels": [{
                "id": "t1", "name": "web", "proto": "http",
                "local_addr": "127.0.0.1:8080", "host": "a.example.com",
                "enabled": true, "rate_limit_kbps": 0, "conn_limit": 0
            }]
        }"#;
        let parsed: HeartbeatResponse = serde_json::from_str(raw).expect("解析");
        let node = parsed.node.expect("应有节点");
        assert_eq!(node.tunnel_server, "203.0.113.9:7835");
        assert_eq!(parsed.tunnels.len(), 1);
        assert_eq!(parsed.tunnels[0].proto, rscross_common::TunnelProto::Http);
    }
}
