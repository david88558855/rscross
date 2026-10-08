//! 节点侧的控制面 HTTP 客户端（`managed` 模式用）。
//!
//! 只在启用 `http-client` feature 时编译：独立控制台二进制不需要它，
//! 因此控制台产物里不会出现 reqwest / hyper / h2。
//!
//! DTO 直接复用控制面里定义的结构体（`crate::api::nodes::*`），
//! 这样**服务端与客户端的字段名不可能漂移** —— 一次编译就能发现不一致。

use std::time::Duration;

use rscross_common::{Error, NodeRuntime, Result};

use crate::api::nodes::{
    NodeEnrollRequest, NodeEnrollResponse, NodeHeartbeatRequest, NodeHeartbeatResponse,
};

/// 控制面 HTTP 客户端。
#[derive(Clone)]
pub struct NodeApiClient {
    http: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for NodeApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeApiClient")
            .field("base", &self.base)
            .finish()
    }
}

impl NodeApiClient {
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
            .user_agent(format!("rscross-server/{}", rscross_common::VERSION))
            .build()
            .map_err(Error::transport)?;
        Ok(Self { http, base })
    }

    /// 基础地址。
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `POST /api/v1/node/enroll`
    pub async fn enroll(
        &self,
        token: &str,
        name: &str,
        runtime: &NodeRuntime,
    ) -> Result<NodeEnrollResponse> {
        let body = NodeEnrollRequest {
            token: token.to_string(),
            name: Some(name.to_string()),
            runtime: runtime.clone(),
        };
        let response = self
            .http
            .post(format!("{}/api/v1/node/enroll", self.base))
            .json(&body)
            .send()
            .await
            .map_err(Error::transport)?;
        decode(response).await
    }

    /// `POST /api/v1/node/heartbeat`
    pub async fn heartbeat(
        &self,
        token: &str,
        runtime: &NodeRuntime,
    ) -> Result<NodeHeartbeatResponse> {
        let body = NodeHeartbeatRequest {
            runtime: runtime.clone(),
        };
        let response = self
            .http
            .post(format!("{}/api/v1/node/heartbeat", self.base))
            .header("x-rscross-node", token)
            .json(&body)
            .send()
            .await
            .map_err(Error::transport)?;
        decode(response).await
    }
}

async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response.text().await.map_err(Error::transport)?;

    if !status.is_success() {
        #[derive(serde::Deserialize)]
        struct ApiErrorBody {
            #[serde(default)]
            code: String,
            #[serde(default)]
            message: String,
        }
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
