//! 节点/客户端运行时：连接服务端、注册、心跳、事件分发

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rscross_common::rpc::RpcClient;
use serde_json::json;

use crate::events;
use crate::AppState;

/// 运行时
pub struct Node {
    state: AppState,
}

impl Node {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// 主循环：断线重连
    pub async fn run(self) -> Result<()> {
        let mut backoff = Duration::from_secs(1);

        loop {
            match self.session().await {
                Ok(()) => {
                    tracing::info!("会话正常结束");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "连接异常");
                }
            }

            // 清理所有隧道
            self.state.services.stop_all();

            tracing::info!("{} 秒后重连", backoff.as_secs());
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    /// 单次会话
    async fn session(&self) -> Result<()> {
        let url = format!("{}/rpc/ws", self.state.ws_url);
        let mut client = RpcClient::connect(&url, &self.state.key)
            .map_err(|e| anyhow::anyhow!("连接服务端失败: {e}"))?;

        // 注册推送处理器
        events::register_handlers(&mut client, &self.state);
        let _dispatch = client.start_dispatch();

        // 注册
        let reg_key = if self.state.config.node {
            "rpc/node/reg"
        } else {
            "rpc/client/reg"
        };

        let mut payload = json!({
            "key": self.state.key,
            "version": rscross_common::VERSION,
        });
        if !self.state.config.proxy_base_url.is_empty() {
            payload["domain"] = json!("1");
        }

        let reply = client
            .call_str(reg_key, payload)
            .await
            .map_err(|e| anyhow::anyhow!("注册失败: {e}"))?;

        if reply != "success" {
            anyhow::bail!("注册被拒绝: {reply}");
        }

        tracing::info!(
            mode = if self.state.config.node { "节点" } else { "客户端" },
            "注册成功"
        );
        self.state.state.set_running("__session__", "");

        // 心跳
        let ping_key = if self.state.config.node {
            "rpc/node/ping"
        } else {
            "rpc/client/ping"
        };
        let ping_task = tokio::spawn({
            let client_url = url.clone();
            let key = self.state.key.clone();
            let ping_key = ping_key.to_string();
            async move {
                let mut ping_client = match RpcClient::connect(&client_url, &key).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "心跳通道建立失败");
                        return;
                    }
                };
                let _h = ping_client.start_dispatch();
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    if ping_client.call_async(&ping_key, json!(null)).is_ok() {
                        // 无需等待响应
                    }
                }
            }
        });

        // 等待连接断开
        loop {
            if self.state.state.get_update_tag("__stop__").is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;

            if !client.is_connected().await {
                break;
            }
        }

        ping_task.abort();
        self.state.state.remove("__session__");
        Ok(())
    }
}

/// 构建 frpc 客户端配置
pub fn build_frpc_config(
    auth_token: &str,
    server_addr: &str,
    server_port: u16,
    pool_count: i32,
) -> rscross_frp::ClientConfig {
    rscross_frp::ClientConfig {
        auth_token: auth_token.to_string(),
        server_addr: server_addr.to_string(),
        server_port,
        pool_count,
        login_fail_exit: false,
        ..Default::default()
    }
}

/// 类型别名
pub type SharedNode = Arc<Node>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_frpc_config() {
        let c = build_frpc_config("token", "1.2.3.4", 7000, 3);
        assert_eq!(c.auth_token, "token");
        assert_eq!(c.control_addr(), "1.2.3.4:7000");
        assert_eq!(c.pool_count, 3);
    }
}
