//! RPC 服务端：处理 WebSocket 连接上的调用请求并支持主动推送

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::error::AppResult;

use super::{decode_frame, encode_frame, frame_type, AppReply, Frame, RpcContext, SessionCtx};

/// 连接建立 / 断开钩子
pub type ConnectedHook = Arc<dyn Fn(SessionCtx) + Send + Sync>;
pub type DisconnectedHook = Arc<dyn Fn(SessionCtx) + Send + Sync>;

/// RPC 服务端
pub struct RpcServer {
    /// 方法路由表：方法名 -> 处理器
    handlers: HashMap<String, super::Handler>,
    /// 连接建立钩子
    on_connected: Vec<ConnectedHook>,
    /// 连接断开钩子
    on_disconnected: Vec<DisconnectedHook>,
    /// 读超时
    read_timeout: Duration,
}

impl Default for RpcServer {
    fn default() -> Self {
        Self {
            handlers: HashMap::new(),
            on_connected: Vec::new(),
            on_disconnected: Vec::new(),
            read_timeout: Duration::from_secs(50),
        }
    }
}

impl RpcServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册方法处理器
    pub fn handle<F>(&mut self, method: &str, f: F) -> &mut Self
    where
        F: Fn(RpcContext) -> super::BoxFuture<AppReply> + Send + Sync + 'static,
    {
        self.handlers
            .insert(method.to_string(), Arc::new(move |ctx| Box::pin(f(ctx))));
        self
    }

    /// 连接建立钩子
    pub fn on_connected<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(SessionCtx) + Send + Sync + 'static,
    {
        self.on_connected.push(Arc::new(f));
        self
    }

    /// 连接断开钩子
    pub fn on_disconnected<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(SessionCtx) + Send + Sync + 'static,
    {
        self.on_disconnected.push(Arc::new(f));
        self
    }

    pub fn set_read_timeout(&mut self, d: Duration) -> &mut Self {
        self.read_timeout = d;
        self
    }

    /// 处理一条已建立的 WebSocket 连接
    pub async fn serve(&self, socket: WebSocket) {
        let (mut sink, mut stream) = socket.split();
        let ctx = SessionCtx::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

        // 写循环
        let writer = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let text = encode_frame(&frame);
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        });

        // 连接钩子
        for hook in &self.on_connected {
            hook(ctx.clone());
        }
        tracing::debug!("RPC 连接已建立");

        // 读循环
        loop {
            let msg = match tokio::time::timeout(self.read_timeout, stream.next()).await {
                Ok(Some(Ok(m))) => m,
                Ok(Some(Err(e))) => {
                    tracing::debug!("RPC 连接读取错误: {e}");
                    break;
                }
                Ok(None) => break, // 对端关闭
                Err(_) => {
                    tracing::debug!("RPC 连接读超时，关闭");
                    break;
                }
            };

            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Ping(p) => {
                    // 回显 pong
                    let _ = tx.send(Frame {
                        ftype: frame_type::PING,
                        id: None,
                        method: String::new(),
                        payload: serde_json::Value::String(String::from_utf8_lossy(&p).to_string()),
                    });
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => break,
                Message::Binary(b) => match String::from_utf8(b.to_vec()) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
            };

            let Some(frame) = decode_frame(&text) else {
                continue;
            };

            // 处理帧
            match frame.ftype {
                // 客户端主动请求（如注册）
                frame_type::CALL => self.dispatch(frame, ctx.clone(), Some(tx.clone())),
                // 客户端通知
                frame_type::NOTIFY => {
                    self.dispatch(frame, ctx.clone(), None);
                }
                // 客户端心跳
                frame_type::PING => {
                    if let Some(id) = frame.id {
                        let _ = tx.send(Frame {
                            ftype: frame_type::PING,
                            id: Some(id),
                            method: String::new(),
                            payload: serde_json::Value::String("pong".into()),
                        });
                    }
                }
                _ => {}
            }
        }

        // 清理
        for hook in &self.on_disconnected {
            hook(ctx.clone());
        }
        drop(tx);
        let _ = writer.await;
        tracing::debug!("RPC 连接已关闭");
    }

    /// 分发请求到对应处理器
    fn dispatch(&self, frame: Frame, ctx: SessionCtx, tx: Option<mpsc::UnboundedSender<Frame>>) {
        let Some(handler) = self.handlers.get(&frame.method) else {
            // 未注册的方法，回错误响应
            if let (Some(id), Some(tx)) = (frame.id, tx.clone()) {
                let _ = tx.send(Frame {
                    ftype: frame_type::ERROR,
                    id: Some(id),
                    method: String::new(),
                    payload: serde_json::Value::String(format!("unknown method: {}", frame.method)),
                });
            }
            tracing::warn!(method = %frame.method, "未注册的 RPC 方法");
            return;
        };

        let rpc_ctx = RpcContext {
            id: frame.id,
            method: frame.method.clone(),
            payload: frame.payload,
            ctx,
            tx,
        };

        let handler = handler.clone();
        tokio::spawn(async move {
            let result = handler(rpc_ctx.clone()).await;
            rpc_ctx.reply(result);
        });
    }

    /// 注册一条连接（供测试与嵌入式使用）
    pub async fn handle_connection(&self, socket: WebSocket) -> AppResult<()> {
        self.serve(socket).await;
        Ok(())
    }
}

/// 从 WebSocket 提取认证 key（连接握手时携带）
pub fn extract_key(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// 错误转字符串，供 RPC 处理器使用
pub fn to_reply(e: AppError) -> AppReply {
    Err(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extract_key() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(extract_key(&headers), None);
        headers.insert("key", "abc123".parse().unwrap());
        assert_eq!(extract_key(&headers), Some("abc123".to_string()));
    }
}
