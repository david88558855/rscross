//! RPC 客户端：主动连接服务端，发送调用并等待响应，同时接收服务端推送

use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot, RwLock};

// WebSocket 流需要 split()，来自 futures 的 SinkExt / StreamExt
use futures_util::{SinkExt, StreamExt};

use super::{decode_frame, encode_frame, frame_type, next_id, Frame, PendingMap, SessionCtx};

/// 推送处理器：收到服务端主动下发的指令
pub type PushHandler = Arc<dyn Fn(&str, Value) + Send + Sync>;

/// 连接状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
}

/// RPC 客户端
pub struct RpcClient {
    /// WebSocket 地址
    url: String,
    /// 认证 key
    key: String,
    /// 待处理请求
    pending: Arc<PendingMap>,
    /// 下行帧接收通道（响应 + 推送）
    inbox: mpsc::UnboundedReceiver<Frame>,
    /// 发送通道
    outbox: mpsc::UnboundedSender<Frame>,
    /// 连接状态
    state: Arc<RwLock<ConnState>>,
    /// 会话上下文
    ctx: SessionCtx,
    /// 推送处理器
    push_handler: PushHandler,
    /// 调用超时
    timeout: Duration,
}

impl RpcClient {
    /// 建立连接
    ///
    /// `url` 形如 `ws://host:port/rpc/ws`
    pub async fn connect(url: &str, key: &str) -> Result<Self, String> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Message;

        let mut req = url
            .into_client_request()
            .map_err(|e| format!("URL 非法: {e}"))?;
        if !key.is_empty() {
            req.headers_mut()
                .insert("key", key.parse().map_err(|_| "key 非法")?);
        }

        let (ws, _resp) = tokio_tungstenite::connect_async(req)
            .await
            .map_err(|e| format!("连接服务端失败: {e}"))?;

        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Frame>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<Frame>();

        // 写循环
        tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                let text = encode_frame(&frame);
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        // 读循环
        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => match String::from_utf8(b.to_vec()) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(_) => break,
                    // 兼容 tungstenite 各版本的额外变体
                    _ => continue,
                };
                if let Some(frame) = decode_frame(&text) {
                    if in_tx.send(frame).is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            url: url.to_string(),
            key: key.to_string(),
            pending: Arc::new(PendingMap::new()),
            inbox: in_rx,
            outbox: out_tx,
            state: Arc::new(RwLock::new(ConnState::Connected)),
            ctx: SessionCtx::new(),
            push_handler: Arc::new(|_, _| {}),
            timeout: Duration::from_secs(30),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn ctx(&self) -> SessionCtx {
        self.ctx.clone()
    }

    /// 设置推送处理器
    pub fn set_push_handler(&mut self, h: PushHandler) {
        self.push_handler = h;
    }

    /// 设置默认调用超时
    pub fn set_timeout(&mut self, d: Duration) {
        self.timeout = d;
    }

    /// 检查连接状态
    pub async fn check_state(&self) -> Result<(), String> {
        match *self.state.read().await {
            ConnState::Connected => Ok(()),
            _ => Err("客户端未连接".to_string()),
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.check_state().await.is_ok()
    }

    /// 发送调用并等待响应
    pub async fn call_raw(&self, method: &str, payload: Value) -> Result<Value, String> {
        self.call_with_timeout(method, payload, self.timeout).await
    }

    /// 发送调用并指定超时
    pub async fn call_with_timeout(
        &self,
        method: &str,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.check_state().await?;

        let id = next_id();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id, tx);

        let frame = Frame {
            ftype: frame_type::CALL,
            id: Some(id),
            method: method.to_string(),
            payload,
        };

        if self.outbox.send(frame).is_err() {
            self.pending.remove(id);
            return Err("发送失败，连接已断开".to_string());
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(_)) => {
                self.pending.remove(id);
                Err("响应通道已关闭".to_string())
            }
            Err(_) => {
                self.pending.remove(id);
                Err(format!("调用 {method} 超时"))
            }
        }
    }

    /// 发送调用并把响应反序列化为具体类型
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        payload: Value,
    ) -> Result<T, String> {
        let v = self.call_raw(method, payload).await?;
        serde_json::from_value(v).map_err(|e| format!("响应解析失败: {e}"))
    }

    /// 发送调用并把响应解析为字符串（大量指令返回 "success"）
    pub async fn call_str(&self, method: &str, payload: Value) -> Result<String, String> {
        let v = self.call_raw(method, payload).await?;
        Ok(match v {
            Value::String(s) => s,
            Value::Null => String::new(),
            other => other.to_string(),
        })
    }

    /// 发送调用但忽略响应（对应 Go 侧 CallAsync）
    pub async fn call_async(&self, method: &str, payload: Value) {
        let frame = Frame {
            ftype: frame_type::NOTIFY,
            id: None,
            method: method.to_string(),
            payload,
        };
        let _ = self.outbox.send(frame);
    }

    /// 发送调用，超时后自动重试 `times` 次
    pub async fn call_retry(
        &self,
        method: &str,
        payload: Value,
        times: u32,
        interval: Duration,
    ) -> Result<Value, String> {
        let mut last_err = String::new();
        for i in 0..=times {
            match self
                .call_with_timeout(method, payload.clone(), self.timeout)
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::warn!(method, error = %e, attempt = i, "调用失败");
                    last_err = e;
                    tokio::time::sleep(interval).await;
                }
            }
        }
        Err(last_err)
    }

    /// 发送心跳
    pub async fn ping(&self) {
        let frame = Frame {
            ftype: frame_type::PING,
            id: Some(next_id()),
            method: String::new(),
            payload: Value::Null,
        };
        let _ = self.outbox.send(frame);
    }

    /// 启动响应分发循环，把响应投递给等待方、把推送交给处理器
    pub fn start_dispatch(mut self) -> DispatchHandle {
        let pending = self.pending.clone();
        let push_handler = self.push_handler.clone();
        let mut inbox = std::mem::replace(
            &mut self.inbox,
            mpsc::unbounded_channel().1, // 占位通道，稍后被丢弃
        );
        let state = self.state.clone();

        let handle = tokio::spawn(async move {
            while let Some(frame) = inbox.recv().await {
                match frame.ftype {
                    frame_type::REPLY | frame_type::ERROR => {
                        if let Some(id) = frame.id {
                            if frame.ftype == frame_type::ERROR {
                                let msg = frame.payload.as_str().unwrap_or("未知错误").to_string();
                                pending.complete(id, Value::String(msg));
                            } else {
                                pending.complete(id, frame.payload);
                            }
                        }
                    }
                    frame_type::PUSH => {
                        push_handler(&frame.method, frame.payload);
                    }
                    frame_type::NOTIFY => {
                        push_handler(&frame.method, frame.payload);
                    }
                    _ => {}
                }
            }
            *state.write().await = ConnState::Disconnected;
        });

        DispatchHandle {
            handle,
            outbox: self.outbox.clone(),
            state: self.state.clone(),
        }
    }

    /// 关闭连接
    pub fn close(&self) {
        let frame = Frame {
            ftype: frame_type::NOTIFY,
            id: None,
            method: "__close__".to_string(),
            payload: Value::Null,
        };
        let _ = self.outbox.send(frame);
    }
}

/// 分发任务句柄
pub struct DispatchHandle {
    handle: tokio::task::JoinHandle<()>,
    outbox: mpsc::UnboundedSender<Frame>,
    state: Arc<RwLock<ConnState>>,
}

impl DispatchHandle {
    /// 标记连接已断开
    pub async fn mark_disconnected(&self) {
        *self.state.write().await = ConnState::Disconnected;
    }

    pub async fn abort(&self) {
        self.handle.abort();
    }
}
