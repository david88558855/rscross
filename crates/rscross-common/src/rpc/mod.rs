//! RPC 传输层：WebSocket 上的请求/响应 RPC
//!
//! rscross 自研的控制面协议，语义如下：
//! - 传输：WebSocket（文本帧，JSON 编码）
//! - 调用：`call(method, payload) -> reply`，支持超时
//! - 通知：`notify(method, payload)`，无响应
//! - 双向：同一连接上服务端可主动下发指令（`ServerPush`）
//!
//! 服务端维护连接级上下文（key/code/userCode 等），
//! 供各处理函数读取当前连接的身份信息。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot, RwLock};

pub mod client;
pub mod server;

pub use client::{ConnState, DispatchHandle, PushHandler, RpcClient};
pub use server::{extract_key, RpcServer};

/// 帧类型
pub mod frame_type {
    /// 请求：需要响应
    pub const CALL: u8 = 1;
    /// 响应
    pub const REPLY: u8 = 2;
    /// 通知：不需响应
    pub const NOTIFY: u8 = 3;
    /// 服务端主动推送
    pub const PUSH: u8 = 4;
    /// 心跳
    pub const PING: u8 = 5;
    /// 错误
    pub const ERROR: u8 = 6;
}

/// RPC 帧
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// 帧类型，见 [`frame_type`]
    #[serde(rename = "t")]
    pub ftype: u8,
    /// 请求 ID，响应需回填
    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// 方法名
    #[serde(rename = "m", default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// 载荷
    #[serde(rename = "p", default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
}

/// 连接级上下文，键值对存储
///
/// 用 newtype 包装 `Arc<RwLock<..>>`：既能定义固有方法，
/// 又能廉价克隆后跨任务共享同一份连接状态。
#[derive(Clone, Debug, Default)]
pub struct SessionCtx(Arc<RwLock<HashMap<String, String>>>);

impl SessionCtx {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn set(&self, k: &str, v: &str) {
        self.0.write().await.insert(k.to_string(), v.to_string());
    }

    pub async fn get(&self, k: &str) -> Option<String> {
        self.0.read().await.get(k).cloned()
    }

    pub async fn has(&self, k: &str) -> bool {
        self.0.read().await.contains_key(k)
    }

    /// 一次性获取并删除，用于注册超时判定
    pub async fn take(&self, k: &str) -> Option<String> {
        self.0.write().await.remove(k)
    }

    pub async fn all(&self) -> HashMap<String, String> {
        self.0.read().await.clone()
    }
}

/// 处理器：处理服务端下发的调用或客户端主动请求
pub type Handler = Arc<dyn Fn(RpcContext) -> BoxFuture<AppReply> + Send + Sync>;

/// 异步返回的 boxed future，避免在类型别名中引入生命周期问题
pub type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// 处理结果
pub type AppReply = Result<Value, String>;

/// RPC 调用上下文
#[derive(Clone)]
pub struct RpcContext {
    /// 请求 ID
    pub id: Option<u64>,
    /// 方法名
    pub method: String,
    /// 载荷
    pub payload: Value,
    /// 连接上下文
    pub ctx: SessionCtx,
    /// 回写通道
    tx: Option<mpsc::UnboundedSender<Frame>>,
}

impl RpcContext {
    /// 读取载荷并反序列化为具体类型
    pub fn bind<T: for<'de> Deserialize<'de>>(&self) -> crate::error::AppResult<T> {
        serde_json::from_value(self.payload.clone())
            .map_err(|e| crate::error::AppError::invalid(format!("参数解析失败: {e}")))
    }

    /// 读取连接上下文字符串
    pub async fn ctx_get(&self, k: &str) -> Option<String> {
        self.ctx.get(k).await
    }

    /// 主动向对端推送数据（服务端下发指令）
    pub async fn push(&self, method: &str, payload: Value) -> crate::error::AppResult<()> {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Frame {
                ftype: frame_type::PUSH,
                id: None,
                method: method.to_string(),
                payload,
            });
        }
        Ok(())
    }

    /// 发送响应
    pub fn reply(self, result: AppReply) {
        let Some(id) = self.id else {
            return;
        };
        let Some(tx) = self.tx.clone() else {
            return;
        };
        let frame = match result {
            Ok(v) => Frame {
                ftype: frame_type::REPLY,
                id: Some(id),
                method: String::new(),
                payload: v,
            },
            Err(e) => Frame {
                ftype: frame_type::ERROR,
                id: Some(id),
                method: String::new(),
                payload: Value::String(e),
            },
        };
        let _ = tx.send(frame);
    }
}

/// 全局请求 ID 分配器
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// 简易重试：固定间隔重试 `times` 次，仅在上次失败后重试
pub async fn retry<F, Fut, T>(mut f: F, times: u32, interval: Duration) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last_err: Option<String> = None;
    for _ in 0..=times {
        match f().await {
            Ok(v) => return Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "操作失败，准备重试");
                last_err = Some(e);
                tokio::time::sleep(interval).await;
            }
        }
    }
    if let Some(e) = last_err {
        tracing::error!(error = %e, "重试耗尽");
    }
    None
}

/// 编码帧为 JSON 文本
pub fn encode_frame(f: &Frame) -> String {
    // 序列化不会失败（结构体字段均为可序列化类型）
    serde_json::to_string(f).unwrap_or_else(|_| "{}".to_string())
}

/// 解码帧
pub fn decode_frame(s: &str) -> Option<Frame> {
    serde_json::from_str(s).ok()
}

/// 一次性 oneshot 等待器池：管理等待中的请求
#[derive(Default)]
pub struct PendingMap {
    inner: parking_lot::Mutex<HashMap<u64, oneshot::Sender<Value>>>,
}

impl PendingMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, id: u64, tx: oneshot::Sender<Value>) {
        self.inner.lock().insert(id, tx);
    }

    /// 投递响应给等待方，失败说明调用方已超时退出
    pub fn complete(&self, id: u64, value: Value) -> bool {
        match self.inner.lock().remove(&id) {
            Some(tx) => tx.send(value).is_ok(),
            None => false,
        }
    }

    pub fn remove(&self, id: u64) {
        self.inner.lock().remove(&id);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let f = Frame {
            ftype: frame_type::CALL,
            id: Some(1),
            method: "rpc/node/reg".to_string(),
            payload: serde_json::json!({"key": "abc"}),
        };
        let s = encode_frame(&f);
        let back = decode_frame(&s).unwrap();
        assert_eq!(back.ftype, frame_type::CALL);
        assert_eq!(back.id, Some(1));
        assert_eq!(back.method, "rpc/node/reg");
        assert_eq!(back.payload["key"], "abc");
    }

    #[test]
    fn test_pending_map() {
        let m = PendingMap::new();
        let (tx, rx) = oneshot::channel();
        m.insert(1, tx);
        assert_eq!(m.len(), 1);
        assert!(m.complete(1, serde_json::json!("ok")));
        assert_eq!(rx.blocking_recv().unwrap(), serde_json::json!("ok"));
        assert!(m.is_empty());
    }
}
