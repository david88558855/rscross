//! 控制台日志总线。
//!
//! 一根 `tracing` Layer 把每条事件同时送进两处：
//! 1. 进程内环形缓冲 —— 供 `/api/v1/logs` 立即读取（「日志」页首屏）。
//! 2. `broadcast` 频道 —— 供 SSE / 轮询实时增量，以及（可选）落库。
//!
//! 之所以自己实现 Layer 而不是用 `tracing-appender`：日志页需要**结构化**的
//! `(level, target, message)` 三元组，而 appender 只给文本行。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// 一条日志事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// 自增序号（单调递增，前端据此做增量拉取）。
    pub seq: u64,
    /// RFC3339 时间戳。
    pub ts: String,
    /// 级别：`TRACE`/`DEBUG`/`INFO`/`WARN`/`ERROR`。
    pub level: String,
    /// 目标模块。
    pub target: String,
    /// 正文（`message` 字段 + 其它结构化字段）。
    pub message: String,
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    seq: AtomicU64,
    ring: Mutex<VecDeque<LogEvent>>,
    tx: broadcast::Sender<LogEvent>,
}

/// 日志总线句柄。
#[derive(Debug, Clone)]
pub struct LogBus {
    inner: Arc<Inner>,
}

impl LogBus {
    /// 创建总线，`capacity` 为环形缓冲容量。
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(64);
        let (tx, _rx) = broadcast::channel(1024);
        Self {
            inner: Arc::new(Inner {
                capacity,
                seq: AtomicU64::new(0),
                ring: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
                tx,
            }),
        }
    }

    /// 环形缓冲当前容量。
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// 写入一条事件。
    pub fn push(&self, mut event: LogEvent) {
        event.seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;

        {
            let mut ring = match self.inner.ring.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if ring.len() == self.inner.capacity {
                ring.pop_front();
            }
            ring.push_back(event.clone());
        }

        // 没有订阅者时 send 会返回 Err，属正常情况。
        let _ = self.inner.tx.send(event);
    }

    /// 读取环形缓冲（倒序，最新的在前），支持级别与关键字过滤。
    pub fn recent(
        &self,
        limit: usize,
        level: Option<&str>,
        keyword: Option<&str>,
    ) -> Vec<LogEvent> {
        let ring = match self.inner.ring.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        ring.iter()
            .rev()
            .filter(|e| level.is_none_or(|lv| e.level.eq_ignore_ascii_case(lv)))
            .filter(|e| keyword.is_none_or(|kw| e.message.contains(kw)))
            .take(limit)
            .cloned()
            .collect()
    }

    /// 订阅实时事件流。
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.inner.tx.subscribe()
    }

    /// 取出一条 Layer，挂到 `tracing_subscriber::registry()` 上。
    pub fn layer(&self) -> LogBusLayer {
        LogBusLayer { bus: self.clone() }
    }
}

/// 把 `tracing` 事件灌进 [`LogBus`] 的 Layer。
#[derive(Debug, Clone)]
pub struct LogBusLayer {
    bus: LogBus,
}

impl<S> Layer<S> for LogBusLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let level = meta.level().as_str().to_string();
        self.bus.push(LogEvent {
            seq: 0,
            ts: rscross_common::time::now_rfc3339(),
            level,
            target: meta.target().to_string(),
            message: visitor.finish(),
        });
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    extra: String,
}

impl FieldVisitor {
    fn finish(self) -> String {
        match (self.message, self.extra.is_empty()) {
            (Some(msg), true) => msg,
            (Some(msg), false) => format!("{msg} {}", self.extra),
            (None, true) => String::new(),
            (None, false) => self.extra,
        }
    }

    fn push_extra(&mut self, field: &Field, value: String) {
        if !self.extra.is_empty() {
            self.extra.push(' ');
        }
        self.extra.push_str(field.name());
        self.extra.push('=');
        self.extra.push_str(&value);
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.push_extra(field, value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            // tracing 的 message 走 Debug，渲染时带引号，这里去掉首尾引号。
            let trimmed = rendered
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&rendered);
            self.message = Some(trimmed.to_string());
        } else {
            self.push_extra(field, rendered);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_drops_oldest() {
        let bus = LogBus::new(64);
        for i in 0..100 {
            bus.push(LogEvent {
                seq: 0,
                ts: "t".to_string(),
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: format!("msg-{i}"),
            });
        }
        let recent = bus.recent(usize::MAX, None, None);
        assert_eq!(recent.len(), 64, "容量应被强制为 64");
        assert_eq!(recent[0].message, "msg-99", "最新的在最前");
        assert_eq!(recent[63].message, "msg-36");
        assert_eq!(recent[0].seq, 100, "序号从 1 开始单调递增");
    }

    #[test]
    fn filtering_works() {
        let bus = LogBus::new(128);
        for (lvl, msg) in [
            ("INFO", "启动完成"),
            ("ERROR", "连接失败"),
            ("INFO", "心跳正常"),
        ] {
            bus.push(LogEvent {
                seq: 0,
                ts: "t".to_string(),
                level: lvl.to_string(),
                target: "test".to_string(),
                message: msg.to_string(),
            });
        }
        assert_eq!(bus.recent(10, Some("error"), None).len(), 1);
        assert_eq!(bus.recent(10, None, Some("心跳")).len(), 1);
        assert_eq!(bus.recent(10, None, None).len(), 3);
    }

    #[test]
    fn subscriber_receives_events() {
        let bus = LogBus::new(64);
        let mut rx = bus.subscribe();
        bus.push(LogEvent {
            seq: 0,
            ts: "t".to_string(),
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: "hello".to_string(),
        });
        let got = rx.try_recv().expect("应当收到事件");
        assert_eq!(got.message, "hello");
    }
}
