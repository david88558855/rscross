//! 客户端日志采集：把 `WARN`/`ERROR` 事件暂存，供心跳循环批量上报。
//!
//! 只上报 `WARN` 及以上：`INFO`/`DEBUG` 在本地 stdout 已经足够，
//! 全量上报会把控制面的日志页淹掉，也浪费内网出口带宽。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::api::ClientLogEntry;

/// 线程安全的日志暂存区。
#[derive(Debug)]
pub struct LogSink {
    capacity: usize,
    entries: Mutex<VecDeque<ClientLogEntry>>,
}

impl LogSink {
    /// 创建暂存区。
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity: capacity.max(16),
            entries: Mutex::new(VecDeque::new()),
        })
    }

    /// 容量。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 写入一条（超容量丢弃最旧的）。
    pub fn push(&self, entry: ClientLogEntry) {
        let mut guard = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// 取走当前全部条目（上报后即清空）。
    pub fn drain(&self, max: usize) -> Vec<ClientLogEntry> {
        let mut guard = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let take = max.min(guard.len());
        guard.drain(..take).collect()
    }

    /// 当前积压条数。
    pub fn len(&self) -> usize {
        match self.entries.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 把 `tracing` 事件写入 [`LogSink`] 的 Layer。
#[derive(Debug, Clone)]
pub struct LogSinkLayer {
    sink: Arc<LogSink>,
}

impl LogSinkLayer {
    /// 用给定暂存区创建。
    pub fn new(sink: Arc<LogSink>) -> Self {
        Self { sink }
    }
}

impl<S> Layer<S> for LogSinkLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if *meta.level() > Level::WARN {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.sink.push(ClientLogEntry {
            level: meta.level().as_str().to_string(),
            message: visitor.finish(),
            target: Some(meta.target().to_string()),
        });
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
    extra: String,
}

impl MessageVisitor {
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

impl Visit for MessageVisitor {
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
    fn sink_drops_oldest_and_drains() {
        let sink = LogSink::new(16);
        for i in 0..20 {
            sink.push(ClientLogEntry {
                level: "WARN".to_string(),
                message: format!("m{i}"),
                target: None,
            });
        }
        assert_eq!(sink.len(), 16);

        let drained = sink.drain(10);
        assert_eq!(drained.len(), 10);
        assert_eq!(drained[0].message, "m4", "最旧的应当先被丢弃");
        assert_eq!(sink.len(), 6);

        let rest = sink.drain(100);
        assert_eq!(rest.len(), 6);
        assert!(sink.is_empty());
    }

    #[test]
    fn drain_more_than_available_is_safe() {
        let sink = LogSink::new(32);
        sink.push(ClientLogEntry {
            level: "ERROR".to_string(),
            message: "boom".to_string(),
            target: None,
        });
        assert_eq!(sink.drain(50).len(), 1);
        assert!(sink.drain(50).is_empty());
    }
}
