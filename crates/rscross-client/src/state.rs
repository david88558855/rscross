//! 全局状态存储：记录各隧道的运行状态与配置版本

use std::collections::HashMap;

use parking_lot::RwLock;
use std::time::Instant;

/// 隧道状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// 未运行
    Stopped,
    /// 运行中
    Running,
    /// 出错
    Error,
}

/// 隧道记录
#[derive(Debug, Clone)]
pub struct Record {
    /// 运行状态
    pub state: RunState,
    /// 配置版本标记，用于判断是否需要更新
    pub update_tag: String,
    /// 最近活跃时间
    pub last_active: Instant,
    /// 错误信息
    pub error: String,
}

/// 状态存储
#[derive(Default)]
pub struct StateStore {
    records: RwLock<HashMap<String, Record>>,
}

impl StateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 标记运行中
    pub fn set_running(&self, key: &str, update_tag: &str) {
        let mut m = self.records.write();
        m.insert(
            key.to_string(),
            Record {
                state: RunState::Running,
                update_tag: update_tag.to_string(),
                last_active: Instant::now(),
                error: String::new(),
            },
        );
    }

    /// 标记已停止
    pub fn set_stopped(&self, key: &str) {
        if let Some(r) = self.records.write().get_mut(key) {
            r.state = RunState::Stopped;
            r.last_active = Instant::now();
        }
    }

    /// 标记出错
    pub fn set_error(&self, key: &str, err: &str) {
        let mut m = self.records.write();
        m.insert(
            key.to_string(),
            Record {
                state: RunState::Error,
                update_tag: String::new(),
                last_active: Instant::now(),
                error: err.to_string(),
            },
        );
    }

    /// 是否运行中
    pub fn is_running(&self, key: &str) -> bool {
        self.records
            .read()
            .get(key)
            .map(|r| r.state == RunState::Running)
            .unwrap_or(false)
    }

    /// 取配置版本
    pub fn get_update_tag(&self, key: &str) -> Option<String> {
        self.records.read().get(key).map(|r| r.update_tag.clone())
    }

    /// 判断是否需要更新
    ///
    /// 语义与原项目 `checkUpdate` 一致：
    /// - 传入空版本号 -> 总是更新
    /// - 无历史记录 -> 总是更新
    /// - 版本号相同 -> 跳过
    pub fn need_update(&self, key: &str, update_tag: &str) -> bool {
        if update_tag.is_empty() {
            return true;
        }
        match self.get_update_tag(key) {
            Some(prev) => prev != update_tag,
            None => true,
        }
    }

    /// 记录配置更新
    pub fn mark_configured(&self, key: &str, update_tag: &str) {
        if let Some(r) = self.records.write().get_mut(key) {
            r.update_tag = update_tag.to_string();
            r.last_active = Instant::now();
        } else {
            self.set_running(key, update_tag);
        }
    }

    /// 移除记录
    pub fn remove(&self, key: &str) {
        self.records.write().remove(key);
    }

    /// 记录数
    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }

    /// 快照
    pub fn snapshot(&self) -> HashMap<String, RunState> {
        self.records
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.state))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_need_update_semantics() {
        let s = StateStore::new();
        // 无记录 -> 需要更新
        assert!(s.need_update("k", "v1"));
        // 配置后同版本 -> 不需更新
        s.mark_configured("k", "v1");
        assert!(!s.need_update("k", "v1"));
        // 版本变化 -> 需要更新
        assert!(s.need_update("k", "v2"));
        // 空版本号 -> 总是更新
        assert!(s.need_update("k", ""));
    }

    #[test]
    fn test_running_state() {
        let s = StateStore::new();
        assert!(!s.is_running("k"));
        s.set_running("k", "v1");
        assert!(s.is_running("k"));
        s.set_stopped("k");
        assert!(!s.is_running("k"));
    }

    #[test]
    fn test_error_state() {
        let s = StateStore::new();
        s.set_error("k", "boom");
        assert_eq!(s.snapshot().get("k"), Some(&RunState::Error));
    }
}
