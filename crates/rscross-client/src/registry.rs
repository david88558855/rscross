//! 隧道服务注册表：管理 key -> agent 服务的映射

use std::sync::Arc;

use dashmap::DashMap;
use rscross_tunnel::AgentService;

/// 服务注册表
#[derive(Default)]
pub struct ServiceRegistry {
    services: DashMap<String, Arc<AgentService>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册服务
    pub fn set(&self, key: &str, svc: Arc<AgentService>) {
        // 同 key 旧服务先停
        if let Some(old) = self.services.get(key) {
            if !Arc::ptr_eq(old.value(), &svc) {
                old.value().stop();
            }
        }
        self.services.insert(key.to_string(), svc);
    }

    /// 取服务
    pub fn get(&self, key: &str) -> Option<Arc<AgentService>> {
        self.services.get(key).map(|e| e.value().clone())
    }

    /// 移除并停止
    pub fn del(&self, key: &str) -> Option<Arc<AgentService>> {
        let removed = self.services.remove(key).map(|(_, v)| v);
        if let Some(svc) = &removed {
            svc.stop();
        }
        removed
    }

    /// 移除记录但不停止服务
    pub fn remove(&self, key: &str) -> Option<Arc<AgentService>> {
        self.services.remove(key).map(|(_, v)| v)
    }

    /// 停止但保留记录
    pub fn stop(&self, key: &str) {
        if let Some(svc) = self.get(key) {
            svc.stop();
        }
    }

    pub fn len(&self) -> usize {
        self.services.len()
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// key 列表
    pub fn keys(&self) -> Vec<String> {
        self.services.iter().map(|e| e.key().clone()).collect()
    }

    /// 停止全部
    pub fn stop_all(&self) {
        for e in self.services.iter() {
            e.value().stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rscross_tunnel::ClientConfig;

    #[test]
    fn test_set_get_del() {
        let reg = ServiceRegistry::new();
        let svc = Arc::new(AgentService::new("k1", ClientConfig::default()));
        reg.set("k1", svc.clone());

        assert!(reg.get("k1").is_some());
        assert_eq!(reg.len(), 1);
        assert!(reg.get("k1").unwrap().is_running());

        reg.del("k1");
        assert!(reg.get("k1").is_none());
    }
}
