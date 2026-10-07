//! 调度引擎：管理在线客户端/节点的 frp 服务实例，按需下发配置

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use rscross_frp::{ClientConfig, FrpcService, FrpsServer, ServiceRegistry};

use rscross_common::error::AppResult;

use crate::db::Database;

/// 引擎类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    /// 客户端引擎（内网客户端）
    Client,
    /// 节点引擎（公网节点，运行 frps）
    Node,
}

/// 引擎实例：封装一个在线实体
pub struct EngineInstance {
    pub kind: EngineKind,
    /// 实体编号
    pub code: String,
    /// frpc 服务（客户端模式）
    pub frpc: Option<Arc<FrpcService>>,
    /// frps 服务（节点模式）
    pub frps: Option<Arc<FrpsServer>>,
    /// 最近活跃时间
    pub last_active: std::time::Instant,
}

impl EngineInstance {
    pub fn is_running(&self) -> bool {
        match (&self.frpc, &self.frps) {
            (Some(s), _) => s.is_running(),
            (_, Some(s)) => s.is_running(),
            _ => false,
        }
    }

    pub fn touch(&mut self) {
        self.last_active = std::time::Instant::now();
    }
}

/// 引擎注册表
pub struct EngineRegistry {    /// 编号 -> 引擎实例
    instances: DashMap<String, Arc<parking_lot::Mutex<EngineInstance>>>,
    /// 按 key 查编号
    key_index: DashMap<String, String>,
    /// 全局 frpc 服务集合
    services: Arc<ServiceRegistry>,
    /// 传输层加密密钥
    secret: Arc<String>,
}

impl EngineRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            instances: DashMap::new(),
            key_index: DashMap::new(),
            services: Arc::new(ServiceRegistry::new()),
            secret: Arc::new(rscross_common::util::random_hex(16)),
        })
    }

    /// 注册客户端引擎
    pub fn register_client(&self, code: &str, key: &str, cfg: ClientConfig) -> Arc<FrpcService> {
        // 同编号旧实例先停掉
        if let Some(old) = self.instances.get(code) {
            let mut guard = old.lock();
            if let Some(s) = &guard.frpc {
                s.stop();
            }
            if let Some(s) = &guard.frps {
                s.stop();
            }
        }
        drop(self.instances.remove(code));

        let svc = FrpcService::new(code, cfg);
        self.services.set(code, svc.clone());
        self.instances.insert(
            code.to_string(),
            Arc::new(parking_lot::Mutex::new(EngineInstance {
                kind: EngineKind::Client,
                code: code.to_string(),
                frpc: Some(svc.clone()),
                frps: None,
                last_active: std::time::Instant::now(),
            })),
        );
        if !key.is_empty() {
            self.key_index.insert(key.to_string(), code.to_string());
        }
        svc
    }

    /// 注册节点引擎（frps）
    pub fn register_node(
        &self,
        code: &str,
        key: &str,
        cfg: rscross_frp::ServerConfig,
    ) -> Arc<FrpsServer> {
        if let Some(old) = self.instances.get(code) {
            let mut guard = old.lock();
            if let Some(s) = &guard.frps {
                s.stop();
            }
        }
        drop(self.instances.remove(code));

        let srv = FrpsServer::new(cfg, self.secret.as_ref().clone());
        self.instances.insert(
            code.to_string(),
            Arc::new(parking_lot::Mutex::new(EngineInstance {
                kind: EngineKind::Node,
                code: code.to_string(),
                frpc: None,
                frps: Some(srv.clone()),
                last_active: std::time::Instant::now(),
            })),
        );
        if !key.is_empty() {
            self.key_index.insert(key.to_string(), code.to_string());
        }
        srv
    }

    /// 按编号取引擎
    pub fn get(&self, code: &str) -> Option<Arc<parking_lot::Mutex<EngineInstance>>> {
        self.instances.get(code).map(|e| e.value().clone())
    }

    /// 按 key 查编号
    pub fn code_by_key(&self, key: &str) -> Option<String> {
        self.key_index.get(key).map(|e| e.value().clone())
    }

    /// 引擎是否在线
    pub fn is_running(&self, code: &str) -> bool {
        self.get(code)
            .map(|e| e.lock().is_running())
            .unwrap_or(false)
    }

    /// 取 frpc 服务
    pub fn frpc(&self, code: &str) -> Option<Arc<FrpcService>> {
        self.get(code).and_then(|e| e.lock().frpc.clone())
    }

    /// 取 frps 服务
    pub fn frps(&self, code: &str) -> Option<Arc<FrpsServer>> {
        self.get(code).and_then(|e| e.lock().frps.clone())
    }

    /// 列出所有在线编号
    pub fn online_codes(&self) -> Vec<String> {
        self.instances
            .iter()
            .filter(|e| e.value().lock().is_running())
            .map(|e| e.key().clone())
            .collect()
    }

    /// 停止某个引擎
    pub fn stop(&self, code: &str, _msg: &str) {
        if let Some(inst) = self.get(code) {
            let mut guard = inst.lock();
            if let Some(s) = &guard.frpc {
                s.stop();
            }
            if let Some(s) = &guard.frps {
                s.stop();
            }
        }
        self.services.del(code);
    }

    /// 移除引擎
    pub fn remove(&self, code: &str) {
        self.stop(code, "");
        self.instances.remove(code);
    }

    /// 服务数量
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// 密钥索引快照
    pub fn key_snapshot(&self) -> HashMap<String, String> {
        self.key_index
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// 从数据库同步所有节点/客户端引擎状态
    pub async fn sync_all(&self, db: &Arc<Database>) {
        // 同步在线状态到数据库
        if let Some(pool) = db.sqlite_pool() {
            let online = self.online_codes();
            for code in &online {
                let _ = sqlx::query(
                    "UPDATE gost_clients SET status = 1 WHERE code = ? AND status != 1",
                )
                .bind(code)
                .execute(pool)
                .await;
            }
        }
        tracing::info!("引擎注册表初始化完成，在线实例 {} 个", self.len());
    }

    /// 校验配置
    pub fn validate(&self) -> AppResult<()> {
        Ok(())
    }
}

impl EngineRegistry {
    /// 批量停止
    pub fn stop_all(&self) {
        for code in self.online_codes() {
            self.stop(&code, "服务停止");
        }
    }
}

/// 引擎配置构造辅助
pub fn build_client_config(
    auth_token: &str,
    server_addr: &str,
    server_port: u16,
    pool_count: i32,
    metadatas: HashMap<String, String>,
) -> ClientConfig {
    ClientConfig {
        auth_token: auth_token.to_string(),
        server_addr: server_addr.to_string(),
        server_port,
        pool_count,
        metadatas,
        ..Default::default()
    }
}

/// 限速字符串构造
pub fn limiter_string(limiter_kb: i32) -> String {
    if limiter_kb <= 0 {
        String::new()
    } else {
        format!("{}KB", limiter_kb * 128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_lookup() {
        let reg = EngineRegistry::new();
        let cfg = build_client_config("key1", "127.0.0.1", 7000, 5, HashMap::new());
        reg.register_client("c1", "key1", cfg);

        assert!(reg.frpc("c1").is_some());
        assert_eq!(reg.code_by_key("key1"), Some("c1".to_string()));
        assert_eq!(reg.len(), 1);
    }

    #[tokio::test]
    async fn test_stop_removes() {
        let reg = EngineRegistry::new();
        let cfg = build_client_config("k", "127.0.0.1", 7000, 1, HashMap::new());
        reg.register_client("c1", "k", cfg);
        reg.stop("c1", "test");
        assert!(!reg.frpc("c1").unwrap().is_running());
    }

    #[test]
    fn test_limiter_string() {
        assert_eq!(limiter_string(0), "");
        assert_eq!(limiter_string(1), "128KB");
        assert_eq!(limiter_string(10), "1280KB");
    }
}
