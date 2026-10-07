//! 客户端代理：运行在内网机器，注册代理并建立工作连接转发流量

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::ClientConfig;
use crate::msg::{self, msg_type, CloseProxy, Envelope, Login, LoginResp, NewProxy,
                 NewProxyResp, NewWorkConn, Ping, Pong, ProxyConfigMsg};
use crate::transport::TrafficCounter;
use crate::ProxyType;

/// AgentService 实例：管理一组代理，共享一条到服务端的控制连接
pub struct AgentService {
    /// 服务编号（隧道 key）
    pub key: String,
    /// 客户端配置
    pub config: ClientConfig,
    /// 已注册的代理
    proxies: RwLock<HashMap<String, ProxyConfigMsg>>,
    /// 待用工作连接
    pending_work: RwLock<HashMap<String, TcpStream>>,
    /// 工作连接分配器
    work_seq: AtomicU64,
    /// 控制流写通道
    control_tx: RwLock<Option<mpsc::UnboundedSender<Envelope>>>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 流量统计
    pub traffic: Arc<TrafficCounter>,
    /// 状态变更回调（供上层感知）
    on_change: RwLock<Option<Arc<dyn Fn(&str) + Send + Sync>>>,
}

impl AgentService {
    pub fn new(key: &str, config: ClientConfig) -> Arc<Self> {
        Arc::new(Self {
            key: key.to_string(),
            config,
            proxies: RwLock::new(HashMap::new()),
            pending_work: RwLock::new(HashMap::new()),
            work_seq: AtomicU64::new(0),
            control_tx: RwLock::new(None),
            running: Arc::new(AtomicBool::new(true)),
            traffic: Arc::new(TrafficCounter::new()),
            on_change: RwLock::new(None()),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(tx) = self.control_tx.read().clone() {
            for name in self.proxies.read().keys() {
                let env = Envelope::new(
                    msg_type::CLOSE_PROXY,
                    serde_json::to_value(CloseProxy {
                        proxy_name: name.clone(),
                    })
                    .unwrap(),
                );
                let _ = tx.send(env);
            }
        }
        self.proxies.write().clear();
    }

    /// 设置状态变更回调
    pub fn on_change<F>(&self, f: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        *self.on_change.write() = Some(Arc::new(f));
    }

    /// 注册一个代理
    pub async fn add_proxy(&self, cfg: ProxyConfigMsg) -> Result<(), String> {
        if !self.is_running() {
            return Err("服务未运行".to_string());
        }

        // 登录后才有控制通道
        let Some(tx) = self.control_tx.read().clone() else {
            return Err("控制连接未建立".to_string());
        };

        // 先关闭旧的同名代理
        if self.proxies.read().contains_key(&cfg.name) {
            let _ = self.remove_proxy(&cfg.name).await;
        }

        let env = Envelope::new(
            msg_type::NEW_PROXY,
            serde_json::to_value(NewProxy { config: cfg.clone() }).unwrap(),
        );
        tx.send(env).map_err(|_| "发送代理配置失败".to_string())?;

        // 等待服务端确认（简化：直接记录，实际由服务端回执驱动）
        self.proxies.write().insert(cfg.name.clone(), cfg);
        if let Some(cb) = self.on_change.read().as_ref() {
            cb(&format!("proxy_added:{}", self.key));
        }
        Ok(())
    }

    /// 移除一个代理
    pub async fn remove_proxy(&self, name: &str) -> Result<(), String> {
        self.proxies.write().remove(name);
        if let Some(tx) = self.control_tx.read().clone() {
            let env = Envelope::new(
                msg_type::CLOSE_PROXY,
                serde_json::to_value(CloseProxy {
                    proxy_name: name.to_string(),
                })
                .unwrap(),
            );
            let _ = tx.send(env);
        }
        if let Some(cb) = self.on_change.read().as_ref() {
            cb(&format!("proxy_removed:{}", self.key));
        }
        Ok(())
    }

    /// 已注册代理名列表
    pub fn proxy_names(&self) -> Vec<String> {
        self.proxies.read().keys().cloned().collect()
    }

    /// 启动客户端循环：连接服务端、登录、心跳、处理工作连接
    pub async fn run(self: Arc<Self>) -> Result<(), String> {
        let addr = self.config.control_addr();
        let mut backoff = Duration::from_secs(1);

        while self.is_running() {
            match self.connect_once(&addr).await {
                Ok(()) => {
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::warn!(%addr, error = %e, "客户端连接失败，准备重试");
                }
            }

            if !self.is_running() {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
        Ok(())
    }

    /// 单次连接会话
    async fn connect_once(self: Arc<Self>, addr: &str) -> Result<(), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("连接 {addr} 失败: {e}"))?;
        let _ = stream.set_nodelay(true);

        let (mut writer, mut reader) = stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Envelope>();
        *self.control_tx.write() = Some(tx.clone());

        // 写循环
        let writer_task = tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                if msg::write_message(&mut writer, &env).await.is_err() {
                    break;
                }
            }
        });

        // 登录
        let login = Login {
            token: self.config.auth_token.clone(),
            version: crate::PROTOCOL_VERSION.to_string(),
            pool_count: self.config.pool_count,
            metadatas: self.config.metadatas.clone(),
            hostname: hostname(),
        };
        msg::write_message(
            &mut writer,
            &Envelope::new(msg_type::LOGIN, serde_json::to_value(login).unwrap()),
        )
        .await?;

        // 等待登录响应
        let env = msg::read_message(&mut reader)
            .await?
            .ok_or_else(|| "登录期间连接关闭".to_string())?;
        if env.msg_type != msg_type::LOGIN_RESP {
            return Err(format!("意外的登录响应: {}", env.msg_type));
        }
        let resp: LoginResp = env.parse()?;
        if !resp.success {
            return Err(format!("登录失败: {}", resp.reason));
        }
        tracing::info!(key = %self.key, "客户端登录成功");

        // 重新注册所有代理
        let names: Vec<ProxyConfigMsg> = self.proxies.read().values().cloned().collect();
        for cfg in names {
            let env = Envelope::new(
                msg_type::NEW_PROXY,
                serde_json::to_value(NewProxy { config: cfg }).unwrap(),
            );
            let _ = tx.send(env);
        }

        // 心跳间隔
        let interval = self.config.heartbeat_interval.max(5) as u64;

        // 主循环
        loop {
            if !self.is_running() {
                break;
            }
            tokio::select! {
                res = msg::read_message(&mut reader) => {
                    match res {
                        Ok(Some(env)) => {
                            self.handle_server_msg(env).await;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::debug!(error = %e, "读取服务端消息失败");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    let env = Envelope::new(
                        msg_type::PING,
                        serde_json::to_value(Ping { interval: interval as i64 }).unwrap(),
                    );
                    let _ = tx.send(env);
                }
            }
        }

        // 清理
        *self.control_tx.write() = None;
        self.pending_work.write().clear();
        writer_task.abort();
        let _ = writer_task.await;
        tracing::info!(key = %self.key, "客户端连接断开");
        Ok(())
    }

    /// 处理服务端下行消息
    async fn handle_server_msg(self: &Arc<Self>, env: Envelope) {
        match env.msg_type.as_str() {
            msg_type::NEW_WORK_CONN => {
                let Ok(req) = env.parse::<NewWorkConn>() else {
                    return;
                };
                self.handle_new_work_conn(req).await;
            }
            msg_type::PING => {
                // 回 pong
                if let Ok(p) = env.parse::<Ping>() {
                    if let Some(tx) = self.control_tx.read().clone() {
                        let _ = tx.send(Envelope::new(
                            msg_type::PONG,
                            serde_json::to_value(Pong { interval: p.interval }).unwrap(),
                        ));
                    }
                }
            }
            msg_type::NEW_PROXY_RESP => {
                if let Ok(r) = env.parse::<NewProxyResp>() {
                    if !r.success {
                        tracing::error!(reason = %r.reason, "代理注册被服务端拒绝");
                    }
                }
            }
            msg_type::CLOSE_PROXY_RESP => {
                if let Ok(r) = env.parse::<crate::msg::CloseProxyResp>() {
                    if !r.success {
                        tracing::error!(reason = %r.reason, "关闭代理失败");
                    }
                }
            }
            _ => {}
        }
    }

    /// 处理新工作连接请求：连接本地服务并回传
    async fn handle_new_work_conn(self: &Arc<Self>, req: NewWorkConn) {
        let Some(cfg) = self.proxies.read().get(&req.proxy_name).cloned() else {
            tracing::warn!(proxy = %req.proxy_name, "收到工作连接请求但代理不存在");
            return;
        };

        // UDP 类型走独立处理
        if let Some(pt) = cfg.proxy_type_enum() {
            if pt.is_udp() {
                self.handle_udp_work_conn(&cfg).await;
                return;
            }
        }

        // 连接本地服务
        let local = format!("{}:{}", cfg.local_ip, cfg.local_port);
        let mut local_stream = match TcpStream::connect(&local).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(local, error = %e, "连接本地服务失败");
                return;
            }
        };
        let _ = local_stream.set_nodelay(true);

        // 携带 conn_id 回连服务端
        let Some(addr) = self.server_addr() else {
            return;
        };
        let mut back = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(%addr, error = %e, "回连服务端失败");
                return;
            }
        };

        // 发送 conn_id 标识（8 字节长度 + 消息）
        let resp = Envelope::new(
            msg_type::NEW_WORK_CONN_RESP,
            serde_json::to_value(crate::msg::NewWorkConnResp {
                conn_id: req.conn_id.clone(),
                success: true,
                reason: String::new(),
            })
            .unwrap(),
        );
        if msg::write_message(&mut back, &resp).await.is_err() {
            return;
        }

        // 开始转发
        let limit = cfg.transport.bandwidth_bytes();
        let counter = self.traffic.clone();
        tracing::debug!(proxy = %req.proxy_name, "工作连接建立，开始转发");

        let _ = crate::transport::relay_bidirectional(
            &mut back,
            &mut local_stream,
            limit,
            Some(Arc::new(move |n: u64| {
                counter.add_output(n);
            })),
        )
        .await;
    }

    /// UDP 工作连接
    async fn handle_udp_work_conn(self: &Arc<Self>, cfg: &ProxyConfigMsg) {
        let local = format!("{}:{}", cfg.local_ip, cfg.local_port);
        let Ok(local_socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            tracing::error!("UDP 本地套接字创建失败");
            return;
        };
        let Ok(remote_socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            tracing::error!("UDP 远端套接字创建失败");
            return;
        };

        // 解析本地地址
        let Ok(local_addr) = local_socket.connect(&local.parse().unwrap_or_else(|_| {
            "127.0.0.1:0".parse().unwrap()
        })) else {
            tracing::error!("UDP 连接本地服务失败: {local}");
            return;
        };
        let _ = local_addr;
        let _ = cfg;
        // UDP 转发循环在真实场景中按需启动；此处保留接口
    }

    /// 服务端地址
    fn server_addr(&self) -> Option<String> {
        if self.config.server_addr.is_empty() {
            None
        } else {
            Some(self.config.control_addr())
        }
    }
}

/// 获取本机主机名
pub fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
}

/// 生成代理名
pub fn make_proxy_name(code: &str, suffix: &str) -> String {
    format!("{code}_{suffix}")
}

/// 依据类型构造默认代理配置
pub fn default_proxy_config(name: &str, pt: ProxyType, local_ip: &str, local_port: u16) -> ProxyConfigMsg {
    ProxyConfigMsg {
        name: name.to_string(),
        proxy_type: pt.as_str().to_string(),
        auth_token: String::new(),
        local_ip: local_ip.to_string(),
        local_port,
        remote_port: 0,
        custom_domains: vec![],
        secret_key: String::new(),
        load_balancer_group: String::new(),
        transport: Default::default(),
        metadatas: Default::default(),
    }
}

/// 发送一条控制流消息
pub async fn send_control(stream: &mut TcpStream, env: &Envelope) -> Result<(), String> {
    msg::write_message(stream, env).await
}

/// 从流中读取控制流消息
pub async fn recv_control(stream: &mut TcpStream) -> Result<Option<Envelope>, String> {
    msg::read_message(stream).await
}

/// 直接写入流
pub async fn write_all(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(data).await
}

/// 类型别名
pub type SharedService = Arc<AgentService>;

/// 服务集合：按 key 管理多个客户端实例
#[derive(Default)]
pub struct ServiceRegistry {
    services: dashmap::DashMap<String, SharedService>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, key: &str, svc: SharedService) {
        self.services.insert(key.to_string(), svc);
    }

    pub fn get(&self, key: &str) -> Option<SharedService> {
        self.services.get(key).map(|e| e.value().clone())
    }

    pub fn del(&self, key: &str) -> Option<SharedService> {
        self.services.remove(key).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.services.len()
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// 停止全部服务
    pub fn stop_all(&self) {
        for e in self.services.iter() {
            e.value().stop();
        }
        self.services.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_registry() {
        let reg = ServiceRegistry::new();
        let svc = AgentService::new("k1", ClientConfig::default());
        reg.set("k1", svc);
        assert!(reg.get("k1").is_some());
        assert_eq!(reg.len(), 1);
        reg.del("k1");
        assert!(reg.is_empty());
    }

    #[test]
    fn test_default_proxy_config() {
        let c = default_proxy_config("p1", ProxyType::Tcp, "127.0.0.1", 8080);
        assert_eq!(c.name, "p1");
        assert_eq!(c.proxy_type, "tcp");
        assert_eq!(c.local_port, 8080);
    }

    #[test]
    fn test_make_proxy_name() {
        assert_eq!(make_proxy_name("abc", "http"), "abc_http");
    }

    #[tokio::test]
    async fn test_add_proxy_without_control_fails() {
        let svc = AgentService::new("k1", ClientConfig::default());
        let cfg = default_proxy_config("p1", ProxyType::Tcp, "127.0.0.1", 80);
        assert!(svc.add_proxy(cfg).await.is_err());
    }
}
