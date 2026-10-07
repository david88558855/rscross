//! tunnel 节点服务 服务端：运行在公网节点，处理控制流、代理注册与流量分发

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::ServerConfig;
use crate::msg::{self, msg_type, CloseProxy, CloseProxyResp, Envelope, Login, LoginResp,
                 NewProxy, NewProxyResp, NewWorkConn, NewWorkConnResp, Ping, Pong,
                 ProxyConfigMsg};
use crate::proxy::ProxyRegistry;
use crate::transport::TrafficCounter;

/// 已登录的客户端会话
pub struct ClientSession {
    /// 会话编号（由登录令牌派生）
    pub login_id: String,
    /// 控制流写通道
    pub tx: mpsc::UnboundedSender<Envelope>,
    /// 待用工作连接池（供 NewWorkConn 响应时下发）
    pub work_conn_waiters: Arc<DashMap<String, mpsc::UnboundedSender<TcpStream>>>,
    /// 该客户端注册的代理名集合
    pub proxies: RwLock<std::collections::HashSet<String>>,
    /// 流量统计
    pub traffic: Arc<TrafficCounter>,
    /// 最后心跳时间
    pub last_seen: std::sync::Mutex<std::time::Instant>,
    /// 认证用户名
    pub username: String,
}

impl ClientSession {
    pub fn touch(&self) {
        if let Ok(mut t) = self.last_seen.lock() {
            *t = std::time::Instant::now();
        }
    }

    pub fn is_alive(&self, timeout: Duration) -> bool {
        self.last_seen
            .lock()
            .map(|t| t.elapsed() < timeout)
            .unwrap_or(false)
    }
}

/// tunnel 节点服务 服务端
pub struct HubServer {
    pub config: ServerConfig,
    /// 代理注册表
    pub registry: Arc<ProxyRegistry>,
    /// 客户端会话表
    pub sessions: Arc<DashMap<String, Arc<ClientSession>>>,
    /// 远程端口 -> 代理名
    pub port_index: Arc<DashMap<u16, String>>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 监听器地址
    bind_addr: RwLock<Option<SocketAddr>>,
    /// 待建立的工作连接（NewWorkConn 触发后客户端回连）
    pending_work_conns: Arc<DashMap<String, mpsc::UnboundedSender<TcpStream>>>,
    /// 传输层加密密钥
    secret: Arc<String>,
}

impl HubServer {
    pub fn new(config: ServerConfig, secret: String) -> Arc<Self> {
        let registry = Arc::new(ProxyRegistry::new());
        let srv = Arc::new(Self {
            registry,
            sessions: Arc::new(DashMap::new()),
            port_index: Arc::new(DashMap::new()),
            running: Arc::new(AtomicBool::new(true)),
            bind_addr: RwLock::new(None),
            pending_work_conns: Arc::new(DashMap::new()),
            secret: Arc::new(secret),
            config,
        });

        // 启动 vhost 监听（HTTP 域名分发）
        if srv.config.vhost_http_port > 0 {
            let s = srv.clone();
            tokio::spawn(async move {
                s.run_vhost().await;
            });
        }

        // 启动心跳监控
        let s = srv.clone();
        tokio::spawn(async move {
            s.monitor_sessions().await;
        });

        srv
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        *self.bind_addr.read()
    }

    /// 启动控制流监听，阻塞直到停止
    pub async fn serve(self: Arc<Self>) -> Result<(), String> {
        self.config
            .validate()
            .map_err(|e| format!("服务端配置错误: {e}"))?;

        let addr = format!("{}:{}", self.config.bind_addr, self.config.bind_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("监听 {addr} 失败: {e}"))?;
        let local = listener
            .local_addr()
            .map_err(|e| format!("获取监听地址失败: {e}"))?;
        *self.bind_addr.write() = Some(local);
        tracing::info!("tunnel 节点服务 控制流监听于 {local}");

        loop {
            if !self.is_running() {
                break;
            }
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let s = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = s.handle_conn(stream, peer).await {
                                    tracing::debug!(%peer, error = %e, "连接处理结束");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept 失败");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
        Ok(())
    }

    /// 处理一条新连接
    async fn handle_conn(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) -> Result<(), String> {
        // 首包必须是登录请求
        let login = match msg::read_message(&mut &stream).await? {
            Some(env) if env.msg_type == msg_type::LOGIN => {
                let l: Login = env.parse()?;
                l
            }
            Some(_) => return Err("首个消息必须是 login".to_string()),
            None => return Err("连接在登录前关闭".to_string()),
        };

        // 校验令牌
        if !self.config.auth_token.is_empty() && login.token != self.config.auth_token {
            let resp = Envelope::new(
                msg_type::LOGIN_RESP,
                serde_json::to_value(LoginResp {
                    success: false,
                    reason: "认证失败，令牌不匹配".to_string(),
                })
                .unwrap(),
            );
            let mut s = &stream;
            let _ = msg::write_message(&mut s, &resp).await;
            return Err("认证失败".to_string());
        }

        let login_id = if login.token.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            login.token.clone()
        };

        let (tx, rx) = mpsc::unbounded_channel();
        let work_conn_waiters = Arc::new(DashMap::new());
        let session = Arc::new(ClientSession {
            login_id: login_id.clone(),
            tx: tx.clone(),
            work_conn_waiters: work_conn_waiters.clone(),
            proxies: RwLock::new(std::collections::HashSet::new()),
            traffic: Arc::new(TrafficCounter::new()),
            last_seen: std::sync::Mutex::new(std::time::Instant::now()),
            username: login.user(),
        });

        // 踢掉同 ID 的旧连接
        if let Some(old) = self.sessions.get(&login_id) {
            tracing::info!(login_id, "客户端重复连接，断开旧连接");
            let _ = old.tx.send(Envelope::bare("__kick__"));
            drop(old);
            self.sessions.remove(&login_id);
        }
        self.sessions.insert(login_id.clone(), session.clone());

        let resp = Envelope::new(
            msg_type::LOGIN_RESP,
            serde_json::to_value(LoginResp {
                success: true,
                reason: String::new(),
            })
            .unwrap(),
        );
        let mut w = &stream;
        msg::write_message(&mut w, &resp)
            .await
            .map_err(|e| e.to_string())?;

        tracing::info!(login_id, username = %session.username, "客户端已登录");

        // 会话主循环
        let result = self.session_loop(&stream, session.clone()).await;

        // 清理：注销该客户端的所有代理
        let proxy_names: Vec<String> = session.proxies.read().iter().cloned().collect();
        for name in proxy_names {
            self.remove_proxy(&name);
        }
        self.sessions.remove(&login_id);
        tracing::info!(login_id, "客户端已断开");

        result
    }

    /// 会话消息处理循环
    async fn session_loop(
        &self,
        stream: &TcpStream,
        session: Arc<ClientSession>,
    ) -> Result<(), String> {
        // 主动下发消息的写循环：消费 session.tx
        let (mut writer, mut writer_rx) = tokio::io::split(stream);
        let writer_task = tokio::spawn(async move {
            while let Some(env) = writer_rx.recv().await {
                if msg::write_message(&mut writer, &env).await.is_err() {
                    break;
                }
            }
        });

        let mut reader = stream;
        let heartbeat_interval = (self.config.heartbeat_timeout / 2).max(1);

        loop {
            if !self.is_running() {
                break;
            }
            if !session.is_alive(Duration::from_secs(self.config.heartbeat_timeout as u64)) {
                tracing::info!(login_id = %session.login_id, "心跳超时，断开连接");
                break;
            }

            tokio::select! {
                msg = msg::read_message(&mut reader) => {
                    match msg {
                        Ok(Some(env)) => {
                            session.touch();
                            self.handle_client_msg(env, &session).await;
                        }
                        Ok(None) => break, // 对端关闭
                        Err(e) => {
                            tracing::debug!(error = %e, "读取客户端消息失败");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(heartbeat_interval as u64)) => {
                    // 主动发心跳探测
                    session.touch();
                }
            }
        }

        // 关闭会话通道，写循环随之退出
        writer_task.abort();
        let _ = writer_task.await;
        Ok(())
    }

    /// 处理客户端上行的控制消息
    async fn handle_client_msg(&self, env: Envelope, session: &Arc<ClientSession>) {
        match env.msg_type.as_str() {
            msg_type::NEW_PROXY => {
                let np: NewProxy = match env.parse() {
                    Ok(v) => v,
                    Err(e) => {
                        self.reply_error(session, msg_type::NEW_PROXY_RESP, &e);
                        return;
                    }
                };
                self.handle_new_proxy(np.config, session).await;
            }
            msg_type::CLOSE_PROXY => {
                if let Ok(cp) = env.parse::<CloseProxy>() {
                    self.remove_proxy(&cp.proxy_name);
                    self.reply(
                        session,
                        msg_type::CLOSE_PROXY_RESP,
                        CloseProxyResp {
                            success: true,
                            reason: String::new(),
                        },
                    );
                }
            }
            msg_type::PONG => {}
            _ => {
                tracing::debug!(msg_type = %env.msg_type, "未识别的客户端消息");
            }
        }
    }

    /// 处理新代理注册
    async fn handle_new_proxy(&self, cfg: ProxyConfigMsg, session: &Arc<ClientSession>) {
        // 基础校验
        if cfg.name.is_empty() {
            self.reply_error(session, msg_type::NEW_PROXY_RESP, "代理名不能为空");
            return;
        }

        // 域名型代理校验
        if let Some(pt) = cfg.proxy_type_enum() {
            if pt.is_vhost() && cfg.custom_domains.is_empty() {
                self.reply_error(
                    session,
                    msg_type::NEW_PROXY_RESP,
                    "HTTP 代理必须指定自定义域名",
                );
                return;
            }
        }

        let mut assigned_port = cfg.remote_port;

        // TCP/UDP 需要抢占远程端口
        if let Some(pt) = cfg.proxy_type_enum() {
            if !pt.is_vhost() && !matches!(pt, crate::ProxyType::Stcp | crate::ProxyType::Xtcp) {
                if assigned_port == 0 {
                    match self.alloc_port() {
                        Some(p) => assigned_port = p,
                        None => {
                            self.reply_error(
                                session,
                                msg_type::NEW_PROXY_RESP,
                                "没有可用端口",
                            );
                            return;
                        }
                    }
                } else if self.port_index.contains_key(&assigned_port) {
                    self.reply_error(
                        session,
                        msg_type::NEW_PROXY_RESP,
                        &format!("端口 {assigned_port} 已被占用"),
                    );
                    return;
                }
            }
        }

        // 同名代理覆盖：先注销旧的
        if self.registry.contains(&cfg.name) {
            tracing::info!(name = %cfg.name, "代理已存在，先注销旧配置");
            self.remove_proxy(&cfg.name);
        }

        let entry = self.registry.register(cfg.name.clone(), session.login_id.clone(), &cfg);
        if entry.is_err() {
            self.reply_error(
                session,
                msg_type::NEW_PROXY_RESP,
                &format!("注册代理失败: {}", entry.err().unwrap()),
            );
            return;
        }
        session.proxies.write().insert(cfg.name.clone());

        // TCP/UDP 监听远程端口
        if assigned_port > 0 {
            if let Some(pt) = cfg.proxy_type_enum() {
                if !pt.is_vhost() && !matches!(pt, crate::ProxyType::Stcp | crate::ProxyType::Xtcp) {
                    self.port_index.insert(assigned_port, cfg.name.clone());
                    let s = self.clone();
                    let name = cfg.name.clone();
                    tokio::spawn(async move {
                        s.listen_remote_port(assigned_port, name).await;
                    });
                }
            }
        }

        tracing::info!(name = %cfg.name, port = assigned_port, type = %cfg.proxy_type, "代理注册成功");
        self.reply(
            session,
            msg_type::NEW_PROXY_RESP,
            NewProxyResp {
                success: true,
                reason: String::new(),
                remote_port: assigned_port,
            },
        );
    }

    /// 监听远程端口并转发流量
    async fn listen_remote_port(self: Arc<Self>, port: u16, proxy_name: String) {
        let addr = format!("0.0.0.0:{port}");
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port, error = %e, "远程端口监听失败");
                self.port_index.remove(&port);
                return;
            }
        };
        tracing::info!(port, proxy = %proxy_name, "远程端口已监听");

        loop {
            if !self.is_running() || !self.registry.contains(&proxy_name) {
                break;
            }
            tokio::select! {
                res = listener.accept() => {
                    let Ok((inbound, peer)) = res else { continue };
                    let s = self.clone();
                    let name = proxy_name.clone();
                    tokio::spawn(async move {
                        s.handle_inbound(inbound, peer, name).await;
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
        tracing::info!(port, proxy = %proxy_name, "远程端口监听结束");
    }

    /// 处理入站流量：向客户端请求工作连接并转发
    async fn handle_inbound(
        self: Arc<Self>,
        mut inbound: TcpStream,
        peer: SocketAddr,
        proxy_name: String,
    ) {
        let Some(entry) = self.registry.get(&proxy_name) else {
            tracing::warn!(proxy = %proxy_name, "入站流量：代理不存在");
            return;
        };

        let Some(session) = self.sessions.get(&entry.login_id).map(|s| s.clone()) else {
            tracing::warn!(proxy = %proxy_name, "入站流量：客户端不在线");
            return;
        };

        let Some(cfg) = entry.config() else {
            return;
        };

        // 申请一条工作连接
        let conn_id = uuid::Uuid::new_v4().to_string();
        let (work_tx, mut work_rx) = mpsc::unbounded_channel();
        session
            .work_conn_waiters
            .insert(conn_id.clone(), work_tx);

        let req = Envelope::new(
            msg_type::NEW_WORK_CONN,
            serde_json::to_value(NewWorkConn {
                proxy_name: proxy_name.clone(),
                conn_id: conn_id.clone(),
            })
            .unwrap(),
        );
        if session.tx.send(req).is_err() {
            session.work_conn_waiters.remove(&conn_id);
            return;
        }

        // 等待客户端回连（超时 10 秒）
        let work = tokio::time::timeout(Duration::from_secs(10), work_rx.recv()).await;
        let Ok(Some(mut work_stream)) = work else {
            session.work_conn_waiters.remove(&conn_id);
            tracing::debug!(proxy = %proxy_name, "等待工作连接超时");
            return;
        };
        session.work_conn_waiters.remove(&conn_id);

        tracing::debug!(proxy = %proxy_name, %peer, "工作连接就绪，开始转发");

        // 限速
        let limit = crate::transport::limit_from_transport(&cfg.transport);
        let counter = session.traffic.clone();

        let _ = crate::transport::relay_bidirectional(
            &mut work_stream,
            &mut inbound,
            limit,
            Some(Arc::new(move |n: u64| {
                counter.add_output(n);
            })),
        )
        .await;
    }

    /// 接受客户端回连的工作连接
    pub fn accept_work_conn(&self, login_id: &str, conn_id: &str, stream: TcpStream) -> bool {
        let Some(session) = self.sessions.get(login_id) else {
            return false;
        };
        if let Some((_, tx)) = session.work_conn_waiters.remove(conn_id) {
            return tx.send(stream).is_ok();
        }
        false
    }

    /// 注销代理
    pub fn remove_proxy(&self, name: &str) {
        if let Some(removed) = self.registry.remove(name) {
            if let Some(cfg) = removed.config() {
                if cfg.remote_port > 0 {
                    self.port_index.remove(&cfg.remote_port);
                }
            }
            // 从会话中摘除
            if let Some(session) = self.sessions.get(&removed.login_id) {
                session.proxies.write().remove(name);
            }
            tracing::info!(name, "代理已注销");
        }
    }

    /// 分配一个空闲端口
    fn alloc_port(&self) -> Option<u16> {
        // 从 20000-60000 范围扫描
        for port in 20000..60000u16 {
            if !self.port_index.contains_key(&port) {
                // 确认系统层面可绑定
                if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() {
                    return Some(port);
                }
            }
        }
        None
    }

    /// 心跳监控：清理超时会话
    async fn monitor_sessions(self: Arc<Self>) {
        let timeout = Duration::from_secs(self.config.heartbeat_timeout.max(10) as u64);
        loop {
            if !self.is_running() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;

            let dead: Vec<String> = self
                .sessions
                .iter()
                .filter(|e| !e.value().is_alive(timeout))
                .map(|e| e.key().clone())
                .collect();

            for id in dead {
                tracing::info!(login_id = %id, "清理超时会话");
                if let Some((_, session)) = self.sessions.remove(&id) {
                    let names: Vec<String> = session.proxies.read().iter().cloned().collect();
                    for n in names {
                        self.remove_proxy(&n);
                    }
                }
            }
        }
    }

    /// vhost HTTP 分发（占位，实现在 vhost 模块）
    async fn run_vhost(self: Arc<Self>) {
        let port = self.config.vhost_http_port;
        let addr = format!("0.0.0.0:{port}");
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port, error = %e, "vhost 监听失败");
                return;
            }
        };
        tracing::info!("vhost HTTP 监听于 {addr}");

        let sub_host = self.config.sub_domain_host.clone();
        loop {
            if !self.is_running() {
                break;
            }
            tokio::select! {
                res = listener.accept() => {
                    let Ok((stream, peer)) = res else { continue };
                    let s = self.clone();
                    let sub = sub_host.clone();
                    tokio::spawn(async move {
                        s.registry.resolve_http(stream, &sub).await;
                        let _ = peer;
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
    }

    /// 向会话发送响应
    fn reply<T: serde::Serialize>(&self, session: &Arc<ClientSession>, msg_type: &str, data: T) {
        let env = Envelope::new(msg_type, serde_json::to_value(data).unwrap());
        let _ = session.tx.send(env);
    }

    fn reply_error(&self, session: &Arc<ClientSession>, msg_type: &str, reason: &str) {
        let resp = match msg_type {
            msg_type::NEW_PROXY_RESP => NewProxyResp {
                success: false,
                reason: reason.to_string(),
                remote_port: 0,
            },
            _ => CloseProxyResp {
                success: false,
                reason: reason.to_string(),
            },
        };
        self.reply(session, msg_type, resp);
    }
}

/// 读取对端地址字符串
pub async fn peer_addr(stream: &TcpStream) -> Option<SocketAddr> {
    stream.peer_addr().ok()
}

/// 消费 incoming 并回写 pong（工具函数）
pub async fn handle_pong(stream: &mut TcpStream, ping: Ping) -> Result<(), String> {
    let env = Envelope::new(
        msg_type::PONG,
        serde_json::to_value(Pong {
            interval: ping.interval,
        })
        .unwrap(),
    );
    msg::write_message(stream, &env).await
}

/// 便捷类型别名
pub type SharedServer = Arc<HubServer>;

/// 生成服务端配置 JSON，便于调试输出
pub fn server_config_to_json(cfg: &ServerConfig) -> String {
    serde_json::to_string_pretty(cfg).unwrap_or_default()
}

/// 工作连接响应构造
pub fn new_work_conn_resp(conn_id: &str) -> NewWorkConnResp {
    NewWorkConnResp {
        conn_id: conn_id.to_string(),
        success: true,
        reason: String::new(),
    }
}

/// 从流中读取固定长度数据
pub async fn read_exact_n(stream: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// 立即关闭流
pub fn close_stream(stream: &TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// 生成 map 快照
pub fn sessions_snapshot(sessions: &DashMap<String, Arc<ClientSession>>) -> HashMap<String, usize> {
    sessions
        .iter()
        .map(|e| (e.key().clone(), e.value().proxies.read().len()))
        .collect()
}
