//! 节点侧隧道分发：把公网流量投递给**归属客户端**。
//!
//! 背景：FerroTunnel 的服务端只提供「控制面 + HTTP 入口」，给不了任意端口监听，
//! 也做不到「访问端凭密钥自建本地入口」。所以端口转发与私有 / P2P 隧道这三类，
//! 入口必须由 rscross 自己在节点上实现 —— 本模块就是那部分。
//!
//! 三件事：
//! 1. [`TunnelIndex`]：`隧道 ID / 公网端口 / 访问密钥 → 投递目标` 的内存索引，
//!    由控制面心跳下发后整表替换。
//! 2. [`TunnelDispatcher`]：按索引里的坐标，通过 Iroh 向客户端开流并桥接字节。
//!    节点不理解业务语义，它只需要「往哪个客户端发、用哪个路由键」。
//! 3. [`PortIngress`] / [`AccessHandler`]：两种入口形态。
//!    - 端口转发：节点监听公网端口（[`PortIngress`]）；
//!    - 私有 / P2P：访问端与节点握手后，直连客户端或由节点中继（[`AccessHandler`]）。
//!
//! 路由键（`tunnel_key`）必须与客户端侧 [`crate::TunnelTargets`] 的键一致，
//! 两侧都用 [`rscross_common::DesiredTunnel::route_key`] 计算 —— 否则会出现
//! 「隧道建立了但流量投递不到」。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointAddr;
use rscross_common::{Error, Result, TunnelKind, ALPN_RSROSS_ACCESS};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::p2p::{
    decode_addr, encode_addr, read_stream_key, write_stream_key, P2pNode, P2pStream,
    MAX_STREAM_KEY_BYTES,
};

/// 访问端 ALPN。
pub const ALPN_ACCESS: &[u8] = ALPN_RSROSS_ACCESS;

/// 一条隧道在节点侧的投递目标。
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchEntry {
    /// 隧道 ID。
    pub tunnel_id: String,
    /// 隧道名（日志与展示）。
    pub name: String,
    /// 用途分类。
    pub kind: TunnelKind,
    /// 投递给客户端时使用的路由键。
    pub tunnel_key: String,
    /// 归属客户端 ID。
    pub client_id: String,
    /// 归属客户端名（日志）。
    pub client_name: String,
    /// 归属客户端的 Iroh 坐标。
    pub client_endpoint: EndpointAddr,
    /// 公网端口（仅「端口转发」）。
    pub remote_port: Option<u16>,
    /// 访问密钥（仅私有 / P2P）。
    pub access_key: Option<String>,
    /// 直连失败时是否允许回退到节点中继（仅 P2P）。
    pub allow_relay: bool,
}

impl DispatchEntry {
    /// 需要在节点上监听的公网端口。
    ///
    /// 只有「端口转发」会占公网端口；私有 / P2P 刻意不暴露端口，
    /// 否则它们和端口转发就没有区别了。
    pub fn listen_port(&self) -> Option<u16> {
        if self.kind == TunnelKind::Port {
            self.remote_port
        } else {
            None
        }
    }

    /// 访问端应该采用的路径。
    ///
    /// P2P 隧道优先直连；私有隧道固定由节点中继（它本来就不要求打洞）。
    pub fn access_mode(&self) -> &'static str {
        if self.kind.prefers_direct() {
            "p2p"
        } else {
            "relay"
        }
    }
}

/// 索引整表替换后，监听端口的变化。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IndexChange {
    /// 需要新开的端口。
    pub added_ports: Vec<u16>,
    /// 需要关闭的端口。
    pub removed_ports: Vec<u16>,
}

impl IndexChange {
    /// 是否什么都没变（心跳周期里绝大多数情况都是这样，可据此跳过日志）。
    pub fn is_empty(&self) -> bool {
        self.added_ports.is_empty() && self.removed_ports.is_empty()
    }
}

/// 节点侧投递索引。
///
/// 与 [`crate::TunnelTargets`] 同样用 `std::sync::RwLock`：临界区都是纯内存查表、
/// 不含 `await`，读多写少时比 tokio 锁更省。
#[derive(Debug, Clone, Default)]
pub struct TunnelIndex {
    inner: Arc<RwLock<Index>>,
}

#[derive(Debug, Default)]
struct Index {
    by_id: HashMap<String, DispatchEntry>,
    by_port: HashMap<u16, String>,
    by_access_key: HashMap<String, String>,
}

impl TunnelIndex {
    /// 空索引。
    pub fn new() -> Self {
        Self::default()
    }

    /// 整表替换（控制面心跳下发后调用）。
    ///
    /// 返回端口增删结果，供 [`PortIngress`] 收敛监听。
    pub fn replace_all(&self, entries: Vec<DispatchEntry>) -> IndexChange {
        let mut guard = self.write();
        let before: Vec<u16> = guard.by_port.keys().copied().collect();

        guard.by_id.clear();
        guard.by_port.clear();
        guard.by_access_key.clear();

        for entry in entries {
            if let Some(port) = entry.listen_port() {
                // 同一端口出现两次说明控制面数据有冲突。注意这里必须**先查再插**：
                // `HashMap::insert` 的返回值是被覆盖掉的旧值，用它判断「已存在」
                // 时覆盖已经发生，结果会变成「后者生效」，与保留先出现者的意图相反。
                if let Some(existing) = guard.by_port.get(&port) {
                    tracing::warn!(
                        port,
                        kept = %existing,
                        dropped = %entry.tunnel_id,
                        "多条隧道争用同一公网端口，已保留先出现的"
                    );
                } else {
                    guard.by_port.insert(port, entry.tunnel_id.clone());
                }
            }
            if let Some(key) = entry.access_key.as_deref().filter(|k| !k.is_empty()) {
                guard
                    .by_access_key
                    .insert(key.to_string(), entry.tunnel_id.clone());
            }
            guard.by_id.insert(entry.tunnel_id.clone(), entry);
        }

        let after: Vec<u16> = guard.by_port.keys().copied().collect();
        drop(guard);

        let mut added_ports: Vec<u16> = after
            .iter()
            .copied()
            .filter(|p| !before.contains(p))
            .collect();
        let mut removed_ports: Vec<u16> = before
            .iter()
            .copied()
            .filter(|p| !after.contains(p))
            .collect();
        added_ports.sort_unstable();
        removed_ports.sort_unstable();
        IndexChange {
            added_ports,
            removed_ports,
        }
    }

    /// 按隧道 ID 查。
    pub fn get(&self, tunnel_id: &str) -> Option<DispatchEntry> {
        self.read().by_id.get(tunnel_id).cloned()
    }

    /// 按公网端口查（端口转发入口用）。
    pub fn by_port(&self, port: u16) -> Option<DispatchEntry> {
        let guard = self.read();
        let id = guard.by_port.get(&port)?;
        guard.by_id.get(id).cloned()
    }

    /// 按访问密钥查（访问端握手用）。
    pub fn by_access_key(&self, key: &str) -> Option<DispatchEntry> {
        let guard = self.read();
        let id = guard.by_access_key.get(key)?;
        guard.by_id.get(id).cloned()
    }

    /// 当前托管的隧道数。
    pub fn len(&self) -> usize {
        self.read().by_id.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 当前需要监听的端口（排序后，便于日志与断言）。
    pub fn listen_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.read().by_port.keys().copied().collect();
        ports.sort_unstable();
        ports
    }

    fn read(&self) -> RwLockReadGuard<'_, Index> {
        match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::error!("隧道索引读锁中毒，继续复用");
                poisoned.into_inner()
            }
        }
    }

    fn write(&self) -> RwLockWriteGuard<'_, Index> {
        match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::error!("隧道索引写锁中毒，继续复用");
                poisoned.into_inner()
            }
        }
    }
}

/// 隧道分发器：按索引里的坐标向客户端投递字节。
#[derive(Debug, Clone)]
pub struct TunnelDispatcher {
    node: P2pNode,
    index: TunnelIndex,
    dial_timeout: Duration,
}

impl TunnelDispatcher {
    /// 创建。
    pub fn new(node: P2pNode, index: TunnelIndex, dial_timeout: Duration) -> Self {
        Self {
            node,
            index,
            dial_timeout,
        }
    }

    /// 索引句柄。
    pub fn index(&self) -> &TunnelIndex {
        &self.index
    }

    /// 节点句柄。
    pub fn node(&self) -> &P2pNode {
        &self.node
    }

    /// 向归属客户端开一条绑定到该隧道的双向流。
    pub async fn open_to_client(&self, entry: &DispatchEntry) -> Result<P2pStream> {
        let dial = self
            .node
            .open_tunnel(&entry.client_endpoint, &entry.tunnel_key);
        match tokio::time::timeout(self.dial_timeout, dial).await {
            Err(_) => Err(Error::transport(format!(
                "向客户端 {} 投递超时（{} 秒）：对方可能已离线或打洞失败",
                entry.client_name,
                self.dial_timeout.as_secs()
            ))),
            Ok(Err(err)) => Err(err),
            Ok(Ok(stream)) => Ok(stream),
        }
    }

    /// 把一条公网 TCP 连接桥接到客户端本地服务（端口转发路径）。
    pub async fn bridge_tcp(
        &self,
        entry: &DispatchEntry,
        tcp: TcpStream,
        peer: Option<SocketAddr>,
    ) -> Result<(u64, u64)> {
        let stream = self.open_to_client(entry).await?;
        let P2pStream {
            connection,
            send,
            recv,
        } = stream;

        let _ = tcp.set_nodelay(true);
        let (tcp_read, tcp_write) = tcp.into_split();
        // up = 公网来访者 → 客户端；down = 客户端 → 公网来访者
        let stats = crate::forward::bridge_split(tcp_read, tcp_write, recv, send).await;

        match &stats {
            Ok((up, down)) => tracing::debug!(
                tunnel = %entry.name,
                client = %entry.client_name,
                peer = peer.map(|p| p.to_string()).as_deref().unwrap_or("-"),
                uplink = up,
                downlink = down,
                "端口转发结束"
            ),
            Err(err) => tracing::debug!(tunnel = %entry.name, error = %err, "端口转发异常结束"),
        }
        // 连接必须活到转发结束之后，否则流会被提前关掉。
        drop(connection);
        stats
    }

    /// 把「访问端开来的流」桥接到客户端（私有隧道的中继路径）。
    ///
    /// `send` / `recv` 是面向访问端的那条流的两半。
    pub async fn bridge_stream(
        &self,
        entry: &DispatchEntry,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<(u64, u64)> {
        let upstream = self.open_to_client(entry).await?;
        let P2pStream {
            connection,
            send: up_send,
            recv: up_recv,
        } = upstream;

        let stats = crate::forward::bridge_split(recv, send, up_recv, up_send).await;
        match &stats {
            Ok((up, down)) => tracing::debug!(
                tunnel = %entry.name,
                client = %entry.client_name,
                uplink = up,
                downlink = down,
                "访问端中继结束"
            ),
            Err(err) => tracing::debug!(tunnel = %entry.name, error = %err, "访问端中继异常结束"),
        }
        drop(connection);
        stats
    }
}

/// 端口转发入口：为每条「端口转发」隧道监听公网端口。
///
/// 监听随控制面配置动态增删 —— 心跳下发后调用 [`Self::reconcile`] 即可，
/// 不需要重启节点。
#[derive(Debug, Clone)]
pub struct PortIngress {
    dispatcher: TunnelDispatcher,
    listeners: Arc<tokio::sync::Mutex<HashMap<u16, CancellationToken>>>,
    bind_host: IpAddr,
}

impl PortIngress {
    /// 默认监听 `0.0.0.0`（公网入口必须对外可达）。
    pub fn new(dispatcher: TunnelDispatcher) -> Self {
        Self {
            dispatcher,
            listeners: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            bind_host: IpAddr::from([0, 0, 0, 0]),
        }
    }

    /// 当前正在监听的端口。
    pub async fn listening_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.listeners.lock().await.keys().copied().collect();
        ports.sort_unstable();
        ports
    }

    /// 按最新配置收敛监听端口。
    pub async fn reconcile(&self, ports: Vec<u16>) {
        // 先关掉不再需要的
        let stale: Vec<u16> = {
            let guard = self.listeners.lock().await;
            guard
                .keys()
                .copied()
                .filter(|p| !ports.contains(p))
                .collect()
        };
        for port in stale {
            let token = self.listeners.lock().await.remove(&port);
            if let Some(token) = token {
                token.cancel();
                tracing::info!(port, "端口转发入口已停止");
            }
        }

        // 再开新的
        for port in ports {
            {
                let mut guard = self.listeners.lock().await;
                if guard.contains_key(&port) {
                    continue;
                }
                guard.insert(port, CancellationToken::new());
            }
            let token = match self.listeners.lock().await.get(&port) {
                Some(token) => token.clone(),
                None => continue,
            };
            let dispatcher = self.dispatcher.clone();
            let host = self.bind_host;
            tokio::spawn(async move {
                if let Err(err) = serve_port(dispatcher, host, port, token).await {
                    // 端口占用是最常见的失败：控制台里配置了 20000，
                    // 但机器上已经有别的服务在听 —— 必须让人一眼看到。
                    tracing::error!(port, error = %err, "端口转发入口不可用");
                }
            });
            tracing::info!(port, "端口转发入口已启动");
        }
    }

    /// 关停全部监听。
    pub async fn shutdown(&self) {
        let mut guard = self.listeners.lock().await;
        for (_, token) in guard.drain() {
            token.cancel();
        }
    }
}

async fn serve_port(
    dispatcher: TunnelDispatcher,
    host: IpAddr,
    port: u16,
    cancel: CancellationToken,
) -> Result<()> {
    let addr = SocketAddr::new(host, port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::transport(format!("监听 {addr} 失败（端口是否被占用？）: {e}")))?;
    tracing::info!(%addr, "端口转发入口正在监听");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, peer)) => {
                        let Some(entry) = dispatcher.index().by_port(port) else {
                            tracing::warn!(port, "公网端口已无对应隧道，丢弃连接");
                            continue;
                        };
                        let dispatcher = dispatcher.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                dispatcher.bridge_tcp(&entry, tcp, Some(peer)).await
                            {
                                tracing::warn!(
                                    tunnel = %entry.name,
                                    client = %entry.client_name,
                                    peer = %peer,
                                    error = %err,
                                    "端口转发投递失败"
                                );
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(port, error = %err, "接受连接失败");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    Ok(())
}

/// 访问端握手的应答。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessReply {
    /// 是否通过密钥校验。
    pub ok: bool,
    /// 失败原因（给人看的）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// `p2p`（访问端直连客户端）或 `relay`（由节点转发）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// `p2p` 模式下客户端的 Iroh 坐标（JSON）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_endpoint: Option<String>,
    /// 投递给客户端时使用的路由键。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_key: Option<String>,
    /// 直连失败时是否允许回退到节点中继。
    #[serde(default)]
    pub allow_relay: bool,
    /// 隧道名（访问端日志用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_name: Option<String>,
}

/// 访问端处理器：在 [`ALPN_ACCESS`] 上校验访问密钥，并提供直连坐标或中继。
///
/// 协议（一条 QUIC 连接上）：
/// 1. 访问端开第 1 条双向流，写入访问密钥（复用长度前缀协议）；
/// 2. 节点回一段 JSON 的 [`AccessReply`]；
/// 3. 之后访问端可以随时再开双向流，节点把每条流中继到客户端 ——
///    这样 P2P 隧道直连失败时能就地回退，不必重新握手。
#[derive(Debug, Clone)]
pub struct AccessHandler {
    dispatcher: TunnelDispatcher,
}

impl AccessHandler {
    /// 创建。
    pub fn new(dispatcher: TunnelDispatcher) -> Self {
        Self { dispatcher }
    }

    async fn serve(&self, connection: Connection) -> Result<()> {
        // ---- 1. 握手 ----
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| Error::transport(format!("读取访问端握手流失败: {e}")))?;
        let key = match read_stream_key(&mut recv, MAX_STREAM_KEY_BYTES).await {
            Ok(key) => key,
            Err(err) => {
                tracing::warn!(error = %err, "访问端握手首部非法");
                let _ = send.finish();
                return Ok(());
            }
        };

        let entry = self.dispatcher.index().by_access_key(&key);
        let reply = match entry.as_ref() {
            Some(entry) => {
                let mode = entry.access_mode();
                AccessReply {
                    ok: true,
                    message: None,
                    mode: Some(mode.to_string()),
                    client_endpoint: if mode == "p2p" {
                        Some(encode_addr(&entry.client_endpoint)?)
                    } else {
                        None
                    },
                    tunnel_key: Some(entry.tunnel_key.clone()),
                    allow_relay: entry.allow_relay,
                    tunnel_name: Some(entry.name.clone()),
                }
            }
            None => AccessReply {
                ok: false,
                message: Some("访问密钥无效，或对应隧道已停用/删除".to_string()),
                ..Default::default()
            },
        };

        let body = serde_json::to_vec(&reply)
            .map_err(|e| Error::transport(format!("序列化握回应答失败: {e}")))?;
        send.write_all(&body).await.map_err(Error::transport)?;
        let _ = send.finish();

        let Some(entry) = entry else {
            tracing::warn!("访问端使用了无效的访问密钥");
            return Ok(());
        };
        tracing::info!(
            tunnel = %entry.name,
            client = %entry.client_name,
            mode = %entry.access_mode(),
            "访问端已通过访问密钥校验"
        );

        // ---- 2. 中继流 ----
        // 无论是 relay 模式，还是 P2P 模式直连失败后的回退，都走这里。
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let dispatcher = self.dispatcher.clone();
                    let entry = entry.clone();
                    tokio::spawn(async move {
                        if let Err(err) = dispatcher.bridge_stream(&entry, send, recv).await {
                            tracing::warn!(
                                tunnel = %entry.name,
                                client = %entry.client_name,
                                error = %err,
                                "访问端中继失败"
                            );
                        }
                    });
                }
                Err(err) => {
                    tracing::debug!(tunnel = %entry.name, error = %err, "访问端连接关闭");
                    break;
                }
            }
        }
        Ok(())
    }
}

impl ProtocolHandler for AccessHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        if let Err(err) = self.serve(connection).await {
            tracing::debug!(error = %err, "访问端会话结束");
        }
        Ok(())
    }
}

/// 访问端与节点之间的一条会话。
///
/// 把「连接节点 → 提交访问密钥 → 解析应答 → 复用同一条连接申请中继流」这套协议
/// 收敛在传输层内部：调用方（`rscross-client access`）不必接触任何 iroh 类型，
/// 也就不会因为 Iroh 迭代而被迫改动。
///
/// 复用同一条连接申请中继流，是 P2P 隧道能**就地回退**的原因：
/// 直连失败时不必重新握手，直接再开一条流即可。
#[derive(Debug, Clone)]
pub struct AccessSession {
    connection: Connection,
    reply: AccessReply,
    tunnel_key: String,
}

/// 访问端应答的字节上限（防止对端构造超大应答把内存吃满）。
const MAX_ACCESS_REPLY_BYTES: usize = 64 * 1024;

impl AccessSession {
    /// 连接节点、提交访问密钥并解析应答。
    pub async fn connect(
        node: &P2pNode,
        node_addr: &EndpointAddr,
        access_key: &str,
    ) -> Result<Self> {
        let connection = node
            .endpoint()
            .connect(node_addr.clone(), ALPN_ACCESS)
            .await
            .map_err(|e| Error::transport(format!("连接节点失败: {e}")))?;

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::transport(format!("打开握手流失败: {e}")))?;
        write_stream_key(&mut send, access_key).await?;
        let _ = send.finish();

        let bytes = recv
            .read_to_end(MAX_ACCESS_REPLY_BYTES)
            .await
            .map_err(|e| Error::transport(format!("读取节点应答失败: {e}")))?;
        let reply: AccessReply = serde_json::from_slice(&bytes)
            .map_err(|e| Error::transport(format!("节点应答不是合法 JSON: {e}")))?;

        if !reply.ok {
            return Err(Error::auth(
                reply
                    .message
                    .clone()
                    .unwrap_or_else(|| "访问密钥被拒绝".to_string()),
            ));
        }

        let tunnel_key = reply.tunnel_key.clone().unwrap_or_default();
        if tunnel_key.is_empty() {
            return Err(Error::transport("节点未下发隧道路由键，无法投递"));
        }
        Ok(Self {
            connection,
            reply,
            tunnel_key,
        })
    }

    /// 带重试的握手。
    ///
    /// 隧道配置是控制面经心跳「拉」给节点的（默认 15 秒一次），所以
    /// **「刚在控制台建完隧道就启动访问端」时，节点很可能还没拿到它** ——
    /// 一次失败就退出会让人误以为密钥是错的（e2e 第一次跑就是这样失败的）。
    /// 这里在 `timeout` 内退避重试，把「等一下就好」与「真的不对」区分开。
    pub async fn connect_with_retry(
        node: &P2pNode,
        node_addr: &EndpointAddr,
        access_key: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match Self::connect(node, node_addr, access_key).await {
                Ok(session) => return Ok(session),
                Err(err) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(Error::transport(format!(
                            "与节点握手失败（重试 {attempt} 次、共 {} 秒）：{err}；\
                             若隧道是刚创建的，请确认客户端在线且节点已收到该隧道",
                            timeout.as_secs()
                        )));
                    }
                    let delay = Duration::from_secs(3).min(remaining);
                    tracing::warn!(
                        error = %err,
                        attempt,
                        retry_in_secs = delay.as_secs(),
                        "与节点握手失败，稍后重试"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// 节点的应答原文。
    pub fn reply(&self) -> &AccessReply {
        &self.reply
    }

    /// 投递给客户端时使用的路由键。
    pub fn tunnel_key(&self) -> &str {
        &self.tunnel_key
    }

    /// 节点建议的路径（`p2p` / `relay`）。
    pub fn mode(&self) -> &str {
        self.reply.mode.as_deref().unwrap_or("relay")
    }

    /// 是否允许直连失败后回退到节点中继。
    pub fn allow_relay(&self) -> bool {
        self.reply.allow_relay
    }

    /// 直连客户端（P2P 隧道的优先路径）。
    pub async fn dial_client(&self, node: &P2pNode, timeout: Duration) -> Result<P2pStream> {
        let raw = self
            .reply
            .client_endpoint
            .as_deref()
            .ok_or_else(|| Error::transport("节点未提供客户端坐标，无法直连"))?;
        let addr = decode_addr(raw)?;
        match tokio::time::timeout(timeout, node.open_tunnel(&addr, &self.tunnel_key)).await {
            Err(_) => Err(Error::transport(format!(
                "直连客户端超时（{} 秒）",
                timeout.as_secs()
            ))),
            Ok(Err(err)) => Err(err),
            Ok(Ok(stream)) => Ok(stream),
        }
    }

    /// 向节点申请一条中继流（私有隧道，或 P2P 直连失败后的回退）。
    pub async fn open_relay(&self) -> Result<P2pStream> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| Error::transport(format!("申请中继流失败: {e}")))?;
        Ok(P2pStream {
            connection: self.connection.clone(),
            send,
            recv,
        })
    }
}

/// 访问端侧：把一段本地 TCP 连接桥接到一条 Iroh 双向流上。
///
/// 访问端与节点、访问端与客户端两种走向共用这一个函数，
/// 保证「p2p 直连」和「节点中继」两条路径的字节语义完全一致。
pub async fn bridge_tcp_to_stream(tcp: TcpStream, stream: P2pStream) -> Result<(u64, u64)> {
    let P2pStream {
        connection,
        send,
        recv,
    } = stream;
    let _ = tcp.set_nodelay(true);
    let (tcp_read, tcp_write) = tcp.into_split();
    let stats = crate::forward::bridge_split(tcp_read, tcp_write, recv, send).await;
    drop(connection);
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> iroh::SecretKey {
        iroh::SecretKey::generate()
    }

    fn entry(id: &str, kind: TunnelKind, port: Option<u16>, access_key: Option<&str>) -> DispatchEntry {
        DispatchEntry {
            tunnel_id: id.to_string(),
            name: format!("t-{id}"),
            kind,
            tunnel_key: id.to_string(),
            client_id: "c1".to_string(),
            client_name: "client-1".to_string(),
            client_endpoint: EndpointAddr::new(key().public()),
            remote_port: port,
            access_key: access_key.map(str::to_string),
            allow_relay: true,
        }
    }

    #[test]
    fn only_port_forwarding_occupies_a_public_port() {
        assert_eq!(entry("a", TunnelKind::Port, Some(20000), None).listen_port(), Some(20000));
        // 私有 / P2P 刻意不暴露公网端口
        assert_eq!(entry("b", TunnelKind::Private, Some(20000), Some("k")).listen_port(), None);
        assert_eq!(entry("c", TunnelKind::P2p, Some(20000), Some("k")).listen_port(), None);
        // 域名解析走 HTTP 入口
        assert_eq!(entry("d", TunnelKind::Domain, None, None).listen_port(), None);
    }

    #[test]
    fn access_mode_prefers_direct_only_for_p2p() {
        assert_eq!(entry("a", TunnelKind::P2p, None, Some("k")).access_mode(), "p2p");
        assert_eq!(entry("b", TunnelKind::Private, None, Some("k")).access_mode(), "relay");
    }

    #[test]
    fn index_reports_port_delta() {
        let index = TunnelIndex::new();
        let change = index.replace_all(vec![
            entry("a", TunnelKind::Port, Some(20000), None),
            entry("b", TunnelKind::Domain, None, None),
        ]);
        assert_eq!(change.added_ports, vec![20000]);
        assert!(change.removed_ports.is_empty());
        assert_eq!(index.listen_ports(), vec![20000]);
        assert_eq!(index.len(), 2);

        // 端口换成了另一个 → 一增一减
        let change = index.replace_all(vec![entry("a", TunnelKind::Port, Some(20001), None)]);
        assert_eq!(change.added_ports, vec![20001]);
        assert_eq!(change.removed_ports, vec![20000]);
        assert_eq!(index.listen_ports(), vec![20001]);
        assert_eq!(index.len(), 1);

        // 配置没变时不产生任何动作（心跳周期里绝大多数情况）
        let change = index.replace_all(vec![entry("a", TunnelKind::Port, Some(20001), None)]);
        assert!(change.is_empty(), "配置未变化时不该有端口增删");
    }

    #[test]
    fn index_looks_up_by_port_and_access_key() {
        let index = TunnelIndex::new();
        index.replace_all(vec![
            entry("a", TunnelKind::Port, Some(20000), None),
            entry("b", TunnelKind::Private, None, Some("rsv_private")),
            entry("c", TunnelKind::P2p, None, Some("rsv_p2p")),
        ]);

        assert!(index.by_port(20000).is_some());
        assert!(index.by_port(20001).is_none());
        assert_eq!(
            index.by_access_key("rsv_private").map(|e| e.tunnel_id),
            Some("b".to_string())
        );
        assert_eq!(
            index.by_access_key("rsv_p2p").map(|e| e.tunnel_id),
            Some("c".to_string())
        );
        assert!(index.by_access_key("rsv_wrong").is_none());
        assert_eq!(index.get("c").map(|e| e.name), Some("t-c".to_string()));
    }

    #[test]
    fn duplicate_public_port_keeps_first_and_warns() {
        let index = TunnelIndex::new();
        index.replace_all(vec![
            entry("first", TunnelKind::Port, Some(20000), None),
            entry("second", TunnelKind::Port, Some(20000), None),
        ]);
        assert_eq!(
            index.by_port(20000).map(|e| e.tunnel_id),
            Some("first".to_string()),
            "同端口争用时保留先出现的那条，避免静默覆盖导致排障对不上号"
        );
    }

    #[test]
    fn empty_access_key_is_not_indexed() {
        let index = TunnelIndex::new();
        index.replace_all(vec![entry("a", TunnelKind::Private, None, Some(""))]);
        assert!(index.by_access_key("").is_none(), "空密钥不能成为可命中的索引");
        assert_eq!(index.len(), 1, "隧道本身仍在索引里");
        assert!(index.listen_ports().is_empty());
    }

    #[test]
    fn access_reply_roundtrips() {
        let reply = AccessReply {
            ok: true,
            message: None,
            mode: Some("p2p".to_string()),
            client_endpoint: Some(r#"{"id":"abc"}"#.to_string()),
            tunnel_key: Some("web".to_string()),
            allow_relay: true,
            tunnel_name: Some("web".to_string()),
        };
        let json = serde_json::to_string(&reply).expect("ser");
        let back: AccessReply = serde_json::from_str(&json).expect("de");
        assert!(back.ok);
        assert_eq!(back.mode.as_deref(), Some("p2p"));
        assert_eq!(back.tunnel_key.as_deref(), Some("web"));

        // 拒绝时只有 ok / message，其余字段全部省略
        let denied = AccessReply {
            ok: false,
            message: Some("访问密钥无效".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&denied).expect("ser");
        assert!(!json.contains("tunnel_key"), "拒绝应答不应带隧道信息: {json}");
    }
}
