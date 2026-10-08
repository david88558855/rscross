//! Iroh 适配层：**打洞 / Relay 回退 / 密钥交换 / 节点发现**。
//!
//! 本模块只依赖 Iroh 的公开 builder API，把「节点身份」和「数据面投递」两件事包成
//! 最小的表面积，方便在 Iroh 快速迭代时把改动收敛到这一个文件。

use std::collections::HashMap;
use std::path::Path as FsPath;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMap, RelayMode, SecretKey};
use rscross_common::{Error, Result};
// 注意：iroh 的 SendStream/RecvStream 自带 write_all / read_exact 固有方法，
// 因此不需要把 tokio 的 AsyncReadExt / AsyncWriteExt 引入作用域；
// 下面 `probe_control` 里的 read_to_end 走的是全限定路径，也不依赖导入。
use tokio::net::TcpStream;

use crate::path::PathProbe;

/// 控制面 ALPN（保留：阶段 3 用于服务端→客户端的配置推送）。
pub const ALPN_CONTROL: &[u8] = rscross_common::ALPN_RSROSS_CONTROL;
/// 数据面 ALPN：把一条双向流投递给目标客户端的本地服务。
pub const ALPN_DATA: &[u8] = rscross_common::ALPN_RSROSS_DATA;

/// 流首部里隧道标识的最大长度。
pub const MAX_STREAM_KEY_BYTES: usize = 256;

/// Iroh 节点构建参数。
#[derive(Debug, Clone)]
pub struct P2pOptions {
    /// `n0` | `custom` | `disabled`。
    pub relay_mode: String,
    /// 自建 Relay 地址（`relay_mode = custom` 时必填）。
    pub relay_urls: Vec<String>,
    /// 是否启用 DNS/Pkarr 地址发现。
    pub address_lookup: bool,
    /// 节点私钥。为 `None` 时由 Iroh 生成一次性密钥（重启后身份会变）。
    pub secret_key: Option<SecretKey>,
}

impl P2pOptions {
    /// 从配置的 `[p2p]` 段构造。
    pub fn from_section(section: &rscross_config::P2pSection, secret_key: Option<SecretKey>) -> Self {
        Self {
            relay_mode: section.relay_mode.clone(),
            relay_urls: section.relay_urls.clone(),
            address_lookup: section.address_lookup,
            secret_key,
        }
    }
}

/// 一个已绑定的 Iroh 节点。
#[derive(Clone)]
pub struct P2pNode {
    endpoint: Endpoint,
}

impl std::fmt::Debug for P2pNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pNode")
            .field("endpoint_id", &self.id_string())
            .finish()
    }
}

impl P2pNode {
    /// 绑定一个节点。
    ///
    /// `presets::N0` 一次性装上：
    /// - **节点发现**：`PkarrPublisher` + `PkarrResolver` + `DnsAddressLookup`
    /// - **中继**：n0 生产 relay（`relay_mode = n0` 时）
    /// - **加密**：`tls-ring`（默认 feature）提供 rustls 的密码学后端
    pub async fn bind(opts: P2pOptions) -> Result<Self> {
        let mut builder = Endpoint::builder(presets::N0);

        if let Some(sk) = opts.secret_key.clone() {
            builder = builder.secret_key(sk);
        }

        builder = match opts.relay_mode.as_str() {
            "disabled" => builder.relay_mode(RelayMode::Disabled),
            "custom" => {
                let map = RelayMap::try_from_iter(opts.relay_urls.iter().map(|s| s.as_str()))
                    .map_err(Error::transport)?;
                if map.is_empty() {
                    return Err(Error::config("p2p.relay_urls 解析后为空"));
                }
                builder.relay_mode(RelayMode::Custom(map))
            }
            // n0 与 default 都走 `RelayMode::Default`（由 N0 preset 设置）
            _ => builder,
        };

        if !opts.address_lookup {
            builder = builder.clear_address_lookup();
        }

        let endpoint = builder.bind().await.map_err(Error::transport)?;
        tracing::info!(
            endpoint_id = %endpoint.id(),
            relay_mode = %opts.relay_mode,
            "Iroh 节点已绑定"
        );
        Ok(Self { endpoint })
    }

    /// 底层 `Endpoint`。
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// 节点公钥（即 `EndpointId`，同时是 QUIC/TLS 的身份）。
    pub fn public_key(&self) -> PublicKey {
        self.endpoint.secret_key().public()
    }

    /// 节点 ID 的十六进制字符串，用于持久化与展示。
    pub fn id_string(&self) -> String {
        self.public_key().to_string()
    }

    /// 当前可用的寻址信息（中继 URL + 直连地址 + 端口映射结果）。
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// 寻址信息的 JSON 形态，便于经控制面推送给对端。
    pub fn addr_json(&self) -> Result<String> {
        encode_addr(&self.addr())
    }

    /// 等待节点上线（拿到 relay 地址、完成 net report）。
    pub async fn wait_online(&self) {
        self.endpoint.online().await;
    }

    /// 关闭节点。
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    /// 以给定 ALPN 注册一个协议处理器，返回 `Router`。
    ///
    /// **注意**：`Router` 必须在调用方持有；drop 会中止 accept 循环。
    pub fn spawn_router<H>(&self, alpn: &[u8], handler: H) -> Router
    where
        H: ProtocolHandler,
    {
        Router::builder(self.endpoint.clone())
            .accept(alpn, handler)
            .spawn()
    }

    /// 对目标节点做一次数据面连通性 + RTT 探测（供 [`crate::PathSelector`] 使用）。
    pub async fn probe(&self, remote: &EndpointAddr, timeout: Duration) -> PathProbe {
        let started = Instant::now();
        match tokio::time::timeout(timeout, self.endpoint.connect(remote.clone(), ALPN_DATA)).await {
            Err(_) => PathProbe::failed("探测超时（打洞可能失败，等待 relay 回退）"),
            Ok(Err(err)) => PathProbe::failed(format!("{err}")),
            Ok(Ok(conn)) => {
                let rtt = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                conn.close(0u32.into(), b"probe");
                PathProbe::ok(rtt)
            }
        }
    }
}

/// 打开一条到远端节点的数据面流，并把隧道标识写进流首部。
///
/// 返回的 [`P2pStream`] 持有 `Connection`，调用方**必须**把它保留到转发结束，
/// 否则连接会被提前关闭。
pub struct P2pStream {
    /// 承载的 QUIC 连接。
    pub connection: Connection,
    /// 发送侧。
    pub send: SendStream,
    /// 接收侧。
    pub recv: RecvStream,
}

impl std::fmt::Debug for P2pStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pStream").finish_non_exhaustive()
    }
}

impl P2pNode {
    /// 连接远端并打开一条绑定到 `tunnel_key` 的双向流。
    pub async fn open_tunnel(&self, remote: &EndpointAddr, tunnel_key: &str) -> Result<P2pStream> {
        let connection = self
            .endpoint
            .connect(remote.clone(), ALPN_DATA)
            .await
            .map_err(|e| Error::transport(format!("Iroh 直连失败: {e}")))?;
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::transport(format!("打开双向流失败: {e}")))?;
        write_stream_key(&mut send, tunnel_key).await?;
        Ok(P2pStream {
            connection,
            send,
            recv,
        })
    }
}

/// 隧道本地目标表：`隧道 key → 本地 socket 地址`。
///
/// 用 `std::sync::RwLock` 而不是 tokio 的锁：所有临界区都是纯内存查表，
/// 不含 `await`，读多写少场景下更省。
#[derive(Debug, Clone, Default)]
pub struct TunnelTargets {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl TunnelTargets {
    /// 空表。
    pub fn new() -> Self {
        Self::default()
    }

    /// 整表替换（控制面下发新配置时调用）。
    pub fn replace_all(&self, entries: Vec<(String, String)>) {
        let mut guard = self.write();
        guard.clear();
        for (k, v) in entries {
            guard.insert(k, v);
        }
    }

    /// 插入/覆盖一条。
    pub fn set(&self, key: impl Into<String>, local_addr: impl Into<String>) {
        self.write().insert(key.into(), local_addr.into());
    }

    /// 删除一条。
    pub fn remove(&self, key: &str) {
        self.write().remove(key);
    }

    /// 查询。
    pub fn get(&self, key: &str) -> Option<String> {
        self.read().get(key).cloned()
    }

    /// 条目数。
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 全部键（用于日志与 API 展示）。
    pub fn keys(&self) -> Vec<String> {
        self.read().keys().cloned().collect()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, String>> {
        match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, String>> {
        match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// 客户端侧的数据面处理器：接受远端开来的流，转发到对应本地服务。
#[derive(Debug, Clone)]
pub struct P2pDataHandler {    targets: TunnelTargets,
    dial_timeout: Duration,
}

impl P2pDataHandler {
    /// 创建处理器。
    pub fn new(targets: TunnelTargets, dial_timeout: Duration) -> Self {
        Self {
            targets,
            dial_timeout,
        }
    }

    /// 目标表句柄。
    pub fn targets(&self) -> &TunnelTargets {
        &self.targets
    }

    async fn serve_stream(&self, mut send: SendStream, mut recv: RecvStream) {
        let key = match read_stream_key(&mut recv, MAX_STREAM_KEY_BYTES).await {
            Ok(k) => k,
            Err(err) => {
                tracing::warn!(error = %err, "P2P 流首部非法，丢弃");
                let _ = send.finish();
                return;
            }
        };

        let Some(target) = self.targets.get(&key) else {
            tracing::warn!(tunnel = %key, "P2P 流指向未知隧道，拒绝");
            let _ = send.finish();
            return;
        };

        let tcp = match tokio::time::timeout(self.dial_timeout, TcpStream::connect(&target)).await {
            Err(_) => {
                tracing::warn!(tunnel = %key, target = %target, "本地服务连接超时");
                let _ = send.finish();
                return;
            }
            Ok(Err(err)) => {
                tracing::warn!(tunnel = %key, target = %target, error = %err, "本地服务不可达");
                let _ = send.finish();
                return;
            }
            Ok(Ok(stream)) => stream,
        };

        let peer = tcp.peer_addr().ok().map(|a| a.to_string());
        let _ = tcp.set_nodelay(true);
        let (tcp_read, tcp_write) = tcp.into_split();

        match crate::forward::bridge_split(recv, send, tcp_read, tcp_write).await {
            Ok((sent, received)) => {
                tracing::debug!(
                    tunnel = %key,
                    peer = peer.as_deref().unwrap_or("-"),
                    uplink = sent,
                    downlink = received,
                    "P2P 流结束"
                );
            }
            Err(err) => {
                tracing::debug!(tunnel = %key, error = %err, "P2P 流异常结束");
            }
        }
    }
}

impl ProtocolHandler for P2pDataHandler {
    // 注意：这里是标准库的 `Result<(), AcceptError>`（两个参数），
    // 不是本 crate 里 `rscross_common::Result`（只有一个参数）。
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let this = self.clone();
                    tokio::spawn(async move { this.serve_stream(send, recv).await });
                }
                Err(err) => {
                    tracing::debug!(error = %err, "P2P 连接关闭");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// 服务端节点侧的控制面处理器：在 [`ALPN_CONTROL`] 上回应一条能力描述。
///
/// 存在的意义有两个，都很具体：
/// 1. **让 P2P 直连可被判真**。客户端用 [`probe_control`] 真正建立一条 QUIC 连接，
///    成功即说明「打洞/直连这条路径通了」，结果直接喂给 [`crate::PathSelector`]，
///    而不是靠猜。
/// 2. **提供一条不过 HTTP 的节点信息通道**，用于排障与后续的配置推送。
#[derive(Debug, Clone)]
pub struct NodeInfoHandler {
    /// 节点名。
    pub node_name: String,
    /// 附加说明（例如监听端口），会原样回给对端。
    pub detail: String,
}

impl NodeInfoHandler {
    /// 创建。
    pub fn new(node_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            node_name: node_name.into(),
            detail: detail.into(),
        }
    }

    fn payload(&self) -> String {
        format!(
            "rscross-node/{}|{}|{}",
            rscross_common::VERSION,
            self.node_name,
            self.detail
        )
    }
}

impl ProtocolHandler for NodeInfoHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        loop {
            match connection.accept_bi().await {
                Ok((mut send, _recv)) => {
                    if let Err(err) = send.write_all(self.payload().as_bytes()).await {
                        tracing::debug!(error = %err, "回应节点信息失败");
                    }
                    let _ = send.finish();
                }
                Err(err) => {
                    tracing::debug!(error = %err, "节点信息通道关闭");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// 在 [`ALPN_CONTROL`] 上探测远端节点，成功时返回对方回应的文本。
///
/// 这是「P2P 直连是否真的可用」的唯一可信判据：TCP 连得上不代表打洞成功，
/// 必须真的建立一条 QUIC 连接。
pub async fn probe_control(
    endpoint: &Endpoint,
    remote: &EndpointAddr,
    timeout: Duration,
) -> Result<String> {
    let started = std::time::Instant::now();
    let connecting = tokio::time::timeout(timeout, endpoint.connect(remote.clone(), ALPN_CONTROL))
        .await
        .map_err(|_| Error::transport("P2P 探测超时"))?
        .map_err(Error::transport)?;

    let (mut send, mut recv) = connecting.open_bi().await.map_err(Error::transport)?;
    // 触发对端 accept：QUIC 的流是惰性创建的，必须先发数据。
    send.write_all(b"ping").await.map_err(Error::transport)?;
    let _ = send.finish();

    let mut buf = Vec::with_capacity(128);
    tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf)
        .await
        .map_err(Error::transport)?;

    let text = String::from_utf8_lossy(&buf).to_string();
    tracing::debug!(
        rtt_ms = started.elapsed().as_millis() as u64,
        reply = %text,
        "P2P 直连探测成功"
    );
    Ok(text)
}

/// 写入长度前缀（u16，大端）的隧道标识。
pub async fn write_stream_key(send: &mut SendStream, key: &str) -> Result<()> {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_STREAM_KEY_BYTES {
        return Err(Error::transport(format!(
            "隧道标识长度非法: {}（允许 1..={MAX_STREAM_KEY_BYTES}）",
            bytes.len()
        )));
    }
    send.write_all(&(bytes.len() as u16).to_be_bytes())
        .await
        .map_err(Error::transport)?;
    send.write_all(bytes).await.map_err(Error::transport)?;
    Ok(())
}

/// 读取长度前缀（u16，大端）的隧道标识。
pub async fn read_stream_key(recv: &mut RecvStream, max_bytes: usize) -> Result<String> {
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::transport(format!("读取流首部长度失败: {e}")))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max_bytes {
        return Err(Error::transport(format!("流首部长度非法: {len}")));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| Error::transport(format!("读取流首部失败: {e}")))?;
    String::from_utf8(buf).map_err(|e| Error::transport(format!("流首部不是合法 UTF-8: {e}")))
}

/// 序列化寻址信息。
pub fn encode_addr(addr: &EndpointAddr) -> Result<String> {
    serde_json::to_string(addr).map_err(Error::from)
}

/// 反序列化寻址信息。
pub fn decode_addr(raw: &str) -> Result<EndpointAddr> {
    serde_json::from_str(raw).map_err(|e| Error::transport(format!("寻址信息解析失败: {e}")))
}

/// 用「只有公钥」的信息构造寻址（此时必须依赖地址发现或 Relay 才能连上）。
pub fn addr_from_id(id: &str) -> Result<EndpointAddr> {
    let key: PublicKey = id
        .trim()
        .parse()
        .map_err(|e| Error::transport(format!("EndpointId 非法: {e}")))?;
    Ok(EndpointAddr::new(key))
}

/// 从文件读取节点私钥；文件不存在时生成并写入（十六进制，`600` 权限）。
///
/// 私钥持久化后 `EndpointId` 才稳定，控制台里的「节点指纹」才有意义。
pub fn load_or_create_secret_key(path: &FsPath) -> Result<SecretKey> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::transport(format!("读取节点私钥 {} 失败: {e}", path.display())))?;
        let raw = raw.trim();
        let bytes = hex::decode(raw)
            .map_err(|e| Error::transport(format!("节点私钥不是合法十六进制: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::transport("节点私钥长度必须是 32 字节"))?;
        return Ok(SecretKey::from_bytes(&arr));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::transport(format!("创建目录 {} 失败: {e}", parent.display()))
            })?;
        }
    }
    let key = SecretKey::generate();
    write_secret_key(path, &key)?;
    tracing::info!(path = %path.display(), "已生成新的 Iroh 节点私钥");
    Ok(key)
}

/// 把节点私钥写入文件。
pub fn write_secret_key(path: &FsPath, key: &SecretKey) -> Result<()> {
    std::fs::write(path, hex::encode(key.to_bytes()))
        .map_err(|e| Error::transport(format!("写入节点私钥 {} 失败: {e}", path.display())))?;
    restrict_permissions(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &FsPath) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(path = %path.display(), error = %err, "设置私钥文件权限失败");
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &FsPath) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_targets_replace_and_query() {
        let t = TunnelTargets::new();
        assert!(t.is_empty());
        t.set("a", "127.0.0.1:1");
        t.set("b", "127.0.0.1:2");
        assert_eq!(t.len(), 2);
        assert_eq!(t.get("a").as_deref(), Some("127.0.0.1:1"));

        t.replace_all(vec![("c".to_string(), "127.0.0.1:3".to_string())]);
        assert_eq!(t.len(), 1);
        assert!(t.get("a").is_none());
        assert_eq!(t.get("c").as_deref(), Some("127.0.0.1:3"));

        t.remove("c");
        assert!(t.is_empty());
    }

    #[test]
    fn addr_json_roundtrip() {
        let key = SecretKey::generate();
        let addr = EndpointAddr::new(key.public());
        let encoded = encode_addr(&addr).expect("encode");
        let decoded = decode_addr(&encoded).expect("decode");
        assert_eq!(decoded.id, addr.id);
    }

    #[test]
    fn addr_from_bad_id_is_error_not_panic() {
        assert!(addr_from_id("not-a-key").is_err());
        assert!(addr_from_id("").is_err());
    }

    #[test]
    fn addr_from_id_roundtrip() {
        let key = SecretKey::generate();
        let id = key.public().to_string();
        let addr = addr_from_id(&id).expect("parse");
        assert_eq!(addr.id, key.public());
    }

    #[test]
    fn secret_key_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rscross-key-{}", uuid_like()));
        let path = dir.join("node.key");
        let key = load_or_create_secret_key(&path).expect("create");
        let again = load_or_create_secret_key(&path).expect("load");
        assert_eq!(key.public(), again.public(), "私钥必须持久化且稳定");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn uuid_like() -> String {
        format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }
}
