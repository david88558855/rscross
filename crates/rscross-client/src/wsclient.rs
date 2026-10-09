//! 控制台 WebSocket 连接：帧编解码 + 请求响应配对 + 重连退避。
//!
//! 与 REST 客户端（[`crate::api`]）并存。切换由 `--console` 的 scheme 决定：
//! `ws://` / `wss://` 走这里，`http://` / `https://` / `txt://` 先经
//! [`crate::discover`] 解析出 ws 地址再走这里。
//!
//! 帧协议定义在 `rscross_common::control` —— 与控制台共用同一份，
//! 所以「客户端发的和服务器解的不是同一个结构」这类漂移在编译期就被挡住。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;
use rscross_common::control::{
    ControlRequest, ControlResponse, Role, CONTROL_VERSION, MAX_HEARTBEAT_SECS, MIN_HEARTBEAT_SECS,
};
use rscross_common::{ClientRuntime, Error, Result};
use serde::de::DeserializeOwned;
use tokio::sync::{mpsc, oneshot, Mutex};

/// 建连超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 单个请求的应答超时。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 等待应答的通道容量。
const INBOX_CAPACITY: usize = 64;

/// 重连退避上限。
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// 一条已建立的控制面连接。
///
/// 只持有收发两端与请求配对表；断线后不自行重连，由调用方决定重试策略
/// （注册失败重试与心跳失败退避的节奏完全不同，混在一起反而难调）。
pub struct ControlSocket {
    role: Role,
    /// 实际建立连接的地址（日志里要能看清到底是哪一个）。
    url: String,
    send: mpsc::UnboundedSender<String>,
    inbox: Arc<Mutex<HashMap<u64, oneshot::Sender<ControlResponse>>>>,
    next_id: AtomicU64,
    /// 收到的帧（由后台任务分发）。
    events: mpsc::UnboundedReceiver<ControlResponse>,
    /// 关停信号。Drop 时取消 —— 否则重连后旧连接的两个任务还在跑，
    /// 它们持有的 sink 会继续把帧发到已经废弃的连接上。
    stop: tokio_util::sync::CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        // 不 await：Drop 里不能阻塞。任务会在下一个检查点退出。
        self.stop.cancel();
    }
}

impl std::fmt::Debug for ControlSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlSocket")
            .field("role", &self.role)
            .field("url", &self.url)
            .finish()
    }
}

impl ControlSocket {
    /// 连接到控制台并完成版本协商。
    ///
    /// `url` 必须是 `ws://` 或 `wss://`（由 [`crate::discover`] 保证）。
    pub async fn connect(role: Role, url: &str) -> Result<Self> {
        let url = normalize_ws_url(url)?;

        // 每次连接都用新的 Client：连接池里残留的旧连接在重连场景下会造成
        // 「明明断了却还能发出去」的假象。
        let (stream, _resp) = tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(&url))
            .await
            .map_err(|_| {
                Error::transport(format!(
                    "连接控制面 {url} 超时（{CONNECT_TIMEOUT:?}）"
                ))
            })?
            .map_err(|err| {
                Error::transport(format!("连接控制面 {url} 失败：{err}"))
            })?;

        tracing::info!(role = ?role, url = %url, "控制面连接已建立");

        let (mut sink, mut stream) = stream.split();
        let (tx, mut tx_rx) = mpsc::unbounded_channel::<String>();
        let inbox: Arc<Mutex<HashMap<u64, oneshot::Sender<ControlResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, event_rx) = mpsc::unbounded_channel::<ControlResponse>();

        let driver_inbox = inbox.clone();
        let stop = tokio_util::sync::CancellationToken::new();
        let driver_stop = stop.clone();
        let driver = tokio::spawn(async move {
            // 发送侧：把队列里的帧刷出去。
            let sender_stop = driver_stop.clone();
            let sender_task = tokio::spawn(async move {
                while let Some(text) = tokio::select! {
                    biased;
                    _ = sender_stop.cancelled() => break,
                    text = tx_rx.recv() => match text {
                        Some(t) => t,
                        None => break,
                    },
                } {
                    if sink
                        .send(tungstenite::Message::Text(text.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = sink.close().await;
            });

            // 接收侧：把应答按 id 配对给等待者；没有对应等待者的（例如主动推送）
            // 走 events 通道交给调用方。
            loop {
                let next = tokio::select! {
                    biased;
                    _ = driver_stop.cancelled() => break,
                    item = stream.next() => item,
                };
                let Some(Ok(msg)) = next else { break };
                let text = match msg {
                    tungstenite::Message::Text(t) => t.to_string(),
                    tungstenite::Message::Close(_) => break,
                    tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => continue,
                    tungstenite::Message::Binary(b) => match String::from_utf8(b.to_vec()) {
                        Ok(t) => t,
                        Err(_) => continue,
                    },
                    // 原始帧：tokio-tungstenite 默认不暴露给我们（未开启 feature），
                    // 真出现时说明协议栈行为变了，跳过而不是让整个循环崩掉。
                    _ => continue,
                };
                let resp: ControlResponse = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(error = %err, "控制面应答解析失败");
                        continue;
                    }
                };
                let id = response_id(&resp);
                let waiter = { driver_inbox.lock().await.remove(&id) };
                match waiter {
                    Some(tx) => {
                        if tx.send(resp).is_err() {
                            // 请求方已经放弃（超时/取消），这属于正常情况。
                            tracing::debug!(id, "控制面应答无人等待");
                        }
                    }
                    None => {
                        // 没人接下行帧（调用方没在读事件）时只记日志，
                        // 不能因此断开连接 —— 心跳还指着它。
                        if event_tx.send(resp).is_err() {
                            tracing::debug!("控制面下行帧无人接收，丢弃");
                        }
                    }
                }
            }

            sender_task.abort();
            // 让所有等待者立刻醒来：否则他们会一直等到 REQUEST_TIMEOUT，
            // 而真实原因只是「连接断了」。
            for (_, tx) in driver_inbox.lock().await.drain() {
                let _ = tx.send(ControlResponse::error(
                    0,
                    "disconnected",
                    "控制面连接已断开",
                ));
            }
        });

        let socket = Self {
            role,
            url: url.clone(),
            send: tx,
            inbox,
            next_id: AtomicU64::new(1),
            events: event_rx,
            stop,
            _driver: driver,
        };

        socket.handshake().await?;
        Ok(socket)
    }

    /// 版本协商。
    ///
    /// 必须在发任何业务帧之前完成：版本不同则帧语义可能完全不同。
    async fn handshake(&self) -> Result<()> {
        let welcome = self
            .request(|id| ControlRequest::Hello {
                id,
                version: CONTROL_VERSION,
            })
            .await?;
        match welcome {
            ControlResponse::Welcome { version, .. } if version == CONTROL_VERSION => {
                tracing::debug!(version, "控制面协议版本协商完成");
                Ok(())
            }
            ControlResponse::Welcome { version, .. } => Err(Error::api(format!(
                "控制台协议版本为 {version}，本端为 {CONTROL_VERSION}"
            ))),
            ControlResponse::Error { message, .. } => {
                Err(Error::api(format!("控制台拒绝连接：{message}")))
            }
            other => Err(Error::api(format!(
                "版本协商收到意外应答：{other:?}"
            ))),
        }
    }

    /// 实际连接的地址（排障时第一眼要看的就是它）。
    pub fn url(&self) -> &str {
        &self.url
    }

    /// 本端角色。
    pub fn role(&self) -> Role {
        self.role
    }

    /// 发一条请求并等它的应答。
    ///
    /// 超时或断连都会返回 `Err` —— 调用方据此决定重试；
    /// 绝不让它挂住，否则隧道状态会永远停在上一次的快照上。
    pub async fn request<F>(&self, build: F) -> Result<ControlResponse>
    where
        F: FnOnce(u64) -> ControlRequest,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = build(id);
        let (tx, rx) = oneshot::channel();
        // 先登记等待者再发送：反过来的话，极快的应答可能在登记前就到了。
        self.inbox.lock().await.insert(id, tx);

        let text = serde_json::to_string(&req)
            .map_err(|err| Error::api(format!("序列化控制面请求失败：{err}")))?;
        if let Err(err) = self.send.send(text) {
            self.inbox.lock().await.remove(&id);
            return Err(Error::transport(format!(
                "控制面连接已关闭，请求未能发出：{err}"
            )));
        }

        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                self.inbox.lock().await.remove(&id);
                Err(Error::transport("控制面连接已关闭"))
            }
            Err(_) => {
                self.inbox.lock().await.remove(&id);
                Err(Error::transport(format!(
                    "等待控制面应答超时（{REQUEST_TIMEOUT:?}）"
                )))
            }
        }
    }

    /// 发一条请求，把应答反序列化成具体类型。
    ///
    /// 帧级别的失败（`ControlResponse::Error`）在这里转成 `Err`，
    /// 调用方不需要在每个调用点重复匹配。
    pub async fn request_json<T, F>(&self, build: F) -> Result<T>
    where
        T: DeserializeOwned,
        F: FnOnce(u64) -> ControlRequest,
    {
        let resp = self.request(build).await?;
        match resp {
            ControlResponse::Error { message, .. } => Err(Error::auth(message)),
            other => serde_json::from_value(serde_json::to_value(&other).map_err(|err| {
                Error::api(format!("序列化控制面应答失败：{err}"))
            })?)
            .map_err(|err| Error::api(format!("控制面应答结构不符：{err}"))),
        }
    }

    /// 接收未被请求消费的下行帧（目前只有配置变更推送）。
    pub async fn next_event(&mut self) -> Option<ControlResponse> {
        self.events.recv().await
    }
}

/// 抽取应答的 id。没有 id 的响应（理论上不该有）归到 0。
fn response_id(resp: &ControlResponse) -> u64 {
    match resp {
        ControlResponse::Welcome { id, .. }
        | ControlResponse::Enrolled { id, .. }
        | ControlResponse::Heartbeat { id, .. }
        | ControlResponse::Tunnels { id, .. }
        | ControlResponse::NodeEnrolled { id, .. }
        | ControlResponse::NodeHeartbeat { id, .. }
        | ControlResponse::LogsAccepted { id, .. }
        | ControlResponse::Ok { id }
        | ControlResponse::Error { id, .. }
        | ControlResponse::NodeSelf { id, .. } => *id,
    }
}

/// 校验并规范化 ws 地址。
///
/// 拒绝的原因是明确的：这里拿到的一定是 `plan_console_address` / `discover`
/// 的输出，出现 `http://` 说明上游判断漏了 —— 与其拿着它去连接然后收到
/// 一个语焉不详的握手失败，不如在这里说清楚。
fn normalize_ws_url(url: &str) -> Result<String> {
    let u = url.trim();
    if u.starts_with("wss://") || u.starts_with("ws://") {
        return Ok(u.to_string());
    }
    Err(Error::config(format!(
        "WebSocket 地址必须以 ws:// 或 wss:// 开头（实际是 {u:?}）"
    )))
}

/// 夹到控制台心跳的合法区间。
pub fn clamp_heartbeat(secs: u64) -> u64 {
    secs.clamp(MIN_HEARTBEAT_SECS, MAX_HEARTBEAT_SECS)
}

/// 指数退避 + 抖动。
///
/// 没有抖动的话，控制台重启后所有客户端会同时涌上来，
/// 把它自己刚起来的连接数又打满。
pub fn backoff_for(attempt: u32) -> Duration {
    let secs = 1u64.saturating_mul(1u64 << attempt.min(6));
    let secs = secs.clamp(1, MAX_BACKOFF.as_secs() as u64);
    Duration::from_secs(secs)
}

/// 客户端注册成功后拿到的信息。
#[derive(Debug, Clone)]
pub struct Enrolled {
    /// 客户端 ID。
    pub client_id: String,
    /// 分配到的名字。
    pub name: String,
    /// 之后每次心跳都要带的令牌。
    pub agent_token: String,
    /// 心跳间隔（秒，已夹到合法区间）。
    pub heartbeat_secs: u64,
    /// 控制台对外地址。
    pub public_url: Option<String>,
    /// 归属节点的数据面坐标。
    pub node: rscross_common::NodeEndpoint,
    /// 初始隧道列表。
    pub tunnels: Vec<rscross_common::DesiredTunnel>,
}

/// 客户端注册。
pub async fn enroll(
    socket: &ControlSocket,
    token: Option<String>,
    name: Option<String>,
    runtime: ClientRuntime,
) -> Result<Enrolled> {
    let resp: ControlResponse = socket
        .request_json(|id| ControlRequest::Enroll {
            id,
            token,
            name,
            runtime,
        })
        .await?;
    match resp {
        ControlResponse::Enrolled {
            client_id,
            name,
            agent_token,
            heartbeat_secs,
            public_url,
            node,
            tunnels,
            ..
        } => Ok(Enrolled {
            client_id,
            name,
            agent_token,
            heartbeat_secs: clamp_heartbeat(heartbeat_secs),
            public_url,
            node,
            tunnels,
        }),
        other => Err(Error::api(format!("注册收到意外应答：{other:?}"))),
    }
}

/// 一次心跳的结果。
#[derive(Debug, Clone)]
pub struct Beat {
    /// 下一次心跳间隔（秒，已夹到合法区间）。
    pub heartbeat_secs: u64,
    /// 控制台观测到的出口 IP。
    pub public_ip: Option<String>,
    /// 归属节点；`None` 表示已被解绑或节点被删除，客户端应停掉隧道。
    pub node: Option<rscross_common::NodeEndpoint>,
    /// 期望的隧道配置。
    pub tunnels: Vec<rscross_common::DesiredTunnel>,
}

/// 心跳。
pub async fn heartbeat(
    socket: &ControlSocket,
    token: &str,
    runtime: ClientRuntime,
) -> Result<Beat> {
    let resp: ControlResponse = socket
        .request_json(|id| ControlRequest::Heartbeat {
            id,
            token: token.to_string(),
            runtime,
        })
        .await?;
    match resp {
        ControlResponse::Heartbeat {
            heartbeat_secs,
            server_time: _,
            public_ip,
            node,
            tunnels,
            ..
        } => Ok(Beat {
            heartbeat_secs: clamp_heartbeat(heartbeat_secs),
            public_ip,
            node,
            tunnels,
        }),
        other => Err(Error::api(format!("心跳收到意外应答：{other:?}"))),
    }
}

/// 上报日志，返回入库条数。
pub async fn push_logs(
    socket: &ControlSocket,
    token: &str,
    entries: Vec<rscross_common::ClientLogEntry>,
) -> Result<usize> {
    let resp: ControlResponse = socket
        .request_json(|id| ControlRequest::PushLogs {
            id,
            token: token.to_string(),
            entries,
        })
        .await?;
    match resp {
        ControlResponse::LogsAccepted { accepted, .. } => Ok(accepted),
        other => Err(Error::api(format!("日志上报收到意外应答：{other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ws_urls_are_rejected_with_a_reason() {
        let err = normalize_ws_url("http://c.example.com").expect_err("http 应被拒绝");
        assert!(err.to_string().contains("ws://"), "{err}");
        assert!(normalize_ws_url(" wss://a.b/ws ").is_ok());
    }

    #[test]
    fn backoff_grows_but_stays_bounded() {
        // 关键性质：单调不降、有上限 —— 否则客户端会在控制台恢复后
        // 等待几分钟才重连，看起来像「彻底断了」。
        let seq: Vec<u64> = (0..12).map(|i| backoff_for(i).as_secs()).collect();
        for w in seq.windows(2) {
            assert!(w[1] >= w[0], "退避不应下降：{seq:?}");
        }
        assert!(*seq.last().unwrap() <= MAX_BACKOFF.as_secs());
    }

    #[test]
    fn every_response_variant_carries_an_id() {
        // 少一个变体就会在这里编译失败 —— 配对表漏项表现为「应答永远等不到」，
        // 那是极难定位的故障。
        let samples = vec![
            ControlResponse::Ok { id: 1 },
            ControlResponse::Error {
                id: 2,
                code: "x".into(),
                message: "m".into(),
            },
            ControlResponse::LogsAccepted { id: 3, accepted: 1 },
        ];
        for s in samples {
            assert!(response_id(&s) > 0);
        }
    }
}