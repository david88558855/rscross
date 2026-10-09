//! 控制面 WebSocket 端点。
//!
//! 客户端与服务端节点都可以改走这里 —— 相比 REST 的价值是：
//! 一条连接上可以并发多个请求（心跳与日志上报交错，不必各开一条连接），
//! 且省掉每轮心跳的 TCP/TLS 握手开销。
//!
//! **设计约束：业务逻辑不重写。** 每个 `ControlRequest` 变体都转成对应的
//! `*_inner` 调用，与 REST 路径共用同一份实现。两边行为一旦分叉，就会出现
//! 「REST 能注册、WS 注册不了」这类极难定位的问题。
//!
//! 鉴权沿用原有方式（令牌 / header 语义），只是从 header 挪到帧载荷里 ——
//! 因为浏览器与部分代理不会给 WS 握手带自定义 header。

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use rscross_common::control::{
    ControlRequest, ControlResponse, Role, CONTROL_VERSION, MAX_HEARTBEAT_SECS,
    MIN_HEARTBEAT_SECS,
};
use rscross_common::NodeRuntime;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::api::{agent, nodes};
use crate::state::AppState;

/// 两条消息之间允许的最大静默时长。
///
/// 超时即判定对端失联：TCP 连接可以「看起来还在」但对端进程已经没了
/// （被 kill、被 NAT 回收），此时继续等下去就永远收不到心跳，
/// 隧道状态会一直停留在控制台的乐观假设上。
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// 单帧上限。日志批量上报是唯一的大帧来源，2 MiB 足够装下数百条。
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// `GET /api/v1/control/ws` —— WebSocket 升级。
pub async fn control_ws(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade.on_upgrade(move |socket| run_socket(socket, state, peer.ip()))
}

/// 处理一条已升级的连接。
async fn run_socket(socket: WebSocket, state: AppState, peer_ip: IpAddr) {
    // split 需要所有权，一次就够；分开 sink 与 stream 才能边收边回。
    let (mut sink, mut stream) = socket.split();

    let mut role: Option<Role> = None;
    let mut version_ok = false;

    loop {
        let next = tokio::time::timeout(IDLE_TIMEOUT, stream.next()).await;
        let frame = match next {
            Err(_) => {
                tracing::info!(?role, %peer_ip, "控制面连接静默超时，关闭");
                let _ = sink
                    .send(Message::Close(
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
                            reason: "idle timeout".into(),
                        },
                    ))
                    .await;
                return;
            }
            Ok(None) => {
                tracing::info!(?role, %peer_ip, "控制面连接已关闭");
                return;
            }
            Ok(Some(Err(err))) => {
                tracing::debug!(?role, %peer_ip, error = %err, "控制面连接出错");
                return;
            }
            Ok(Some(Ok(msg))) => msg,
        };

        let text = match msg {
            Message::Text(t) => t,
            Message::Ping(p) => {
                if sink.send(Message::Pong(p)).await.is_err() {
                    return;
                }
                continue;
            }
            Message::Pong(_) => continue,
            Message::Close(_) => return,
            Message::Binary(_) => {
                let _ = send_err(&mut sink, 0, "只接受文本帧").await;
                return;
            }
        };

        if text.len() > MAX_FRAME_BYTES {
            let _ = send_err(&mut sink, 0, "单帧过大").await;
            return;
        }

        let req: ControlRequest = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(%peer_ip, error = %err, "控制面帧解析失败");
                if send_err(&mut sink, 0, "帧格式非法").await.is_err() {
                    return;
                }
                continue;
            }
        };
        let id = req.id();

        // 版本协商必须是第一条：版本不同的帧语义可能完全不同，
        // 后面所有请求都依赖它已经达成一致。
        if !version_ok && !matches!(req, ControlRequest::Hello { .. }) {
            if send_err(&mut sink, id, "首帧必须是版本协商").await.is_err() {
                return;
            }
            continue;
        }

        let resp = match req {
            ControlRequest::Hello { id, version } => {
                if version != CONTROL_VERSION {
                    tracing::warn!(%peer_ip, client = version, server = CONTROL_VERSION, "控制面协议版本不一致");
                    let _ = send_resp(
                        &mut sink,
                        ControlResponse::Error {
                            id,
                            message: format!(
                                "控制面协议版本不一致：本端 {CONTROL_VERSION}，你的 {version}"
                            ),
                        },
                    )
                    .await;
                    return;
                }
                version_ok = true;
                ControlResponse::Welcome {
                    id,
                    version: CONTROL_VERSION,
                }
            }

            ControlRequest::Enroll {
                id,
                token,
                name,
                runtime,
            } => {
                role = Some(Role::Agent);
                let req = agent::EnrollRequest {
                    token,
                    name,
                    runtime: to_client_runtime(runtime),
                };
                match agent::enroll_inner(&state, req, peer_ip).await {
                    Ok(r) => ControlResponse::Enrolled {
                        id,
                        client_id: r.client_id,
                        name: r.name,
                        agent_token: r.agent_token,
                        heartbeat_secs: clamp_heartbeat(r.heartbeat_secs),
                        public_url: r.public_url,
                        node: r.node,
                        tunnels: r.tunnels,
                    },
                    Err(err) => err.into_control_response(id),
                }
            }

            ControlRequest::Heartbeat {
                id,
                token,
                runtime,
            } => {
                let mut headers = HeaderMap::new();
                if let Ok(v) = token.parse() {
                    headers.insert(crate::api::AGENT_HEADER, v);
                }
                let req = agent::HeartbeatRequest {
                    runtime: to_client_runtime(runtime),
                };
                match agent::heartbeat_inner(&state, &headers, req, peer_ip).await {
                    Ok(r) => ControlResponse::Heartbeat {
                        id,
                        heartbeat_secs: clamp_heartbeat(r.heartbeat_secs),
                        server_time: r.server_time,
                        public_ip: r.public_ip,
                        node: r.node,
                        tunnels: r.tunnels,
                    },
                    Err(err) => err.into_control_response(id),
                }
            }

            ControlRequest::PushLogs {
                id,
                token,
                entries,
            } => {
                let mut headers = HeaderMap::new();
                if let Ok(v) = token.parse() {
                    headers.insert(crate::api::AGENT_HEADER, v);
                }
                match agent::push_logs_inner(&state, &headers, entries).await {
                    Ok(accepted) => ControlResponse::LogsAccepted { id, accepted },
                    Err(err) => err.into_control_response(id),
                }
            }

            ControlRequest::NodeEnroll {
                id,
                token,
                name,
                runtime,
            } => {
                role = Some(Role::Node);
                let token = token.unwrap_or_default();
                match nodes::node_enroll_inner(&state, &token, name, runtime, peer_ip).await {
                    Ok(r) => ControlResponse::NodeEnrolled {
                        id,
                        node_id: r.node_id,
                        name: r.name,
                        tunnel_token: r.tunnel_token,
                        heartbeat_secs: clamp_heartbeat(r.heartbeat_secs),
                        public_url: r.public_url,
                    },
                    Err(err) => err.into_control_response(id),
                }
            }

            ControlRequest::NodeHeartbeat {
                id,
                token,
                runtime,
            } => {
                let mut headers = HeaderMap::new();
                if let Ok(v) = token.parse() {
                    headers.insert(crate::api::NODE_HEADER, v);
                }
                match nodes::node_heartbeat_inner(&state, &headers, runtime, peer_ip).await {
                    Ok(r) => ControlResponse::NodeHeartbeat {
                        id,
                        heartbeat_secs: clamp_heartbeat(r.heartbeat_secs),
                        server_time: r.server_time,
                        public_ip: r.public_ip,
                        tunnel_token: r.tunnel_token,
                        tunnels: r.tunnels,
                    },
                    Err(err) => err.into_control_response(id),
                }
            }

            ControlRequest::NodeSelf { id, token } => {
                let mut headers = HeaderMap::new();
                if let Ok(v) = token.parse() {
                    headers.insert(crate::api::NODE_HEADER, v);
                }
                match nodes::node_self_inner(&state, &headers).await {
                    Ok(node) => {
                        // NodeRecord 含仅内部可见的 node_token_hash，直接序列化会泄漏摘要。
                        match serde_json::to_value(&node) {
                            Ok(v) => ControlResponse::NodeSelf { id, node: v },
                            Err(err) => {
                                tracing::warn!(error = %err, "节点记录序列化失败");
                                send_err(&mut sink, id, "节点记录序列化失败").await.ok();
                                continue;
                            }
                        }
                    }
                    Err(err) => err.into_control_response(id),
                }
            }
        };

        if send_resp(&mut sink, resp).await.is_err() {
            return;
        }
    }
}

async fn send_resp<S>(sink: &mut S, resp: ControlResponse) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    let text = serde_json::to_string(&resp).map_err(|_| ())?;
    sink.send(Message::Text(text.into())).await.map_err(|_| ())
}

async fn send_err<S>(sink: &mut S, id: u64, message: &str) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    send_resp(sink, ControlResponse::Error { id, message: message.to_string() }).await
}

fn clamp_heartbeat(secs: u64) -> u64 {
    secs.clamp(MIN_HEARTBEAT_SECS, MAX_HEARTBEAT_SECS)
}

fn to_client_runtime(rt: NodeRuntime) -> rscross_common::ClientRuntime {
    rscross_common::ClientRuntime {
        version: rt.version,
        os: rt.os,
        arch: rt.arch,
        endpoint_id: rt.endpoint_id,
        endpoint_addr: rt.endpoint_addr,
    }
}

/// 供测试与文档引用：连接上可以承载的角色。
pub const ROLES: &[Role] = &[Role::Agent, Role::Node];

/// 便捷函数：把帧序列化成文本（客户端侧与 e2e 共用同一套编解码）。
pub fn encode_frame(resp: &ControlResponse) -> String {
    serde_json::to_string(resp).unwrap_or_else(|_| "{\"type\":\"error\"}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_with_a_stable_type_tag() {
        // 帧的 `type` 标签是协议的一部分（客户端按它分派），改名等于破坏兼容。
        let resp = ControlResponse::Ok { id: 7 };
        let text = encode_frame(&resp);
        assert!(text.contains("\"type\":\"ok\""), "{text}");
        assert!(text.contains("\"id\":7"), "{text}");
        let back: ControlResponse = serde_json::from_str(&text).expect("应能反序列化");
        assert!(back.is_ok());
    }

    #[test]
    fn error_carries_a_code_the_client_can_branch_on() {
        let resp = ControlResponse::error(3, "unauthorized", "接入令牌无效");
        let text = encode_frame(&resp);
        assert!(text.contains("\"code\":\"unauthorized\""), "{text}");
        assert!(!resp_is_ok(&resp));
    }

    fn resp_is_ok(r: &ControlResponse) -> bool {
        r.is_ok()
    }

    #[test]
    fn heartbeat_is_clamped_into_a_sane_range() {
        // 心跳间隔直接来自控制台配置；0 或超大都会让客户端要么空转要么收不到状态。
        assert_eq!(clamp_heartbeat(0), MIN_HEARTBEAT_SECS);
        assert_eq!(clamp_heartbeat(1_000_000), MAX_HEARTBEAT_SECS);
        assert_eq!(clamp_heartbeat(30), 30);
    }
}