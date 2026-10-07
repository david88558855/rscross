//! NAT 打洞：支撑 XTCP 的 P2P 直连
//!
//! 完整实现需要 STUN 与 UDP 打洞。本模块提供 STUN 候选地址发现与
//! 打洞协调的核心逻辑，P2P 直连失败时上层回退到 STCP 中继。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::msg::{self, msg_type, Envelope, NatHole, NatHoleResp};

/// 打洞结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoleResult {
    /// P2P 直连成功，地址为对端候选地址
    Direct(SocketAddr),
    /// 需要回退到中继
    Relay,
    /// 打洞失败
    Failed(String),
}

/// STUN 服务器地址
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// 发现本机候选地址
///
/// 通过向 STUN 服务器发送 binding 请求获取公网映射地址。
/// 网络受限时会返回空列表，由上层回退到中继模式。
pub async fn discover_candidates(timeout_ms: u64) -> Vec<String> {
    let mut out = Vec::new();

    for server in DEFAULT_STUN_SERVERS {
        match query_stun(server, timeout_ms).await {
            Some(addr) => out.push(addr),
            None => continue,
        }
    }

    out
}

/// 向单个 STUN 服务器查询映射地址
async fn query_stun(server: &str, timeout_ms: u64) -> Option<String> {
    let bind_addr = "0.0.0.0:0";
    let socket = UdpSocket::bind(bind_addr).await.ok()?;

    // 解析 STUN 服务器地址
    let target = tokio::net::lookup_host(server).await.ok()?.next()?;

    // STUN binding request：magic cookie 0x2112A442
    let mut req = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
    socket.send_to(&req, target).await.ok()?;

    let mut buf = vec![0u8; 512];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf),
    )
    .await
    .ok()?
    .ok()?;

    parse_stun_response(&buf[..n])
}

/// 解析 STUN binding response，提取 XOR-MAPPED-ADDRESS
pub fn parse_stun_response(data: &[u8]) -> Option<String> {
    if data.len() < 20 {
        return None;
    }
    // 校验消息类型为 binding response
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return None;
    }
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut offset = 20;
    let end = std::cmp::min(20 + msg_len, data.len());

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > data.len() {
            break;
        }
        // XOR-MAPPED-ADDRESS
        if attr_type == 0x0020 && attr_len >= 8 {
            let family = data[offset + 1];
            let xport = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) ^ 0x2112;
            if family == 0x01 {
                // IPv4：地址与 magic cookie 异或
                let cookie = [0x21u8, 0x12, 0xA4, 0x42];
                let mut ip = [0u8; 4];
                for i in 0..4 {
                    ip[i] = data[offset + 4 + i] ^ cookie[i];
                }
                return Some(format!(
                    "{}:{}",
                    std::net::Ipv4Addr::from(ip),
                    xport
                ));
            }
        }
        // 对齐到 4 字节边界
        offset += attr_len + (4 - attr_len % 4) % 4;
    }
    None
}

/// 打洞协调器：协助两个客户端建立 P2P 直连
pub struct NatHoleCoordinator {
    /// 代理名 -> 等待中的请求方地址
    waiters: dashmap::DashMap<String, Vec<SocketAddr>>,
}

impl Default for NatHoleCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl NatHoleCoordinator {
    pub fn new() -> Self {
        Self {
            waiters: dashmap::DashMap::new(),
        }
    }

    /// 注册等待打洞的一方
    pub fn register(&self, proxy_name: &str, addr: SocketAddr) {
        self.waiters
            .entry(proxy_name.to_string())
            .or_default()
            .push(addr);
    }

    /// 取出并清空等待者
    pub fn take_waiters(&self, proxy_name: &str) -> Vec<SocketAddr> {
        self.waiters
            .remove(proxy_name)
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    /// 协调一次打洞，返回结果
    pub async fn coordinate(
        self: &Arc<Self>,
        stream: &mut tokio::net::TcpStream,
        req: &NatHole,
    ) -> Result<HoleResult, String> {
        let waiters = self.take_waiters(&req.proxy_name);
        if waiters.is_empty() {
            let resp = Envelope::new(
                msg_type::NAT_HOLE_RESP,
                serde_json::to_value(NatHoleResp {
                    success: false,
                    reason: "目标未就绪，需回退中继".to_string(),
                    address: String::new(),
                })
                .unwrap(),
            );
            msg::write_message(stream, &resp).await?;
            return Ok(HoleResult::Relay);
        }

        // 返回第一个可用地址
        let target = waiters[0];
        let resp = Envelope::new(
            msg_type::NAT_HOLE_RESP,
            serde_json::to_value(NatHoleResp {
                success: true,
                reason: String::new(),
                address: target.to_string(),
            })
            .unwrap(),
        );
        msg::write_message(stream, &resp).await?;
        Ok(HoleResult::Direct(target))
    }
}

/// 判断 NAT 类型是否友好（简化判断：仅看是否有公网候选地址）
pub fn is_p2p_friendly(candidates: &[String]) -> bool {
    !candidates.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stun_response_ipv4() {
        // 构造一个 XOR-MAPPED-ADDRESS 响应
        let mut data = vec![0x00, 0x01, 0x00, 0x0c]; // msg type + len
        data.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // cookie
        data.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]); // attr type + len
        data.push(0x00);
        data.push(0x01); // family IPv4
        data.push(0xAB); // port hi (will xor)
        data.push(0xCD); // port lo
        data.extend_from_slice(&[1, 2, 3, 4]); // ip (will xor with cookie)

        let parsed = parse_stun_response(&data);
        assert!(parsed.is_some());
        let s = parsed.unwrap();
        // 端口 0xABCD ^ 0x2112 = 0x8ABF
        assert!(s.ends_with(":35519"), "got {s}");
        // IP 1^0x21=0x20, 2^0x12=0x10, 3^0xA4=0xA7, 4^0x42=0x46 -> 32.16.167.70
        assert!(s.starts_with("32.16.167.70"), "got {s}");
    }

    #[test]
    fn test_parse_stun_invalid() {
        assert!(parse_stun_response(&[]).is_none());
        assert!(parse_stun_response(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_coordinator_register_and_take() {
        let c = NatHoleCoordinator::new();
        c.register("p1", "1.1.1.1:1000".parse().unwrap());
        c.register("p1", "2.2.2.2:2000".parse().unwrap());
        let taken = c.take_waiters("p1");
        assert_eq!(taken.len(), 2);
        assert!(c.take_waiters("p1").is_empty());
    }

    #[test]
    fn test_is_p2p_friendly() {
        assert!(!is_p2p_friendly(&[]));
        assert!(is_p2p_friendly(&["1.2.3.4:5678".to_string()]));
    }
}
