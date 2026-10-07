//! 控制流消息：agent 与 hub 之间的 JSON over TCP 协议
//!
//! 消息以 8 字节大端长度前缀 + JSON 负载的方式在流上传输。

use serde::{Deserialize, Serialize};

use crate::ProxyType;

/// 消息类型
pub mod msg_type {
    pub const LOGIN: &str = "login";
    pub const LOGIN_RESP: &str = "login_resp";
    pub const NEW_PROXY: &str = "new_proxy";
    pub const NEW_PROXY_RESP: &str = "new_proxy_resp";
    pub const CLOSE_PROXY: &str = "close_proxy";
    pub const CLOSE_PROXY_RESP: &str = "close_proxy_resp";
    pub const NEW_WORK_CONN: &str = "new_work_conn";
    pub const NEW_WORK_CONN_RESP: &str = "new_work_conn_resp";
    pub const PING: &str = "ping";
    pub const PONG: &str = "pong";
    pub const NAT_HOLE: &str = "nat_hole";
    pub const NAT_HOLE_RESP: &str = "nat_hole_resp";
    pub const VISITOR: &str = "visitor";
    pub const VISITOR_RESP: &str = "visitor_resp";
}

/// 控制流消息信封
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// 消息类型
    #[serde(rename = "type")]
    pub msg_type: String,
    /// 版本
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// 载荷
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl Envelope {
    pub fn new(msg_type: &str, payload: serde_json::Value) -> Self {
        Self {
            msg_type: msg_type.to_string(),
            version: crate::PROTOCOL_VERSION.to_string(),
            payload: Some(payload),
        }
    }

    pub fn bare(msg_type: &str) -> Self {
        Self {
            msg_type: msg_type.to_string(),
            version: crate::PROTOCOL_VERSION.to_string(),
            payload: None,
        }
    }

    /// 反序列化载荷
    pub fn parse<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        let p = self
            .payload
            .clone()
            .ok_or_else(|| format!("{} 消息缺少载荷", self.msg_type))?;
        serde_json::from_value(p).map_err(|e| format!("载荷解析失败: {e}"))
    }

    /// 编码为字节（含长度前缀）
    pub fn encode(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).unwrap_or_default();
        let mut buf = Vec::with_capacity(json.len() + 8);
        buf.extend_from_slice(&(json.len() as u64).to_be_bytes());
        buf.extend_from_slice(&json);
        buf
    }
}

/// 登录请求（agent -> hub）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Login {
    /// 认证令牌，即节点/客户端编号
    #[serde(default)]
    pub token: String,
    /// 协议版本
    #[serde(default)]
    pub version: String,
    /// 连接池大小
    #[serde(default)]
    pub pool_count: i32,
    /// 元数据（用户名/密码等）
    #[serde(default)]
    pub metadatas: std::collections::HashMap<String, String>,
    /// 客户端主机名
    #[serde(default)]
    pub hostname: String,
}

impl Login {
    /// 认证信息
    pub fn user(&self) -> String {
        self.metadatas.get("user").cloned().unwrap_or_default()
    }

    pub fn password(&self) -> String {
        self.metadatas.get("password").cloned().unwrap_or_default()
    }
}

/// 登录响应（hub -> agent）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResp {
    /// 是否成功
    pub success: bool,
    /// 失败原因
    #[serde(default)]
    pub reason: String,
}

/// 代理配置，注册时随 NewProxy 一起提交
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfigMsg {
    /// 代理名，全局唯一
    pub name: String,
    /// 代理类型
    #[serde(rename = "type")]
    pub proxy_type: String,
    /// 认证令牌
    #[serde(default)]
    pub auth_token: String,
    /// 本地服务地址
    #[serde(default)]
    pub local_ip: String,
    /// 本地服务端口
    #[serde(default)]
    pub local_port: u16,
    /// 远程监听端口（TCP/UDP 转发用）
    #[serde(default)]
    pub remote_port: u16,
    /// 自定义域名（HTTP 代理用）
    #[serde(default)]
    pub custom_domains: Vec<String>,
    /// 私有隧道密钥
    #[serde(default)]
    pub secret_key: String,
    /// 负载均衡组
    #[serde(default)]
    pub load_balancer_group: String,
    /// 传输层配置
    #[serde(default)]
    pub transport: TransportConfig,
    /// 元数据
    #[serde(default)]
    pub metadatas: std::collections::HashMap<String, String>,
}

impl ProxyConfigMsg {
    pub fn proxy_type_enum(&self) -> Option<ProxyType> {
        ProxyType::from_str_opt(&self.proxy_type)
    }
}

/// 新代理请求（agent -> hub）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProxy {
    #[serde(flatten)]
    pub config: ProxyConfigMsg,
}

/// 新代理响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProxyResp {
    pub success: bool,
    #[serde(default)]
    pub reason: String,
    /// 实际分配的远程端口
    #[serde(default)]
    pub remote_port: u16,
}

/// 关闭代理请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseProxy {
    pub proxy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseProxyResp {
    pub success: bool,
    #[serde(default)]
    pub reason: String,
}

/// 服务端请求客户端建立工作连接（hub -> agent）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWorkConn {
    /// 对应的代理名
    pub proxy_name: String,
    /// 服务端为该连接分配的标识
    #[serde(default)]
    pub conn_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWorkConnResp {
    #[serde(default)]
    pub conn_id: String,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub reason: String,
}

/// 心跳
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    /// 距上次心跳的秒数
    #[serde(default)]
    pub interval: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    #[serde(default)]
    pub interval: i64,
}

/// P2P 打洞请求（agent -> hub -> 对端 agent）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHole {
    /// 请求方
    pub from: String,
    /// 目标代理名
    pub proxy_name: String,
    /// 打洞候选地址
    #[serde(default)]
    pub candidate_addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleResp {
    pub success: bool,
    #[serde(default)]
    pub reason: String,
    /// 目标地址
    #[serde(default)]
    pub address: String,
}

/// 访客注册（用于访问私有隧道）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Visitor {
    /// 访客名
    pub visitor_name: String,
    /// 目标代理名
    pub server_name: String,
    /// 密钥
    pub secret_key: String,
    /// 本地监听地址
    #[serde(default)]
    pub bind_addr: String,
    /// 本地监听端口
    #[serde(default)]
    pub bind_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorResp {
    pub success: bool,
    #[serde(default)]
    pub reason: String,
}

/// 传输层配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportConfig {
    /// 是否加密
    #[serde(default)]
    pub use_encryption: bool,
    /// 是否压缩
    #[serde(default)]
    pub use_compression: bool,
    /// 带宽限速，如 "128KB"
    #[serde(default)]
    pub bandwidth_limit: String,
    /// 限速模式：client / server
    #[serde(default)]
    pub bandwidth_limit_mode: String,
    /// Proxy Protocol 版本："v1" / "v2"
    #[serde(default)]
    pub proxy_protocol_version: String,
}

impl TransportConfig {
    /// 解析带宽上限为字节/秒
    pub fn bandwidth_bytes(&self) -> Option<u64> {
        rscross_common::util::parse_bandwidth(&self.bandwidth_limit)
    }
}

/// 编解码：读取一条完整消息
///
/// 协议为 8 字节大端长度前缀 + JSON。返回 `Ok(None)` 表示流已结束。
pub async fn read_message<R>(reader: &mut R) -> Result<Option<Envelope>, String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 8];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("读取长度失败: {e}")),
    }

    let len = u64::from_be_bytes(len_buf) as usize;
    // 防御恶意长度：控制流消息不会超过 1MB
    if len > 1024 * 1024 {
        return Err(format!("消息长度异常: {len}"));
    }

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("读取载荷失败: {e}"))?;

    let env: Envelope = serde_json::from_slice(&buf).map_err(|e| format!("消息解析失败: {e}"))?;
    Ok(Some(env))
}

/// 写出一条完整消息
pub async fn write_message<W>(writer: &mut W, env: &Envelope) -> Result<(), String>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let buf = env.encode();
    writer
        .write_all(&buf)
        .await
        .map_err(|e| format!("写入失败: {e}"))?;
    writer.flush().await.map_err(|e| format!("刷新失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let env = Envelope::new(msg_type::LOGIN, serde_json::json!({"token": "abc"}));
        let bytes = env.encode();
        // 8 字节长度前缀
        let len = u64::from_be_bytes(bytes[..8].try_into().unwrap()) as usize;
        assert_eq!(len, bytes.len() - 8);

        let parsed: Envelope = serde_json::from_slice(&bytes[8..]).unwrap();
        assert_eq!(parsed.msg_type, msg_type::LOGIN);
        let login: Login = parsed.parse().unwrap();
        assert_eq!(login.token, "abc");
    }

    #[test]
    fn test_proxy_config_msg() {
        let cfg = ProxyConfigMsg {
            name: "test_tcp".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 9000,
            ..Default::default()
        };
        assert_eq!(cfg.proxy_type_enum(), Some(ProxyType::Tcp));

        let env = Envelope::new(
            msg_type::NEW_PROXY,
            serde_json::to_value(&cfg).unwrap(),
        );
        let back: ProxyConfigMsg = env.parse().unwrap();
        assert_eq!(back.remote_port, 9000);
    }

    #[tokio::test]
    async fn test_read_write_message() {
        let env = Envelope::new(msg_type::PING, serde_json::json!({"interval": 30}));
        let mut buf = Vec::new();
        write_message(&mut buf, &env).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let got = read_message(&mut cursor).await.unwrap().unwrap();
        assert_eq!(got.msg_type, msg_type::PING);
        let p: Ping = got.parse().unwrap();
        assert_eq!(p.interval, 30);
    }

    #[tokio::test]
    async fn test_read_empty_stream() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(read_message(&mut cursor).await.unwrap().is_none());
    }
}
