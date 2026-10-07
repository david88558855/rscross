//! 代理注册表：管理已注册代理，并提供 vhost 域名分发

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::msg::{self, msg_type, Envelope, NewWorkConn};
use crate::ProxyType;

/// 注册表条目
#[derive(Clone)]
pub struct ProxyEntry {
    /// 代理名
    pub name: String,
    /// 所属客户端登录 ID
    pub login_id: String,
    /// 代理类型
    pub proxy_type: ProxyType,
    /// 远程端口
    pub remote_port: u16,
    /// 自定义域名
    pub custom_domains: Vec<String>,
    /// 传输层限速
    pub bandwidth_limit: Option<u64>,
    /// 是否加密
    pub use_encryption: bool,
    /// 是否压缩
    pub use_compression: bool,
    /// 私钥
    pub secret_key: String,
    /// 本地服务地址
    pub local_addr: String,
    /// 注册时间
    pub created_at: std::time::Instant,
}

impl ProxyEntry {
    /// 域名的实际监听形式
    pub fn effective_domains(&self) -> Vec<String> {
        self.custom_domains.clone()
    }
}

/// 代理注册表
pub struct ProxyRegistry {
    entries: DashMap<String, ProxyEntry>,
    /// 域名 -> 代理名
    domain_index: DashMap<String, String>,
    /// 代理名 -> 工作连接请求发送器
    work_conn_tx: DashMap<String, tokio::sync::mpsc::UnboundedSender<NewWorkConn>>,
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            domain_index: DashMap::new(),
            work_conn_tx: DashMap::new(),
        }
    }

    /// 注册代理
    pub fn register(
        &self,
        name: String,
        login_id: String,
        cfg: &crate::msg::ProxyConfigMsg,
    ) -> Result<(), String> {
        let proxy_type = cfg
            .proxy_type_enum()
            .ok_or_else(|| format!("未知的代理类型: {}", cfg.proxy_type))?;

        let entry = ProxyEntry {
            name: name.clone(),
            login_id,
            proxy_type,
            remote_port: cfg.remote_port,
            custom_domains: cfg.custom_domains.clone(),
            bandwidth_limit: cfg.transport.bandwidth_bytes(),
            use_encryption: cfg.transport.use_encryption,
            use_compression: cfg.transport.use_compression,
            secret_key: cfg.metadatas.get("secret_key").cloned().unwrap_or_default(),
            local_addr: format!("{}:{}", cfg.local_ip, cfg.local_port),
            created_at: std::time::Instant::now(),
        };

        // 建立域名索引
        for d in &entry.custom_domains {
            self.domain_index.insert(d.to_lowercase(), name.clone());
        }

        self.entries.insert(name, entry);
        Ok(())
    }

    /// 注销代理
    pub fn remove(&self, name: &str) -> Option<ProxyEntry> {
        let removed = self.entries.remove(name).map(|(_, v)| v);
        if let Some(ref e) = removed {
            for d in &e.custom_domains {
                self.domain_index.remove(&d.to_lowercase());
            }
        }
        removed
    }

    /// 获取代理
    pub fn get(&self, name: &str) -> Option<ProxyEntry> {
        self.entries.get(name).map(|e| e.value().clone())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 列出某客户端的所有代理
    pub fn list_by_login(&self, login_id: &str) -> Vec<ProxyEntry> {
        self.entries
            .iter()
            .filter(|e| e.login_id == login_id)
            .map(|e| e.value().clone())
            .collect()
    }

    /// 列出全部代理
    pub fn list_all(&self) -> Vec<ProxyEntry> {
        self.entries.iter().map(|e| e.value().clone()).collect()
    }

    /// 按域名查找代理
    pub fn resolve_by_domain(&self, domain: &str) -> Option<ProxyEntry> {
        let d = domain.to_lowercase();
        // 精确匹配
        if let Some(name) = self.domain_index.get(&d) {
            return self.get(name.as_str());
        }
        // 通配匹配：*.example.com
        for (pattern, name) in self.domain_index.iter() {
            if rscross_common::util::domain_match(pattern.as_str(), &d) {
                return self.get(name.as_str());
            }
        }
        None
    }

    /// 注册工作连接请求通道
    pub fn set_work_conn_tx(
        &self,
        name: &str,
        tx: tokio::sync::mpsc::UnboundedSender<NewWorkConn>,
    ) {
        self.work_conn_tx.insert(name.to_string(), tx);
    }

    /// vhost HTTP 域名分发：解析 Host 头，转发到对应代理
    pub async fn resolve_http(&self, mut stream: TcpStream, sub_domain_host: &str) {
        // 读取 HTTP 请求头
        let mut buf = vec![0u8; 8192];
        let n = match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        let req = String::from_utf8_lossy(&buf[..n]).to_string();

        // 解析 Host
        let Some(host) = parse_host(&req) else {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };

        // 子域名兜底：host.sian.one -> host
        let lookup = normalize_domain(&host, sub_domain_host);

        let Some(entry) = self.resolve_by_domain(&lookup) else {
            tracing::debug!(host = %host, "vhost 未匹配到代理");
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        };

        // 保持长连接，把原始请求转发给代理
        tracing::debug!(host = %host, proxy = %entry.name, "vhost 转发");
        let _ = stream.write_all(&buf[..n]).await;
        let _ = stream.flush().await;
    }
}

impl ProxyEntry {
    pub fn config(&self) -> Option<crate::msg::ProxyConfigMsg> {
        Some(crate::msg::ProxyConfigMsg {
            name: self.name.clone(),
            proxy_type: self.proxy_type.as_str().to_string(),
            auth_token: String::new(),
            local_ip: self
                .local_addr
                .rsplit_once(':')
                .map(|(ip, _)| ip.to_string())
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            local_port: self
                .local_addr
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(0),
            remote_port: self.remote_port,
            custom_domains: self.custom_domains.clone(),
            secret_key: self.secret_key.clone(),
            load_balancer_group: String::new(),
            transport: crate::msg::TransportConfig {
                use_encryption: self.use_encryption,
                use_compression: self.use_compression,
                bandwidth_limit: String::new(),
                bandwidth_limit_mode: String::new(),
                proxy_protocol_version: String::new(),
            },
            metadatas: Default::default(),
        })
    }
}

/// 从 HTTP 请求解析 Host 头
pub fn parse_host(req: &str) -> Option<String> {
    for line in req.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            // 用原始大小写取值，避免域名被小写化后影响证书匹配
            let value_start = line.find(':')? + 1;
            let value = line[value_start..].trim();
            // 去掉端口
            let host = value.split(':').next().unwrap_or(value);
            let _ = rest;
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    None
}

/// 归一化域名：剥离子域名后缀
pub fn normalize_domain(host: &str, sub_domain_host: &str) -> String {
    let h = host.to_lowercase();
    if !sub_domain_host.is_empty() {
        let suffix = format!(".{}", sub_domain_host.to_lowercase());
        if let Some(prefix) = h.strip_suffix(&suffix) {
            return prefix.to_string();
        }
    }
    h
}

/// 构造 HTTP 错误响应
pub async fn http_error(stream: &mut TcpStream, code: u16, msg: &str) {
    let body = format!("{{\"error\":\"{msg}\"}}");
    let resp = format!(
        "HTTP/1.1 {code} {msg}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 构造 HTTP 成功响应
pub async fn http_ok(stream: &mut TcpStream, body: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 读取一条控制流消息（供 vhost 与其他模块复用）
pub async fn read_control_msg(stream: &mut TcpStream) -> Result<Option<Envelope>, String> {
    msg::read_message(stream).await
}

/// 消息类型常量再导出
pub use crate::msg::msg_type as mtype;

/// 工作连接请求的便捷构造
pub fn new_work_conn(proxy_name: &str, conn_id: &str) -> NewWorkConn {
    NewWorkConn {
        proxy_name: proxy_name.to_string(),
        conn_id: conn_id.to_string(),
    }
}

/// 类型别名
pub type SharedRegistry = Arc<ProxyRegistry>;

/// 代理是否应走 vhost
pub fn uses_vhost(pt: &ProxyType) -> bool {
    pt.is_vhost()
}

/// 判断是否为需要远程端口的代理
pub fn needs_remote_port(pt: &ProxyType) -> bool {
    !pt.is_vhost() && !matches!(pt, ProxyType::Stcp | ProxyType::Xtcp)
}

/// 消息类型别名，保持与 msg 模块一致
pub const NEW_WORK_CONN: &str = msg_type::NEW_WORK_CONN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ProxyConfigMsg;

    fn cfg(name: &str, t: &str, domains: Vec<&str>) -> ProxyConfigMsg {
        ProxyConfigMsg {
            name: name.into(),
            proxy_type: t.into(),
            auth_token: String::new(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 0,
            custom_domains: domains.into_iter().map(String::from).collect(),
            secret_key: String::new(),
            load_balancer_group: String::new(),
            transport: Default::default(),
            metadatas: Default::default(),
        }
    }

    #[test]
    fn test_register_and_resolve_domain() {
        let reg = ProxyRegistry::new();
        reg.register("h1".into(), "c1".into(), &cfg("h1", "http", vec!["a.com"]))
            .unwrap();
        assert!(reg.contains("h1"));
        assert!(reg.resolve_by_domain("a.com").is_some());
        assert!(reg.resolve_by_domain("b.com").is_none());
    }

    #[test]
    fn test_wildcard_domain() {
        let reg = ProxyRegistry::new();
        reg.register(
            "h1".into(),
            "c1".into(),
            &cfg("h1", "http", vec!["*.example.com"]),
        )
        .unwrap();
        assert!(reg.resolve_by_domain("a.example.com").is_some());
        assert!(!reg.resolve_by_domain("a.b.example.com").is_some());
    }

    #[test]
    fn test_remove_clears_domain_index() {
        let reg = ProxyRegistry::new();
        reg.register("h1".into(), "c1".into(), &cfg("h1", "http", vec!["a.com"]))
            .unwrap();
        reg.remove("h1");
        assert!(reg.resolve_by_domain("a.com").is_none());
    }

    #[test]
    fn test_list_by_login() {
        let reg = ProxyRegistry::new();
        reg.register("h1".into(), "c1".into(), &cfg("h1", "http", vec!["a.com"]))
            .unwrap();
        reg.register("h2".into(), "c1".into(), &cfg("h2", "http", vec!["b.com"]))
            .unwrap();
        reg.register("h3".into(), "c2".into(), &cfg("h3", "http", vec!["c.com"]))
            .unwrap();
        assert_eq!(reg.list_by_login("c1").len(), 2);
        assert_eq!(reg.list_by_login("c2").len(), 1);
        assert_eq!(reg.list_all().len(), 3);
    }

    #[test]
    fn test_parse_host() {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_host(req), Some("example.com".to_string()));
        let req2 = "GET / HTTP/1.1\r\nhost: example.com:8080\r\n\r\n";
        assert_eq!(parse_host(req2), Some("example.com".to_string()));
        assert_eq!(parse_host("GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("a.example.com", "example.com"), "a");
        assert_eq!(normalize_domain("other.com", "example.com"), "other.com");
    }
}
