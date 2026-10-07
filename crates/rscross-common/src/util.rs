//! 通用工具函数

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

use crate::error::{AppError, AppResult};

/// 生成随机十六进制字符串，`n` 为字节长度
pub fn random_hex(n: usize) -> String {
    use rand::Rng;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill(&mut buf[..]);
    hex::encode(buf)
}

/// 生成 UUID v4 字符串
pub fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// 宽松地把字符串解析为整数，失败返回 0
///
/// 对应 Go 侧 `utils.StrMustInt` 的语义。
pub fn str_must_int(s: &str) -> i64 {
    s.trim().parse::<i64>().unwrap_or(0)
}

/// 生成用户密钥（32 位大写字母数字）
pub fn generate_key() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// 生成访客密钥
pub fn generate_vkey() -> String {
    random_hex(8)
}

/// 校验密钥格式
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 64 && key.chars().all(|c| c.is_ascii_alphanumeric())
}

/// 校验端口范围
pub fn is_valid_port(port: i64) -> bool {
    (1..=65535).contains(&port)
}

/// 校验主机名（允许通配符前缀 `*.`）
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let d = domain.strip_prefix("*.").unwrap_or(domain);
    if d.is_empty() {
        return false;
    }
    // 标签校验
    d.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// 域名通配匹配，支持 `*.example.com`
pub fn domain_match(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.example.com` 匹配 `a.example.com`，但不匹配 `a.b.example.com`
        if let Some(sub) = host.strip_suffix(suffix) {
            return !sub.is_empty() && !sub.contains('.');
        }
    }
    false
}

/// 解析监听地址，兼容 `:8080` 与 `0.0.0.0:8080`
pub fn resolve_bind_addr(addr: &str) -> AppResult<SocketAddr> {
    let normalized = if let Some(port) = addr.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else if !addr.contains(':') {
        format!("{addr}:8080")
    } else {
        addr.to_string()
    };

    normalized
        .to_socket_addrs()
        .map_err(|e| AppError::Config(format!("无法解析监听地址 {addr}: {e}")))?
        .next()
        .ok_or_else(|| AppError::Config(format!("监听地址 {addr} 无有效结果")))
}

/// 判断字符串是否为内网地址（RFC1918 / 回环 / 链路本地 / CGNAT）
pub fn is_private_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// 校验内网 IP 是否合法（允许内网与回环，拒绝公网与非法输入）
pub fn validate_target_ip(ip: &str) -> AppResult<()> {
    if ip.is_empty() {
        return Err(AppError::invalid("内网IP不能为空"));
    }
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| AppError::invalid(format!("内网IP格式错误: {ip}")))?;

    match addr {
        IpAddr::V4(v4) => {
            if v4.is_broadcast() || v4.is_multicast() {
                return Err(AppError::invalid(format!("不允许的内网IP: {ip}")));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_multicast() {
                return Err(AppError::invalid(format!("不允许的内网IP: {ip}")));
            }
        }
    }
    Ok(())
}

/// 获取本机所有非回环 IPv4 地址
pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    // UDP connect 不会真正发包，仅用于查询路由表选出的源地址
    let mut out = Vec::new();
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                if let IpAddr::V4(v4) = addr.ip() {
                    out.push(v4);
                }
            }
        }
    }
    out
}

/// 带宽限速字符串（如 `1024KB`）解析为字节/秒
///
/// 支持 `B` / `KB` / `MB` / `GB` 后缀，缺省按 `B`。
pub fn parse_bandwidth(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len()),
    );
    let value: f64 = num_part.parse().ok()?;
    let mult = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u64,
        "KB" | "K" => 1024,
        "MB" | "M" => 1024 * 1024,
        "GB" | "G" => 1024 * 1024 * 1024,
        _ => return None,
    };
    Some((value * mult as f64) as u64)
}

/// 字节数格式化为人类可读字符串
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}B")
    } else {
        format!("{v:.2}{}", UNITS[i])
    }
}

/// 转义 JSON 字符串中的 HTML 敏感字符，防止前端渲染时 XSS
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// 清理日志/命令输出中的不可见字符
pub fn sanitize_log(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(4096)
        .collect()
}

/// 判断是否为受限路径（防止目录穿越）
pub fn is_path_traversal(path: &str) -> bool {
    path.contains("..") || path.starts_with('/') || path.contains('\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth() {
        assert_eq!(parse_bandwidth("1024"), Some(1024));
        assert_eq!(parse_bandwidth("1KB"), Some(1024));
        assert_eq!(parse_bandwidth("1MB"), Some(1024 * 1024));
        assert_eq!(parse_bandwidth("1.5MB"), Some(1572864));
        assert_eq!(parse_bandwidth(""), None);
        assert_eq!(parse_bandwidth("abc"), None);
    }

    #[test]
    fn test_domain_validation() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("*.example.com"));
        assert!(is_valid_domain("a-b.example.com"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("*.com".trim_start_matches("*.")));
        assert!(!is_valid_domain("-bad.com"));
        assert!(!is_valid_domain("bad..com"));
    }

    #[test]
    fn test_domain_match() {
        assert!(domain_match("*.example.com", "a.example.com"));
        assert!(!domain_match("*.example.com", "a.b.example.com"));
        assert!(domain_match("a.com", "a.com"));
        assert!(!domain_match("a.com", "b.com"));
    }

    #[test]
    fn test_human_bytes() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(2048), "2.00KB");
    }

    #[test]
    fn test_validate_target_ip() {
        assert!(validate_target_ip("192.168.1.1").is_ok());
        assert!(validate_target_ip("127.0.0.1").is_ok());
        assert!(validate_target_ip("not-an-ip").is_err());
        assert!(validate_target_ip("").is_err());
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
    }
}
