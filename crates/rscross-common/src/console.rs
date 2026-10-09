//! 控制台连接地址的解析（按 scheme 分派）。
//!
//! `--console` 支持三种写法，最终都收敛成一个 `ws://` 或 `wss://` 地址：
//!
//! | 写法 | 语义 |
//! |---|---|
//! | `ws://…` / `wss://…` | 就是真实地址，不做任何解析，直接使用 |
//! | `http://…` / `https://…` | **发现入口**：向它发一次请求，按 307 的 `Location` 得到真实地址 |
//! | `txt://域名` | **DNS 发现**：查该域名的 TXT 记录，其内容须为 `ws://` / `wss://` 地址 |
//!
//! 为什么保留 `http://` 而不是删掉：已经有人照着旧文档把
//! `--console http://…` 写进了脚本与服务配置。让这个入口继续工作、
//! 只是把语义改成「去问真实地址在哪」，比直接报错友好得多。
//!
//! 本模块**只做解析与形态校验，不发起任何网络请求** ——
//! 真正的发现动作由调用方执行，因此这里的行为可以完全用单测覆盖，
//! 不需要真的有 DNS 或可达的控制台。

use crate::{Error, Result};

/// 控制台的 WebSocket 控制面端点路径。
pub const CONTROL_WS_PATH: &str = "/api/v1/control/ws";

/// 控制台地址的 scheme。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConsoleScheme {
    /// `ws://`
    #[default]
    Ws,
    /// `wss://`
    Wss,
    /// `http://` —— 仅作发现入口
    Http,
    /// `https://` —— 同上
    Https,
    /// `txt://` —— 走 DNS TXT 发现
    Txt,
}

impl ConsoleScheme {
    /// 支持的 scheme 列表（错误信息与帮助文案用）。
    pub const ALL: [&'static str; 5] = ["ws", "wss", "http", "https", "txt"];

    /// scheme 的字符串形式（生成命令与日志用）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ws => "ws",
            Self::Wss => "wss",
            Self::Http => "http",
            Self::Https => "https",
            Self::Txt => "txt",
        }
    }

    /// 解析 scheme（不区分大小写，忽略两侧空白）。
    pub fn parse(scheme: &str) -> Option<Self> {
        match scheme.trim().to_ascii_lowercase().as_str() {
            "ws" => Some(Self::Ws),
            "wss" => Some(Self::Wss),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "txt" => Some(Self::Txt),
            _ => None,
        }
    }

    /// 拆出 scheme 与 `://` 之后的剩余部分。
    ///
    /// 匹配顺序刻意从长到短：`https://` 不会被 `http://` 误吞，
    /// `wss://` 也不会被 `ws://` 误吞。
    pub fn split(spec: &str) -> Result<(Self, &str)> {
        let spec = spec.trim();
        let candidates: [(&str, ConsoleScheme); 5] = [
            ("https://", ConsoleScheme::Https),
            ("http://", ConsoleScheme::Http),
            ("wss://", ConsoleScheme::Wss),
            ("ws://", ConsoleScheme::Ws),
            ("txt://", ConsoleScheme::Txt),
        ];
        // 只对「scheme 那几个字符」做大小写无关比较，`://` 之后的 host
        // 原样保留 —— 主机名大小写本来不敏感，但路径可能大小写敏感，
        // 顺手改掉会真的连错地址。
        //
        // 用户从文档里复制 `WSS://…` 是很常见的，值得多这一步。
        let prefix_len = spec.find("://").map(|i| i + 3).unwrap_or(0);
        let (head, tail) = spec.split_at(prefix_len);
        for (prefix, scheme) in candidates {
            if head.eq_ignore_ascii_case(prefix) {
                return Ok((scheme, tail));
            }
        }
        Err(Error::config(format!(
            "控制台地址应以 scheme:// 开头（支持 {}）：{spec}",
            ConsoleScheme::ALL.join(" / ")
        )))
    }

    /// 是否可以直接用来建立 WebSocket 连接。
    pub fn is_direct(self) -> bool {
        matches!(self, Self::Ws | Self::Wss)
    }

    /// 是否需要先做一次发现（HTTP 307 或 DNS TXT）。
    pub fn needs_discovery(self) -> bool {
        !self.is_direct()
    }

    /// 映射到 WebSocket scheme：`http` → `ws`、`https` → `wss`。
    ///
    /// 只改「是否加密」这一件事，host / 端口 / 路径原样保留 ——
    /// 否则 `http://h:7700/p/ws` 会在「顺手规范化」时被悄悄改掉路径。
    pub fn ws_scheme(self) -> Option<&'static str> {
        match self {
            Self::Ws | Self::Http => Some("ws"),
            Self::Wss | Self::Https => Some("wss"),
            Self::Txt => None,
        }
    }
}

impl std::fmt::Display for ConsoleScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// 解析后的「怎么得到真实连接地址」计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsolePlan {
    /// 输入本身就是真实地址，直接用。
    Direct(String),

    /// 先向 `probe_url` 发一次请求，按 307 的 `Location` 得到真实地址。
    ///
    /// `fallback` 是发现失败时仍要尝试的地址（由 scheme 映射而来）。
    /// 保留兜底是因为「入口挂了」与「控制台挂了」是两件事：
    /// 只有前者时，直连默认地址仍然能通，不该把整条连接一起判死。
    Redirect {
        /// 要请求的入口地址。
        probe_url: String,
        /// 发现失败时的兜底地址。
        fallback: String,
    },

    /// 先查 `domain` 的 TXT 记录，其内容须为 `ws://` / `wss://` 地址。
    DnsTxt {
        /// 待查询的域名（已去掉 `txt://` 前缀）。
        domain: String,
    },
}

/// 解析 `--console` 输入的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleAddress {
    /// 用户的原始输入（日志与排障用：能直接看到他写的是什么）。
    pub spec: String,
    /// 输入里声明的 scheme。
    pub scheme: ConsoleScheme,
    /// `://` 之后的完整部分（含路径），排障时比对用。
    pub authority: String,
    /// **最终实际建立连接的地址**（`ws://` 或 `wss://`）。
    pub ws_url: String,
    /// 经过的发现跳数（0 = 直接使用，未做发现）。
    pub hops: usize,
    /// 通过 `txt://` 发现时的原始记录内容（便于核对 DNS 到底返回了什么）。
    pub discovered: Option<String>,
}

impl ConsoleAddress {
    /// 用 `ws://` / `wss://` 地址构造（不经过发现）。
    pub fn direct(spec: &str) -> Self {
        let raw = spec.trim();
        Self {
            spec: raw.to_string(),
            scheme: ConsoleScheme::default(),
            authority: raw.split("://").nth(1).unwrap_or(raw).to_string(),
            ws_url: raw.to_string(),
            hops: 0,
            discovered: None,
        }
    }
}

/// 解析一条 `--console` 输入。
///
/// 只判断**写法**，不发起任何请求（发现动作由调用方执行）：
///
/// - `ws://…` / `wss://…` → [`ConsolePlan::Direct`]，**原样保留**路径与查询串；
/// - `http://…` / `https://…` → [`ConsolePlan::Redirect`]，记录入口并按
///   `http→ws`、`https→wss` 给出兜底地址；
/// - `txt://域名` → [`ConsolePlan::DnsTxt`]，记录待查询的域名；
/// - 其它（无 scheme、未知 scheme、缺主机）→ 报错，消息里列出支持的写法。
pub fn plan_console_address(spec: &str) -> Result<ConsoleAddress> {
    let raw = spec.trim();
    let (scheme, rest) = ConsoleScheme::split(raw)?;
    let authority = rest.trim_matches('/');
    if authority.is_empty() {
        return Err(Error::config(format!("控制台地址缺少主机部分：{raw}")));
    }

    match scheme {
        ConsoleScheme::Ws | ConsoleScheme::Wss => Ok(ConsoleAddress {
            spec: raw.to_string(),
            scheme,
            authority: authority.to_string(),
            ws_url: raw.to_string(),
            hops: 0,
            discovered: None,
        }),
        ConsoleScheme::Http | ConsoleScheme::Https => {
            let fallback = http_to_ws(raw);
            Ok(ConsoleAddress {
                spec: raw.to_string(),
                scheme,
                authority: authority.to_string(),
                ws_url: fallback.trim_end_matches('/').to_string(),
                // 还没探测；真正探测到 307 之后调用方才把它改成实际跳数。
                hops: 0,
                discovered: None,
            })
        }
        ConsoleScheme::Txt => Ok(ConsoleAddress {
            spec: raw.to_string(),
            scheme,
            authority: authority.to_string(),
            // 真实地址要等 DNS 查询才知道
            ws_url: String::new(),
            hops: 0,
            discovered: None,
        }),
    }
}

/// 把 http(s) 地址映射成 ws(s) 地址；不认识就原样返回。
///
/// 这是「保留 `http://` 入口」的另一半：入口本身不用于建连接，
/// 真正的地址由 scheme 映射得到。所以就算发现流程失败，也总有一个可用的默认地址。
pub fn http_to_ws(spec: &str) -> String {
    let trimmed = spec.trim();
    if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        trimmed.to_string()
    }
}

/// 校验「发现出来的地址」能不能直接拿来连接。
///
/// 只接受 `ws://` / `wss://`；`http(s)://` 会按同一个映射规则转换；
/// 空串或其它写法一律报错 —— 因为 `txt://` 是管理员在 DNS 里手填的，
/// 写错了就该在日志里说清楚，而不是让客户端拿着一个畸形地址去连。
pub fn normalize_console_target(candidate: &str) -> Result<String> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return Err(Error::config("发现到的控制台地址为空"));
    }
    if candidate.starts_with("ws://") {
        return Ok(candidate.to_string());
    }
    if candidate.starts_with("wss://") {
        return Ok(candidate.to_string());
    }
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        return Ok(http_to_ws(candidate));
    }
    Err(Error::config(format!(
        "发现到的地址必须以 ws:// 或 wss:// 开头（实际是 {candidate:?}），\
         请检查 DNS TXT 记录的内容"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_urls_pass_through_untouched() {
        // 关键是「不解析」：路径与查询串都要原样保留
        for spec in ["ws://1.2.3.4:7700", "wss://c.example.com/ws?token=1"] {
            let addr = plan_console_address(spec).expect(spec);
            assert_eq!(addr.ws_url, spec, "{spec} 应原样保留");
            assert_eq!(addr.hops, 0, "直接使用不该有发现跳数");
        }
    }

    #[test]
    fn http_schemes_need_discovery_and_keep_paths() {
        let cases = [
            ("http://h:7700", "ws://h:7700"),
            ("https://c.example.com", "wss://c.example.com"),
            ("http://h/p/ws", "ws://h/p/ws"),
        ];
        for (spec, expected) in cases {
            let addr = plan_console_address(spec).expect(spec);
            assert_eq!(addr.ws_url, expected, "{spec} 的兜底地址应为 {expected}");
            assert!(
                addr.scheme.needs_discovery(),
                "http(s) 只是发现入口，必须再去问真实地址"
            );
        }
    }

    #[test]
    fn txt_records_domain_without_a_url_yet() {
        let addr = plan_console_address("txt://rscross.example.com").expect("txt");
        assert_eq!(addr.scheme, ConsoleScheme::Txt);
        assert_eq!(addr.authority, "rscross.example.com");
        assert!(addr.ws_url.is_empty(), "真实地址要等 DNS 查询才知道");
        assert!(addr.discovered.is_none());
    }

    #[test]
    fn scheme_strings_round_trip() {
        for scheme in [
            ConsoleScheme::Ws,
            ConsoleScheme::Wss,
            ConsoleScheme::Http,
            ConsoleScheme::Https,
            ConsoleScheme::Txt,
        ] {
            assert_eq!(ConsoleScheme::parse(scheme.as_str()), Some(scheme));
        }
        assert_eq!(ConsoleScheme::parse("WSS"), Some(ConsoleScheme::Wss));
    }

    #[test]
    fn scheme_mapping_touches_only_encryption() {
        assert_eq!(ConsoleScheme::Http.ws_scheme(), Some("ws"));
        assert_eq!(ConsoleScheme::Https.ws_scheme(), Some("wss"));
        assert_eq!(ConsoleScheme::Ws.ws_scheme(), Some("ws"));
        assert_eq!(ConsoleScheme::Wss.ws_scheme(), Some("wss"));
        assert_eq!(
            ConsoleScheme::Txt.ws_scheme(),
            None,
            "txt:// 不是可直接连接的协议"
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        for bad in ["1.2.3.4:7700", "ftp://host", "ws://", "txt://", "   "] {
            plan_console_address(bad).expect_err(bad);
        }
    }
}
