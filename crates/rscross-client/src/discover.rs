//! 控制台连接的**发现**阶段：把 `--console` 的各种写法解析成一个可连接的 ws 地址。
//!
//! 与 [`crate::wsclient`] 的分工：
//! - 本模块：纯地址决策，无长连接状态；
//! - `wsclient`：拿到地址后建立连接、收发帧、重连。
//!
//! 拆开是因为「地址算错了」和「连不上」是两种完全不同的故障，
//! 混在一个函数里会让日志同时说这两件事，反而看不出是哪一步坏的。

use std::time::Duration;

use hickory_proto::rr::RData;
use rscross_common::console::{
    normalize_console_target, plan_console_address, ConsoleAddress, ConsoleScheme, CONTROL_WS_PATH,
};
use rscross_common::{Error, Result};

/// 探测 `http(s)://` 入口时的超时。
///
/// 刻意短：这个请求只为拿一个 307，不值得让启动卡几十秒。
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// DNS TXT 查询超时。
const DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// 把 `--console` 的输入解析成最终要连接的 ws 地址。
///
/// 支持的写法（见 [`ConsoleScheme`]）：
///
/// | 写法 | 行为 |
/// |---|---|
/// | `ws://…` / `wss://…` | 不做任何解析，直接用 |
/// | `http://…` / `https://…` | 请求它，按 307 的 `Location` 得到真实地址 |
/// | `txt://域名` | 查该域名的 TXT 记录，其内容须为 ws/wss 地址 |
///
/// 每种失败都给出可操作的提示 —— 用户在这三种写法下踩的坑完全不同，
/// 笼统报「连接失败」等于让人自己猜。
pub async fn discover(spec: &str) -> Result<ConsoleAddress> {
    let addr = plan_console_address(spec)?;

    match addr.scheme {
        // 直连：路径与查询串原样保留，不补默认值。
        //
        // 这里刻意**不**自动追加 CONTROL_WS_PATH：用户写了完整地址，
        // 悄悄改路径只会让他在别处花更多时间排查。真要追加应该是显式开关。
        ConsoleScheme::Ws | ConsoleScheme::Wss => Ok(addr),

        ConsoleScheme::Http | ConsoleScheme::Https => {
            let (target, hops, discovered) = probe_redirect(&addr).await?;
            Ok(ConsoleAddress {
                spec: addr.spec,
                scheme: addr.scheme,
                authority: addr.authority,
                ws_url: target,
                hops,
                discovered: Some(discovered),
            })
        }

        ConsoleScheme::Txt => {
            let record = lookup_txt(&addr.authority).await?;
            let target = normalize_console_target(&record).map_err(|err| {
                Error::config(format!(
                    "域名 {} 的 TXT 记录内容无法用作控制台地址：{err}",
                    addr.authority
                ))
            })?;
            Ok(ConsoleAddress {
                spec: addr.spec,
                scheme: addr.scheme,
                authority: addr.authority,
                ws_url: target,
                hops: 1,
                discovered: Some(record),
            })
        }
    }
}

/// 探测 `http(s)://` 入口，按 307 的 `Location` 拿到真实地址。
///
/// 只跟随 307/308（明确的「临时/永久重定向到别处」），不跟随 301/302/303/304：
/// 那几个在 Web 语境下通常表示「这个资源换了位置，请重新 GET」，
/// 而不是「WebSocket 端点在那边」。
async fn probe_redirect(addr: &ConsoleAddress) -> Result<(String, usize, String)> {
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        // 有些反代会按 UA 拦请求，明确表明身份比被当成爬虫更好排障。
        .user_agent(format!("rscross-client/{}", rscross_common::VERSION))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::transport)?;

    let response = client
        .get(addr.spec.trim())
        // 必须显式声明不要 HTML，否则控制台的根路径会返回页面而不是
        // 307 到WebSocket 端点 —— 判据见 rscross-control 的 console::fallback：
        // 只有「明确声明不要 HTML」的请求才拿重定向。
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| {
            Error::transport(format!(
            "探测控制台入口 {} 失败：{err}（若该地址只接受 WebSocket，\
                 请直接用 ws:// 或 wss:// 填写）",
            addr.spec
        ))
    })?;

    let status = response.status();
    if !matches!(status.as_u16(), 307 | 308) {
        return Err(Error::config(format!(
            "控制台入口 {} 返回 {status}，期望 307/308 重定向到 WebSocket 地址。\
             请改用 ws:// 或 wss:// 直接填写",
            addr.spec
        )));
    }

    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Error::config(format!(
                "控制台入口 {} 返回 {status} 但没有 Location 头，无法确定真实地址",
                addr.spec
            ))
        })?
        .trim()
        .to_string();

    // Location 可能是相对路径（`/api/v1/control/ws`），按 RFC 7231 相对入口解析。
    let absolute = absolutize(&location, &addr.spec);
    let target = normalize_console_target(&absolute)?;
    Ok((target, 1, location))
}

/// 查域名的 TXT 记录，取第一条内容为 ws/wss 的。
///
/// 找不到可用记录时，把**实际查到的内容**报出来 —— TXT 里常见的问题是
/// 写成了 `wss://example.com` 却漏了端口、或者写成 `https://`，
/// 只说「没找到」的话用户得自己再查一遍 DNS。
async fn lookup_txt(domain: &str) -> Result<String> {
    // `builder_tokio()` 读系统 DNS 配置（Unix 用 /etc/resolv.conf，Windows 用注册表）——
    // 企业网络里的 split-horizon DNS 只能靠系统配置解析，自建 nameserver 会绕过它。
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(|err| Error::config(format!("初始化 DNS 解析器失败：{err}")))?;

    let lookup = tokio::time::timeout(DNS_TIMEOUT, resolver.txt_lookup(domain))
        .await
        .map_err(|_| {
            Error::config(format!(
                "查询 {domain} 的 TXT 记录超时（{DNS_TIMEOUT:?}）——\
                 请确认该域名已配置 TXT 记录，且当前网络允许 DNS 查询"
            ))
        })?
        .map_err(|err| {
            Error::config(format!(
                "查询 {domain} 的 TXT 记录失败：{err}——\
                 请确认控制台管理员已在该域名下添加 TXT 记录"
            ))
        })?;

    // 必须拿 TXT 载荷本身，不能用 Record 的 Display ——
    // 后者按 RFC 1033 输出 `<name> <ttl> <class> TXT <data>` 的完整资源记录，
    // 拿它当地址必然失败（txt:// 会永远报「不是合法的 ws:// 地址」）。
    //
    // 路径：Record 的公开字段 `data` → 匹配 `RData::TXT` → 用
    // `Display for TXT`（只渲染载荷；多段字符串在 Display 里已按 RFC 7208 拼好）。
    let mut records: Vec<String> = Vec::new();
    for record in lookup.answers() {
        if let RData::TXT(txt) = &record.data {
            let value = txt.to_string().trim().to_string();
            if !value.is_empty() {
                records.push(value);
            }
        }
    }
    if records.is_empty() {
        return Err(Error::config(format!(
            "域名 {domain} 没有 TXT 记录。\
             记录内容须形如 wss://console.example.com{CONTROL_WS_PATH}"
        )));
    }

    // 多条 TXT 时挑第一条能用的：把「哪条写错了」也报出来。
    let mut rejected = Vec::new();
    for record in &records {
        if normalize_console_target(record).is_ok() {
            if !rejected.is_empty() {
                tracing::debug!(domain, skipped = ?rejected, "TXT 记录中前几条不可用，已采用可用的一条");
            }
            return Ok(record.to_owned());
        }
        rejected.push(record.clone());
    }
    Err(Error::config(format!(
        "域名 {domain} 的 {} 条 TXT 记录都不是合法的 ws:// 或 wss:// 地址：{rejected:?}",
        records.len()
    )))
}

/// 把可能是相对路径的 Location 拼成绝对地址。
fn absolutize(location: &str, base: &str) -> String {
    let loc = location.trim();
    if loc.contains("://") {
        return loc.to_string();
    }
    // 相对路径：以 scheme + authority 为基准（够用，且不引 url 依赖）。
    let Some(idx) = base.find("://") else {
        return loc.to_string();
    };
    let after = &base[idx + 3..];
    let authority = after.split('/').next().unwrap_or(after);
    if let Some(stripped) = loc.strip_prefix('/') {
        format!(
            "{}{}{}",
            &base[..idx + 3],
            authority,
            format!("/{stripped}")
        )
    } else {
        format!("{}{}{}", &base[..idx + 3], authority, loc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolutize_handles_relative_and_absolute() {
        assert_eq!(
            absolutize("/api/v1/control/ws", "http://c.example.com:7700/x"),
            "http://c.example.com:7700/api/v1/control/ws"
        );
        assert_eq!(
            absolutize("ws://other.example.com/ws", "http://c.example.com"),
            "ws://other.example.com/ws"
        );
    }

    #[tokio::test]
    async fn ws_spec_needs_no_network() {
        let addr = discover("ws://1.2.3.4:7700").await.expect("直连不该失败");
        assert_eq!(addr.ws_url, "ws://1.2.3.4:7700");
        assert_eq!(addr.hops, 0);
    }

    #[tokio::test]
    async fn bad_spec_reports_supported_forms() {
        let err = discover("1.2.3.4:7700")
            .await
            .expect_err("缺 scheme 应报错");
        let text = err.to_string();
        // 提示里必须列出全部五种写法 —— 只说「格式错误」的话，
        // 用户得自己猜这五种里哪一种才对。
        for scheme in ["ws", "wss", "http", "https", "txt"] {
            assert!(text.contains(scheme), "提示里应列出 {scheme} 支持：{text}");
        }
        // 也要带上他实际写的那串，方便他核对是哪里写错了
        assert!(text.contains("1.2.3.4:7700"), "提示应回显原始输入：{text}");
    }

    #[tokio::test]
    async fn scheme_is_matched_case_insensitively() {
        // 用户从文档里复制 WSS:// 是很常见的；大小写不该影响解析。
        let addr = discover("WSS://c.example.com/ws")
            .await
            .expect("大小写不敏感");
        assert_eq!(addr.scheme, rscross_common::console::ConsoleScheme::Wss);
        // 关键是 host / path 原样保留 —— 路径可能大小写敏感，
        // 顺手改小写会真的连错地址。
        assert_eq!(addr.ws_url, "WSS://c.example.com/ws");
    }

    #[tokio::test]
    async fn unknown_scheme_lists_the_known_ones() {
        let err = discover("ftp://x.example.com")
            .await
            .expect_err("未知 scheme 应报错");
        let text = err.to_string();
        assert!(
            text.contains("ftp://x.example.com"),
            "应回显原始输入：{text}"
        );
        assert!(text.contains("wss"), "应列出可用写法：{text}");
    }

    #[tokio::test]
    async fn txt_pointing_at_nothing_says_so() {
        // 这个域名一定不存在 TXT —— 断言的是「错误提示可操作」，不是网络行为。
        let err = discover("txt://this-domain-should-not-exist.invalid")
            .await
            .expect_err("不存在的域名应报错");
        let text = err.to_string();
        assert!(
            text.contains("TXT"),
            "提示应说明是 TXT 解析失败，而不是笼统的网络错误：{text}"
        );
    }
}
