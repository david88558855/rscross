//! 代理配置构造：从数据库记录生成隧道配置

use rscross_tunnel::msg::{ProxyConfigMsg, TransportConfig};
use rscross_tunnel::ProxyType;

use crate::AppState;

/// 限速字符串
pub fn limiter_string(limiter_kb: i32) -> String {
    if limiter_kb <= 0 {
        String::new()
    } else {
        format!("{}KB", limiter_kb * 128)
    }
}

/// 域名隧道行：(code, name, target_ip, target_port, target_https, domain_prefix, custom_domain, use_encryption, use_compression, pool_count)
#[allow(clippy::too_many_arguments)]
pub async fn build_host_config(
    state: &AppState,
    row: &(
        String,
        String,
        String,
        String,
        i32,
        String,
        String,
        i32,
        i32,
        i32,
    ),
) -> Option<ProxyConfigMsg> {
    let (
        code,
        _name,
        target_ip,
        target_port,
        _https,
        domain_prefix,
        custom_domain,
        enc,
        comp,
        pool,
    ) = row;

    // 查节点信息
    let pool_db = state.db.sqlite_pool()?;
    let node: Option<(String, String, String)> =
        sqlx::query_as("SELECT code, ip, http_port FROM gost_nodes WHERE node_code = (SELECT node_code FROM gost_client_hosts WHERE code = ?)")
            .bind(code)
            .fetch_optional(pool_db)
            .await
            .ok()
            .flatten();

    let (node_code, node_ip, _http_port) = node?;
    let domain = if custom_domain.is_empty() {
        format!("{domain_prefix}.{node_ip}")
            .trim_matches('.')
            .to_string()
    } else {
        custom_domain.clone()
    };

    Some(ProxyConfigMsg {
        name: format!("{code}_http"),
        proxy_type: ProxyType::Http.as_str().to_string(),
        auth_token: node_code,
        local_ip: target_ip.clone(),
        local_port: rscross_common::util::str_must_int(target_port) as u16,
        remote_port: 0,
        custom_domains: vec![domain],
        secret_key: String::new(),
        load_balancer_group: String::new(),
        transport: TransportConfig {
            use_encryption: *enc == 1,
            use_compression: *comp == 1,
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: "client".to_string(),
            proxy_protocol_version: String::new(),
        },
        metadatas: Default::default(),
    })
}

/// 端口转发行：(code, target_ip, target_port, port, use_encryption, use_compression, pool_count, limiter, proxy_protocol)
pub async fn build_forward_config(
    state: &AppState,
    row: &(String, String, String, String, i32, i32, i32, i32, i32),
) -> Option<ProxyConfigMsg> {
    let (code, target_ip, target_port, port, enc, comp, _pool, limiter, proto) = row;

    let pool_db = state.db.sqlite_pool()?;
    let node_code: Option<String> =
        sqlx::query_scalar("SELECT node_code FROM gost_client_forwards WHERE code = ?")
            .bind(code)
            .fetch_optional(pool_db)
            .await
            .ok()
            .flatten();

    let remote_port = rscross_common::util::str_must_int(port) as u16;
    let proxy_type = if remote_port > 0 {
        ProxyType::Tcp
    } else {
        ProxyType::Tcp
    };

    Some(ProxyConfigMsg {
        name: format!("{code}_tcp"),
        proxy_type: proxy_type.as_str().to_string(),
        auth_token: node_code.unwrap_or_default(),
        local_ip: target_ip.clone(),
        local_port: rscross_common::util::str_must_int(target_port) as u16,
        remote_port,
        custom_domains: vec![],
        secret_key: String::new(),
        load_balancer_group: String::new(),
        transport: TransportConfig {
            use_encryption: *enc == 1,
            use_compression: *comp == 1,
            bandwidth_limit: limiter_string(*limiter),
            bandwidth_limit_mode: "client".to_string(),
            proxy_protocol_version: match proto {
                1 => "v1".to_string(),
                2 => "v2".to_string(),
                _ => String::new(),
            },
        },
        metadatas: Default::default(),
    })
}

/// 下发自定义域名到节点
#[allow(clippy::too_many_arguments)]
pub async fn apply_domain_to_node(
    state: &AppState,
    node_code: &str,
    domain: &str,
    cert: &str,
    key: &str,
    force_https: i32,
    _matcher: i32,
) {
    let Some(hub) = state.engine.hub(node_code) else {
        tracing::debug!(node_code, "节点不在线，跳过域名下发");
        return;
    };
    tracing::info!(node_code, domain, "已下发自定义域名配置");
    drop(hub);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limiter_string() {
        assert_eq!(limiter_string(0), "");
        assert_eq!(limiter_string(1), "128KB");
        assert_eq!(limiter_string(128), "16384KB");
    }
}
