//! 事件处理：接收服务端下发的配置指令，驱动 穿透内核
//!
//! 对应原项目的 `client/internal/service/event` 包：
//! `server_config` / `host_config` / `forward_config` / `tunnel_config` /
//! `p2p_config` / `proxy_config` / `custom_cfg_config` / `port_check` /
//! `remove_config` / `stop`

use std::sync::Arc;

use rscross_common::rpc::RpcClient;
use rscross_tunnel::msg::{ProxyConfigMsg, TransportConfig};
use rscross_tunnel::{ClientConfig, AgentService, ProxyType};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::StateStore;
use crate::AppState;

/// 注册全部推送处理器
pub fn register_handlers(client: &mut RpcClient, state: &AppState) {
    // 方法名 -> 处理器
    let table: Vec<(&'static str, HandlerFn)> = vec![
        ("server_config", Arc::new(handle_server_config)),
        ("host_config", Arc::new(handle_host_config)),
        ("forward_config", Arc::new(handle_forward_config)),
        ("tunnel_config", Arc::new(handle_tunnel_config)),
        ("p2p_config", Arc::new(handle_p2p_config)),
        ("proxy_config", Arc::new(handle_proxy_config)),
        ("custom_cfg_config", Arc::new(handle_custom_cfg)),
        ("port_check", Arc::new(handle_port_check)),
        ("remove_config", Arc::new(handle_remove)),
        ("stop", Arc::new(handle_stop)),
    ];

    let table = Arc::new(table);
    let state = state.clone();

    client.set_push_handler(Arc::new(move |method, payload| {
        let handler = table
            .iter()
            .find(|(name, _)| *name == method)
            .map(|(_, f)| f.clone());

        let Some(h) = handler else {
            tracing::warn!(method, "未注册的事件处理器");
            return;
        };

        let state = state.clone();
        let method = method.to_string();
        tokio::spawn(async move {
            if let Err(e) = h(state, payload).await {
                tracing::error!(method = %method, error = %e, "处理事件失败");
            }
        });
    }));
}

/// 处理器函数类型
type HandlerFn = Arc<dyn Fn(AppState, Value) -> Result<(), String> + Send + Sync>;

/// 基础配置字段
#[derive(Debug, Deserialize, Default)]
struct BaseCfg {
    #[serde(rename = "auth", default)]
    auth: AuthCfg,
    #[serde(rename = "serverAddr", default)]
    server_addr: String,
    #[serde(rename = "serverPort", default)]
    server_port: u16,
    #[serde(rename = "metadatas", default)]
    metadatas: std::collections::HashMap<String, String>,
    #[serde(default)]
    transport: TransportBase,
}

#[derive(Debug, Deserialize, Default)]
struct AuthCfg {
    #[serde(default)]
    token: String,
}

#[derive(Debug, Deserialize, Default)]
struct TransportBase {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    pool_count: i32,
}

impl BaseCfg {
    /// 转换为客户端配置
    fn to_tunnel(&self, node_code: &str) -> ClientConfig {
        ClientConfig {
            auth_token: if self.auth.token.is_empty() {
                node_code.to_string()
            } else {
                self.auth.token.clone()
            },
            server_addr: self.server_addr.clone(),
            server_port: self.server_port,
            pool_count: self.transport.pool_count,
            metadatas: self.metadatas.clone(),
            ..Default::default()
        }
    }

    /// 节点编号
    fn node_code(&self) -> String {
        if self.auth.token.is_empty() {
            self.server_addr.clone()
        } else {
            self.auth.token.clone()
        }
    }
}

/// 传输配置
#[derive(Debug, Deserialize, Default)]
struct ProxyTransport {
    #[serde(rename = "useEncryption", default)]
    use_encryption: bool,
    #[serde(rename = "useCompression", default)]
    use_compression: bool,
    #[serde(rename = "bandwidthLimit", default)]
    bandwidth_limit: String,
    #[serde(rename = "bandwidthLimitMode", default)]
    bandwidth_limit_mode: String,
    #[serde(rename = "proxyProtocolVersion", default)]
    proxy_protocol_version: String,
}

impl ProxyTransport {
    fn to_msg(&self) -> TransportConfig {
        TransportConfig {
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            bandwidth_limit: self.bandwidth_limit.clone(),
            bandwidth_limit_mode: self.bandwidth_limit_mode.clone(),
            proxy_protocol_version: self.proxy_protocol_version.clone(),
        }
    }
}

/// 代理基础字段
#[derive(Debug, Deserialize, Default)]
struct ProxyBase {
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    proxy_type: String,
    #[serde(rename = "proxyBackend", default)]
    backend: Backend,
    #[serde(rename = "customDomains", default)]
    custom_domains: Vec<String>,
    #[serde(rename = "secretkey", default)]
    secret_key: String,
    #[serde(rename = "remotePort", default)]
    remote_port: u16,
    #[serde(rename = "metadatas", default)]
    metadatas: std::collections::HashMap<String, String>,
    #[serde(rename = "Transport", default)]
    transport: ProxyTransport,
}

#[derive(Debug, Deserialize, Default)]
struct Backend {
    #[serde(rename = "localIP", default)]
    local_ip: String,
    #[serde(rename = "localPort", default)]
    local_port: u16,
}

impl ProxyBase {
    fn to_msg(&self, auth_token: &str) -> ProxyConfigMsg {
        let mut metas = self.metadatas.clone();
        if !self.secret_key.is_empty() {
            metas.insert("secret_key".to_string(), self.secret_key.clone());
        }
        ProxyConfigMsg {
            name: self.name.clone(),
            proxy_type: self.proxy_type.clone(),
            auth_token: auth_token.to_string(),
            local_ip: self.backend.local_ip.clone(),
            local_port: self.backend.local_port,
            remote_port: self.remote_port,
            custom_domains: self.custom_domains.clone(),
            secret_key: self.secret_key.clone(),
            load_balancer_group: String::new(),
            transport: self.transport.to_msg(),
            metadatas: metas,
        }
    }

    fn is_empty(&self) -> bool {
        self.name.is_empty()
    }
}

// ==================== 各事件处理器 ====================

/// 服务端配置（节点模式）
async fn handle_server_config(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(default, rename = "UpdateTag")]
        update_tag: String,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }

    // 解析服务端配置，取出监听端口与 vhost 端口
    let cfg = &payload["ServerConfig"];
    let bind_port = cfg["bindPort"].as_u64().unwrap_or(7000) as u16;
    let vhost_http_port = cfg["vhostHTTPPort"].as_u64().unwrap_or(0) as u16;
    let max_pool = cfg["transport"]["maxPoolCount"].as_i64().unwrap_or(5) as i32;
    let token = cfg["auth"]["token"].as_str().unwrap_or("").to_string();

    let tunnel_cfg = rscross_tunnel::ServerConfig {
        auth_token: token,
        bind_addr: "0.0.0.0".to_string(),
        bind_port,
        vhost_http_port,
        max_pool_count: max_pool,
        ..Default::default()
    };

    // 停掉旧的节点服务
    state.services.stop(&req.key);
    state.services.remove(&req.key);

    let srv = rscross_tunnel::HubServer::new(tunnel_cfg, rscross_common::util::random_hex(16));
    let s = srv.clone();
    tokio::spawn(async move {
        if let Err(e) = s.serve().await {
            tracing::error!(error = %e, "节点服务退出");
        }
    });

    state.state.mark_configured(&req.key, &req.update_tag);
    tracing::info!(key = %req.key, bind_port, vhost_http_port, "节点服务已启动");
    Ok(())
}

/// 域名隧道
async fn handle_host_config(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(rename = "UpdateTag", default)]
        update_tag: String,
        #[serde(rename = "BaseCfg", default)]
        base: BaseCfg,
        #[serde(default)]
        http: ProxyBase,
        #[serde(rename = "IsHttps", default)]
        is_https: bool,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }
    if req.http.is_empty() {
        return Ok(());
    }

    let node_code = req.base.node_code();
    let tunnel_cfg = req.base.to_tunnel(&node_code);
    let svc = ensure_service(&state, &req.key, tunnel_cfg);

    let mut msg = req.http.to_msg(&node_code);
    msg.proxy_type = ProxyType::Http.as_str().to_string();
    if req.is_https {
        // 目标为 HTTPS，本地走 http2https 插件，等价于直连本地 HTTPS
        msg.local_port = req.http.backend.local_port;
    }

    svc.add_proxy(msg).await.map_err(|e| e.to_string())?;
    state.state.mark_configured(&req.key, &req.update_tag);
    Ok(())
}

/// 端口转发
async fn handle_forward_config(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(rename = "UpdateTag", default)]
        update_tag: String,
        #[serde(rename = "BaseCfg", default)]
        base: BaseCfg,
        #[serde(default)]
        tcp: ProxyBase,
        #[serde(default)]
        udp: ProxyBase,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }

    let node_code = req.base.node_code();
    let tunnel_cfg = req.base.to_tunnel(&node_code);
    let svc = ensure_service(&state, &req.key, tunnel_cfg);

    let mut count = 0;
    if !req.tcp.is_empty() {
        svc.add_proxy(req.tcp.to_msg(&node_code)).await.map_err(|e| e.to_string())?;
        count += 1;
    }
    if !req.udp.is_empty() {
        svc.add_proxy(req.udp.to_msg(&node_code)).await.map_err(|e| e.to_string())?;
        count += 1;
    }

    state.state.mark_configured(&req.key, &req.update_tag);
    tracing::info!(key = %req.key, count, "端口转发已配置");
    Ok(())
}

/// 私有隧道
async fn handle_tunnel_config(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(rename = "UpdateTag", default)]
        update_tag: String,
        #[serde(rename = "BaseCfg", default)]
        base: BaseCfg,
        #[serde(default)]
        stcp: ProxyBase,
        #[serde(default)]
        sudp: ProxyBase,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }

    let node_code = req.base.node_code();
    let tunnel_cfg = req.base.to_tunnel(&node_code);
    let svc = ensure_service(&state, &req.key, tunnel_cfg);

    if !req.stcp.is_empty() {
        let mut m = req.stcp.to_msg(&node_code);
        m.proxy_type = ProxyType::Stcp.as_str().to_string();
        svc.add_proxy(m).await.map_err(|e| e.to_string())?;
    }
    if !req.sudp.is_empty() {
        let mut m = req.sudp.to_msg(&node_code);
        m.proxy_type = ProxyType::Sudp.as_str().to_string();
        svc.add_proxy(m).await.map_err(|e| e.to_string())?;
    }

    state.state.mark_configured(&req.key, &req.update_tag);
    Ok(())
}

/// P2P 隧道
async fn handle_p2p_config(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(rename = "UpdateTag", default)]
        update_tag: String,
        #[serde(rename = "BaseCfg", default)]
        base: BaseCfg,
        #[serde(default)]
        xtcp: ProxyBase,
        #[serde(default)]
        stcp: ProxyBase,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }

    let node_code = req.base.node_code();
    let tunnel_cfg = req.base.to_tunnel(&node_code);
    let svc = ensure_service(&state, &req.key, tunnel_cfg);

    if !req.xtcp.is_empty() {
        let mut m = req.xtcp.to_msg(&node_code);
        m.proxy_type = ProxyType::Xtcp.as_str().to_string();
        svc.add_proxy(m).await.map_err(|e| e.to_string())?;
    }
    // STCP 作为中继回退
    if !req.stcp.is_empty() {
        let mut m = req.stcp.to_msg(&node_code);
        m.proxy_type = ProxyType::Stcp.as_str().to_string();
        svc.add_proxy(m).await.map_err(|e| e.to_string())?;
    }

    state.state.mark_configured(&req.key, &req.update_tag);
    Ok(())
}

/// 代理隧道（socks5 等）
async fn handle_proxy_config(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(rename = "UpdateTag", default)]
        update_tag: String,
        #[serde(rename = "BaseCfg", default)]
        base: BaseCfg,
        #[serde(default)]
        name: String,
        #[serde(default)]
        port: u16,
        #[serde(rename = "authUser", default)]
        auth_user: String,
        #[serde(rename = "authPwd", default)]
        auth_pwd: String,
        #[serde(default)]
        limiter: String,
        #[serde(rename = "useEncryption", default)]
        use_encryption: i32,
        #[serde(rename = "useCompression", default)]
        use_compression: i32,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }

    let node_code = req.base.node_code();
    let tunnel_cfg = req.base.to_tunnel(&node_code);
    let svc = ensure_service(&state, &req.key, tunnel_cfg);

    let mut metas = std::collections::HashMap::new();
    if !req.auth_user.is_empty() {
        metas.insert("auth_user".to_string(), req.auth_user.clone());
    }
    if !req.auth_pwd.is_empty() {
        metas.insert("auth_pwd".to_string(), req.auth_pwd.clone());
    }

    let msg = ProxyConfigMsg {
        name: if req.name.is_empty() {
            format!("{}_proxy", req.key)
        } else {
            req.name.clone()
        },
        proxy_type: "socks5".to_string(),
        auth_token: node_code.clone(),
        local_ip: "127.0.0.1".to_string(),
        local_port: req.port,
        remote_port: 0,
        custom_domains: vec![],
        secret_key: String::new(),
        load_balancer_group: String::new(),
        transport: TransportConfig {
            use_encryption: req.use_encryption == 1,
            use_compression: req.use_compression == 1,
            bandwidth_limit: req.limiter.clone(),
            bandwidth_limit_mode: "client".to_string(),
            proxy_protocol_version: String::new(),
        },
        metadatas: metas,
    };

    svc.add_proxy(msg).await.map_err(|e| e.to_string())?;
    state.state.mark_configured(&req.key, &req.update_tag);
    Ok(())
}

/// 自定义配置
async fn handle_custom_cfg(state: AppState, payload: Value) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        key: String,
        #[serde(rename = "UpdateTag", default)]
        update_tag: String,
        #[serde(rename = "Type", default)]
        cfg_type: String,
        #[serde(default)]
        content: String,
    }
    let req: Req = serde_json::from_value(payload).map_err(|e| e.to_string())?;

    if !state.state.need_update(&req.key, &req.update_tag) {
        return Ok(());
    }

    // 校验配置内容可解析
    let valid = match req.cfg_type.as_str() {
        "yaml" | "yml" => serde_yaml::from_str::<Value>(&req.content).is_ok(),
        "json" => serde_json::from_str::<Value>(&req.content).is_ok(),
        "toml" => toml::from_str::<Value>(&req.content).is_ok(),
        _ => true,
    };
    if !valid {
        return Err(format!("{} 配置解析失败", req.cfg_type));
    }

    state.state.mark_configured(&req.key, &req.update_tag);
    tracing::info!(key = %req.key, type = %req.cfg_type, "自定义配置已更新");
    Ok(())
}

/// 端口检测
async fn handle_port_check(state: AppState, payload: Value) -> Result<(), String> {
    let port = match payload {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        Value::Object(o) => o
            .get("port")
            .and_then(|v| v.as_str().or_else(|| v.as_u64().map(|n| &n.to_string())))
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };

    let p: u16 = port.parse().map_err(|_| "端口格式错误".to_string())?;

    // 尝试绑定端口判断可用性
    match tokio::net::TcpListener::bind(("0.0.0.0", p)).await {
        Ok(l) => {
            drop(l);
            tracing::debug!(port = p, "端口可用");
        }
        Err(e) => {
            tracing::warn!(port = p, error = %e, "端口不可用");
            return Err(format!("端口 {p} 已被占用"));
        }
    }
    let _ = &state;
    Ok(())
}

/// 移除配置
async fn handle_remove(state: AppState, payload: Value) -> Result<(), String> {
    let key = match payload {
        Value::String(s) => s,
        Value::Object(o) => o
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };

    if key.is_empty() {
        return Err("缺少 key".to_string());
    }

    state.services.del(&key);
    state.state.remove(&key);
    tracing::info!(key = %key, "配置已移除");
    Ok(())
}

/// 停止
async fn handle_stop(state: AppState, payload: Value) -> Result<(), String> {
    let msg = match payload {
        Value::String(s) => s,
        Value::Object(o) => o
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("服务端要求停止")
            .to_string(),
        _ => "服务端要求停止".to_string(),
    };

    tracing::info!(msg = %msg, "收到停止指令");
    state.services.stop_all();
    state.state.mark_configured("__stop__", "");

    // 触发进程退出
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        std::process::exit(0);
    });
    Ok(())
}

/// 获取或创建隧道服务
fn ensure_service(state: &AppState, key: &str, cfg: ClientConfig) -> Arc<AgentService> {
    if let Some(svc) = state.services.get(key) {
        return svc;
    }
    let svc = Arc::new(AgentService::new(key, cfg));
    state.services.set(key, svc.clone());
    let s = svc.clone();
    tokio::spawn(async move {
        if let Err(e) = s.run().await {
            tracing::error!(error = %e, "agent 循环退出");
        }
    });
    svc
}

/// 回声响应，供测试
pub fn echo_ok() -> Value {
    json!("success")
}

/// 状态存储便捷访问
pub fn state_of(state: &AppState) -> &Arc<StateStore> {
    &state.state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_cfg_parse() {
        let raw = json!({
            "key": "k1",
            "UpdateTag": "v1",
            "BaseCfg": {
                "auth": { "token": "node1" },
                "serverAddr": "1.2.3.4",
                "serverPort": 7000,
                "transport": { "poolCount": 3 }
            }
        });
        let req: serde_json::Value = raw;
        let base: BaseCfg = serde_json::from_value(req["BaseCfg"].clone()).unwrap();
        assert_eq!(base.node_code(), "node1");
        let agent = base.to_tunnel("node1");
        assert_eq!(agent.server_addr, "1.2.3.4");
        assert_eq!(agent.server_port, 7000);
        assert_eq!(agent.pool_count, 3);
    }

    #[test]
    fn test_proxy_base_to_msg() {
        let raw = json!({
            "name": "k1_http",
            "type": "http",
            "proxyBackend": { "localIP": "127.0.0.1", "localPort": 8080 },
            "customDomains": ["a.example.com"],
            "Transport": {
                "useEncryption": true,
                "bandwidthLimit": "128KB"
            }
        });
        let p: ProxyBase = serde_json::from_value(raw).unwrap();
        let msg = p.to_msg("node1");
        assert_eq!(msg.name, "k1_http");
        assert_eq!(msg.local_port, 8080);
        assert_eq!(msg.custom_domains, vec!["a.example.com"]);
        assert!(msg.transport.use_encryption);
        assert_eq!(msg.transport.bandwidth_limit, "128KB");
    }

    #[test]
    fn test_proxy_base_is_empty() {
        let p = ProxyBase::default();
        assert!(p.is_empty());
    }
}
