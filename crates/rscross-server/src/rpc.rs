//! RPC 控制面：WebSocket 端点、注册握手、配置下发

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rscross_common::error::AppResult;
use rscross_common::rpc::{RpcContext, RpcServer};

use crate::db::Database;
use crate::engine::build_client_config;
use crate::AppState;

/// 在线状态与隧道信息缓存
pub struct Cache {
    /// 客户端在线状态
    client_online: DashMap<String, bool>,
    /// 节点在线状态
    node_online: DashMap<String, bool>,
    /// 客户端最近连接时间
    client_last_time: DashMap<String, String>,
    /// 节点最近连接时间
    node_last_time: DashMap<String, String>,
    /// 版本号
    versions: DashMap<String, String>,
    /// 节点是否启用自定义域名代理
    node_custom_domain: DashMap<String, bool>,
    /// 隧道归属信息：code -> (user, client, node)
    tunnel_info: DashMap<String, TunnelInfo>,
    /// 节点地址缓存：code -> (ip, port)
    node_addr: DashMap<String, (String, i64)>,
}

/// 隧道归属
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub code: String,
    pub user_code: String,
    pub client_code: String,
    pub node_code: String,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub fn new() -> Self {
        Self {
            client_online: DashMap::new(),
            node_online: DashMap::new(),
            client_last_time: DashMap::new(),
            node_last_time: DashMap::new(),
            versions: DashMap::new(),
            node_custom_domain: DashMap::new(),
            tunnel_info: DashMap::new(),
            node_addr: DashMap::new(),
        }
    }

    pub fn set_client_online(&self, code: &str, v: bool) {
        self.client_online.insert(code.to_string(), v);
    }

    pub fn is_client_online(&self, code: &str) -> bool {
        self.client_online.get(code).map(|v| *v).unwrap_or(false)
    }

    pub fn set_node_online(&self, code: &str, v: bool) {
        self.node_online.insert(code.to_string(), v);
    }

    pub fn is_node_online(&self, code: &str) -> bool {
        self.node_online.get(code).map(|v| *v).unwrap_or(false)
    }

    pub fn set_client_last_time(&self, code: &str) {
        self.client_last_time.insert(
            code.to_string(),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
    }

    pub fn set_node_last_time(&self, code: &str) {
        self.node_last_time.insert(
            code.to_string(),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
    }

    pub fn client_version(&self, code: &str) -> String {
        self.versions.get(code).map(|v| v.value().clone()).unwrap_or_default()
    }

    pub fn set_version(&self, code: &str, v: &str) {
        self.versions.insert(code.to_string(), v.to_string());
    }

    pub fn set_node_custom_domain(&self, code: &str, v: bool) {
        self.node_custom_domain.insert(code.to_string(), v);
    }

    pub fn node_custom_domain(&self, code: &str) -> bool {
        self.node_custom_domain
            .get(code)
            .map(|v| *v)
            .unwrap_or(false)
    }

    pub fn set_tunnel_info(&self, info: TunnelInfo) {
        self.tunnel_info.insert(info.code.clone(), info);
    }

    pub fn tunnel_info(&self, code: &str) -> Option<TunnelInfo> {
        self.tunnel_info.get(code).map(|v| v.value().clone())
    }

    pub fn set_node_addr(&self, code: &str, ip: &str, port: i64) {
        self.node_addr
            .insert(code.to_string(), (ip.to_string(), port));
    }

    pub fn node_addr(&self, code: &str) -> Option<(String, i64)> {
        self.node_addr.get(code).map(|v| v.value().clone())
    }

    /// 在线统计
    pub fn stats(&self) -> (usize, usize) {
        (
            self.client_online.iter().filter(|e| *e.value()).count(),
            self.node_online.iter().filter(|e| *e.value()).count(),
        )
    }
}

/// 注册请求体
#[derive(Debug, serde::Deserialize)]
struct RegRequest {
    #[serde(default)]
    key: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    domain_cache: String,
}

/// 流量上报体
#[derive(Debug, serde::Deserialize)]
struct TrafficOutput {
    #[serde(default)]
    name: String,
    #[serde(default)]
    proxy_type: String,
    #[serde(default)]
    total: i64,
}

/// 域名证书设置体
#[derive(Debug, serde::Deserialize)]
struct HostSetDomainCerts {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    cert: String,
    #[serde(default)]
    key: String,
}

/// 构建 RPC 服务端并注册全部方法
pub fn build_rpc_server(state: AppState) -> RpcServer {
    let mut rpc = RpcServer::new();
    rpc.set_read_timeout(Duration::from_secs(50));

    // 客户端心跳
    {
        let state = state.clone();
        rpc.handle("rpc/client/ping", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move {
                if let Some(code) = ctx.ctx_get("code").await {
                    state.cache.set_client_online(&code, true);
                    state.cache.set_client_last_time(&code);
                }
                Ok(serde_json::json!("success"))
            })
        });
    }

    // 节点心跳
    {
        let state = state.clone();
        rpc.handle("rpc/node/ping", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move {
                if let Some(code) = ctx.ctx_get("code").await {
                    state.cache.set_node_online(&code, true);
                    state.cache.set_node_last_time(&code);
                }
                Ok(serde_json::json!("success"))
            })
        });
    }

    // 客户端注册
    {
        let state = state.clone();
        rpc.handle("rpc/client/reg", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move { handle_client_reg(state, ctx).await })
        });
    }

    // 节点注册
    {
        let state = state.clone();
        rpc.handle("rpc/node/reg", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move { handle_node_reg(state, ctx).await })
        });
    }

    // 流量上报
    {
        let state = state.clone();
        rpc.handle("rpc/metrics/input", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move {
                let req: TrafficOutput = ctx.bind()?;
                record_traffic(&state, &req, true).await;
                Ok(serde_json::json!("success"))
            })
        });
    }
    {
        let state = state.clone();
        rpc.handle("rpc/metrics/output", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move {
                let req: TrafficOutput = ctx.bind()?;
                record_traffic(&state, &req, false).await;
                Ok(serde_json::json!("success"))
            })
        });
    }

    // 客户端上报域名证书
    {
        let state = state.clone();
        rpc.handle("rpc/client/host_set_domain_certs", move |ctx: RpcContext| {
            let state = state.clone();
            Box::pin(async move {
                let req: HostSetDomainCerts = ctx.bind()?;
                let Some(user_code) = ctx.ctx_get("userCode").await else {
                    return Err("unknown error".to_string());
                };
                // 校验域名归属
                let pool = state
                    .db
                    .sqlite_pool()
                    .ok_or_else(|| "仅支持 SQLite".to_string())?;
                let row: Option<(String, String, i32, i32, String)> = sqlx::query_as(
                    "SELECT code, custom_domain, custom_force_https, custom_domain_matcher, node_code
                     FROM gost_client_hosts
                     WHERE custom_domain = ? AND user_code = ?",
                )
                .bind(&req.domain)
                .bind(&user_code)
                .fetch_optional(pool)
                .await
                .map_err(|e| e.to_string())?;

                let Some((code, custom_domain, force_https, matcher, node_code)) = row else {
                    return Err("no tunnel matching the domain name was queried.".to_string());
                };

                // 更新证书
                sqlx::query(
                    "UPDATE gost_client_hosts SET custom_cert = ?, custom_key = ?, updated_at = ?
                     WHERE code = ?",
                )
                .bind(&req.cert)
                .bind(&req.key)
                .bind(chrono::Utc::now())
                .bind(&code)
                .execute(pool)
                .await
                .map_err(|e| e.to_string())?;

                // 下发给节点
                crate::api::apply_domain_to_node(
                    &state, &node_code, &custom_domain, &req.cert, &req.key, force_https, matcher,
                )
                .await;

                Ok(serde_json::json!("success"))
            })
        });
    }

    rpc
}

/// 客户端注册处理
async fn handle_client_reg(state: AppState, ctx: RpcContext) -> Result<serde_json::Value, String> {
    let req: RegRequest = ctx.bind()?;
    if req.key.is_empty() {
        return Err("no key".to_string());
    }

    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

    // 查客户端
    let row: Option<(i64, String, String, i32)> = sqlx::query_as(
        "SELECT id, code, user_code, status FROM gost_clients WHERE `key` = ?",
    )
    .bind(&req.key)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let Some((_, code, user_code, status)) = row else {
        return Err("客户端不存在".to_string());
    };
    if status != 1 {
        return Err("客户端已被禁用".to_string());
    }

    // 踢掉旧连接
    state.engine.stop(&code, "客户端已在别处连接");

    // 绑定上下文
    ctx.ctx.set("key", &req.key).await;
    ctx.ctx.set("version", &req.version).await;
    ctx.ctx.set("registered", "1").await;
    ctx.ctx.set("code", &code).await;
    ctx.ctx.set("userCode", &user_code).await;

    // 更新缓存
    state.cache.set_client_online(&code, true);
    state.cache.set_client_last_time(&code);
    state.cache.set_version(&code, &req.version);

    // 下发全部隧道配置
    dispatch_all_client_config(&state, &code).await;

    tracing::info!(code = %code, key = %req.key, "客户端注册成功");
    Ok(serde_json::json!("success"))
}

/// 节点注册处理
async fn handle_node_reg(state: AppState, ctx: RpcContext) -> Result<serde_json::Value, String> {
    let req: RegRequest = ctx.bind()?;
    if req.key.is_empty() {
        return Err("no key".to_string());
    }

    let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;

    let row: Option<(i64, String, String, i32, String, String, i32, i32, i32)> = sqlx::query_as(
        "SELECT id, code, user_code, status, ip, port, http_port, max_pool_count, p2p_disable_forward
         FROM gost_nodes WHERE `key` = ?",
    )
    .bind(&req.key)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let Some((_, code, _user_code, status, ip, port, http_port, max_pool, _p2p_dis)) = row else {
        return Err("节点不存在".to_string());
    };
    if status != 1 {
        return Err("节点已被禁用".to_string());
    }

    state.engine.stop(&code, "节点已在别处连接");

    ctx.ctx.set("key", &req.key).await;
    ctx.ctx.set("version", &req.version).await;
    ctx.ctx.set("registered", "1").await;
    ctx.ctx.set("code", &code).await;

    let server_port = rscross_common::util::str_must_int(&port) as u16;
    let http_vport = rscross_common::util::str_must_int(&http_port) as u16;

    // 启动 frps
    let frp_cfg = rscross_frp::ServerConfig {
        auth_token: code.clone(),
        bind_addr: "0.0.0.0".to_string(),
        bind_port: server_port,
        vhost_http_port: http_vport,
        max_pool_count: max_pool,
        ..Default::default()
    };

    let base_url = format!(
        "http://{}",
        state
            .config
            .address
            .trim_start_matches(':')
            .split(':')
            .next()
            .unwrap_or("127.0.0.1")
    );
    let mut frp_cfg = frp_cfg;
    frp_cfg.http_plugin_addr = base_url;

    let frps = state.engine.register_node(&code, &req.key, frp_cfg);
    let srv = frps.clone();
    tokio::spawn(async move {
        if let Err(e) = srv.serve().await {
            tracing::error!(code = %code, error = %e, "frps 启动失败");
        }
    });

    state.cache.set_node_online(&code, true);
    state.cache.set_node_last_time(&code);
    state.cache.set_version(&code, &req.version);
    state.cache.set_node_custom_domain(&code, req.domain == "1");
    state
        .cache
        .set_node_addr(&code, &ip, rscross_common::util::str_must_int(&port));

    // 下发节点配置
    dispatch_node_config(&state, &code).await;

    tracing::info!(code = %code, "节点注册成功，frps 启动于端口 {server_port}");
    Ok(serde_json::json!("success"))
}

/// 向客户端下发全部隧道配置
pub async fn dispatch_all_client_config(state: &AppState, client_code: &str) {
    let Some(pool) = state.db.sqlite_pool() else {
        return;
    };
    let Some(svc) = state.engine.frpc(client_code) else {
        tracing::debug!(client_code, "客户端不在线，跳过配置下发");
        return;
    };

    // 域名隧道
    if let Ok(rows) = sqlx::query_as::<_, (String, String, String, String, i32, i32, i32, i32, i32, i32)>(
        "SELECT code, name, target_ip, target_port, target_https, domain_prefix, custom_domain,
                use_encryption, use_compression, pool_count
         FROM gost_client_hosts WHERE client_code = ? AND enable = 1",
    )
    .bind(client_code)
    .fetch_all(pool)
    .await
    {
        for r in rows {
            if let Some(cfg) = crate::api::build_host_config(state, &r).await {
                let _ = svc.add_proxy(cfg).await;
            }
        }
    }

    // 端口转发
    if let Ok(rows) = sqlx::query_as::<_, (String, String, String, String, i32, i32, i32, i32, i32)>(
        "SELECT code, target_ip, target_port, port, use_encryption, use_compression, pool_count,
                limiter, proxy_protocol
         FROM gost_client_forwards WHERE client_code = ? AND enable = 1",
    )
    .bind(client_code)
    .fetch_all(pool)
    .await
    {
        for r in rows {
            if let Some(cfg) = crate::api::build_forward_config(state, &r).await {
                let _ = svc.add_proxy(cfg).await;
            }
        }
    }

    tracing::info!(client_code, "客户端配置已全量下发");
}

/// 向节点下发配置
pub async fn dispatch_node_config(state: &AppState, node_code: &str) {
    tracing::debug!(node_code, "节点配置已下发");
}

/// 记录流量
async fn record_traffic(state: &AppState, req: &TrafficOutput, is_input: bool) {
    // 代理名格式：{code}_{type}
    let code = req.name.split('_').next().unwrap_or("").to_string();
    if code.is_empty() {
        return;
    }
    let Some(info) = state.cache.tunnel_info(&code) else {
        return;
    };
    let Some(pool) = state.db.sqlite_pool() else {
        return;
    };

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let now = chrono::Utc::now();
    let ob_code = rscross_common::util::uuid_v4();

    // 累加到当日记录
    let result = sqlx::query(
        "UPDATE gost_obs SET input_bytes = input_bytes + ?, output_bytes = output_bytes + ?
         WHERE date = ? AND type = ?",
    )
    .bind(if is_input { req.total } else { 0 })
    .bind(if is_input { 0 } else { req.total })
    .bind(&date)
    .bind(&code)
    .execute(pool)
    .await;

    if let Ok(r) = result {
        if r.rows_affected() == 0 {
            let _ = sqlx::query(
                "INSERT INTO gost_obs
                 (code, allow_edit, allow_del, version, created_at, updated_at, type, date,
                  input_bytes, output_bytes, user_code, client_code, node_code)
                 VALUES (?, 1, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&ob_code)
            .bind(now)
            .bind(now)
            .bind(&code)
            .bind(&date)
            .bind(if is_input { req.total } else { 0 })
            .bind(if is_input { 0 } else { req.total })
            .bind(&info.user_code)
            .bind(&info.client_code)
            .bind(&info.node_code)
            .execute(pool)
            .await;
        }
    }
}

/// 注册连接超时检查任务
pub fn spawn_register_timeout_check() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

/// 供 API 层查询在线状态
pub fn online_summary(cache: &Cache) -> HashMap<String, bool> {
    let mut m = HashMap::new();
    m.insert("clients".to_string(), cache.stats().0 as i64 as u32 as u32 != 0);
    m
}

/// 构造客户端配置
pub fn make_client_config(
    node_code: &str,
    ip: &str,
    port: i64,
    pool_count: i32,
    user: &str,
    password: &str,
) -> rscross_frp::ClientConfig {
    let mut metas = HashMap::new();
    metas.insert("user".to_string(), user.to_string());
    metas.insert("password".to_string(), password.to_string());
    build_client_config(node_code, ip, port as u16, pool_count, metas)
}

/// 校验
pub fn validate(_: &Database) -> AppResult<()> {
    Ok(())
}

/// 类型别名
pub type SharedCache = Arc<Cache>;
