//! HTTP API：路由、处理器与中间件

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;

use rscross_common::error::AppError;
use rscross_common::response::ApiResponse;

use crate::assets;
use crate::AppState;

/// 启动 HTTP 服务
pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    // 初始化数据库表
    state.db.execute_batch(crate::db::SCHEMA).await?;

    let app = build_router(state.clone());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("HTTP 服务已启动: http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// 构建路由表
pub fn build_router(state: AppState) -> Router {
    let mut app = Router::new();

    // ---- 公开接口 ----
    app = app
        .route("/api/v1/public/system/config", post(public_config))
        .route("/api/v1/public/system/notice", post(public_notice))
        .route("/api/v1/public/frp/login", post(frp_login))
        .route("/api/v1/public/frp/newProxy", post(frp_new_proxy))
        .route("/api/v1/public/frp/closeProxy", post(frp_close_proxy))
        .route("/api/v1/public/frp/ping", post(frp_ping))
        .route("/api/v1/public/frp/newWorkConn", post(frp_new_work_conn))
        .route("/api/v1/public/frp/newUserConn", post(frp_new_user_conn));

    // ---- 认证接口 ----
    app = app
        .route("/api/v1/auth", post(auth_login))
        .route("/api/v1/auth/check", post(auth_check))
        .route("/api/v1/auth/register", post(auth_register))
        .route("/api/v1/auth/reset", post(auth_reset));

    // ---- 普通用户接口（需登录）----
    let normal = Router::new()
        .route("/dashboard", post(normal_dashboard))
        .route("/gost/client", post(normal_client_list))
        .route("/gost/client/create", post(normal_client_create))
        .route("/gost/client/delete", post(normal_client_delete))
        .route("/gost/client/host", post(normal_host_list))
        .route("/gost/client/host/page", post(normal_host_page))
        .route("/gost/client/host/create", post(normal_host_create))
        .route("/gost/client/host/update", post(normal_host_update))
        .route("/gost/client/host/config", post(normal_host_config))
        .route("/gost/client/host/delete", post(normal_host_delete))
        .route("/gost/client/forward", post(normal_forward_list))
        .route("/gost/client/forward/page", post(normal_forward_page))
        .route("/gost/client/forward/create", post(normal_forward_create))
        .route("/gost/client/forward/update", post(normal_forward_update))
        .route("/gost/client/forward/config", post(normal_forward_config))
        .route("/gost/client/forward/delete", post(normal_forward_delete))
        .route("/gost/client/tunnel", post(normal_tunnel_list))
        .route("/gost/client/tunnel/page", post(normal_tunnel_page))
        .route("/gost/client/tunnel/create", post(normal_tunnel_create))
        .route("/gost/client/tunnel/update", post(normal_tunnel_update))
        .route("/gost/client/tunnel/config", post(normal_tunnel_config))
        .route("/gost/client/tunnel/delete", post(normal_tunnel_delete))
        .route("/gost/client/p2p", post(normal_p2p_list))
        .route("/gost/client/p2p/page", post(normal_p2p_page))
        .route("/gost/client/p2p/create", post(normal_p2p_create))
        .route("/gost/client/p2p/update", post(normal_p2p_update))
        .route("/gost/client/p2p/config", post(normal_p2p_config))
        .route("/gost/client/p2p/delete", post(normal_p2p_delete))
        .route("/gost/client/proxy", post(normal_proxy_list))
        .route("/gost/client/proxy/page", post(normal_proxy_page))
        .route("/gost/client/proxy/config", post(normal_proxy_config))
        .route("/gost/client/proxy/delete", post(normal_proxy_delete))
        .route("/gost/client/logger", post(normal_client_logger))
        .route("/gost/node", post(normal_node_list))
        .route("/gost/node/config", post(normal_node_config))
        .route("/frp/client/cfg", post(normal_cfg_list))
        .route("/frp/client/cfg/page", post(normal_cfg_page))
        .route("/frp/client/cfg/create", post(normal_cfg_create))
        .route("/frp/client/cfg/update", post(normal_cfg_update))
        .route("/frp/client/cfg/config", post(normal_cfg_config))
        .route("/frp/client/cfg/delete", post(normal_cfg_delete))
        .route("/gost/obs", post(normal_obs_page))
        .route("/system/notice", post(normal_notice))
        .route("/system/user/info", post(normal_user_info))
        .route("/system/user/reset", post(normal_user_reset))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .route("/health", get(|| async { "ok" }));

    app = app.nest("/api/v1/normal", normal);

    // ---- 管理接口（需管理员）----
    let admin = Router::new()
        .route("/dashboard/count", post(admin_dashboard_count))
        .route("/dashboard/userObs", post(admin_dashboard_user_obs))
        .route("/dashboard/nodeObs", post(admin_dashboard_node_obs))
        .route("/dashboard/userObsDate", post(admin_dashboard_user_obs_date))
        .route("/dashboard/nodeObsDate", post(admin_dashboard_node_obs_date))
        .route("/dashboard/clientObsDate", post(admin_dashboard_client_obs_date))
        .route(
            "/dashboard/clientHostObsDate",
            post(admin_dashboard_host_obs_date),
        )
        .route(
            "/dashboard/clientForwardObsDate",
            post(admin_dashboard_forward_obs_date),
        )
        .route(
            "/dashboard/clientTunnelObsDate",
            post(admin_dashboard_tunnel_obs_date),
        )
        .route("/gost/client", post(admin_client_list))
        .route("/gost/client/page", post(admin_client_page))
        .route("/gost/client/list", post(admin_client_list))
        .route("/gost/client/create", post(admin_client_create))
        .route("/gost/client/delete", post(admin_client_delete))
        .route("/gost/client/logger", post(admin_client_logger_page))
        .route("/gost/node", post(admin_node_list))
        .route("/gost/node/page", post(admin_node_page))
        .route("/gost/node/list", post(admin_node_list))
        .route("/gost/node/create", post(admin_node_create))
        .route("/gost/node/update", post(admin_node_update))
        .route("/gost/node/delete", post(admin_node_delete))
        .route("/gost/node/query", post(admin_node_query))
        .route("/gost/node/cleanPort", post(admin_node_clean_port))
        .route("/gost/node/logger", post(admin_node_logger_page))
        .route("/gost/node/rule", post(admin_node_rule_list))
        .route("/gost/node/bind/update", post(admin_node_bind_update))
        .route("/gost/node/config", post(admin_node_config_list))
        .route("/gost/node/config/page", post(admin_node_config_page))
        .route("/gost/node/config/create", post(admin_node_config_create))
        .route("/gost/node/config/update", post(admin_node_config_update))
        .route("/gost/node/config/delete", post(admin_node_config_delete))
        .route("/gost/client/host", post(admin_host_list))
        .route("/gost/client/host/list", post(admin_host_list))
        .route("/gost/client/host/page", post(admin_host_page))
        .route("/gost/client/host/create", post(admin_host_create))
        .route("/gost/client/host/update", post(admin_host_update))
        .route("/gost/client/host/config", post(admin_host_config))
        .route("/gost/client/host/delete", post(admin_host_delete))
        .route("/gost/client/forward", post(admin_forward_list))
        .route("/gost/client/forward/list", post(admin_forward_list))
        .route("/gost/client/forward/page", post(admin_forward_page))
        .route("/gost/client/forward/create", post(admin_forward_create))
        .route("/gost/client/forward/config", post(admin_forward_config))
        .route("/gost/client/forward/delete", post(admin_forward_delete))
        .route("/gost/client/tunnel", post(admin_tunnel_list))
        .route("/gost/client/tunnel/list", post(admin_tunnel_list))
        .route("/gost/client/tunnel/page", post(admin_tunnel_page))
        .route("/gost/client/tunnel/create", post(admin_tunnel_create))
        .route("/gost/client/tunnel/config", post(admin_tunnel_config))
        .route("/gost/client/tunnel/update", post(admin_tunnel_update))
        .route("/gost/client/tunnel/delete", post(admin_tunnel_delete))
        .route("/gost/client/p2p", post(admin_p2p_list))
        .route("/gost/client/p2p/list", post(admin_p2p_list))
        .route("/gost/client/p2p/page", post(admin_p2p_page))
        .route("/gost/client/p2p/create", post(admin_p2p_create))
        .route("/gost/client/p2p/config", post(admin_p2p_config))
        .route("/gost/client/p2p/update", post(admin_p2p_update))
        .route("/gost/client/p2p/delete", post(admin_p2p_delete))
        .route("/gost/client/proxy", post(admin_proxy_list))
        .route("/gost/client/proxy/list", post(admin_proxy_list))
        .route("/gost/client/proxy/page", post(admin_proxy_page))
        .route("/gost/client/proxy/config", post(admin_proxy_config))
        .route("/gost/client/proxy/delete", post(admin_proxy_delete))
        .route("/system/user", post(admin_user_list))
        .route("/system/user/page", post(admin_user_page))
        .route("/system/user/create", post(admin_user_create))
        .route("/system/user/update", post(admin_user_update))
        .route("/system/user/delete", post(admin_user_delete))
        .route("/system/config/base", post(admin_config_base))
        .route("/system/config/gost", post(admin_config_gost))
        .route("/system/config/email", post(admin_config_email))
        .route("/system/notice", post(admin_notice_list))
        .route("/system/notice/page", post(admin_notice_page))
        .route("/system/notice/create", post(admin_notice_create))
        .route("/system/notice/update", post(admin_notice_update))
        .route("/system/notice/delete", post(admin_notice_delete))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_middleware,
        ));

    app = app.nest("/api/v1/admin", admin);

    // ---- RPC WebSocket ----
    app = app.route(
        "/rpc/ws",
        get(rpc_ws_handler).with_state(state.clone()),
    );

    // ---- 全局中间件与静态资源 ----
    app = app
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .fallback(static_handler)
        .with_state(state);

    app
}

/// 鉴权中间件：解析 JWT 并注入上下文
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(token) = extract_token(&req) else {
        return unauthorized("缺少登录凭证");
    };
    match rscross_common::crypto::jwt_decode(&token, &state.config.inner.jwt_secret) {
        Ok(payload) => {
            req.extensions_mut().insert(UserAuth {
                code: payload.code,
                role: payload.role,
            });
            next.run(req).await
        }
        Err(_) => unauthorized("登录已失效"),
    }
}

/// 管理员鉴权
async fn admin_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(token) = extract_token(&req) else {
        return unauthorized("缺少登录凭证");
    };
    match rscross_common::crypto::jwt_decode(&token, &state.config.inner.jwt_secret) {
        Ok(payload) => {
            if payload.role != "admin" {
                return forbidden("需要管理员权限");
            }
            req.extensions_mut().insert(UserAuth {
                code: payload.code,
                role: payload.role,
            });
            next.run(req).await
        }
        Err(_) => unauthorized("登录已失效"),
    }
}

/// 用户认证信息
#[derive(Clone)]
pub struct UserAuth {
    pub code: String,
    pub role: String,
}

/// 从请求头或查询参数提取 token
fn extract_token(req: &Request) -> Option<String> {
    if let Some(v) = req.headers().get("token") {
        if let Ok(s) = v.to_str() {
            return Some(s.to_string());
        }
    }
    if let Some(v) = req.headers().get("authorization") {
        if let Ok(s) = v.to_str() {
            return Some(s.trim_start_matches("Bearer ").to_string());
        }
    }
    if let Some(q) = req.uri().query() {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("token=") {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// 从扩展中取当前用户
pub fn current_user(ext: &axum::http::Extensions) -> Option<UserAuth> {
    ext.get::<UserAuth>().cloned()
}

/// 统一 JSON 错误响应
pub fn unauthorized(msg: &str) -> Response {
    ApiResponse::<serde_json::Value>::fail(rscross_common::ErrorCode::Unauthorized, msg)
        .into_response()
}

pub fn forbidden(msg: &str) -> Response {
    ApiResponse::<serde_json::Value>::fail(rscross_common::ErrorCode::Forbidden, msg)
        .into_response()
}

/// 兜底处理器：返回内嵌前端资源
async fn static_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path();

    // API 未命中返回 404 JSON
    if path.starts_with("/api/") {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "code": rscross_common::ErrorCode::NotFound.as_i32(),
                "msg": "接口不存在",
            })),
        )
            .into_response();
    }

    // 内嵌前端资源
    match assets::get(path) {
        Some((bytes, mime)) => ([(axum::http::header::CONTENT_TYPE, mime)], bytes).into_response(),
        None => {
            // SPA 路由回退到 index.html
            if rscross_common::assets::is_spa_route(path) {
                if let Some((bytes, mime)) = assets::get("/index.html") {
                    return ([(axum::http::header::CONTENT_TYPE, mime)], bytes)
                        .into_response();
                }
            }
            Html("<h1>rscross</h1><p>前端资源未构建，请先执行 npm run build 并运行 scripts/embed-web.sh</p>")
                .into_response()
        }
    }
}

/// RPC WebSocket 端点
async fn rpc_ws_handler(
    State(state): State<AppState>,
    ws: axum::extract::ws::WebSocketUpgrade,
    headers: axum::http::HeaderMap,
) -> Response {
    // 提取认证 key
    let key = rscross_common::rpc::extract_key(&headers).unwrap_or_default();

    let rpc = crate::rpc::build_rpc_server(state);

    ws.on_upgrade(move |socket| async move {
        if let Err(e) = rpc.serve(socket).await {
            tracing::error!(error = %e, "RPC 服务异常");
        }
    })
}

/// 便捷：Ok 响应
pub fn ok<T: serde::Serialize>(data: T) -> Response {
    ApiResponse::ok(data).into_response()
}

/// 便捷：空成功响应
pub fn ok_msg(msg: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"code": 0, "msg": msg})),
    )
        .into_response()
}

/// 便捷：错误响应
pub fn err(msg: impl Into<String>) -> Response {
    AppError::msg(msg).into_response()
}

// ==================== 处理器实现 ====================
// 详见 handlers 子模块

mod auth_handlers;
mod normal_handlers;
mod admin_handlers;
mod public_handlers;
mod frp_handlers;
mod builders;

pub use auth_handlers::*;
pub use normal_handlers::*;
pub use admin_handlers::*;
pub use public_handlers::*;
pub use frp_handlers::*;
pub use builders::*;
