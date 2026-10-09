//! 控制面 HTTP API。

pub mod access;
pub mod agent;
pub mod auth;
pub mod client;
pub mod misc;
pub mod nodes;
pub mod users;
pub mod ws;

use axum::routing::{delete, get, patch, post};
use axum::Router;
use rscross_common::{DesiredTunnel, TunnelKind};
use rscross_store::TunnelRecord;

use crate::console;
use crate::error::ApiError;
use crate::state::AppState;

/// 服务端节点认证头。
pub const NODE_HEADER: &str = "x-rscross-node";
/// 内网客户端认证头。
pub const AGENT_HEADER: &str = "x-rscross-agent";

/// 管理员角色：可读可写，能看到令牌 / 访问密钥。
pub const ROLE_ADMIN: &str = "admin";
/// 只读角色：能看列表与统计，但所有写操作被拒，且看不到令牌 / 访问密钥。
pub const ROLE_VIEWER: &str = "viewer";

/// 校验角色名。缺省按 `viewer`（最小权限）。
///
/// 大小写不敏感，但**统一回写成小写**：库里只存 `admin` / `viewer` 两种字面量，
/// 这样 `state::require_admin` 与 `count_admins`（`WHERE role = 'admin'`）的
/// 字符串比较永远对得上 —— 否则 `"Admin"` 会既拿不到权限、又不计入
/// 「最后一个管理员」的保护，变成一个说不出哪里错的怪状态。
pub fn normalize_role(raw: Option<&str>) -> Result<String, ApiError> {
    let role = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| ROLE_VIEWER.to_string());
    match role.as_str() {
        ROLE_ADMIN => Ok(ROLE_ADMIN.to_string()),
        ROLE_VIEWER => Ok(ROLE_VIEWER.to_string()),
        other => Err(ApiError::bad_request(format!(
            "角色只能是 {ROLE_ADMIN} 或 {ROLE_VIEWER}（实际 {other:?}）"
        ))),
    }
}

/// 密码最短长度。
///
/// 自建内网工具，用户往往就是本人在几台机器之间同步口令；定成 8 位会把
/// 「顺手把默认密码改掉」这件事变得麻烦，反而助长「干脆不改」。
/// 6 位作为下限，配合下面的长度上限一起挡住粘贴整段文本这类误操作。
pub const PASSWORD_MIN_LEN: usize = 6;
/// 密码最长长度（挡住把整段文件当密码贴进来的情况）。
pub const PASSWORD_MAX_LEN: usize = 128;

/// 校验密码强度。注册与改密共用同一套规则，避免「注册能过、改密被拒」这类不一致。
pub fn validate_password(password: &str) -> Result<(), ApiError> {
    let len = password.chars().count();
    if len < PASSWORD_MIN_LEN {
        return Err(ApiError::bad_request(format!(
            "密码至少 {PASSWORD_MIN_LEN} 位"
        )));
    }
    if len > PASSWORD_MAX_LEN {
        return Err(ApiError::bad_request(format!(
            "密码不能超过 {PASSWORD_MAX_LEN} 位"
        )));
    }
    Ok(())
}

/// 组装路由。
///
/// 注意：
/// - 同一路径的多个方法必须写在**同一个** `MethodRouter` 上（`get(a).post(b)`），
///   分成两次 `.route()` 会让 axum 在启动时 panic。
/// - 这里**不注册**通配路由，全部交给 [`console::fallback`] 处理，
///   这样 `/api/v1/未知路径` 才会返回 JSON 404 而不是被 SPA 首页吞掉。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/health", get(misc::health))
        // 控制面主协议（WebSocket）：客户端与服务端节点都走这里
        .route(
            rscross_common::console::CONTROL_WS_PATH,
            get(ws::control_ws),
        )
        // 控制台认证
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/password", post(auth::change_password))
        // 用户管理（仅管理员）
        .route(
            "/api/v1/users",
            get(users::list_users).post(users::create_user),
        )
        .route(
            "/api/v1/users/{id}",
            patch(users::patch_user).delete(users::delete_user),
        )
        // 概览 / 报表
        .route("/api/v1/overview", get(misc::overview))
        .route("/api/v1/traffic", get(misc::traffic))
        // 服务端节点（控制台侧管理）
        .route(
            "/api/v1/nodes",
            get(nodes::list_nodes).post(nodes::create_node),
        )
        .route(
            "/api/v1/nodes/{id}",
            get(nodes::get_node)
                .patch(nodes::patch_node)
                .delete(nodes::delete_node),
        )
        .route("/api/v1/nodes/{id}/token", post(nodes::rotate_node_token))
        // 取回接入命令（命令原文不再"只显示一次"）
        .route("/api/v1/nodes/{id}/command", get(nodes::get_node_command))
        // 客户端与隧道
        .route(
            "/api/v1/clients",
            get(client::list_clients).post(client::create_client),
        )
        .route(
            "/api/v1/clients/{id}",
            get(client::get_client)
                .patch(client::patch_client)
                .delete(client::delete_client),
        )
        // 「待接入」的客户端令牌：列表（含可复制的命令）与撤销
        .route("/api/v1/enroll-tokens", get(client::list_enroll_tokens))
        .route(
            "/api/v1/enroll-tokens/{id}",
            delete(client::revoke_enroll_token),
        )
        .route("/api/v1/tunnels", get(client::list_tunnels))
        .route(
            "/api/v1/clients/{id}/tunnels",
            get(client::list_client_tunnels).post(client::create_tunnel),
        )
        .route(
            "/api/v1/tunnels/{id}",
            patch(client::patch_tunnel).delete(client::delete_tunnel),
        )
        .route(
            "/api/v1/tunnels/{id}/access-key",
            post(client::rotate_access_key),
        )
        // 审计 / 日志 / 配置
        .route("/api/v1/logs", get(misc::logs))
        .route("/api/v1/audit", get(misc::audit_log))
        .route(
            "/api/v1/config",
            get(misc::get_config).put(misc::put_config),
        )
        // 访问端（免鉴权：凭访问密钥换取节点坐标；密钥本身就是凭证）
        .route("/api/v1/access/resolve", post(access::resolve))
        // 服务端节点侧（节点进程调用）
        .route("/api/v1/node/enroll", post(nodes::node_enroll))
        .route("/api/v1/node/heartbeat", post(nodes::node_heartbeat))
        .route("/api/v1/node/self", get(nodes::node_self))
        // 内网客户端侧（客户端进程调用）
        .route("/api/v1/agent/enroll", post(agent::enroll))
        .route("/api/v1/agent/heartbeat", post(agent::heartbeat))
        .route("/api/v1/agent/tunnels", get(agent::tunnels))
        .route("/api/v1/agent/logs", post(agent::push_logs))
        .fallback(console::fallback)
}

/// 把数据库里的隧道记录转成「下发给客户端」的形态。
///
/// - 只保留启用项；
/// - 协议字符串无法识别时跳过并告警（而不是让整个心跳失败）；
/// - 客户端不依赖 `rusqlite`，所以这里做一次 DTO 转换。
pub fn desired_tunnels(records: Vec<TunnelRecord>) -> Vec<DesiredTunnel> {
    records
        .into_iter()
        .filter(|t| t.enabled)
        .filter_map(|t| {
            let Some(proto) = parse_proto(&t.proto) else {
                tracing::warn!(tunnel = %t.name, proto = %t.proto, "隧道协议无法识别，跳过下发");
                return None;
            };
            let kind = TunnelKind::parse(&t.kind).unwrap_or_default();
            // 私有 / P2P 隧道没有密钥就无法校验来访者，宁可不下发也不要下发一条
            // 「看起来在跑、实际谁都连不上」的隧道。
            if kind.needs_access_key() && t.access_key.as_deref().unwrap_or("").is_empty() {
                tracing::warn!(
                    tunnel = %t.name,
                    kind = %kind,
                    "隧道缺少访问密钥，跳过下发（可在控制台重新签发）"
                );
                return None;
            }
            Some(DesiredTunnel {
                id: t.id,
                name: t.name,
                kind,
                proto,
                local_addr: t.local_addr,
                remote_port: t.remote_port.and_then(|p| u16::try_from(p).ok()),
                host: t.host,
                path_prefix: t.path_prefix,
                access_key: t.access_key,
                allow_relay: t.allow_relay,
                enabled: t.enabled,
                rate_limit_kbps: u32::try_from(t.rate_limit_kbps.max(0)).unwrap_or(0),
                conn_limit: u32::try_from(t.conn_limit.max(0)).unwrap_or(0),
            })
        })
        .collect()
}

/// 校验隧道协议字符串。
pub fn parse_proto(raw: &str) -> Option<rscross_common::TunnelProto> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(rscross_common::TunnelProto::Tcp),
        "http" => Some(rscross_common::TunnelProto::Http),
        "https" => Some(rscross_common::TunnelProto::Https),
        "udp" => Some(rscross_common::TunnelProto::Udp),
        _ => None,
    }
}

/// 归一化并校验名称（用于唯一索引与展示）。
pub fn normalize_name(raw: &str) -> Result<String, crate::error::ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(crate::error::ApiError::bad_request("名称不能为空"));
    }
    if name.len() > 64 {
        return Err(crate::error::ApiError::bad_request(
            "名称不能超过 64 个字符",
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(crate::error::ApiError::bad_request(
            "名称只能包含字母、数字、'-'、'_'、'.'",
        ));
    }
    Ok(name.to_string())
}

/// 把「唯一约束冲突」翻译成 409，其余保持原样。
pub fn map_store_conflict(err: rscross_common::Error) -> crate::error::ApiError {
    let text = err.to_string();
    if text.contains("UNIQUE") || text.contains("constraint") {
        crate::error::ApiError::conflict("名称或端口与已有记录冲突")
    } else {
        crate::error::ApiError::from(err)
    }
}

/// 从请求头取任意认证头的值。
pub fn header_token(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_defaults_to_viewer_and_rejects_typos() {
        // 不给角色时按最小权限处理 —— 自助注册与管理员建号都会走到这里。
        assert_eq!(normalize_role(None).expect("缺省"), ROLE_VIEWER);
        assert_eq!(normalize_role(Some("  ")).expect("空白"), ROLE_VIEWER);
        assert_eq!(normalize_role(Some("admin")).expect("admin"), ROLE_ADMIN);
        // 大小写不敏感，但必须回写成小写：库里混进 "Admin" 会让
        // require_admin 与 count_admins 双双认不出来。
        assert_eq!(normalize_role(Some("ADMIN")).expect("ADMIN"), ROLE_ADMIN);
        assert_eq!(normalize_role(Some("Viewer")).expect("Viewer"), ROLE_VIEWER);
        assert_eq!(normalize_role(Some(" admin ")).expect("带空格"), ROLE_ADMIN);
        // 空串等同于没给，仍然落到最小权限。
        assert_eq!(normalize_role(Some("")).expect("空串"), ROLE_VIEWER);
        assert!(normalize_role(Some("operator")).is_err());
    }

    #[test]
    fn password_policy_is_shared_by_register_and_change() {
        // 下限是 6 位（自建工具场景下刻意压低，换取「愿意把默认密码改掉」）。
        assert_eq!(PASSWORD_MIN_LEN, 6);
        assert!(validate_password("12345").is_err(), "短于 6 位应被拒");
        assert!(validate_password("123456").is_ok(), "6 位应通过");
        // 按字符数而不是字节数：一个汉字 3 字节，按字节判会让 4 个汉字
        // （12 字节）「达标」，也会让 44 个汉字被误判超长。
        assert!(validate_password("密码密码").is_err(), "4 个汉字应被拒");
        assert!(validate_password("密码密码密码").is_ok(), "6 个汉字应通过");
        assert!(validate_password(&"x".repeat(PASSWORD_MAX_LEN)).is_ok());
        assert!(validate_password(&"x".repeat(PASSWORD_MAX_LEN + 1)).is_err());
    }
}
