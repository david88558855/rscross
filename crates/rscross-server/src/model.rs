//! 数据模型：对应原 GORM 实体
//!
//! 字段命名与原项目保持一致（snake_case），表名单复数与 GORM 默认一致。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 允许编辑
pub const ALLOW_EDIT: i32 = 1;
/// 拒绝编辑
pub const DENY_EDIT: i32 = 2;
/// 允许删除
pub const ALLOW_DEL: i32 = 1;
/// 拒绝删除
pub const DENY_DEL: i32 = 2;

/// 实体基类字段
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Base {
    pub id: i64,
    pub code: String,
    pub allow_edit: i32,
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 系统用户
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemUser {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 登录名
    pub username: String,
    /// 口令哈希
    pub password: String,
    /// 角色：admin / user
    pub role: String,
    /// 邮箱
    #[serde(default)]
    pub email: String,
    /// 状态：1 正常 2 封禁
    pub status: i32,
    /// 余额
    #[serde(default)]
    pub balance: i64,
    /// 流量配额（字节，-1 无限）
    #[serde(default)]
    pub traffic_limit: i64,
    /// 隧道数量上限
    #[serde(default)]
    pub tunnel_limit: i32,
    /// 是否允许创建节点
    #[serde(default)]
    pub allow_node: i32,
    /// 是否允许创建客户端
    #[serde(default)]
    pub allow_client: i32,
    /// 等级
    #[serde(default)]
    pub level: i32,
    /// 邀请人编号
    #[serde(default)]
    pub inviter_code: String,
    /// 签到配置
    #[serde(default)]
    pub checkin_enabled: i32,
}

/// 客户端配置项（内嵌到各隧道表）
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientConfig {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub use_encryption: i32,
    pub use_compression: i32,
    pub pool_count: i32,
    /// 限速值，KB 为单位
    pub limiter: i32,
    /// 限速总配额（字节）
    #[serde(default)]
    pub limiter_total: i64,
    /// 已用流量（字节）
    #[serde(default)]
    pub limiter_usage: i64,
}

/// 准入配置
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientAdmission {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 流量限制（字节，-1 无限）
    pub bandwidth_limit: i64,
    /// 隧道数量限制
    pub tunnel_limit: i32,
    /// 最大连接数
    pub max_conns: i32,
    /// 有效期天数，0 永久
    pub expire_days: i32,
    /// 是否启用
    pub enable: i32,
}

/// 客户端
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClient {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 连接密钥
    pub key: String,
    /// 名称
    pub name: String,
    /// 所属用户
    pub user_code: String,
    /// 状态
    pub status: i32,
    /// 启用
    pub enable: i32,
    /// 节点数量上限
    pub node_limit: i32,
    /// 备注
    #[serde(default)]
    pub remark: String,
}

/// 节点
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostNode {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 连接密钥
    pub key: String,
    /// 节点名
    pub name: String,
    /// 节点 IP
    pub ip: String,
    /// 服务端口
    pub port: String,
    /// HTTP 域名端口
    pub http_port: String,
    /// 传输协议：tcp / kcp / quic
    pub protocol: String,
    /// 状态
    pub status: i32,
    /// 启用
    pub enable: i32,
    /// 所属用户
    pub user_code: String,
    /// 最大连接池
    pub max_pool_count: i32,
    /// 允许泛域名
    pub allow_domain_matcher: i32,
    /// 禁用 P2P 中继回退
    pub p2p_disable_forward: i32,
    /// 带宽限制
    pub bandwidth_limit: i64,
    /// 已用带宽
    pub bandwidth_usage: i64,
}

impl GostNode {
    /// 控制流监听端口
    pub fn origin_port(&self) -> i64 {
        rscross_common::util::str_must_int(&self.port)
    }

    /// 外部可访问地址
    pub fn address(&self) -> (String, i64) {
        (self.ip.clone(), self.origin_port())
    }

    /// 组装域名：子域名 + 自定义域名
    pub fn domain_host(&self, prefix: &str, custom: &str, use_proxy: bool) -> String {
        if !custom.is_empty() {
            return custom.to_string();
        }
        let base = if self.ip.is_empty() {
            String::new()
        } else {
            self.ip.clone()
        };
        if prefix.is_empty() {
            base
        } else {
            format!("{prefix}.{base}")
        }
        .trim_matches('.')
        .to_string()
    }
}

/// 节点配置
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostNodeConfig {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 配置类型：client / node
    pub config_type: String,
    /// 配置内容（YAML/JSON 文本）
    pub content: String,
    /// 内容类型
    pub content_type: String,
    /// 状态
    pub status: i32,
    /// 名称
    pub name: String,
    /// 所属用户
    pub user_code: String,
}

/// 隧道认证
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostAuth {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 隧道编号
    pub tunnel_code: String,
    /// 用户名
    pub user: String,
    /// 密码
    pub password: String,
    /// 状态
    pub status: i32,
}

/// 域名映射隧道
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientHost {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub target_ip: String,
    pub target_port: String,
    pub target_https: i32,
    pub domain_prefix: String,
    pub custom_domain: String,
    pub custom_cert: String,
    pub custom_key: String,
    pub custom_force_https: i32,
    pub custom_domain_matcher: i32,
    pub node_code: String,
    pub client_code: String,
    pub user_code: String,
    pub enable: i32,
    pub status: i32,
    pub use_encryption: i32,
    pub use_compression: i32,
    pub pool_count: i32,
    pub limiter: i32,
    pub limiter_total: i64,
    pub limiter_usage: i64,
    pub bandwidth_limit: i64,
    pub tunnel_limit: i32,
    pub max_conns: i32,
    pub expire_days: i32,
}

/// 端口转发隧道
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientForward {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub target_ip: String,
    pub target_port: String,
    pub port: String,
    pub node_code: String,
    pub client_code: String,
    pub user_code: String,
    pub enable: i32,
    pub status: i32,
    pub use_encryption: i32,
    pub use_compression: i32,
    pub pool_count: i32,
    pub limiter: i32,
    /// Proxy Protocol：0 无 1 v1 2 v2
    pub proxy_protocol: i32,
    pub limiter_total: i64,
    pub limiter_usage: i64,
    pub bandwidth_limit: i64,
    pub tunnel_limit: i32,
    pub max_conns: i32,
    pub expire_days: i32,
}

/// 私有隧道
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientTunnel {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub target_ip: String,
    pub target_port: String,
    /// 访客密钥
    pub vkey: String,
    pub node_code: String,
    pub client_code: String,
    pub user_code: String,
    pub enable: i32,
    pub status: i32,
    pub use_encryption: i32,
    pub use_compression: i32,
    pub pool_count: i32,
    pub limiter: i32,
    pub limiter_total: i64,
    pub limiter_usage: i64,
    pub bandwidth_limit: i64,
    pub tunnel_limit: i32,
    pub max_conns: i32,
    pub expire_days: i32,
}

/// P2P 隧道
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientP2P {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub target_ip: String,
    pub target_port: String,
    pub vkey: String,
    /// 是否允许中继回退
    pub forward: i32,
    pub node_code: String,
    pub client_code: String,
    pub user_code: String,
    pub enable: i32,
    pub status: i32,
    pub use_encryption: i32,
    pub use_compression: i32,
    pub pool_count: i32,
    pub limiter: i32,
    pub limiter_total: i64,
    pub limiter_usage: i64,
    pub bandwidth_limit: i64,
    pub tunnel_limit: i32,
    pub max_conns: i32,
    pub expire_days: i32,
}

/// 代理隧道
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostClientProxy {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    /// 代理监听端口
    pub port: String,
    /// 认证用户
    pub auth_user: String,
    /// 认证密码
    pub auth_pwd: String,
    pub node_code: String,
    pub client_code: String,
    pub user_code: String,
    pub enable: i32,
    pub status: i32,
    pub use_encryption: i32,
    pub use_compression: i32,
    pub pool_count: i32,
    pub limiter: i32,
    pub limiter_total: i64,
    pub limiter_usage: i64,
    pub bandwidth_limit: i64,
    pub tunnel_limit: i32,
    pub max_conns: i32,
    pub expire_days: i32,
}

/// FRP 自定义配置
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ClientCfg {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub content: String,
    pub content_type: String,
    pub client_code: String,
    pub user_code: String,
    pub enable: i32,
    pub status: i32,
}

/// 流量观测
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostObs {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub type: String,
    pub date: String,
    pub input_bytes: i64,
    pub output_bytes: i64,
    pub user_code: String,
    pub client_code: String,
    pub node_code: String,
}

/// 系统配置
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemConfig {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub value: String,
    /// 配置分组：base / gost / email
    pub group: String,
}

/// 系统公告
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemNotice {
    pub id: i64,
    pub code: String,
    #[serde(rename = "allowEdit")]
    pub allow_edit: i32,
    #[serde(rename = "allowDel")]
    pub allow_del: i32,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub title: String,
    pub content: String,
    pub type: String,
    pub status: i32,
}

/// 节点域名
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostNodeDomain {
    pub id: i64,
    pub code: String,
    pub node_code: String,
    pub domain: String,
    pub status: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 节点端口
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostNodePort {
    pub id: i64,
    pub code: String,
    pub node_code: String,
    pub port: i64,
    pub status: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 节点绑定（节点与客户端的关联）
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GostNodeBind {
    pub id: i64,
    pub code: String,
    pub node_code: String,
    pub user_code: String,
    pub client_code: String,
    pub status: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 用户邮箱
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemUserEmail {
    pub id: i64,
    pub code: String,
    pub user_code: String,
    pub email: String,
    pub status: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 用户签到
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemUserCheckin {
    pub id: i64,
    pub code: String,
    pub user_code: String,
    pub date: String,
    pub amount: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 通用配置键
pub mod config_key {
    pub const SITE_NAME: &str = "site_name";
    pub const SITE_URL: &str = "site_url";
    pub const REGISTER_ENABLE: &str = "register_enable";
    pub const REGISTER_CODE: &str = "register_code";
    pub const EMAIL_ENABLE: &str = "email_enable";
    pub const EMAIL_HOST: &str = "email_host";
    pub const EMAIL_PORT: &str = "email_port";
    pub const EMAIL_USER: &str = "email_user";
    pub const EMAIL_PASSWORD: &str = "email_password";
    pub const GOST_TRAFFIC: &str = "gost_traffic";
    pub const GOST_EXPIRE: &str = "gost_expire";
    pub const GOST_BANDWIDTH: &str = "gost_bandwidth";
    pub const GOST_P2P: &str = "gost_p2p";
    pub const NOTICE: &str = "notice";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_origin_port() {
        let n = GostNode {
            id: 1,
            code: "n1".into(),
            allow_edit: 1,
            allow_del: 1,
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            key: "k".into(),
            name: "node".into(),
            ip: "1.2.3.4".into(),
            port: "7000".into(),
            http_port: "8080".into(),
            protocol: "tcp".into(),
            status: 1,
            enable: 1,
            user_code: "u1".into(),
            max_pool_count: 5,
            allow_domain_matcher: 0,
            p2p_disable_forward: 0,
            bandwidth_limit: 0,
            bandwidth_usage: 0,
        };
        assert_eq!(n.origin_port(), 7000);
        assert_eq!(n.address(), ("1.2.3.4".to_string(), 7000));
    }
}
