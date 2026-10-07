//! 配置模型：服务端、客户端与各类代理配置

use serde::{Deserialize, Serialize};

use crate::msg::TransportConfig;
use crate::ProxyType;

/// 服务端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 认证令牌
    #[serde(default)]
    pub auth_token: String,
    /// 控制流监听地址
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// 控制流监听端口
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    /// vhost HTTP 监听端口
    #[serde(default)]
    pub vhost_http_port: u16,
    /// vhost HTTPS 监听端口
    #[serde(default)]
    pub vhost_https_port: u16,
    /// 连接池大小
    #[serde(default = "default_pool_count")]
    pub max_pool_count: i32,
    /// 心跳超时（秒）
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: i64,
    /// HTTP 插件地址前缀，节点侧由 rscross-server 注入
    #[serde(default)]
    pub http_plugin_addr: String,
    /// 子域名主机名
    #[serde(default)]
    pub sub_domain_host: String,
    /// 自定义域名转发目标（网关场景）
    #[serde(default)]
    pub custom_domain_target: String,
    /// 自定义域名证书
    #[serde(default)]
    pub custom_domain_cert: String,
    /// 自定义域名私钥
    #[serde(default)]
    pub custom_domain_key: String,
    /// 强制 HTTPS
    #[serde(default)]
    pub custom_domain_force_https: bool,
}

fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    7000
}
fn default_pool_count() -> i32 {
    5
}
fn default_heartbeat_timeout() -> i64 {
    40
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            auth_token: String::new(),
            bind_addr: default_bind_addr(),
            bind_port: default_bind_port(),
            vhost_http_port: 0,
            vhost_https_port: 0,
            max_pool_count: default_pool_count(),
            heartbeat_timeout: default_heartbeat_timeout(),
            http_plugin_addr: String::new(),
            sub_domain_host: String::new(),
            custom_domain_target: String::new(),
            custom_domain_cert: String::new(),
            custom_domain_key: String::new(),
            custom_domain_force_https: false,
        }
    }
}

impl ServerConfig {
    /// 校验配置
    pub fn validate(&self) -> Result<(), String> {
        if self.bind_port == 0 {
            return Err("控制流端口不能为 0".to_string());
        }
        if self.max_pool_count < 0 {
            return Err("连接池大小不能为负数".to_string());
        }
        Ok(())
    }
}

/// 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 认证令牌（节点/客户端编号）
    #[serde(default)]
    pub auth_token: String,
    /// 服务端地址
    #[serde(default)]
    pub server_addr: String,
    /// 服务端控制流端口
    #[serde(default = "default_bind_port")]
    pub server_port: u16,
    /// 连接池大小
    #[serde(default = "default_pool_count")]
    pub pool_count: i32,
    /// 登录失败时退出
    #[serde(default)]
    pub login_fail_exit: bool,
    /// 心跳间隔（秒）
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: i64,
    /// 元数据（用户名/密码）
    #[serde(default)]
    pub metadatas: std::collections::HashMap<String, String>,
    /// 传输层全局配置
    #[serde(default)]
    pub transport: TransportConfig,
    /// 走代理连接服务端
    #[serde(default)]
    pub proxy_url: String,
}

fn default_heartbeat_interval() -> i64 {
    30
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            auth_token: String::new(),
            server_addr: String::new(),
            server_port: default_bind_port(),
            pool_count: default_pool_count(),
            login_fail_exit: false,
            heartbeat_interval: default_heartbeat_interval(),
            metadatas: std::collections::HashMap::new(),
            transport: TransportConfig::default(),
            proxy_url: String::new(),
        }
    }
}

impl ClientConfig {
    /// 服务端控制流地址
    pub fn control_addr(&self) -> String {
        format!("{}:{}", self.server_addr, self.server_port)
    }
}

/// 代理基础配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBaseConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    /// 认证令牌
    #[serde(default)]
    pub auth_token: String,
    /// 本地服务 IP
    #[serde(default = "default_local_ip")]
    pub local_ip: String,
    /// 本地服务端口
    #[serde(default)]
    pub local_port: u16,
    /// 远程监听端口
    #[serde(default)]
    pub remote_port: u16,
    /// 自定义域名
    #[serde(default)]
    pub custom_domains: Vec<String>,
    /// 负载均衡组名
    #[serde(default)]
    pub load_balancer_group: String,
    /// 传输层配置
    #[serde(default)]
    pub transport: TransportConfig,
    /// 元数据
    #[serde(default)]
    pub metadatas: std::collections::HashMap<String, String>,
    /// Proxy Protocol 版本
    #[serde(default)]
    pub proxy_protocol_version: String,
}

fn default_local_ip() -> String {
    "127.0.0.1".to_string()
}

impl ProxyBaseConfig {
    /// 代理类型
    pub fn proxy_type_enum(&self) -> Option<ProxyType> {
        ProxyType::from_str_opt(&self.proxy_type)
    }

    /// 本地服务地址
    pub fn local_addr(&self) -> String {
        format!("{}:{}", self.local_ip, self.local_port)
    }

    /// 校验代理配置
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("代理名不能为空".to_string());
        }
        let Some(pt) = self.proxy_type_enum() else {
            return Err(format!("未知的代理类型: {}", self.proxy_type));
        };
        match pt {
            ProxyType::Tcp | ProxyType::Udp => {
                if self.remote_port == 0 {
                    return Err(format!("{} 代理必须指定远程端口", pt));
                }
            }
            ProxyType::Http | ProxyType::Https => {
                if self.custom_domains.is_empty() && self.load_balancer_group.is_empty() {
                    return Err("HTTP 代理必须指定自定义域名或负载均衡组".to_string());
                }
            }
            ProxyType::Stcp | ProxyType::Sudp | ProxyType::Xtcp => {
                if self.secret_key_required() && self.metadatas.get("secret_key").is_none() {
                    // 密钥通过 metadatas 传递
                }
            }
        }
        if self.local_port == 0 {
            return Err("本地服务端口不能为 0".to_string());
        }
        Ok(())
    }

    fn secret_key_required(&self) -> bool {
        false
    }

    /// 私有隧道密钥
    pub fn secret_key(&self) -> String {
        self.metadatas
            .get("secret_key")
            .cloned()
            .or_else(|| self.metadatas.get("secretKey").cloned())
            .unwrap_or_default()
    }
}

/// 带宽限速，从配置字符串读取
pub fn bandwidth_of(cfg: &ProxyBaseConfig) -> Option<u64> {
    cfg.transport.bandwidth_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(t: &str) -> ProxyBaseConfig {
        ProxyBaseConfig {
            name: "p1".into(),
            proxy_type: t.into(),
            auth_token: String::new(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 0,
            custom_domains: vec![],
            load_balancer_group: String::new(),
            transport: TransportConfig::default(),
            metadatas: Default::default(),
            proxy_protocol_version: String::new(),
        }
    }

    #[test]
    fn test_validate_tcp_requires_remote_port() {
        let mut c = base("tcp");
        assert!(c.validate().is_err());
        c.remote_port = 9000;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_http_requires_domain() {
        let mut c = base("http");
        assert!(c.validate().is_err());
        c.custom_domains = vec!["a.example.com".into()];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_unknown_type() {
        assert!(base("magic").validate().is_err());
    }

    #[test]
    fn test_client_control_addr() {
        let c = ClientConfig {
            server_addr: "1.2.3.4".into(),
            server_port: 7000,
            ..Default::default()
        };
        assert_eq!(c.control_addr(), "1.2.3.4:7000");
    }
}
