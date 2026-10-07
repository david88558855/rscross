//! 客户端配置

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 服务端地址
    #[serde(default)]
    pub addr: String,
    /// 连接密钥
    #[serde(default)]
    pub key: String,
    /// 是否启用 TLS
    #[serde(default)]
    pub tls: bool,
    /// 是否为节点模式
    #[serde(default)]
    pub node: bool,
    /// 代理服务地址（自定义域名网关）
    #[serde(default)]
    pub proxy_base_url: String,
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            key: String::new(),
            tls: false,
            node: false,
            proxy_base_url: String::new(),
            log_level: default_log_level(),
        }
    }
}

impl ClientConfig {
    /// 从配置文件或环境变量加载
    pub fn load() -> Result<Self> {
        let mut cfg = match std::env::var("RSC_CLIENT_CONFIG")
            .ok()
            .or_else(|| {
                let p = std::path::Path::new("configs/client.yaml");
                p.exists().then(|| p.to_string_lossy().to_string())
            })
        {
            Some(path) => {
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("读取客户端配置 {path} 失败"))?;
                serde_yaml::from_str(&content)
                    .with_context(|| format!("解析客户端配置 {path} 失败"))?
            }
            None => ClientConfig::default(),
        };

        apply_env(&mut cfg);
        Ok(cfg)
    }
}

fn apply_env(cfg: &mut ClientConfig) {
    if let Ok(v) = std::env::var("RSC_ADDR") {
        cfg.addr = v;
    }
    if let Ok(v) = std::env::var("RSC_KEY") {
        cfg.key = v;
    }
    if let Ok(v) = std::env::var("RSC_TLS") {
        cfg.tls = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(v) = std::env::var("RSC_NODE") {
        cfg.node = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(v) = std::env::var("RSC_LOG_LEVEL") {
        cfg.log_level = v;
    }
    if let Ok(v) = std::env::var("RSC_PROXY_BASE_URL") {
        cfg.proxy_base_url = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let c = ClientConfig::default();
        assert!(c.addr.is_empty());
        assert!(!c.tls);
        assert!(!c.node);
    }
}
