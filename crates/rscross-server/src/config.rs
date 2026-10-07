//! 服务端配置（包装公共配置）

pub use rscross_common::config::ServerConfig as CommonServerConfig;

use rscross_common::error::AppResult;

/// 服务端配置
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub inner: CommonServerConfig,
}

impl ServerConfig {
    /// 从文件或环境变量加载
    pub fn load() -> AppResult<Self> {
        let path = std::env::var("RSC_CONFIG").ok().or_else(|| {
            let p = std::path::Path::new("configs/config.yaml");
            p.exists().then(|| p.to_string_lossy().to_string())
        });

        Ok(Self {
            inner: rscross_common::config::load_server_config(path.as_deref())?,
        })
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }

    pub fn is_dev(&self) -> bool {
        self.inner.is_dev()
    }
}
