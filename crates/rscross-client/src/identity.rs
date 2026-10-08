//! 客户端本地状态目录：身份、Iroh 私钥、一次性接入令牌。

use std::path::{Path, PathBuf};

use rscross_common::Result;
use serde::{Deserialize, Serialize};

/// 从服务端注册后持久化的身份信息。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    /// 服务端分配的客户端 ID。
    pub client_id: Option<String>,
    /// agent token（长期凭证）。
    pub agent_token: Option<String>,
    /// 节点名。
    pub name: Option<String>,
    /// FerroTunnel 控制面地址（由服务端下发，可覆盖本地配置）。
    pub tunnel_server: Option<String>,
    /// FerroTunnel 握手 token（由服务端下发）。
    pub tunnel_token: Option<String>,
    /// 服务端建议的心跳间隔。
    pub heartbeat_secs: Option<u64>,
    /// 服务端下发的 P2P 设置。
    pub p2p: Option<P2pSettings>,
}

/// 服务端下发的 P2P 设置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct P2pSettings {
    /// 是否启用。
    pub enabled: bool,
    /// 路径策略字符串。
    pub policy: String,
    /// 服务端 Iroh 节点 ID。
    pub server_endpoint_id: Option<String>,
    /// 服务端寻址信息（JSON）。
    pub server_endpoint_addr: Option<String>,
    /// Relay 模式。
    pub relay_mode: String,
    /// 是否启用地址发现。
    pub address_lookup: bool,
}

/// 状态目录。
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// 打开（必要时创建）状态目录。
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| {
            rscross_common::Error::config(format!("创建状态目录 {} 失败: {e}", root.display()))
        })?;
        Ok(Self { root })
    }

    /// 目录路径。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Iroh 节点私钥路径。
    pub fn node_key_path(&self) -> PathBuf {
        self.root.join("node.key")
    }

    /// 身份文件路径。
    pub fn identity_path(&self) -> PathBuf {
        self.root.join("identity.json")
    }

    /// 一次性接入令牌文件路径。
    pub fn enroll_token_path(&self) -> PathBuf {
        self.root.join("enroll.token")
    }

    /// 读取身份（不存在或损坏都返回默认值，让调用方走重新注册流程）。
    pub fn load_identity(&self) -> Identity {
        match std::fs::read_to_string(self.identity_path()) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|err| {
                tracing::warn!(error = %err, "身份文件损坏，将重新注册");
                Identity::default()
            }),
            Err(_) => Identity::default(),
        }
    }

    /// 写回身份。
    pub fn save_identity(&self, identity: &Identity) -> Result<()> {
        let text = serde_json::to_string_pretty(identity)?;
        let path = self.identity_path();
        std::fs::write(&path, text).map_err(|e| {
            rscross_common::Error::config(format!("写入身份文件 {} 失败: {e}", path.display()))
        })?;
        restrict(&path);
        Ok(())
    }

    /// 读取一次性接入令牌。
    pub fn load_enroll_token(&self) -> Option<String> {
        std::fs::read_to_string(self.enroll_token_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// 写入一次性接入令牌。
    pub fn save_enroll_token(&self, token: &str) -> Result<()> {
        let path = self.enroll_token_path();
        std::fs::write(&path, token.trim()).map_err(|e| {
            rscross_common::Error::config(format!("写入接入令牌 {} 失败: {e}", path.display()))
        })?;
        restrict(&path);
        Ok(())
    }

    /// 注册成功后删除一次性令牌（它不可再用，留着只会造成「重复注册」的困惑）。
    pub fn clear_enroll_token(&self) {
        let path = self.enroll_token_path();
        if path.exists() {
            if let Err(err) = std::fs::remove_file(&path) {
                tracing::warn!(error = %err, "删除已用接入令牌失败");
            }
        }
    }
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(path = %path.display(), error = %err, "设置文件权限失败");
    }
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("rscross-{tag}-{stamp}"))
    }

    #[test]
    fn identity_roundtrip() {
        let dir = temp_dir("identity");
        let state = StateDir::open(&dir).expect("open");
        assert!(state.load_identity().agent_token.is_none());

        let identity = Identity {
            client_id: Some("c1".to_string()),
            agent_token: Some("rsa_x".to_string()),
            name: Some("n".to_string()),
            ..Default::default()
        };
        state.save_identity(&identity).expect("save");

        let loaded = state.load_identity();
        assert_eq!(loaded.client_id.as_deref(), Some("c1"));
        assert_eq!(loaded.agent_token.as_deref(), Some("rsa_x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_token_lifecycle() {
        let dir = temp_dir("enroll");
        let state = StateDir::open(&dir).expect("open");
        assert!(state.load_enroll_token().is_none());

        state.save_enroll_token("  rse_abc  ").expect("save");
        assert_eq!(state.load_enroll_token().as_deref(), Some("rse_abc"));

        state.clear_enroll_token();
        assert!(state.load_enroll_token().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_identity_falls_back_to_default() {
        let dir = temp_dir("corrupt");
        let state = StateDir::open(&dir).expect("open");
        std::fs::write(state.identity_path(), "{ not json").expect("write");
        assert!(state.load_identity().agent_token.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
