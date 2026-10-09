//! 客户端本地状态目录：身份、Iroh 私钥、一次性接入令牌。

use std::path::{Path, PathBuf};

use rscross_common::{NodeEndpoint, Result};
use serde::{Deserialize, Serialize};

/// 注册后持久化的身份信息。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    /// 控制台分配的客户端 ID。
    pub client_id: Option<String>,
    /// agent token（长期凭证）。
    pub agent_token: Option<String>,
    /// 节点名。
    pub name: Option<String>,
    /// 控制台建议的心跳间隔。
    pub heartbeat_secs: Option<u64>,
    /// 归属的服务端节点（数据面坐标）。控制台每次心跳都会回带，
    /// 因此「把客户端迁到另一台节点」不需要改客户端配置。
    pub node: Option<NodeEndpoint>,
}

impl Identity {
    /// 是否具备可用凭证。
    pub fn is_registered(&self) -> bool {
        self.client_id.is_some() && self.agent_token.is_some()
    }

    /// 归属节点的反向隧道地址。
    pub fn tunnel_server(&self) -> Option<String> {
        self.node.as_ref().map(|n| n.tunnel_server.clone())
    }
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

    /// 注册成功后删除一次性令牌（它不可再用）。
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
        std::env::temp_dir().join(format!("rscross-client-{tag}-{stamp}"))
    }

    #[test]
    fn identity_roundtrip_keeps_node_coordinates() {
        let dir = temp_dir("identity");
        let state = StateDir::open(&dir).expect("open");
        assert!(!state.load_identity().is_registered());

        let identity = Identity {
            client_id: Some("c1".to_string()),
            agent_token: Some("rsa_x".to_string()),
            name: Some("n".to_string()),
            heartbeat_secs: Some(15),
            node: Some(NodeEndpoint {
                node_id: "n1".to_string(),
                name: "node-1".to_string(),
                tunnel_server: "203.0.113.9:7835".to_string(),
                tunnel_token: "tt".to_string(),
                endpoint_id: None,
                endpoint_addr: None,
                public_addr: None,
                transport: "tcp".to_string(),
            }),
        };
        state.save_identity(&identity).expect("save");

        let loaded = state.load_identity();
        assert!(loaded.is_registered());
        assert_eq!(loaded.tunnel_server().as_deref(), Some("203.0.113.9:7835"));
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
        assert!(!state.load_identity().is_registered());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
