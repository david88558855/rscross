//! `rscross-auth`：认证与鉴权原语。
//!
//! 设计选择：
//! - **密码**用 Argon2id 的原始 KDF 接口（[`argon2::Argon2::hash_password_into`]），
//!   自行携带 salt 并存储为 `v1$salt$hash`。这样不依赖 `SaltString` / `PasswordHash`
//!   的 RNG trait 绑定，跨版本更稳。
//! - **令牌**一律「明文只出现一次、库内只存 SHA-256 摘要」，配合常数时间比较。
//! - **登录限流**在内存里做（进程级），不依赖外部组件。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use rscross_common::{Error, Result};
use rscross_store::{SessionRecord, Store};
use sha2::{Digest, Sha256};

/// 哈希版本前缀，便于未来平滑升级参数。
const HASH_PREFIX: &str = "v1";
/// 盐长度（字节）。
const SALT_LEN: usize = 16;
/// 派生密钥长度（字节）。
const KEY_LEN: usize = 32;

/// 令牌明文长度（字节）。
pub const TOKEN_BYTES: usize = 32;

fn argon2() -> Argon2<'static> {
    // Argon2id + 19 版本，参数为 OWASP 推荐的「19 MiB / 2 次迭代 / 1 lane」
    // 的轻量变体（32 MiB / 3 次迭代在低配 VPS 上会让登录明显变慢）。
    let params = Params::new(32 * 1024, 3, 1, Some(KEY_LEN)).expect("argon2 参数是常量且合法");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// 计算密码哈希，返回 `v1$<salt_hex>$<hash_hex>`。
pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err(Error::auth("密码不能为空"));
    }
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let mut out = [0u8; KEY_LEN];
    argon2()
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| Error::auth(format!("密码哈希失败: {e}")))?;

    Ok(format!(
        "{HASH_PREFIX}${}${}",
        hex::encode(salt),
        hex::encode(out)
    ))
}

/// 校验密码。任何格式错误都返回 `false`，不泄漏内部细节。
pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut parts = stored.split('$');
    let (Some(prefix), Some(salt_hex), Some(hash_hex), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if prefix != HASH_PREFIX {
        return false;
    }
    let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(hash_hex)) else {
        return false;
    };
    if salt.len() != SALT_LEN || expected.len() != KEY_LEN {
        return false;
    }

    let mut out = [0u8; KEY_LEN];
    if argon2()
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .is_err()
    {
        return false;
    }
    constant_time_eq(&out, &expected)
}

/// 常数时间字节比较（长度不同立刻返回 `false`，长度本身不是秘密）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 生成一个新的令牌明文（32 字节 → 64 位十六进制）。
pub fn new_token() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut buf = [0u8; TOKEN_BYTES];
    rng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// 计算令牌摘要，用于落库与查找。
pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// 生成 `agent` token，形如 `rsa_<32hex>`，便于在日志里一眼识别类型。
pub fn new_agent_token() -> String {
    format!("rsa_{}", new_token())
}

/// 生成服务端**节点** token，形如 `rsn_<32hex>`。
pub fn new_node_token() -> String {
    format!("rsn_{}", new_token())
}

/// 生成 `enroll` token，形如 `rse_<32hex>`。
pub fn new_enroll_token() -> String {
    format!("rse_{}", new_token())
}

/// 会话创建结果。
#[derive(Debug, Clone)]
pub struct IssuedSession {
    /// 会话 token 明文（只返回一次，客户端存 cookie / localStorage）。
    pub token: String,
    /// 过期时间（RFC3339）。
    pub expires_at: String,
    /// 所属用户。
    pub user_id: String,
}

/// 为用户签发一个会话。
pub async fn issue_session(
    store: &Store,
    user_id: &str,
    ttl_hours: u64,
    user_agent: Option<String>,
) -> Result<IssuedSession> {
    let token = new_token();
    let hash = token_hash(&token);
    let expires = rscross_common::time::now()
        + chrono::Duration::from_std(Duration::from_secs(ttl_hours.max(1) * 3600))
            .map_err(|e| Error::auth(format!("会话有效期换算失败: {e}")))?;
    let expires_at = rscross_common::time::to_rfc3339(expires);

    store
        .create_session(hash, user_id.to_string(), expires_at.clone(), user_agent)
        .await?;

    Ok(IssuedSession {
        token,
        expires_at,
        user_id: user_id.to_string(),
    })
}

/// 校验会话 token 是否有效，返回对应会话记录。
pub async fn verify_session(store: &Store, token: &str) -> Result<Option<SessionRecord>> {
    let hash = token_hash(token);
    let Some(session) = store.find_session(&hash).await? else {
        return Ok(None);
    };
    if session.expires_at < rscross_common::time::now_rfc3339() {
        // 顺手清理过期会话，避免表无限增长
        let _ = store.delete_session(&hash).await;
        return Ok(None);
    }
    Ok(Some(session))
}

/// 从 `Authorization: Bearer xxx` 或 cookie 值里取出 token。
pub fn extract_bearer(header_value: Option<&str>) -> Option<String> {
    let raw = header_value?;
    let raw = raw.trim();
    let rest = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// 进程级登录限流器。
///
/// 仅用于抵御在线暴力破解；多副本部署时应换成 Redis 之类的共享存储
/// （见 `docs/ROADMAP.md` 阶段 2 的「后续加固」）。
#[derive(Debug, Default)]
pub struct LoginThrottle {
    inner: Mutex<HashMap<String, Attempt>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Attempt {
    failures: u32,
    locked_until_unix: i64,
}

impl LoginThrottle {
    /// 创建空的限流器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 登录前检查。被锁定时返回 `Err`，消息里带上剩余秒数。
    pub fn check(&self, key: &str) -> Result<()> {
        let now = rscross_common::time::now().timestamp();
        let guard = self.lock();
        if let Some(a) = guard.get(key) {
            if a.locked_until_unix > now {
                let remain = a.locked_until_unix - now;
                return Err(Error::auth(format!("登录已锁定，请 {remain} 秒后再试")));
            }
        }
        Ok(())
    }

    /// 记录一次失败；达到阈值则上锁。
    pub fn record_failure(&self, key: &str, max_attempts: u32, lock_minutes: u64) {
        if max_attempts == 0 {
            return;
        }
        let now = rscross_common::time::now().timestamp();
        let mut guard = self.lock();
        let entry = guard.entry(key.to_string()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= max_attempts {
            entry.locked_until_unix = now + (lock_minutes.max(1) as i64) * 60;
            entry.failures = 0;
            tracing::warn!(key, "登录失败次数超限，已临时锁定");
        }
    }

    /// 登录成功后清零。
    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    /// 清理已过期的条目（由后台任务周期性调用）。
    pub fn sweep(&self) {
        let now = rscross_common::time::now().timestamp();
        let mut guard = self.lock();
        guard.retain(|_, a| a.locked_until_unix > now || a.failures > 0);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Attempt>> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let stored = hash_password("S3cret!").expect("hash");
        assert!(stored.starts_with("v1$"));
        assert!(verify_password("S3cret!", &stored));
        assert!(!verify_password("wrong", &stored));
    }

    #[test]
    fn password_hash_is_salted() {
        let a = hash_password("same").expect("hash");
        let b = hash_password("same").expect("hash");
        assert_ne!(a, b, "两次哈希必须因随机盐而不同");
        assert!(verify_password("same", &a));
        assert!(verify_password("same", &b));
    }

    #[test]
    fn malformed_hash_is_rejected_not_panicking() {
        for bad in ["", "v1$", "v1$zz$zz", "v2$aa$bb", "v1$aabb$cc"] {
            assert!(!verify_password("x", bad), "输入 {bad:?} 不应通过");
        }
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn token_hash_is_stable_and_opaque() {
        let t = new_agent_token();
        assert!(t.starts_with("rsa_"));
        assert_eq!(token_hash(&t), token_hash(&t));
        assert_ne!(token_hash(&t), t);
        assert_eq!(token_hash(&t).len(), 64);
    }

    #[test]
    fn token_prefixes_are_distinguishable() {
        assert!(new_agent_token().starts_with("rsa_"));
        assert!(new_node_token().starts_with("rsn_"));
        assert!(new_enroll_token().starts_with("rse_"));
    }

    #[test]
    fn bearer_extraction() {
        assert_eq!(extract_bearer(Some("Bearer abc")).as_deref(), Some("abc"));
        assert_eq!(extract_bearer(Some("  Bearer  abc  ")).as_deref(), Some("abc"));
        assert_eq!(extract_bearer(Some("Basic abc")), None);
        assert_eq!(extract_bearer(None), None);
    }

    #[test]
    fn throttle_locks_after_threshold() {
        let t = LoginThrottle::new();
        t.check("k").expect("首次放行");
        t.record_failure("k", 2, 1);
        t.check("k").expect("一次失败还不锁");
        t.record_failure("k", 2, 1);
        assert!(t.check("k").is_err(), "达到阈值后必须锁定");
        t.record_success("k");
        t.check("k").expect("成功后解锁");
    }

    #[tokio::test]
    async fn session_issue_and_verify() {
        let store = Store::open_in_memory().expect("store");
        let issued = issue_session(&store, "u1", 1, Some("ut".to_string()))
            .await
            .expect("issue");
        let found = verify_session(&store, &issued.token)
            .await
            .expect("verify")
            .expect("应当有效");
        assert_eq!(found.user_id, "u1");
        assert!(verify_session(&store, "nope").await.expect("verify").is_none());
    }
}
