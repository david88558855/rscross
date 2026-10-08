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

/// 生成隧道**访问密钥**，形如 `rsv_<16hex>`（共 20 字符）。
///
/// 语义与密码相同：访问端凭它才能向节点申请一条到目标内网服务的通道，
/// 因此只用在下发与展示环节，不参与任何哈希校验。
///
/// 长度刻意比其他令牌短得多：它是要被人抄写的。与之配套的是
/// `/api/v1/access/resolve` 上的失败限流 —— 缩短密钥**必须**同时收紧
/// 猜测的代价，否则就是单向降低强度。
pub fn new_access_key() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    // 位数必须是偶数才能整字节生成；用常量断言在编译期挡住写错的可能。
    const BYTES: usize = rscross_common::ACCESS_KEY_HEX_LEN / 2;
    const _: () = assert!(
        rscross_common::ACCESS_KEY_HEX_LEN % 2 == 0,
        "ACCESS_KEY_HEX_LEN 必须是偶数"
    );
    let mut buf = [0u8; BYTES];
    rng.fill_bytes(&mut buf);
    format!("{}{}", rscross_common::ACCESS_KEY_PREFIX, hex::encode(buf))
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

/// 进程级失败限流器（按调用方给的 key 计数）。
///
/// 目前有两个使用方，共用同一套原语：
/// - 控制台登录：key = 用户名 + 来源 IP；
/// - 访问密钥校验：key = 来源 IP（密钥本体是秘密，不能进计数键 ——
///   否则限流表本身就变成了一张「被尝试过的密钥」清单）。
///
/// 仅用于抵御在线暴力破解；多副本部署时应换成 Redis 之类的共享存储
/// （见 `docs/ROADMAP.md` 阶段 2 的「后续加固」）。
#[derive(Debug, Default)]
pub struct Throttle {
    inner: Mutex<HashMap<String, Attempt>>,
}

/// 登录限流器的历史名字。
///
/// 保留别名是因为登录侧代码与测试都在用这个名字，而它现在已经是通用限流器了；
/// 改名是为了让「访问密钥校验」也能名正言顺地用它。
pub type LoginThrottle = Throttle;

#[derive(Debug, Clone, Copy, Default)]
struct Attempt {
    failures: u32,
    locked_until_unix: i64,
}

impl Throttle {
    /// 创建空的限流器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 若该 key 处于锁定中，返回**剩余秒数**；未锁定则 `None`。
    ///
    /// 只返回事实、不代拟文案，是刻意的：文案里必须带上「是哪一类被锁了」
    /// （登录 / 访问密钥校验指向完全不同的排查方向），而「鉴权错误: 」这种
    /// 类型前缀不该出现在 HTTP 429 的响应体里 —— 429 说的是「太频繁」，
    /// 不是「你没权限」。所以拼文案交给调用方。
    pub fn locked_for(&self, key: &str) -> Option<u64> {
        let now = rscross_common::time::now().timestamp();
        let guard = self.lock();
        let attempt = guard.get(key)?;
        (attempt.locked_until_unix > now).then(|| (attempt.locked_until_unix - now) as u64)
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
            // 计数键可能是 IP 而不是用户名，不该当作用户名打日志；
            // 这里只说事实：该键对应的调用方被临时锁定了。
            tracing::warn!(key, "失败次数超限，已临时锁定");
        }
    }

    /// 成功后清零。
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
    fn access_key_is_short_enough_to_transcribe_and_still_well_shaped() {
        let key = new_access_key();
        // 22 字符左右是「一眼能抄对」的上限；这里锁住 20（rsv_ + 16 位）。
        assert_eq!(
            key.len(),
            rscross_common::ACCESS_KEY_PREFIX.len() + rscross_common::ACCESS_KEY_HEX_LEN
        );
        assert!(
            rscross_common::access_key_shape_ok(&key),
            "生成的密钥必须通过形状校验"
        );

        // 它必须明显短于其它令牌 —— 那些是给机器读的，这个是给人抄的。
        assert!(key.len() < new_agent_token().len() / 3);
    }

    #[test]
    fn throttle_exposes_only_the_facts_and_keys_are_independent() {
        let t = Throttle::new();

        // 未失败过：不算锁定
        assert_eq!(t.locked_for("ip"), None);

        t.record_failure("ip", 2, 1);
        assert_eq!(t.locked_for("ip"), None, "一次失败还不锁");

        // 达到阈值 → 锁定，且能给出剩余秒数（文案由调用方拼）
        t.record_failure("ip", 2, 1);
        let remain = t.locked_for("ip").expect("达到阈值后应锁定");
        assert!(remain > 0 && remain <= 60, "剩余秒数应在 1..=60，实际 {remain}");

        // 计数键之间必须互相独立：否则一个人输错密码会锁掉同 IP 的其他人
        assert_eq!(t.locked_for("other-ip"), None);

        // 成功后立刻解锁
        t.record_success("ip");
        assert_eq!(t.locked_for("ip"), None);

        // max_attempts = 0 表示「不启用限流」
        t.record_failure("never", 0, 1);
        assert_eq!(t.locked_for("never"), None);
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
        assert_eq!(t.locked_for("k"), None, "首次放行");
        t.record_failure("k", 2, 1);
        assert_eq!(t.locked_for("k"), None, "一次失败还不锁");
        t.record_failure("k", 2, 1);
        assert!(t.locked_for("k").is_some(), "达到阈值后必须锁定");
        t.record_success("k");
        assert_eq!(t.locked_for("k"), None, "成功后解锁");
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
