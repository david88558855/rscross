//! `rscross-store`：SQLite 持久化层。
//!
//! 并发模型：`rusqlite` 是**同步阻塞** API，因此内部用一把 `std::sync::Mutex<Connection>`
//! 串行化写操作，并把每次调用放进 `tokio::task::spawn_blocking`，
//! 避免阻塞 async 工作线程。WAL 模式下读并发由 SQLite 自身保证。

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension, Row};
use rscross_common::{Error, Result};

pub mod model;

pub use model::{
    AuditEntry, ClientRecord, EnrollTokenRecord, LogEntry, OverviewStats, SessionRecord,
    TrafficPoint, TunnelRecord, UserRecord,
};

/// 数据库句柄。内部是 `Arc<Mutex<Connection>>`，克隆开销极低。
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    /// 日志是否落库（由配置决定）。
    persist_logs: bool,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("persist_logs", &self.persist_logs)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// 打开（或创建）数据库并执行迁移。
    pub fn open(path: &str, wal: bool, busy_timeout_ms: u32, persist_logs: bool) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::store(format!("创建数据目录 {} 失败: {e}", parent.display()))
                })?;
            }
        }

        let conn = Connection::open(path).map_err(Error::store)?;
        conn.busy_timeout(std::time::Duration::from_millis(u64::from(busy_timeout_ms)))
            .map_err(Error::store)?;
        if wal {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(Error::store)?;
            conn.pragma_update(None, "synchronous", "NORMAL")
                .map_err(Error::store)?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(Error::store)?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            persist_logs,
        };
        store.migrate()?;
        Ok(store)
    }

    /// 打开内存库（测试用）。
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(Error::store)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(Error::store)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            persist_logs: true,
        };
        store.migrate()?;
        Ok(store)
    }

    /// 执行 schema 迁移（幂等）。
    pub fn migrate(&self) -> Result<()> {
        let mut guard = self.lock();
        guard
            .execute_batch(SCHEMA)
            .map_err(|e| Error::store(format!("迁移失败: {e}")))?;
        let version: i64 = guard
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(Error::store)?;
        drop(guard);
        tracing::debug!(schema_version = version, "数据库迁移完成");
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // 中毒的锁不应阻止服务继续提供只读能力：取回内部值并记录。
        match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::error!("数据库锁中毒（前一次写入 panic），继续复用连接");
                poisoned.into_inner()
            }
        }
    }

    async fn blocking<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = match conn.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            f(&guard)
        })
        .await
        .map_err(|e| Error::store(format!("数据库任务 panic: {e}")))?
    }

    // ---------------------------------------------------------------- users

    /// 创建用户；用户名冲突返回错误。
    pub async fn create_user(
        &self,
        username: String,
        password_hash: String,
        role: String,
    ) -> Result<UserRecord> {
        let now = rscross_common::time::now_rfc3339();
        let id = uuid::Uuid::new_v4().to_string();
        let (id2, now2) = (id.clone(), now.clone());
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO users (id, username, password_hash, role, disabled, created_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                params![id2, username, password_hash, role, now2],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await?;
        self.find_user_by_name(&username)
            .await?
            .ok_or_else(|| Error::store("用户创建后立即查询失败"))
    }

    /// 按用户名查询用户。
    pub async fn find_user_by_name(&self, username: &str) -> Result<Option<UserRecord>> {
        let username = username.to_string();
        self.blocking(move |c| {
            c.query_row(
                "SELECT id, username, password_hash, role, disabled, created_at, last_login_at
                 FROM users WHERE username = ?1",
                params![username],
                map_user,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 按 ID 查询用户。
    pub async fn find_user_by_id(&self, id: &str) -> Result<Option<UserRecord>> {
        let id = id.to_string();
        self.blocking(move |c| {
            c.query_row(
                "SELECT id, username, password_hash, role, disabled, created_at, last_login_at
                 FROM users WHERE id = ?1",
                params![id],
                map_user,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 统计用户数量（用于判断是否需要创建初始管理员）。
    pub async fn count_users(&self) -> Result<i64> {
        self.blocking(|c| {
            c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                .map_err(Error::store)
        })
        .await
    }

    /// 记录一次成功登录。
    pub async fn touch_login(&self, user_id: &str) -> Result<()> {
        let (id, now) = (user_id.to_string(), rscross_common::time::now_rfc3339());
        self.blocking(move |c| {
            c.execute(
                "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
                params![now, id],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 修改密码。
    pub async fn set_password(&self, user_id: &str, password_hash: String) -> Result<()> {
        let id = user_id.to_string();
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                    params![password_hash, id],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("用户不存在"));
            }
            Ok(())
        })
        .await
    }

    // ------------------------------------------------------------- sessions

    /// 新建会话。
    pub async fn create_session(
        &self,
        token_hash: String,
        user_id: String,
        expires_at: String,
        user_agent: Option<String>,
    ) -> Result<()> {
        let now = rscross_common::time::now_rfc3339();
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, user_agent)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![token_hash, user_id, now, expires_at, user_agent],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 按 token 哈希查询有效会话。
    pub async fn find_session(&self, token_hash: &str) -> Result<Option<SessionRecord>> {
        let token_hash = token_hash.to_string();
        self.blocking(move |c| {
            c.query_row(
                "SELECT token_hash, user_id, created_at, expires_at, user_agent
                 FROM sessions WHERE token_hash = ?1",
                params![token_hash],
                |row| {
                    Ok(SessionRecord {
                        token_hash: row.get(0)?,
                        user_id: row.get(1)?,
                        created_at: row.get(2)?,
                        expires_at: row.get(3)?,
                        user_agent: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 删除会话（登出）。
    pub async fn delete_session(&self, token_hash: &str) -> Result<()> {
        let token_hash = token_hash.to_string();
        self.blocking(move |c| {
            c.execute("DELETE FROM sessions WHERE token_hash = ?1", params![token_hash])
                .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 清理过期会话。
    pub async fn purge_expired_sessions(&self) -> Result<usize> {
        let now = rscross_common::time::now_rfc3339();
        self.blocking(move |c| {
            c.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now])
                .map_err(Error::store)
        })
        .await
    }

    // -------------------------------------------------------------- clients

    /// 插入客户端。
    pub async fn insert_client(&self, rec: ClientRecord) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO clients
                 (id, name, status, agent_token_hash, version, os, arch, endpoint_id,
                  endpoint_addr, public_ip, last_seen_at, last_error, created_at, updated_at, disabled)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    rec.id,
                    rec.name,
                    rec.status,
                    rec.agent_token_hash,
                    rec.version,
                    rec.os,
                    rec.arch,
                    rec.endpoint_id,
                    rec.endpoint_addr,
                    rec.public_ip,
                    rec.last_seen_at,
                    rec.last_error,
                    rec.created_at,
                    rec.updated_at,
                    rec.disabled as i64,
                ],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 按 ID 查询客户端。
    pub async fn find_client(&self, id: &str) -> Result<Option<ClientRecord>> {
        let id = id.to_string();
        self.blocking(move |c| {
            c.query_row(
                &format!("{CLIENT_SELECT} WHERE id = ?1"),
                params![id],
                map_client,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 按 agent token 哈希查询客户端（心跳鉴权用）。
    pub async fn find_client_by_token_hash(&self, hash: &str) -> Result<Option<ClientRecord>> {
        let hash = hash.to_string();
        self.blocking(move |c| {
            c.query_row(
                &format!("{CLIENT_SELECT} WHERE agent_token_hash = ?1"),
                params![hash],
                map_client,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 列出全部客户端。
    pub async fn list_clients(&self) -> Result<Vec<ClientRecord>> {
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!("{CLIENT_SELECT} ORDER BY created_at DESC"))
                .map_err(Error::store)?;
            let rows = stmt.query_map([], map_client).map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)
        })
        .await
    }

    /// 客户端数量。
    pub async fn count_clients(&self) -> Result<i64> {
        self.blocking(|c| {
            c.query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))
                .map_err(Error::store)
        })
        .await
    }

    /// 更新心跳与运行时信息。
    pub async fn touch_client(
        &self,
        id: String,
        runtime: ClientRuntimePatch,
    ) -> Result<()> {
        let now = rscross_common::time::now_rfc3339();
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE clients SET status = 'online', last_seen_at = ?2, updated_at = ?2,
                        version = COALESCE(?3, version), os = COALESCE(?4, os),
                        arch = COALESCE(?5, arch), endpoint_id = COALESCE(?6, endpoint_id),
                        endpoint_addr = COALESCE(?7, endpoint_addr),
                        public_ip = COALESCE(?8, public_ip), last_error = NULL
                     WHERE id = ?1",
                    params![
                        id,
                        now,
                        runtime.version,
                        runtime.os,
                        runtime.arch,
                        runtime.endpoint_id,
                        runtime.endpoint_addr,
                        runtime.public_ip,
                    ],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("客户端不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 把「超过阈值未心跳」的客户端标记为离线。
    pub async fn mark_stale_clients_offline(&self, cutoff_rfc3339: String) -> Result<usize> {
        self.blocking(move |c| {
            c.execute(
                "UPDATE clients SET status = 'offline', updated_at = ?1
                 WHERE status = 'online' AND (last_seen_at IS NULL OR last_seen_at < ?2)",
                params![rscross_common::time::now_rfc3339(), cutoff_rfc3339],
            )
            .map_err(Error::store)
        })
        .await
    }

    /// 设置客户端启用/禁用。
    pub async fn set_client_disabled(&self, id: &str, disabled: bool) -> Result<()> {
        let (id, now) = (id.to_string(), rscross_common::time::now_rfc3339());
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE clients SET disabled = ?2, status = CASE WHEN ?2 = 1 THEN 'disabled'
                        ELSE 'pending' END, updated_at = ?3 WHERE id = ?1",
                    params![id, disabled as i64, now],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("客户端不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 重命名客户端。
    pub async fn rename_client(&self, id: &str, name: &str) -> Result<()> {
        let (id, name, now) = (
            id.to_string(),
            name.to_string(),
            rscross_common::time::now_rfc3339(),
        );
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE clients SET name = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id, name, now],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("客户端不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 删除客户端（级联删除隧道与流量采样）。
    pub async fn delete_client(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.blocking(move |c| {
            let tx = c.unchecked_transaction().map_err(Error::store)?;
            tx.execute("DELETE FROM tunnels WHERE client_id = ?1", params![id])
                .map_err(Error::store)?;
            tx.execute("DELETE FROM traffic_samples WHERE client_id = ?1", params![id])
                .map_err(Error::store)?;
            tx.execute("DELETE FROM clients WHERE id = ?1", params![id])
                .map_err(Error::store)?;
            tx.commit().map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    // -------------------------------------------------------- enroll tokens

    /// 写入接入令牌。
    pub async fn insert_enroll_token(&self, rec: EnrollTokenRecord) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO enroll_tokens
                 (token_hash, client_name, created_by, created_at, expires_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    rec.token_hash,
                    rec.client_name,
                    rec.created_by,
                    rec.created_at,
                    rec.expires_at
                ],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 查询接入令牌。
    pub async fn find_enroll_token(&self, hash: &str) -> Result<Option<EnrollTokenRecord>> {
        let hash = hash.to_string();
        self.blocking(move |c| {
            c.query_row(
                "SELECT token_hash, client_name, created_by, created_at, expires_at, used_at, used_client_id
                 FROM enroll_tokens WHERE token_hash = ?1",
                params![hash],
                |row| {
                    Ok(EnrollTokenRecord {
                        token_hash: row.get(0)?,
                        client_name: row.get(1)?,
                        created_by: row.get(2)?,
                        created_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        used_at: row.get(5)?,
                        used_client_id: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 标记接入令牌已使用。
    pub async fn consume_enroll_token(&self, hash: &str, client_id: &str) -> Result<()> {
        let (hash, client_id, now) = (
            hash.to_string(),
            client_id.to_string(),
            rscross_common::time::now_rfc3339(),
        );
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE enroll_tokens SET used_at = ?2, used_client_id = ?3
                     WHERE token_hash = ?1 AND used_at IS NULL",
                    params![hash, now, client_id],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::auth("接入令牌已被使用"));
            }
            Ok(())
        })
        .await
    }

    // -------------------------------------------------------------- tunnels

    /// 新增隧道。
    pub async fn insert_tunnel(&self, rec: TunnelRecord) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO tunnels
                 (id, client_id, name, proto, local_addr, remote_port, host, path_prefix,
                  enabled, rate_limit_kbps, conn_limit, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    rec.id,
                    rec.client_id,
                    rec.name,
                    rec.proto,
                    rec.local_addr,
                    rec.remote_port,
                    rec.host,
                    rec.path_prefix,
                    rec.enabled as i64,
                    rec.rate_limit_kbps,
                    rec.conn_limit,
                    rec.created_at,
                    rec.updated_at
                ],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 按 ID 查询隧道。
    pub async fn find_tunnel(&self, id: &str) -> Result<Option<TunnelRecord>> {
        let id = id.to_string();
        self.blocking(move |c| {
            c.query_row(
                &format!("{TUNNEL_SELECT} WHERE id = ?1"),
                params![id],
                map_tunnel,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 列出全部隧道。
    pub async fn list_tunnels(&self) -> Result<Vec<TunnelRecord>> {
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!("{TUNNEL_SELECT} ORDER BY created_at DESC"))
                .map_err(Error::store)?;
            let rows = stmt.query_map([], map_tunnel).map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)
        })
        .await
    }

    /// 列出某客户端的隧道（配置下发用）。
    pub async fn list_tunnels_of_client(&self, client_id: &str) -> Result<Vec<TunnelRecord>> {
        let client_id = client_id.to_string();
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!(
                    "{TUNNEL_SELECT} WHERE client_id = ?1 ORDER BY name ASC"
                ))
                .map_err(Error::store)?;
            let rows = stmt
                .query_map(params![client_id], map_tunnel)
                .map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)
        })
        .await
    }

    /// 更新一条隧道的可变字段。
    pub async fn update_tunnel(&self, patch: TunnelPatch) -> Result<()> {
        let now = rscross_common::time::now_rfc3339();
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE tunnels SET name = COALESCE(?2, name), proto = COALESCE(?3, proto),
                        local_addr = COALESCE(?4, local_addr), remote_port = ?5,
                        host = ?6, path_prefix = ?7,
                        enabled = COALESCE(?8, enabled),
                        rate_limit_kbps = COALESCE(?9, rate_limit_kbps),
                        conn_limit = COALESCE(?10, conn_limit), updated_at = ?11
                     WHERE id = ?1",
                    params![
                        patch.id,
                        patch.name,
                        patch.proto,
                        patch.local_addr,
                        patch.remote_port,
                        patch.host,
                        patch.path_prefix,
                        patch.enabled.map(|b| b as i64),
                        patch.rate_limit_kbps,
                        patch.conn_limit,
                        now
                    ],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("隧道不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 删除隧道。
    pub async fn delete_tunnel(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.blocking(move |c| {
            c.execute("DELETE FROM tunnels WHERE id = ?1", params![id])
                .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 隧道总数。
    pub async fn count_tunnels(&self) -> Result<i64> {
        self.blocking(|c| {
            c.query_row("SELECT COUNT(*) FROM tunnels", [], |r| r.get(0))
                .map_err(Error::store)
        })
        .await
    }

    // --------------------------------------------------------------- 流量/日志

    /// 写入一条流量采样。
    pub async fn insert_traffic(&self, p: TrafficPoint) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO traffic_samples (ts, tunnel_id, client_id, path, bytes_in, bytes_out, conns)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![p.ts, p.tunnel_id, p.client_id, p.path, p.bytes_in, p.bytes_out, p.conns],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 概览统计。
    pub async fn overview(&self) -> Result<OverviewStats> {
        self.blocking(|c| {
            let clients_total: i64 = c
                .query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))
                .map_err(Error::store)?;
            let clients_online: i64 = c
                .query_row(
                    "SELECT COUNT(*) FROM clients WHERE status = 'online'",
                    [],
                    |r| r.get(0),
                )
                .map_err(Error::store)?;
            let tunnels_total: i64 = c
                .query_row("SELECT COUNT(*) FROM tunnels", [], |r| r.get(0))
                .map_err(Error::store)?;
            let tunnels_enabled: i64 = c
                .query_row("SELECT COUNT(*) FROM tunnels WHERE enabled = 1", [], |r| {
                    r.get(0)
                })
                .map_err(Error::store)?;
            let (bytes_in, bytes_out, conns): (i64, i64, i64) = c
                .query_row(
                    "SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
                            COALESCE(SUM(conns),0)
                     FROM traffic_samples WHERE ts >= ?1",
                    params![rscross_common::time::to_rfc3339(
                        rscross_common::time::now() - chrono::Duration::hours(24)
                    )],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(Error::store)?;
            let path_split: (i64, i64) = c
                .query_row(
                    "SELECT
                        COALESCE(SUM(CASE WHEN path = 'p2p' THEN bytes_in + bytes_out ELSE 0 END),0),
                        COALESCE(SUM(CASE WHEN path <> 'p2p' THEN bytes_in + bytes_out ELSE 0 END),0)
                     FROM traffic_samples WHERE ts >= ?1",
                    params![rscross_common::time::to_rfc3339(
                        rscross_common::time::now() - chrono::Duration::hours(24)
                    )],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(Error::store)?;
            Ok(OverviewStats {
                clients_total,
                clients_online,
                tunnels_total,
                tunnels_enabled,
                bytes_in_24h: bytes_in,
                bytes_out_24h: bytes_out,
                conns_24h: conns,
                bytes_direct_24h: path_split.0,
                bytes_relayed_24h: path_split.1,
            })
        })
        .await
    }

    /// 按小时聚合的流量趋势（最近 `hours` 小时）。
    pub async fn traffic_series(&self, hours: i64) -> Result<Vec<TrafficBucket>> {
        self.blocking(move |c| {
            let since = rscross_common::time::to_rfc3339(
                rscross_common::time::now() - chrono::Duration::hours(hours.max(1)),
            );
            let mut stmt = c
                .prepare(
                    "SELECT substr(ts, 1, 13) AS bucket,
                            COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
                            COALESCE(SUM(conns),0)
                     FROM traffic_samples WHERE ts >= ?1
                     GROUP BY bucket ORDER BY bucket ASC",
                )
                .map_err(Error::store)?;
            let rows = stmt
                .query_map(params![since], |row| {
                    Ok(TrafficBucket {
                        bucket: row.get(0)?,
                        bytes_in: row.get(1)?,
                        bytes_out: row.get(2)?,
                        conns: row.get(3)?,
                    })
                })
                .map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)
        })
        .await
    }

    /// 写入日志（配置里 `log.persist = true` 时启用）。
    pub async fn insert_log(&self, e: LogEntry) -> Result<()> {
        if !self.persist_logs {
            return Ok(());
        }
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO logs (ts, level, target, message, client_id, tunnel_id)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![e.ts, e.level, e.target, e.message, e.client_id, e.tunnel_id],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 查询历史日志。
    pub async fn query_logs(
        &self,
        level: Option<String>,
        keyword: Option<String>,
        limit: i64,
    ) -> Result<Vec<LogEntry>> {
        self.blocking(move |c| {
            let mut sql = String::from(
                "SELECT id, ts, level, target, message, client_id, tunnel_id FROM logs WHERE 1=1",
            );
            let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            if let Some(lv) = level.clone() {
                sql.push_str(" AND level = ?");
                args.push(Box::new(lv));
            }
            if let Some(kw) = keyword.clone() {
                sql.push_str(" AND message LIKE ?");
                args.push(Box::new(format!("%{kw}%")));
            }
            sql.push_str(" ORDER BY id DESC LIMIT ?");
            args.push(Box::new(limit.clamp(1, 2000)));

            let mut stmt = c.prepare(&sql).map_err(Error::store)?;
            let params_ref: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
            let rows = stmt
                .query_map(params_ref.as_slice(), |row| {
                    Ok(LogEntry {
                        id: row.get(0)?,
                        ts: row.get(1)?,
                        level: row.get(2)?,
                        target: row.get(3)?,
                        message: row.get(4)?,
                        client_id: row.get(5)?,
                        tunnel_id: row.get(6)?,
                    })
                })
                .map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)
        })
        .await
    }

    /// 写入审计记录。
    pub async fn insert_audit(&self, a: AuditEntry) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO audit (ts, user_id, action, target, detail, ip)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![a.ts, a.user_id, a.action, a.target, a.detail, a.ip],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 查询审计记录。
    pub async fn list_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, ts, user_id, action, target, detail, ip FROM audit
                     ORDER BY id DESC LIMIT ?1",
                )
                .map_err(Error::store)?;
            let rows = stmt
                .query_map(params![limit.clamp(1, 1000)], |row| {
                    Ok(AuditEntry {
                        id: row.get(0)?,
                        ts: row.get(1)?,
                        user_id: row.get(2)?,
                        action: row.get(3)?,
                        target: row.get(4)?,
                        detail: row.get(5)?,
                        ip: row.get(6)?,
                    })
                })
                .map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)
        })
        .await
    }

    /// 清理保留期之外的数据。
    pub async fn purge_old_data(&self, traffic_days: u32, log_days: u32) -> Result<()> {
        self.blocking(move |c| {
            let traffic_cutoff = rscross_common::time::to_rfc3339(
                rscross_common::time::now()
                    - chrono::Duration::days(i64::from(traffic_days.max(1))),
            );
            let log_cutoff = rscross_common::time::to_rfc3339(
                rscross_common::time::now() - chrono::Duration::days(i64::from(log_days.max(1))),
            );
            c.execute(
                "DELETE FROM traffic_samples WHERE ts < ?1",
                params![traffic_cutoff],
            )
            .map_err(Error::store)?;
            c.execute("DELETE FROM logs WHERE ts < ?1", params![log_cutoff])
                .map_err(Error::store)?;
            Ok(())
        })
        .await
    }
}

/// 心跳时更新的运行时字段（None 表示不覆盖）。
#[derive(Debug, Clone, Default)]
pub struct ClientRuntimePatch {
    /// 客户端版本。
    pub version: Option<String>,
    /// 操作系统。
    pub os: Option<String>,
    /// CPU 架构。
    pub arch: Option<String>,
    /// Iroh EndpointId。
    pub endpoint_id: Option<String>,
    /// Iroh EndpointAddr（JSON）。
    pub endpoint_addr: Option<String>,
    /// 出口公网 IP。
    pub public_ip: Option<String>,
}

/// 隧道可变字段补丁（None 表示不修改）。
#[derive(Debug, Clone, Default)]
pub struct TunnelPatch {
    /// 隧道 ID。
    pub id: String,
    /// 名称。
    pub name: Option<String>,
    /// 协议。
    pub proto: Option<String>,
    /// 本地地址。
    pub local_addr: Option<String>,
    /// 公网端口（显式设置，None 表示清空）。
    pub remote_port: Option<Option<i64>>,
    /// Host。
    pub host: Option<Option<String>>,
    /// 路径前缀。
    pub path_prefix: Option<Option<String>>,
    /// 启用状态。
    pub enabled: Option<bool>,
    /// 限速。
    pub rate_limit_kbps: Option<i64>,
    /// 连接数上限。
    pub conn_limit: Option<i64>,
}

/// 小时聚合桶。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficBucket {
    /// `YYYY-MM-DDTHH` 前缀。
    pub bucket: String,
    /// 入向字节。
    pub bytes_in: i64,
    /// 出向字节。
    pub bytes_out: i64,
    /// 连接数。
    pub conns: i64,
}

const CLIENT_SELECT: &str = "SELECT id, name, status, agent_token_hash, version, os, arch,
    endpoint_id, endpoint_addr, public_ip, last_seen_at, last_error, created_at, updated_at, disabled
    FROM clients";

const TUNNEL_SELECT: &str = "SELECT id, client_id, name, proto, local_addr, remote_port, host,
    path_prefix, enabled, rate_limit_kbps, conn_limit, created_at, updated_at FROM tunnels";

// 结果收集统一走 `rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::store)`，
// 避免在 `MappedRows<'stmt, F>` 上书写高阶生命周期约束。

fn map_user(row: &Row<'_>) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: row.get(3)?,
        disabled: row.get::<_, i64>(4)? != 0,
        created_at: row.get(5)?,
        last_login_at: row.get(6)?,
    })
}

fn map_client(row: &Row<'_>) -> rusqlite::Result<ClientRecord> {
    Ok(ClientRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        status: row.get(2)?,
        agent_token_hash: row.get(3)?,
        version: row.get(4)?,
        os: row.get(5)?,
        arch: row.get(6)?,
        endpoint_id: row.get(7)?,
        endpoint_addr: row.get(8)?,
        public_ip: row.get(9)?,
        last_seen_at: row.get(10)?,
        last_error: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        disabled: row.get::<_, i64>(14)? != 0,
    })
}

fn map_tunnel(row: &Row<'_>) -> rusqlite::Result<TunnelRecord> {
    Ok(TunnelRecord {
        id: row.get(0)?,
        client_id: row.get(1)?,
        name: row.get(2)?,
        proto: row.get(3)?,
        local_addr: row.get(4)?,
        remote_port: row.get(5)?,
        host: row.get(6)?,
        path_prefix: row.get(7)?,
        enabled: row.get::<_, i64>(8)? != 0,
        rate_limit_kbps: row.get(9)?,
        conn_limit: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

const SCHEMA: &str = r#"
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'admin',
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS clients (
  id               TEXT PRIMARY KEY,
  name             TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending',
  agent_token_hash TEXT NOT NULL,
  version          TEXT,
  os               TEXT,
  arch             TEXT,
  endpoint_id      TEXT,
  endpoint_addr    TEXT,
  public_ip        TEXT,
  last_seen_at     TEXT,
  last_error       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  disabled         INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_name ON clients(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_token ON clients(agent_token_hash);

CREATE TABLE IF NOT EXISTS enroll_tokens (
  token_hash     TEXT PRIMARY KEY,
  client_name    TEXT,
  created_by     TEXT,
  created_at     TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  used_at        TEXT,
  used_client_id TEXT
);

CREATE TABLE IF NOT EXISTS tunnels (
  id              TEXT PRIMARY KEY,
  client_id       TEXT NOT NULL,
  name            TEXT NOT NULL,
  proto           TEXT NOT NULL,
  local_addr      TEXT NOT NULL,
  remote_port     INTEGER,
  host            TEXT,
  path_prefix     TEXT,
  enabled         INTEGER NOT NULL DEFAULT 1,
  rate_limit_kbps INTEGER NOT NULL DEFAULT 0,
  conn_limit      INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  UNIQUE(client_id, name)
);
CREATE INDEX IF NOT EXISTS idx_tunnels_client ON tunnels(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_port ON tunnels(remote_port) WHERE remote_port IS NOT NULL;

CREATE TABLE IF NOT EXISTS traffic_samples (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  tunnel_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  path      TEXT NOT NULL DEFAULT 'p2p',
  bytes_in  INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  conns     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_samples(ts);

CREATE TABLE IF NOT EXISTS logs (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  level     TEXT NOT NULL,
  target    TEXT,
  message   TEXT NOT NULL,
  client_id TEXT,
  tunnel_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);

CREATE TABLE IF NOT EXISTS audit (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,
  user_id TEXT,
  action  TEXT NOT NULL,
  target  TEXT,
  detail  TEXT,
  ip      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn client_rec(name: &str) -> ClientRecord {
        let now = rscross_common::time::now_rfc3339();
        ClientRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            status: "pending".to_string(),
            agent_token_hash: format!("hash-{name}"),
            version: Some("0.1.0".to_string()),
            os: Some("linux".to_string()),
            arch: Some("x86_64".to_string()),
            endpoint_id: None,
            endpoint_addr: None,
            public_ip: None,
            last_seen_at: None,
            last_error: None,
            created_at: now.clone(),
            updated_at: now,
            disabled: false,
        }
    }

    #[tokio::test]
    async fn client_crud_roundtrip() {
        let store = Store::open_in_memory().expect("open");
        let rec = client_rec("node-a");
        let id = rec.id.clone();
        store.insert_client(rec).await.expect("insert");

        let found = store.find_client(&id).await.expect("find").expect("some");
        assert_eq!(found.name, "node-a");
        assert_eq!(found.status, "pending");

        store
            .touch_client(
                id.clone(),
                ClientRuntimePatch {
                    version: Some("0.2.0".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("touch");
        let found = store.find_client(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "online");
        assert_eq!(found.version.as_deref(), Some("0.2.0"));

        store.set_client_disabled(&id, true).await.expect("disable");
        let found = store.find_client(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "disabled");

        store.delete_client(&id).await.expect("delete");
        assert!(store.find_client(&id).await.expect("find").is_none());
    }

    #[tokio::test]
    async fn tunnels_are_cascaded_on_client_delete() {
        let store = Store::open_in_memory().expect("open");
        let rec = client_rec("node-b");
        let cid = rec.id.clone();
        store.insert_client(rec).await.expect("insert");

        let now = rscross_common::time::now_rfc3339();
        store
            .insert_tunnel(TunnelRecord {
                id: uuid::Uuid::new_v4().to_string(),
                client_id: cid.clone(),
                name: "web".to_string(),
                proto: "http".to_string(),
                local_addr: "127.0.0.1:8080".to_string(),
                remote_port: None,
                host: Some("a.example.com".to_string()),
                path_prefix: None,
                enabled: true,
                rate_limit_kbps: 0,
                conn_limit: 0,
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .expect("insert tunnel");

        assert_eq!(store.count_tunnels().await.expect("count"), 1);
        store.delete_client(&cid).await.expect("delete client");
        assert_eq!(store.count_tunnels().await.expect("count"), 0);
    }

    #[tokio::test]
    async fn overview_reflects_inserted_traffic() {
        let store = Store::open_in_memory().expect("open");
        store
            .insert_traffic(TrafficPoint {
                ts: rscross_common::time::now_rfc3339(),
                tunnel_id: "t1".to_string(),
                client_id: "c1".to_string(),
                path: "p2p".to_string(),
                bytes_in: 100,
                bytes_out: 200,
                conns: 3,
            })
            .await
            .expect("traffic");
        let o = store.overview().await.expect("overview");
        assert_eq!(o.bytes_in_24h, 100);
        assert_eq!(o.bytes_out_24h, 200);
        assert_eq!(o.bytes_direct_24h, 300);
        assert_eq!(o.bytes_relayed_24h, 0);
    }

    #[tokio::test]
    async fn stale_clients_are_marked_offline() {
        let store = Store::open_in_memory().expect("open");
        let rec = client_rec("node-c");
        let id = rec.id.clone();
        store.insert_client(rec).await.expect("insert");
        store
            .touch_client(id.clone(), ClientRuntimePatch::default())
            .await
            .expect("touch");

        // 未来时间作为 cutoff，必然命中「已过期」分支
        let cutoff =
            rscross_common::time::to_rfc3339(rscross_common::time::now() + chrono::Duration::hours(1));
        let affected = store
            .mark_stale_clients_offline(cutoff)
            .await
            .expect("mark");
        assert_eq!(affected, 1);
        let found = store.find_client(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "offline");
    }

    #[tokio::test]
    async fn enroll_token_can_only_be_used_once() {
        let store = Store::open_in_memory().expect("open");
        let now = rscross_common::time::now();
        store
            .insert_enroll_token(EnrollTokenRecord {
                token_hash: "h1".to_string(),
                client_name: Some("n".to_string()),
                created_by: None,
                created_at: rscross_common::time::to_rfc3339(now),
                expires_at: rscross_common::time::to_rfc3339(now + chrono::Duration::minutes(30)),
                used_at: None,
                used_client_id: None,
            })
            .await
            .expect("insert");
        store
            .consume_enroll_token("h1", "c1")
            .await
            .expect("first use ok");
        assert!(store.consume_enroll_token("h1", "c2").await.is_err());
    }

    #[tokio::test]
    async fn logs_are_filtered_by_level_and_keyword() {
        let store = Store::open_in_memory().expect("open");
        for (level, msg) in [("info", "隧道已建立"), ("error", "连接被拒绝"), ("info", "心跳正常")] {
            store
                .insert_log(LogEntry {
                    id: 0,
                    ts: rscross_common::time::now_rfc3339(),
                    level: level.to_string(),
                    target: Some("test".to_string()),
                    message: msg.to_string(),
                    client_id: None,
                    tunnel_id: None,
                })
                .await
                .expect("log");
        }
        let all = store.query_logs(None, None, 100).await.expect("all");
        assert_eq!(all.len(), 3);
        let errs = store
            .query_logs(Some("error".to_string()), None, 100)
            .await
            .expect("errors");
        assert_eq!(errs.len(), 1);
        let hits = store
            .query_logs(None, Some("心跳".to_string()), 100)
            .await
            .expect("kw");
        assert_eq!(hits.len(), 1);
    }
}
