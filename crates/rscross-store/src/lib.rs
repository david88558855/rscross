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
    AuditEntry, ClientRecord, EnrollTokenRecord, LogEntry, NodeRecord, OverviewStats, SessionRecord,
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
        let guard = self.lock();
        guard
            .execute_batch(SCHEMA)
            .map_err(|e| Error::store(format!("迁移失败: {e}")))?;
        // 老库是用 CREATE TABLE IF NOT EXISTS 建的，新增列不会被自动补上，
        // 必须显式 ALTER —— 否则老用户升级后一读隧道就报 no such column。
        add_missing_columns(&guard)?;
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
        // 闭包会拿走 username，查询用的副本先留好。
        let lookup = username.clone();
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
        self.find_user_by_name(&lookup)
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

    /// 按 token 哈希查询会话。
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
            c.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                params![token_hash],
            )
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

    // ---------------------------------------------------------------- nodes

    /// 插入节点。
    pub async fn insert_node(&self, rec: NodeRecord) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO nodes
                 (id, name, status, node_token_hash, tunnel_token, public_host, tunnel_port,
                  ingress_port, version, os, arch, endpoint_id, endpoint_addr, public_ip,
                  last_seen_at, last_error, created_at, updated_at, disabled)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![
                    rec.id,
                    rec.name,
                    rec.status,
                    rec.node_token_hash,
                    rec.tunnel_token,
                    rec.public_host,
                    rec.tunnel_port,
                    rec.ingress_port,
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

    /// 按 ID 查询节点。
    pub async fn find_node(&self, id: &str) -> Result<Option<NodeRecord>> {
        let id = id.to_string();
        self.blocking(move |c| {
            c.query_row(&format!("{NODE_SELECT} WHERE id = ?1"), params![id], map_node)
                .optional()
                .map_err(Error::store)
        })
        .await
    }

    /// 按名称查询节点。
    pub async fn find_node_by_name(&self, name: &str) -> Result<Option<NodeRecord>> {
        let name = name.to_string();
        self.blocking(move |c| {
            c.query_row(
                &format!("{NODE_SELECT} WHERE name = ?1"),
                params![name],
                map_node,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 按 node token 哈希查询（节点心跳鉴权用）。
    pub async fn find_node_by_token_hash(&self, hash: &str) -> Result<Option<NodeRecord>> {
        let hash = hash.to_string();
        self.blocking(move |c| {
            c.query_row(
                &format!("{NODE_SELECT} WHERE node_token_hash = ?1"),
                params![hash],
                map_node,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 列出全部节点。
    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>> {
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!("{NODE_SELECT} ORDER BY created_at ASC"))
                .map_err(Error::store)?;
            let rows = stmt.query_map([], map_node).map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
        })
        .await
    }

    /// 节点数量。
    pub async fn count_nodes(&self) -> Result<i64> {
        self.blocking(|c| {
            c.query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
                .map_err(Error::store)
        })
        .await
    }

    /// 更新节点心跳与运行时信息。
    pub async fn touch_node(&self, id: String, patch: NodeRuntimePatch) -> Result<()> {
        let now = rscross_common::time::now_rfc3339();
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE nodes SET status = 'online', last_seen_at = ?2, updated_at = ?2,
                        version = COALESCE(?3, version), os = COALESCE(?4, os),
                        arch = COALESCE(?5, arch), endpoint_id = COALESCE(?6, endpoint_id),
                        endpoint_addr = COALESCE(?7, endpoint_addr),
                        public_ip = COALESCE(?8, public_ip),
                        tunnel_port = COALESCE(?9, tunnel_port),
                        ingress_port = COALESCE(?10, ingress_port),
                        last_error = NULL
                     WHERE id = ?1",
                    params![
                        id,
                        now,
                        patch.version,
                        patch.os,
                        patch.arch,
                        patch.endpoint_id,
                        patch.endpoint_addr,
                        patch.public_ip,
                        patch.tunnel_port,
                        patch.ingress_port,
                    ],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("节点不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 把「超过阈值未心跳」的节点标记为离线。
    pub async fn mark_stale_nodes_offline(&self, cutoff_rfc3339: String) -> Result<usize> {
        self.blocking(move |c| {
            c.execute(
                "UPDATE nodes SET status = 'offline', updated_at = ?1
                 WHERE status = 'online' AND (last_seen_at IS NULL OR last_seen_at < ?2)",
                params![rscross_common::time::now_rfc3339(), cutoff_rfc3339],
            )
            .map_err(Error::store)
        })
        .await
    }

    /// 设置节点启用/禁用。
    pub async fn set_node_disabled(&self, id: &str, disabled: bool) -> Result<()> {
        let (id, now) = (id.to_string(), rscross_common::time::now_rfc3339());
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE nodes SET disabled = ?2, status = CASE WHEN ?2 = 1 THEN 'disabled'
                        ELSE 'pending' END, updated_at = ?3 WHERE id = ?1",
                    params![id, disabled as i64, now],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("节点不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 更新节点可变字段（名称、对外主机名）。
    pub async fn update_node(&self, patch: NodePatch) -> Result<()> {
        let now = rscross_common::time::now_rfc3339();
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE nodes SET name = COALESCE(?2, name),
                        public_host = ?3, updated_at = ?4
                     WHERE id = ?1",
                    params![patch.id, patch.name, patch.public_host, now],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("节点不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 替换节点的 token 摘要（轮换凭证用）。
    pub async fn set_node_token_hash(&self, id: &str, token_hash: &str) -> Result<()> {
        let (id, token_hash, now) = (
            id.to_string(),
            token_hash.to_string(),
            rscross_common::time::now_rfc3339(),
        );
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE nodes SET node_token_hash = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id, token_hash, now],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("节点不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 删除节点（其下客户端会置空归属而不是级联删除，避免误删内网记录）。
    pub async fn delete_node(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.blocking(move |c| {
            let tx = c.unchecked_transaction().map_err(Error::store)?;
            tx.execute(
                "UPDATE clients SET node_id = NULL WHERE node_id = ?1",
                params![id],
            )
            .map_err(Error::store)?;
            tx.execute("DELETE FROM nodes WHERE id = ?1", params![id])
                .map_err(Error::store)?;
            tx.commit().map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    // -------------------------------------------------------------- clients

    /// 插入客户端。
    pub async fn insert_client(&self, rec: ClientRecord) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO clients
                 (id, node_id, name, status, agent_token_hash, version, os, arch, endpoint_id,
                  endpoint_addr, public_ip, last_seen_at, last_error, created_at, updated_at, disabled)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    rec.id,
                    rec.node_id,
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
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
        })
        .await
    }

    /// 列出某节点下的客户端。
    pub async fn list_clients_of_node(&self, node_id: &str) -> Result<Vec<ClientRecord>> {
        let node_id = node_id.to_string();
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!(
                    "{CLIENT_SELECT} WHERE node_id = ?1 ORDER BY created_at DESC"
                ))
                .map_err(Error::store)?;
            let rows = stmt
                .query_map(params![node_id], map_client)
                .map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
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
    pub async fn touch_client(&self, id: String, runtime: ClientRuntimePatch) -> Result<()> {
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

    /// 改派客户端归属节点。
    pub async fn reassign_client(&self, id: &str, node_id: Option<&str>) -> Result<()> {
        let (id, node_id, now) = (
            id.to_string(),
            node_id.map(str::to_string),
            rscross_common::time::now_rfc3339(),
        );
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE clients SET node_id = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id, node_id, now],
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
            tx.execute(
                "DELETE FROM traffic_samples WHERE client_id = ?1",
                params![id],
            )
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
                 (token_hash, node_id, client_name, created_by, created_at, expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    rec.token_hash,
                    rec.node_id,
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
                "SELECT token_hash, node_id, client_name, created_by, created_at, expires_at,
                        used_at, used_client_id
                 FROM enroll_tokens WHERE token_hash = ?1",
                params![hash],
                |row| {
                    Ok(EnrollTokenRecord {
                        token_hash: row.get(0)?,
                        node_id: row.get(1)?,
                        client_name: row.get(2)?,
                        created_by: row.get(3)?,
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        used_at: row.get(6)?,
                        used_client_id: row.get(7)?,
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
                 (id, client_id, name, kind, proto, local_addr, remote_port, host, path_prefix,
                  access_key, allow_relay, enabled, rate_limit_kbps, conn_limit,
                  created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    rec.id,
                    rec.client_id,
                    rec.name,
                    rec.kind,
                    rec.proto,
                    rec.local_addr,
                    rec.remote_port,
                    rec.host,
                    rec.path_prefix,
                    rec.access_key,
                    rec.allow_relay as i64,
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

    /// 按访问密钥查隧道（私有 / P2P 的访问端握手用）。
    ///
    /// 密钥本身就是凭证，所以这里不做任何「是否存在」的额外校验 ——
    /// 查不到就是无效密钥，由调用方统一按 401 处理，避免出现
    /// 「密钥对但隧道停用」这类可探测的差异。
    pub async fn find_tunnel_by_access_key(&self, key: &str) -> Result<Option<TunnelRecord>> {
        let key = key.to_string();
        self.blocking(move |c| {
            c.query_row(
                &format!("{TUNNEL_SELECT} WHERE access_key = ?1"),
                params![key],
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
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
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
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
        })
        .await
    }

    /// 列出某节点下所有客户端的隧道（节点侧统计用）。
    pub async fn list_tunnels_of_node(&self, node_id: &str) -> Result<Vec<TunnelRecord>> {
        let node_id = node_id.to_string();
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!(
                    "{TUNNEL_SELECT} WHERE client_id IN
                       (SELECT id FROM clients WHERE node_id = ?1)
                     ORDER BY created_at DESC"
                ))
                .map_err(Error::store)?;
            let rows = stmt
                .query_map(params![node_id], map_tunnel)
                .map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
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
                        host = ?6, path_prefix = ?7, access_key = ?8,
                        allow_relay = COALESCE(?9, allow_relay),
                        enabled = COALESCE(?10, enabled),
                        rate_limit_kbps = COALESCE(?11, rate_limit_kbps),
                        conn_limit = COALESCE(?12, conn_limit), updated_at = ?13
                     WHERE id = ?1",
                    params![
                        patch.id,
                        patch.name,
                        patch.proto,
                        patch.local_addr,
                        patch.remote_port,
                        patch.host,
                        patch.path_prefix,
                        patch.access_key,
                        patch.allow_relay.map(|b| b as i64),
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

    // -------------------------------------------------------- 流量 / 日志

    /// 写入一条流量采样。
    pub async fn insert_traffic(&self, p: TrafficPoint) -> Result<()> {
        self.blocking(move |c| {
            c.execute(
                "INSERT INTO traffic_samples
                   (ts, tunnel_id, client_id, node_id, path, bytes_in, bytes_out, conns)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    p.ts,
                    p.tunnel_id,
                    p.client_id,
                    p.node_id,
                    p.path,
                    p.bytes_in,
                    p.bytes_out,
                    p.conns
                ],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 概览统计。
    pub async fn overview(&self) -> Result<OverviewStats> {
        self.blocking(|c| {
            let count = |sql: &str| -> Result<i64> {
                c.query_row(sql, [], |r| r.get(0)).map_err(Error::store)
            };
            let nodes_total = count("SELECT COUNT(*) FROM nodes")?;
            let nodes_online = count("SELECT COUNT(*) FROM nodes WHERE status = 'online'")?;
            let clients_total = count("SELECT COUNT(*) FROM clients")?;
            let clients_online = count("SELECT COUNT(*) FROM clients WHERE status = 'online'")?;
            let tunnels_total = count("SELECT COUNT(*) FROM tunnels")?;
            let tunnels_enabled = count("SELECT COUNT(*) FROM tunnels WHERE enabled = 1")?;

            let since = rscross_common::time::to_rfc3339(
                rscross_common::time::now() - chrono::Duration::hours(24),
            );
            let (bytes_in, bytes_out, conns): (i64, i64, i64) = c
                .query_row(
                    "SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
                            COALESCE(SUM(conns),0)
                     FROM traffic_samples WHERE ts >= ?1",
                    params![since],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(Error::store)?;
            let (direct, relayed): (i64, i64) = c
                .query_row(
                    "SELECT
                        COALESCE(SUM(CASE WHEN path = 'p2p' THEN bytes_in + bytes_out ELSE 0 END),0),
                        COALESCE(SUM(CASE WHEN path <> 'p2p' THEN bytes_in + bytes_out ELSE 0 END),0)
                     FROM traffic_samples WHERE ts >= ?1",
                    params![since],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(Error::store)?;

            Ok(OverviewStats {
                nodes_total,
                nodes_online,
                clients_total,
                clients_online,
                tunnels_total,
                tunnels_enabled,
                bytes_in_24h: bytes_in,
                bytes_out_24h: bytes_out,
                conns_24h: conns,
                bytes_direct_24h: direct,
                bytes_relayed_24h: relayed,
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
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
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
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
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
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
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

/// 节点心跳时更新的运行时字段（None 表示不覆盖）。
#[derive(Debug, Clone, Default)]
pub struct NodeRuntimePatch {
    /// 节点版本。
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
    /// 反向隧道监听端口。
    pub tunnel_port: Option<i64>,
    /// 公网入口监听端口。
    pub ingress_port: Option<i64>,
}

/// 节点可变字段补丁（None 表示不修改）。
#[derive(Debug, Clone, Default)]
pub struct NodePatch {
    /// 节点 ID。
    pub id: String,
    /// 名称。
    pub name: Option<String>,
    /// 对外主机名（`Some(None)` 表示清空）。
    pub public_host: Option<Option<String>>,
}

/// 客户端心跳时更新的运行时字段（None 表示不覆盖）。
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
    /// 公网端口（显式设置）。
    pub remote_port: Option<Option<i64>>,
    /// Host。
    pub host: Option<Option<String>>,
    /// 路径前缀。
    pub path_prefix: Option<Option<String>>,
    /// 访问密钥（轮换或清空）。
    pub access_key: Option<Option<String>>,
    /// P2P 隧道是否允许中继回退。
    pub allow_relay: Option<bool>,
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

const NODE_SELECT: &str = "SELECT id, name, status, node_token_hash, tunnel_token, public_host,
    tunnel_port, ingress_port, version, os, arch, endpoint_id, endpoint_addr, public_ip,
    last_seen_at, last_error, created_at, updated_at, disabled FROM nodes";

const CLIENT_SELECT: &str = "SELECT id, node_id, name, status, agent_token_hash, version, os, arch,
    endpoint_id, endpoint_addr, public_ip, last_seen_at, last_error, created_at, updated_at, disabled
    FROM clients";

const TUNNEL_SELECT: &str = "SELECT id, client_id, name, kind, proto, local_addr, remote_port,
    host, path_prefix, access_key, allow_relay, enabled, rate_limit_kbps, conn_limit,
    created_at, updated_at FROM tunnels";

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

fn map_node(row: &Row<'_>) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        status: row.get(2)?,
        node_token_hash: row.get(3)?,
        tunnel_token: row.get(4)?,
        public_host: row.get(5)?,
        tunnel_port: row.get(6)?,
        ingress_port: row.get(7)?,
        version: row.get(8)?,
        os: row.get(9)?,
        arch: row.get(10)?,
        endpoint_id: row.get(11)?,
        endpoint_addr: row.get(12)?,
        public_ip: row.get(13)?,
        last_seen_at: row.get(14)?,
        last_error: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
        disabled: row.get::<_, i64>(18)? != 0,
    })
}

fn map_client(row: &Row<'_>) -> rusqlite::Result<ClientRecord> {
    Ok(ClientRecord {
        id: row.get(0)?,
        node_id: row.get(1)?,
        name: row.get(2)?,
        status: row.get(3)?,
        agent_token_hash: row.get(4)?,
        version: row.get(5)?,
        os: row.get(6)?,
        arch: row.get(7)?,
        endpoint_id: row.get(8)?,
        endpoint_addr: row.get(9)?,
        public_ip: row.get(10)?,
        last_seen_at: row.get(11)?,
        last_error: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
        disabled: row.get::<_, i64>(15)? != 0,
    })
}

/// 在既有库上补齐新增列（幂等）。
///
/// SQLite 的 `ALTER TABLE ... ADD COLUMN` 没有 `IF NOT EXISTS`，重复执行会报
/// 「duplicate column name」，所以先读 `pragma table_info` 再决定是否执行。
fn add_missing_columns(conn: &Connection) -> Result<()> {
    const ADDITIONS: [(&str, &str, &str); 3] = [
        (
            "kind",
            "tunnels",
            "ALTER TABLE tunnels ADD COLUMN kind TEXT NOT NULL DEFAULT 'port'",
        ),
        (
            "access_key",
            "tunnels",
            "ALTER TABLE tunnels ADD COLUMN access_key TEXT",
        ),
        (
            "allow_relay",
            "tunnels",
            "ALTER TABLE tunnels ADD COLUMN allow_relay INTEGER NOT NULL DEFAULT 1",
        ),
    ];

    for (column, table, ddl) in ADDITIONS {
        if !has_column(conn, table, column)? {
            conn.execute(ddl, [])
                .map_err(|e| Error::store(format!("为 {table} 补列 {column} 失败: {e}")))?;
            tracing::info!(table, column, "已为既有数据库补充新增列");
        }
    }
    Ok(())
}

/// 表里是否已有该列。
fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(Error::store)?;
    let mut rows = stmt.query([]).map_err(Error::store)?;
    while let Some(row) = rows.next().map_err(Error::store)? {
        let name: String = row.get(1).map_err(Error::store)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn map_tunnel(row: &Row<'_>) -> rusqlite::Result<TunnelRecord> {
    Ok(TunnelRecord {
        id: row.get(0)?,
        client_id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        proto: row.get(4)?,
        local_addr: row.get(5)?,
        remote_port: row.get(6)?,
        host: row.get(7)?,
        path_prefix: row.get(8)?,
        access_key: row.get(9)?,
        allow_relay: row.get::<_, i64>(10)? != 0,
        enabled: row.get::<_, i64>(11)? != 0,
        rate_limit_kbps: row.get(12)?,
        conn_limit: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

const SCHEMA: &str = r#"
PRAGMA user_version = 2;

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

-- 服务端节点：独立控制台可以管理多个；内嵌控制台下只有一行。
CREATE TABLE IF NOT EXISTS nodes (
  id               TEXT PRIMARY KEY,
  name             TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending',
  node_token_hash  TEXT NOT NULL,
  tunnel_token     TEXT NOT NULL,
  public_host      TEXT,
  tunnel_port      INTEGER,
  ingress_port     INTEGER,
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_token ON nodes(node_token_hash);

CREATE TABLE IF NOT EXISTS clients (
  id               TEXT PRIMARY KEY,
  node_id          TEXT,
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
CREATE INDEX IF NOT EXISTS idx_clients_node ON clients(node_id);

CREATE TABLE IF NOT EXISTS enroll_tokens (
  token_hash     TEXT PRIMARY KEY,
  node_id        TEXT,
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
  kind            TEXT NOT NULL DEFAULT 'port',
  proto           TEXT NOT NULL,
  local_addr      TEXT NOT NULL,
  remote_port     INTEGER,
  host            TEXT,
  path_prefix     TEXT,
  access_key      TEXT,
  allow_relay     INTEGER NOT NULL DEFAULT 1,
  enabled         INTEGER NOT NULL DEFAULT 1,
  rate_limit_kbps INTEGER NOT NULL DEFAULT 0,
  conn_limit      INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  UNIQUE(client_id, name)
);
CREATE INDEX IF NOT EXISTS idx_tunnels_client ON tunnels(client_id);

CREATE TABLE IF NOT EXISTS traffic_samples (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  tunnel_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  node_id   TEXT,
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

    fn node_rec(name: &str) -> NodeRecord {
        let now = rscross_common::time::now_rfc3339();
        NodeRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            status: "pending".to_string(),
            node_token_hash: format!("nhash-{name}"),
            tunnel_token: format!("ttok-{name}"),
            public_host: None,
            tunnel_port: None,
            ingress_port: None,
            version: None,
            os: None,
            arch: None,
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

    fn client_rec(name: &str, node_id: Option<String>) -> ClientRecord {
        let now = rscross_common::time::now_rfc3339();
        ClientRecord {
            id: uuid::Uuid::new_v4().to_string(),
            node_id,
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
    async fn node_lifecycle_and_heartbeat() {
        let store = Store::open_in_memory().expect("open");
        let rec = node_rec("node-a");
        let id = rec.id.clone();
        store.insert_node(rec).await.expect("insert");

        let found = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "pending");
        assert_eq!(found.tunnel_server(), "127.0.0.1:7835", "未知出口 IP 时回落到本地默认端口");

        store
            .touch_node(
                id.clone(),
                NodeRuntimePatch {
                    tunnel_port: Some(17835),
                    public_ip: Some("203.0.113.9".to_string()),
                    endpoint_id: Some("aa".repeat(32)),
                    ..Default::default()
                },
            )
            .await
            .expect("touch");

        let found = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "online");
        assert_eq!(
            found.tunnel_server(),
            "203.0.113.9:17835",
            "客户端接入地址应由观测到的出口 IP + 上报端口拼出"
        );

        // 管理员显式指定对外主机名时优先
        store
            .update_node(NodePatch {
                id: id.clone(),
                name: None,
                public_host: Some(Some("t.example.com".to_string())),
            })
            .await
            .expect("update");
        let found = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(found.tunnel_server(), "t.example.com:17835");
    }

    #[tokio::test]
    async fn node_names_and_tokens_are_unique() {
        let store = Store::open_in_memory().expect("open");
        store.insert_node(node_rec("dup")).await.expect("first");

        let mut second = node_rec("dup");
        second.node_token_hash = "other".to_string();
        assert!(store.insert_node(second).await.is_err(), "重名节点必须被拒绝");

        let mut third = node_rec("dup2");
        third.node_token_hash = format!("nhash-{}", "dup");
        assert!(
            store.insert_node(third).await.is_err(),
            "token 摘要冲突必须被拒绝"
        );
    }

    #[tokio::test]
    async fn clients_are_grouped_by_node() {
        let store = Store::open_in_memory().expect("open");
        let node = node_rec("n1");
        let node_id = node.id.clone();
        store.insert_node(node).await.expect("node");
        let other = node_rec("n2");
        let other_id = other.id.clone();
        store.insert_node(other).await.expect("node2");

        store
            .insert_client(client_rec("c1", Some(node_id.clone())))
            .await
            .expect("c1");
        store
            .insert_client(client_rec("c2", Some(other_id)))
            .await
            .expect("c2");
        store
            .insert_client(client_rec("c3", None))
            .await
            .expect("c3");

        let of_node = store.list_clients_of_node(&node_id).await.expect("list");
        assert_eq!(of_node.len(), 1);
        assert_eq!(of_node[0].name, "c1");

        store.reassign_client(&of_node[0].id, None).await.expect("reassign");
        assert!(store
            .list_clients_of_node(&node_id)
            .await
            .expect("list")
            .is_empty());
    }

    #[tokio::test]
    async fn deleting_node_detaches_clients_instead_of_dropping_them() {
        let store = Store::open_in_memory().expect("open");
        let node = node_rec("n1");
        let node_id = node.id.clone();
        store.insert_node(node).await.expect("node");
        store
            .insert_client(client_rec("c1", Some(node_id.clone())))
            .await
            .expect("client");

        store.delete_node(&node_id).await.expect("delete node");

        assert!(store.find_node(&node_id).await.expect("find").is_none());
        let clients = store.list_clients().await.expect("clients");
        assert_eq!(clients.len(), 1, "客户端必须保留，只解除归属");
        assert!(clients[0].node_id.is_none());
    }

    #[tokio::test]
    async fn stale_nodes_are_marked_offline() {
        let store = Store::open_in_memory().expect("open");
        let rec = node_rec("node-c");
        let id = rec.id.clone();
        store.insert_node(rec).await.expect("insert");
        store
            .touch_node(id.clone(), NodeRuntimePatch::default())
            .await
            .expect("touch");

        let cutoff = rscross_common::time::to_rfc3339(
            rscross_common::time::now() + chrono::Duration::hours(1),
        );
        assert_eq!(
            store.mark_stale_nodes_offline(cutoff).await.expect("mark"),
            1
        );
        let found = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "offline");
    }

    #[tokio::test]
    async fn overview_counts_nodes_and_clients() {
        let store = Store::open_in_memory().expect("open");
        let node = node_rec("n1");
        let node_id = node.id.clone();
        store.insert_node(node).await.expect("node");
        store
            .insert_client(client_rec("c1", Some(node_id)))
            .await
            .expect("client");

        let o = store.overview().await.expect("overview");
        assert_eq!(o.nodes_total, 1);
        assert_eq!(o.clients_total, 1);
        assert_eq!(o.tunnels_total, 0);
    }

    #[tokio::test]
    async fn enroll_token_binds_to_node() {
        let store = Store::open_in_memory().expect("open");
        let now = rscross_common::time::now();
        store
            .insert_enroll_token(EnrollTokenRecord {
                token_hash: "h1".to_string(),
                node_id: Some("node-1".to_string()),
                client_name: Some("n".to_string()),
                created_by: None,
                created_at: rscross_common::time::to_rfc3339(now),
                expires_at: rscross_common::time::to_rfc3339(now + chrono::Duration::minutes(30)),
                used_at: None,
                used_client_id: None,
            })
            .await
            .expect("insert");

        let found = store
            .find_enroll_token("h1")
            .await
            .expect("find")
            .expect("some");
        assert_eq!(found.node_id.as_deref(), Some("node-1"));

        store
            .consume_enroll_token("h1", "c1")
            .await
            .expect("first use ok");
        assert!(store.consume_enroll_token("h1", "c2").await.is_err());
    }

    #[tokio::test]
    async fn tunnels_of_node_follow_client_ownership() {
        let store = Store::open_in_memory().expect("open");
        let node = node_rec("n1");
        let node_id = node.id.clone();
        store.insert_node(node).await.expect("node");
        let client = client_rec("c1", Some(node_id.clone()));
        let client_id = client.id.clone();
        store.insert_client(client).await.expect("client");

        let now = rscross_common::time::now_rfc3339();
        store
            .insert_tunnel(TunnelRecord {
                id: uuid::Uuid::new_v4().to_string(),
                client_id: client_id.clone(),
                name: "web".to_string(),
                kind: "domain".to_string(),
                proto: "http".to_string(),
                local_addr: "127.0.0.1:8080".to_string(),
                remote_port: None,
                host: Some("a.example.com".to_string()),
                path_prefix: None,
                access_key: None,
                allow_relay: true,
                enabled: true,
                rate_limit_kbps: 0,
                conn_limit: 0,
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .expect("tunnel");

        assert_eq!(
            store.list_tunnels_of_node(&node_id).await.expect("by node").len(),
            1
        );
        store.delete_client(&client_id).await.expect("delete");
        assert_eq!(
            store.list_tunnels_of_node(&node_id).await.expect("by node").len(),
            0
        );
    }

    #[tokio::test]
    async fn disabling_node_marks_status() {
        let store = Store::open_in_memory().expect("open");
        let rec = node_rec("n1");
        let id = rec.id.clone();
        store.insert_node(rec).await.expect("insert");
        store.set_node_disabled(&id, true).await.expect("disable");
        let found = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(found.status, "disabled");
        assert!(found.disabled);
    }
}
