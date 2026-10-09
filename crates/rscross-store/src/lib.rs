//! `rscross-store`：SQLite 持久化层。
//!
//! 并发模型：`rusqlite` 是**同步阻塞** API，因此内部用一把 `std::sync::Mutex<Connection>`
//! 串行化写操作，并把每次调用放进 `tokio::task::spawn_blocking`，
//! 避免阻塞 async 工作线程。WAL 模式下读并发由 SQLite 自身保证。

use std::sync::{Arc, Mutex};

use rscross_common::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};

pub mod model;

pub use model::{
    AuditEntry, ClientRecord, EnrollTokenRecord, LogEntry, NodeRecord, OverviewStats,
    SessionRecord, TrafficPoint, TunnelRecord, UserRecord,
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

    /// 列出全部用户（按创建时间正序，最初的管理员排在最前）。
    pub async fn list_users(&self) -> Result<Vec<UserRecord>> {
        self.blocking(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, username, password_hash, role, disabled, created_at, last_login_at
                     FROM users ORDER BY created_at ASC",
                )
                .map_err(Error::store)?;
            let rows = stmt.query_map([], map_user).map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
        })
        .await
    }

    /// 统计管理员数量（用于「不能把最后一个管理员禁掉/删掉」这类保护）。
    pub async fn count_admins(&self) -> Result<i64> {
        self.blocking(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0",
                [],
                |r| r.get(0),
            )
            .map_err(Error::store)
        })
        .await
    }

    /// 禁用 / 启用用户。
    pub async fn set_user_disabled(&self, user_id: &str, disabled: bool) -> Result<()> {
        let (id, flag) = (user_id.to_string(), disabled as i64);
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE users SET disabled = ?1 WHERE id = ?2",
                    params![flag, id],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("用户不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 修改用户角色。
    pub async fn set_user_role(&self, user_id: &str, role: &str) -> Result<()> {
        let (id, role) = (user_id.to_string(), role.to_string());
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE users SET role = ?1 WHERE id = ?2",
                    params![role, id],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("用户不存在"));
            }
            Ok(())
        })
        .await
    }

    /// 删除某用户的全部会话（改密 / 重置密码 / 禁用后调用，让旧登录态立即失效）。
    pub async fn purge_user_sessions(&self, user_id: &str) -> Result<usize> {
        let id = user_id.to_string();
        self.blocking(move |c| {
            c.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])
                .map_err(Error::store)
        })
        .await
    }

    /// 删除用户；其会话一并清理，避免留下可用的登录态。
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        let id = user_id.to_string();
        self.blocking(move |c| {
            c.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])
                .map_err(Error::store)?;
            let n = c
                .execute("DELETE FROM users WHERE id = ?1", params![id])
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
                  last_seen_at, last_error, created_at, updated_at, disabled,
                  public_addr, description, transport, allow_relay, node_token_plain, port_range)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)",
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
                    rec.public_addr,
                    rec.description,
                    rec.transport,
                    rec.allow_relay as i64,
                    rec.node_token_plain,
                    rec.port_range,
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
            c.query_row(
                &format!("{NODE_SELECT} WHERE id = ?1"),
                params![id],
                map_node,
            )
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
                    // 三态语义，不能用 COALESCE 一把梭：
                    //   None      = 不改这个字段
                    //   Some(v)   = 改成 v
                    //   Some(None)= 清空
                    // COALESCE(x, col) 只区分前两种，Some(None) 传进去就是 NULL，
                    // 会被当成「不改」—— 清空功能静默失效。
                    // 单层 Option 的字段（transport / allow_relay）用 COALESCE 即可。
                    //
                    // 每个可改字段都必须出现在这里：`NodePatch` 加了字段而忘了
                    // 加进 SET，接口会返回 200、记录也读得出来，但改动根本没落库。
                    "UPDATE nodes SET
                        name = COALESCE(?2, name),
                        public_host = CASE WHEN ?3 THEN ?4 ELSE public_host END,
                        public_addr = CASE WHEN ?5 THEN ?6 ELSE public_addr END,
                        description = CASE WHEN ?7 THEN ?8 ELSE description END,
                        transport = COALESCE(?9, transport),
                        allow_relay = COALESCE(?10, allow_relay),
                        port_range = CASE WHEN ?11 THEN ?12 ELSE port_range END,
                        updated_at = ?13
                     WHERE id = ?1",
                    params![
                        patch.id,
                        patch.name,
                        patch.public_host.is_some(),
                        patch.public_host.flatten(),
                        patch.public_addr.is_some(),
                        patch.public_addr.flatten(),
                        patch.description.is_some(),
                        patch.description.flatten(),
                        patch.transport,
                        patch.allow_relay.map(i64::from),
                        patch.port_range.is_some(),
                        patch.port_range.flatten(),
                        now,
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

    /// 替换节点的 token 摘要（轮换凭证用）。
    /// 覆盖节点的 node token（摘要 + 明文）。
    ///
    /// 明文必须一起写：轮换之后若只更新摘要，「复制接入命令」拿到的仍是旧
    /// token —— 用户会复制出一条**注定连不上**的命令，而报错只会说「令牌无效」，
    /// 很难联想到是控制台自己没同步。
    pub async fn set_node_token(
        &self,
        id: &str,
        token_hash: &str,
        token_plain: &str,
    ) -> Result<()> {
        let (id, token_hash, token_plain, now) = (
            id.to_string(),
            token_hash.to_string(),
            token_plain.to_string(),
            rscross_common::time::now_rfc3339(),
        );
        self.blocking(move |c| {
            let n = c
                .execute(
                    "UPDATE nodes SET node_token_hash = ?2, node_token_plain = ?3,
                     updated_at = ?4 WHERE id = ?1",
                    params![id, token_hash, token_plain, now],
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
                 (token_hash, node_id, client_name, created_by, created_at, expires_at,
                  id, token_plain)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    rec.token_hash,
                    rec.node_id,
                    rec.client_name,
                    rec.created_by,
                    rec.created_at,
                    rec.expires_at,
                    rec.id,
                    rec.token_plain,
                ],
            )
            .map_err(Error::store)?;
            Ok(())
        })
        .await
    }

    /// 查出所有**尚未使用**的接入令牌（含已过期）。
    ///
    /// 只列未使用的：控制台的「待接入」区就是在回答「哪些客户端还没来」，
    /// 已使用的令牌必然已经有一条客户端记录，再列一遍只会让人对不上号。
    /// 已过期的**保留**并交给界面标注 —— 直接消失的话，用户看到的是
    /// 「我刚签发的令牌不见了」，而实际情况是「到期了，该重新签发」。
    pub async fn list_enroll_tokens(&self) -> Result<Vec<EnrollTokenRecord>> {
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, token_hash, token_plain, node_id, client_name, created_by,
                            created_at, expires_at, used_at, used_client_id
                     FROM enroll_tokens WHERE used_at IS NULL
                     ORDER BY created_at DESC",
                )
                .map_err(Error::store)?;
            let rows = stmt.query_map([], map_enroll_token).map_err(Error::store)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Error::store)
        })
        .await
    }

    /// 按条目 ID 查询接入令牌（撤销与「复制命令」都靠它定位）。
    pub async fn find_enroll_token_by_id(&self, id: &str) -> Result<Option<EnrollTokenRecord>> {
        let id = id.to_string();
        self.blocking(move |c| {
            c.query_row(
                "SELECT id, token_hash, token_plain, node_id, client_name, created_by,
                        created_at, expires_at, used_at, used_client_id
                 FROM enroll_tokens WHERE id = ?1",
                params![id],
                map_enroll_token,
            )
            .optional()
            .map_err(Error::store)
        })
        .await
    }

    /// 撤销（删除）一条**尚未使用**的接入令牌。
    ///
    /// 已使用的令牌一律拒绝删除：它对应着一条真实客户端记录，
    /// 抹掉它只会让「这个客户端当初凭什么进来的」变成一笔糊涂账。
    pub async fn revoke_enroll_token(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.blocking(move |c| {
            let n = c
                .execute(
                    "DELETE FROM enroll_tokens WHERE id = ?1 AND used_at IS NULL",
                    params![id],
                )
                .map_err(Error::store)?;
            if n == 0 {
                return Err(Error::store("接入令牌不存在，或已被使用无法撤销"));
            }
            Ok(())
        })
        .await
    }

    /// 查询接入令牌。
    pub async fn find_enroll_token(&self, hash: &str) -> Result<Option<EnrollTokenRecord>> {
        let hash = hash.to_string();
        self.blocking(move |c| {
            c.query_row(
                "SELECT id, token_hash, token_plain, node_id, client_name, created_by,
                        created_at, expires_at, used_at, used_client_id
                 FROM enroll_tokens WHERE token_hash = ?1",
                params![hash],
                map_enroll_token,
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

    /// 列出与「归属某个节点（或尚未归属任何节点）的客户端」相关的全部隧道。
    ///
    /// 为什么需要它：公网端口是**节点级**资源 —— 同一台节点上所有客户端的端口
    /// 转发隧道都由该节点统一监听，端口池也是按节点配的（见
    /// `resolve_port_pool`）。所以「这个端口还能不能用」必须看**同节点下所有
    /// 客户端**的隧道。只看自己那几条的话，同节点上的两个客户端会各自从池首
    /// 开始分配，双双拿到同一个端口，直到两台机器都开监听才在节点日志里报错。
    ///
    /// `node_id` 为 `None` 时归为「尚未归属」这一组：它们都回落全局
    /// `ingress.port_range`，事先错开可以避免将来被改派到同一节点时才暴露冲突。
    ///
    /// 用 `IS ?1` 而不是 `= ?1`：`IS` 是 SQLite 的空值安全比较，绑定 NULL 时
    /// 正好匹配 `node_id IS NULL` 的行，这样两种情况能共用一条语句。
    pub async fn list_tunnels_sharing_pool(
        &self,
        node_id: Option<&str>,
    ) -> Result<Vec<TunnelRecord>> {
        let node_id = node_id.map(str::to_string);
        self.blocking(move |c| {
            let mut stmt = c
                .prepare(&format!(
                    "{TUNNEL_SELECT} WHERE client_id IN
                       (SELECT id FROM clients WHERE node_id IS ?1)
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
            // `remote_port` / `host` / `path_prefix` / `access_key` 在 `TunnelPatch`
            // 里是**三态** `Option<Option<T>>`：
            //   None      = 不改这个字段
            //   Some(v)   = 改成 v
            //   Some(None)= 清空
            // 这里必须用 `CASE WHEN ?n THEN ?m ELSE col END`，不能用 `col = ?n`：
            // rusqlite 把外层 `None` 和 `Some(None)` **都绑成 SQL NULL**，直接赋值会让
            // 「不改」退化成「清空」。最典型的翻车路径是前端隧道列表的「启用 / 停用」
            // 按钮 —— 它只发 `{"enabled": false}`，于是切一次开关就把端口转发的公网
            // 端口、域名隧道的 Host、私有隧道的访问密钥一起抹成 NULL，而接口返回 200、
            // 界面上还提示「隧道已停用」。单层 Option 的字段（name / proto /
            // local_addr / allow_relay / enabled / 两个限值）用 COALESCE 即可。
            //
            // 每个可改字段都必须出现在这里：`TunnelPatch` 加了字段而忘了加进 SET，
            // 接口会返回 200、记录也读得出来，但改动根本没落库。
            let n = c
                .execute(
                    "UPDATE tunnels SET
                        name = COALESCE(?2, name),
                        proto = COALESCE(?3, proto),
                        local_addr = COALESCE(?4, local_addr),
                        remote_port = CASE WHEN ?5 THEN ?6 ELSE remote_port END,
                        host = CASE WHEN ?7 THEN ?8 ELSE host END,
                        path_prefix = CASE WHEN ?9 THEN ?10 ELSE path_prefix END,
                        access_key = CASE WHEN ?11 THEN ?12 ELSE access_key END,
                        allow_relay = COALESCE(?13, allow_relay),
                        enabled = COALESCE(?14, enabled),
                        rate_limit_kbps = COALESCE(?15, rate_limit_kbps),
                        conn_limit = COALESCE(?16, conn_limit),
                        updated_at = ?17
                     WHERE id = ?1",
                    params![
                        patch.id,
                        patch.name,
                        patch.proto,
                        patch.local_addr,
                        patch.remote_port.is_some(),
                        patch.remote_port.flatten(),
                        patch.host.is_some(),
                        patch.host.flatten(),
                        patch.path_prefix.is_some(),
                        patch.path_prefix.flatten(),
                        patch.access_key.is_some(),
                        patch.access_key.flatten(),
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
    /// 控制台显式配置的服务端地址（客户端据此连接服务端）。
    pub public_addr: Option<Option<String>>,
    /// 对外可见的介绍。
    pub description: Option<Option<String>>,
    /// 传输协议（`tcp` / `udp` / `quic` / `kcp` / `ws` / `wss`）。
    pub transport: Option<String>,
    /// 是否允许 P2P 直连失败后回退到中继。
    pub allow_relay: Option<bool>,
    /// 该节点的公网端口池（`lo-hi`；`Some(None)` 表示清空、回退到全局配置）。
    pub port_range: Option<Option<String>>,
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

// 列顺序必须与 `map_node` 的下标一一对应。
// 两者靠位置绑定，加列时只改一边就会让查询整体报「列数不匹配」——
// 表现为所有节点查询都失败，而不是某一列读错值。
const NODE_SELECT: &str = "SELECT id, name, status, node_token_hash, tunnel_token, public_host,
    tunnel_port, ingress_port, version, os, arch, endpoint_id, endpoint_addr, public_ip,
    last_seen_at, last_error, created_at, updated_at, disabled,
    public_addr, description, transport, allow_relay, node_token_plain, port_range FROM nodes";

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
        public_addr: row.get(19)?,
        description: row.get(20)?,
        transport: row.get(21)?,
        allow_relay: row.get::<_, i64>(22)? != 0,
        node_token_plain: row.get(23)?,
        port_range: row.get(24)?,
    })
}

/// 列顺序必须与所有 enroll_tokens 查询的 SELECT 一致。
fn map_enroll_token(row: &Row<'_>) -> rusqlite::Result<EnrollTokenRecord> {
    Ok(EnrollTokenRecord {
        id: row.get(0)?,
        token_hash: row.get(1)?,
        token_plain: row.get(2)?,
        node_id: row.get(3)?,
        client_name: row.get(4)?,
        created_by: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        used_at: row.get(8)?,
        used_client_id: row.get(9)?,
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
    const ADDITIONS: [(&str, &str, &str); 11] = [
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
        // 「新增自建节点」表单：介绍 / 服务端地址 / 传输协议 / P2P 中继开关
        (
            "description",
            "nodes",
            "ALTER TABLE nodes ADD COLUMN description TEXT",
        ),
        (
            "public_addr",
            "nodes",
            "ALTER TABLE nodes ADD COLUMN public_addr TEXT",
        ),
        (
            "transport",
            "nodes",
            "ALTER TABLE nodes ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp'",
        ),
        (
            "allow_relay",
            "nodes",
            "ALTER TABLE nodes ADD COLUMN allow_relay INTEGER NOT NULL DEFAULT 1",
        ),
        // schema v4：节点公网端口池 + node token 明文（供「复制接入命令」）
        (
            "port_range",
            "nodes",
            "ALTER TABLE nodes ADD COLUMN port_range TEXT",
        ),
        (
            "node_token_plain",
            "nodes",
            "ALTER TABLE nodes ADD COLUMN node_token_plain TEXT",
        ),
        (
            "id",
            "enroll_tokens",
            "ALTER TABLE enroll_tokens ADD COLUMN id TEXT",
        ),
        (
            "token_plain",
            "enroll_tokens",
            "ALTER TABLE enroll_tokens ADD COLUMN token_plain TEXT",
        ),
    ];

    for (column, table, ddl) in ADDITIONS {
        if !has_column(conn, table, column)? {
            conn.execute(ddl, [])
                .map_err(|e| Error::store(format!("为 {table} 补列 {column} 失败: {e}")))?;
            tracing::info!(table, column, "已为既有数据库补充新增列");
        }
    }

    // 老库里的 enroll_tokens 没有 id（v4 才引入），而「撤销 / 复制命令」都要靠它定位。
    // 这里回填一个随机 id，而不是让前端去处理「id 为 NULL 的条目」——
    // 后者意味着老令牌在界面上永远是灰的、点不动的，用户只能删库重来。
    // 语句对空表无副作用，可以每次迁移都跑。
    conn.execute(
        "UPDATE enroll_tokens SET id = lower(hex(randomblob(16)))
         WHERE id IS NULL OR id = ''",
        [],
    )
    .map_err(|e| Error::store(format!("为老接入令牌回填 id 失败: {e}")))?;

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
PRAGMA user_version = 4;

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
  disabled         INTEGER NOT NULL DEFAULT 0,
  -- 以下为「新增自建节点」表单引入的字段（schema v3）
  public_addr      TEXT,
  description      TEXT,
  transport        TEXT NOT NULL DEFAULT 'tcp',
  allow_relay      INTEGER NOT NULL DEFAULT 1,
  -- schema v4：节点自己的公网端口池 + node token 明文（供复制接入命令）
  port_range       TEXT,
  node_token_plain TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_token ON nodes(node_token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_public_addr
    ON nodes(public_addr) WHERE public_addr IS NOT NULL;

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
  used_client_id TEXT,
  -- schema v4：条目 ID 与令牌明文（明文仅供管理员「复制接入命令」）
  id             TEXT,
  token_plain    TEXT
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
            node_token_plain: Some(format!("nplain-{name}")),
            tunnel_token: format!("ttok-{name}"),
            public_host: None,
            public_addr: None,
            description: None,
            transport: "tcp".to_string(),
            allow_relay: true,
            port_range: None,
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

    /// 造一条隧道记录。`host` 一律填上，方便测试里验证「不该被清空」。
    fn tunnel_rec(client_id: &str, name: &str, remote_port: Option<i64>) -> TunnelRecord {
        let now = rscross_common::time::now_rfc3339();
        TunnelRecord {
            id: uuid::Uuid::new_v4().to_string(),
            client_id: client_id.to_string(),
            name: name.to_string(),
            kind: if remote_port.is_some() {
                "port"
            } else {
                "domain"
            }
            .to_string(),
            proto: "tcp".to_string(),
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port,
            host: Some(format!("{name}.example.com")),
            path_prefix: None,
            access_key: None,
            allow_relay: true,
            enabled: true,
            rate_limit_kbps: 0,
            conn_limit: 0,
            created_at: now.clone(),
            updated_at: now,
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
        assert_eq!(
            found.tunnel_server(),
            "127.0.0.1:7835",
            "未知出口 IP 时回落到本地默认端口"
        );

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
                public_addr: None,
                description: None,
                transport: None,
                allow_relay: None,
                port_range: None,
            })
            .await
            .expect("update");
        let found = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(found.tunnel_server(), "t.example.com:17835");
    }

    #[tokio::test]
    async fn console_addr_does_not_leak_into_the_reverse_tunnel_address() {
        // public_addr 存的是**控制台**地址（ws://host:7800），
        // tunnel_server() 要的是反向隧道控制面（host:7835）。
        // 两者协议与端口都不同 —— 混用会让客户端拿 7800 去连 7835 的服务，
        // 能连上才怪。这条用例就是钉住这个边界。
        let store = Store::open_in_memory().expect("open");
        let id = uuid::Uuid::new_v4().to_string();
        let mut rec = node_rec("console-addr");
        rec.id = id.clone();
        rec.tunnel_port = Some(7835);
        store.insert_node(rec).await.expect("insert");

        store
            .update_node(NodePatch {
                id: id.clone(),
                name: None,
                public_host: None,
                public_addr: Some(Some("ws://203.0.113.9:7800".to_string())),
                description: Some(Some("香港出口".to_string())),
                transport: Some("wss".to_string()),
                allow_relay: Some(false),
                port_range: None,
            })
            .await
            .expect("update");

        let got = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(got.public_addr.as_deref(), Some("ws://203.0.113.9:7800"));
        assert_eq!(got.description.as_deref(), Some("香港出口"));
        assert_eq!(got.transport, "wss");
        assert!(!got.allow_relay);

        // 关键：控制台地址里带了 7800，但它绝不能出现在反向隧道地址里。
        // 没有 public_host 也没有 public_ip 时回落到127.0.0.1。
        assert_eq!(
            got.tunnel_server(),
            "127.0.0.1:7835",
            "控制面地址不应影响反向隧道地址"
        );

        // 配了 public_host 时用它（内嵌形态启动流程会自动填这一列）。
        store
            .update_node(NodePatch {
                id: id.clone(),
                name: None,
                public_host: Some(Some("203.0.113.9".to_string())),
                public_addr: None,
                description: None,
                transport: None,
                allow_relay: None,
                port_range: None,
            })
            .await
            .expect("update");
        let got = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(got.tunnel_server(), "203.0.113.9:7835");

        // 三态：None = 不改，Some(None) = 清空。
        store
            .update_node(NodePatch {
                id: id.clone(),
                name: None,
                public_host: None,
                public_addr: None,
                description: None,
                transport: Some("kcp".to_string()),
                allow_relay: None,
                port_range: None,
            })
            .await
            .expect("update");
        let got = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(
            got.public_addr.as_deref(),
            Some("ws://203.0.113.9:7800"),
            "public_addr 传 None 表示不改，不该被清掉"
        );
        assert_eq!(
            got.description.as_deref(),
            Some("香港出口"),
            "未传的字段不该变"
        );
        assert_eq!(got.transport, "kcp", "只改 transport，另两个不该动");
        assert!(!got.allow_relay, "未传的 allow_relay 不该变");
    }

    #[tokio::test]
    async fn node_names_and_tokens_are_unique() {
        let store = Store::open_in_memory().expect("open");
        store.insert_node(node_rec("dup")).await.expect("first");

        let mut second = node_rec("dup");
        second.node_token_hash = "other".to_string();
        assert!(
            store.insert_node(second).await.is_err(),
            "重名节点必须被拒绝"
        );

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

        store
            .reassign_client(&of_node[0].id, None)
            .await
            .expect("reassign");
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
                id: "tok-1".to_string(),
                token_hash: "h1".to_string(),
                token_plain: Some("rse_plain_1".to_string()),
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
    async fn enroll_token_may_have_no_node() {
        // 「控制台里还没有节点」是合法状态：令牌照发，归属留空。
        // 这条守的是「创建客户端不依赖节点」这条产品规则，
        // 一旦有人把 node_id 改回 NOT NULL，测试会立刻失败。
        let store = Store::open_in_memory().expect("open");
        let now = rscross_common::time::now();
        store
            .insert_enroll_token(EnrollTokenRecord {
                id: "tok-orphan".to_string(),
                token_hash: "orphan".to_string(),
                token_plain: Some("rse_plain_orphan".to_string()),
                node_id: None,
                client_name: None,
                created_by: None,
                created_at: rscross_common::time::to_rfc3339(now),
                expires_at: rscross_common::time::to_rfc3339(now + chrono::Duration::minutes(30)),
                used_at: None,
                used_client_id: None,
            })
            .await
            .expect("无归属节点的令牌也要能落库");

        let found = store
            .find_enroll_token("orphan")
            .await
            .expect("find")
            .expect("some");
        assert!(found.node_id.is_none());
    }

    #[tokio::test]
    async fn enroll_token_listing_skips_used_and_revoke_is_one_way() {
        // 「待接入」列表的语义：只列**还没被用掉**的令牌。
        // 已使用的那条必然对应一条客户端记录，再列一遍只会让人对不上号。
        let store = Store::open_in_memory().expect("open");
        let now = rscross_common::time::now();
        let mk = |id: &str, hash: &str| EnrollTokenRecord {
            id: id.to_string(),
            token_hash: hash.to_string(),
            token_plain: Some(format!("rse_plain_{hash}")),
            node_id: None,
            client_name: Some(format!("c-{id}")),
            created_by: Some("admin".to_string()),
            created_at: rscross_common::time::to_rfc3339(now),
            expires_at: rscross_common::time::to_rfc3339(now + chrono::Duration::minutes(30)),
            used_at: None,
            used_client_id: None,
        };
        store.insert_enroll_token(mk("t1", "h1")).await.expect("i1");
        store.insert_enroll_token(mk("t2", "h2")).await.expect("i2");

        let all = store.list_enroll_tokens().await.expect("list");
        assert_eq!(all.len(), 2, "两条都还没用掉");
        // 明文必须能读回来，否则「复制接入命令」就没有数据源。
        assert!(all.iter().all(|t| t.token_plain.is_some()));

        store
            .consume_enroll_token("h1", "client-1")
            .await
            .expect("consume");
        let after = store.list_enroll_tokens().await.expect("list");
        assert_eq!(after.len(), 1, "用掉的那条不再出现在待接入列表里");
        assert_eq!(after[0].id, "t2");

        // 按 id 能定位到（撤销 / 复制命令都依赖它）。
        let t2 = store
            .find_enroll_token_by_id("t2")
            .await
            .expect("find")
            .expect("some");
        assert_eq!(t2.token_hash, "h2");
        assert_eq!(t2.token_plain.as_deref(), Some("rse_plain_h2"));

        // 撤销后从列表消失，且再撤一次会报错（不是静默成功）。
        store.revoke_enroll_token("t2").await.expect("revoke");
        assert!(store.list_enroll_tokens().await.expect("list").is_empty());
        assert!(
            store.revoke_enroll_token("t2").await.is_err(),
            "重复撤销应报错，而不是静默通过"
        );

        // 已使用的令牌不允许撤销：它对应一条真实客户端记录，删掉就说不清来历了。
        assert!(
            store.revoke_enroll_token("t1").await.is_err(),
            "已使用的令牌不该被撤销"
        );
    }

    #[tokio::test]
    async fn node_port_range_round_trips_and_can_be_cleared() {
        // 节点自己的端口池：空 = 用全局配置；设了 = 覆盖。
        // 三态必须都能表达，否则用户没法「改回全局」。
        let store = Store::open_in_memory().expect("open");
        let mut rec = node_rec("edge-1");
        let id = rec.id.clone();
        rec.port_range = Some("30000-30100".to_string());
        store.insert_node(rec).await.expect("insert");

        let got = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(got.port_range.as_deref(), Some("30000-30100"));

        // 明文 token 也要能读回（复制接入命令的数据源）。
        assert_eq!(got.node_token_plain.as_deref(), Some("nplain-edge-1"));

        // 清空 → 回退到全局。
        store
            .update_node(NodePatch {
                id: id.clone(),
                name: None,
                public_host: None,
                public_addr: None,
                description: None,
                transport: None,
                allow_relay: None,
                port_range: Some(None),
            })
            .await
            .expect("update");
        let got = store.find_node(&id).await.expect("find").expect("some");
        assert!(got.port_range.is_none(), "传 Some(None) 应清空端口池");

        // 只改别的字段时，端口池不该被动。
        store
            .update_node(NodePatch {
                id: id.clone(),
                name: Some("edge-1-renamed".to_string()),
                public_host: None,
                public_addr: None,
                description: None,
                transport: None,
                allow_relay: None,
                port_range: None,
            })
            .await
            .expect("update");
        let got = store.find_node(&id).await.expect("find").expect("some");
        assert_eq!(got.name, "edge-1-renamed");
        assert!(got.port_range.is_none(), "未传的字段不该被改动");
    }

    #[tokio::test]
    async fn user_admin_crud_and_last_admin_guard_inputs() {
        let store = Store::open_in_memory().expect("open");
        let admin = store
            .create_user(
                "admin".to_string(),
                "hash-a".to_string(),
                "admin".to_string(),
            )
            .await
            .expect("create admin");
        let viewer = store
            .create_user(
                "alice".to_string(),
                "hash-b".to_string(),
                "viewer".to_string(),
            )
            .await
            .expect("create viewer");

        assert_eq!(store.count_users().await.expect("count"), 2);
        assert_eq!(store.count_admins().await.expect("admins"), 1);

        let users = store.list_users().await.expect("list");
        assert_eq!(users.len(), 2);
        let names: std::collections::HashSet<&str> =
            users.iter().map(|u| u.username.as_str()).collect();
        assert!(names.contains("admin") && names.contains("alice"));
        assert!(users.iter().all(|u| !u.disabled));

        store
            .set_user_disabled(&viewer.id, true)
            .await
            .expect("disable");
        let found = store
            .find_user_by_id(&viewer.id)
            .await
            .expect("find")
            .expect("some");
        assert!(found.disabled);

        store
            .set_user_role(&viewer.id, "admin")
            .await
            .expect("promote");
        assert_eq!(
            store.count_admins().await.expect("admins"),
            1,
            "被禁用的管理员不计入"
        );
        store
            .set_user_disabled(&viewer.id, false)
            .await
            .expect("enable");
        assert_eq!(store.count_admins().await.expect("admins"), 2);

        store
            .set_password(&admin.id, "hash-c".to_string())
            .await
            .expect("set password");
        store
            .purge_user_sessions(&admin.id)
            .await
            .expect("purge sessions");

        store.delete_user(&viewer.id).await.expect("delete");
        assert_eq!(store.count_users().await.expect("count"), 1);
        assert!(
            store.delete_user(&viewer.id).await.is_err(),
            "重复删除应报错"
        );
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
            store
                .list_tunnels_of_node(&node_id)
                .await
                .expect("by node")
                .len(),
            1
        );
        store.delete_client(&client_id).await.expect("delete");
        assert_eq!(
            store
                .list_tunnels_of_node(&node_id)
                .await
                .expect("by node")
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn update_tunnel_only_touches_the_fields_it_is_given() {
        // 回归：`TunnelPatch` 的 remote_port / host / path_prefix / access_key 是
        // **三态** `Option<Option<T>>`，SQL 里若图省事写成 `col = ?n`，rusqlite 会把
        // 外层 `None` 与 `Some(None)` 一并绑成 NULL，「不改」就退化成「清空」。
        // 真实现场是前端隧道列表的「启用 / 停用」按钮：它只发 `{"enabled":false}`，
        // 于是切一次开关就把公网端口、域名 Host、访问密钥全部抹掉。
        let store = Store::open_in_memory().expect("open");
        let client = client_rec("c1", None);
        let client_id = client.id.clone();
        store.insert_client(client).await.expect("client");

        let mut tunnel = tunnel_rec(&client_id, "web", Some(45000));
        tunnel.path_prefix = Some("/app".to_string());
        tunnel.access_key = Some("ak-secret".to_string());
        let id = tunnel.id.clone();
        store.insert_tunnel(tunnel).await.expect("tunnel");

        // 只改 enabled —— 其余字段必须原封不动。
        store
            .update_tunnel(TunnelPatch {
                id: id.clone(),
                enabled: Some(false),
                ..Default::default()
            })
            .await
            .expect("patch enabled");
        let after = store.find_tunnel(&id).await.expect("find").expect("some");
        assert!(!after.enabled);
        assert_eq!(after.remote_port, Some(45000), "切开关不该清空公网端口");
        assert_eq!(
            after.host.as_deref(),
            Some("web.example.com"),
            "切开关不该清空 Host"
        );
        assert_eq!(
            after.path_prefix.as_deref(),
            Some("/app"),
            "切开关不该清空路径前缀"
        );
        assert_eq!(
            after.access_key.as_deref(),
            Some("ak-secret"),
            "切开关不该清空访问密钥"
        );
        assert_eq!(after.name, "web");
        assert_eq!(after.local_addr, "127.0.0.1:8080");

        // 反面：显式 `Some(None)` 必须真的能清空，否则「清空」功能会静默失效。
        store
            .update_tunnel(TunnelPatch {
                id: id.clone(),
                host: Some(None),
                ..Default::default()
            })
            .await
            .expect("clear host");
        let after = store.find_tunnel(&id).await.expect("find").expect("some");
        assert_eq!(after.host, None, "Some(None) 应清空 Host");
        assert_eq!(after.remote_port, Some(45000), "清空 Host 不该波及端口");

        // 显式改值也要落库。
        store
            .update_tunnel(TunnelPatch {
                id: id.clone(),
                remote_port: Some(Some(45001)),
                ..Default::default()
            })
            .await
            .expect("set port");
        let after = store.find_tunnel(&id).await.expect("find").expect("some");
        assert_eq!(after.remote_port, Some(45001));
        assert_eq!(
            after.access_key.as_deref(),
            Some("ak-secret"),
            "改端口不该动访问密钥"
        );
    }

    #[tokio::test]
    async fn tunnels_sharing_pool_group_by_node_ownership() {
        // 公网端口是节点级资源：占用判定必须覆盖**同节点下所有客户端**的隧道，
        // 否则同节点上两个客户端会各自从池首分配、拿到同一个端口。
        let store = Store::open_in_memory().expect("open");
        let node = node_rec("n1");
        let node_id = node.id.clone();
        store.insert_node(node).await.expect("node");

        let a = client_rec("c-a", Some(node_id.clone()));
        let b = client_rec("c-b", Some(node_id.clone()));
        let orphan = client_rec("c-orphan", None);
        let (a_id, b_id, o_id) = (a.id.clone(), b.id.clone(), orphan.id.clone());
        store.insert_client(a).await.expect("a");
        store.insert_client(b).await.expect("b");
        store.insert_client(orphan).await.expect("orphan");

        let ta = tunnel_rec(&a_id, "web", Some(20000));
        let tb = tunnel_rec(&b_id, "web", Some(20000));
        let to = tunnel_rec(&o_id, "web", Some(20000));
        let (ta_id, tb_id, to_id) = (ta.id.clone(), tb.id.clone(), to.id.clone());
        store.insert_tunnel(ta).await.expect("ta");
        store.insert_tunnel(tb).await.expect("tb");
        store.insert_tunnel(to).await.expect("to");

        let scoped = store
            .list_tunnels_sharing_pool(Some(&node_id))
            .await
            .expect("by node");
        let ids: std::collections::HashSet<&str> = scoped.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids.len(), 2, "同节点下两个客户端的隧道都应计入：{ids:?}");
        assert!(ids.contains(ta_id.as_str()) && ids.contains(tb_id.as_str()));
        assert!(
            !ids.contains(to_id.as_str()),
            "未归属节点的客户端不该混进该节点的占用集合"
        );

        let orphans = store
            .list_tunnels_sharing_pool(None)
            .await
            .expect("orphans");
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].id, to_id);
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
