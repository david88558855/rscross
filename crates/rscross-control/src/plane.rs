//! 控制面外观（facade）。
//!
//! 把「一个可运行的控制面」打包成一个对象，供两种部署形态复用：
//!
//! - 独立控制台二进制：`bootstrap_plane` + `serve_plane`，监听公网端口；
//! - 服务端内嵌：同一个进程里再调 `ensure_node` / `node_heartbeat`，
//!   **直接走进程内函数调用**，不绕 HTTP、不需要自己给自己发 token。

use std::net::SocketAddr;

use axum::Router;
use rscross_common::{Error, NodeEndpoint, NodeRuntime, Result};
use rscross_store::NodeRecord;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::api::nodes::{
    apply_node_heartbeat, node_endpoint, provision_node, rotate_token, NodeHeartbeatResponse,
};
use crate::state::AppState;

/// 可运行的控制面。
#[derive(Clone)]
pub struct ControlPlane {
    state: AppState,
}

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("embedded", &self.state.embedded)
            .field("config_path", &self.state.config_path)
            .finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// 用已构建好的状态创建。
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// 共享状态句柄。
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// 组装 axum 路由。
    pub fn router(&self) -> Router {
        crate::api::router().with_state(self.state.clone())
    }

    /// 绑定监听地址。
    pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
        TcpListener::bind(addr)
            .await
            .map_err(|e| Error::config(format!("控制台绑定 {addr} 失败: {e}")))
    }

    /// 运行 HTTP 服务 + 内务循环，直到 `cancel` 触发。
    pub async fn serve(self, listener: TcpListener, cancel: CancellationToken) -> Result<()> {
        let state = self.state.clone();

        // 内务循环：离线判定、会话清理、登录限流清扫、保留期清理。
        let housekeeping = tokio::spawn({
            let state = state.clone();
            async move { housekeeping_loop(state).await }
        });

        // 日志落库（可选）
        let persist = if state.config_snapshot().await.log.persist {
            Some(tokio::spawn({
                let state = state.clone();
                async move { persist_logs(state).await }
            }))
        } else {
            None
        };

        let bound = listener
            .local_addr()
            .map_err(|e| Error::config(format!("读取实际监听地址失败: {e}")))?;
        // 监听在 0.0.0.0 时 `http://0.0.0.0:7800` 对使用者毫无意义，换成占位提示。
        let console_url = if bound.ip().is_unspecified() {
            format!("http://<本机IP或域名>:{}", bound.port())
        } else {
            format!("http://{bound}")
        };

        let missing = crate::console::missing_assets();
        if missing.is_empty() {
            tracing::info!(
                console = %console_url,
                bind = %bound,
                assets = crate::console::asset_count(),
                embedded = state.embedded,
                "控制台已就绪：浏览器打开上面的地址即可"
            );
        } else {
            tracing::error!(
                bind = %bound,
                missing = ?missing,
                embedded = state.embedded,
                "前端资源未内嵌，浏览器打开控制台只会看到 404 或空白；\
                 请确认构建时仓库根的 web/ 目录存在且已被提交"
            );
        }

        // 「浏览器打开 ip:7800 没反应」十有八九不是前端的问题，而是网络可达性。
        // 这里把三种最常见成因直接点出来，省得去猜。
        if bound.ip().is_unspecified() {
            tracing::info!(
                port = bound.port(),
                "浏览器打不开时按顺序排查：1) 云服务器安全组 / 系统防火墙已放行该端口；\
                 2) 用 http:// 而不是 https:// 访问；3) 从外部机器执行 \
                 curl -v http://<公网IP>:<端口>/api/v1/health 看是否通"
            );
        } else if bound.ip().is_loopback() {
            tracing::warn!(
                bind = %bound,
                "控制台只监听回环地址，其他机器访问不到；如需对外开放，\
                 请把 console.bind 改为 \"0.0.0.0:{}\"",
                bound.port()
            );
        }

        let app = self.router();
        let serve_result = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown({
            let token = cancel.clone();
            async move { token.cancelled().await }
        })
        .await;

        if let Err(err) = serve_result {
            tracing::error!(error = %err, "控制台 HTTP 服务异常退出");
        }

        let grace = std::time::Duration::from_secs(
            state
                .config_snapshot()
                .await
                .console
                .shutdown_grace_secs
                .max(1),
        );
        for (name, handle) in [("housekeeping", housekeeping)] {
            match tokio::time::timeout(grace, handle).await {
                Ok(Ok(())) => tracing::debug!(task = name, "任务已退出"),
                Ok(Err(err)) => tracing::warn!(task = name, error = %err, "任务 panic"),
                Err(_) => tracing::warn!(task = name, "任务未在宽限期内退出"),
            }
        }
        if let Some(handle) = persist {
            let _ = tokio::time::timeout(grace, handle).await;
        }

        Ok(())
    }

    // ------------------------------------------------------- 内嵌模式专用

    /// 确保「本机节点」存在，返回它的记录与**新的** node token 明文。
    ///
    /// 内嵌模式下每次都轮换 token：token 只在本进程内使用，轮换代价为零，
    /// 却避免了「state_dir 里残留旧 token、库里已是新 hash」这种静默不一致。
    ///
    /// `public_host` 用于生成客户端接入地址（`tunnel_server`）。内嵌进程自己是拿不到
    /// 公网出口 IP 的（心跳来自 127.0.0.1），所以这里必须由节点配置显式提供，
    /// 否则客户端命令会指向 127.0.0.1。
    pub async fn ensure_node(
        &self,
        name: &str,
        tunnel_token: Option<String>,
        public_host: Option<String>,
    ) -> Result<(NodeRecord, String)> {
        let existing = self
            .state
            .store
            .find_node_by_name(name)
            .await
            .map_err(Error::store)?;

        match existing {
            Some(existing) => {
                let token = rotate_token(&self.state, &existing.id)
                    .await
                    .map_err(|e| Error::api(e.to_string()))?;
                if let Some(host) = public_host.clone() {
                    self.state
                        .store
                        .update_node(rscross_store::NodePatch {
                            id: existing.id.clone(),
                            name: None,
                            public_host: Some(Some(host)),
                            public_addr: None,
                            description: None,
                            transport: None,
                            allow_relay: None,
                            // 内嵌形态只维护对外主机名，端口池由用户在控制台配置。
                            port_range: None,
                        })
                        .await
                        .map_err(Error::store)?;
                }
                let node = self
                    .state
                    .store
                    .find_node(&existing.id)
                    .await
                    .map_err(Error::store)?
                    .ok_or_else(|| Error::internal("节点在轮换后消失"))?;
                Ok((node, token))
            }
            None => provision_node(
                &self.state,
                name.to_string(),
                tunnel_token,
                Some("embedded".to_string()),
            )
            .await
            .map_err(|e| Error::api(e.to_string())),
        }
    }

    /// 直接把一次心跳应用到控制面（不经 HTTP / 鉴权）。
    pub async fn heartbeat(
        &self,
        node_id: &str,
        runtime: &NodeRuntime,
        public_ip: Option<String>,
    ) -> Result<NodeHeartbeatResponse> {
        apply_node_heartbeat(&self.state, node_id, runtime, public_ip)
            .await
            .map_err(|e| Error::api(e.to_string()))
    }

    /// 取节点的数据面坐标。
    pub async fn endpoint_of(&self, node_id: &str) -> Result<NodeEndpoint> {
        let node = self
            .state
            .store
            .find_node(node_id)
            .await
            .map_err(Error::store)?
            .ok_or_else(|| Error::api("节点不存在"))?;
        Ok(node_endpoint(&node))
    }

    /// 由 [`ControlPlane`] 持有的存储句柄（内嵌模式启动时用）。
    pub fn store(&self) -> &rscross_store::Store {
        &self.state.store
    }
}

async fn housekeeping_loop(state: AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut rounds: u64 = 0;

    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            _ = ticker.tick() => {}
        }

        rounds += 1;
        let cfg = state.config_snapshot().await;
        let cutoff = rscross_common::time::to_rfc3339(
            rscross_common::time::now()
                - chrono::Duration::seconds(cfg.console.offline_after_secs as i64),
        );

        match state.store.mark_stale_nodes_offline(cutoff.clone()).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "标记超时服务端节点为离线"),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "节点离线判定失败"),
        }
        match state.store.mark_stale_clients_offline(cutoff).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "标记超时客户端为离线"),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "客户端离线判定失败"),
        }

        if let Err(err) = state.store.purge_expired_sessions().await {
            tracing::warn!(error = %err, "清理过期会话失败");
        }
        state.throttle.sweep();

        // 保留期清理每小时一次即可。
        if rounds % 240 == 0 {
            if let Err(err) = state
                .store
                .purge_old_data(
                    cfg.database.traffic_retention_days,
                    cfg.database.log_retention_days,
                )
                .await
            {
                tracing::warn!(error = %err, "保留期清理失败");
            }
        }
    }
}

async fn persist_logs(state: AppState) {
    let mut rx = state.logs.subscribe();
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            received = rx.recv() => match received {
                Ok(event) => {
                    let entry = rscross_store::LogEntry {
                        id: 0,
                        ts: event.ts,
                        level: event.level,
                        target: Some(event.target),
                        message: event.message,
                        client_id: None,
                        tunnel_id: None,
                    };
                    if let Err(err) = state.store.insert_log(entry).await {
                        tracing::warn!(error = %err, "日志落库失败");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "日志订阅落后，已丢弃部分事件");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}
