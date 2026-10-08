//! `rscross-server`：控制面 + 中继 + 控制台。
//!
//! 进程内并发的六条任务：
//! 1. **HTTP 服务**（axum）：控制台静态资源 + `/api/v1/*`。
//! 2. **FerroTunnel 中继服务端**：反向隧道控制面 + 公网 HTTP 入口。
//! 3. **Iroh 节点**：本进程内绑定，供控制面做直连探测与投递；无 accept 循环时不占额外任务。
//! 4. **日志持久化**：订阅 [`logbus::LogBus`]，按配置落库。
//! 5. **内务循环**：离线判定、会话清理、保留期清理、登录限流清扫。
//! 6. **信号监听**：SIGINT/SIGTERM → 触发 `CancellationToken` → 各任务收敛。

pub mod api;
pub mod bootstrap;
pub mod console;
pub mod error;
pub mod logbus;
pub mod state;

pub use bootstrap::run;
pub use state::AppState;
