//! rscross-common —— rscross 公共库
//!
//! 提供跨 crate 复用的基础设施：配置解析、日志、加密、RPC 传输层、
//! 统一响应结构与工具函数。

pub mod assets;
pub mod config;
pub mod crypto;
pub mod error;
pub mod logger;
pub mod response;
pub mod rpc;
pub mod util;

pub use error::{AppError, AppResult, ErrorCode};
pub use response::{ApiResponse, PageData, PageQuery};

/// 项目名称
pub const APP_NAME: &str = "rscross";
/// 版本号
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
