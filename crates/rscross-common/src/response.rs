//! 统一 API 响应结构
//!
//! 前端约定：HTTP 状态码恒为 200，业务结果由 `code` 字段表达。
//! `code == 0` 表示成功，其余为业务错误码。

use serde::{Deserialize, Serialize};

use crate::error::{AppError, ErrorCode};

#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 0,
            msg: "success".to_string(),
            data: Some(data),
        }
    }

    pub fn ok_empty() -> Self {
        Self {
            code: 0,
            msg: "success".to_string(),
            data: None,
        }
    }
}

impl ApiResponse<serde_json::Value> {
    /// 构造失败响应
    pub fn fail(code: ErrorCode, msg: impl Into<String>) -> Self {
        let m = msg.into();
        Self {
            code: code.as_i32(),
            msg: if m.is_empty() {
                code.message().to_string()
            } else {
                m
            },
            data: None,
        }
    }
}

/// 包装 `Result`，成功取数据，失败转统一响应
impl<T: Serialize> From<AppResult<T>> for ApiResponse<T> {
    fn from(r: AppResult<T>) -> Self {
        match r {
            Ok(v) => ApiResponse::ok(v),
            Err(e) => {
                let code = e.code();
                ApiResponse {
                    code: code.as_i32(),
                    msg: e.to_string(),
                    data: None,
                }
            }
        }
    }
}

/// 分页查询请求体（前端统一 POST 传参）
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    pub page: u32,
    #[serde(default)]
    pub page_size: u32,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub order: Option<String>,
    #[serde(default)]
    pub order_field: Option<String>,
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub end_time: Option<String>,
    /// 业务过滤条件，直接透传到 SQL WHERE
    #[serde(flatten)]
    pub filters: serde_json::Map<String, serde_json::Value>,
}

impl PageQuery {
    /// 页码归一化，最小为 1
    pub fn page(&self) -> u64 {
        self.page.max(1) as u64
    }

    /// 每页条数归一化，限制在 1..=500，防止恶意超大分页
    pub fn page_size(&self) -> u64 {
        self.page_size.clamp(1, 500) as u64
    }

    pub fn offset(&self) -> u64 {
        (self.page() - 1) * self.page_size()
    }

    /// 排序字段白名单校验，防止 SQL 注入
    ///
    /// 仅允许 `column` 或 `column ASC|DESC` 形式，且列名匹配 `[A-Za-z0-9_]+`。
    pub fn order_by(&self, allowed: &[&str]) -> String {
        let raw = self.order.clone().unwrap_or_default();
        let field = self.order_field.clone().unwrap_or_else(|| "id".to_string());

        // 拆分字段与方向
        let (field, desc) = if let Some(f) = raw.strip_prefix("-") {
            (f, true)
        } else {
            (raw.as_str(), false)
        };

        let field = if field.is_empty() { "id" } else { field };

        if !allowed.contains(&field) || !is_valid_identifier(field) {
            return "id DESC".to_string();
        }

        if desc {
            format!("{field} DESC")
        } else {
            format!("{field} ASC")
        }
    }
}

fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// 分页响应数据
#[derive(Debug, Clone, Serialize)]
pub struct PageData<T> {
    pub list: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

impl<T> PageData<T> {
    pub fn new(list: Vec<T>, total: u64, q: &PageQuery) -> Self {
        Self {
            list,
            total,
            page: q.page(),
            page_size: q.page_size(),
        }
    }
}
