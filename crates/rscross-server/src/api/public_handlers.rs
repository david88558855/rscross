//! 公开接口：无需登录即可访问

use axum::extract::State;
use axum::Json;
use serde_json::json;

use rscross_common::error::AppResult;
use rscross_common::response::ApiResponse;

use crate::AppState;

/// 公开系统配置（登录页使用）
pub async fn public_config(
    State(state): State<AppState>,
) -> Json<ApiResponse<serde_json::Value>> {
    let result = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT name, value, `group` FROM system_configs")
                .fetch_all(pool)
                .await?;

        // 只暴露前端需要的公开配置
        let mut cfg = serde_json::Map::new();
        for (name, value, _g) in rows {
            if matches!(
                name.as_str(),
                "site_name" | "site_url" | "register_enable" | "email_enable" | "notice"
            ) {
                cfg.insert(name, json!(value));
            }
        }
        Ok::<_, rscross_common::error::AppError>(json!({ "config": cfg }))
    }
    .await;
    Json(result.into())
}

/// 公开公告
pub async fn public_notice(
    State(state): State<AppState>,
) -> Json<ApiResponse<serde_json::Value>> {
    let result: AppResult<serde_json::Value> = async {
        let pool = state.db.sqlite_pool().ok_or("仅支持 SQLite")?;
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT title, content FROM system_notices WHERE status = 1 ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(json!({ "list": rows }))
    }
    .await;
    Json(result.into())
}
