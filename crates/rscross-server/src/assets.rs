//! 内嵌静态资源：编译期打包前端产物
//!
//! 前端由 CI 执行 `npm run build` 后通过 `scripts/embed-web.sh`
//! 复制到 `assets/` 目录。若目录不存在（例如纯后端开发），
//! 降级为运行期文件读取，两种模式都不存在时返回 `None`。

use std::sync::OnceLock;

static EMBEDDED: OnceLock<Option<include_dir::Dir<'_>>> = OnceLock::new();

fn embedded() -> Option<&'static include_dir::Dir<'static>> {
    EMBEDDED
        .get_or_init(|| {
            let dir = include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets");
            if dir.is_empty() {
                None
            } else {
                Some(dir)
            }
        })
        .as_ref()
}

/// 读取静态资源，返回 `(内容, Content-Type)`
pub fn get(path: &str) -> Option<(Vec<u8>, &'static str)> {
    let clean = rscross_common::assets::normalize(path);

    if let Some(dir) = embedded() {
        return dir
            .get_file(&clean)
            .map(|f| (f.contents().to_vec(), rscross_common::assets::mime_of(&clean)));
    }

    // 降级：读运行期目录
    let fs_path = std::path::Path::new("assets").join(clean.trim_start_matches('/'));
    if fs_path.is_file() {
        if let Ok(bytes) = std::fs::read(&fs_path) {
            return Some((bytes, rscross_common::assets::mime_of(&clean)));
        }
    }
    None
}
