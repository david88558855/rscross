#!/usr/bin/env bash
# 将前端构建产物嵌入 rsc-server 的静态资源目录。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIST="$ROOT/web/dist"
OUT_DIR="$ROOT/crates/rsc-server/assets"

if [ ! -d "$WEB_DIST" ]; then
  echo "错误：未找到前端产物 $WEB_DIST，请先执行 npm run build" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -r "$WEB_DIST/." "$OUT_DIR/"

# 移除前端 sourcemap，避免镜像体积膨胀
find "$OUT_DIR" -name '*.map' -delete

echo "已嵌入前端资源到 $OUT_DIR ($(du -sh "$OUT_DIR" | cut -f1))"
