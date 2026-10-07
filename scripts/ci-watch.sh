#!/usr/bin/env bash
# 推送后轮询 CI，提取编译错误并以高亮格式输出。
# 用法：./scripts/ci-watch.sh [等待秒数，默认 90]
set -uo pipefail

REPO="${RSCROSS_REPO:-david88558855/rscross}"
WAIT="${1:-90}"

echo "等待 CI 启动..."
sleep "$WAIT"

RID=$(gh run list --repo "$REPO" --limit 1 --json databaseId --jq '.[0].databaseId')
if [ -z "$RID" ]; then
  echo "未找到运行记录"
  exit 1
fi

echo "run: https://github.com/$REPO/actions/runs/$RID"
echo

for i in $(seq 1 40); do
  STATUS=$(gh run view "$RID" --repo "$REPO" --json status --jq '.status')
  if [ "$STATUS" = "completed" ]; then
    break
  fi
  sleep 15
done

gh run view "$RID" --repo "$REPO" --json jobs --jq \
  '.jobs[] | "[\(.conclusion // .status)] \(.name)"'

echo
echo "================ 错误详情 ================"
gh run view "$RID" --repo "$REPO" --log-failed 2>/dev/null \
  | sed 's/\x1b\[[0-9;]*m//g' \
  | sed 's/^[^ ]*Z //' \
  | grep -E "^(error|warning)(\[E[0-9]+\])?:|^ *--> |^error: could not compile" \
  | grep -v "generated .* warning" \
  | sort -u \
  | head -60
