#!/usr/bin/env bash
# 結合試験（make test-integration。REPAIR-7 ステージ 3・タイムアウト保護された結合試験。TASK-86.2・#36）。
#
# CI（ci.yml の platform-ci ジョブ）と同じ判定を行う: integration test target（`tests/*.rs`。cargo metadata 上で
# kind が "test" のもの）が 0 件の場合は「no test target matches pattern」で `cargo test --workspace --test '*'` が
# 非 0 終了するため、jq で件数を数えてから呼び出す。jq 未導入は fail-closed（CI との false-green 乖離を避ける）。
# CI 側のみが持つタイムアウト保護（実行ステップ 10 分・ジョブ全体 60 分）とハングプローブはローカルには持ち込まない。
# `make ci` には含めない（`make test` が既に同じ workspace のテストを走らせるため二重実行になる）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace test-integration
command -v jq >/dev/null 2>&1 || {
  echo "jq not found: install it and re-run (brew install jq / apt-get install jq)" >&2
  exit 1
}
metadata="$(cargo metadata --no-deps --format-version 1)" || {
  echo "NG: cargo metadata failed" >&2
  exit 1
}
count="$(printf '%s' "${metadata}" | jq -er '[.packages[].targets[] | select(.kind[]? == "test")] | length')" || {
  echo "NG: failed to count integration test targets (jq)" >&2
  exit 1
}
echo "integration test targets: ${count}"
if [ "${count}" = "0" ]; then
  echo "notice: no integration test target, nothing to run"
  exit 0
fi
cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server,fandhe-container-plugin/grpc
cargo test -p fandhe-container-io --bins --features crash-test-server
