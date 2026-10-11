#!/usr/bin/env bash
# CLI がバックエンド実装 crate へ直接依存しないことの機械判定（make check-cli-backend-deps。
# CLI-1・PLUG-1・PLUG-4・TASK-79.4）。
#
# macOS / Windows は core の plugin 発見・登録機構経由で呼ぶ。`cargo tree` に platform-macos / platform-windows /
# plugin-macos / plugin-windows / microvm / plugin-microvm が現れたら NG（cargo tree の失敗も NG）。
# - 辺は normal,build,dev: build 依存の推移的な混入と、cli 自身のテスト（dev）からの境界の迂回を防ぐ。
# - `--target all`: 実行ランナーの OS に依らず `[target.'cfg(...)'.dependencies]` の辺も検査する。
# - 行頭アンカーと ` v` 接尾辞で境界機構 crate（fandhe-container-plugin）やパス文字列への誤一致を避ける。
# - plugin-cri / plugin-mcp は CLI のバックエンドではないため本検査の範囲外。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace check-cli-backend-deps
tree="$(cargo tree -p fandhe-container-cli -e normal,build,dev --target all --prefix none --format '{p}' --locked)" || {
  echo "NG: cargo tree failed" >&2
  exit 1
}
if printf '%s\n' "${tree}" | grep -Eq '^fandhe-container-(platform-(macos|windows)|plugin-(macos|windows|microvm)|microvm) v'; then
  echo "NG: the cli dependency tree contains a macOS / Windows / microVM backend crate" >&2
  exit 1
fi
echo "OK: cli does not depend on platform-macos / platform-windows / plugin-macos / plugin-windows / microvm / plugin-microvm"
