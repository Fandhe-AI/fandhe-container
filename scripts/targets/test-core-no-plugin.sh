#!/usr/bin/env bash
# core の plugin 無効構成の検証（make test-core-no-plugin。PLUG-3・TASK-111.1・#262・REPAIR-10 (d)）。
#
# `--no-default-features` で core がビルド・テストでき、依存ツリーに plugin 境界基盤（fandhe-container-plugin）が
# 入らないことを確認する。`make ci` には含めない（CI の platform-ci ジョブが同じターゲットを実行する）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace test-core-no-plugin
run cargo test -p fandhe-container-core --no-default-features --lib
tree="$(cargo tree -p fandhe-container-core --no-default-features -e normal)" || {
  echo "NG: cargo tree failed" >&2
  exit 1
}
if printf '%s\n' "${tree}" | grep -q 'fandhe-container-plugin'; then
  echo "NG: the plugin-disabled dependency tree contains fandhe-container-plugin" >&2
  exit 1
fi
echo "OK: fandhe-container-plugin is not in the dependency tree of the plugin-disabled build"
