#!/usr/bin/env bash
# CLI の plugin 無効構成の検証（make check-cli-no-plugin。PLUG-3・REPAIR-7・#3204）。
#
# `--no-default-features` で CLI の lib / bin が警告なしにビルド（clippy）でき、依存ツリーに plugin 境界基盤
# （fandhe-container-plugin）が入らないことを確認する。`make ci` には含めない（CI の platform-ci ジョブが同じ
# ターゲットを実行する。main では 3 OS で、Windows・macOS の cfg 分岐もネイティブで見る）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace check-cli-no-plugin
start="${SECONDS}"
run cargo clippy -p fandhe-container-cli --no-default-features --lib --bins -- -D warnings
tree="$(cargo tree -p fandhe-container-cli --no-default-features -e normal --target all)" || {
  echo "NG: cargo tree failed" >&2
  exit 1
}
if printf '%s\n' "${tree}" | grep -q 'fandhe-container-plugin'; then
  echo "NG: the plugin-disabled CLI dependency tree contains fandhe-container-plugin" >&2
  exit 1
fi
echo "OK: the plugin-disabled CLI builds and fandhe-container-plugin is not in its dependency tree ($((SECONDS - start)) s)"
