#!/usr/bin/env bash
# 必須コマンドの存在を確認してから、指定のスクリプトへ exec する薄いラッパー。
#
# 使い方: scripts/with-tools.sh <tool>[,<tool>...] <command> [args...]
# 例:     scripts/with-tools.sh jq scripts/fio-randwrite-4k-selftest.sh
#
# 未導入のツールがあれば黙ってスキップせず exit 1（fail-closed。CI との false-green 乖離を避ける）。
# Makefile の自己テスト系ターゲットが「jq 必須」等の前提確認を 1 行で呼ぶために使う。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${DIR}/lib.sh"

if [ "$#" -lt 2 ]; then
  echo "usage: with-tools.sh <tool>[,<tool>...] <command> [args...]" >&2
  exit 2
fi
tools="$1"
shift
IFS=',' read -r -a tool_list <<<"${tools}"
for t in "${tool_list[@]}"; do
  require_cmd "${t}"
done
exec "$@"
