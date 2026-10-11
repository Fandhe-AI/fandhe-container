#!/usr/bin/env bash
# Cargo.toml とメンバー crate が揃っているときだけコマンドを実行し、無ければ skip して成功終了する。
#
# 使い方: scripts/with-workspace.sh <target-name> <command> [args...]
# 例:     scripts/with-workspace.sh plug4-core-invariance bash scripts/check-plug4-core-invariance.sh
#
# member crate が 1 つも無い仮想 workspace では cargo の fmt/clippy/test 等が「対象パッケージが無い」
# エラーで落ちるため、workspace 作成前の中間状態でも make が失敗しないようにする（冪等セルフヒール）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${DIR}/lib.sh"

if [ "$#" -lt 2 ]; then
  echo "usage: with-workspace.sh <target-name> <command> [args...]" >&2
  exit 2
fi
name="$1"
shift
skip_unless_workspace "${name}"
exec "$@"
