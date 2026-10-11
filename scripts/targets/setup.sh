#!/usr/bin/env bash
# 開発環境を一括構築する（make setup）。
#
# submodule → rustup → hooks の順を保証する。Make の依存ターゲット並記だと -j 実行時に順序が
# 保証されず、cargo フォールバックを持つ hooks が rustup より先に走りうるため、順次呼び出す。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

"${DIR}/submodule.sh"
"${DIR}/rustup.sh"
"${DIR}/hooks.sh"
echo "setup complete"
