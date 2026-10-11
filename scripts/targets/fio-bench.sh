#!/usr/bin/env bash
# fio 4K ランダム write ベンチの実行（make fio-bench。TASK-25.1・IO-8・MS-1 Phase 2）。
#
# 実機前提（fio・GNU coreutils の `timeout`・Linux ホスト）のため `make ci` には含めない（AGENTS.md「実機前提テスト」）。
# 入力は環境変数: TARGET_DIR・LABEL（必須）、RUNTIME（秒。既定 30）。値の検証自体は scripts/fio-randwrite-4k.sh の許可リストが担う。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${TARGET_DIR:-}" ] || [ -z "${LABEL:-}" ]; then
  echo "usage: make fio-bench TARGET_DIR=<dir> LABEL=<label> [RUNTIME=<seconds>]" >&2
  exit 2
fi
run bash scripts/fio-randwrite-4k.sh --target-dir "${TARGET_DIR}" --label "${LABEL}" --runtime "${RUNTIME:-30}"
