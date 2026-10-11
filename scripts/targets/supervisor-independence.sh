#!/usr/bin/env bash
# 監視プロセス独立性の実証（make supervisor-independence。TASK-162・SUP-5。実証・判定は #499 で人間が実機実行する）。
#
# N（既定 50）個の監視プロセスのうち 1 個を SIGKILL して残りの継続と孤児の稼働継続を確認する実機前提ターゲット
# （make ci には含めない。スクリプト内で sudo は呼ばない。launcher 契約は scripts/verify-supervisor-independence.sh 冒頭を参照）。
# スクリプトの終了コード 0〜4 はそのまま返し、timeout 超過（124・137）と想定外の値は 1、起動不能（125〜127）は 2。
# 入力は環境変数: LAUNCHER・BUNDLE（必須）、COUNT・TARGET_INDEX・OUTPUT（任意）、SUPERVISOR_INDEPENDENCE_TIMEOUT（既定 600）。
# SUPERVISOR_INDEPENDENCE_SCRIPT は差し替え口。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${LAUNCHER:-}" ] || [ -z "${BUNDLE:-}" ]; then
  echo "usage: make supervisor-independence LAUNCHER=<abs-path> BUNDLE=<dir> [COUNT=<n, default 50>] [TARGET_INDEX=<k, default count/2 rounded up>] [OUTPUT=<new file>] [SUPERVISOR_INDEPENDENCE_TIMEOUT=<secs, default 600>]" >&2
  exit 2
fi
t="${SUPERVISOR_INDEPENDENCE_TIMEOUT:-600}"
script="${SUPERVISOR_INDEPENDENCE_SCRIPT:-scripts/verify-supervisor-independence.sh}"
validate_timeout SUPERVISOR_INDEPENDENCE_TIMEOUT "${t}"
require_timeout_cmd
args=(--launcher "${LAUNCHER}" --bundle "${BUNDLE}")
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${TARGET_INDEX:-}" ]; then args+=(--target-index "${TARGET_INDEX}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
rc=0
timeout --kill-after=60 "${t}" bash "${script}" "${args[@]}" || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3 | 4) exit "${rc}" ;;
  124 | 137) echo "error: timeout: verification or cleanup stalled for ${t}s" >&2; exit 1 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the verification under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: verification-failed: unexpected exit status ${rc}" >&2; exit 1 ;;
esac
