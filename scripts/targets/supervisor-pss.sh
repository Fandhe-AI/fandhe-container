#!/usr/bin/env bash
# 監視プロセスの PSS 計測（make supervisor-pss。TASK-158・SUP-2。Linux 限定。bash のみで完結）。
#
# 実測は製品バイナリ（fandhe-container-supervisor）提供後に人間が #485（TASK-158.h1）で行う。`make ci` には含めない（実機前提）。
# PID=<pid ...>（空白区切りで複数可）または COUNT=<N> のどちらか必須。起動は操作者が事前に行う（スクリプトは起動しない・sudo を呼ばない）。
# 任意: SAMPLES・INTERVAL・EXE_NAME・EXPECTED_DIR・OUTPUT。/proc の読み取りがハングし得るため timeout で包む（REPAIR-5）。
# 秒数は SUPERVISOR_PSS_TIMEOUT（1〜999999・既定 300）。スクリプトの終了コード 0〜3 はそのまま返し、timeout 超過（124・137）と
# 想定外の値は 3、起動不能（125〜127）は 2。SUPERVISOR_PSS_SCRIPT は selftest が配線を stub で照合するための差し替え口。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

t="${SUPERVISOR_PSS_TIMEOUT:-300}"
script="${SUPERVISOR_PSS_SCRIPT:-scripts/bench/supervisor_pss.sh}"
validate_timeout SUPERVISOR_PSS_TIMEOUT "${t}"
if [ -z "${PID:-}" ] && [ -z "${COUNT:-}" ]; then
  echo 'error: invalid-argument: PID="<pid> ..." or COUNT=<N> is required (see scripts/bench/supervisor_pss.sh --help)' >&2
  exit 2
fi
require_timeout_cmd
args=()
for p in ${PID:-}; do args+=(--pid "${p}"); done
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${SAMPLES:-}" ]; then args+=(--samples "${SAMPLES}"); fi
if [ -n "${INTERVAL:-}" ]; then args+=(--interval "${INTERVAL}"); fi
if [ -n "${EXE_NAME:-}" ]; then args+=(--exe-name "${EXE_NAME}"); fi
if [ -n "${EXPECTED_DIR:-}" ]; then args+=(--expected-dir "${EXPECTED_DIR}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
rc=0
timeout --kill-after=10 "${t}" bash "${script}" --format json ${args[@]+"${args[@]}"} || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3) exit "${rc}" ;;
  124 | 137) echo "error: measurement-failed: timed out after ${t}s reading /proc" >&2; exit 3 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the measurement under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: measurement-failed: unexpected exit status ${rc}" >&2; exit 3 ;;
esac
