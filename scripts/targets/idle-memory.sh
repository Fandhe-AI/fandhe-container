#!/usr/bin/env bash
# アイドル時常駐メモリ（プロセス数・PSS・RSS）を JSON で出力する（make idle-memory。TASK-45.1・CORE-7。Linux 限定・timeout 付き）。
#
# /proc の読み取りがハングしたプロセスで止まり得るため timeout で包む（REPAIR-5）。秒数は IDLE_MEMORY_TIMEOUT
# （1〜999999 の整数。既定 120。0 は timeout 無効になるため拒否）で上書きできる。
# スクリプトの終了コード 0〜3 はそのまま返し、それ以外は契約の値へ変換する: timeout の超過（124）・強制終了（137）と
# シグナル等の想定外の値は計測失敗（3）、timeout 自体の失敗（125）・bash / スクリプトを起動できない（126・127）は 2。
# IDLE_MEMORY_SCRIPT（既定 scripts/bench/idle_memory.sh）は selftest が変換の配線を stub で照合するための差し替え口。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

t="${IDLE_MEMORY_TIMEOUT:-120}"
script="${IDLE_MEMORY_SCRIPT:-scripts/bench/idle_memory.sh}"
validate_timeout IDLE_MEMORY_TIMEOUT "${t}"
require_timeout_cmd
rc=0
timeout --kill-after=10 "${t}" bash "${script}" --format json || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3) exit "${rc}" ;;
  124 | 137) echo "error: measurement-failed: timed out after ${t}s reading /proc" >&2; exit 3 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the measurement under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: measurement-failed: unexpected exit status ${rc}" >&2; exit 3 ;;
esac
