#!/usr/bin/env bash
# restart レイテンシの実機実測（make restart-latency。TASK-160・SUP-3。実測・合否判定は #491 で人間が行う）。
#
# コンテナを繰り返し SIGKILL して再起動レイテンシの中央値・p95（supervisor の既定バックオフ 100ms を差し引いた値も）を JSON 出力する実機前提ターゲット
# （make ci には含めない。合否は出さない。スクリプト内で sudo は呼ばない。契約は scripts/measure-restart-latency.sh 冒頭を参照）。
# 全体期限 RESTART_LATENCY_TIMEOUT（秒・1〜999999）は未指定ならスクリプトの --print-budget の値を使う
# （(試行数 + 2) × 各待機の上限 ＋ 試行ごとの余裕 ＋ 後始末 60 秒。既定の 20 試行・warmup 1・待機 30 秒で 843 秒）。
# 固定値にしないのは、TRIALS・WARMUP・RESTART_LATENCY_WAIT_TIMEOUT を変えたときに正常な計測を途中で打ち切らないため（REPAIR-5）。
# 明示した値が上限より短い場合は警告を出してそのまま使う。
# timeout は --preserve-status で使い、スクリプトの終了コードを保つ（期限切れの TERM でも後始末失敗の 4 を隠さない）。
# スクリプトの終了コード 0〜4 はそのまま返す。期限切れ・中断（後始末は完了。129・130・143）と想定外の値は 1、後始末の完了前に
# SIGKILL された場合（137。--kill-after 60 秒の超過を含む）は残存を否定できないため 4、起動不能（125〜127）は 2。
# 入力は環境変数: BIN_DIR（fandhe-container と fandhe-container-supervisor を置いたディレクトリの絶対パス）・BUNDLE（必須）、SYSTEMD_RUN・STATE_ROOT・TRIALS・WARMUP・OUTPUT・RESTART_LATENCY_WAIT_TIMEOUT・RESTART_LATENCY_TIMEOUT（任意）。
# RESTART_LATENCY_SCRIPT は差し替え口。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -n "${LAUNCHER:-}" ]; then
  echo "error: invalid-argument: LAUNCHER was replaced by BIN_DIR (the directory holding fandhe-container and fandhe-container-supervisor)" >&2
  exit 2
fi
if [ -z "${BIN_DIR:-}" ] || [ -z "${BUNDLE:-}" ]; then
  echo "usage: make restart-latency BIN_DIR=<abs-path> BUNDLE=<dir> [SYSTEMD_RUN=<abs-path, default /usr/bin/systemd-run>] [TRIALS=<n, default 20>] [WARMUP=<n, default 1>] [OUTPUT=<new file>] [RESTART_LATENCY_WAIT_TIMEOUT=<secs per wait, default 30>] [RESTART_LATENCY_TIMEOUT=<secs for the whole run, default: computed from the above>]" >&2
  exit 2
fi
require_timeout_cmd
script="${RESTART_LATENCY_SCRIPT:-scripts/measure-restart-latency.sh}"
args=()
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${WARMUP:-}" ]; then args+=(--warmup "${WARMUP}"); fi
if [ -n "${RESTART_LATENCY_WAIT_TIMEOUT:-}" ]; then args+=(--timeout "${RESTART_LATENCY_WAIT_TIMEOUT}"); fi
budget="$(bash "${script}" --print-budget ${args[@]+"${args[@]}"})" || exit 2
case "${budget}" in '' | *[!0-9]* | ???????*)
  echo "error: invalid-input: cannot compute the time budget" >&2
  exit 2
  ;;
esac
t="${RESTART_LATENCY_TIMEOUT:-}"
if [ -z "${t}" ]; then t="${budget}"; fi
validate_timeout RESTART_LATENCY_TIMEOUT "${t}"
if [ "${t}" -lt "${budget}" ]; then
  echo "warning: RESTART_LATENCY_TIMEOUT=${t}s is shorter than the worst-case duration ${budget}s; a slow but valid run may be cut off" >&2
fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
if [ -n "${SYSTEMD_RUN:-}" ]; then args+=(--systemd-run "${SYSTEMD_RUN}"); fi
rc=0
timeout --preserve-status --kill-after=60 "${t}" bash "${script}" --bin-dir "${BIN_DIR}" --bundle "${BUNDLE}" ${args[@]+"${args[@]}"} || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3 | 4) exit "${rc}" ;;
  129 | 130 | 143) echo "error: timeout: the measurement was stopped by a signal (time limit ${t}s or an interrupt); cleanup completed and no result is published" >&2; exit 1 ;;
  137) echo "error: cleanup-failed: the measurement was killed before cleanup finished; processes may remain, inspect and kill them manually" >&2; exit 4 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the measurement under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: measurement-failed: unexpected exit status ${rc}" >&2; exit 1 ;;
esac
