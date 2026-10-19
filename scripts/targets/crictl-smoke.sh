#!/usr/bin/env bash
# crictl による CRI 疎通確認（make crictl-smoke。TASK-60・CRI-1・MS-4。実機での実行と判定は #442 で人間が行う）。
#
# 実機前提ターゲット（make ci・CI には含めない。スクリプト内で sudo は呼ばない。契約は scripts/cri/crictl-smoke.sh 冒頭を参照）。
# 入力は環境変数: CRI_ENDPOINT（必須。unix:///<絶対パス>）、CRICTL・POD_CONFIG・CONTAINER_CONFIG・LOG_DIR・STEP_TIMEOUT・
# CRICTL_TIMEOUT・KEEP=1・CRICTL_SMOKE_TIMEOUT（全体期限の秒。未指定ならスクリプトの --print-budget の値）は任意。
# CRICTL_SMOKE_SCRIPT は差し替え口（自己テスト用）。
# スクリプトの終了コード 0〜4 はそのまま返す。期限切れ・中断（129・130・143）と想定外の値は 1、後始末の完了前に
# SIGKILL された場合（137）は残存を否定できないため 4、起動不能（125〜127）は 2（restart-latency と同じ流儀。REPAIR-5）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${CRI_ENDPOINT:-}" ]; then
  echo "usage: make crictl-smoke CRI_ENDPOINT=unix:///<abs-path> [CRICTL=<abs-path>] [POD_CONFIG=<file>] [CONTAINER_CONFIG=<file>] [LOG_DIR=<new dir>] [STEP_TIMEOUT=<secs, default 60>] [CRICTL_TIMEOUT=<e.g. 10s>] [KEEP=1] [CRICTL_SMOKE_TIMEOUT=<secs for the whole run>]" >&2
  exit 2
fi
require_timeout_cmd
script="${CRICTL_SMOKE_SCRIPT:-scripts/cri/crictl-smoke.sh}"
args=()
if [ -n "${STEP_TIMEOUT:-}" ]; then args+=(--step-timeout "${STEP_TIMEOUT}"); fi
budget="$(bash "${script}" --print-budget ${args[@]+"${args[@]}"})" || exit 2
case "${budget}" in '' | *[!0-9]* | ???????*)
  echo "error: invalid-input: cannot compute the time budget" >&2
  exit 2
  ;;
esac
t="${CRICTL_SMOKE_TIMEOUT:-}"
if [ -z "${t}" ]; then t="${budget}"; fi
validate_timeout CRICTL_SMOKE_TIMEOUT "${t}"
if [ "${t}" -lt "${budget}" ]; then
  echo "warning: CRICTL_SMOKE_TIMEOUT=${t}s is shorter than the worst-case duration ${budget}s; a slow but valid run may be cut off" >&2
fi
# 利用者の相対パスは cwd 基準で解釈させるため、lib.sh の cd 前の値は使えない。絶対パスでの指定を求める。
if [ -n "${CRICTL:-}" ]; then args+=(--crictl "${CRICTL}"); fi
if [ -n "${POD_CONFIG:-}" ]; then args+=(--pod-config "${POD_CONFIG}"); fi
if [ -n "${CONTAINER_CONFIG:-}" ]; then args+=(--container-config "${CONTAINER_CONFIG}"); fi
if [ -n "${LOG_DIR:-}" ]; then args+=(--log-dir "${LOG_DIR}"); fi
if [ -n "${CRICTL_TIMEOUT:-}" ]; then args+=(--crictl-timeout "${CRICTL_TIMEOUT}"); fi
if [ "${KEEP:-}" = 1 ]; then args+=(--keep); fi
rc=0
timeout --preserve-status --kill-after=60 "${t}" bash "${script}" --endpoint "${CRI_ENDPOINT}" ${args[@]+"${args[@]}"} || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3 | 4) exit "${rc}" ;;
  129 | 130 | 143) echo "error: timeout: the smoke test was stopped by a signal (time limit ${t}s or an interrupt); the sandbox or container may remain, inspect it manually" >&2; exit 1 ;;
  137) echo "error: cleanup-failed: the smoke test was killed before cleanup finished; the sandbox or container may remain, inspect it manually" >&2; exit 4 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the smoke test under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: smoke-failed: unexpected exit status ${rc}" >&2; exit 1 ;;
esac
