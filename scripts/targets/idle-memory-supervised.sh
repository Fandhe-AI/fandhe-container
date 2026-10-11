#!/usr/bin/env bash
# 監視プロセス込みのアイドル常駐メモリ回帰テスト（make idle-memory-supervised。TASK-47・CORE-7・Linux・実機前提）。
#
# 実機前提（root 権限の操作者が driver を渡して明示実行する。実 driver は製品バイナリ未提供のため現状なし。make ci には
# 含めない。ci.md「実機前提テスト」）。全体に timeout を掛け（REPAIR-5）、終了コードの変換規則は idle-memory と同じ。
# 入力は環境変数: DRIVER（必須。絶対パス）、EXPECTED_DIR・OUTPUT（任意）、IDLE_MEMORY_SUPERVISED_TIMEOUT（全体の秒数。
# 1〜999999・既定 900）、IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT（driver・各計測 1 回あたりの秒数。未指定ならスクリプト既定）。
# 外側 timeout の TERM 後、スクリプトは TERM trap で実行中の driver を待ち（最大 call timeout + 10 秒）、続く EXIT trap で
# driver down を実行する（最大 call timeout + 10 秒）。両段階が完走できるよう、--kill-after は余裕 10 秒を含む
# 2 * call timeout + 30 秒（未指定・不正値は既定 120 秒 → 270 秒）を確保する（後始末の時間予算。AGENTS.md「特権操作の後始末」）。
# IDLE_MEMORY_SUPERVISED_SCRIPT は selftest が配線を stub で照合するための差し替え口。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

t="${IDLE_MEMORY_SUPERVISED_TIMEOUT:-900}"
script="${IDLE_MEMORY_SUPERVISED_SCRIPT:-scripts/bench/idle_memory_supervised.sh}"
validate_timeout IDLE_MEMORY_SUPERVISED_TIMEOUT "${t}"
if [ -z "${DRIVER:-}" ]; then
  echo "error: invalid-argument: DRIVER=<absolute-path> is required (an executable taking 'up' / 'down'; see scripts/bench/idle_memory_supervised.sh)" >&2
  exit 2
fi
require_timeout_cmd
args=(--driver "${DRIVER}")
if [ -n "${EXPECTED_DIR:-}" ]; then args+=(--expected-dir "${EXPECTED_DIR}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
if [ -n "${IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT:-}" ]; then args+=(--timeout "${IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT}"); fi
c="${IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT:-}"
case "${c}" in '' | *[!0-9]* | ???????* | 0) c=120 ;; esac
k=$((2 * c + 30))
rc=0
timeout --kill-after="${k}" "${t}" bash "${script}" "${args[@]}" || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3) exit "${rc}" ;;
  124 | 137) echo "error: measurement-failed: timed out after ${t}s" >&2; exit 3 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the measurement under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: measurement-failed: unexpected exit status ${rc}" >&2; exit 3 ;;
esac
