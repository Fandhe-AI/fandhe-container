#!/usr/bin/env bash
# 50 コンテナ同時起動の集約 PSS 計測（make concurrent-memory。TASK-50.1・CORE-9・SUP-1。Linux 限定・実機前提・timeout 付き）。
#
# 実測は own の CLI・本番 launcher 提供後に人間が #219（TASK-50.h1）で行う。`make ci` には含めない（実機前提）。
# timeout・終了コードの変換は concurrent-memory-docker.sh と同じ（0〜4 はそのまま、timeout 超過と想定外は 1、起動不能は 2）。
# 入力は環境変数: LAUNCHER・BUNDLE・TARGET（必須）、COUNT・TRIALS・OUTPUT（任意）、CONCURRENT_MEMORY_TIMEOUT（既定 1800）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${LAUNCHER:-}" ] || [ -z "${BUNDLE:-}" ] || [ -z "${TARGET:-}" ]; then
  echo "usage: make concurrent-memory LAUNCHER=<abs-path> BUNDLE=<dir> TARGET=<name, e.g. own> [COUNT=<n, default 50>] [TRIALS=<n, default 3>] [OUTPUT=<new file>] [CONCURRENT_MEMORY_TIMEOUT=<secs, default 1800>]" >&2
  exit 2
fi
t="${CONCURRENT_MEMORY_TIMEOUT:-1800}"
script="${CONCURRENT_MEMORY_SCRIPT:-scripts/bench/concurrent_50_memory.sh}"
validate_timeout CONCURRENT_MEMORY_TIMEOUT "${t}"
require_timeout_cmd
args=(--launcher "${LAUNCHER}" --bundle "${BUNDLE}" --target "${TARGET}")
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
rc=0
timeout --kill-after=60 "${t}" bash "${script}" "${args[@]}" || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3 | 4) exit "${rc}" ;;
  124 | 137) echo "error: measurement-failed: timed out after ${t}s (measurement or cleanup stalled)" >&2; exit 1 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the measurement under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: measurement-failed: unexpected exit status ${rc}" >&2; exit 1 ;;
esac
