#!/usr/bin/env bash
# bind / named volume の 2 構成で small_files ハーネスを回す（make small-files-compare。TASK-24.1・IO-7。実機前提）。
#
# scripts/bench/small_files_compare.sh へ make 変数を渡す薄い入口。HARNESS 未指定のときは
# `cargo bench --no-run` でハーネスをビルドして実行ファイルを特定する（ビルド時間を計測の期限に混ぜない）。
# 実ファイルを多数書くため `make ci` と CI には含めない。sudo は呼ばない。実測は #107（人間）、評価は #110（TASK-24.2）。
# 入力は環境変数: BIND_ROOT・VOLUME_ROOT（必須）、HARNESS・COUNT・TRIALS・BATCH_SIZE・FILE_SIZE・LAYOUT・
# TRIAL_TIMEOUT_SECS・TIMEOUT_SECS・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${BIND_ROOT:-}" ] || [ -z "${VOLUME_ROOT:-}" ]; then
  echo "usage: make small-files-compare BIND_ROOT=<abs dir> VOLUME_ROOT=<abs dir> [HARNESS=<abs path of the small_files bench executable>] [COUNT=<n>] [TRIALS=<n>] [BATCH_SIZE=<n>] [FILE_SIZE=<n>] [LAYOUT=auto|flat|tree] [TRIAL_TIMEOUT_SECS=<n>] [TIMEOUT_SECS=<n>] [OUTPUT=<new abs file>]" >&2
  exit 2
fi

harness="${HARNESS:-}"
if [ -z "${harness}" ]; then
  skip_unless_workspace small-files-compare
  require_cmd jq
  RUN_LIMITED_DIR="$(mktemp -d)"
  trap 'run_limited_abort; rm -rf "${RUN_LIMITED_DIR}"' EXIT
  build_out="${RUN_LIMITED_DIR}/build.jsonl"
  run_limited 1800 cargo bench --no-run --message-format=json -p fandhe-container-benches --bench small_files >"${build_out}"
  exes="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "small_files" and .executable != null) | .executable' "${build_out}")"
  if [ -z "${exes}" ] || [ "$(printf '%s\n' "${exes}" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "error: could not identify exactly one small_files bench executable" >&2
    exit 1
  fi
  harness="${exes}"
fi

args=(--harness "${harness}" --bind-root "${BIND_ROOT}" --volume-root "${VOLUME_ROOT}")
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${BATCH_SIZE:-}" ]; then args+=(--batch-size "${BATCH_SIZE}"); fi
if [ -n "${FILE_SIZE:-}" ]; then args+=(--file-size "${FILE_SIZE}"); fi
if [ -n "${LAYOUT:-}" ]; then args+=(--layout "${LAYOUT}"); fi
if [ -n "${TRIAL_TIMEOUT_SECS:-}" ]; then args+=(--trial-timeout-secs "${TRIAL_TIMEOUT_SECS}"); fi
if [ -n "${TIMEOUT_SECS:-}" ]; then args+=(--timeout-secs "${TIMEOUT_SECS}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/small_files_compare.sh "${args[@]}"
