#!/usr/bin/env bash
# Docker Desktop 側の小ファイル多数ワークロードの計測（make mac-small-files-docker。TASK-70 準備・#1880・MAC-3）。
#
# mac_small_files.sh の `--mode docker` を呼ぶ。Docker Desktop は実機前提・イメージは事前に手動 pull。
# 合否判定は #381（TASK-70）で人間が行う。
# 入力は環境変数: DOCKER・HOST_DIR（必須）、IMAGE・COUNT・TRIALS・BATCH・LABEL・TRIAL_TIMEOUT_SECS・TIMEOUT_SECS・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${DOCKER:-}" ] || [ -z "${HOST_DIR:-}" ]; then
  echo "usage: make mac-small-files-docker DOCKER=<abs-path of docker CLI> HOST_DIR=<abs real path of the bind mount source dir> [IMAGE=<ref, default alpine:3.20 (pull it first)>] [COUNT=<n>] [TRIALS=<n>] [BATCH=<n>] [LABEL=<label>] [TRIAL_TIMEOUT_SECS=<n>] [TIMEOUT_SECS=<n>] [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--mode docker --runtime "${DOCKER}" --host-dir "${HOST_DIR}")
if [ -n "${IMAGE:-}" ]; then args+=(--image "${IMAGE}"); fi
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${BATCH:-}" ]; then args+=(--batch "${BATCH}"); fi
if [ -n "${LABEL:-}" ]; then args+=(--label "${LABEL}"); fi
if [ -n "${TRIAL_TIMEOUT_SECS:-}" ]; then args+=(--trial-timeout-secs "${TRIAL_TIMEOUT_SECS}"); fi
if [ -n "${TIMEOUT_SECS:-}" ]; then args+=(--timeout-secs "${TIMEOUT_SECS}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/mac_small_files.sh "${args[@]}"
