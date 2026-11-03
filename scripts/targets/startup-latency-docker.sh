#!/usr/bin/env bash
# Docker の起動時間の計測（make startup-latency-docker。TASK-46.2）。
#
# startup_latency.sh の `--mode docker` で `docker run --rm ... --entrypoint true <image>` の全体時間を計測する
# （Docker は実機前提・イメージは事前に手動 pull）。own と Docker の計測区間は異なり（method / methods_differ に明示）、
# 合否判定は #213（TASK-46.h1）で人間が行う。
# 入力は環境変数: DOCKER（必須）、TARGET（既定 docker）、ITERATIONS（既定 10）、LABEL（既定 TARGET）、IMAGE・WARMUP・TIMEOUT・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${DOCKER:-}" ]; then
  echo "usage: make startup-latency-docker DOCKER=<abs-path of docker CLI> [TARGET=<name, default docker>] [IMAGE=<ref, default alpine:3.20 (pull it first)>] [ITERATIONS=<n>] [WARMUP=<n>] [TIMEOUT=<1-120 secs>] [LABEL=<label>] [OUTPUT=<new file>]" >&2
  exit 2
fi
target="${TARGET:-docker}"
args=(--mode docker --runtime "${DOCKER}" --target "${target}" --iterations "${ITERATIONS:-10}" --label "${LABEL:-${target}}")
if [ -n "${IMAGE:-}" ]; then args+=(--image "${IMAGE}"); fi
if [ -n "${WARMUP:-}" ]; then args+=(--warmup "${WARMUP}"); fi
if [ -n "${TIMEOUT:-}" ]; then args+=(--timeout "${TIMEOUT}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/startup_latency.sh "${args[@]}"
