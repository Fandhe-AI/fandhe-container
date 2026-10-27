#!/usr/bin/env bash
# net-throughput-rtt の 2 つの結果から Docker 比（%）と p50・p99 の倍率を出す（make net-throughput-rtt-compare。
# TASK-140 準備・#1882・NET-2・NET-3）。合否は出さない（暫定値）。root・docker は不要。
# 入力は環境変数: OWN_RESULT・DOCKER_RESULT（必須。TARGET=both の出力 1 つを両方に渡してもよい）、OUTPUT（任意・新規ファイルのみ）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${OWN_RESULT:-}" ] || [ -z "${DOCKER_RESULT:-}" ]; then
  echo "usage: make net-throughput-rtt-compare OWN_RESULT=<result json> DOCKER_RESULT=<result json> [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--mode compare --own-result "${OWN_RESULT}" --docker-result "${DOCKER_RESULT}")
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/net_throughput_rtt.sh "${args[@]}"
