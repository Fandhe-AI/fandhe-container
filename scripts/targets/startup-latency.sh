#!/usr/bin/env bash
# 起動時間の計測（make startup-latency。TASK-46.1・CORE-10・MS-2 Phase 3）。
#
# scripts/bench/startup_latency.sh は OCI Runtime CLI 契約のランタイムに対し create からプロセス実行開始
# （state が running / stopped を返した時点）までの時間の中央値を計測する。own 実装の実測は CLI の state / kill（#1903・#1902）に照合済み（#3123）で。
# 人間が #213（TASK-46.h1）で行う実機前提（ランタイム・bundle・場合により root）のため `make ci` には含めない。
# 入力は環境変数: RUNTIME・BUNDLE・TARGET（必須）、ITERATIONS（既定 10）、LABEL（既定 TARGET）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${RUNTIME:-}" ] || [ -z "${BUNDLE:-}" ] || [ -z "${TARGET:-}" ]; then
  echo "usage: make startup-latency RUNTIME=<abs-path> BUNDLE=<dir> TARGET=<name, e.g. own> [ITERATIONS=<n>] [LABEL=<label>]" >&2
  exit 2
fi
run bash scripts/bench/startup_latency.sh --runtime "${RUNTIME}" --bundle "${BUNDLE}" --target "${TARGET}" \
  --iterations "${ITERATIONS:-10}" --label "${LABEL:-${TARGET}}"
