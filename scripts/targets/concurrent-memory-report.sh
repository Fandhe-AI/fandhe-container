#!/usr/bin/env bash
# own と Docker の 50 コンテナ集約メモリの結果を 1 つのレポートに統合する（make concurrent-memory-report。TASK-50.2）。
#
# 合否は出さない。入力は環境変数: OWN_RESULT・DOCKER_RESULT（必須）、OUTPUT（任意）。jq 未導入は fail-closed。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${OWN_RESULT:-}" ] || [ -z "${DOCKER_RESULT:-}" ]; then
  echo "usage: make concurrent-memory-report OWN_RESULT=<own-mode result.json> DOCKER_RESULT=<docker-mode result.json> [OUTPUT=<new file>]" >&2
  exit 2
fi
require_cmd jq
script="${CONCURRENT_MEMORY_SCRIPT:-scripts/bench/concurrent_50_memory.sh}"
args=(--mode report --own-result "${OWN_RESULT}" --docker-result "${DOCKER_RESULT}")
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash "${script}" "${args[@]}"
