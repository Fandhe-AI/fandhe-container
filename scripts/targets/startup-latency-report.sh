#!/usr/bin/env bash
# own と Docker の起動時間の結果を 1 つのレポートに統合する（make startup-latency-report。TASK-46.2）。
#
# 入力は環境変数: OWN_RESULT・DOCKER_RESULT（必須。それぞれ oci-mode / docker-mode の result.json）、OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${OWN_RESULT:-}" ] || [ -z "${DOCKER_RESULT:-}" ]; then
  echo "usage: make startup-latency-report OWN_RESULT=<oci-mode result.json> DOCKER_RESULT=<docker-mode result.json> [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--mode report --own-result "${OWN_RESULT}" --docker-result "${DOCKER_RESULT}")
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/startup_latency.sh "${args[@]}"
