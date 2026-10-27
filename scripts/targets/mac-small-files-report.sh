#!/usr/bin/env bash
# 自前側と Docker Desktop 側の小ファイル多数ワークロードの結果を 1 つのレポートに統合する
# （make mac-small-files-report。TASK-70 準備・#1880・MAC-3）。短縮率・低減率を出すだけで合否は出さない。
#
# 入力は環境変数: OWN_RESULT・BASELINE_RESULT（必須。それぞれ target=own / target=docker の結果 JSON）、OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${OWN_RESULT:-}" ] || [ -z "${BASELINE_RESULT:-}" ]; then
  echo "usage: make mac-small-files-report OWN_RESULT=<target=own result.json> BASELINE_RESULT=<target=docker result.json> [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--mode report --own-result "${OWN_RESULT}" --baseline-result "${BASELINE_RESULT}")
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/mac_small_files.sh "${args[@]}"
