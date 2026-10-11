#!/usr/bin/env bash
# fio ベースライン比の算出（make fio-baseline-ratio。TASK-25.2・IO-8・MS-1 Phase 2）。
#
# scripts/fio-baseline-ratio.sh は fio-randwrite-4k.sh の results.json を 2 つ（baseline / candidate）受け取り、
# IOPS・レイテンシの倍率を出す（fio 自体は実行しない。jq のみで完結するため実機前提テストへは分離しない）。
# 入力は環境変数: BASELINE・CANDIDATE（results.json のパス。必須）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${BASELINE:-}" ] || [ -z "${CANDIDATE:-}" ]; then
  echo "usage: make fio-baseline-ratio BASELINE=<results.json> CANDIDATE=<results.json>" >&2
  exit 2
fi
run bash scripts/fio-baseline-ratio.sh --baseline "${BASELINE}" --candidate "${CANDIDATE}"
