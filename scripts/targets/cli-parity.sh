#!/usr/bin/env bash
# CLI 3 OS 比較の capture / compare（make cli-parity。TASK-125.1・CLI-1・MS-6）。
#
# 実機での記録・突き合わせ（実機前提・make ci 対象外。判定は #661〔TASK-125.h1〕で人間が行う）。
# CLI/OUTPUT を指定すると capture、BASELINE/CANDIDATE を指定すると compare を実行する（環境変数で受け取る）。
# 値の検証は scripts/cli-parity-check.sh が担う。TIMEOUT（任意。1〜600 秒）を指定すると capture の 1 呼び出しあたりの
# 期限になる（既定 20 秒。start の結果の受信期限は 58.9 秒のため、start を通す環境では 90 を勧める。#2891）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -n "${CLI:-}" ] && [ -n "${OUTPUT:-}" ]; then
  if [ -n "${TIMEOUT:-}" ]; then
    bash scripts/cli-parity-check.sh capture --cli "${CLI}" --output "${OUTPUT}" --timeout "${TIMEOUT}"
  else
    bash scripts/cli-parity-check.sh capture --cli "${CLI}" --output "${OUTPUT}"
  fi
elif [ -n "${BASELINE:-}" ] && [ -n "${CANDIDATE:-}" ]; then
  bash scripts/cli-parity-check.sh compare --baseline "${BASELINE}" --candidate "${CANDIDATE}"
else
  echo "usage: make cli-parity CLI=<abs-path> OUTPUT=<new-file>  |  make cli-parity BASELINE=<capture> CANDIDATE=<capture>" >&2
  exit 2
fi
