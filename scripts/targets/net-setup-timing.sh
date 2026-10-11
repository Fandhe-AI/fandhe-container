#!/usr/bin/env bash
# ネットワーク作成・接続・削除の所要時間計測（make net-setup-timing。TASK-139.5・NET-1・NET-4。Linux・root・実機前提）。
#
# scripts/bench/net_setup_timing.sh は network_paths_privileged の `--measure` を実行し、操作ごとの中央値等を単位 ms の
# JSON で出す。sudo も cargo も呼ばないため、`cargo test -p fandhe-container-net --test network_paths_privileged --no-run`
# で得た実行ファイルを `sudo make net-setup-timing EXE=<絶対パス>` で渡す（root 実行は人間の明示操作。実測・比較・判定は TASK-140）。
# 実機前提のため `make ci` には含めない。入力は環境変数: EXE（必須）、TRIALS・WARMUP・LABEL・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${EXE:-}" ]; then
  echo "usage: sudo make net-setup-timing EXE=<abs-path of network_paths_privileged built by cargo test --no-run> [TRIALS=<n>] [WARMUP=<n>] [LABEL=<label>] [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--exe "${EXE}")
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${WARMUP:-}" ]; then args+=(--warmup "${WARMUP}"); fi
if [ -n "${LABEL:-}" ]; then args+=(--label "${LABEL}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/net_setup_timing.sh "${args[@]}"
