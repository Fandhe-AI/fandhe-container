#!/usr/bin/env bash
# DNS ヘルパーの正答率・レイテンシ・常駐 PSS 計測（make dns-helper-measure。TASK-141.3・NET-5。
# Linux・root・cgroup v2・実機前提）。
#
# scripts/bench/dns_helper_measure.sh は dns_helper_privileged の `--measure` を実行し、正答率・p50/p99（単位 us）・
# 専用 cgroup の cgroup.procs から取った PID の PSS/RSS（単位 kB）を JSON で出す。計測対象はテストバイナリが組み立てた
# DnsHelperServer + RegistryHandler で、製品の入口 run_dns_helper_main ではない（REPAIR-3）。sudo も cargo も呼ばないため、
# `cargo test -p fandhe-container-net --test dns_helper_privileged --no-run` で得た実行ファイルを
# `sudo make dns-helper-measure EXE=<絶対パス>` で渡す（root 実行は人間の明示操作。実測・比較・判定は TASK-142）。
# 実機前提のため `make ci` には含めない。入力は環境変数: EXE（必須）、QUERIES・WARMUP・TIMEOUT・LABEL・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${EXE:-}" ]; then
  echo "usage: sudo make dns-helper-measure EXE=<abs-path of dns_helper_privileged built by cargo test --no-run> [QUERIES=<n>] [WARMUP=<n>] [TIMEOUT=<secs>] [LABEL=<label>] [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--exe "${EXE}")
if [ -n "${QUERIES:-}" ]; then args+=(--queries "${QUERIES}"); fi
if [ -n "${WARMUP:-}" ]; then args+=(--warmup "${WARMUP}"); fi
if [ -n "${TIMEOUT:-}" ]; then args+=(--timeout "${TIMEOUT}"); fi
if [ -n "${LABEL:-}" ]; then args+=(--label "${LABEL}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/dns_helper_measure.sh "${args[@]}"
