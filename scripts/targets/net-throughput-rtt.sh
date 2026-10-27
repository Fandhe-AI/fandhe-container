#!/usr/bin/env bash
# iperf3 スループットと 1 バイト TCP 往復の計測（make net-throughput-rtt。TASK-140 準備・#1882・NET-2・NET-3。Linux・root・実機前提）。
#
# scripts/bench/net_throughput_rtt.sh を呼ぶ。sudo も cargo も呼ばないため、`cargo test -p fandhe-container-net --test
# network_paths_privileged --test tcp_rtt_probe --no-run` で得た実行ファイルを `sudo make net-throughput-rtt EXE=... PROBE=...`
# で渡す（root 実行は人間の明示操作）。TARGET=docker|both は docker がホストの bridge・nftables を変えるため、人間の承認後に実行する。
# 実機前提のため `make ci` には含めない。入力は環境変数: PROBE（必須）、EXE（TARGET=docker 以外で必須）、TARGET・IPERF3・NSENTER・
# DOCKER・HOST_ADDR・IMAGE・TRIALS・IPERF_SECS・RTT_ROUNDS・RTT_WARMUP・TIMEOUT・LABEL・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${PROBE:-}" ]; then
  echo "usage: sudo make net-throughput-rtt PROBE=<abs-path of tcp_rtt_probe> EXE=<abs-path of network_paths_privileged> [TARGET=own|docker|both] [DOCKER=<abs-path> HOST_ADDR=<non-loopback IPv4> [IMAGE=<image>]] [IPERF3=<abs>] [NSENTER=<abs>] [TRIALS=<n>] [IPERF_SECS=<n>] [RTT_ROUNDS=<n>] [RTT_WARMUP=<n>] [TIMEOUT=<secs>] [LABEL=<label>] [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--probe "${PROBE}")
if [ -n "${EXE:-}" ]; then args+=(--exe "${EXE}"); fi
if [ -n "${TARGET:-}" ]; then args+=(--target "${TARGET}"); fi
if [ -n "${IPERF3:-}" ]; then args+=(--iperf3 "${IPERF3}"); fi
if [ -n "${NSENTER:-}" ]; then args+=(--nsenter "${NSENTER}"); fi
if [ -n "${DOCKER:-}" ]; then args+=(--docker "${DOCKER}"); fi
if [ -n "${HOST_ADDR:-}" ]; then args+=(--host-addr "${HOST_ADDR}"); fi
if [ -n "${IMAGE:-}" ]; then args+=(--image "${IMAGE}"); fi
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${IPERF_SECS:-}" ]; then args+=(--iperf-secs "${IPERF_SECS}"); fi
if [ -n "${RTT_ROUNDS:-}" ]; then args+=(--rtt-rounds "${RTT_ROUNDS}"); fi
if [ -n "${RTT_WARMUP:-}" ]; then args+=(--rtt-warmup "${RTT_WARMUP}"); fi
if [ -n "${TIMEOUT:-}" ]; then args+=(--timeout "${TIMEOUT}"); fi
if [ -n "${LABEL:-}" ]; then args+=(--label "${LABEL}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
run bash scripts/bench/net_throughput_rtt.sh "${args[@]}"
