#!/usr/bin/env bash
# 50 コンテナ同時起動の集約メモリ計測のうち Docker 側（make concurrent-memory-docker。TASK-50.2・CORE-9・SUP-1。
# Linux 限定・実機前提）。
#
# scripts/bench/concurrent_50_memory.sh の `--mode docker` で Docker 側を own と同一手法（PSS 合計の中央値。集計対象は
# デーモン＋各コンテナの shim ツリー）で測る（実 Docker・ローカルデーモン・イメージの事前 pull・他コンテナなし・権限付き
# シェルが前提）。計測全体を timeout で包む（REPAIR-5）。秒数は CONCURRENT_MEMORY_TIMEOUT（1〜999999・既定 1800）。
# スクリプトの終了コード 0〜4 はそのまま返し、timeout 超過（124・137）と想定外の値は 1、起動不能（125〜127）は 2。
# timeout の --kill-after は 60 秒固定（TERM 後に KILL するまでの猶予）。スクリプトの後始末（ln_stop）の最悪所要時間
# 〔launcher 終了待ち最大 10 秒＋強制終了後の確認 5 秒＋所有プロセス回収 5 秒＋ログ収集プロセスの終了待ち 2 秒＋/proc 走査〕より
# 十分長く取り、後始末の途中で KILL して起動プロセスを残さないようにする（REPAIR-5）。
# 入力は環境変数: DOCKER（必須）、TARGET（既定 docker）、IMAGE・COUNT・TRIALS・OUTPUT（任意）。
# CONCURRENT_MEMORY_SCRIPT は差し替え口（既定 scripts/bench/concurrent_50_memory.sh）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${DOCKER:-}" ]; then
  echo "usage: make concurrent-memory-docker DOCKER=<abs-path of docker CLI> [TARGET=<name, default docker>] [IMAGE=<ref, default alpine:3.20 (pull it first)>] [COUNT=<n, default 50>] [TRIALS=<n, default 3>] [OUTPUT=<new file>] [CONCURRENT_MEMORY_TIMEOUT=<secs, default 1800>]" >&2
  exit 2
fi
t="${CONCURRENT_MEMORY_TIMEOUT:-1800}"
script="${CONCURRENT_MEMORY_SCRIPT:-scripts/bench/concurrent_50_memory.sh}"
validate_timeout CONCURRENT_MEMORY_TIMEOUT "${t}"
require_timeout_cmd
args=(--mode docker --docker "${DOCKER}" --target "${TARGET:-docker}")
if [ -n "${IMAGE:-}" ]; then args+=(--image "${IMAGE}"); fi
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
rc=0
timeout --kill-after=60 "${t}" bash "${script}" "${args[@]}" || rc=$?
case "${rc}" in
  0 | 1 | 2 | 3 | 4) exit "${rc}" ;;
  124 | 137) echo "error: measurement-failed: timed out after ${t}s (measurement or cleanup stalled)" >&2; exit 1 ;;
  125 | 126 | 127) echo "error: invalid-input: cannot run the measurement under timeout (exit ${rc})" >&2; exit 2 ;;
  *) echo "error: measurement-failed: unexpected exit status ${rc}" >&2; exit 1 ;;
esac
