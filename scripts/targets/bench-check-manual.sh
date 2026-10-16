#!/usr/bin/env bash
# 実機前提ベンチ（起動レイテンシ p95。lib.sh の BENCH_MANUAL_NAMES）の結果を基準値と比べる
# （make bench-check-manual。#1901・TASK-190 追補・REPAIR-8）。
#
# 役割: 起動 p95 は Linux 6.12 以上・非 root・非特権 user namespace・systemd-run --user を要し、GitHub ホステッド
# runner では動かないため CI の bench-regression では測らない（BENCH_NAMES 外）。人が実機で
#   cargo bench -p fandhe-container-benches --bench startup_latency -- <引数> --output <絶対パス>
# を実行して得た結果ファイルを、本スクリプトが実機前提の基準値（benches/baseline-manual.json）と比べる。
# CI では回帰を検出できない（REPAIR-8 の「CI で 15% 超の悪化を fail」は未充足。docs/design/bench-calibration.md）。
# ベンチ自体は実行せず、ファイルを比べるだけなので OS に依らない。sudo は呼ばない。リポジトリ内のファイルは書き換えない。
#
# 入力（環境変数）:
#   BENCH_RESULTS          必須。結果ファイルの絶対パス（通常ファイル・symlink 不可・1 MiB 以下）
#   BENCH_MANUAL_BASELINE  任意。基準値（既定 benches/baseline-manual.json。実測の確定は TASK-88.h1・#230）
#   BENCH_METRICS          任意。metrics の SSOT（既定 benches/metrics.json）
#
# 終了コード: 0 合格（基準値が無い間は skip: を出して 0。結果の検査は行う）/ 1 回帰を検出 / 2 入力エラー。
# 失敗した実行（metrics が空・failures.total > 0・leftover_ids 有り）は基準値の有無に関わらず 2（fail-closed）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

readonly MAX_FILE_BYTES=1048576
err() { echo "error: invalid-input: $1" >&2; }

BENCH_RESULTS="${BENCH_RESULTS:-}"
BENCH_MANUAL_BASELINE="${BENCH_MANUAL_BASELINE:-benches/baseline-manual.json}"
BENCH_METRICS="${BENCH_METRICS:-benches/metrics.json}"

if [ -z "${BENCH_RESULTS}" ]; then
  echo "usage: make bench-check-manual BENCH_RESULTS=<absolute path of the startup_latency results json>" >&2
  exit 2
fi
case "${BENCH_RESULTS}" in
  /*) ;;
  *)
    err "BENCH_RESULTS must be an absolute path"
    exit 2
    ;;
esac
if ! command -v jq >/dev/null 2>&1; then
  err "jq is required"
  exit 2
fi

# 入力ファイルの検査（assemble_results.sh と同じ規則: symlink 拒否・通常ファイル・1 MiB 上限）。
check_input_file() {
  local path="$1" size
  if [ -L "${path}" ]; then
    err "${path} is a symlink, refusing to read"
    exit 2
  fi
  if [ ! -f "${path}" ]; then
    err "${path} is not an existing regular file"
    exit 2
  fi
  if ! size=$(wc -c <"${path}" 2>/dev/null | tr -d ' '); then
    err "${path} could not be read"
    exit 2
  fi
  if [ "${size}" -gt "${MAX_FILE_BYTES}" ]; then
    err "${path} exceeds ${MAX_FILE_BYTES} bytes"
    exit 2
  fi
}

check_input_file "${BENCH_RESULTS}"
check_input_file "${BENCH_METRICS}"
manual_json="$(bench_manual_metrics_jq)"

# 結果そのものの検査（基準値の有無に関わらず行う）: 実機前提 metric だけを持ち、失敗・後始末の残りが無いこと。
if ! jq -e --argjson m "${manual_json}" \
  '.schema_version == 1
   and ((.metrics | type) == "object")
   and ((.metrics | keys | sort) == ($m | sort))
   and (((.failures.total // 0) | . == 0))
   and (((.leftover_ids // []) | length) == 0)' "${BENCH_RESULTS}" >/dev/null 2>&1; then
  err "results must have schema_version 1, exactly the manual-bench metrics ${manual_json}, no failures and no leftover ids (a failed run emits empty metrics)"
  exit 2
fi

# 各 metric の値と単位の検査（基準値の有無に関わらず行う）: value は有限の正の数（文字列・0・負数・欠落は不可）、
# unit は metrics.json に登録された単位（ms）と一致すること。metric 名だけの検査では {} も通ってしまうため。
if ! jq -e --slurpfile reg "${BENCH_METRICS}" \
  '(.metrics | to_entries | length > 0)
   and (.metrics | to_entries | all(
     (.value | type) == "object"
     and ((.value.value | type) == "number")
     and (.value.value > 0 and .value.value < 1.7976931348623157e308)
     and ((.value.unit | type) == "string")
     and (.value.unit == ($reg[0].metrics[.key].unit // null))
   ))' "${BENCH_RESULTS}" >/dev/null 2>&1; then
  err "every metric in results must have a finite positive numeric value and a unit equal to the registered one in ${BENCH_METRICS}"
  exit 2
fi

if [ ! -e "${BENCH_MANUAL_BASELINE}" ] && [ ! -L "${BENCH_MANUAL_BASELINE}" ]; then
  echo "skip: bench-check-manual: ${BENCH_MANUAL_BASELINE} is not registered yet (TASK-88.h1 #230); results validated but not compared"
  exit 0
fi
check_input_file "${BENCH_MANUAL_BASELINE}"

# 基準値は実機前提 metric だけを持つこと（CI 向け metric の混入は共有 baseline.json との取り違え）。
if ! jq -e --argjson m "${manual_json}" \
  '((.metrics | type) == "object") and ((.metrics | keys) - $m | length == 0)' \
  "${BENCH_MANUAL_BASELINE}" >/dev/null 2>&1; then
  err "${BENCH_MANUAL_BASELINE} must contain only the manual-bench metrics ${manual_json}"
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
bash "${DIR}/../bench/assemble_results.sh" --baseline "${BENCH_MANUAL_BASELINE}" --metrics "${BENCH_METRICS}" \
  --staged "" --output "${tmp}/results.json" "${BENCH_RESULTS}"
rc=0
bash "${DIR}/../check-bench-regression.sh" "${BENCH_MANUAL_BASELINE}" "${tmp}/results.json" || rc=$?
exit "${rc}"
