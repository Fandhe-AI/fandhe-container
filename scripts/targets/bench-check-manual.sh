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
#   BENCH_HOST_KIND        基準値があるとき必須。実測したホストの種類（bare-metal / vm / wsl2。lib.sh の語彙）。
#                          結果の .arch と基準値の host.arch、または host.kind が食い違うと比較せず 2（#2095）
#
# 終了コード: 0 合格（基準値が無い間は skip: を出して 0。結果の検査は行う）/ 1 回帰を検出 / 2 入力エラー。
# 失敗した実行（metrics が空・failures.total > 0・leftover_ids 有り）は基準値の有無に関わらず 2（fail-closed）。
# 結果の arch が語彙外でも 2。基準値は make bench-baseline-manual で作る（host を持たない基準値は 2）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

err() { echo "error: invalid-input: $1" >&2; }

BENCH_RESULTS="${BENCH_RESULTS:-}"
BENCH_MANUAL_BASELINE="${BENCH_MANUAL_BASELINE:-benches/baseline-manual.json}"
BENCH_METRICS="${BENCH_METRICS:-benches/metrics.json}"
BENCH_HOST_KIND="${BENCH_HOST_KIND:-}"

if [ -z "${BENCH_RESULTS}" ]; then
  echo "usage: make bench-check-manual BENCH_RESULTS=<absolute path of the startup_latency results json> BENCH_HOST_KIND=<bare-metal|vm|wsl2>" >&2
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

bench_manual_check_input_file "${BENCH_RESULTS}"
bench_manual_check_input_file "${BENCH_METRICS}"
manual_json="$(bench_manual_metrics_jq)"

# 結果そのものの検査（基準値の有無に関わらず行う。bench-baseline-manual と共通の規則）。
bench_manual_validate_results "${BENCH_RESULTS}" "${BENCH_METRICS}"

# 環境の語彙検査（基準値の有無に関わらず行う）: 操作者指定のホストの種類と、結果の arch。
if [ -n "${BENCH_HOST_KIND}" ] && ! bench_manual_in_vocab "${BENCH_HOST_KIND}" "${BENCH_MANUAL_HOST_KINDS}"; then
  err "BENCH_HOST_KIND must be one of: ${BENCH_MANUAL_HOST_KINDS}"
  exit 2
fi
results_arch="$(jq -r '.arch // "" | if type == "string" then . else "" end' "${BENCH_RESULTS}")"
if ! bench_manual_in_vocab "${results_arch}" "${BENCH_MANUAL_ARCHES}"; then
  err "results must have a top-level arch that is one of: ${BENCH_MANUAL_ARCHES}"
  exit 2
fi

if [ ! -e "${BENCH_MANUAL_BASELINE}" ] && [ ! -L "${BENCH_MANUAL_BASELINE}" ]; then
  echo "skip: bench-check-manual: ${BENCH_MANUAL_BASELINE} is not registered yet (TASK-88.h1 #230); results validated but not compared"
  exit 0
fi
bench_manual_check_input_file "${BENCH_MANUAL_BASELINE}"

# 基準値は実機前提 metric だけを持つこと（CI 向け metric の混入は共有 baseline.json との取り違え）。
if ! jq -e --argjson m "${manual_json}" \
  '((.metrics | type) == "object") and ((.metrics | keys) - $m | length == 0)' \
  "${BENCH_MANUAL_BASELINE}" >/dev/null 2>&1; then
  err "${BENCH_MANUAL_BASELINE} must contain only the manual-bench metrics ${manual_json}"
  exit 2
fi

# 環境の機械照合（fail-closed）: 基準値の host（arch・kind）と結果の環境が食い違う比較は行わない。
# 食い違いを偽の合格・偽の回帰にしないため、比較スクリプトを呼ぶ前に 2 で終える（#2095・REPAIR-8）。
base_arch="$(jq -r '.host.arch // "" | if type == "string" then . else "" end' "${BENCH_MANUAL_BASELINE}" 2>/dev/null || true)"
base_kind="$(jq -r '.host.kind // "" | if type == "string" then . else "" end' "${BENCH_MANUAL_BASELINE}" 2>/dev/null || true)"
if ! bench_manual_in_vocab "${base_arch}" "${BENCH_MANUAL_ARCHES}" || ! bench_manual_in_vocab "${base_kind}" "${BENCH_MANUAL_HOST_KINDS}"; then
  err "${BENCH_MANUAL_BASELINE} must have host.arch (${BENCH_MANUAL_ARCHES}) and host.kind (${BENCH_MANUAL_HOST_KINDS}); regenerate it with make bench-baseline-manual"
  exit 2
fi
if [ -z "${BENCH_HOST_KIND}" ]; then
  err "BENCH_HOST_KIND is required when a baseline exists (one of: ${BENCH_MANUAL_HOST_KINDS})"
  exit 2
fi
if [ "${results_arch}" != "${base_arch}" ]; then
  err "environment mismatch: results arch ${results_arch} != baseline host.arch ${base_arch}"
  exit 2
fi
if [ "${BENCH_HOST_KIND}" != "${base_kind}" ]; then
  err "environment mismatch: BENCH_HOST_KIND ${BENCH_HOST_KIND} != baseline host.kind ${base_kind}"
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
bash "${DIR}/../bench/assemble_results.sh" --baseline "${BENCH_MANUAL_BASELINE}" --metrics "${BENCH_METRICS}" \
  --staged "" --output "${tmp}/results.json" "${BENCH_RESULTS}"
rc=0
bash "${DIR}/../check-bench-regression.sh" "${BENCH_MANUAL_BASELINE}" "${tmp}/results.json" || rc=$?
exit "${rc}"
