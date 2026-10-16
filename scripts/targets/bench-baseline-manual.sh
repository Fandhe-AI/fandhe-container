#!/usr/bin/env bash
# 実機前提ベンチ（起動レイテンシ p95）の結果 JSON から、実機前提の基準値を生成する
# （make bench-baseline-manual。#2095・TASK-190 追補・TASK-88・REPAIR-8）。
#
# 役割: 人が実機で採った結果（cargo bench ... --bench startup_latency -- <引数> --output <絶対パス>）を、
# benches/baseline-manual.json と同じ形式（host: {arch, kind} つき）の基準値へ変換する。実際の変換・往復検証・
# アトミック置換は scripts/bench/generate_baseline.sh が行い、本スクリプトは結果の検査と引数の組み立てだけを担う。
# 比較側は make bench-check-manual（scripts/targets/bench-check-manual.sh）で、host が食い違うと比較しない。
# ベンチ自体は実行せずファイルを変換するだけなので OS に依らない。sudo は呼ばない。ホスト名・ユーザー名は集めない。
# 実測値・基準値の確定は人間担当の TASK-88.h1（#230）で、本スクリプトはリポジトリに基準値を置かない。
#
# 入力（環境変数）:
#   BENCH_RESULTS       必須。結果ファイルの絶対パス（通常ファイル・symlink 不可・1 MiB 以下）
#   BENCH_HOST_KIND     必須。実測したホストの種類（lib.sh の BENCH_MANUAL_HOST_KINDS）
#   BENCH_BASELINE_OUT  任意。出力先（既定 target/bench-baseline-manual/baseline-manual.json。
#                       共有の benches/baseline-manual.json へは明示指定したときだけ書く）
#   BENCH_ENVIRONMENT   任意。一般化した環境説明（256 文字以内。generate_baseline.sh の --environment）
#   BENCH_METRICS       任意。metrics の SSOT（既定 benches/metrics.json）
#
# 終了コード: 0 生成成功 / 1 往復検証の失敗 / 2 入力エラー（失敗した実行の結果からは作らない）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

err() { echo "error: invalid-input: $1" >&2; }

BENCH_RESULTS="${BENCH_RESULTS:-}"
BENCH_HOST_KIND="${BENCH_HOST_KIND:-}"
BENCH_BASELINE_OUT="${BENCH_BASELINE_OUT:-${BENCH_MANUAL_BASELINE_OUT_DEFAULT}}"
BENCH_METRICS="${BENCH_METRICS:-benches/metrics.json}"

if [ -z "${BENCH_RESULTS}" ] || [ -z "${BENCH_HOST_KIND}" ]; then
  echo "usage: make bench-baseline-manual BENCH_RESULTS=<absolute path of the startup_latency results json> BENCH_HOST_KIND=<bare-metal|vm|wsl2> [BENCH_BASELINE_OUT=<path>] [BENCH_ENVIRONMENT=<text>]" >&2
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
if ! bench_manual_in_vocab "${BENCH_HOST_KIND}" "${BENCH_MANUAL_HOST_KINDS}"; then
  err "BENCH_HOST_KIND must be one of: ${BENCH_MANUAL_HOST_KINDS}"
  exit 2
fi

bench_manual_check_input_file "${BENCH_RESULTS}"
bench_manual_check_input_file "${BENCH_METRICS}"
bench_manual_validate_results "${BENCH_RESULTS}" "${BENCH_METRICS}"

results_arch="$(jq -r '.arch // "" | if type == "string" then . else "" end' "${BENCH_RESULTS}")"
if ! bench_manual_in_vocab "${results_arch}" "${BENCH_MANUAL_ARCHES}"; then
  err "results must have a top-level arch that is one of: ${BENCH_MANUAL_ARCHES}"
  exit 2
fi

# 既定の出力先だけ親ディレクトリを作る（明示指定の出力先の親は操作者が用意する）。
if [ "${BENCH_BASELINE_OUT}" = "${BENCH_MANUAL_BASELINE_OUT_DEFAULT}" ]; then
  mkdir -p "$(dirname "${BENCH_BASELINE_OUT}")"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
# metrics を実機前提 metric だけに絞る（generate_baseline.sh は metrics と結果の集合の一致を要求するため）。
jq --argjson m "$(bench_manual_metrics_jq)" '.metrics |= with_entries(select(.key as $k | $m | index($k)))' \
  "${BENCH_METRICS}" >"${tmp}/metrics-manual.json"

env_args=()
if [ -n "${BENCH_ENVIRONMENT:-}" ]; then
  env_args=(--environment "${BENCH_ENVIRONMENT}")
fi
rc=0
bash "${DIR}/../bench/generate_baseline.sh" --metrics "${tmp}/metrics-manual.json" --output "${BENCH_BASELINE_OUT}" \
  --arch "${results_arch}" --host-kind "${BENCH_HOST_KIND}" ${env_args[@]+"${env_args[@]}"} "${BENCH_RESULTS}" || rc=$?
exit "${rc}"
