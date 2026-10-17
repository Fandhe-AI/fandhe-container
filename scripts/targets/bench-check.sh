#!/usr/bin/env bash
# ベンチ回帰チェック（make bench-check。REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）。
#
# `make ci` には含めない: (1) ci.md のローカルゲート定義を変えないため、(2) 実ベンチの実行は時間がかかるため。
# CI 側は ci.yml の bench-regression 専用ジョブが必ず実行するため、`make ci` に無くてもゲートは抜けない。
#
# 登録済みベンチ（lib.sh の BENCH_NAMES）を実行し、結果を基準値（benches/baseline.json）と比較する。
# 一時ディレクトリは trap で必ず削除する。対象ベンチは Unix では BENCH_NAMES、Windows（OS=Windows_NT）では
# BENCH_UNIX_ONLY_NAMES を除いたもの（regression_placeholder のみ）。各ベンチへの引数は lib.sh の bench_args_for。
# 絞り込みと照合は scripts/bench/assemble_results.sh が担う: 段階登録ベンチ（BENCH_STAGED_NAMES。plugin 境界ベンチ
# と small_files）は baseline.json に登録済みの metric に限って比較し、未登録の間は比較しない。それ以外のベンチ
# （regression_placeholder 等）の未登録 metric は絞り込まず、check-bench-regression.sh が入力エラーにする
# （登録漏れを検出する）。Windows は Unix 限定ベンチを実行しないため、baseline 側からもその metric を除いて比較する。
# 実機前提ベンチ（lib.sh の BENCH_MANUAL_NAMES。起動 p95・#1901）は実行も比較もしない（CI では回帰を検出できない）。
# 実機で採った結果の比較は make bench-check-manual（scripts/targets/bench-check-manual.sh）。
# baseline 再生成（TASK-88.h1・TASK-113.h1）後は、再生成した metric がそのまま 15% 回帰判定の対象になり、本スクリプト
# の追従修正が要らない。未登録の間は plugin 境界・files/s の性能回帰ゲートは未有効。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace bench-check
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/in"
for n in $(bench_names_for_os); do
  mkdir -p "${tmp}/root/${n}"
  bench_args=()
  while IFS= read -r line; do
    bench_args+=("${line}")
  done < <(bench_args_for "${n}" "${tmp}/root/${n}")
  cargo bench -p fandhe-container-benches --bench "${n}" -- ${bench_args[@]+"${bench_args[@]}"} --output "${tmp}/in/${n}.json" >/dev/null
done
bash scripts/bench/assemble_results.sh --baseline benches/baseline.json --metrics benches/metrics.json \
  --staged "${BENCH_STAGED_NAMES}" --output "${tmp}/results.json" "${tmp}"/in/*.json
if [ "${OS:-}" = "Windows_NT" ]; then
  jq --argjson p "$(bench_metric_prefixes_jq)" \
    '.metrics |= with_entries(select(.key as $k | $p | any(. as $x | $k | startswith($x)) | not))' \
    benches/baseline.json >"${tmp}/baseline.json"
else
  cp benches/baseline.json "${tmp}/baseline.json"
fi
bash scripts/check-bench-regression.sh "${tmp}/baseline.json" "${tmp}/results.json"
