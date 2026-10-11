#!/usr/bin/env bash
# 登録済みベンチを実行し、benches/metrics.json（direction・unit の SSOT）と合わせて baseline.json を再生成する
# （make bench-baseline。TASK-88.1・REPAIR-8）。
#
# 校正記録は docs/design/bench-calibration.md（TASK-88.2・#229）、実測と基準値の確定は TASK-88.h1・TASK-113.h1。
# 入力は環境変数: BENCH_METRICS（既定 benches/metrics.json）・BENCH_BASELINE_OUT（既定 benches/baseline.json）・
# BENCH_ENVIRONMENT（任意）。値は二重引用符付きで参照し、引用が壊れない。
# Windows（OS=Windows_NT）は plugin 境界ベンチ（Unix ドメインソケット前提）を実行できないため regression_placeholder のみ
# 実行し、metrics.json からも plugin_boundary* を除いた一時ファイルを生成スクリプトへ渡す（AGENTS.md「3 OS 対応」）。
# このため Windows で既定の出力先 benches/baseline.json へ書くと共有 baseline から plugin metric が消えるので、
# Windows では BENCH_BASELINE_OUT を別ファイルに指定しない限りエラーにする。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace bench-baseline
BENCH_METRICS="${BENCH_METRICS:-benches/metrics.json}"
BENCH_BASELINE_OUT="${BENCH_BASELINE_OUT:-benches/baseline.json}"
BENCH_ENVIRONMENT="${BENCH_ENVIRONMENT:-}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/res"
for n in $(bench_names_for_os); do
  cargo bench -p fandhe-container-benches --bench "${n}" -- --output "${tmp}/res/${n}.json"
done
metrics="${BENCH_METRICS}"
if [ "${OS:-}" = "Windows_NT" ]; then
  if [ "${BENCH_BASELINE_OUT}" = "benches/baseline.json" ]; then
    echo "error: invalid-input: on Windows plugin_boundary metrics are not measured; set BENCH_BASELINE_OUT to a separate file so the shared benches/baseline.json keeps its plugin baselines" >&2
    exit 2
  fi
  jq '.metrics |= with_entries(select(.key | startswith("plugin_boundary") | not))' \
    "${BENCH_METRICS}" >"${tmp}/metrics.json"
  metrics="${tmp}/metrics.json"
fi
args=(--metrics "${metrics}" --output "${BENCH_BASELINE_OUT}")
if [ -n "${BENCH_ENVIRONMENT}" ]; then
  args+=(--environment "${BENCH_ENVIRONMENT}")
fi
bash scripts/bench/generate_baseline.sh "${args[@]}" "${tmp}"/res/*.json
