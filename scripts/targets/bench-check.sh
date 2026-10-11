#!/usr/bin/env bash
# ベンチ回帰チェック（make bench-check。REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）。
#
# `make ci` には含めない: (1) ci.md のローカルゲート定義を変えないため、(2) 実ベンチの実行は時間がかかるため。
# CI 側は ci.yml の bench-regression 専用ジョブが必ず実行するため、`make ci` に無くてもゲートは抜けない。
#
# プレースホルダベンチ（benches/benches/regression_placeholder.rs）等を実行し、結果を基準値
# （benches/baseline.json）と比較する。一時ディレクトリは trap で必ず削除する。
# 対象ベンチは Unix では lib.sh の BENCH_NAMES、Windows（OS=Windows_NT）では regression_placeholder のみ。
# 絞り込みは plugin 境界ベンチ（plugin_boundary*）の結果だけに適用し、baseline.json に登録済みの metric に限って
# 比較する（plugin 系 metric の段階登録を許容するため）。それ以外のベンチ（regression_placeholder 等）の未登録
# metric は絞り込まず、check-bench-regression.sh が入力エラーにする（登録漏れを検出する）。Windows は
# plugin 境界ベンチが unsupported-platform で失敗するため実行せず、baseline 側から plugin_boundary* の metric だけを
# 除外して比較する（plugin 境界は Unix 専用。PLUG-5）。baseline 再生成（TASK-88.h1・TASK-113.h1）後は、再生成した
# metric がそのまま 15% 回帰判定の対象になり、本スクリプトの追従修正が要らない。未登録の間は plugin 系 metric は
# 比較されない（plugin 境界の性能回帰ゲートは未有効）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace bench-check
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/in" "${tmp}/out"
if [ "${OS:-}" != "Windows_NT" ]; then
  reg="$(jq -c '[.metrics | keys[] | select(startswith("plugin_boundary"))]' benches/baseline.json)"
  exp="$(jq -c '[.metrics | keys[] | select(startswith("plugin_boundary"))]' benches/metrics.json)"
  if [ "${reg}" != "[]" ] && [ "${reg}" != "${exp}" ]; then
    echo "error: invalid-input: baseline.json plugin_boundary metrics ${reg} do not match metrics.json ${exp} (a registered metric was removed or is missing; recalibrate per TASK-88)" >&2
    exit 2
  fi
fi
for n in $(bench_names_for_os); do
  cargo bench -p fandhe-container-benches --bench "${n}" -- --output "${tmp}/in/${n}.json" >/dev/null
done
for f in "${tmp}"/in/*.json; do
  case "$(basename "${f}")" in
    plugin_boundary*)
      jq --slurpfile b benches/baseline.json \
        '{schema_version: 1, metrics: (.metrics | with_entries(select(.key as $k | $b[0].metrics | has($k))))}' \
        "${f}" >"${tmp}/out/$(basename "${f}")"
      ;;
    *) cp "${f}" "${tmp}/out/" ;;
  esac
done
jq -s '{schema_version: 1, metrics: (map(.metrics) | add)}' "${tmp}"/out/*.json >"${tmp}/results.json"
if [ "${OS:-}" = "Windows_NT" ]; then
  jq '.metrics |= with_entries(select(.key | startswith("plugin_boundary") | not))' \
    benches/baseline.json >"${tmp}/baseline.json"
else
  cp benches/baseline.json "${tmp}/baseline.json"
fi
bash scripts/check-bench-regression.sh "${tmp}/baseline.json" "${tmp}/results.json"
