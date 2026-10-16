#!/usr/bin/env bash
# scripts/check-bench-regression.sh の自己テスト（TASK-86.3・REPAIR-7 第 4 段階・REPAIR-8）。
#
# 役割: 固定 fixture（scripts/testdata/bench-regression/）を用い、比較スクリプトの
# 終了コードを具体値で照合する。受け入れ基準「15% 超の悪化を検出して非ゼロ終了する
# ことを確認した記録がある」を CI 上で毎回機械照合する（REPAIR-12）。
# 呼び出し元は Makefile の `bench-check-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 期待と異なる終了コードが 1 件でもあれば非ゼロで終了する（fail-closed）。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check_script="${script_dir}/check-bench-regression.sh"
fixtures_dir="${script_dir}/testdata/bench-regression"
baseline="${fixtures_dir}/baseline.json"

failures=0

# 期待終了コードと比較スクリプトの実際の終了コードを照合する 1 ケース分の判定。
# 引数: <ケース名> <baseline> <results> <期待終了コード>
run_case() {
  local name="$1"
  local baseline_arg="$2"
  local results_arg="$3"
  local expected="$4"
  local actual=0

  bash "$check_script" "$baseline_arg" "$results_arg" >/dev/null 2>&1 || actual=$?

  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: ${name} (exit=${actual})"
  else
    echo "FAIL: ${name} (expected exit=${expected}, actual exit=${actual})" >&2
    failures=$((failures + 1))
  fi
}

# REPAIR-8: ちょうど 15.0% の悪化は合格（0）
run_case "boundary-15-percent" "$baseline" "${fixtures_dir}/results-boundary-15.json" 0

# REPAIR-8: higher_is_better metric が 16% 悪化 → 回帰検出（1）
run_case "regress-higher-16-percent" "$baseline" "${fixtures_dir}/results-regress-higher-16.json" 1

# REPAIR-8: lower_is_better metric が 16% 悪化 → 回帰検出（1）
run_case "regress-lower-16-percent" "$baseline" "${fixtures_dir}/results-regress-lower-16.json" 1

# 改善方向の変化は合格（0）
run_case "improved" "$baseline" "${fixtures_dir}/results-improved.json" 0

# baseline にある metric が results に無い → 入力エラー（2）
run_case "missing-metric" "$baseline" "${fixtures_dir}/results-missing-metric.json" 2

# results にしかない metric がある → 入力エラー（2）
run_case "unknown-metric" "$baseline" "${fixtures_dir}/results-unknown-metric.json" 2

# baseline の value が 0（有限の正数ではない）→ 入力エラー（2）
run_case "baseline-invalid-zero" "${fixtures_dir}/baseline-invalid-zero.json" "${fixtures_dir}/results-improved.json" 2

# 極端に大きい有限値同士（baseline=1e307, current=1e308 の 10 倍悪化）で乗算比較が
# DBL_MAX へ飽和し「回帰なし」と誤判定しないことを確認する回帰テスト（比率比較への
# 修正の受け入れ基準）
run_case "regress-lower-extreme-overflow" "${fixtures_dir}/baseline-extreme.json" "${fixtures_dir}/results-regress-extreme-10x.json" 1

# TASK-113.3・PLUG-5・REPAIR-8: plugin 境界ベンチの実 metric 名（Δp50）での判定。
# Δp50 単独の悪化（他 metric は基準値と同値）を検出できることを機械照合する。
plugin_baseline="${fixtures_dir}/baseline-plugin.json"
run_case "plugin-delta-boundary-15-percent" "$plugin_baseline" "${fixtures_dir}/results-plugin-boundary-15.json" 0
run_case "plugin-delta-regress-16-percent" "$plugin_baseline" "${fixtures_dir}/results-plugin-regress-delta-16.json" 1
run_case "plugin-delta-improved" "$plugin_baseline" "${fixtures_dir}/results-plugin-improved.json" 0

# 存在しないファイル → 入力エラー（2）
run_case "missing-file" "$baseline" "${fixtures_dir}/does-not-exist.json" 2

# 読み取り権限の無いファイル → 入力エラー（2）。`wc -c` 自体が失敗するケースを
# `set -e` に丸投げして exit 1（回帰検出）と誤認しないことを確認する回帰テスト。
# root（CI コンテナ等）はパーミッションを無視して読めてしまうため、その場合は
# このケースを意味のある形で再現できずスキップする。
if [ "$(id -u)" -eq 0 ]; then
  echo "SKIP: unreadable-file (running as root, permission bits are not enforced)"
else
  unreadable="${fixtures_dir}/unreadable.json"
  cp "${fixtures_dir}/results-improved.json" "$unreadable"
  chmod 000 "$unreadable"
  run_case "unreadable-file" "$baseline" "$unreadable" 2
  chmod 644 "$unreadable"
  rm -f "$unreadable"
fi

# TASK-189 追補・#1899・REPAIR-8: scripts/bench/assemble_results.sh（段階登録ベンチの絞り込み・照合）と
# 比較スクリプトをつないだ判定。fixture は一時ディレクトリへ生成する（cargo 不要）。
assemble_script="${script_dir}/bench/assemble_results.sh"
gate_tmp="$(mktemp -d)"
trap 'rm -rf "${gate_tmp}"' EXIT

sf='"small_files_files_per_sec"'
pb1='"plugin_boundary_op_a_inproc_p50"'
pb2='"plugin_boundary_op_a_framed_p50"'
ph='"placeholder_throughput"'

# 結果 JSON を書く: <ファイル> <metric 名> <値> <単位>...（3 つ組の繰り返し）
write_results() {
  local out="$1"
  shift
  local body=""
  while [ "$#" -ge 3 ]; do
    body="${body:+${body}, }$1: {\"value\": $2, \"unit\": \"$3\"}"
    shift 3
  done
  printf '{"schema_version": 1, "metrics": {%s}}\n' "${body}" >"${out}"
}
# baseline JSON を書く: <ファイル> と 4 つ組（metric 名・値・単位・direction）の繰り返し
write_baseline() {
  local out="$1"
  shift
  local body=""
  while [ "$#" -ge 4 ]; do
    body="${body:+${body}, }$1: {\"value\": $2, \"unit\": \"$3\", \"direction\": \"$4\"}"
    shift 4
  done
  printf '{"schema_version": 1, "metrics": {%s}}\n' "${body}" >"${out}"
}
write_metrics() {
  printf '{"schema_version": 1, "metrics": {%s}}\n' "$1" >"$2"
}
all_metrics='"placeholder_throughput": {"unit": "ops/s", "direction": "higher_is_better"}, "plugin_boundary_op_a_inproc_p50": {"unit": "ns", "direction": "lower_is_better"}, "plugin_boundary_op_a_framed_p50": {"unit": "ns", "direction": "lower_is_better"}, "small_files_files_per_sec": {"unit": "files/s", "direction": "higher_is_better"}'
write_metrics "${all_metrics}" "${gate_tmp}/metrics.json"
mkdir "${gate_tmp}/in"
write_results "${gate_tmp}/in/placeholder.json" "${ph}" 1000 ops/s
cp "${gate_tmp}/in/placeholder.json" "${gate_tmp}/in/regression_placeholder.json"
rm "${gate_tmp}/in/placeholder.json"
write_results "${gate_tmp}/in/small_files.json" "${sf}" 2000 files/s
write_results "${gate_tmp}/in/plugin_boundary.json" "${pb1}" 100 ns "${pb2}" 200 ns
staged="plugin_boundary small_files"

# 段階登録の 1 ケース: <名> <baseline> <metrics> <staged> <assemble の期待終了コード> <比較の期待終了コード（assemble 成功時）>
# assemble の期待が 2 のときは比較を実行しない。results は ${gate_tmp}/in/*.json を使う。
run_gate_case() {
  local name="$1" bl="$2" mt="$3" st="$4" exp_asm="$5" exp_cmp="${6:-}"
  local act_asm=0 act_cmp=0
  rm -f "${gate_tmp}/out.json"
  bash "${assemble_script}" --baseline "${bl}" --metrics "${mt}" --staged "${st}" \
    --output "${gate_tmp}/out.json" "${gate_tmp}"/in/*.json >/dev/null 2>&1 || act_asm=$?
  if [ "${act_asm}" -ne "${exp_asm}" ]; then
    echo "FAIL: ${name} (assemble expected exit=${exp_asm}, actual exit=${act_asm})" >&2
    failures=$((failures + 1))
    return
  fi
  if [ "${exp_asm}" -eq 0 ]; then
    bash "$check_script" "${bl}" "${gate_tmp}/out.json" >/dev/null 2>&1 || act_cmp=$?
    if [ "${act_cmp}" -ne "${exp_cmp}" ]; then
      echo "FAIL: ${name} (compare expected exit=${exp_cmp}, actual exit=${act_cmp})" >&2
      failures=$((failures + 1))
      return
    fi
  fi
  echo "PASS: ${name} (assemble exit=${act_asm}, compare exit=${act_cmp})"
}

write_baseline "${gate_tmp}/b-unreg.json" "${ph}" 1000 ops/s higher_is_better
# 未登録の段階登録ベンチは比較しない: assemble 0・比較 0・出力に small_files と plugin の metric が無い
run_gate_case "gate-unregistered-not-compared" "${gate_tmp}/b-unreg.json" "${gate_tmp}/metrics.json" "${staged}" 0 0
if [ "$(jq -c '.metrics | keys' "${gate_tmp}/out.json")" = '["placeholder_throughput"]' ]; then
  echo "PASS: gate-unregistered-output-keys"
else
  echo "FAIL: gate-unregistered-output-keys (got $(jq -c '.metrics | keys' "${gate_tmp}/out.json"))" >&2
  failures=$((failures + 1))
fi

# 登録済み: ちょうど 15% 悪化（higher_is_better 2000 → 1700）は合格、16% 悪化（1680）は回帰
write_baseline "${gate_tmp}/b-reg.json" "${ph}" 1000 ops/s higher_is_better "${sf}" 2000 files/s higher_is_better
write_results "${gate_tmp}/in/small_files.json" "${sf}" 1700 files/s
run_gate_case "gate-registered-boundary-15" "${gate_tmp}/b-reg.json" "${gate_tmp}/metrics.json" "${staged}" 0 0
write_results "${gate_tmp}/in/small_files.json" "${sf}" 1680 files/s
run_gate_case "gate-registered-regress-16" "${gate_tmp}/b-reg.json" "${gate_tmp}/metrics.json" "${staged}" 0 1
write_results "${gate_tmp}/in/small_files.json" "${sf}" 2000 files/s

# 登録済み metric が metrics.json から消えた → 入力エラー
write_metrics "${all_metrics%, \"small_files_files_per_sec\"*}" "${gate_tmp}/metrics-removed.json"
run_gate_case "gate-registered-metric-removed" "${gate_tmp}/b-reg.json" "${gate_tmp}/metrics-removed.json" "${staged}" 2

# 段階登録ベンチの部分登録（2 metric のうち 1 つだけ baseline に登録）→ 入力エラー
write_baseline "${gate_tmp}/b-partial.json" "${ph}" 1000 ops/s higher_is_better "${pb1}" 100 ns lower_is_better
run_gate_case "gate-staged-partial-registration" "${gate_tmp}/b-partial.json" "${gate_tmp}/metrics.json" "${staged}" 2

# 段階登録でないベンチの未登録 metric は絞り込まず、比較スクリプトが入力エラー（登録漏れの検出）
run_gate_case "gate-non-staged-unregistered" "${gate_tmp}/b-unreg.json" "${gate_tmp}/metrics.json" "plugin_boundary" 0 2

# 複数の段階登録ベンチの独立性: plugin_boundary は登録済み（比較対象）、small_files は未登録（除外）
write_baseline "${gate_tmp}/b-plugin.json" "${ph}" 1000 ops/s higher_is_better "${pb1}" 100 ns lower_is_better "${pb2}" 200 ns lower_is_better
run_gate_case "gate-staged-independent" "${gate_tmp}/b-plugin.json" "${gate_tmp}/metrics.json" "${staged}" 0 0
if [ "$(jq -c '.metrics | keys' "${gate_tmp}/out.json")" = '["placeholder_throughput","plugin_boundary_op_a_framed_p50","plugin_boundary_op_a_inproc_p50"]' ]; then
  echo "PASS: gate-staged-independent-output-keys"
else
  echo "FAIL: gate-staged-independent-output-keys (got $(jq -c '.metrics | keys' "${gate_tmp}/out.json"))" >&2
  failures=$((failures + 1))
fi

# 入力検証: 不正な段階登録名・symlink の結果ファイル → 入力エラー
run_gate_case "gate-invalid-staged-name" "${gate_tmp}/b-unreg.json" "${gate_tmp}/metrics.json" 'bad;name' 2
ln -s "${gate_tmp}/in/small_files.json" "${gate_tmp}/in/link.json"
run_gate_case "gate-symlink-result" "${gate_tmp}/b-unreg.json" "${gate_tmp}/metrics.json" "${staged}" 2
rm -f "${gate_tmp}/in/link.json"

# lib.sh と metrics.json の整合: 段階登録・Unix 限定の各名が BENCH_NAMES に含まれ、small_files の metric が
# ハーネスの定数（METRIC_NAME・METRIC_UNIT）と metrics.json で一致する。
repo_root="$(cd "${script_dir}/.." && pwd)"
lib_check="$(bash -c 'source "$1/scripts/lib.sh"; for n in ${BENCH_STAGED_NAMES} ${BENCH_UNIX_ONLY_NAMES}; do case " ${BENCH_NAMES} " in *" ${n} "*) ;; *) echo "missing:${n}" ;; esac; done' _ "${repo_root}")"
if [ -z "${lib_check}" ]; then
  echo "PASS: lib-bench-names-consistent"
else
  echo "FAIL: lib-bench-names-consistent (${lib_check})" >&2
  failures=$((failures + 1))
fi
harness_name="$(sed -n 's/^pub const METRIC_NAME: &str = "\(.*\)";$/\1/p' "${repo_root}/benches/src/small_files.rs")"
harness_unit="$(sed -n 's/^pub const METRIC_UNIT: &str = "\(.*\)";$/\1/p' "${repo_root}/benches/src/small_files.rs")"
if jq -e --arg n "${harness_name}" --arg u "${harness_unit}" \
  '.metrics[$n] | .unit == $u and .direction == "higher_is_better"' "${repo_root}/benches/metrics.json" >/dev/null; then
  echo "PASS: small-files-metric-registered (${harness_name} ${harness_unit})"
else
  echo "FAIL: small-files-metric-registered (${harness_name} ${harness_unit})" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
  echo "self-test failed: ${failures} case(s) did not match the expected exit code" >&2
  exit 1
fi

echo "self-test passed: all cases matched the expected exit code"
