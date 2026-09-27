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

# 存在しないファイル → 入力エラー（2）
run_case "missing-file" "$baseline" "${fixtures_dir}/does-not-exist.json" 2

if [ "$failures" -gt 0 ]; then
  echo "self-test failed: ${failures} case(s) did not match the expected exit code" >&2
  exit 1
fi

echo "self-test passed: all cases matched the expected exit code"
