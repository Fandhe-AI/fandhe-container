#!/usr/bin/env bash
# scripts/bench/generate_baseline.sh の自己テスト（TASK-88.1・REPAIR-8・REPAIR-12）。
#
# 役割: 固定 fixture（scripts/testdata/bench-baseline/）を用い、生成器の終了コードと
# 出力を具体値で照合する。生成物が比較スクリプト（check-bench-regression.sh）の入力
# スキーマに合うこと（往復検証）も機械的に確認する。
# 呼び出し元は Makefile の `bench-baseline-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gen="${script_dir}/generate_baseline.sh"
check="${script_dir}/../check-bench-regression.sh"
fx="${script_dir}/../testdata/bench-baseline"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
sentinel='{"sentinel":true}'

pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# 引数: <ケース名> <期待終了コード> <生成器の引数...>。--output は $work/out.json 固定。
# 失敗ケースでは既存の出力ファイルが書き換わらないことも確認する。
run_case() {
  local name="$1" expected="$2"
  shift 2
  local actual=0
  printf '%s' "$sentinel" >"${work}/out.json"
  bash "$gen" --output "${work}/out.json" "$@" >/dev/null 2>&1 || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    fail "${name} (expected exit=${expected}, actual exit=${actual})"
    return
  fi
  if [ "$expected" -ne 0 ] && [ "$(cat "${work}/out.json")" != "$sentinel" ]; then
    fail "${name} (output file was modified on failure)"
    return
  fi
  pass "${name} (exit=${actual})"
}

# 正常系: 単一 results → golden と一致（REPAIR-8 の校正記録フィールドを含む）
actual=0
SOURCE_DATE_EPOCH=0 bash "$gen" --metrics "${fx}/metrics.json" --output "${work}/golden.json" \
  --environment "fixture env" "${fx}/results-all.json" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 0 ] && [ "$(jq -S . "${work}/golden.json")" = "$(jq -S . "${fx}/expected-baseline.json")" ]; then
  pass "golden-single-results"
else
  fail "golden-single-results (exit=${actual})"
fi

# 往復検証: 生成物を比較スクリプトへそのまま通すと exit 0（受け入れ基準 2）
actual=0
bash "$check" "${work}/golden.json" "${fx}/results-all.json" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 0 ]; then
  pass "roundtrip-check-bench-regression (exit=0)"
else
  fail "roundtrip-check-bench-regression (exit=${actual})"
fi

# 15% 超悪化の results は生成物に対して回帰として検出される（direction が引き継がれている）
printf '%s' '{"schema_version":1,"metrics":{"placeholder_throughput":{"value":900,"unit":"ops/s"},"placeholder_latency_p95":{"value":80,"unit":"ms"}}}' >"${work}/regress.json"
actual=0
bash "$check" "${work}/golden.json" "${work}/regress.json" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 1 ]; then
  pass "generated-direction-detects-regression (exit=1)"
else
  fail "generated-direction-detects-regression (expected exit=1, actual exit=${actual})"
fi

# 複数 results ファイルのマージ
run_case "merge-two-files" 0 --metrics "${fx}/metrics.json" "${fx}/results-a.json" "${fx}/results-b.json"

# placeholder: false の定義 → 出力の placeholder が false
run_case "placeholder-false-definition" 0 --metrics "${fx}/metrics-real.json" "${fx}/results-all.json"
if [ "$(jq -r '.placeholder' "${work}/out.json")" = "false" ]; then
  pass "placeholder-false-propagated"
else
  fail "placeholder-false-propagated"
fi

run_case "missing-metric" 2 --metrics "${fx}/metrics.json" "${fx}/results-a.json"
run_case "unknown-metric" 2 --metrics "${fx}/metrics.json" "${fx}/results-unknown.json"
run_case "unit-mismatch" 2 --metrics "${fx}/metrics.json" "${fx}/results-unit-mismatch.json"
run_case "duplicate-across-files" 2 --metrics "${fx}/metrics.json" "${fx}/results-a.json" "${fx}/results-dup.json" "${fx}/results-b.json"
run_case "value-zero" 2 --metrics "${fx}/metrics.json" "${fx}/results-invalid-zero.json"
run_case "placeholder-not-specified" 2 --metrics "${fx}/metrics-missing-placeholder.json" "${fx}/results-all.json"
run_case "no-results-files" 2 --metrics "${fx}/metrics.json"
run_case "missing-input-file" 2 --metrics "${fx}/metrics.json" "${fx}/does-not-exist.json"

# 入力が symlink → 拒否
ln -s "${fx}/results-all.json" "${work}/link-results.json"
run_case "input-symlink" 2 --metrics "${fx}/metrics.json" "${work}/link-results.json"

# 出力先が symlink → 拒否し、リンク先を書き換えない
printf '%s' "$sentinel" >"${work}/target.json"
ln -s "${work}/target.json" "${work}/link-out.json"
actual=0
bash "$gen" --metrics "${fx}/metrics.json" --output "${work}/link-out.json" "${fx}/results-all.json" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 2 ] && [ "$(cat "${work}/target.json")" = "$sentinel" ]; then
  pass "output-symlink (exit=2, target untouched)"
else
  fail "output-symlink (exit=${actual})"
fi

# SOURCE_DATE_EPOCH が非数値 → 入力エラー
actual=0
SOURCE_DATE_EPOCH=abc bash "$gen" --metrics "${fx}/metrics.json" --output "${work}/out.json" "${fx}/results-all.json" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 2 ]; then
  pass "source-date-epoch-non-numeric (exit=2)"
else
  fail "source-date-epoch-non-numeric (expected exit=2, actual exit=${actual})"
fi

if [ "$failures" -gt 0 ]; then
  echo "${failures} case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
