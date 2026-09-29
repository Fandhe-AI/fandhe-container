#!/usr/bin/env bash
# scripts/fio-baseline-ratio.sh の自己テスト（TASK-25.2・IO-8・REPAIR-12）。
#
# 役割: fio-baseline-ratio.sh の終了コード・出力値を固定 fixture
# （scripts/testdata/fio-baseline/）で照合する。実 fio・実 Docker は使わない
# （比較スクリプト自体は fio を実行しないため、常にこの自己テストだけで完結する）。
# 呼び出し元は Makefile の `fio-baseline-ratio-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# end-to-end ケース（case 2）では `fio-randwrite-4k.sh --from-json` の実出力を
# そのまま入力にすることで、TASK-25.1 の出力スキーマと本スクリプトの前提が
# 食い違っていないことも機械照合する。
#
# 期待と異なる終了コード・値が 1 件でもあれば非ゼロで終了する（fail-closed）。
# 各ケースの失敗は failures に数えて最後まで実行を続け、末尾のサマリーで判定する
# （fio-randwrite-4k-selftest.sh と同じ方針。set -e 下でヘルパーが打ち切らないよう
# 常に 0 を返し、結果は変数で渡す）。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/fio-baseline-ratio.sh"
converter_script="${script_dir}/fio-randwrite-4k.sh"
fixtures_dir="${script_dir}/testdata/fio-baseline"
bench_fixtures_dir="${script_dir}/testdata/fio-bench"
bash_bin="$(command -v bash)"

failures=0
tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

last_output=""
last_stdout=""
last_case_passed=0

print_indented() {
  local line
  while IFS= read -r line; do
    printf '  | %s\n' "$line" >&2
  done <<<"$1"
}

# 引数: <ケース名> <期待終了コード> <target_script への残り引数...>
# last_output（stdout+stderr 結合。メッセージ照合用）と last_stdout（stdout のみ。
# jq での値照合用。stderr の人が読むサマリー行が混ざると JSON として壊れるため分ける）
# の両方を更新する。
run_case() {
  local name="$1"
  local expected="$2"
  shift 2
  local actual=0
  local stderr_only
  local stdout_file
  stdout_file="${tmp_root}/last-stdout.$$"
  # `2>&1 1>file` は先に fd2 を現在の fd1（$() のパイプ）へ複製してから fd1 を
  # file へ切り替えるため、$() は stderr だけを、file は stdout だけを受け取る。
  stderr_only=$("$bash_bin" "$target_script" "$@" 2>&1 1>"$stdout_file") || actual=$?
  last_stdout=$(cat -- "$stdout_file" 2>/dev/null || true)
  rm -f -- "$stdout_file"
  last_output="${last_stdout}"$'\n'"${stderr_only}"
  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: ${name} (exit=${actual})"
    last_case_passed=1
    return 0
  fi
  echo "FAIL: ${name} (expected exit=${expected}, actual exit=${actual})" >&2
  print_indented "$last_output"
  failures=$((failures + 1))
  last_case_passed=0
  return 0
}

# run_case に加え、出力に期待する部分文字列が含まれることを照合する。
run_case_msg() {
  local name="$1"
  local expected="$2"
  local needle="$3"
  shift 3
  run_case "$name" "$expected" "$@"
  if [ "$last_case_passed" -ne 1 ]; then
    return 0
  fi
  if [[ "$last_output" == *"$needle"* ]]; then
    echo "PASS: ${name}-message (contains '${needle}')"
  else
    echo "FAIL: ${name}-message (output does not contain '${needle}')" >&2
    print_indented "$last_output"
    failures=$((failures + 1))
  fi
}

# 期待する jq 式の評価結果と実際の stdout の jq 抽出値を照合する。
# 引数: <ケース名> <期待値> <jq フィルタ>
check_jq_value() {
  local name="$1"
  local expected="$2"
  local filter="$3"
  local actual
  actual=$(printf '%s' "$last_stdout" | jq -r "$filter" 2>&1) || actual="<jq-error: ${actual}>"
  if [ "$actual" = "$expected" ]; then
    echo "PASS: ${name} (${filter} == ${expected})"
  else
    echo "FAIL: ${name} (${filter}: expected '${expected}', actual '${actual}')" >&2
    failures=$((failures + 1))
  fi
}

# --------------------------------------------------
# case 1: ok 同士 — 終了コード 0・具体値の照合
# --------------------------------------------------
run_case "ok-baseline-candidate" 0 --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-ok.json"
if [ "$last_case_passed" -eq 1 ]; then
  check_jq_value "ok-ratio-iops" "1.5" ".ratios.iops.value"
  check_jq_value "ok-ratio-lat-mean" "0.8" ".ratios.lat_mean_us.value"
  check_jq_value "ok-ratio-clat-p50" "0.8" ".ratios.clat_p50_us.value"
  check_jq_value "ok-ratio-clat-p95" "0.8" ".ratios.clat_p95_us.value"
  check_jq_value "ok-ratio-clat-p99" "0.8" ".ratios.clat_p99_us.value"
  check_jq_value "ok-baseline-label" "docker_bind_mount" ".baseline.label"
  check_jq_value "ok-candidate-label" "fandhe_shared_mount" ".candidate.label"
fi

# --------------------------------------------------
# case 2: end-to-end 互換性確認（fio-randwrite-4k.sh --from-json の実出力を入力にする）
# --------------------------------------------------
e2e_a="${tmp_root}/e2e-a.json"
e2e_b="${tmp_root}/e2e-b.json"
"$bash_bin" "$converter_script" --from-json "${bench_fixtures_dir}/fio-3-ok.json" --label e2e_a >"$e2e_a"
"$bash_bin" "$converter_script" --from-json "${bench_fixtures_dir}/fio-3-ok.json" --label e2e_b >"$e2e_b"
run_case "e2e-same-source" 0 --baseline "$e2e_a" --candidate "$e2e_b"
if [ "$last_case_passed" -eq 1 ]; then
  check_jq_value "e2e-ratio-iops" "1" ".ratios.iops.value"
fi

# --------------------------------------------------
# case 3: params 不一致
# --------------------------------------------------
run_case_msg "params-mismatch" 2 "direct" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-params-mismatch.json"

# --------------------------------------------------
# case 4: baseline の IOPS が 0
# --------------------------------------------------
run_case_msg "baseline-zero-iops" 2 "greater than 0" --baseline "${fixtures_dir}/baseline-zero-iops.json" --candidate "${fixtures_dir}/candidate-ok.json"

# --------------------------------------------------
# case 5: metric 欠落・unit 不一致・benchmark 名不一致・非 JSON
# --------------------------------------------------
run_case_msg "candidate-missing-metric" 2 "is missing" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-missing-metric.json"
run_case_msg "wrong-unit" 2 "unit must be" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/wrong-unit.json"
run_case_msg "wrong-benchmark" 2 "benchmark must be" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/wrong-benchmark.json"
run_case "not-json" 2 --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/not-json.txt"

# --------------------------------------------------
# case 6: symlink・ディレクトリ・サイズ上限超過
# --------------------------------------------------
symlink_path="${tmp_root}/symlink-to-baseline.json"
ln -s "${fixtures_dir}/baseline-ok.json" "$symlink_path"
run_case_msg "symlink-rejected" 2 "is a symlink" --baseline "$symlink_path" --candidate "${fixtures_dir}/candidate-ok.json"

dir_path="${tmp_root}/a-directory"
mkdir -p "$dir_path"
run_case_msg "directory-rejected" 2 "is not a regular file" --baseline "$dir_path" --candidate "${fixtures_dir}/candidate-ok.json"

# 4 MiB 上限超過（jq のパース前に拒否されることを、パース不能でない内容で確かめる）
oversized_path="${tmp_root}/oversized.json"
{
  printf '{"a":"'
  head -c 5000000 /dev/zero | tr '\0' 'a'
  printf '"}'
} >"$oversized_path"
run_case_msg "oversized-input-rejected" 2 "exceeds" --baseline "$oversized_path" --candidate "${fixtures_dir}/candidate-ok.json"

# --------------------------------------------------
# case 7: 引数の欠落・未知の引数
# --------------------------------------------------
run_case "missing-args" 2 --baseline "${fixtures_dir}/baseline-ok.json"
run_case "unknown-arg" 2 --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-ok.json" --unknown-flag x

# --------------------------------------------------
# case 8: fio_version 不一致 — 拒否せず警告のみ（終了コード 0）
# --------------------------------------------------
fioversion_path="${tmp_root}/baseline-old-fio.json"
jq '.fio_version = "fio-3.30"' "${fixtures_dir}/baseline-ok.json" >"$fioversion_path"
run_case_msg "fio-version-mismatch-warns" 0 "fio_version differs" --baseline "$fioversion_path" --candidate "${fixtures_dir}/candidate-ok.json"

# --------------------------------------------------
# case 9: 前提ツール欠如（jq を PATH から外す）
# --------------------------------------------------
no_jq_dir="${tmp_root}/no-jq-path"
mkdir -p "$no_jq_dir"
for tool in bash grep head wc tr cat mktemp; do
  tool_path="$(command -v "$tool")"
  ln -sf "$tool_path" "${no_jq_dir}/${tool}"
done
actual=0
last_output=$(PATH="$no_jq_dir" "$bash_bin" "$target_script" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-ok.json" 2>&1) || actual=$?
if [ "$actual" -eq 3 ]; then
  echo "PASS: missing-jq (exit=${actual})"
else
  echo "FAIL: missing-jq (expected exit=3, actual exit=${actual})" >&2
  print_indented "$last_output"
  failures=$((failures + 1))
fi

# --------------------------------------------------
# サマリー
# --------------------------------------------------
if [ "$failures" -eq 0 ]; then
  echo "all fio-baseline-ratio.sh selftest cases passed"
  exit 0
fi
echo "${failures} fio-baseline-ratio.sh selftest case(s) failed" >&2
exit 1
