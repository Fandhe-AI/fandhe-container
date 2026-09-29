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
# case 2b: argv 長上限の回避確認（Linux の 1 引数あたりの上限〔MAX_ARG_STRLEN・
# 通常 128 KiB〕を、4 MiB まで許す契約の入力〔ここでは約 300 KiB〕で越え、
# `--argjson` 経由なら `Argument list too long` で終了コード 126 になっていた
# ケースが、stdin 経由になったことで exit 0・正しい比率を返すことを照合する）
# --------------------------------------------------
padded_path="${tmp_root}/baseline-padded.json"
jq '.pad = ("a" * 300000)' "${fixtures_dir}/baseline-ok.json" >"$padded_path"
run_case "padded-input-exceeds-argv-limit" 0 --baseline "$padded_path" --candidate "${fixtures_dir}/candidate-ok.json"
if [ "$last_case_passed" -eq 1 ]; then
  check_jq_value "padded-input-ratio-iops" "1.5" ".ratios.iops.value"
fi

# --------------------------------------------------
# case 3: params 不一致
# --------------------------------------------------
run_case_msg "params-mismatch" 2 "direct" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-params-mismatch.json"

# --------------------------------------------------
# case 4: baseline の IOPS が 0
# --------------------------------------------------
run_case_msg "baseline-zero-iops" 2 "greater than 0" --baseline "${fixtures_dir}/baseline-zero-iops.json" --candidate "${fixtures_dir}/candidate-ok.json"

# 4b: 極端に小さい candidate ÷ 大きい baseline は倍率がアンダーフローで 0 になるため拒否する
underflow_path="${tmp_root}/candidate-underflow.json"
jq '.metrics.fio_randwrite_4k_iops.value = 1e-320' "${fixtures_dir}/candidate-ok.json" >"$underflow_path"
underflow_base="${tmp_root}/baseline-huge.json"
jq '.metrics.fio_randwrite_4k_iops.value = 1e300' "${fixtures_dir}/baseline-ok.json" >"$underflow_base"
run_case_msg "ratio-underflow-to-zero" 2 "finite positive" --baseline "$underflow_base" --candidate "$underflow_path"

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
# 前提ツール一式（jq・grep・head・wc・tr）を PATH に揃えたディレクトリを作り、
# 対象を 1 つずつ外して欠如時に終了コード 3 になることを照合する
# （対象スクリプトの前提ツール確認一覧との整合。fio-randwrite-4k-selftest.sh と
# 同方針）。
all_tools_dir="${tmp_root}/all-tools-path"
mkdir -p "$all_tools_dir"
for tool in bash jq grep head wc tr cat mktemp; do
  tool_path="$(command -v "$tool")"
  ln -sf "$tool_path" "${all_tools_dir}/${tool}"
done
for missing_tool in jq grep head wc tr; do
  case_dir="${tmp_root}/no-${missing_tool}-path"
  mkdir -p "$case_dir"
  for tool in bash jq grep head wc tr cat mktemp; do
    [ "$tool" = "$missing_tool" ] && continue
    ln -sf "${all_tools_dir}/${tool}" "${case_dir}/${tool}"
  done
  actual=0
  last_output=$(PATH="$case_dir" "$bash_bin" "$target_script" --baseline "${fixtures_dir}/baseline-ok.json" --candidate "${fixtures_dir}/candidate-ok.json" 2>&1) || actual=$?
  if [ "$actual" -eq 3 ]; then
    echo "PASS: missing-${missing_tool} (exit=${actual})"
  else
    echo "FAIL: missing-${missing_tool} (expected exit=3, actual exit=${actual})" >&2
    print_indented "$last_output"
    failures=$((failures + 1))
  fi
done

# --------------------------------------------------
# case 10: 1 ファイルに JSON 値が複数連結されている（--baseline）
# 後段の `jq -s` が先頭 2 個（.[0]/.[1]）しか使わないため、検証をすり抜けて
# 意図しない値同士の比率を算出しうる入力を拒否できることを照合する。
# --------------------------------------------------
multi_value_path="${tmp_root}/baseline-multi-value.json"
cat "${fixtures_dir}/baseline-ok.json" "${fixtures_dir}/candidate-ok.json" >"$multi_value_path"
run_case_msg "multi-json-value-rejected" 2 "exactly one JSON value" --baseline "$multi_value_path" --candidate "${fixtures_dir}/candidate-ok.json"

# --------------------------------------------------
# case 10b: NUL バイトを含む入力の拒否
# Bash の変数格納で NUL が除去されると、除去後の内容が正しい JSON なら検証を
# 通過してしまうため、変数格納前に元ファイルの NUL を拒否できることを照合する。
# --------------------------------------------------
nul_path="${tmp_root}/baseline-nul.json"
{
  head -c 10 "${fixtures_dir}/baseline-ok.json"
  printf '\000'
  tail -c +11 "${fixtures_dir}/baseline-ok.json"
} >"$nul_path"
run_case_msg "nul-byte-rejected" 2 "contains NUL bytes" --baseline "$nul_path" --candidate "${fixtures_dir}/candidate-ok.json"

# --------------------------------------------------
# case 11: params のキー欠落と null の区別
# baseline 側に params.extra = null（キーは存在する）を追加し、candidate 側には
# そのキー自体が無い場合、`$bp[.] != $cp[.]`（値のみの比較）だと両者とも
# jq 上で null になり一致と誤判定してしまう。キーの存在も比較対象にして
# 不一致として検出できることを照合する。
# --------------------------------------------------
params_null_path="${tmp_root}/baseline-params-null-key.json"
jq '.params.extra = null' "${fixtures_dir}/baseline-ok.json" >"$params_null_path"
run_case_msg "params-missing-vs-null-key" 2 "params differ" --baseline "$params_null_path" --candidate "${fixtures_dir}/candidate-ok.json"

# --------------------------------------------------
# サマリー
# --------------------------------------------------
if [ "$failures" -eq 0 ]; then
  echo "all fio-baseline-ratio.sh selftest cases passed"
  exit 0
fi
echo "${failures} fio-baseline-ratio.sh selftest case(s) failed" >&2
exit 1
