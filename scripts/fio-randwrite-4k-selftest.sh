#!/usr/bin/env bash
# scripts/fio-randwrite-4k.sh の自己テスト（TASK-25.1・IO-8・REPAIR-12）。
#
# 役割: 実 fio を必要としない `--from-json` モードと固定 fixture
# （scripts/testdata/fio-bench/）で、終了コードと変換結果の値を具体値で照合する
# （REPAIR-12: 受け入れ基準を機械照合する）。run モードの経路は起動コマンド組み立て
# （引数検証・symlink・上限チェック・欠如ツール検出・後始末）を最小の fio スタブで
# 確認する（実 fio は使わない）。専用サブディレクトリへの書き込み・事前に置かれた
# symlink を踏まないこと・--output の検証後に置かれた symlink を拒否することも
# スタブで照合する（security.md）。fio JSON の実行条件（job options・jobname・jobs 件数・
# error）の照合と総書き込み量（--size × --numjobs）の上限の境界も、fixture と
# 受け取ったオプションを job options に記録するスタブで照合する（IO-8）。
# run モードは対象スクリプト自体が GNU coreutils の
# `timeout`・`realpath` を要求する契約（Linux ホストのみ対象）のため、本自己テストの
# run モード関連ケースも同じ前提（Linux・GNU coreutils）を引き継ぐ。実測（実際の
# 書き込み性能）はここでは行わない（実測は docs/design/io-fio-bench.md の
# 「実機での確認」節を参照）。
# 呼び出し元は Makefile の `fio-bench-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 期待と異なる終了コード・値が 1 件でもあれば非ゼロで終了する（fail-closed）。
# 各ケースの失敗は failures に数えて最後まで実行を続け、末尾のサマリーで判定する
# （`set -e` 下で判定ヘルパーが非ゼロを返すと途中で打ち切られ、後続ケースと
# サマリーが出なくなるため、ヘルパーは常に 0 を返し、ケース結果は変数で渡す）。

set -euo pipefail
# 対象スクリプトは書き込み先の全パス要素に「group・other が書き込めない」ことを要求する。
# 作業ディレクトリの権限が実行環境の umask（002 等）に左右されないよう固定する。
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/fio-randwrite-4k.sh"
fixtures_dir="${script_dir}/testdata/fio-bench"
bench_check_script="${script_dir}/check-bench-regression.sh"
# 前提ツール欠如ケースで PATH を絞ると `bash` 自体が解決できなくなるため、
# 絶対パスを先に確定させてそちらを呼ぶ（PATH に依存しない起動経路）。
bash_bin="$(command -v bash)"

failures=0
tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

# 直近の run_case で対象スクリプトが出した stdout+stderr（失敗時の診断・
# メッセージ照合用）と、そのケースが期待どおりだったか（1/0）。
last_output=""
last_case_passed=0

# 失敗時の診断出力を字下げして stderr へ出す。PATH を絞ったケース（前提ツール
# 欠如の検証）でも動くよう、sed 等の外部コマンドを使わない。
print_indented() {
  local line
  while IFS= read -r line; do
    printf '  | %s\n' "$line" >&2
  done <<<"$1"
}

# 期待終了コードと実際の終了コードを照合する 1 ケース分の判定。失敗時は対象
# スクリプトの出力をそのまま表示し、CI のログだけで原因を追えるようにする。
# 引数: <ケース名> <期待終了コード> <target_script への残り引数...>
run_case() {
  local name="$1"
  local expected="$2"
  shift 2
  local actual=0
  # RUN_CASE_CWD を指定すると、その作業ディレクトリで対象スクリプトを起動する
  # （相対パス引数の扱いの確認用）
  last_output=$(cd "${RUN_CASE_CWD:-.}" && "$bash_bin" "$target_script" "$@" 2>&1) || actual=$?
  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: ${name} (exit=${actual})"
    last_case_passed=1
    return 0
  fi
  echo "FAIL: ${name} (expected exit=${expected}, actual exit=${actual})" >&2
  print_indented "$last_output"
  failures=$((failures + 1))
  last_case_passed=0
  # set -e で打ち切られないよう、失敗でも 0 を返す（結果は last_case_passed と failures）
  return 0
}

# run_case に加えて、出力に期待する文字列が含まれることを照合する（終了コードが
# 同じでも別の理由で止まっていないことを確かめる）。PATH を絞った状態でも
# 動くよう、外部コマンドを使わず bash のパターン照合で判定する。
# 引数: <ケース名> <期待終了コード> <期待する部分文字列> <target_script への残り引数...>
run_case_msg() {
  local name="$1"
  local expected="$2"
  local needle="$3"
  shift 3
  run_case "$name" "$expected" "$@"
  # 終了コードが違う時点で失敗は計上済み。メッセージ照合は重ねて数えない
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

# 期待する文字列内容とファイルの中身を照合する（symlink 経由の上書きが無いことの確認用）。
# 引数: <ケース名> <ファイル> <期待内容>
check_file_content() {
  local name="$1"
  local file="$2"
  local expected="$3"
  local actual
  actual=$(cat -- "$file" 2>/dev/null || echo "<unreadable>")
  if [ "$actual" = "$expected" ]; then
    echo "PASS: ${name}"
  else
    echo "FAIL: ${name} (expected content '${expected}', actual '${actual}': ${file})" >&2
    failures=$((failures + 1))
  fi
}

# find で数えたエントリ数を返す。find の失敗を `set -e` による打ち切りや 0 件扱い
# （空出力を合格とみなす fail-open）にせず、`error` を返して呼び出し側の数値比較を
# 失敗させる。引数: find への引数一式
count_entries() {
  local listing
  local count
  if ! listing=$(find "$@" 2>&1); then
    printf 'error'
    return 0
  fi
  if [ -z "$listing" ]; then
    printf '0'
    return 0
  fi
  count=$(printf '%s\n' "$listing" | wc -l | tr -d ' ') || count="error"
  printf '%s' "$count"
}

# 期待値が数値で、実際の値がそれと一致するか（`error` 等の非数値は不一致）
is_count() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -eq "$2" ]
}

# --------------------------------------------------
# --from-json モード（jq のみで完結。fio 不要）
# --------------------------------------------------
run_case "from-json-ok" 0 --from-json "${fixtures_dir}/fio-3-ok.json" --label docker_bind_mount
# 負例 fixture は実行条件（job options）を正しく持たせたうえで 1 点だけ壊している。
# 同じ exit 2 でも別の理由で止まっていないことをメッセージで照合する。
run_case_msg "from-json-missing-clat" 2 "clat_ns is missing" --from-json "${fixtures_dir}/fio-3-missing-clat.json" --label x
run_case_msg "from-json-zero-iops" 2 "iops must be a finite number greater than 0" --from-json "${fixtures_dir}/fio-3-zero-iops.json" --label x
run_case_msg "from-json-fio-2x-legacy" 2 "unsupported fio version" --from-json "${fixtures_dir}/fio-2-legacy.json" --label x
# 回帰テスト: capture(...)? は正規表現が不一致でも空ストリーム（jq 側は成功扱い）を
# 返すため、テストなしで放置すると壊れた version 文字列が「変換成功・空 JSON」と
# いう exit 0 の誤判定を通してしまう（fail-closed の穴）。バージョン文字列が
# "fio-" 接頭辞を持たない壊れた形式を、明示的に exit 2 で拒否することを確認する。
run_case_msg "from-json-unparseable-version" 2 "cannot parse fio version" --from-json "${fixtures_dir}/fio-3-bad-version.json" --label x
run_case "from-json-not-json" 2 --from-json "${fixtures_dir}/not-json.txt" --label x
run_case "from-json-invalid-label" 2 --from-json "${fixtures_dir}/fio-3-ok.json" --label "Bad Label"
run_case "from-json-missing-file" 2 --from-json "${fixtures_dir}/does-not-exist.json" --label x

# --------------------------------------------------
# 実行条件の照合（IO-8: fio_randwrite_4k_* として出してよいのは 4K ランダム write の
# 条件で実行された結果だけ。run モードと同じ条件以外の fio JSON は exit 2 で拒否する）
# --------------------------------------------------
run_case_msg "from-json-no-job-options" 2 "cannot verify that the run used the 4K random write conditions" --from-json "${fixtures_dir}/fio-3-no-job-options.json" --label x
run_case_msg "from-json-wrong-rw" 2 "fio option rw must be" --from-json "${fixtures_dir}/fio-3-wrong-rw.json" --label x
run_case_msg "from-json-wrong-bs" 2 "fio option bs must be 4k" --from-json "${fixtures_dir}/fio-3-wrong-bs.json" --label x
run_case_msg "from-json-wrong-jobname" 2 "jobs[0].jobname must be" --from-json "${fixtures_dir}/fio-3-wrong-jobname.json" --label x
run_case_msg "from-json-extra-option" 2 "unexpected fio options (only the options passed in run mode are accepted): rate_iops" --from-json "${fixtures_dir}/fio-3-extra-option.json" --label x
run_case_msg "from-json-two-jobs" 2 "exactly one entry" --from-json "${fixtures_dir}/fio-3-two-jobs.json" --label x
run_case_msg "from-json-job-error" 2 "jobs[0].error must be present and 0 (got 5)" --from-json "${fixtures_dir}/fio-3-job-error.json" --label x
# time_based は総書き込み量の上限を無効にするため受け付けない（Codex P1）
run_case_msg "from-json-time-based-present" 2 "unexpected fio options (only the options passed in run mode are accepted): time_based" --from-json "${fixtures_dir}/fio-3-time-based-present.json" --label x
# 同じ fixture でも、CLI の条件（既定値を含む）と食い違えば拒否する（出力の params が
# 元の fio 実行条件と一致することの保証）
run_case_msg "from-json-size-mismatch" 2 "size must match --size 512m" --from-json "${fixtures_dir}/fio-3-ok.json" --label x --size 512m
run_case_msg "from-json-direct-mismatch" 2 "direct must match --direct 0" --from-json "${fixtures_dir}/fio-3-ok.json" --label x --direct 0
run_case_msg "from-json-iodepth-mismatch" 2 "iodepth must match --iodepth 4" --from-json "${fixtures_dir}/fio-3-ok.json" --label x --iodepth 4
run_case_msg "from-json-numjobs-mismatch" 2 "numjobs must match --numjobs 2" --from-json "${fixtures_dir}/fio-3-ok.json" --label x --numjobs 2
run_case_msg "from-json-runtime-60-default-cli" 2 "runtime must match --runtime 30" --from-json "${fixtures_dir}/fio-3-runtime-60.json" --label x
run_case "from-json-runtime-60-matching-cli" 0 --from-json "${fixtures_dir}/fio-3-runtime-60.json" --label x --runtime 60
# 表記ゆれ（size=256M・runtime=30s・bs=4096）は正規化して同じ条件として受け付ける
run_case "from-json-normalized-units" 0 --from-json "${fixtures_dir}/fio-3-normalized-units.json" --label x
# global options に置かれた条件も job options と合わせた実効値で照合する
run_case "from-json-global-options" 0 --from-json "${fixtures_dir}/fio-3-global-options.json" --label x
# --target-dir は run モード専用。併用すると黙って無視されるため拒否する
run_case_msg "from-json-with-target-dir" 2 "cannot be combined with --from-json" --from-json "${fixtures_dir}/fio-3-ok.json" --label x --target-dir /tmp

# 必須オプションの欠落（Codex P1: 「値があるときだけ照合」の穴を塞いだことの確認）。
# 許可リストの 14 項目それぞれを fio-3-ok.json の job options から 1 つだけ消した
# JSON を作り、どれを消しても exit 2 かつその項目名を挙げて拒否することを照合する。
missing_dir="${tmp_root}/missing-option-fixtures"
mkdir -p "$missing_dir"
for key in name directory filename rw bs ioengine direct size runtime iodepth numjobs end_fsync group_reporting; do
  missing_fixture="${missing_dir}/fio-3-missing-${key}.json"
  jq --arg k "$key" 'del(.jobs[0]["job options"][$k])' "${fixtures_dir}/fio-3-ok.json" >"$missing_fixture" 2>/dev/null || true
  run_case_msg "from-json-missing-option-${key}" 2 "fio option ${key} " --from-json "$missing_fixture" --label x
done

# directory の形式（空でない・絶対パス・':' を含まない）と global options の型
make_variant() {
  # 引数: <出力ファイル名> <jq フィルタ>。fio-3-ok.json を jq で 1 点だけ変えた JSON を作る
  jq "$2" "${fixtures_dir}/fio-3-ok.json" >"${missing_dir}/$1" 2>/dev/null || true
}
make_variant "empty-directory.json" '.jobs[0]["job options"].directory = ""'
make_variant "relative-directory.json" '.jobs[0]["job options"].directory = "relative/dir"'
make_variant "colon-directory.json" '.jobs[0]["job options"].directory = "/data:/other"'
make_variant "global-options-false.json" '. + {"global options": false}'
run_case_msg "from-json-empty-directory" 2 "fio option directory must be present and non-empty" --from-json "${missing_dir}/empty-directory.json" --label x
run_case_msg "from-json-relative-directory" 2 "fio option directory must be an absolute path" --from-json "${missing_dir}/relative-directory.json" --label x
run_case_msg "from-json-colon-directory" 2 "fio option directory must not contain a colon" --from-json "${missing_dir}/colon-directory.json" --label x
run_case_msg "from-json-global-options-not-object" 2 '"global options" must be an object' --from-json "${missing_dir}/global-options-false.json" --label x

# symlink 入力の拒否（security.md のパストラバーサル・symlink 対策）
sym_input="${tmp_root}/sym-input.json"
ln -s "${fixtures_dir}/fio-3-ok.json" "$sym_input"
run_case "from-json-symlink-input" 2 --from-json "$sym_input" --label x

# --from-json のサイズ上限超過（DoS 防止。MAX_FROM_JSON_BYTES=4MiB を 1 バイトだけ超える）
oversized_input="${tmp_root}/oversized.json"
head -c $((4 * 1024 * 1024 + 1)) /dev/zero >"$oversized_input"
run_case_msg "from-json-oversized-input" 2 "exceeds 4194304 bytes" --from-json "$oversized_input" --label x
# 境界: ちょうど上限（4 MiB）はサイズ判定を通る（中身は JSON でないため変換で拒否）
at_limit_input="${tmp_root}/at-limit.json"
head -c $((4 * 1024 * 1024)) /dev/zero >"$at_limit_input"
run_case_msg "from-json-at-limit-input-passes-size-check" 2 "jq: error" --from-json "$at_limit_input" --label x
if [[ "$last_output" == *"exceeds"* ]]; then
  echo "FAIL: from-json-at-limit-input-not-rejected-by-size (rejected by the size cap at exactly the limit)" >&2
  failures=$((failures + 1))
else
  echo "PASS: from-json-at-limit-input-not-rejected-by-size"
fi

# --------------------------------------------------
# 値の照合（from-json-ok が exit 0 で返す JSON の各値が期待どおりか。
# 真偽値のみの assert に頼らず具体値で照合する。coding-rust.md）
# --------------------------------------------------
# 期待値は JSON リテラルで渡し、jq の中で JSON の値として比較する（`jq -e`）。
# jq の数値の文字列表現は版で異なる（jq 1.6 は 1000.0 を `1000`、jq 1.7 はリテラルの
# まま `1000.0` と出力する）ため、`jq -r` の出力を文字列比較しない。
# 引数: <ケース名> <JSON ファイル> <jq フィルタ> <期待値の JSON リテラル>
check_json_value() {
  local name="$1"
  local json_file="$2"
  local jq_filter="$3"
  local expected_json="$4"
  local actual
  actual=$(jq -c "$jq_filter" "$json_file" 2>/dev/null || echo "<unreadable>")
  if jq -e --argjson want "$expected_json" "(${jq_filter}) == \$want" "$json_file" >/dev/null 2>&1; then
    echo "PASS: ${name} (${actual})"
  else
    echo "FAIL: ${name} (expected ${expected_json}, actual ${actual})" >&2
    failures=$((failures + 1))
  fi
}

from_json_ok_out="${tmp_root}/from-json-ok-out.json"
"$bash_bin" "$target_script" --from-json "${fixtures_dir}/fio-3-ok.json" --label docker_bind_mount >"$from_json_ok_out" 2>/dev/null || true
check_value() {
  check_json_value "value-$1" "$from_json_ok_out" "$2" "$3"
}

check_value "schema-version" ".schema_version" '1'
check_value "benchmark" ".benchmark" '"fio_randwrite_4k"'
check_value "label" ".label" '"docker_bind_mount"'
check_value "target-kind" ".target_kind" '"from_json"'
check_value "iops" ".metrics.fio_randwrite_4k_iops.value" '1000'
check_value "iops-unit" ".metrics.fio_randwrite_4k_iops.unit" '"ops/s"'
check_value "lat-mean-us" ".metrics.fio_randwrite_4k_lat_mean_us.value" '500'
check_value "clat-p50-us" ".metrics.fio_randwrite_4k_clat_p50_us.value" '400'
check_value "clat-p95-us" ".metrics.fio_randwrite_4k_clat_p95_us.value" '900'
check_value "clat-p99-us" ".metrics.fio_randwrite_4k_clat_p99_us.value" '1300'
check_value "params-rw" ".params.rw" '"randwrite"'
check_value "params-bs" ".params.bs" '"4k"'
check_value "params-ioengine" ".params.ioengine" '"psync"'
check_value "params-end-fsync" ".params.end_fsync" '1'

# --------------------------------------------------
# check-bench-regression.sh との回帰比較の round-trip（出力がそのまま
# results.json として受け入れられることの確認。TASK-88・TASK-113 での再利用の
# 前提を機械照合する）
# --------------------------------------------------
results_json="${tmp_root}/results.json"
# 準備段階の失敗でも set -e で打ち切らず、下の round-trip 判定の FAIL として数える
"$bash_bin" "$target_script" --from-json "${fixtures_dir}/fio-3-ok.json" --label docker_bind_mount >"$results_json" 2>/dev/null || true

baseline_json="${tmp_root}/baseline.json"
jq '{
  schema_version: 1,
  metrics: (.metrics | with_entries(.value += {direction: (
    if (.key | test("_iops$")) then "higher_is_better" else "lower_is_better" end
  )}))
}' "$results_json" >"$baseline_json" 2>/dev/null || true

roundtrip_actual=0
roundtrip_output=$(bash "$bench_check_script" "$baseline_json" "$results_json" 2>&1) || roundtrip_actual=$?
if [ "$roundtrip_actual" -eq 0 ]; then
  echo "PASS: results-json-compatible-with-bench-regression (exit=${roundtrip_actual})"
else
  echo "FAIL: results-json-compatible-with-bench-regression (expected exit=0, actual exit=${roundtrip_actual})" >&2
  print_indented "$roundtrip_output"
  failures=$((failures + 1))
fi

# --------------------------------------------------
# --output 指定時の書き込み・既存ファイルへの上書き拒否
# --------------------------------------------------
out_path="${tmp_root}/out.json"
run_case "output-write" 0 --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "$out_path"
if [ -s "$out_path" ]; then
  echo "PASS: output-file-written"
else
  echo "FAIL: output-file-written (file missing or empty: $out_path)" >&2
  failures=$((failures + 1))
fi
run_case "output-refuse-overwrite" 2 --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "$out_path"

# --output が dangling symlink の場合も拒否し、リンク先を作らない（`-e` は dangling
# symlink を「存在しない」と判定するため、`-L` 判定が先に効いていることの確認）
dangling_victim="${tmp_root}/dangling-victim.json"
dangling_link="${tmp_root}/dangling-link.json"
ln -s "$dangling_victim" "$dangling_link"
run_case "output-refuse-dangling-symlink" 2 --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "$dangling_link"
if [ ! -e "$dangling_victim" ]; then
  echo "PASS: output-dangling-symlink-target-not-created"
else
  echo "FAIL: output-dangling-symlink-target-not-created (created: $dangling_victim)" >&2
  failures=$((failures + 1))
fi

# --output の親ディレクトリが存在しない場合は入力エラー（exit 2）として弾く
# （回帰テスト: `printf ... >"$output_path"` の書き込み失敗に丸投げすると
# `set -e` 経由で「fio 実行失敗」（exit 1）に誤分類されていた）。
run_case "output-parent-missing" 2 --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${tmp_root}/no-such-dir-xyz/out.json"

# --output の親ディレクトリが書き込み不可の場合も同様に exit 2（root 実行では
# permission bit が強制されないため他の readonly ケースと同様に skip する）。
readonly_output_dir="${tmp_root}/readonly-output-dir"
mkdir -p "$readonly_output_dir"
chmod 555 "$readonly_output_dir"
if [ "$(id -u)" -eq 0 ]; then
  echo "SKIP: output-parent-readonly (running as root, permission bits are not enforced)"
else
  run_case "output-parent-readonly" 2 --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${readonly_output_dir}/out.json"
fi
chmod 755 "$readonly_output_dir"

# --------------------------------------------------
# run モード: 引数検証・ツール欠如検出（実 fio は使わない）
# --------------------------------------------------
# jq が無い PATH（全モード共通の前提ツール欠如。exit 3。`bash` 自体は絶対パスで
# 起動するため PATH を空にしても解決できる）
empty_bin="${tmp_root}/empty-bin"
mkdir -p "$empty_bin"
PATH="$empty_bin" run_case_msg "missing-jq-tool" 3 "jq is required" --from-json "${fixtures_dir}/fio-3-ok.json" --label x

# jq だけがある PATH（coreutils 系の前提ツール欠如。exit 3。欠如したまま進むと
# `set -e` 経由で exit 1「fio 実行失敗」に誤分類されていた穴の回帰テスト）
jq_only_bin="${tmp_root}/jq-only-bin"
mkdir -p "$jq_only_bin"
ln -s "$(command -v jq)" "${jq_only_bin}/jq"
PATH="$jq_only_bin" run_case_msg "missing-grep-tool" 3 "grep is required" --from-json "${fixtures_dir}/fio-3-ok.json" --label x

# 全モード共通の前提ツールは揃っているが fio が無い PATH（run モードのみの前提
# ツール欠如。exit 3。fio の欠如そのものを検出していることをメッセージで確認する）
common_bin="${tmp_root}/common-bin"
mkdir -p "$common_bin"
for tool in jq grep dirname basename wc tr mktemp find ln head sleep id; do
  ln -s "$(command -v "$tool")" "${common_bin}/${tool}"
done
PATH="$common_bin" run_case_msg "missing-fio-tool" 3 "fio is required" --target-dir /tmp --label x

# 最小の fio スタブ（固定 JSON を --output へ書き出すだけ）を作り、既存 PATH の
# 先頭に足すことで「fio・timeout・jq は揃っている」状態を作る（bash 解決に
# 使う既存 PATH は残すため、以降のケースは stub_bin を PATH の先頭に prefix する）。
stub_bin="${tmp_root}/stub-bin"
mkdir -p "$stub_bin"
# fio スタブは実 fio と同じく、受け取った `--key=value`・値なしフラグ（`--group_reporting` 等）
# を `jobs[0]["job options"]` に正規名→入力文字列（フラグは空文字列）で記録した JSON を
# --output へ書く（fio 本体の parse.c `add_to_dump_list`・stat.c `json_add_job_opts` と
# 同じ形。run モードの出力も --from-json と同じ実行条件の照合を通ることを確かめるため）。
# 加えて --directory/--filename が指す固定データファイルも実際に作る
# （run-cleanup-no-leftover-files が「後始末で実在するファイルが消える」ことを確認
# できるようにするため）。
fio_stub="${stub_bin}/fio"
cat >"$fio_stub" <<STUB
#!/usr/bin/env bash
fixture="${fixtures_dir}/fio-3-ok.json"
STUB
cat >>"$fio_stub" <<'STUB'
out="" dir="" fname="" opts='{}'
for a in "$@"; do
  case "$a" in
    --output=*) out="${a#--output=}" ;;
    --output-format=*) ;;
    --*=*)
      k="${a%%=*}"
      k="${k#--}"
      v="${a#*=}"
      [ "$k" = directory ] && dir="$v"
      [ "$k" = filename ] && fname="$v"
      opts=$(jq -c --arg k "$k" --arg v "$v" '. + {($k): $v}' <<<"$opts")
      ;;
    --*) opts=$(jq -c --arg k "${a#--}" '. + {($k): ""}' <<<"$opts") ;;
  esac
done
# 受け取った --output（fio の JSON 出力先。一時ディレクトリの中）を記録する
[ -n "${FIO_STUB_OUT_LOG:-}" ] && echo "$out" >"$FIO_STUB_OUT_LOG"
# 受け取った --directory を記録する（書き込み先が専用サブディレクトリであることの照合用）
[ -n "${FIO_STUB_DIR_LOG:-}" ] && echo "$dir" >"$FIO_STUB_DIR_LOG"
# 実 fio と同じく、データファイルを symlink をたどる形（O_CREAT・O_EXCL なし）で書く
[ -n "$dir" ] && [ -n "$fname" ] && echo stub-fio-data >"$dir/$fname"
# 実行中に第三者が symlink を置く競合（TOCTOU）を再現するためのフック
[ -n "${FIO_STUB_PLANT_LINK:-}" ] && ln -s "$FIO_STUB_PLANT_TARGET" "$FIO_STUB_PLANT_LINK"
[ -n "${FIO_STUB_PLANT_DIR:-}" ] && mkdir "$FIO_STUB_PLANT_DIR"
# 出力 JSON を書かずに成功終了する fio を再現するためのフック
[ -n "${FIO_STUB_NO_OUTPUT:-}" ] && exit 0
# 受け取ったオプション（上書き前）を記録する（run モードが渡す引数の照合用）
[ -n "${FIO_STUB_OPTS_LOG:-}" ] && printf '%s\n' "$opts" >"$FIO_STUB_OPTS_LOG"
# 記録するオプションを上書きする（run モードでも実行条件の照合が効くことの確認用）
[ -n "${FIO_STUB_OVERRIDE_OPTS:-}" ] && opts=$(jq -c --argjson o "$FIO_STUB_OVERRIDE_OPTS" '. + $o' <<<"$opts")
jq --argjson o "$opts" '.jobs[0]["job options"] = $o' "$fixture" >"$out"
exit 0
STUB
chmod +x "$fio_stub"
stub_path="${stub_bin}:${PATH}"

PATH="$stub_path" run_case "run-invalid-runtime-zero" 2 --target-dir /tmp --label x --runtime 0
# 回帰テスト: 先頭ゼロの数値は `$((...))` の 8 進数解釈で「fio 失敗」（exit 1）に
# 化けたり、無効な JSON 数値として argjson エラーになったりしうるため、入力検証の
# 段階で確実に exit 2 になることを確認する。
PATH="$stub_path" run_case "run-invalid-runtime-leading-zero" 2 --target-dir /tmp --label x --runtime 08
PATH="$stub_path" run_case "run-invalid-size-leading-zero" 2 --target-dir /tmp --label x --size 08m
PATH="$stub_path" run_case "run-invalid-size-oversized" 2 --target-dir /tmp --label x --size 999999g
PATH="$stub_path" run_case "run-invalid-iodepth" 2 --target-dir /tmp --label x --iodepth 999
PATH="$stub_path" run_case "run-invalid-numjobs" 2 --target-dir /tmp --label x --numjobs 0
PATH="$stub_path" run_case "run-invalid-direct" 2 --target-dir /tmp --label x --direct 2
PATH="$stub_path" run_case "run-nonexistent-target-dir" 2 --target-dir /no-such-fandhe-fio-dir --label x
run_case "run-missing-label" 2 --target-dir /tmp
PATH="$stub_path" run_case_msg "run-missing-target-dir" 2 "--target-dir is required in run mode" --label x

# 総書き込み量の上限（--size はジョブごとの値のため --size × --numjobs ≤ 10 GiB。
# DoS 防止）の境界。スタブは --size 分を実際には書かない
cap_target="${tmp_root}/cap-target"
mkdir -p "$cap_target"
PATH="$stub_path" run_case "run-total-size-10g-x1-at-cap" 0 --target-dir "$cap_target" --label x --runtime 5 --size 10g
PATH="$stub_path" run_case "run-total-size-5g-x2-at-cap" 0 --target-dir "$cap_target" --label x --runtime 5 --size 5g --numjobs 2
PATH="$stub_path" run_case "run-total-size-10240m-x1-at-cap" 0 --target-dir "$cap_target" --label x --runtime 5 --size 10240m
PATH="$stub_path" run_case_msg "run-total-size-10241m-x1-over-cap" 2 "total cap" --target-dir "$cap_target" --label x --runtime 5 --size 10241m
PATH="$stub_path" run_case_msg "run-total-size-5g-x3-over-cap" 2 "total cap" --target-dir "$cap_target" --label x --runtime 5 --size 5g --numjobs 3
PATH="$stub_path" run_case_msg "run-total-size-10g-x2-over-cap" 2 "total cap" --target-dir "$cap_target" --label x --runtime 5 --size 10g --numjobs 2
# --from-json でも同じ上限を課す（params の契約は両モード共通）
run_case_msg "from-json-total-size-over-cap" 2 "total cap" --from-json "${fixtures_dir}/fio-3-ok.json" --label x --size 5g --numjobs 3

# run モードの fio 出力にも同じ実行条件の照合をかける（fio が別条件で走った場合を
# スタブの記録オプション上書きで再現する）
opts_target="${tmp_root}/opts-target"
mkdir -p "$opts_target"
FIO_STUB_OVERRIDE_OPTS='{"rw":"randrw"}' PATH="$stub_path" run_case_msg "run-fio-options-mismatch" 2 "fio option rw must be" --target-dir "$opts_target" --label x --runtime 5
# run モードでは directory が本スクリプトの作った専用サブディレクトリと一致することまで照合する
FIO_STUB_OVERRIDE_OPTS='{"directory":"/somewhere/else"}' PATH="$stub_path" run_case_msg "run-fio-directory-mismatch" 2 "must be the private working directory of this run" --target-dir "$opts_target" --label x --runtime 5

# fio が exit 0 でも出力 JSON を書かなかった場合は fio 側の失敗（exit 1）として扱う
FIO_STUB_NO_OUTPUT=1 PATH="$stub_path" run_case_msg "run-fio-no-output" 1 "did not write its JSON output" --target-dir "$opts_target" --label x --runtime 5

# run モードの出力の params・target_kind が実際に fio へ渡した条件を表すこと
run_out="${tmp_root}/run-out.json"
PATH="$stub_path" run_case "run-ok-output-params" 0 --target-dir "$opts_target" --label x --runtime 5 --numjobs 2 --output "$run_out"
check_json_value "run-output-params-values" "$run_out" '[.target_kind, .params.runtime, .params.numjobs, .params.size]' '["run", 5, 2, "256m"]'

sym_target="${tmp_root}/sym-target"
real_target="${tmp_root}/real-target"
mkdir -p "$real_target"
ln -s "$real_target" "$sym_target"
PATH="$stub_path" run_case "run-symlink-target-dir" 2 --target-dir "$sym_target" --label x

# ':' を含む --target-dir の拒否（fio が --directory/--filename の ':' を
# ディレクトリ・ファイル名リストの区切り文字として解釈する仕様への対策。
# security.md の「ボリューム外へ書き込める経路を作らない」）
colon_target="${tmp_root}/colon:target"
mkdir -p "$colon_target"
PATH="$stub_path" run_case "run-target-dir-with-colon" 2 --target-dir "$colon_target" --label x

readonly_target="${tmp_root}/readonly-target"
mkdir -p "$readonly_target"
chmod 555 "$readonly_target"
if [ "$(id -u)" -eq 0 ]; then
  echo "SKIP: run-readonly-target-dir (running as root, permission bits are not enforced)"
else
  PATH="$stub_path" run_case "run-readonly-target-dir" 2 --target-dir "$readonly_target" --label x
fi
chmod 755 "$readonly_target"

# 他ユーザー書き込み可能で sticky bit が無い --target-dir は拒否する（作成した専用
# サブディレクトリを第三者が symlink へ差し替える競合を防ぐ。security.md）
ww_target="${tmp_root}/world-writable-target"
mkdir -p "$ww_target"
chmod 777 "$ww_target"
PATH="$stub_path" run_case_msg "run-world-writable-no-sticky-target-dir" 2 "can be modified by other users" --target-dir "$ww_target" --label x
chmod 755 "$ww_target"

# sticky bit 付き（/tmp と同じ 1777）は許容する
sticky_target="${tmp_root}/sticky-target"
mkdir -p "$sticky_target"
chmod 1777 "$sticky_target"
PATH="$stub_path" run_case "run-sticky-world-writable-target-dir" 0 --target-dir "$sticky_target" --label x --runtime 5
chmod 755 "$sticky_target"

# run モードの正常系（fio スタブ経由。データファイルが専用サブディレクトリに書かれ、
# 後始末でサブディレクトリごと残らないことも確認する）
run_target="${tmp_root}/run-target"
mkdir -p "$run_target"
dir_log="${tmp_root}/fio-stub-dir.log"
FIO_STUB_DIR_LOG="$dir_log" PATH="$stub_path" run_case "run-ok-with-stub" 0 --target-dir "$run_target" --label local_tmp --runtime 5
stub_dir=$(cat -- "$dir_log" 2>/dev/null || true)
case "$stub_dir" in
  "${run_target}"/fandhe-fio-randwrite-4k.??????????)
    echo "PASS: run-uses-private-subdir (${stub_dir})"
    ;;
  *)
    echo "FAIL: run-uses-private-subdir (fio --directory was '${stub_dir}', expected ${run_target}/fandhe-fio-randwrite-4k.XXXXXXXXXX)" >&2
    failures=$((failures + 1))
    ;;
esac
leftover_count=$(count_entries "$run_target" -mindepth 1)
if is_count "$leftover_count" 0; then
  echo "PASS: run-cleanup-no-leftover-files"
else
  echo "FAIL: run-cleanup-no-leftover-files (found ${leftover_count} leftover entries under $run_target)" >&2
  failures=$((failures + 1))
fi

# 回帰テスト（security.md・symlink 経由のボリューム外書き込み）: --target-dir 直下に
# 固定データファイル名の symlink をボリューム外の victim へ向けて事前に置いても、
# fio（スタブは実 fio と同じく symlink をたどって書く）は専用サブディレクトリへ書く
# ため victim は変更されない。事前検査での拒否ではなくサブディレクトリ方式にした
# 理由（TOCTOU）は fio-randwrite-4k.sh の run_dir 作成箇所のコメントを参照。
attack_target="${tmp_root}/attack-target"
mkdir -p "$attack_target"
victim_file="${tmp_root}/victim.txt"
printf 'victim-original-content\n' >"$victim_file"
ln -s "$victim_file" "${attack_target}/fandhe-fio-randwrite-4k.dat"
PATH="$stub_path" run_case "run-preplaced-data-file-symlink" 0 --target-dir "$attack_target" --label x --runtime 5
check_file_content "run-preplaced-symlink-victim-unchanged" "$victim_file" "victim-original-content"
if [ -L "${attack_target}/fandhe-fio-randwrite-4k.dat" ]; then
  echo "PASS: run-preplaced-symlink-left-untouched"
else
  echo "FAIL: run-preplaced-symlink-left-untouched (symlink was removed or replaced)" >&2
  failures=$((failures + 1))
fi
attack_leftover=$(count_entries "$attack_target" -mindepth 1 ! -name fandhe-fio-randwrite-4k.dat)
if is_count "$attack_leftover" 0; then
  echo "PASS: run-preplaced-symlink-no-leftover-subdir"
else
  echo "FAIL: run-preplaced-symlink-no-leftover-subdir (found ${attack_leftover} leftover entries under $attack_target)" >&2
  failures=$((failures + 1))
fi

# 回帰テスト（--output の検証後に symlink を置かれる競合。TOCTOU）: fio 実行中に
# --output のパスへ victim（既存の通常ファイル）を指す symlink を置いても、一時ファイル
# からのハードリンク作成（宛先が存在すれば失敗し、symlink をたどらない）で排他的に
# 作るため書き込みを拒否し（exit 2）、victim は変更されない。
race_target="${tmp_root}/race-target"
mkdir -p "$race_target"
race_victim="${tmp_root}/race-victim.txt"
printf 'race-victim-original\n' >"$race_victim"
race_output="${tmp_root}/race-output.json"
FIO_STUB_PLANT_LINK="$race_output" FIO_STUB_PLANT_TARGET="$race_victim" PATH="$stub_path" \
  run_case_msg "run-output-symlink-planted-during-run" 2 "could not be created exclusively" \
  --target-dir "$race_target" --label x --runtime 5 --output "$race_output"
check_file_content "run-output-race-victim-unchanged" "$race_victim" "race-victim-original"
# --output の書き込みに失敗したときは stdout に結果 JSON を出さない（呼び出し元は
# exit 0 のときだけ stdout を結果として読む）
if [[ "$last_output" != *'"schema_version"'* ]]; then
  echo "PASS: run-output-failure-emits-no-result"
else
  echo "FAIL: run-output-failure-emits-no-result (result JSON was printed although --output failed)" >&2
  failures=$((failures + 1))
fi

# 回帰テスト（Codex P0）: 検証後に --output のパスへ FIFO を指す symlink を置かれても
# リンク先を開かない。旧実装（bash の noclobber）は既存の通常ファイル以外を
# O_CREAT なしで開くため、読み手のいない FIFO の open で止まっていた。ハングを
# 検出できるよう timeout 付きで起動し、124（タイムアウト）ではなく 2 を期待する。
race_fifo="${tmp_root}/race-fifo"
mkfifo "$race_fifo"
race_fifo_output="${tmp_root}/race-fifo-output.json"
fifo_actual=0
fifo_out=$(FIO_STUB_PLANT_LINK="$race_fifo_output" FIO_STUB_PLANT_TARGET="$race_fifo" PATH="$stub_path" \
  timeout -k 5s 30s "$bash_bin" "$target_script" --target-dir "$race_target" --label x --runtime 5 \
  --output "$race_fifo_output" 2>&1) || fifo_actual=$?
if [ "$fifo_actual" -eq 2 ] && [[ "$fifo_out" == *"could not be created exclusively"* ]]; then
  echo "PASS: run-output-fifo-symlink-planted-during-run (exit=${fifo_actual})"
else
  echo "FAIL: run-output-fifo-symlink-planted-during-run (expected exit=2 with 'could not be created exclusively', actual exit=${fifo_actual}; 124 means the FIFO was opened)" >&2
  print_indented "$fifo_out"
  failures=$((failures + 1))
fi
if [ -p "$race_fifo" ] && [ -L "$race_fifo_output" ]; then
  echo "PASS: run-output-fifo-and-symlink-left-untouched"
else
  echo "FAIL: run-output-fifo-and-symlink-left-untouched (FIFO or planted symlink was replaced)" >&2
  failures=$((failures + 1))
fi

# 検証後にディレクトリを指す symlink を置かれても、その中へ書かない（`ln -n`）
race_linked_dir="${tmp_root}/race-linked-dir"
mkdir -p "$race_linked_dir"
race_dirlink_output="${tmp_root}/race-dirlink-output.json"
FIO_STUB_PLANT_LINK="$race_dirlink_output" FIO_STUB_PLANT_TARGET="$race_linked_dir" PATH="$stub_path" \
  run_case_msg "run-output-dir-symlink-planted-during-run" 2 "could not be created exclusively" \
  --target-dir "$race_target" --label x --runtime 5 --output "$race_dirlink_output"
linked_dir_entries=$(count_entries "$race_linked_dir" -mindepth 1)
if is_count "$linked_dir_entries" 0; then
  echo "PASS: run-output-dir-symlink-target-unchanged"
else
  echo "FAIL: run-output-dir-symlink-target-unchanged (found ${linked_dir_entries} entries under $race_linked_dir)" >&2
  failures=$((failures + 1))
fi

# 検証後に実ディレクトリを置かれた場合（`ln` がその中へリンクを作る）も、--output の
# パスが作成した通常ファイルでないことを検出して exit 2 にする
race_realdir_output="${tmp_root}/race-realdir-output.json"
FIO_STUB_PLANT_DIR="$race_realdir_output" PATH="$stub_path" \
  run_case_msg "run-output-real-dir-planted-during-run" 2 "was replaced during the write" \
  --target-dir "$race_target" --label x --runtime 5 --output "$race_realdir_output"

# --output の親ディレクトリが他ユーザー書き込み可かつ sticky bit 無しなら拒否する
# （一時ファイルを差し替えられる競合への対策）
ww_output_dir="${tmp_root}/world-writable-output-dir"
mkdir -p "$ww_output_dir"
chmod 777 "$ww_output_dir"
run_case_msg "output-parent-world-writable-no-sticky" 2 "--output parent path component ${ww_output_dir} can be modified by other users" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${ww_output_dir}/out.json"
chmod 755 "$ww_output_dir"

# 成功・失敗のどちらの経路でも --output 用の一時ファイルが残らない
output_tmp_leftover=$(count_entries "$tmp_root" -maxdepth 1 -name '.fandhe-fio-output.*')
if is_count "$output_tmp_leftover" 0; then
  echo "PASS: output-no-leftover-temp-files"
else
  echo "FAIL: output-no-leftover-temp-files (found ${output_tmp_leftover} .fandhe-fio-output.* files under $tmp_root)" >&2
  failures=$((failures + 1))
fi

# --------------------------------------------------
# 全体自己監査の回帰テスト（TOCTOU・外部コマンドの失敗による fail-open・上限の
# すり抜け・symlink）。PR #1129 の Codex P0/P1 と同種の穴をまとめて照合する
# --------------------------------------------------
# ディレクトリの権限確認は find が「安全」と判定したときだけ通す（fail-closed）。
# find が失敗する・何も出力しない（旧実装は空出力を合格扱いにしていた）状況を
# find スタブで再現する。スタブ以外のツールは実物を使う。
# スタブは対象のディレクトリ（名前に perm-check- を含むもの）の判定だけを壊し、
# それ以外（一時ディレクトリ等の祖先の判定）は実物の find に渡す。
find_fail_bin="${tmp_root}/find-fail-bin"
find_empty_bin="${tmp_root}/find-empty-bin"
mkdir -p "$find_fail_bin" "$find_empty_bin"
real_find=$(command -v find)
# shellcheck disable=SC2016 # スタブへ書き出す文字列であり、$1 等はスタブ側で展開させる
printf '#!/usr/bin/env bash\ncase "$1" in *perm-check-*) echo "find: simulated failure" >&2; exit 1 ;; esac\nexec "%s" "$@"\n' "$real_find" >"${find_fail_bin}/find"
# shellcheck disable=SC2016 # 同上
printf '#!/usr/bin/env bash\ncase "$1" in *perm-check-*) exit 0 ;; esac\nexec "%s" "$@"\n' "$real_find" >"${find_empty_bin}/find"
chmod +x "${find_fail_bin}/find" "${find_empty_bin}/find"
perm_out_dir="${tmp_root}/perm-check-output"
mkdir -p "$perm_out_dir"
PATH="${find_fail_bin}:${PATH}" run_case_msg "output-parent-permission-check-find-fails" 2 "could not verify the permissions of --output parent path component" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${perm_out_dir}/a.json"
PATH="${find_empty_bin}:${PATH}" run_case_msg "output-parent-permission-check-find-empty" 2 "could not verify the permissions of --output parent path component" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${perm_out_dir}/b.json"
perm_target="${tmp_root}/perm-check-target"
mkdir -p "$perm_target"
PATH="${find_fail_bin}:${stub_path}" run_case_msg "target-dir-permission-check-find-fails" 2 "could not verify the permissions of --target-dir path component" \
  --target-dir "$perm_target" --label x --runtime 5
PATH="${find_empty_bin}:${stub_path}" run_case_msg "target-dir-permission-check-find-empty" 2 "could not verify the permissions of --target-dir path component" \
  --target-dir "$perm_target" --label x --runtime 5
perm_leftover=$(count_entries "$perm_out_dir" "$perm_target" -mindepth 1)
if is_count "$perm_leftover" 0; then
  echo "PASS: permission-check-failure-writes-nothing"
else
  echo "FAIL: permission-check-failure-writes-nothing (found ${perm_leftover} entries)" >&2
  failures=$((failures + 1))
fi

# サイズの判定は数値であることを確かめてから行う（wc の出力が非数値のとき
# `[ -gt ]` が偽になって上限判定を素通りするのを防ぐ）。wc スタブで再現する
wc_bad_bin="${tmp_root}/wc-bad-bin"
mkdir -p "$wc_bad_bin"
printf '#!/usr/bin/env bash\ncat >/dev/null\necho "not-a-number"\n' >"${wc_bad_bin}/wc"
chmod +x "${wc_bad_bin}/wc"
PATH="${wc_bad_bin}:${PATH}" run_case_msg "from-json-size-check-non-numeric-wc" 2 "could not determine the size of --from-json input" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x

# `-` で始まる相対パスの --output がオプションとして解釈されない（find・mktemp への
# 受け渡しで `./` を前置する）
mkdir -p "${tmp_root}/-dash-dir"
RUN_CASE_CWD="$tmp_root" run_case "output-relative-dash-dir" 0 \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "-dash-dir/out.json"
check_json_value "output-relative-dash-dir-written" "${tmp_root}/-dash-dir/out.json" '.schema_version' '1'

# 後始末（rm）の失敗が終了コードの契約を上書きしない（成功は 0、入力エラーは 2 の
# まま、警告を stderr に出す）。rm スタブで再現する
rm_fail_bin="${tmp_root}/rm-fail-bin"
mkdir -p "$rm_fail_bin"
printf '#!/usr/bin/env bash\nexit 1\n' >"${rm_fail_bin}/rm"
chmod +x "${rm_fail_bin}/rm"
# 消せずに残る本スクリプトの一時ディレクトリが tmp_root 配下に収まるよう TMPDIR を向ける
# （selftest 自身の後始末で実物の rm が消す）
rm_fail_tmp="${tmp_root}/rm-fail-tmpdir"
mkdir -p "$rm_fail_tmp"
TMPDIR="$rm_fail_tmp" PATH="${rm_fail_bin}:${PATH}" run_case_msg "cleanup-failure-keeps-exit-0" 0 "warning: cleanup-failed" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x
TMPDIR="$rm_fail_tmp" PATH="${rm_fail_bin}:${PATH}" run_case_msg "cleanup-failure-keeps-exit-2" 2 "warning: cleanup-failed" \
  --from-json "${fixtures_dir}/fio-3-wrong-rw.json" --label x

# ルートからの全パス要素の検証（Codex P0: 祖先ディレクトリの差し替え）。祖先・最終
# ディレクトリのどれかが group 書き込み可なら拒否し、何も作らない（chmod で再現できる範囲）
gw_parent="${tmp_root}/group-writable-ancestor"
mkdir -p "${gw_parent}/inner-target" "${gw_parent}/inner-output"
chmod 775 "$gw_parent"
PATH="$stub_path" run_case_msg "run-group-writable-ancestor-target-dir" 2 "path component ${gw_parent} can be modified by other users" \
  --target-dir "${gw_parent}/inner-target" --label x --runtime 5
run_case_msg "output-group-writable-ancestor" 2 "path component ${gw_parent} can be modified by other users" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${gw_parent}/inner-output/out.json"
gw_leftover=$(count_entries "${gw_parent}/inner-target" "${gw_parent}/inner-output" -mindepth 1)
if is_count "$gw_leftover" 0; then
  echo "PASS: group-writable-ancestor-writes-nothing"
else
  echo "FAIL: group-writable-ancestor-writes-nothing (found ${gw_leftover} entries)" >&2
  failures=$((failures + 1))
fi
chmod 755 "$gw_parent"
gw_final="${tmp_root}/group-writable-final"
mkdir -p "$gw_final"
chmod 775 "$gw_final"
PATH="$stub_path" run_case_msg "run-group-writable-final-target-dir" 2 "path component ${gw_final} can be modified by other users" \
  --target-dir "$gw_final" --label x --runtime 5
chmod 755 "$gw_final"

# 途中に symlink を含む --target-dir は実体へ解決してから全要素を検証し、以後は解決
# 済みのパスだけを使う（fio の --directory も実体側の専用サブディレクトリになる）
link_real_parent="${tmp_root}/link-real-parent"
mkdir -p "${link_real_parent}/target"
ln -s "$link_real_parent" "${tmp_root}/link-to-parent"
link_dir_log="${tmp_root}/fio-stub-dir-link.log"
FIO_STUB_DIR_LOG="$link_dir_log" PATH="$stub_path" run_case "run-target-dir-through-symlinked-ancestor" 0 \
  --target-dir "${tmp_root}/link-to-parent/target" --label x --runtime 5
link_stub_dir=$(cat -- "$link_dir_log" 2>/dev/null || true)
case "$link_stub_dir" in
  "${link_real_parent}"/target/fandhe-fio-randwrite-4k.??????????)
    echo "PASS: run-target-dir-resolved-before-use (${link_stub_dir})"
    ;;
  *)
    echo "FAIL: run-target-dir-resolved-before-use (fio --directory was '${link_stub_dir}', expected under ${link_real_parent}/target)" >&2
    failures=$((failures + 1))
    ;;
esac
# 途中の symlink の先が第三者に書き換え可能な場所なら、解決後の検証で拒否する
link_gw_parent="${tmp_root}/link-gw-parent"
mkdir -p "${link_gw_parent}/target"
chmod 775 "$link_gw_parent"
ln -s "$link_gw_parent" "${tmp_root}/link-to-gw-parent"
PATH="$stub_path" run_case_msg "run-target-dir-symlink-into-group-writable" 2 "path component ${link_gw_parent} can be modified by other users" \
  --target-dir "${tmp_root}/link-to-gw-parent/target" --label x --runtime 5
chmod 755 "$link_gw_parent"

# 一時ディレクトリ（TMPDIR）の祖先も検証する（スナップショットの差し替え対策）
gw_tmpdir="${tmp_root}/group-writable-tmpdir"
mkdir -p "$gw_tmpdir"
chmod 775 "$gw_tmpdir"
TMPDIR="$gw_tmpdir" run_case_msg "from-json-group-writable-tmpdir" 2 "temporary (TMPDIR) path component ${gw_tmpdir} can be modified by other users" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x
gw_tmp_leftover=$(count_entries "$gw_tmpdir" -mindepth 1)
if is_count "$gw_tmp_leftover" 0; then
  echo "PASS: group-writable-tmpdir-cleaned-up"
else
  echo "FAIL: group-writable-tmpdir-cleaned-up (found ${gw_tmp_leftover} entries)" >&2
  failures=$((failures + 1))
fi
chmod 755 "$gw_tmpdir"

# run モードは --time_based を渡さない（総書き込み量が --size × --numjobs 以下に
# なることの前提）。スタブが記録したオプションに time_based が無いことを照合する
nt_target="${tmp_root}/no-time-based-target"
mkdir -p "$nt_target"
nt_out="${tmp_root}/no-time-based-out.json"
nt_opts_log="${tmp_root}/fio-stub-opts.log"
FIO_STUB_OPTS_LOG="$nt_opts_log" PATH="$stub_path" run_case "run-without-time-based" 0 \
  --target-dir "$nt_target" --label x --runtime 5 --output "$nt_out"
check_json_value "run-fio-args-have-no-time-based" "$nt_opts_log" 'has("time_based")' 'false'
check_json_value "run-fio-args-runtime-and-size" "$nt_opts_log" '[.runtime, .size, .numjobs]' '["5", "256m", "1"]'

# 計測データ（run モードの専用サブディレクトリ）を後始末で削除できなければ、残った
# パスを出して exit 4 で終わる（Codex P1。大容量のデータが黙って残るのを防ぐ）。
# rm スタブ（失敗する・成功を装って何も消さない）で再現する。本来の終了コードが
# 非ゼロ（fio の出力が条件不一致で exit 2）でも exit 4 を優先し、元の値も出す。
rm_noop_bin="${tmp_root}/rm-noop-bin"
mkdir -p "$rm_noop_bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"${rm_noop_bin}/rm"
chmod +x "${rm_noop_bin}/rm"
data_left_tmp="${tmp_root}/data-left-tmpdir"
mkdir -p "$data_left_tmp"
for variant in fail noop; do
  if [ "$variant" = fail ]; then
    variant_bin="$rm_fail_bin"
  else
    variant_bin="$rm_noop_bin"
  fi
  data_left_target="${tmp_root}/data-left-target-${variant}"
  mkdir -p "$data_left_target"
  TMPDIR="$data_left_tmp" PATH="${variant_bin}:${stub_path}" run_case_msg "run-data-cleanup-${variant}-exits-4" 4 \
    "could not remove benchmark data (up to --size bytes may remain): ${data_left_target}/fandhe-fio-randwrite-4k." \
    --target-dir "$data_left_target" --label x --runtime 5
  data_left_count=$(count_entries "$data_left_target" -mindepth 2 -name fandhe-fio-randwrite-4k.dat)
  if is_count "$data_left_count" 1; then
    echo "PASS: run-data-cleanup-${variant}-data-really-left"
  else
    echo "FAIL: run-data-cleanup-${variant}-data-really-left (expected 1 leftover data file, found ${data_left_count})" >&2
    failures=$((failures + 1))
  fi
done
data_left_failed_target="${tmp_root}/data-left-target-failed-run"
mkdir -p "$data_left_failed_target"
TMPDIR="$data_left_tmp" FIO_STUB_OVERRIDE_OPTS='{"rw":"randrw"}' PATH="${rm_fail_bin}:${stub_path}" \
  run_case_msg "run-data-cleanup-fail-overrides-exit-2" 4 "the run had already failed with exit status 2" \
  --target-dir "$data_left_failed_target" --label x --runtime 5

# 一時ディレクトリは TMPDIR を先に実体へ解決・検証し、その下に mktemp -d したパスを
# そのまま使う（Cursor Medium）。TMPDIR が symlink 経由でも、fio の JSON 出力先は
# 実体側の fandhe-fio-bench.XXXXXXXXXX の中になる
tmpdir_real="${tmp_root}/tmpdir-real"
mkdir -p "$tmpdir_real"
ln -s "$tmpdir_real" "${tmp_root}/tmpdir-link"
tmpdir_target="${tmp_root}/tmpdir-target"
mkdir -p "$tmpdir_target"
out_log="${tmp_root}/fio-stub-out.log"
TMPDIR="${tmp_root}/tmpdir-link" FIO_STUB_OUT_LOG="$out_log" PATH="$stub_path" run_case "run-tmpdir-through-symlink" 0 \
  --target-dir "$tmpdir_target" --label x --runtime 5
stub_out=$(cat -- "$out_log" 2>/dev/null || true)
case "$stub_out" in
  "${tmpdir_real}"/fandhe-fio-bench.??????????/*)
    echo "PASS: run-tmpdir-resolved-before-mktemp (${stub_out})"
    ;;
  *)
    echo "FAIL: run-tmpdir-resolved-before-mktemp (fio --output was '${stub_out}', expected under ${tmpdir_real}/fandhe-fio-bench.XXXXXXXXXX/)" >&2
    failures=$((failures + 1))
    ;;
esac
tmpdir_leftover=$(count_entries "$tmpdir_real" -mindepth 1)
if is_count "$tmpdir_leftover" 0; then
  echo "PASS: run-tmpdir-cleaned-up"
else
  echo "FAIL: run-tmpdir-cleaned-up (found ${tmpdir_leftover} entries under ${tmpdir_real})" >&2
  failures=$((failures + 1))
fi
TMPDIR="${tmp_root}/no-such-tmpdir" run_case_msg "from-json-missing-tmpdir" 2 "temporary (TMPDIR) directory could not be resolved" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x

# 変換対象 JSON のスナップショット（snapshot_json_input）の単体照合。検証後の差し替え
# （FIFO・デバイス）は起動経路からは決定的に再現できないため、対象スクリプトから関数
# 定義だけを取り出し、差し替え後の状態を直接入力して照合する（実装そのものを使う）
snapshot_harness="${tmp_root}/snapshot-harness.sh"
# shellcheck disable=SC2016 # ハーネスへ書き出す文字列であり、$1 等はハーネス側で展開させる
{
  echo 'set -euo pipefail'
  echo 'err() { echo "error: $1: $2" >&2; }'
  echo 'MAX_FROM_JSON_BYTES=16'
  echo 'INPUT_READ_TIMEOUT_SECS=2'
  echo 'tmp_dir="$2"'
  sed -n '/^snapshot_json_input() {$/,/^}$/p' "$target_script"
  echo 'snapshot_json_input "$1" "test input"'
  # コピーの権限（0600）と内容を呼び出し側で照合できるよう、コピーのパスを出す
  echo 'echo "snapshot=${snapshot_path}"'
} >"$snapshot_harness"
snapshot_case() {
  # 引数: <ケース名> <期待終了コード> <期待する部分文字列> <入力パス>
  local name="$1" expected="$2" needle="$3" src="$4" actual=0 out
  local work="${tmp_root}/snapshot-work-${name}"
  mkdir -p "$work"
  out=$(timeout -k 5s 30s "$bash_bin" "$snapshot_harness" "$src" "$work" 2>&1) || actual=$?
  last_output="$out"
  if [ "$actual" -eq "$expected" ] && [[ "$out" == *"$needle"* ]]; then
    echo "PASS: snapshot-${name} (exit=${actual})"
  else
    echo "FAIL: snapshot-${name} (expected exit=${expected} with '${needle}', actual exit=${actual})" >&2
    print_indented "$out"
    failures=$((failures + 1))
  fi
}
printf '{"a":1}\n' >"${tmp_root}/snapshot-small.json"
snapshot_case "regular-file" 0 "snapshot=" "${tmp_root}/snapshot-small.json"
snapshot_copy="${last_output##*snapshot=}"
check_file_content "snapshot-regular-file-copied" "$snapshot_copy" '{"a":1}'
snapshot_mode_listing=$(count_entries "$snapshot_copy" -perm 0600)
if is_count "$snapshot_mode_listing" 1; then
  echo "PASS: snapshot-copy-mode-0600"
else
  echo "FAIL: snapshot-copy-mode-0600 (copy is not mode 0600: ${snapshot_copy})" >&2
  failures=$((failures + 1))
fi
head -c 17 /dev/zero >"${tmp_root}/snapshot-over.json"
snapshot_case "over-limit" 2 "exceeds 16 bytes" "${tmp_root}/snapshot-over.json"
snapshot_case "device" 2 "is not a regular file" /dev/zero
mkfifo "${tmp_root}/snapshot-fifo"
snapshot_case "fifo-open-blocks" 2 "could not be read within 2s" "${tmp_root}/snapshot-fifo"
snapshot_case "missing" 2 "could not be opened" "${tmp_root}/snapshot-no-such-file"

if [ "$failures" -gt 0 ]; then
  echo "self-test failed: ${failures} case(s) did not match the expected result" >&2
  exit 1
fi

echo "self-test passed: all cases matched the expected result"
