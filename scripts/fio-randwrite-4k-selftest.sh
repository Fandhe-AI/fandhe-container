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

set -euo pipefail

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
# メッセージ照合用）。
last_output=""

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
  last_output=$("$bash_bin" "$target_script" "$@" 2>&1) || actual=$?
  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: ${name} (exit=${actual})"
    return 0
  fi
  echo "FAIL: ${name} (expected exit=${expected}, actual exit=${actual})" >&2
  print_indented "$last_output"
  failures=$((failures + 1))
  return 1
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
  run_case "$name" "$expected" "$@" || return 0
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
run_case_msg "from-json-time-based-off" 2 "time_based must be enabled" --from-json "${fixtures_dir}/fio-3-time-based-off.json" --label x
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

# symlink 入力の拒否（security.md のパストラバーサル・symlink 対策）
sym_input="${tmp_root}/sym-input.json"
ln -s "${fixtures_dir}/fio-3-ok.json" "$sym_input"
run_case "from-json-symlink-input" 2 --from-json "$sym_input" --label x

# --from-json のサイズ上限超過（DoS 防止。MAX_FROM_JSON_BYTES=4MiB を 1 バイトだけ超える）
oversized_input="${tmp_root}/oversized.json"
head -c $((4 * 1024 * 1024 + 1)) /dev/zero >"$oversized_input"
run_case "from-json-oversized-input" 2 --from-json "$oversized_input" --label x

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
"$bash_bin" "$target_script" --from-json "${fixtures_dir}/fio-3-ok.json" --label docker_bind_mount >"$results_json"

baseline_json="${tmp_root}/baseline.json"
jq '{
  schema_version: 1,
  metrics: (.metrics | with_entries(.value += {direction: (
    if (.key | test("_iops$")) then "higher_is_better" else "lower_is_better" end
  )}))
}' "$results_json" >"$baseline_json"

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
for tool in jq grep dirname wc tr mktemp find ln; do
  ln -s "$(command -v "$tool")" "${common_bin}/${tool}"
done
PATH="$common_bin" run_case_msg "missing-fio-tool" 3 "fio is required" --target-dir /tmp --label x

# 最小の fio スタブ（固定 JSON を --output へ書き出すだけ）を作り、既存 PATH の
# 先頭に足すことで「fio・timeout・jq は揃っている」状態を作る（bash 解決に
# 使う既存 PATH は残すため、以降のケースは stub_bin を PATH の先頭に prefix する）。
stub_bin="${tmp_root}/stub-bin"
mkdir -p "$stub_bin"
# fio スタブは実 fio と同じく、受け取った `--key=value`・値なしフラグ（`--time_based` 等）
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
# 受け取った --directory を記録する（書き込み先が専用サブディレクトリであることの照合用）
[ -n "${FIO_STUB_DIR_LOG:-}" ] && echo "$dir" >"$FIO_STUB_DIR_LOG"
# 実 fio と同じく、データファイルを symlink をたどる形（O_CREAT・O_EXCL なし）で書く
[ -n "$dir" ] && [ -n "$fname" ] && echo stub-fio-data >"$dir/$fname"
# 実行中に第三者が symlink を置く競合（TOCTOU）を再現するためのフック
[ -n "${FIO_STUB_PLANT_LINK:-}" ] && ln -s "$FIO_STUB_PLANT_TARGET" "$FIO_STUB_PLANT_LINK"
[ -n "${FIO_STUB_PLANT_DIR:-}" ] && mkdir "$FIO_STUB_PLANT_DIR"
# 出力 JSON を書かずに成功終了する fio を再現するためのフック
[ -n "${FIO_STUB_NO_OUTPUT:-}" ] && exit 0
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
PATH="$stub_path" run_case_msg "run-world-writable-no-sticky-target-dir" 2 "world-writable without the sticky bit" --target-dir "$ww_target" --label x
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
leftover_count=$(find "$run_target" -mindepth 1 | wc -l | tr -d ' ')
if [ "$leftover_count" -eq 0 ]; then
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
attack_leftover=$(find "$attack_target" -mindepth 1 ! -name fandhe-fio-randwrite-4k.dat | wc -l | tr -d ' ')
if [ "$attack_leftover" -eq 0 ]; then
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
linked_dir_entries=$(find "$race_linked_dir" -mindepth 1 | wc -l | tr -d ' ')
if [ "$linked_dir_entries" -eq 0 ]; then
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
run_case_msg "output-parent-world-writable-no-sticky" 2 "--output parent directory is world-writable without the sticky bit" \
  --from-json "${fixtures_dir}/fio-3-ok.json" --label x --output "${ww_output_dir}/out.json"
chmod 755 "$ww_output_dir"

# 成功・失敗のどちらの経路でも --output 用の一時ファイルが残らない
output_tmp_leftover=$(find "$tmp_root" -maxdepth 1 -name '.fandhe-fio-output.*' | wc -l | tr -d ' ')
if [ "$output_tmp_leftover" -eq 0 ]; then
  echo "PASS: output-no-leftover-temp-files"
else
  echo "FAIL: output-no-leftover-temp-files (found ${output_tmp_leftover} .fandhe-fio-output.* files under $tmp_root)" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
  echo "self-test failed: ${failures} case(s) did not match the expected result" >&2
  exit 1
fi

echo "self-test passed: all cases matched the expected result"
