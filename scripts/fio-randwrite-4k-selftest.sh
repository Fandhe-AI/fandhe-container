#!/usr/bin/env bash
# scripts/fio-randwrite-4k.sh の自己テスト（TASK-25.1・IO-8・REPAIR-12）。
#
# 役割: 実 fio を必要としない `--from-json` モードと固定 fixture
# （scripts/testdata/fio-bench/）で、終了コードと変換結果の値を具体値で照合する
# （REPAIR-12: 受け入れ基準を機械照合する）。run モードの経路は起動コマンド組み立て
# （引数検証・symlink・上限チェック・欠如ツール検出・後始末）を最小の fio スタブで
# 確認する（実 fio は使わない）。run モードは対象スクリプト自体が GNU coreutils の
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

# 期待終了コードと実際の終了コードを照合する 1 ケース分の判定。
# 引数: <ケース名> <期待終了コード> -- <target_script への残り引数...>
run_case() {
  local name="$1"
  local expected="$2"
  shift 2
  local actual=0
  "$bash_bin" "$target_script" "$@" >/dev/null 2>&1 || actual=$?
  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: ${name} (exit=${actual})"
  else
    echo "FAIL: ${name} (expected exit=${expected}, actual exit=${actual})" >&2
    failures=$((failures + 1))
  fi
}

# --------------------------------------------------
# --from-json モード（jq のみで完結。fio 不要）
# --------------------------------------------------
run_case "from-json-ok" 0 --from-json "${fixtures_dir}/fio-3-ok.json" --label docker_bind_mount
run_case "from-json-missing-clat" 2 --from-json "${fixtures_dir}/fio-3-missing-clat.json" --label x
run_case "from-json-zero-iops" 2 --from-json "${fixtures_dir}/fio-3-zero-iops.json" --label x
run_case "from-json-fio-2x-legacy" 2 --from-json "${fixtures_dir}/fio-2-legacy.json" --label x
# 回帰テスト: capture(...)? は正規表現が不一致でも空ストリーム（jq 側は成功扱い）を
# 返すため、テストなしで放置すると壊れた version 文字列が「変換成功・空 JSON」と
# いう exit 0 の誤判定を通してしまう（fail-closed の穴）。バージョン文字列が
# "fio-" 接頭辞を持たない壊れた形式を、明示的に exit 2 で拒否することを確認する。
run_case "from-json-unparseable-version" 2 --from-json "${fixtures_dir}/fio-3-bad-version.json" --label x
run_case "from-json-not-json" 2 --from-json "${fixtures_dir}/not-json.txt" --label x
run_case "from-json-invalid-label" 2 --from-json "${fixtures_dir}/fio-3-ok.json" --label "Bad Label"
run_case "from-json-missing-file" 2 --from-json "${fixtures_dir}/does-not-exist.json" --label x

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
check_value() {
  local name="$1"
  local jq_filter="$2"
  local expected="$3"
  local actual
  actual=$("$bash_bin" "$target_script" --from-json "${fixtures_dir}/fio-3-ok.json" --label docker_bind_mount 2>/dev/null | jq -r "$jq_filter")
  if [ "$actual" = "$expected" ]; then
    echo "PASS: value-${name} (${actual})"
  else
    echo "FAIL: value-${name} (expected ${expected}, actual ${actual})" >&2
    failures=$((failures + 1))
  fi
}

check_value "schema-version" ".schema_version" "1"
check_value "benchmark" ".benchmark" "fio_randwrite_4k"
check_value "label" ".label" "docker_bind_mount"
check_value "target-kind" ".target_kind" "from_json"
check_value "iops" ".metrics.fio_randwrite_4k_iops.value" "1000.0"
check_value "iops-unit" ".metrics.fio_randwrite_4k_iops.unit" "ops/s"
check_value "lat-mean-us" ".metrics.fio_randwrite_4k_lat_mean_us.value" "500"
check_value "clat-p50-us" ".metrics.fio_randwrite_4k_clat_p50_us.value" "400"
check_value "clat-p95-us" ".metrics.fio_randwrite_4k_clat_p95_us.value" "900"
check_value "clat-p99-us" ".metrics.fio_randwrite_4k_clat_p99_us.value" "1300"
check_value "params-rw" ".params.rw" "randwrite"
check_value "params-bs" ".params.bs" "4k"
check_value "params-ioengine" ".params.ioengine" "psync"
check_value "params-end-fsync" ".params.end_fsync" "1"

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
bash "$bench_check_script" "$baseline_json" "$results_json" >/dev/null 2>&1 || roundtrip_actual=$?
if [ "$roundtrip_actual" -eq 0 ]; then
  echo "PASS: results-json-compatible-with-bench-regression (exit=${roundtrip_actual})"
else
  echo "FAIL: results-json-compatible-with-bench-regression (expected exit=0, actual exit=${roundtrip_actual})" >&2
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

# --------------------------------------------------
# run モード: 引数検証・ツール欠如検出（実 fio は使わない）
# --------------------------------------------------
# jq が無い PATH（全モード共通の前提ツール欠如。exit 3。`bash` 自体は絶対パスで
# 起動するため PATH を空にしても解決できる）
empty_bin="${tmp_root}/empty-bin"
mkdir -p "$empty_bin"
no_jq_actual=0
PATH="$empty_bin" "$bash_bin" "$target_script" --from-json "${fixtures_dir}/fio-3-ok.json" --label x >/dev/null 2>&1 || no_jq_actual=$?
if [ "$no_jq_actual" -eq 3 ]; then
  echo "PASS: missing-jq-tool (exit=${no_jq_actual})"
else
  echo "FAIL: missing-jq-tool (expected exit=3, actual exit=${no_jq_actual})" >&2
  failures=$((failures + 1))
fi

# fio が無い PATH（run モードのみの前提ツール欠如。exit 3。PATH を jq だけに絞る）
jq_only_bin="${tmp_root}/jq-only-bin"
mkdir -p "$jq_only_bin"
jq_path=$(command -v jq)
ln -s "$jq_path" "${jq_only_bin}/jq"
no_fio_actual=0
PATH="$jq_only_bin" "$bash_bin" "$target_script" --target-dir /tmp --label x >/dev/null 2>&1 || no_fio_actual=$?
if [ "$no_fio_actual" -eq 3 ]; then
  echo "PASS: missing-fio-tool (exit=${no_fio_actual})"
else
  echo "FAIL: missing-fio-tool (expected exit=3, actual exit=${no_fio_actual})" >&2
  failures=$((failures + 1))
fi

# 最小の fio スタブ（固定 JSON を --output へ書き出すだけ）を作り、既存 PATH の
# 先頭に足すことで「fio・timeout・jq は揃っている」状態を作る（bash 解決に
# 使う既存 PATH は残すため、以降のケースは stub_bin を PATH の先頭に prefix する）。
stub_bin="${tmp_root}/stub-bin"
mkdir -p "$stub_bin"
# fio スタブは --output 引数の JSON 書き出しに加えて、--directory/--filename が
# 指す固定データファイルも実際に作る（run-cleanup-no-leftover-files が「後始末で
# 実在するファイルが消える」ことを確認できるようにするため。ファイルを作らないと
# 後始末の trap が空振りしても検出できず、テストが意味を持たない）。
fio_stub="${stub_bin}/fio"
# shellcheck disable=SC2016 # stub スクリプトへ書き出す文字列であり、$@ 等は
# stub 側で展開させる意図でシングルクォートにしている。
{
  echo '#!/usr/bin/env bash'
  echo 'out="" dir="" fname=""'
  echo 'for a in "$@"; do'
  echo '  case "$a" in'
  echo '    --output=*) out="${a#--output=}" ;;'
  echo '    --directory=*) dir="${a#--directory=}" ;;'
  echo '    --filename=*) fname="${a#--filename=}" ;;'
  echo '  esac'
  echo 'done'
  echo '[ -n "$dir" ] && [ -n "$fname" ] && : > "$dir/$fname"'
  echo "cat \"${fixtures_dir}/fio-3-ok.json\" >\"\$out\""
  echo 'exit 0'
} >"$fio_stub"
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

sym_target="${tmp_root}/sym-target"
real_target="${tmp_root}/real-target"
mkdir -p "$real_target"
ln -s "$real_target" "$sym_target"
PATH="$stub_path" run_case "run-symlink-target-dir" 2 --target-dir "$sym_target" --label x

readonly_target="${tmp_root}/readonly-target"
mkdir -p "$readonly_target"
chmod 555 "$readonly_target"
if [ "$(id -u)" -eq 0 ]; then
  echo "SKIP: run-readonly-target-dir (running as root, permission bits are not enforced)"
else
  PATH="$stub_path" run_case "run-readonly-target-dir" 2 --target-dir "$readonly_target" --label x
fi
chmod 755 "$readonly_target"

# run モードの正常系（fio スタブ経由。データファイルが後始末で残らないことも確認する）
run_target="${tmp_root}/run-target"
mkdir -p "$run_target"
PATH="$stub_path" run_case "run-ok-with-stub" 0 --target-dir "$run_target" --label local_tmp --runtime 5
leftover_count=$(find "$run_target" -mindepth 1 | wc -l | tr -d ' ')
if [ "$leftover_count" -eq 0 ]; then
  echo "PASS: run-cleanup-no-leftover-files"
else
  echo "FAIL: run-cleanup-no-leftover-files (found ${leftover_count} leftover entries under $run_target)" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
  echo "self-test failed: ${failures} case(s) did not match the expected result" >&2
  exit 1
fi

echo "self-test passed: all cases matched the expected result"
