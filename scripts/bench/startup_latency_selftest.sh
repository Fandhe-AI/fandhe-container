#!/usr/bin/env bash
# scripts/bench/startup_latency.sh の自己テスト（TASK-46.1・CORE-10・REPAIR-12）。
#
# 役割: 実ランタイム・root を使わず、bash のスタブランタイム（create / start / delete /
# kill を模し、固定 sleep と呼び出しログを持つ）で、終了コード・出力 JSON の値・呼び出し
# 順序・タイムアウト・後始末を具体値で機械照合する。own 実装の実測そのものは行わない
# （CLI 提供後に人間が #213 で実施する。startup_latency.sh 冒頭の「現状の制約」参照）。
# 呼び出し元は Makefile の `startup-latency-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。各ケースの失敗は
# failures に数えて最後まで実行を続け、末尾のサマリーで判定する。

set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/startup_latency.sh"
bench_check_script="${script_dir}/../check-bench-regression.sh"
# PATH を絞るケースで bash 自体が解決できなくなるため、絶対パスを先に確定する。
bash_bin="$(command -v bash)"

failures=0
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

last_output=""
last_stdout=""
last_rc=0

print_indented() {
  local line
  while IFS= read -r line; do
    printf '  | %s\n' "$line" >&2
  done <<<"$1"
}

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

pass() {
  echo "PASS: $1"
}

# 対象スクリプトを実行し、stdout・stdout+stderr・終了コードを保持する（常に 0 を返す）。
run_target() {
  local errfile="$tmp_root/stderr.txt"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" "$@" 2>"$errfile")" || last_rc=$?
  last_output="${last_stdout}"$'\n'"$(cat "$errfile")"
}

# 期待終了コードを照合する。引数: <名前> <期待 rc> <対象への引数...>
expect_rc() {
  local name="$1" expected="$2"
  shift 2
  run_target "$@"
  if [ "$last_rc" -eq "$expected" ]; then
    pass "$name (exit=$last_rc)"
  else
    fail "$name (expected exit=$expected, actual exit=$last_rc)"
    print_indented "$last_output"
  fi
}

expect_contains() {
  local name="$1" needle="$2"
  if [[ "$last_output" == *"$needle"* ]]; then
    pass "$name"
  else
    fail "$name (output lacks '$needle')"
    print_indented "$last_output"
  fi
}

expect_eq() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    pass "$name"
  else
    fail "$name (expected '$expected', actual '$actual')"
  fi
}

# --- フィクスチャ: スタブランタイムとダミー bundle ---
work="$tmp_root/work"
mkdir -p "$work/bundle"
echo '{}' >"$work/bundle/config.json"
stub_log="$work/stub.log"

stub="$work/stub-runtime"
cat >"$stub" <<STUB
#!${bash_bin}
# スタブランタイム。STUB_MODE: ok / create-fail / create-fail-delete-fail / start-fail / start-hang / delete-fail
cmd="\$1"
shift
case "\$cmd" in
  create) id="\${@: -1}" ;;
  *) id="\$1" ;;
esac
echo "\$cmd \$id" >>"\$STUB_LOG"
case "\$cmd" in
  create)
    sleep 0.05
    case "\${STUB_MODE:-ok}" in create-fail | create-fail-delete-fail) echo "stub: create failed" >&2; exit 1 ;; esac
    ;;
  start)
    [ "\${STUB_MODE:-ok}" = start-fail ] && { echo "stub: start failed" >&2; exit 1; }
    [ "\${STUB_MODE:-ok}" = start-hang ] && exec sleep 30
    sleep 0.10
    ;;
  delete)
    case "\${STUB_MODE:-ok}" in delete-fail | create-fail-delete-fail) echo "stub: delete failed" >&2; exit 1 ;; esac
    ;;
  kill) ;;
esac
exit 0
STUB
chmod 755 "$stub"
export STUB_LOG="$stub_log"

reset_log() { : >"$stub_log"; }

# --- 1. 正常系 ---
reset_log
export STUB_MODE=ok
expect_rc "normal-run" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 3 --warmup 1
normal_json="$last_stdout"
expect_eq "normal-schema_version" "1" "$(jq -r '.schema_version' <<<"$normal_json")"
expect_eq "normal-benchmark" "startup_latency" "$(jq -r '.benchmark' <<<"$normal_json")"
expect_eq "normal-target" "own" "$(jq -r '.target' <<<"$normal_json")"
expect_eq "normal-samples-count" "3" "$(jq -r '.samples_us | length' <<<"$normal_json")"
expect_eq "normal-total-consistent" "true" "$(jq -r 'all(.samples_us[]; .total_us >= .create_us + .start_us and .total_us >= 150000)' <<<"$normal_json")"
expect_eq "normal-p50-unit" "ms" "$(jq -r '.metrics.startup_latency_p50_ms.unit' <<<"$normal_json")"
expect_eq "normal-no-path-leak" "false" "$(jq -r --arg p "$work" 'tostring | contains($p)' <<<"$normal_json")"

# --- 2. 中央値・min・max を awk で独立再計算（奇数・偶数） ---
verify_stats() {
  local name="$1" json="$2" exp
  exp="$(jq -r '.samples_us[].total_us' <<<"$json" | sort -n | awk '
    { a[NR] = $1 }
    END {
      if (NR % 2) m = a[(NR + 1) / 2]; else m = (a[NR / 2] + a[NR / 2 + 1]) / 2
      printf "%.6f %.6f %.6f\n", m / 1000, a[1] / 1000, a[NR] / 1000
    }')"
  local got
  got="$(jq -r '[.metrics.startup_latency_p50_ms.value, .metrics.startup_latency_min_ms.value, .metrics.startup_latency_max_ms.value] | map(. * 1000000 | round / 1000000) | map(tostring) | join(" ")' <<<"$json")"
  # 比較は数値として行う（表記ゆれを避ける）。
  local ok
  ok="$(awk -v e="$exp" -v g="$got" 'BEGIN {
    split(e, ea, " "); split(g, ga, " ")
    ok = 1
    for (i = 1; i <= 3; i++) { d = ea[i] - ga[i]; if (d < 0) d = -d; if (d > 0.0001) ok = 0 }
    print ok }')"
  expect_eq "$name" "1" "$ok"
}
verify_stats "median-odd(3)" "$normal_json"
reset_log
expect_rc "even-run" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 4 --warmup 0
verify_stats "median-even(4)" "$last_stdout"

# --- 3. 呼び出し順: warmup 込み 4 回・ID 一意・create -> start -> delete ---
reset_log
expect_rc "call-order-run" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 3 --warmup 1
mapfile -t log_lines <"$stub_log"
expect_eq "call-order-line-count" "12" "${#log_lines[@]}"
order_ok=1
declare -A seen_ids=()
for ((i = 0; i + 2 < ${#log_lines[@]}; i += 3)); do
  read -r c1 id1 <<<"${log_lines[$i]}"
  read -r c2 id2 <<<"${log_lines[$((i + 1))]}"
  read -r c3 id3 <<<"${log_lines[$((i + 2))]}"
  if [ "$c1 $c2 $c3" != "create start delete" ] || [ "$id1" != "$id2" ] || [ "$id2" != "$id3" ]; then
    order_ok=0
  fi
  seen_ids["$id1"]=1
done
expect_eq "call-order-sequence" "1" "$order_ok"
expect_eq "call-order-unique-ids" "4" "${#seen_ids[@]}"

# --- 4. --output ---
out_file="$work/result.json"
reset_log
expect_rc "output-write" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 2 --warmup 0 --output "$out_file"
expect_eq "output-file-equals-stdout" "$last_stdout" "$(cat "$out_file")"
expect_rc "output-existing-file" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$out_file"
ln -s "$work/nonexistent-target" "$work/link.json"
expect_rc "output-existing-symlink" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/link.json"
expect_rc "output-parent-missing" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/nodir/x.json"

# --- 5. 入力エラー（exit 2） ---
expect_rc "input-runtime-missing" 2 --bundle "$work/bundle"
expect_rc "input-runtime-relative" 2 --runtime stub-runtime --bundle "$work/bundle"
cp "$stub" "$work/not-exec"
chmod 644 "$work/not-exec"
expect_rc "input-runtime-not-executable" 2 --runtime "$work/not-exec" --bundle "$work/bundle"
expect_rc "input-bundle-missing" 2 --runtime "$stub"
expect_rc "input-bundle-not-found" 2 --runtime "$stub" --bundle "$work/nodir"
mkdir -p "$work/nocfg"
expect_rc "input-config-missing" 2 --runtime "$stub" --bundle "$work/nocfg"
mkdir -p "$work/cfglink"
ln -s "$work/bundle/config.json" "$work/cfglink/config.json"
expect_rc "input-config-symlink" 2 --runtime "$stub" --bundle "$work/cfglink"
ln -s "$work/bundle" "$work/bundlelink"
expect_rc "input-bundle-symlink" 2 --runtime "$stub" --bundle "$work/bundlelink"
for v in 0 1001 abc 01 -1; do
  expect_rc "input-iterations-$v" 2 --runtime "$stub" --bundle "$work/bundle" --iterations "$v"
done
for v in 0 61; do
  expect_rc "input-timeout-$v" 2 --runtime "$stub" --bundle "$work/bundle" --timeout "$v"
done
expect_rc "input-warmup-101" 2 --runtime "$stub" --bundle "$work/bundle" --warmup 101
expect_rc "input-label-invalid" 2 --runtime "$stub" --bundle "$work/bundle" --label 'a b;c'
expect_rc "input-unknown-option" 2 --runtime "$stub" --bundle "$work/bundle" --bogus
expect_rc "input-duplicate-option" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --iterations 2
expect_rc "input-value-missing" 2 --runtime "$stub" --bundle
expect_rc "help" 0 --help

# --- 6. create / start 失敗 ---
reset_log
STUB_MODE=create-fail expect_rc "create-fail" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "create-fail-log-tail" "stub: create failed"
if grep -q '^delete ' "$stub_log"; then pass "create-fail-delete-called"; else fail "create-fail-delete-called"; fi
# create 失敗後の delete も失敗する場合は kill → delete を再試行し、残存 ID を報告して exit 4。
reset_log
STUB_MODE=create-fail-delete-fail expect_rc "create-fail-delete-fail" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "create-fail-leftover-id" "containers left behind: fandhe-startup-"
if grep -q '^kill ' "$stub_log"; then pass "create-fail-kill-called"; else fail "create-fail-kill-called"; fi
reset_log
STUB_MODE=start-fail expect_rc "start-fail" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
if grep -q '^delete ' "$stub_log"; then pass "start-fail-delete-called"; else fail "start-fail-delete-called"; fi

# --- 7. start ハング（REPAIR-5）: timeout で打ち切り、delete が呼ばれる ---
reset_log
started="$SECONDS"
STUB_MODE=start-hang expect_rc "start-hang" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "start-hang-elapsed (${elapsed}s < 15s)"; else fail "start-hang-elapsed (${elapsed}s)"; fi
if grep -q '^delete ' "$stub_log"; then pass "start-hang-delete-called"; else fail "start-hang-delete-called"; fi

# --- 8. delete 失敗: 計測成功でも exit 4、残存 ID を出力 ---
reset_log
STUB_MODE=delete-fail expect_rc "delete-fail" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "delete-fail-leftover-id" "fandhe-startup-"

# --- 9. 前提ツール欠如: jq を含まない PATH で exit 3 ---
mkdir -p "$work/emptybin"
rc=0
PATH="$work/emptybin" "$bash_bin" "$target_script" --runtime "$stub" --bundle "$work/bundle" >/dev/null 2>&1 || rc=$?
expect_eq "missing-jq-exit3" "3" "$rc"

# --- 10. 出力が check-bench-regression.sh のスキーマと互換（機械照合） ---
export STUB_MODE=ok
run_target --runtime "$stub" --bundle "$work/bundle" --iterations 2 --warmup 0
printf '%s\n' "$last_stdout" >"$work/results.json"
cat >"$work/baseline.json" <<'JSON'
{
  "schema_version": 1,
  "metrics": {
    "startup_latency_p50_ms": {"value": 100000, "unit": "ms", "direction": "lower_is_better"},
    "startup_latency_min_ms": {"value": 100000, "unit": "ms", "direction": "lower_is_better"},
    "startup_latency_max_ms": {"value": 100000, "unit": "ms", "direction": "lower_is_better"}
  }
}
JSON
rc=0
"$bash_bin" "$bench_check_script" "$work/baseline.json" "$work/results.json" >/dev/null 2>&1 || rc=$?
expect_eq "bench-regression-schema-compat" "0" "$rc"

if [ "$failures" -ne 0 ]; then
  echo "startup_latency_selftest: $failures failure(s)" >&2
  exit 1
fi
echo "startup_latency_selftest: all cases passed"
