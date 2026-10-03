#!/usr/bin/env bash
# scripts/bench/net_setup_timing.sh の自己テスト（TASK-139.5・NET-1・NET-4・REPAIR-12）。
#
# 役割: 実機（root・netns）を使わず、固定の JSONL を出す bash のスタブ exe で、集計値（中央値・最小・
# 最大・p90・平均）と異常系（ok:false・不正 JSON・件数不足・未知の op・相対パス・書き込み可の exe・
# 既存 output・範囲外の引数・タイムアウト・exe の失敗）の終了コードと出力を具体値で機械照合する。
# 実測そのものは行わない（実機での計測は TASK-140 で人間が実施する）。
# 呼び出し元は Makefile の `net-setup-timing-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。各ケースの失敗は
# failures に数えて最後まで実行を続け、末尾のサマリーで判定する。

set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/net_setup_timing.sh"
bash_bin="$(command -v bash)"

failures=0
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

last_stdout=""
last_stderr=""
last_rc=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

pass() {
  echo "PASS: $1"
}

# 対象スクリプトを実行し、stdout・stderr・終了コードを保持する（常に 0 を返す）。
run_target() {
  local errfile="$tmp_root/stderr.txt"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" "$@" 2>"$errfile")" || last_rc=$?
  last_stderr="$(cat "$errfile")"
}

# 期待終了コードを照合する。引数: <名前> <期待 rc> <対象への引数...>
expect_rc() {
  local name="$1" expected="$2"
  shift 2
  run_target "$@"
  if [ "$last_rc" -eq "$expected" ]; then
    pass "$name (rc=$last_rc)"
  else
    fail "$name: expected rc=$expected, got rc=$last_rc (stderr: $last_stderr)"
  fi
}

# jq 式で出力 JSON を照合する。引数: <名前> <jq 式（true を期待）>
expect_json() {
  local name="$1" expr="$2"
  if printf '%s' "$last_stdout" | jq -e "$expr" >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name: jq expression failed: $expr (stdout: $last_stdout)"
  fi
}

# スタブ exe を作る。引数: <パス> <本文>。本文は --measure 起動時に実行される。
make_stub() {
  printf '#!%s\n%s\n' "$bash_bin" "$2" >"$1"
  chmod 755 "$1"
}

# 5 試行 + 1 ウォームアップの JSONL を作る。ウォームアップ行は集計から除外されることを値 99.0 で示す。
#   net_create:       1,2,3,4,5          -> median 3 / min 1 / max 5 / p90 5 / mean 3
#   container_attach: 10,20,30,40,50     -> median 30 / min 10 / max 50 / p90 50 / mean 30
#   net_delete:       5,5,5,5,100        -> median 5 / min 5 / max 100 / p90 100 / mean 24
good="$tmp_root/good.jsonl"
{
  printf '{"trial":0,"warmup":true,"op":"net_create","elapsed_ms":99.000,"ok":true}\n'
  printf '{"trial":0,"warmup":true,"op":"container_attach","elapsed_ms":99.000,"ok":true}\n'
  printf '{"trial":0,"warmup":true,"op":"net_delete","elapsed_ms":99.000,"ok":true}\n'
  creates=(1 2 3 4 5)
  attaches=(10 20 30 40 50)
  deletes=(5 5 5 5 100)
  for i in 0 1 2 3 4; do
    printf '{"trial":%d,"warmup":false,"op":"net_create","elapsed_ms":%d.000,"ok":true}\n' "$i" "${creates[$i]}"
    printf '{"trial":%d,"warmup":false,"op":"container_attach","elapsed_ms":%d.000,"ok":true}\n' "$i" "${attaches[$i]}"
    printf '{"trial":%d,"warmup":false,"op":"net_delete","elapsed_ms":%d.000,"ok":true}\n' "$i" "${deletes[$i]}"
  done
} >"$good"

good_exe="$tmp_root/good_exe"
make_stub "$good_exe" "cat '$good'"

# --- 正常系 ---
run_target --exe "$good_exe" --trials 5 --warmup 1 --label selftest
if [ "$last_rc" -eq 0 ]; then pass "normal run (rc=0)"; else fail "normal run: rc=$last_rc ($last_stderr)"; fi
expect_json "schema と単位" '.schema == "fandhe-container.net-setup-timing/v1" and .unit == "ms" and .label == "selftest" and .trials == 5 and .warmup == 1'
expect_json "isolation の記録" '.isolation == "unshare --net --mount (fresh netns)"'
expect_json "net_create の集計" '.metrics.net_create == {samples:5, median:3, min:1, max:5, p90:5, mean:3}'
expect_json "container_attach の集計" '.metrics.container_attach == {samples:5, median:30, min:10, max:50, p90:50, mean:30}'
expect_json "net_delete の集計（ウォームアップ 99 を除外）" '.metrics.net_delete == {samples:5, median:5, min:5, max:100, p90:100, mean:24}'
expect_json "method に PoC-15 との差を記録" '(.method.net_create | contains("DNS helper")) and (.method.container_attach | contains("PoC-15 (ii)"))'

# --- --output: 新規作成できる。既存は上書きしない ---
out_file="$tmp_root/out.json"
expect_rc "output 新規作成" 0 --exe "$good_exe" --trials 5 --warmup 1 --output "$out_file"
if jq -e '.metrics.net_create.median == 3' "$out_file" >/dev/null 2>&1; then pass "output の内容"; else fail "output の内容"; fi
expect_rc "既存 output は上書きしない" 2 --exe "$good_exe" --trials 5 --warmup 1 --output "$out_file"

# --- 異常系: 計測出力の検証失敗（rc=1）---
bad_exe="$tmp_root/bad_exe"
bad_case() { # 名前 本文
  make_stub "$bad_exe" "$2"
  expect_rc "$1" 1 --exe "$bad_exe" --trials 5 --warmup 1
}
bad_case "ok:false は失敗" "sed 's/\"ok\":true/\"ok\":false/' '$good'"
bad_case "不正 JSON は失敗" "cat '$good'; echo 'not json'"
bad_case "件数不足は失敗" "head -n 10 '$good'"
bad_case "未知の op は失敗" "sed 's/\"op\":\"net_delete\"/\"op\":\"net_other\"/' '$good'"
bad_case "余分なキーは失敗" "sed 's/\"ok\":true/\"ok\":true,\"x\":1/' '$good'"
bad_case "exe の非ゼロ終了は失敗" "cat '$good'; exit 7"
make_stub "$bad_exe" "sleep 30"
expect_rc "タイムアウトは失敗" 1 --exe "$bad_exe" --trials 5 --warmup 1 --timeout 1

# --- 異常系: 入力エラー（rc=2）---
expect_rc "--exe 必須" 2 --trials 5
expect_rc "相対パスの exe" 2 --exe "relative_exe" --trials 5
expect_rc "存在しない exe" 2 --exe "$tmp_root/none" --trials 5
ln -s "$good_exe" "$tmp_root/link_exe"
expect_rc "symlink の exe" 2 --exe "$tmp_root/link_exe" --trials 5
writable_exe="$tmp_root/writable_exe"
make_stub "$writable_exe" "cat '$good'"
chmod 775 "$writable_exe"
expect_rc "group 書き込み可の exe" 2 --exe "$writable_exe" --trials 5 --warmup 1
chmod 757 "$writable_exe"
expect_rc "other 書き込み可の exe" 2 --exe "$writable_exe" --trials 5 --warmup 1
expect_rc "trials 範囲外 (0)" 2 --exe "$good_exe" --trials 0
expect_rc "trials 範囲外 (201)" 2 --exe "$good_exe" --trials 201
expect_rc "warmup 範囲外 (21)" 2 --exe "$good_exe" --warmup 21
expect_rc "trials 非数値" 2 --exe "$good_exe" --trials abc
expect_rc "timeout 範囲外 (0)" 2 --exe "$good_exe" --timeout 0
expect_rc "label 不正" 2 --exe "$good_exe" --label 'a b;c'
expect_rc "未知の引数" 2 --exe "$good_exe" --bogus 1
expect_rc "値の欠落" 2 --exe "$good_exe" --trials

# --- 前提ツール欠如（rc=3）: PATH から jq を外す ---
no_jq_dir="$tmp_root/nojq"
mkdir -p "$no_jq_dir"
for tool in timeout mktemp stat rm cat sleep grep; do
  tool_path="$(command -v "$tool")"
  ln -s "$tool_path" "$no_jq_dir/$tool"
done
rc=0
PATH="$no_jq_dir" "$bash_bin" "$target_script" --exe "$good_exe" --trials 5 >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 3 ]; then pass "jq 欠如 (rc=3)"; else fail "jq 欠如: expected rc=3, got $rc"; fi

if [ "$failures" -ne 0 ]; then
  echo "net_setup_timing_selftest: $failures failure(s)" >&2
  exit 1
fi
echo "net_setup_timing_selftest: all passed"
