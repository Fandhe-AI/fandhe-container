#!/usr/bin/env bash
# scripts/bench/dns_helper_measure.sh の自己テスト（TASK-141.3・#323・NET-5・REPAIR-12）。
#
# 役割: 実機（root・実 cgroup・実 netns）を使わず、固定の JSONL を出す bash のスタブ exe と、疑似 cgroup・
# 疑似 /proc（mktemp -d 配下）で、集計値（正答率・p50・p99・min・max・mean・系列ごと）、cgroup.procs からの
# PID 取得（0 個・2 個・sudo の代役 PID の拒否）、smaps_rollup の読み取りと異常系の終了コードを具体値で機械照合する。
# 実測そのものは行わない（実機での計測は TASK-142 で人間が実施する）。
# 呼び出し元は Makefile の `dns-helper-measure-selftest` ターゲットと `.github/workflows/ci.yml` の
# `bench-regression` ジョブ。
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。各ケースの失敗は failures に数えて最後まで
# 実行を続け、末尾のサマリーで判定する。

set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/dns_helper_measure.sh"
bash_bin="$(command -v bash)"

failures=0
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

fake_proc="$tmp_root/proc"
fake_cg="$tmp_root/cg"
mkdir -p "$fake_proc" "$fake_cg"

# 対象スクリプトとスタブに渡す環境（スタブの挙動はこれらの STUB_* で切り替える）。
export FANDHE_DNS_HELPER_MEASURE_SELFTEST=1
export FAKE_PROC="$fake_proc"
reset_stub() {
  export STUB_PIDS="424242"
  export STUB_EXE_LINK=""
  export STUB_ARGV1="--dns-measure-helper"
  export STUB_SMAPS=$'Pss:                 530 kB\nRss:                1200 kB'
  export STUB_NO_READY=""
  export STUB_EXIT=0
}
reset_stub

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

# 対象スクリプトを実行し、stdout・stderr・終了コードを保持する（常に 0 を返す）。疑似 cgroup / proc を常に渡す。
run_target() {
  local errfile="$tmp_root/stderr.txt"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" --cgroup-parent "$fake_cg" --proc-root "$fake_proc" "$@" 2>"$errfile")" || last_rc=$?
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

# スタブ exe を作る。引数: <パス> <JSONL ファイル>。本物の exe と同じ引数（--measure ... --cgroup C --sync-dir S）で
# 起動され、JSONL を stdout へ出し、疑似 cgroup.procs・疑似 /proc/<pid>/* を用意して pss-ready を作り、
# pss-done を待ってから cgroup.procs を空にして終了する。
make_stub() {
  cat >"$1" <<STUB
#!$bash_bin
cg=""; sync=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    --cgroup) cg="\$2"; shift 2 ;;
    --sync-dir) sync="\$2"; shift 2 ;;
    *) shift ;;
  esac
done
cat '$2'
[ -z "\$STUB_NO_READY" ] || exit "\$STUB_EXIT"
for pid in \$STUB_PIDS; do
  mkdir -p "\$FAKE_PROC/\$pid"
  ln -sfn "\${STUB_EXE_LINK:-\$0}" "\$FAKE_PROC/\$pid/exe"
  printf '%s\\0%s\\0' "\$0" "\$STUB_ARGV1" >"\$FAKE_PROC/\$pid/cmdline"
  printf '%s\\n' "\$STUB_SMAPS" >"\$FAKE_PROC/\$pid/smaps_rollup"
  printf '%s\\n' "\$pid" >>"\$cg/cgroup.procs"
done
touch "\$sync/pss-ready"
for _ in \$(seq 1 100); do
  [ -e "\$sync/pss-done" ] && break
  sleep 0.1
done
: >"\$cg/cgroup.procs"
exit "\$STUB_EXIT"
STUB
  chmod 755 "$1"
}

# 5 クエリ + 1 ウォームアップ x 6 系列の JSONL を作る。ウォームアップ行は集計から除外されることを 999.5 で示す。
#   系列 k（0..5 = c1/svc-a, c1/svc-b, c1/svc-c, c2/svc-a, c2/svc-b, c2/svc-c）の trial t の latency_us = 10*(t+1) + k
#   全体 30 サンプル: p50 = sorted[14] = 32 / p99 = sorted[29] = 55 / min 10 / max 55 / mean 32.5
#   系列 0: p50 30 / p99 50 / min 10 / max 50 / mean 30、系列 5: p50 35 / p99 55 / min 15 / max 55 / mean 35
series_names=("c1/svc-a" "c1/svc-b" "c1/svc-c" "c2/svc-a" "c2/svc-b" "c2/svc-c")
good="$tmp_root/good.jsonl"
{
  for k in 0 1 2 3 4 5; do
    printf '{"series":"%s","trial":0,"warmup":true,"ok":true,"latency_us":999.500}\n' "${series_names[$k]}"
  done
  for k in 0 1 2 3 4 5; do
    for t in 0 1 2 3 4; do
      printf '{"series":"%s","trial":%d,"warmup":false,"ok":true,"latency_us":%d.000}\n' \
        "${series_names[$k]}" "$t" $((10 * (t + 1) + k))
    done
  done
} >"$good"

good_exe="$tmp_root/good_exe"
make_stub "$good_exe" "$good"

# --- 正常系 ---
run_target --exe "$good_exe" --queries 5 --warmup 1 --label selftest
if [ "$last_rc" -eq 0 ]; then pass "normal run (rc=0)"; else fail "normal run: rc=$last_rc ($last_stderr)"; fi
expect_json "schema・label・条件" '.schema == "fandhe-container.dns-helper-measure/v1" and .label == "selftest" and .queries_per_series == 5 and .warmup == 1'
expect_json "isolation の記録" '(.isolation | contains("unshare --net --mount")) and (.isolation | contains("cgroup v2"))'
expect_json "全体の正答率" '.accuracy == {correct:30, total:30, ratio:1, percent:100}'
expect_json "全体のレイテンシ（ウォームアップ 999.5 を除外）" '.latency == {unit:"us", samples:30, p50:32, p99:55, min:10, max:55, mean:32.5}'
expect_json "系列は 6 つで順序固定" '[.per_series[].series] == ["c1/svc-a","c1/svc-b","c1/svc-c","c2/svc-a","c2/svc-b","c2/svc-c"]'
expect_json "系列 0 の集計" '.per_series[0] == {series:"c1/svc-a", accuracy:{correct:5,total:5,ratio:1,percent:100}, latency:{unit:"us",samples:5,p50:30,p99:50,min:10,max:50,mean:30}}'
expect_json "系列 5 の集計" '.per_series[5] == {series:"c2/svc-c", accuracy:{correct:5,total:5,ratio:1,percent:100}, latency:{unit:"us",samples:5,p50:35,p99:55,min:15,max:55,mean:35}}'
expect_json "メモリ（PID は cgroup.procs 由来）" '.memory.unit == "kB" and .memory.pss_kb == 530 and .memory.rss_kb == 1200 and .memory.pid_source == "cgroup.procs" and (.memory.cgroup | startswith("fandhe-dns-measure-"))'
expect_json "method に計測対象と PoC-15 系列構成を記録" '(.method | contains("NOT the product entry run_dns_helper_main")) and (.method | contains("PoC-15")) and (.method | contains("nearest-rank")) and (.method | contains("TASK-142"))'
expect_json "合否判定を出さない" 'has("pass") | not'
if [ -z "$(ls -A "$fake_cg")" ]; then pass "専用 cgroup が後始末される"; else fail "専用 cgroup が残っている: $(ls -A "$fake_cg")"; fi

# --- --output: 新規作成できる。既存は上書きしない ---
out_file="$tmp_root/out.json"
expect_rc "output 新規作成" 0 --exe "$good_exe" --queries 5 --warmup 1 --output "$out_file"
if jq -e '.latency.p50 == 32' "$out_file" >/dev/null 2>&1; then pass "output の内容"; else fail "output の内容"; fi
expect_rc "既存 output は上書きしない" 2 --exe "$good_exe" --queries 5 --warmup 1 --output "$out_file"

# --- ok:false（誤答・無応答）は失敗にせず正答率へ反映する ---
miss="$tmp_root/miss.jsonl"
sed 's/{"series":"c1\/svc-c","trial":2,"warmup":false,"ok":true,"latency_us":32.000}/{"series":"c1\/svc-c","trial":2,"warmup":false,"ok":false,"latency_us":null}/' "$good" >"$miss"
miss_exe="$tmp_root/miss_exe"
make_stub "$miss_exe" "$miss"
run_target --exe "$miss_exe" --queries 5 --warmup 1
if [ "$last_rc" -eq 0 ]; then pass "ok:false を含む実行 (rc=0)"; else fail "ok:false を含む実行: rc=$last_rc ($last_stderr)"; fi
expect_json "正答率が下がる" '.accuracy == {correct:29, total:30, ratio:0.966667, percent:96.667}'
expect_json "無応答はレイテンシのサンプルに入らない" '.latency == {unit:"us", samples:29, p50:33, p99:55, min:10, max:55, mean:32.517}'
expect_json "系列ごとの正答率" '(.per_series[] | select(.series == "c1/svc-c")) == {series:"c1/svc-c", accuracy:{correct:4,total:5,ratio:0.8,percent:80}, latency:{unit:"us",samples:4,p50:22,p99:52,min:12,max:52,mean:32}}'

# --- 異常系: 計測出力の検証失敗（rc=1）---
bad_jsonl="$tmp_root/bad.jsonl"
bad_exe="$tmp_root/bad_exe"
bad_case() { # 名前 変換後の JSONL を作るコマンド（stdout が bad.jsonl）
  bash -c "$2" >"$bad_jsonl"
  make_stub "$bad_exe" "$bad_jsonl"
  expect_rc "$1" 1 --exe "$bad_exe" --queries 5 --warmup 1
}
bad_case "不正 JSON は失敗" "cat '$good'; echo 'not json'"
bad_case "件数不足は失敗" "head -n 20 '$good'"
bad_case "未知の series は失敗" "sed 's/c2\\/svc-c/c3\\/svc-x/' '$good'"
bad_case "余分なキーは失敗" "sed 's/\"ok\":true/\"ok\":true,\"x\":1/' '$good'"
bad_case "試行番号の重複は失敗" "sed 's/\"trial\":4,/\"trial\":3,/' '$good'"
bad_case "ok:true なのに latency が null は失敗" "sed '10s/\"latency_us\":[0-9.]*/\"latency_us\":null/' '$good'"
bad_case "負の latency は失敗" "sed '10s/\"latency_us\":[0-9.]*/\"latency_us\":-1.000/' '$good'"
bad_case "ウォームアップ番号の不正は失敗" "sed '1s/\"trial\":0/\"trial\":1/' '$good'"

# --- 異常系: PID 取得・メモリ（rc=1）。正常な JSONL のスタブで挙動だけ切り替える ---
mem_case() { # 名前
  expect_rc "$1" 1 --exe "$good_exe" --queries 5 --warmup 1
  reset_stub
}
export STUB_PIDS=""
mem_case "cgroup.procs が空（ヘルパーが cgroup に参加していない）は失敗"
export STUB_PIDS="424242 424243"
mem_case "cgroup.procs の PID が 2 個は失敗"
export STUB_EXE_LINK="/usr/bin/sudo"
mem_case "exe が複製と一致しない PID（sudo の代役）は失敗"
export STUB_ARGV1="--other-mode"
mem_case "argv[1] が計測専用ヘルパーでない PID は失敗"
export STUB_SMAPS=$'Rss:                1200 kB'
mem_case "Pss 行が無いは失敗"
export STUB_SMAPS=$'Pss:                   0 kB\nRss:                1200 kB'
mem_case "Pss が 0 は失敗（0 を混入させない）"
export STUB_SMAPS=$'Pss:                 abc kB\nRss:                1200 kB'
mem_case "Pss が数値でないは失敗"
export STUB_SMAPS=$'Pss:                 530 kB'
mem_case "Rss 行が無いは失敗"

# --- 異常系: exe の失敗（rc=1）---
export STUB_EXIT=7
mem_case "exe の非ゼロ終了は失敗"
export STUB_NO_READY=1
mem_case "pss-ready が来ないまま exe が終了すると失敗"
export STUB_NO_READY=1 STUB_EXIT=7
mem_case "pss-ready なしの非ゼロ終了は失敗"

sleep_exe="$tmp_root/sleep_exe"
printf '#!%s\nsleep 30\n' "$bash_bin" >"$sleep_exe"
chmod 755 "$sleep_exe"
expect_rc "タイムアウトは失敗" 1 --exe "$sleep_exe" --queries 5 --warmup 1 --timeout 1

# --- タイムアウトで子孫プロセスが残らない ---
pidfile="$tmp_root/child.pid"
printf '#!%s\nsleep 300 & echo $! >%q; wait\n' "$bash_bin" "$pidfile" >"$sleep_exe"
chmod 755 "$sleep_exe"
expect_rc "タイムアウト（子孫あり）は失敗" 1 --exe "$sleep_exe" --queries 5 --warmup 1 --timeout 1
child_pid="$(cat "$pidfile" 2>/dev/null || true)"
if [ -n "$child_pid" ] && ! kill -0 "$child_pid" 2>/dev/null; then
  pass "タイムアウト後に子孫プロセスが残らない"
else
  fail "タイムアウト後に子孫プロセスが残っている (pid=$child_pid)"
  [ -z "$child_pid" ] || kill -KILL "$child_pid" 2>/dev/null || true
fi
if [ -z "$(ls -A "$fake_cg")" ]; then pass "失敗後も専用 cgroup が後始末される"; else fail "失敗後に専用 cgroup が残っている"; fi

# --- 異常系: 入力エラー（rc=2）---
expect_rc "--exe 必須" 2 --queries 5
expect_rc "相対パスの exe" 2 --exe "relative_exe" --queries 5
expect_rc "存在しない exe" 2 --exe "$tmp_root/none" --queries 5
ln -s "$good_exe" "$tmp_root/link_exe"
expect_rc "symlink の exe" 2 --exe "$tmp_root/link_exe" --queries 5
writable_exe="$tmp_root/writable_exe"
make_stub "$writable_exe" "$good"
chmod 775 "$writable_exe"
expect_rc "group 書き込み可の exe" 2 --exe "$writable_exe" --queries 5 --warmup 1
chmod 757 "$writable_exe"
expect_rc "other 書き込み可の exe" 2 --exe "$writable_exe" --queries 5 --warmup 1
chmod 755 "$writable_exe"
loose_dir="$tmp_root/loose"
mkdir -p "$loose_dir"
make_stub "$loose_dir/exe" "$good"
chmod 777 "$loose_dir"
expect_rc "親ディレクトリが other 書き込み可の exe" 2 --exe "$loose_dir/exe" --queries 5 --warmup 1
expect_rc "非正規パス（..）の exe" 2 --exe "$tmp_root/loose/../good_exe" --queries 5 --warmup 1
expect_rc "queries 範囲外 (0)" 2 --exe "$good_exe" --queries 0
expect_rc "queries 範囲外 (10001)" 2 --exe "$good_exe" --queries 10001
expect_rc "warmup 範囲外 (1001)" 2 --exe "$good_exe" --warmup 1001
expect_rc "queries 非数値" 2 --exe "$good_exe" --queries abc
expect_rc "timeout 範囲外 (0)" 2 --exe "$good_exe" --timeout 0
expect_rc "label 不正" 2 --exe "$good_exe" --label 'a b;c'
expect_rc "未知の引数" 2 --exe "$good_exe" --bogus 1
expect_rc "値の欠落" 2 --exe "$good_exe" --queries

# 自己テスト専用の引数は、環境変数なしでは受け付けない。
rc=0
env -u FANDHE_DNS_HELPER_MEASURE_SELFTEST "$bash_bin" "$target_script" --exe "$good_exe" --proc-root "$fake_proc" >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then pass "--proc-root は自己テスト以外で拒否 (rc=2)"; else fail "--proc-root の拒否: expected rc=2, got $rc"; fi
rc=0
env -u FANDHE_DNS_HELPER_MEASURE_SELFTEST "$bash_bin" "$target_script" --exe "$good_exe" --cgroup-parent "$fake_cg" >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then pass "--cgroup-parent は自己テスト以外で拒否 (rc=2)"; else fail "--cgroup-parent の拒否: expected rc=2, got $rc"; fi
# 非 root では実 cgroup の作成に進まず入力エラーにする（root で実行している環境では判定できないため省略）。
if [ "$(id -u)" != "0" ]; then
  rc=0
  env -u FANDHE_DNS_HELPER_MEASURE_SELFTEST "$bash_bin" "$target_script" --exe "$good_exe" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 2 ]; then pass "非 root は入力エラー (rc=2)"; else fail "非 root: expected rc=2, got $rc"; fi
fi

# --- 前提ツール欠如（rc=3）: PATH から jq を外す ---
no_jq_dir="$tmp_root/nojq"
mkdir -p "$no_jq_dir"
for tool in timeout mktemp stat rm cat sleep grep setsid realpath chmod readlink mkdir rmdir touch head tr sed wc seq id dirname; do
  tool_path="$(command -v "$tool")"
  ln -s "$tool_path" "$no_jq_dir/$tool"
done
rc=0
PATH="$no_jq_dir" "$bash_bin" "$target_script" --exe "$good_exe" --queries 5 >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 3 ]; then pass "jq 欠如 (rc=3)"; else fail "jq 欠如: expected rc=3, got $rc"; fi

if [ "$failures" -ne 0 ]; then
  echo "dns_helper_measure_selftest: $failures failure(s)" >&2
  exit 1
fi
echo "dns_helper_measure_selftest: all passed"
