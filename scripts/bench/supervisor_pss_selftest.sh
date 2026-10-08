#!/usr/bin/env bash
# scripts/bench/supervisor_pss.sh の自己テスト（TASK-158・SUP-2・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へ疑似 /proc を生成し、--proc-root で計測スクリプトへ渡して
# 出力と終了コードを具体値で照合する。呼び出し元は Makefile の `supervisor-pss-selftest`。
# 実プロセスは計測しない。期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。
# Linux・非 root 限定で、前提を満たさない環境では skip せず失敗する（ci.md「skip で CI を通さない」）。

set -euo pipefail

export FANDHE_SUPERVISOR_PSS_SELFTEST=1

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/supervisor_pss.sh"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

failures=0

if [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: selftest must not run as root (chmod-based unreadable cases would not be exercised)" >&2
  exit 1
fi
if [ "$(uname -s)" != "Linux" ]; then
  echo "FAIL: selftest requires Linux" >&2
  exit 1
fi

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# 疑似プロセスを作る。引数: <proc-root> <pid> <argv0> <pss> <rss> [exe] [comm]
mkproc() {
  local d="$1/$2" exe="${6:-$3}"
  mkdir -p "$d"
  if [ "$exe" != "-" ]; then ln -s "/opt/bin/${exe##*/}" "$d/exe"; fi
  printf '%s\0--flag\0' "$3" >"$d/cmdline"
  printf '%s\n' "${7:-${3##*/}}" >"$d/comm"
  printf 'Rss: 1 kB\nPss: %s kB\n' "$4" >"$d/smaps_rollup"
  printf 'Name: x\nPPid:\t1000\nVmRSS: %s kB\n' "$5" >"$d/status"
}

# 期待 exit コードと stdout の部分一致を照合する。引数: <名前> <期待exit> <期待文字列(空可)> <args...>
check() {
  local name="$1" want="$2" needle="$3"
  shift 3
  local out actual=0
  out="$(bash "$target" "$@" 2>/dev/null)" || actual=$?
  if [ "$actual" -ne "$want" ]; then
    fail "${name} (expected exit=${want}, actual=${actual})"
  elif [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
    fail "${name} (missing output: ${needle})"
  elif [ "$want" -ne 0 ] && [ -n "$out" ]; then
    fail "${name} (stdout must be empty on failure)"
  else
    pass "${name}"
  fi
}

sup=fandhe-container-supervisor

# 1. PID 指定（AC1）。text / JSON
one="${root}/one"
mkproc "$one" 300 "/opt/bin/${sup}" 600 900
mkproc "$one" 301 /usr/bin/bash 10 10
check "pid-single-text" 0 "process pid=300 name=${sup} pss_kb=600 rss_kb=900" --proc-root "$one" --pid 300 --interval 0
check "pid-single-median" 0 "per_process_pss_kb_median=600.0" --proc-root "$one" --pid 300
check "pid-single-json" 0 '"pss_kb": 600' --proc-root "$one" --pid 300 --format json
check "json-behavior-sup2" 0 '"behavior": "SUP-2"' --proc-root "$one" --pid 300 --format json
check "json-task-158" 0 '"task": "TASK-158"' --proc-root "$one" --pid 300 --format json
check "json-target-reference" 0 '"target_pss_kb": 2048' --proc-root "$one" --pid 300 --format json
check "pid-not-target-exe" 3 "" --proc-root "$one" --pid 301
check "pid-missing" 3 "" --proc-root "$one" --pid 999
check "count-1-found" 0 "apportioned_pss_kb_median=600.0" --proc-root "$one" --count 1

# 2. 按分（AC2）。3 個で 300 / 600 / 900
three="${root}/three"
mkproc "$three" 400 "$sup" 300 1
mkproc "$three" 401 "$sup" 600 1
mkproc "$three" 402 "$sup" 900 1
check "count-3-total" 0 "total_pss_kb_median=1800.0" --proc-root "$three" --count 3
check "count-3-apportioned" 0 "apportioned_pss_kb_median=600.0" --proc-root "$three" --count 3
check "count-3-per-process-median" 0 "per_process_pss_kb_median=600.0" --proc-root "$three" --count 3
check "pid-3-apportioned" 0 "apportioned_pss_kb_median=600.0" --proc-root "$three" --pid 400 --pid 401 --pid 402
check "samples-odd" 0 '"sample_totals_pss_kb": [1800, 1800, 1800]' --proc-root "$three" --count 3 --samples 3 --interval 0 --format json
check "samples-even" 0 "apportioned_pss_kb_median=600.0" --proc-root "$three" --count 3 --samples 2 --interval 0
check "count-too-many-expected" 3 "" --proc-root "$three" --count 4
check "count-too-few-expected" 3 "" --proc-root "$three" --count 2

# 3. 丸め: 合計 1000 / 3 = 333.33 -> 333.3、合計 2000 / 3 = 666.67 -> 666.7
round="${root}/round"
mkproc "$round" 500 "$sup" 333 1
mkproc "$round" 501 "$sup" 333 1
mkproc "$round" 502 "$sup" 334 1
check "round-down" 0 "apportioned_pss_kb_median=333.3" --proc-root "$round" --count 3
round2="${root}/round2"
mkproc "$round2" 510 "$sup" 666 1
mkproc "$round2" 511 "$sup" 667 1
mkproc "$round2" 512 "$sup" 667 1
check "round-up" 0 "apportioned_pss_kb_median=666.7" --proc-root "$round2" --count 3

# 4. 偶数個のプロセス間中央値（中央 2 値の平均）。100 / 200 / 300 / 500 -> 250.0、按分 275.0
even="${root}/even"
mkproc "$even" 600 "$sup" 100 1
mkproc "$even" 601 "$sup" 200 1
mkproc "$even" 602 "$sup" 300 1
mkproc "$even" 603 "$sup" 500 1
check "even-per-process-median" 0 "per_process_pss_kb_median=250.0" --proc-root "$even" --count 4
check "even-apportioned" 0 "apportioned_pss_kb_median=275.0" --proc-root "$even" --count 4

# 5. 識別の fail-closed
alias_="${root}/alias"
mkproc "$alias_" 700 "$sup" 100 1 /opt/bin/other
check "claim-by-argv0" 3 "" --proc-root "$alias_" --count 1
alias2="${root}/alias2"
mkproc "$alias2" 710 other 100 1 /opt/bin/other fandhe-containe
check "claim-by-comm" 3 "" --proc-root "$alias2" --count 1
noexe="${root}/noexe"
mkproc "$noexe" 720 "$sup" 100 1 -
check "exe-unreadable" 3 "" --proc-root "$noexe" --count 1
check "expected-dir-match" 0 "count=1" --proc-root "$one" --count 1 --expected-dir /opt/bin
check "expected-dir-mismatch" 3 "" --proc-root "$one" --count 1 --expected-dir /usr/bin

# 6. PSS 異常は 0 として足さず失敗
zero="${root}/zero"
mkproc "$zero" 800 "$sup" 0 1
check "pss-zero" 3 "" --proc-root "$zero" --count 1
nonnum="${root}/nonnum"
mkproc "$nonnum" 810 "$sup" abc 1
check "pss-non-numeric" 3 "" --proc-root "$nonnum" --count 1
missing="${root}/missing"
mkproc "$missing" 820 "$sup" 5 1
printf 'Rss: 1 kB\n' >"$missing/820/smaps_rollup"
check "pss-missing" 3 "" --proc-root "$missing" --count 1
unread="${root}/unread"
mkproc "$unread" 830 "$sup" 5 1
chmod 000 "$unread/830/smaps_rollup"
check "smaps-unreadable" 3 "" --proc-root "$unread" --count 1
chmod 600 "$unread/830/smaps_rollup"

# 7. 引数エラー
check "pid-count-exclusive" 2 "" --proc-root "$one" --pid 300 --count 1
check "no-mode" 2 "" --proc-root "$one"
check "count-zero" 2 "" --proc-root "$one" --count 0
check "count-too-big" 2 "" --proc-root "$one" --count 1025
check "pid-leading-zero" 2 "" --proc-root "$one" --pid 0300
check "pid-duplicate" 2 "" --proc-root "$one" --pid 300 --pid 300
check "samples-zero" 2 "" --proc-root "$one" --pid 300 --samples 0
check "interval-too-big" 2 "" --proc-root "$one" --pid 300 --interval 601
check "bad-exe-name" 2 "" --proc-root "$one" --pid 300 --exe-name bash
check "bad-format" 2 "" --proc-root "$one" --pid 300 --format xml
check "unknown-arg" 2 "" --bogus
check "help" 0 "SUP-2" --help

# 8. selftest ゲートと OS 判定
gate_out=0
env -u FANDHE_SUPERVISOR_PSS_SELFTEST bash "$target" --proc-root "$one" --pid 300 >/dev/null 2>&1 || gate_out=$?
if [ "$gate_out" -eq 2 ]; then pass "proc-root-needs-selftest-env"; else fail "proc-root-needs-selftest-env (exit=${gate_out})"; fi
os_out=0
FANDHE_SUPERVISOR_PSS_UNAME_S=Darwin bash "$target" --pid 1 >/dev/null 2>&1 || os_out=$?
if [ "$os_out" -eq 2 ]; then pass "non-linux-unsupported"; else fail "non-linux-unsupported (exit=${os_out})"; fi

# 9. --output
out_ok="${root}/out.json"
check "output-written" 0 "" --proc-root "$one" --pid 300 --format json --output "$out_ok"
if grep -qF '"behavior": "SUP-2"' "$out_ok" 2>/dev/null; then pass "output-content"; else fail "output-content"; fi
mkdir "${root}/outdir"
check "output-is-directory" 2 "" --proc-root "$one" --pid 300 --output "${root}/outdir"
check "output-parent-missing" 2 "" --proc-root "$one" --pid 300 --output "${root}/nodir/out.json"
out_fail="${root}/out_fail.json"
check "output-not-published-on-failure" 3 "" --proc-root "$zero" --count 1 --output "$out_fail"
leftover="$(find "$root" -maxdepth 1 -name 'out_fail.json*' | wc -l)"
if [ "$leftover" -eq 0 ]; then pass "no-output-on-failure"; else fail "no-output-on-failure (${leftover} files)"; fi

# 10. AC3: スクリプトに SUP-2 が明記されている
if grep -q 'SUP-2' "$target"; then pass "script-mentions-sup2"; else fail "script-mentions-sup2"; fi

if [ "$failures" -ne 0 ]; then
  echo "FAILED: ${failures} case(s)" >&2
  exit 1
fi
echo "OK: all supervisor_pss selftest cases passed"
