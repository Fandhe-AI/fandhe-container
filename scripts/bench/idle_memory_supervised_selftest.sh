#!/usr/bin/env bash
# scripts/bench/idle_memory_supervised.sh の自己テスト（TASK-47・CORE-7・SUP-1・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へスタブ計測スクリプト（呼び出し回数ごとに before / supervised /
# after の結果を返す）とスタブ driver（up / down の呼び出しを記録する）を生成し、終了コード・出力 JSON・
# 呼び出し順序を具体値で照合する。実 /proc は読まず、実コンテナも起動しない（実計測は #215・人間担当）。
# 呼び出し元は Makefile の `idle-memory-supervised-selftest`。1 件でも期待と異なれば非ゼロで終了する
# （fail-closed）。Linux・非 root 限定で、前提を満たさない環境では skip せず失敗する
# （ci.md「skip で CI を通さない」）。

set -euo pipefail

export FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST=1

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/idle_memory_supervised.sh"
repo_root="$(cd "${script_dir}/../.." && pwd)"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

failures=0

if [ "$(uname -s)" != "Linux" ]; then
  echo "FAIL: selftest requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: selftest must not run as root (the operator-run measurement is out of CI scope)" >&2
  exit 1
fi

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# スタブ計測スクリプト。$STUB_DIR/m<n>（"<rc> <process_count> <pss> <rss>"）を n 回目の呼び出しで使い、
# 受け取った引数を m<n>.args へ記録する。--expect-zero で process_count != 0 なら idle_memory.sh と同じく
# 終了コード 1 で何も出力しない。
cat >"${root}/measure.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
n=0
[ ! -f "$STUB_DIR/count" ] || n="$(cat "$STUB_DIR/count")"
n=$((n + 1))
echo "$n" >"$STUB_DIR/count"
printf '%s\n' "$*" >"$STUB_DIR/m$n.args"
read -r rc pc pss rss <"$STUB_DIR/m$n"
[ ! -f "$STUB_DIR/m$n.sleep" ] || sleep "$(cat "$STUB_DIR/m$n.sleep")"
[ "$rc" -eq 0 ] || exit "$rc"
case " $* " in *" --expect-zero "*) [ "$pc" -eq 0 ] || exit 1 ;; esac
printf '{\n  "schema_version": 1,\n  "process_count": %s,\n  "pss_kb": %s,\n  "rss_kb": %s,\n  "vanished_count": 0,\n  "processes": [\n    {"pid": 1, "name": "x", "pss_kb": 9, "rss_kb": 9}\n  ]\n}\n' "$pc" "$pss" "$rss"
STUB

# スタブ driver。呼び出しを $STUB_DIR/driver.log へ記録し、up_rc / down_rc / up_sleep で挙動を変える。
cat >"${root}/driver.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
echo "$1" >>"$STUB_DIR/driver.log"
echo "driver-stdout-noise"
case "$1" in
  up)
    [ ! -f "$STUB_DIR/up_sleep" ] || sleep "$(cat "$STUB_DIR/up_sleep")"
    exit "$(cat "$STUB_DIR/up_rc" 2>/dev/null || echo 0)"
    ;;
  down) exit "$(cat "$STUB_DIR/down_rc" 2>/dev/null || echo 0)" ;;
  *) exit 64 ;;
esac
STUB
chmod +x "${root}/measure.sh" "${root}/driver.sh"

case_no=0
# ケースごとの作業ディレクトリを作り STUB_DIR を設定する。引数は 3 回分の "<rc> <pc> <pss> <rss>"。
new_case() {
  case_no=$((case_no + 1))
  STUB_DIR="${root}/case${case_no}"
  mkdir -p "$STUB_DIR"
  export STUB_DIR
  printf '%s\n' "$1" >"$STUB_DIR/m1"
  printf '%s\n' "$2" >"$STUB_DIR/m2"
  printf '%s\n' "$3" >"$STUB_DIR/m3"
}

# 計測スクリプトを差し替えて本体を実行する。終了コードを actual、stdout を out、stderr を errout へ入れる。
actual=0 out="" errout=""
run_target() {
  actual=0
  out="$(FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE="${root}/measure.sh" bash "$target" "$@" 2>"${root}/stderr")" || actual=$?
  errout="$(cat "${root}/stderr")"
}

expect_exit() {
  if [ "$actual" -ne "$2" ]; then fail "$1 (expected exit=$2, actual=${actual}: ${errout})"; return 1; fi
  return 0
}
expect_err() {
  if ! grep -qF -- "$2" <<<"$errout"; then fail "$1 (missing stderr: $2; got: ${errout})"; return 1; fi
  return 0
}
driver_log() { if [ -f "$STUB_DIR/driver.log" ]; then tr '\n' ',' <"$STUB_DIR/driver.log"; fi; }

driver="${root}/driver.sh"

# 1. 正常系: 0 → 2 プロセス → 0。値・呼び出し順・--expected-dir の素通しを照合する。
new_case "0 0 0 0" "0 2 150 500" "0 0 0 0"
run_target --driver "$driver" --expected-dir /opt/a --expected-dir /opt/b --timeout 30
ok=1
expect_exit "normal-exit" 0 || ok=0
for needle in '"task": "TASK-47"' '"behavior": "CORE-7"' \
  '"before": {"process_count": 0, "pss_kb": 0, "rss_kb": 0}' \
  '"supervised": {"process_count": 2, "pss_kb": 150, "rss_kb": 500}' \
  '"after": {"process_count": 0, "pss_kb": 0, "rss_kb": 0}' \
  '"driver": {"up_exit": 0, "down_exit": 0}'; do
  grep -qF -- "$needle" <<<"$out" || { fail "normal-json (missing: ${needle})"; ok=0; }
done
[ "$(driver_log)" = "up,down," ] || { fail "normal-driver-order (got: $(driver_log))"; ok=0; }
[ "$(cat "$STUB_DIR/m1.args")" = "--format json --expect-zero --expected-dir /opt/a --expected-dir /opt/b" ] ||
  { fail "normal-args-before (got: $(cat "$STUB_DIR/m1.args"))"; ok=0; }
[ "$(cat "$STUB_DIR/m2.args")" = "--format json --expected-dir /opt/a --expected-dir /opt/b" ] ||
  { fail "normal-args-supervised (got: $(cat "$STUB_DIR/m2.args"))"; ok=0; }
[ "$(cat "$STUB_DIR/m3.args")" = "--format json --expect-zero --expected-dir /opt/a --expected-dir /opt/b" ] ||
  { fail "normal-args-after (got: $(cat "$STUB_DIR/m3.args"))"; ok=0; }
grep -qF "driver-stdout-noise" <<<"$out" && { fail "normal-driver-stdout-leaked"; ok=0; }
grep -qF "$driver" <<<"$out" && { fail "normal-driver-path-leaked"; ok=0; }
[ "$ok" -eq 1 ] && pass "normal-0-2-0"

# 2. before が 0 でない → 1。driver は呼ばれない。
new_case "0 1 10 10" "0 2 150 500" "0 0 0 0"
run_target --driver "$driver"
if expect_exit "before-not-zero" 1 && expect_err "before-not-zero" "before-not-zero"; then
  [ -z "$out" ] && [ -z "$(driver_log)" ] && pass "before-not-zero" || fail "before-not-zero (out or driver call leaked: $(driver_log))"
fi

# 3. supervised が 0 → 1。down は呼ばれる。
new_case "0 0 0 0" "0 0 0 0" "0 0 0 0"
run_target --driver "$driver"
if expect_exit "supervised-zero" 1 && expect_err "supervised-zero" "supervised-zero"; then
  [ -z "$out" ] && [ "$(driver_log)" = "up,down," ] && pass "supervised-zero" || fail "supervised-zero (got: $(driver_log))"
fi

# 4. after が 0 でない → 1。stdout は空、--output は未公開、既存ファイルは不変。
new_case "0 0 0 0" "0 2 150 500" "0 1 20 40"
printf 'keep\n' >"${STUB_DIR}/result.json"
run_target --driver "$driver" --output "${STUB_DIR}/result.json"
if expect_exit "after-not-zero" 1 && expect_err "after-not-zero" "after-not-zero"; then
  leftovers="$(find "$STUB_DIR" -maxdepth 1 -name 'result.json.*' | wc -l)"
  if [ -z "$out" ] && [ "$(cat "${STUB_DIR}/result.json")" = "keep" ] && [ "$leftovers" -eq 0 ]; then
    pass "after-not-zero-unpublished"
  else
    fail "after-not-zero-unpublished (out='${out}' leftovers=${leftovers})"
  fi
fi

# 5. 計測失敗（各フェーズ rc=3）→ 3。up 後の失敗では down が呼ばれる。
new_case "3 0 0 0" "0 2 1 1" "0 0 0 0"
run_target --driver "$driver"
expect_exit "measure-fail-before" 3 && [ -z "$(driver_log)" ] && pass "measure-fail-before" || fail "measure-fail-before (driver: $(driver_log))"
new_case "0 0 0 0" "3 0 0 0" "0 0 0 0"
run_target --driver "$driver"
expect_exit "measure-fail-supervised" 3 && [ "$(driver_log)" = "up,down," ] && pass "measure-fail-supervised" || fail "measure-fail-supervised (driver: $(driver_log))"
new_case "0 0 0 0" "0 2 1 1" "3 0 0 0"
run_target --driver "$driver"
expect_exit "measure-fail-after" 3 && [ "$(driver_log)" = "up,down," ] && pass "measure-fail-after" || fail "measure-fail-after (driver: $(driver_log))"

# 6. 計測のタイムアウト → 3。
new_case "0 0 0 0" "0 2 1 1" "0 0 0 0"
echo 30 >"$STUB_DIR/m2.sleep"
run_target --driver "$driver" --timeout 1
expect_exit "measure-timeout" 3 && expect_err "measure-timeout" "timed out after 1s" &&
  [ "$(driver_log)" = "up,down," ] && pass "measure-timeout" || fail "measure-timeout (driver: $(driver_log))"

# 7. driver up 失敗 → 3、down は呼ばれる。
new_case "0 0 0 0" "0 2 1 1" "0 0 0 0"
echo 7 >"$STUB_DIR/up_rc"
run_target --driver "$driver"
expect_exit "driver-up-fail" 3 && expect_err "driver-up-fail" "driver up failed" &&
  [ "$(driver_log)" = "up,down," ] && pass "driver-up-fail" || fail "driver-up-fail (driver: $(driver_log))"

# 8. driver up タイムアウト → 3、down は呼ばれる。
new_case "0 0 0 0" "0 2 1 1" "0 0 0 0"
echo 30 >"$STUB_DIR/up_sleep"
run_target --driver "$driver" --timeout 1
expect_exit "driver-up-timeout" 3 && [ "$(driver_log)" = "up,down," ] && pass "driver-up-timeout" || fail "driver-up-timeout (driver: $(driver_log))"

# 9. driver down 失敗 → 3、残存の可能性を明示。
new_case "0 0 0 0" "0 2 1 1" "0 0 0 0"
echo 9 >"$STUB_DIR/down_rc"
run_target --driver "$driver"
expect_exit "driver-down-fail" 3 && expect_err "driver-down-fail" "may still be running" &&
  [ "$(driver_log)" = "up,down," ] && pass "driver-down-fail" || fail "driver-down-fail (driver: $(driver_log))"

# 9b. 期待違反（exit 1）の後に cleanup の down が失敗 → 後始末失敗が優先され 3。
new_case "0 0 0 0" "0 0 0 0" "0 0 0 0"
echo 9 >"$STUB_DIR/down_rc"
run_target --driver "$driver"
expect_exit "cleanup-fail-priority-violation" 3 && expect_err "cleanup-fail-priority-violation" "cleanup-failed" && pass "cleanup-fail-priority" || fail "cleanup-fail-priority"

# 10. 正常系の --output はアトミックに公開される（JSON 全体を具体値で照合）。
new_case "0 0 0 0" "0 3 210 640" "0 0 0 0"
run_target --driver "$driver" --output "${STUB_DIR}/result.json"
if expect_exit "output-publish" 0; then
  if [ -z "$out" ] && grep -qF '"supervised": {"process_count": 3, "pss_kb": 210, "rss_kb": 640}' "${STUB_DIR}/result.json" &&
    [ "$(find "$STUB_DIR" -maxdepth 1 -name 'result.json.*' | wc -l)" -eq 0 ]; then
    pass "output-publish"
  else
    fail "output-publish"
  fi
fi

# 11. 引数エラー → 2（driver・計測は起動されない）。
new_case "0 0 0 0" "0 2 1 1" "0 0 0 0"
printf '#!/bin/sh\nexit 0\n' >"${STUB_DIR}/noexec.sh"
check_arg() {
  local name="$1" needle="$2"
  shift 2
  run_target "$@"
  if expect_exit "$name" 2 && expect_err "$name" "$needle"; then
    [ ! -f "$STUB_DIR/count" ] && [ -z "$(driver_log)" ] && pass "$name" || fail "$name (something was executed)"
  fi
}
check_arg "arg-no-driver" "--driver <absolute-path> is required"
check_arg "arg-relative-driver" "must be an absolute path" --driver driver.sh
check_arg "arg-non-executable-driver" "not an executable regular file" --driver "${STUB_DIR}/noexec.sh"
check_arg "arg-driver-directory" "not an executable regular file" --driver "$root"
check_arg "arg-unknown" "unknown argument: --bogus" --driver "$driver" --bogus
check_arg "arg-timeout-zero" "--timeout must be" --driver "$driver" --timeout 0
check_arg "arg-timeout-text" "--timeout must be" --driver "$driver" --timeout 1s
check_arg "arg-timeout-long" "--timeout must be" --driver "$driver" --timeout 1000000
check_arg "arg-settle-bad" "--settle must be" --driver "$driver" --settle 99999
check_arg "arg-output-dir" "output path is a directory" --driver "$driver" --output "$STUB_DIR"
check_arg "arg-output-missing-dir" "output directory does not exist" --driver "$driver" --output "${STUB_DIR}/nodir/x.json"
check_arg "arg-value-missing" "--driver requires a value" --driver

# 12. 差し替え環境変数は selftest フラグなしでは拒否 → 2。
new_case "0 0 0 0" "0 2 1 1" "0 0 0 0"
actual=0
errout="$(env -u FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE="${root}/measure.sh" \
  bash "$target" --driver "$driver" 2>&1 >/dev/null)" || actual=$?
if expect_exit "override-needs-selftest-flag" 2 && expect_err "override-needs-selftest-flag" "for selftest only"; then
  [ ! -f "$STUB_DIR/count" ] && pass "override-needs-selftest-flag" || fail "override-needs-selftest-flag (measure ran)"
fi

# 13. 非 Linux（OS 名の注入）→ 2。
actual=0
errout="$(FANDHE_IDLE_MEMORY_SUPERVISED_UNAME_S=Darwin bash "$target" --driver "$driver" 2>&1 >/dev/null)" || actual=$?
expect_exit "non-linux" 2 && expect_err "non-linux" "only Linux is supported (got Darwin)" && pass "non-linux"

# 14. stderr の制御文字は無害化される（--driver に ESC を含める）。
actual=0
errout="$(bash "$target" --driver "/nonexistent/$(printf '\033[31m')x" 2>&1 >/dev/null)" || actual=$?
if expect_exit "stderr-sanitized" 2; then
  if grep -q "$(printf '\033')" <<<"$errout"; then fail "stderr-sanitized (ESC leaked)"; else pass "stderr-sanitized"; fi
fi

# 15. Makefile の配線: DRIVER 未指定は案内付きで 2、スクリプトの終了コード 0〜3 は素通し、
# timeout は 3、起動不能は 2 へ変換する。make 自体は失敗時に 2 で終わるため "Error <n>" 行で照合する。
check_make() {
  local name="$1" want="$2" needle="$3" stub="$4" tmo="$5" drv="$6" errout2
  printf '%s\n' "$stub" >"${root}/make_stub.sh"
  errout2="$(make -s --no-print-directory -C "$repo_root" idle-memory-supervised \
    IDLE_MEMORY_SUPERVISED_SCRIPT="${root}/make_stub.sh" IDLE_MEMORY_SUPERVISED_TIMEOUT="$tmo" DRIVER="$drv" 2>&1 >/dev/null)" || true
  if [ "$want" -eq 0 ]; then
    if grep -q 'Error [0-9]' <<<"$errout2"; then fail "${name} (unexpected: ${errout2})"; else pass "$name"; fi
  elif ! grep -qE "\] Error ${want}\$" <<<"$errout2"; then
    fail "${name} (expected Error ${want}: ${errout2})"
  elif [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$errout2"; then
    fail "${name} (missing stderr: ${needle})"
  else
    pass "$name"
  fi
}
check_make "make-passthrough-0" 0 "" "exit 0" 5 /bin/true
check_make "make-passthrough-1" 1 "" "exit 1" 5 /bin/true
check_make "make-passthrough-3" 3 "" "exit 3" 5 /bin/true
check_make "make-timeout-to-3" 3 "timed out after 1s" "sleep 30" 1 /bin/true
check_make "make-unexpected-to-3" 3 "unexpected exit status 5" "exit 5" 5 /bin/true
check_make "make-cannot-run-to-2" 2 "cannot run the measurement under timeout (exit 127)" "exit 127" 5 /bin/true
check_make "make-invalid-timeout-2" 2 "IDLE_MEMORY_SUPERVISED_TIMEOUT must be" "exit 0" 0 /bin/true
check_make "make-driver-missing-2" 2 "DRIVER=<absolute-path> is required" "exit 0" 5 ""

if [ "$failures" -ne 0 ]; then
  echo "${failures} case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
