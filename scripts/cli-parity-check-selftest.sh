#!/usr/bin/env bash
# scripts/cli-parity-check.sh の自己テスト（TASK-125.1・CLI-1・REPAIR-12）。
#
# 役割: 製品バイナリ・root を使わず、契約どおりの出力を返すスタブ CLI（一時ディレクトリに生成する bash
# スクリプト）だけで capture / compare の挙動を具体値で照合する。実機での 3 OS 比較そのものは
# #661（人間担当）の範囲で、本テストはその道具が壊れていないことだけを確かめる。
#
# 呼び出し元: Makefile の `cli-parity-selftest`、CI の integration-test ジョブ（ubuntu・macos。
# Windows の Git Bash は未検証のため対象外）。make ci には含めない。
# 失敗は `FAIL:` 行を出し、最後に非 0 で終了する。bash 3.2 以上で動く。
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="$script_dir/cli-parity-check.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fails=0

fail() {
  printf 'FAIL: %s\n' "$1"
  fails=$((fails + 1))
}
pass() { printf 'ok: %s\n' "$1"; }

# 期待する終了コードと一致するか確かめる。
expect_rc() {
  local name="$1" want="$2" got="$3"
  if [ "$got" -eq "$want" ]; then pass "$name"; else fail "$name (want rc=$want got rc=$got)"; fi
}

# --------------------------------------------------
# スタブ CLI。STUB_MODE で挙動を切り替える。
#   ok       = Linux の現行挙動を模した固定応答
#   nonlinux = 引数解析は同じで、解析後の全コマンドが FAILED_PRECONDITION（5）
#   diff     = ok と同じだが B03 相当（create 後の list）の終了コードだけ変える
#   noisy    = ok と同じ終了コードで、stderr / stdout にパス風文字列・制御文字を流す
#   hang     = 未知コマンド（bogus）だけ止まる（子孫の sleep を残し得る構成）
#   nl       = create 成功時に改行のみを stdout へ出す
#   blank    = list の末尾に余分な空行を出す
#   nul      = create 成功時に NUL を含む出力を stdout へ出す
# --------------------------------------------------
stub="$work/stub-cli"
cat >"$stub" <<'STUB'
#!/usr/bin/env bash
mode="${STUB_MODE:-ok}"
seen_root=0
seen_pps=0
root=""
bad() {
  if [ "$mode" = "noisy" ]; then
    printf '{"code":"INVALID_ARGUMENT","message":"/home/secret-user/path \001 host-leak"}\n' >&2
  else
    printf '{"code":"INVALID_ARGUMENT","message":"usage"}\n' >&2
  fi
  exit 2
}
fail_with() { printf '{"code":"%s","message":"x"}\n' "$2" >&2; exit "$1"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || bad; [ "$seen_root" = 0 ] || bad; seen_root=1; root="$2"; shift 2 ;;
    --plugin-path-search) [ "$seen_pps" = 0 ] || bad; seen_pps=1; shift ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || bad
cmd="$1"; shift
valid_id() { [[ "$1" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; }
case "$cmd" in
  bogus)
    if [ "$mode" = "hang" ]; then
      # 子孫プロセスを作る（pid を記録して、回収されたか自己テストで確認する）。
      sleep 30 &
      [ -z "${STUB_PIDFILE:-}" ] || echo $! >>"$STUB_PIDFILE"
      wait
    fi
    bad ;;
  create)
    bundle=""; id=""; n=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --bundle) [ $# -ge 2 ] || bad; [ -z "$bundle" ] || bad; bundle="$2"; shift 2 ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ -n "$bundle" ] && [ "$n" -eq 1 ] && valid_id "$id" || bad ;;
  start | stop | logs)
    [ $# -eq 1 ] && valid_id "$1" && [ "${1#-}" = "$1" ] || bad; id="$1" ;;
  delete)
    force=0; n=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --force) [ "$force" = 0 ] || bad; force=1; shift ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ "$n" -eq 1 ] && valid_id "$id" || bad ;;
  list) [ $# -eq 0 ] || bad ;;
  *) bad ;;
esac
[ "$mode" = "nonlinux" ] && fail_with 5 FAILED_PRECONDITION
case "$cmd" in
  list)
    [ -d "$root" ] || fail_with 3 NOT_FOUND
    printf 'ID\tSTATUS\tPID\n'
    for f in "$root"/*.c; do
      [ -e "$f" ] || continue
      b="$(basename "$f" .c)"
      if [ -f "$root/$b.pid" ]; then printf '%s\tcreated\t4242\n' "$b"; else printf '%s\tcreated\t-\n' "$b"; fi
    done
    [ "$mode" = "blank" ] && printf '\n'
    [ "$mode" = "diff" ] && [ -e "$root/c1.c" ] && exit 7
    ;;
  create)
    [ -d "$root" ] || fail_with 3 NOT_FOUND
    [ -e "$root/$id.c" ] && fail_with 4 ALREADY_EXISTS
    : >"$root/$id.c"
    [ "$mode" = "noisy" ] && printf '/home/secret-user/out\n'
    [ "$mode" = "nl" ] && printf '\n'
    [ "$mode" = "nul" ] && printf 'a\000b'
    ;;
  start | logs) [ -e "$root/$id.c" ] || fail_with 3 NOT_FOUND; fail_with 8 UNIMPLEMENTED ;;
  stop) [ -e "$root/$id.c" ] || fail_with 3 NOT_FOUND; fail_with 5 FAILED_PRECONDITION ;;
  delete) [ -e "$root/$id.c" ] || fail_with 3 NOT_FOUND; rm -f "$root/$id.c" ;;
esac
exit 0
STUB
chmod +x "$stub"

run_capture() { # <mode> <output> [追加引数...]
  local mode="$1" out="$2"
  shift 2
  STUB_MODE="$mode" "$target" capture --cli "$stub" --output "$out" "$@" >/dev/null 2>"$work/stderr.txt"
}

line_of() { grep -E "^$2	" "$1" | head -n 1; } # <file> <case id>

# --- capture: 具体値 ---
run_capture ok "$work/ok.txt"
expect_rc "capture ok exits 0" 0 $?
count="$(grep -cE '^[AB][0-9]{2}	' "$work/ok.txt")"
[ "$count" = "33" ] && pass "capture records 33 cases" || fail "capture records 33 cases (got $count)"
[ "$(line_of "$work/ok.txt" A02)" = $'A02\tA\t2\tINVALID_ARGUMENT\t-' ] && pass "A02 usage error" || fail "A02 usage error"
[ "$(line_of "$work/ok.txt" B03)" = $'B03\tB\t0\t-\tlist:H;c1,created,-' ] && pass "B03 list after create" || fail "B03 list after create: $(line_of "$work/ok.txt" B03)"
[ "$(line_of "$work/ok.txt" B04)" = $'B04\tB\t4\tALREADY_EXISTS\t-' ] && pass "B04 duplicate create" || fail "B04 duplicate create"
[ "$(line_of "$work/ok.txt" B15)" = $'B15\tB\t3\tNOT_FOUND\t-' ] && pass "B15 missing state root" || fail "B15 missing state root"
head -n 2 "$work/ok.txt" | grep -qxE '# os=(linux|macos)' && pass "meta lines present" || fail "meta lines present"

# --- capture: 既存ファイルへの --output / 引数不足 / CLI 不在 ---
STUB_MODE=ok "$target" capture --cli "$stub" --output "$work/ok.txt" >/dev/null 2>&1
expect_rc "capture refuses existing --output" 2 $?
"$target" capture --cli "$stub" >/dev/null 2>&1
expect_rc "capture without --output is rc 2" 2 $?
"$target" capture --cli relative/path --output "$work/rel.txt" >/dev/null 2>&1
expect_rc "capture with relative --cli is rc 2" 2 $?
"$target" capture --cli "$work/does-not-exist" --output "$work/none.txt" >/dev/null 2>&1
expect_rc "capture with missing CLI is rc 3" 3 $?
[ ! -e "$work/none.txt" ] && pass "no output file for missing CLI" || fail "no output file for missing CLI"

# --- compare ---
"$target" compare --baseline "$work/ok.txt" --candidate "$work/ok.txt" >"$work/cmp.txt" 2>&1
expect_rc "compare identical is rc 0" 0 $?
grep -q 'layer A (syntax): match=18 mismatch=0 missing=0' "$work/cmp.txt" && pass "layer A summary" || fail "layer A summary"

run_capture diff "$work/diff.txt"
"$target" compare --baseline "$work/ok.txt" --candidate "$work/diff.txt" >"$work/cmp.txt" 2>&1
expect_rc "compare with changed exit code is rc 1" 1 $?
grep -q '^B03 MISMATCH' "$work/cmp.txt" && pass "B03 reported as MISMATCH" || fail "B03 reported as MISMATCH"
grep -q '^B01 MATCH' "$work/cmp.txt" && pass "unchanged case stays MATCH" || fail "unchanged case stays MATCH"

run_capture nonlinux "$work/nl.txt"
"$target" compare --baseline "$work/ok.txt" --candidate "$work/nl.txt" >"$work/cmp.txt" 2>&1
expect_rc "non-linux stub differs in layer B (rc 1)" 1 $?
grep -q 'layer A (syntax): match=18 mismatch=0 missing=0' "$work/cmp.txt" && pass "non-linux layer A all match" || fail "non-linux layer A all match"
grep -q 'layer B (behavior): match=1 mismatch=14 missing=0' "$work/cmp.txt" && pass "non-linux layer B mismatches (B08 coincides at 5)" || fail "non-linux layer B all mismatch: $(tail -n 1 "$work/cmp.txt")"

# ケース欠落は MISSING
grep -v '^B05	' "$work/ok.txt" >"$work/missing.txt"
"$target" compare --baseline "$work/ok.txt" --candidate "$work/missing.txt" >"$work/cmp.txt" 2>&1
expect_rc "missing case is rc 1" 1 $?
grep -q '^B05 MISSING' "$work/cmp.txt" && pass "B05 reported as MISSING" || fail "B05 reported as MISSING"

# 両側から同じケースが欠落しても MISSING（期待 ID 集合は CASES から作る）
grep -v '^B05	' "$work/ok.txt" >"$work/missing2.txt"
"$target" compare --baseline "$work/missing.txt" --candidate "$work/missing2.txt" >"$work/cmp.txt" 2>&1
expect_rc "case missing on both sides is rc 1" 1 $?
grep -q '^B05 MISSING' "$work/cmp.txt" && pass "B05 missing on both sides reported" || fail "B05 missing on both sides reported"

# タイムアウト記録同士は値が一致しても rc 1
run_capture hang "$work/hang1.txt" --timeout 1
run_capture hang "$work/hang2.txt" --timeout 1
"$target" compare --baseline "$work/hang1.txt" --candidate "$work/hang2.txt" >"$work/cmp.txt" 2>&1
expect_rc "matching timeout records are rc 1" 1 $?
grep -q '^A02 TIMEOUT' "$work/cmp.txt" && pass "A02 timeout reported" || fail "A02 timeout reported"

# 壊れた capture は rc 2
printf 'garbage\n' >"$work/broken.txt"
"$target" compare --baseline "$work/ok.txt" --candidate "$work/broken.txt" >/dev/null 2>&1
expect_rc "compare with broken capture is rc 2" 2 $?
sed 's/^A02	A	2/A02	A	999/' "$work/ok.txt" >"$work/badexit.txt"
"$target" compare --baseline "$work/ok.txt" --candidate "$work/badexit.txt" >/dev/null 2>&1
expect_rc "compare with malformed exit field is rc 2" 2 $?
"$target" compare --baseline "$work/ok.txt" >/dev/null 2>&1
expect_rc "compare without --candidate is rc 2" 2 $?

# --- 情報漏えい防止: パス風文字列・制御文字・ホスト名が記録に現れない ---
run_capture noisy "$work/noisy.txt"
if grep -qE 'secret-user|host-leak|/home' "$work/noisy.txt"; then fail "noisy output leaked into capture"; else pass "noisy output not leaked"; fi
if LC_ALL=C grep -q "$(printf '\001')" "$work/noisy.txt"; then fail "control char leaked into capture"; else pass "control chars not leaked"; fi
[ "$(line_of "$work/noisy.txt" B02)" = $'B02\tB\t0\t-\t<unexpected>:1' ] && pass "unexpected stdout is summarized" || fail "unexpected stdout is summarized: $(line_of "$work/noisy.txt" B02)"

# --- タイムアウト ---
run_capture hang "$work/hang.txt" --timeout 1
expect_rc "hanging CLI is rc 1" 1 $?
line_of "$work/hang.txt" A02 | grep -q '<timeout>' && pass "A02 recorded as timeout" || fail "A02 recorded as timeout"

# --- 改行のみ・NUL 含みの stdout は空出力 '-' と区別して異常として記録する ---
run_capture nl "$work/nl2.txt"
[ "$(line_of "$work/nl2.txt" B02)" = $'B02\tB\t0\t-\t<unexpected>:1' ] && pass "newline-only stdout is unexpected" || fail "newline-only stdout is unexpected: $(line_of "$work/nl2.txt" B02)"
run_capture nul "$work/nul.txt"
[ "$(line_of "$work/nul.txt" B02)" = $'B02\tB\t0\t-\t<unexpected>:nul' ] && pass "NUL stdout is unexpected" || fail "NUL stdout is unexpected: $(line_of "$work/nul.txt" B02)"
"$target" compare --baseline "$work/nl2.txt" --candidate "$work/nul.txt" >/dev/null 2>&1
expect_rc "unexpected-stdout captures pass format validation" 1 $?

# --- 解析不能な出力同士は一致扱いにしない（UNVERIFIED・rc 1） ---
"$target" compare --baseline "$work/noisy.txt" --candidate "$work/noisy.txt" >"$work/cmp.txt" 2>&1
expect_rc "identical <unexpected> records are rc 1" 1 $?
grep -q '^B02 UNVERIFIED' "$work/cmp.txt" && pass "B02 <unexpected> reported as UNVERIFIED" || fail "B02 <unexpected> reported as UNVERIFIED"
sed 's/^A02\tA\t2\tINVALID_ARGUMENT/A02\tA\t2\t<unparsed>/' "$work/ok.txt" >"$work/unparsed.txt"
"$target" compare --baseline "$work/unparsed.txt" --candidate "$work/unparsed.txt" >"$work/cmp.txt" 2>&1
expect_rc "identical <unparsed> records are rc 1" 1 $?
grep -q '^A02 UNVERIFIED' "$work/cmp.txt" && pass "A02 <unparsed> reported as UNVERIFIED" || fail "A02 <unparsed> reported as UNVERIFIED"

# --- list 出力の末尾の余分な空行は正常出力と区別して異常にする ---
run_capture blank "$work/blank.txt"
[ "$(line_of "$work/blank.txt" B03)" = $'B03\tB\t0\t-\t<unexpected>:3' ] && pass "trailing blank line in list is unexpected" || fail "trailing blank line in list is unexpected: $(line_of "$work/blank.txt" B03)"
"$target" compare --baseline "$work/ok.txt" --candidate "$work/blank.txt" >/dev/null 2>&1
expect_rc "list with trailing blank line differs from ok (rc 1)" 1 $?

# --- タイムアウト時に子孫プロセス（スタブの sleep）が残らない ---
: >"$work/pids.txt"
STUB_PIDFILE="$work/pids.txt" run_capture hang "$work/hang3.txt" --timeout 1
alive=0
for p in $(cat "$work/pids.txt"); do
  kill -0 "$p" 2>/dev/null && alive=$((alive + 1))
done
[ -s "$work/pids.txt" ] && [ "$alive" = "0" ] && pass "no descendant left after timeout" || fail "descendants left after timeout (alive=$alive)"

# --- 後始末: capture 自身の mktemp -d が残らない（TMPDIR を専用ディレクトリにして空を確認） ---
mkdir -p "$work/tmpdir"
TMPDIR="$work/tmpdir" STUB_MODE=ok "$target" capture --cli "$stub" --output "$work/again.txt" >/dev/null 2>&1
expect_rc "capture with private TMPDIR exits 0" 0 $?
leftover="$(ls -A "$work/tmpdir" | wc -l | tr -d ' ')"
[ "$leftover" = "0" ] && pass "no leftover temp directories" || fail "leftover temp directories ($leftover)"

if [ "$fails" -ne 0 ]; then
  printf '%s check(s) failed\n' "$fails"
  exit 1
fi
printf 'all cli-parity-check self tests passed\n'
