#!/usr/bin/env bash
# cli-parity-check.sh のタイムアウト時に、ネイティブ exe の子孫が回収されるかを確かめる（#1548・
# TASK-125.1・CLI-1・REPAIR-5）。Git Bash（MSYS2）ではネイティブ exe の子が POSIX の pgid を持たず、
# プロセスグループ宛ての kill が届かない可能性があるため、CI の 3 OS で実測する。
# CI の platform-ci ジョブが `make cli-parity-native-reclaim-check` で呼ぶ。make ci には含めない。
# 結果は `cli-parity native reclaim: ...` の行で出す（CI ログから grep できる）。
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fail() { printf 'FAIL: %s\n' "$1"; exit 1; }

command -v rustc >/dev/null 2>&1 || fail "rustc not found"
exe=""
case "${OSTYPE:-}" in msys* | cygwin*) exe=".exe" ;; esac
helper="$work/native-hang$exe"
rustc --edition 2021 -O -o "$helper" "$root/scripts/testdata/cli-parity/native-hang.rs" || fail "helper build failed"

count_ticks() { # <dir>。tick 行の総数
  local n=0 f l
  for f in "$1"/ticks.*; do
    [ -f "$f" ] || continue
    while IFS= read -r l; do n=$((n + 1)); done <"$f"
  done
  printf '%s' "$n"
}
count_role() { # <dir> <role>。そのロールの tick ファイル数
  local n=0 f
  for f in "$1"/ticks."$2".*; do
    if [ -f "$f" ]; then n=$((n + 1)); fi
  done
  printf '%s' "$n"
}

# ベースライン診断（判定には使わない）: プロセスグループ宛ての kill だけで子が止まるか。
base="$work/base"
mkdir "$base"
set -m
STUB_NATIVE_DIR="$base" "$helper" bogus </dev/null >/dev/null 2>&1 &
bpid=$!
set +m
w=0
while [ "$(count_role "$base" child)" -lt 1 ] && [ "$w" -lt 50 ]; do
  sleep 0.1
  w=$((w + 1))
done
kill -TERM -- "-$bpid" 2>/dev/null || true
sleep 0.5
kill -KILL -- "-$bpid" 2>/dev/null || true
wait "$bpid" 2>/dev/null || true
b1="$(count_ticks "$base")"
sleep 3
b2="$(count_ticks "$base")"
base_alive=0
if [ "$b2" -gt "$b1" ]; then base_alive=1; fi
echo "cli-parity native reclaim: baseline_group_kill_descendant_alive=$base_alive"

# 本判定: capture のタイムアウト回収で子孫が残らないこと。
run="$work/run"
mkdir "$run"
rc=0
started=$SECONDS
STUB_NATIVE_DIR="$run" bash "$root/scripts/cli-parity-check.sh" capture --cli "$helper" --output "$work/cap.txt" --timeout 2 >/dev/null 2>"$work/cap.err" || rc=$?
[ "$rc" -eq 1 ] || fail "capture rc expected 1 (timeout), got $rc"
tab=$'\t'
a02=""
a01=""
while IFS= read -r l; do
  case "$l" in
    "A02$tab"*) a02="$l" ;;
    "A01$tab"*) a01="$l" ;;
  esac
done <"$work/cap.txt"
IFS=$'\t' read -r _ _ _ code out <<<"$a02"
[ "$code" = "<timeout>" ] && [ "$out" = "<timeout>" ] || fail "A02 expected <timeout> code and stdout"
[ "$a01" = "A01${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-" ] || fail "A01 unexpected record"
[ "$(count_role "$run" parent)" -ge 1 ] || fail "parent never started"
[ "$(count_role "$run" child)" -ge 1 ] || fail "child never started (probe is vacuous)"
t1="$(count_ticks "$run")"
sleep 3
t2="$(count_ticks "$run")"
alive=0
if [ "$t2" -gt "$t1" ]; then alive=1; fi
# ヘルパーは起動から約 120 秒で自然終了する。観測がその前に終わっていなければ、回収失敗でも tick が
# 増えず偽陽性になるため、判定不能として失敗させる（余裕を見て 90 秒を上限にする）。
elapsed=$((SECONDS - started))
[ "$elapsed" -le 90 ] || fail "observation finished too late to be conclusive (elapsed=${elapsed}s, helper lifetime 120s)"
winpid=no
case "${OSTYPE:-}" in msys* | cygwin*) if [ -r "/proc/$$/winpid" ]; then winpid=yes; fi ;; esac
echo "cli-parity native reclaim: os=$(uname -s | cut -c1-7) descendant_alive=$alive winpid_available=$winpid"
[ "$alive" -eq 0 ] || fail "descendants survived the timeout reclaim"
echo "ok: native reclaim"
