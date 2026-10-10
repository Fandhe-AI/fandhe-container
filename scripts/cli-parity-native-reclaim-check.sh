#!/usr/bin/env bash
# cli-parity-check.sh のタイムアウト時に、ネイティブ exe の子孫が回収されるかを確かめる（#1548・
# TASK-125.1・CLI-1・REPAIR-5）。Git Bash（MSYS2）ではネイティブ exe の子が POSIX の pgid を持たず、
# プロセスグループ宛ての kill が届かない可能性があるため、CI の 3 OS で実測する。
# CI の integration-test ジョブが `make cli-parity-native-reclaim-check` で呼ぶ。make ci には含めない。
# 結果は `cli-parity native reclaim: ...` の行で出す（CI ログから grep できる）。
#
# 全体の期限（#1688・REPAIR-5・REPAIR-7）: Windows の integration-test でこの確認が止まり、ステップの
# timeout-minutes が効かずジョブ上限まで止まらなかった（ログも残らなかった）。そこで本スクリプト自身が
# wall clock（$SECONDS）の期限（既定 150 秒 = ヘルパーの寿命 120 秒 + 余裕。ステップ上限 5 分より十分短い）を
# 持ち、全段（build・baseline・capture）をバックグラウンド起動して期限つきでポーリングする。期限を超えたら
# 子孫を回収し、`deadline_exceeded` の行を出して非ゼロで終わる。上限の無い `wait` は使わない。
# 経過時間を sleep の回数で数えない（Git Bash では sleep の fork が遅く、回数換算は wall time を過小に数える）。
# 段ごとの経過は `cli-parity native reclaim: phase=<段> event=start|end elapsed=<秒>` を stderr に出す。
#
# 試験・プローブ用の環境変数（値は許可リスト検証。不正値は終了コード 2。#1688）:
#   CLI_PARITY_RECLAIM_DEADLINE_SECS  全体の期限（10〜3600。既定 150）
#   CLI_PARITY_RECLAIM_TEST_HANG      baseline = baseline 段でグループ kill を送らない / capture = capture へ
#                                     --timeout 600 を渡し内側の監視に回収させない（ハングを注入する）
#   STUB_NATIVE_TICKS                 ヘルパーの寿命（60〜3600。既定 120）。期限より長くしてハングを模擬する
set -euo pipefail
export LC_ALL=C

started_all=$SECONDS
root="$(cd "$(dirname "$0")/.." && pwd)"
fail() { printf 'FAIL: %s\n' "$1"; exit 1; }
usage_fail() { printf 'FAIL: %s\n' "$1"; exit 2; }

deadline_secs="${CLI_PARITY_RECLAIM_DEADLINE_SECS:-150}"
test_hang="${CLI_PARITY_RECLAIM_TEST_HANG:-}"
helper_ticks="${STUB_NATIVE_TICKS:-120}"
[[ $deadline_secs =~ ^[1-9][0-9]{1,3}$ ]] && [ "$deadline_secs" -ge 10 ] && [ "$deadline_secs" -le 3600 ] ||
  usage_fail "CLI_PARITY_RECLAIM_DEADLINE_SECS must be 10..3600"
[[ $helper_ticks =~ ^[1-9][0-9]{1,3}$ ]] && [ "$helper_ticks" -ge 60 ] && [ "$helper_ticks" -le 3600 ] ||
  usage_fail "STUB_NATIVE_TICKS must be 60..3600"
case "$test_hang" in '' | baseline | capture) ;; *) usage_fail "CLI_PARITY_RECLAIM_TEST_HANG must be empty, baseline or capture" ;; esac
export STUB_NATIVE_TICKS="$helper_ticks"
deadline=$((started_all + deadline_secs))

is_windows=0
case "${OSTYPE:-}" in msys* | cygwin*) is_windows=1 ;; esac

work="$(mktemp -d)"
tracked_pid="" # 起動済みで未回収の子。EXIT trap と期限切れ回収の対象（回収済みの pid には何も送らない）
bounded_rc=0

log_phase() { # <段> <event>
  printf 'cli-parity native reclaim: phase=%s event=%s elapsed=%s\n' "$1" "$2" "$((SECONDS - started_all))" >&2
}

# 未回収の pid $1 の木を回収する。期限切れ時と EXIT trap から呼ぶ。順序が重要: Windows ではグループ kill
# より前に taskkill /T を送る（親が先に死ぬと /T は木を辿れない。cli-parity-check.sh の kill_win_tree と同じ理由）。
# winpid は数字のみ・桁数上限を検証してから渡す（インジェクション防止）。taskkill 自体にも 10 秒の上限を置く。
reclaim_tree() {
  local pid="$1" w="" tk until_s n
  if [ "$is_windows" -eq 1 ] && [ -r "/proc/$pid/winpid" ]; then
    IFS= read -r w <"/proc/$pid/winpid" || true
    case "$w" in
      '' | *[!0-9]* | ???????????*) ;;
      *)
        taskkill //F //T //PID "$w" >/dev/null 2>&1 &
        tk=$!
        until_s=$((SECONDS + 10))
        while kill -0 "$tk" 2>/dev/null && [ "$SECONDS" -lt "$until_s" ]; do sleep 0.2; done
        kill -KILL "$tk" 2>/dev/null || true
        wait "$tk" 2>/dev/null || true
        ;;
    esac
  fi
  kill -TERM -- "-$pid" 2>/dev/null || true
  sleep 0.5
  kill -KILL -- "-$pid" 2>/dev/null || true
  kill -KILL "$pid" 2>/dev/null || true # 未回収の子なので pid は再利用されていない
  n=0
  while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 50 ]; do
    sleep 0.1
    n=$((n + 1))
  done
  # 消えていなければ wait で塞がらない（上限の無い wait を使わない）。
  if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; fi
}

cleanup() {
  if [ -n "$tracked_pid" ]; then
    reclaim_tree "$tracked_pid" || true
    tracked_pid=""
  fi
  # Windows では生き残りがファイルを握ると rm が失敗し、set -e 下の trap が終了コードを変えるため握りつぶす。
  rm -rf -- "$work" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

# 期限切れ: 追跡中の木を回収し、その段の tick が 3 秒間増えるかを数え、機械可読な 1 行を出して失敗する。
expire() { # <段> <pid> <tick ディレクトリまたは空>
  local phase="$1" pid="$2" dir="$3" t1 t2 alive=0 elapsed
  reclaim_tree "$pid"
  tracked_pid=""
  if [ -n "$dir" ]; then
    t1="$(count_ticks "$dir")"
    sleep 3
    t2="$(count_ticks "$dir")"
    if [ "$t2" -gt "$t1" ]; then alive=1; fi
  fi
  elapsed=$((SECONDS - started_all))
  printf 'cli-parity native reclaim: deadline_exceeded phase=%s elapsed=%s deadline=%s descendant_alive=%s\n' \
    "$phase" "$elapsed" "$deadline_secs" "$alive" >&2
  fail "deadline exceeded in phase=$phase (elapsed=${elapsed}s, deadline=${deadline_secs}s)"
}

# 追跡中の tracked_pid の終了を期限つきで待つ。終了コードは bounded_rc。
wait_bounded() { # <段> <tick ディレクトリまたは空>
  local pid="$tracked_pid"
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then expire "$1" "$pid" "$2"; fi
    sleep 0.2
  done
  bounded_rc=0
  wait "$pid" || bounded_rc=$?
  tracked_pid=""
}

# <段> <tick ディレクトリまたは空> <cmd...> を独立グループで起動して期限つきで待つ。出力はステップの
# パイプを継承させずファイルへ付け替える（生き残りが runner の出力パイプを握り続けるのを避ける）。
run_bounded() {
  local phase="$1" dir="$2"
  shift 2
  log_phase "$phase" start
  set -m
  "$@" </dev/null >"$work/$phase.out" 2>"$work/$phase.err" &
  tracked_pid=$!
  set +m
  wait_bounded "$phase" "$dir"
  log_phase "$phase" end
}

command -v rustc >/dev/null 2>&1 || fail "rustc not found"
exe=""
if [ "$is_windows" -eq 1 ]; then exe=".exe"; fi
helper="$work/native-hang$exe"
run_bounded build "" rustc --edition 2021 -O -o "$helper" "$root/scripts/testdata/cli-parity/native-hang.rs"
if [ "$bounded_rc" -ne 0 ]; then
  head -c 2000 "$work/build.err" >&2 || true
  fail "helper build failed"
fi

# ベースライン診断（判定には使わない）: プロセスグループ宛ての kill だけで子が止まるか。
# 試験用の baseline ハング注入では kill を送らず、ヘルパーの寿命まで待たせて期限で止まることを確かめる。
base="$work/base"
mkdir "$base"
log_phase baseline start
set -m
STUB_NATIVE_DIR="$base" "$helper" bogus </dev/null >/dev/null 2>&1 &
tracked_pid=$!
set +m
bpid="$tracked_pid"
w=0
while [ "$(count_role "$base" child)" -lt 1 ] && [ "$w" -lt 50 ] && [ "$SECONDS" -lt "$deadline" ]; do
  sleep 0.1
  w=$((w + 1))
done
if [ "$test_hang" != "baseline" ]; then
  kill -TERM -- "-$bpid" 2>/dev/null || true
  sleep 0.5
  kill -KILL -- "-$bpid" 2>/dev/null || true
fi
wait_bounded baseline "$base"
log_phase baseline end
b1="$(count_ticks "$base")"
sleep 3
b2="$(count_ticks "$base")"
base_alive=0
if [ "$b2" -gt "$b1" ]; then base_alive=1; fi
echo "cli-parity native reclaim: baseline_group_kill_descendant_alive=$base_alive"

# 本判定: capture のタイムアウト回収で子孫が残らないこと。
run="$work/run"
mkdir "$run"
export STUB_NATIVE_DIR="$run"
capture_timeout=2
if [ "$test_hang" = "capture" ]; then capture_timeout=600; fi
started=$SECONDS
run_bounded capture "$run" bash "$root/scripts/cli-parity-check.sh" capture --cli "$helper" \
  --output "$work/cap.txt" --timeout "$capture_timeout"
[ "$bounded_rc" -eq 1 ] || fail "capture rc expected 1 (timeout), got $bounded_rc"
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
log_phase observe start
t1="$(count_ticks "$run")"
sleep 3
t2="$(count_ticks "$run")"
alive=0
if [ "$t2" -gt "$t1" ]; then alive=1; fi
# ヘルパーは起動から約 helper_ticks 秒（既定 120）で自然終了する。観測がその前に終わっていなければ、回収失敗でも
# tick が増えず偽陽性になるため、判定不能として失敗させる（余裕 30 秒を引いた値が上限。既定で 90 秒）。
elapsed=$((SECONDS - started))
limit=$((helper_ticks - 30))
[ "$elapsed" -le "$limit" ] || fail "observation finished too late to be conclusive (elapsed=${elapsed}s, helper lifetime ${helper_ticks}s)"
log_phase observe end
winpid=no
if [ "$is_windows" -eq 1 ] && [ -r "/proc/$$/winpid" ]; then winpid=yes; fi
echo "cli-parity native reclaim: os=$(uname -s | cut -c1-7) descendant_alive=$alive winpid_available=$winpid"
[ "$alive" -eq 0 ] || fail "descendants survived the timeout reclaim"
echo "ok: native reclaim"
