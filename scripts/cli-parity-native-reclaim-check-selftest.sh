#!/usr/bin/env bash
# cli-parity-native-reclaim-check.sh の全体期限の自己テスト（#1688・REPAIR-5・REPAIR-12）。
# 試験専用の切り替え（CLI_PARITY_RECLAIM_TEST_HANG）で意図的にハングさせ、スクリプトが「期限以上、期限 + 猶予
# 以内」に非ゼロで終わり、`deadline_exceeded` の行に段・経過秒・descendant_alive=0 が出ることを外側の
# $SECONDS で照合する。不正な環境変数値がビルド前に終了コード 2 で拒否されることも確かめる。
# CI の platform-ci ジョブが `make cli-parity-native-reclaim-selftest` で実行する（PR は ubuntu・main は 3 OS。Windows は
# Git Bash）。rustc でヘルパーをビルドし、ハングするプロセスを起動するため make ci には含めない。
# 成功基準: 終了コード 0 かつ FAIL 行なし。
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/.." && pwd)"
target="$root/scripts/cli-parity-native-reclaim-check.sh"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp" 2>/dev/null || true' EXIT

# 期限切れ後の回収（taskkill の上限 10 秒・グループ回収 約 6 秒・tick 観測 3 秒）と Git Bash の fork の遅さを
# 見込んだ猶予。上限のこの値を超えて終わるなら、期限が回収を含めて効いていない。
GRACE=30
failures=0
fail() { printf 'FAIL: %s\n' "$1"; failures=$((failures + 1)); }

# 対象を独立グループでバックグラウンド起動し、自己テスト自身の外側の期限（$1 秒）で監視する（REPAIR-5・#1709）。
# 対象の期限処理や回収がハングしても自己テストは止まらない。外側の期限を超えたら対象を強制回収し、
# outer_rc=124 とする。終了していなければ wait しない（上限の無い wait を使わない）。結果は outer_rc に入る。
outer_rc=0
run_outer() { # <外側の期限秒> <名前> <env...>
  local limit="$1" name="$2" pid n until_s
  shift 2
  outer_rc=0
  set -m
  env "$@" bash "$target" >"$tmp/$name.out" 2>"$tmp/$name.err" </dev/null &
  pid=$!
  set +m
  until_s=$((SECONDS + limit))
  while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$until_s" ]; do sleep 0.2; done
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM -- "-$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
    sleep 0.5
    kill -KILL -- "-$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
    n=0
    while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 50 ]; do
      sleep 0.1
      n=$((n + 1))
    done
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; fi
    outer_rc=124
    return 0
  fi
  wait "$pid" || outer_rc=$?
}

# <名前> <期待 rc> <期限> <段> <env...>: 外側から経過秒を測り、rc・出力行・経過秒の上下限を照合する。
hang_case() {
  local name="$1" want_rc="$2" dl="$3" phase="$4" rc=0 s e el line="" l
  shift 4
  s=$SECONDS
  run_outer $((dl + GRACE + 30)) "$name" "$@" CLI_PARITY_RECLAIM_DEADLINE_SECS="$dl"
  rc=$outer_rc
  e=$SECONDS
  el=$((e - s))
  [ "$rc" -eq "$want_rc" ] || fail "$name: rc expected $want_rc, got $rc"
  [ "$el" -ge "$dl" ] || fail "$name: finished before the deadline (elapsed=${el}s, deadline=${dl}s)"
  [ "$el" -le $((dl + GRACE)) ] || fail "$name: exceeded deadline + grace (elapsed=${el}s, deadline=${dl}s, grace=${GRACE}s)"
  while IFS= read -r l; do
    case "$l" in *"deadline_exceeded phase="*) line="$l" ;; esac
  done <"$tmp/$name.err"
  case "$line" in
    "cli-parity native reclaim: deadline_exceeded phase=$phase elapsed="*" deadline=$dl descendant_alive=0") ;;
    *) fail "$name: unexpected deadline line: '$line'" ;;
  esac
  printf '%s: rc=%s elapsed=%ss deadline=%ss\n' "$name" "$rc" "$el" "$dl"
}

# H1: baseline 段でグループ kill が届かない状況。ヘルパーの寿命（120 秒）より先に期限 20 秒で止まる。
hang_case H1 1 20 baseline CLI_PARITY_RECLAIM_TEST_HANG=baseline STUB_NATIVE_TICKS=120
# H2: capture 段の内側の監視が効かない状況（--timeout 600）。build + baseline（通常 10 秒未満、遅い Windows でも
# 数十秒を超えない）を終えた後の capture 中に期限 60 秒が来て、寿命 120 秒より先に止まる。
hang_case H2 1 60 capture CLI_PARITY_RECLAIM_TEST_HANG=capture STUB_NATIVE_TICKS=120

# E1: 不正値はヘルパーのビルド前に終了コード 2 で拒否する（ビルドへ進んだ形跡 phase=build が無いこと）。
bad_case() { # <名前> <env...>
  local name="$1" rc=0 l
  shift
  run_outer 60 "$name" "$@"
  rc=$outer_rc
  [ "$rc" -eq 2 ] || fail "$name: rc expected 2, got $rc"
  while IFS= read -r l; do
    case "$l" in *phase=build*) fail "$name: reached the build phase" ;; esac
  done <"$tmp/$name.err"
  printf '%s: rc=%s\n' "$name" "$rc"
}
bad_case E1a CLI_PARITY_RECLAIM_TEST_HANG=bogus
bad_case E1b CLI_PARITY_RECLAIM_DEADLINE_SECS=5
bad_case E1c CLI_PARITY_RECLAIM_DEADLINE_SECS=abc
bad_case E1d CLI_PARITY_RECLAIM_DEADLINE_SECS=99999
bad_case E1e STUB_NATIVE_TICKS=30

if [ "$failures" -ne 0 ]; then
  printf 'FAIL: %s case(s) failed\n' "$failures"
  exit 1
fi
echo "ok: cli-parity native reclaim selftest"
