#!/usr/bin/env bash
# scope を作らずに実機前提テストを全体期限つき・ログファイル直接出力で実行する補助（#3505・REPAIR-5・REPAIR-7・SEC-5・SUP-6）。
# .github/workflows/ci.yml の platform-ci（ubuntu）の実機前提ステップ（`cargo test ... --ignored` 等）が呼ぶ。
# 兄弟の scripts/run-in-user-scope.sh（委譲スコープ版・#3486）と引数・終了コード・失敗行の契約を揃える（変えるときは両方）。
#
# 背景: `<試験> 2>&1 | tee` の形では、試験が setsid / 自前の systemd-run --scope / unshare の再実行などで作った子孫が
# 孤児になって出力の書き込み端を持ち続けると tee が EOF を受け取れず、ステップの timeout-minutes が効かないまま
# ジョブ上限まで止まりうる。対策は run-in-user-scope.sh と同じく (1) 出力はログファイルへ直接書く (2) 全体期限を持つ
# (3) 期限切れは固定の失敗行（code=deadline_exceeded）と 124 で終わる。
# 委譲スコープで包むと試験プロセスの cgroup が変わり、start_scope_real のシナリオ B 等の検出の感度が変わるため、
# 本補助は scope・cgroup・namespace・uid を一切変えない（run_limited は子を新しいプロセスグループに置くだけ）。
#
# 使い方:
#   scripts/run-with-deadline.sh --name <name> --deadline <秒> --log <絶対パス> -- <コマンド> [引数...]
# 終了コード: 子の終了コードをそのまま返す。期限切れは 124。引数の誤りは 2。呼び出し側の環境変数は子へ渡る。
# 残余: setsid した子孫や試験自身が別 scope に置いた子孫はプロセスグループ宛ての kill では止まらない。ただし pipe を
# 持たないので bash の wait は主プロセスの終了で戻り、ステップは期限内に終わる（孤児の停止は試験自身の責務。#3485）。
# D 状態で KILL が効かない子は run_limited の wait を戻さず、その場合はステップの timeout-minutes が最後の層になる。
# Actions ログのライブ表示は無くなり、終了後にまとめて出る。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${DIR}/lib.sh"

usage() {
  echo "usage: run-with-deadline.sh --name <[a-z0-9_]{1,48}> --deadline <1-3600> --log <absolute path> -- <command> [args...]" >&2
  exit 2
}

name=""
deadline=""
log=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      [ "$#" -ge 2 ] || usage
      name="$2"
      shift 2
      ;;
    --deadline)
      [ "$#" -ge 2 ] || usage
      deadline="$2"
      shift 2
      ;;
    --log)
      [ "$#" -ge 2 ] || usage
      log="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *) usage ;;
  esac
done
{ [ -n "${name}" ] && [ -n "${deadline}" ] && [ -n "${log}" ] && [ "$#" -ge 1 ]; } || usage
case "${name}" in *[!a-z0-9_]*) usage ;; esac
[ "${#name}" -le 48 ] || usage
int_in_range "${deadline}" 1 3600 || usage
case "${log}" in /*) ;; *) usage ;; esac
# 先頭ゼロを 10 進にそろえる（表示のため）。
while [ "${#deadline}" -gt 1 ] && [ "${deadline#0}" != "${deadline}" ]; do deadline="${deadline#0}"; done

RUN_LIMITED_DIR="$(mktemp -d)"
export RUN_LIMITED_DIR

emit_log() {
  [ ! -f "${log}" ] || cat "${log}"
}
finished=0
cleanup() {
  run_limited_abort
  if [ "${finished}" -eq 0 ]; then
    # runner の取り消し等の異常終了。取れたログを出す。
    emit_log
  fi
  rm -rf "${RUN_LIMITED_DIR}"
}
trap cleanup EXIT
trap 'exit 143' INT TERM

: >"${log}"
run_child() {
  # run_limited がこの関数を背景のコマンド子として起動するため、親の cleanup / INT / TERM の trap を引き継がない。
  # 引き継ぐと子が finished=0 のまま異常終了の後始末と RUN_LIMITED_DIR（期限切れの印）の削除を行い、
  # 親が 124 でなく 143 を返す・残存警告が出ない（cleanup は親だけが実行する）。
  trap - EXIT INT TERM
  "$@" >"${log}" 2>&1
}

rc=0
run_limited "${deadline}" run_child "$@" || rc=$?

if [ "${rc}" -eq 124 ]; then
  finished=1
  emit_log
  err_code deadline_exceeded "name=${name} deadline_secs=${deadline}"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::error::run-with-deadline deadline_exceeded name=${name} deadline_secs=${deadline}"
  fi
  exit 124
fi

finished=1
emit_log
exit "${rc}"
