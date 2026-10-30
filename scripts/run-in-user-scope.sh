#!/usr/bin/env bash
# 委譲スコープ（systemd-run --user --scope -p Delegate=yes）で実機前提テストを全体期限つきで実行する補助（#3486・REPAIR-5・REPAIR-7）。
# 兄弟の scripts/run-with-deadline.sh（scope を作らない版・#3505）と引数・終了コード・失敗行の契約を揃える（変えるときは両方）。
# .github/workflows/ci.yml の platform-ci（ubuntu）の「委譲スコープで実行する実機前提テスト」ステップが呼ぶ。
#
# 背景: `systemd-run ... | tee` の形では、試験が別 cgroup / setsid の子孫に出力の書き込み端を残すと tee が EOF を受け取れず、
# ステップの timeout-minutes が効かないままジョブ上限まで止まった（PR #3458 の run 40926425955）。
# 対策は次の 3 点で、期限は呼び出し側が timeout-minutes × 60 - 60 秒で渡す。
#   1. 出力は pipe ではなくログファイルへ直接書く（孤児が書き込み端を持っても bash の待ちが戻る）
#   2. 名前付きの unit（fandhe-ci-<name>-<pid>）にして、期限切れ時に scope ごと SIGKILL → stop する
#   3. 期限切れは固定の失敗行（code=deadline_exceeded）と非 0（124）で終わる
#
# 使い方:
#   scripts/run-in-user-scope.sh --name <name> --deadline <秒> --log <絶対パス> -- <コマンド> [引数...]
# 終了コード: 子の終了コードをそのまま返す。期限切れは 124。引数の誤りは 2。前提コマンド不在は 1。
# 呼び出し側の環境変数（USER 等）はそのまま子へ渡る。外側の待ちの上限は期限 + 約 40 秒。
# 残余: D 状態で KILL が効かない子は run_limited の wait を戻さない。CLI の start が別 scope へ逃がした子孫は
# 止めないが、pipe を持たないため待ち続けの原因にはならない（試験自身の停止は #3485）。
# 本体は systemd の user manager 専用（Linux のみ）。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${DIR}/lib.sh"

usage() {
  echo "usage: run-in-user-scope.sh --name <[a-z0-9_]{1,48}> --deadline <1-3600> --log <absolute path> -- <command> [args...]" >&2
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

# 前提は skip せず fail-closed にする。
for c in systemd-run systemctl timeout; do
  if ! command -v "${c}" >/dev/null 2>&1; then
    err_code missing-command "${c} is required but not found"
    exit 1
  fi
done

unit="fandhe-ci-${name}-$$"
RUN_LIMITED_DIR="$(mktemp -d)"
export RUN_LIMITED_DIR

# 自分が作った unit だけを止める。失敗は無視する（best effort。待ちは timeout で有界）。
scope_stop() {
  timeout 15 systemctl --user kill --signal=SIGKILL "${unit}.scope" >/dev/null 2>&1 || true
  timeout 15 systemctl --user stop "${unit}.scope" >/dev/null 2>&1 || true
}
emit_log() {
  [ ! -f "${log}" ] || cat "${log}"
}
finished=0
cleanup() {
  run_limited_abort
  if [ "${finished}" -eq 0 ]; then
    # runner の取り消し等の異常終了。scope を回収し、取れたログを出す。
    scope_stop
    emit_log
  fi
  rm -rf "${RUN_LIMITED_DIR}"
}
trap cleanup EXIT
trap 'exit 143' INT TERM

: >"${log}"
run_scope() {
  # run_limited がこの関数を背景のコマンド子として起動するため、親の cleanup / INT / TERM の trap を引き継がない。
  # 引き継ぐと子が finished=0 のまま scope_stop と RUN_LIMITED_DIR（期限切れの印）の削除を行い、
  # 親が 124 でなく 143 を返す・残存警告が出ない（cleanup は親だけが実行する）。
  trap - EXIT INT TERM
  systemd-run --user --scope --quiet -p Delegate=yes --unit="${unit}" -- "$@" >"${log}" 2>&1
}

rc=0
run_limited "${deadline}" run_scope "$@" || rc=$?

if [ "${rc}" -eq 124 ]; then
  scope_stop
  finished=1
  emit_log
  err_code deadline_exceeded "name=${name} deadline_secs=${deadline} unit=${unit}"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::error::run-in-user-scope deadline_exceeded name=${name} deadline_secs=${deadline}"
  fi
  exit 124
fi

# 正常終了でも scope に子孫が残っていれば回収する。合否（rc）は変えない。
if timeout 10 systemctl --user is-active "${unit}.scope" >/dev/null 2>&1; then
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::warning::run-in-user-scope leftover_processes name=${name} unit=${unit}"
  else
    info_msg "leftover_processes name=${name} unit=${unit}"
  fi
  scope_stop
fi
finished=1
emit_log
exit "${rc}"
