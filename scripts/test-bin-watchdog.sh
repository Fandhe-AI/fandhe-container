#!/usr/bin/env bash
# cargo の試験バイナリを期限つきで実行する runner（#3504・REPAIR-5・REPAIR-7・REPAIR-12）。
# `.cargo/config.toml` の `[target.x86_64-unknown-linux-gnu] runner` から、cargo が試験バイナリごとに
# `test-bin-watchdog.sh <バイナリ> [引数...]` の形で呼ぶ（cargo test / cargo run / doctest が対象）。
#
# 背景: reusable の rust-ci（Fandhe-AI/actions の rust-base-ci）の `cargo test --workspace --all-features` が
# 間欠的にジョブ上限で取り消され、ログが残らず止まった試験を特定できなかった。reusable にはステップも env も
# 差し込めないため、リポジトリ側で効く runner で全試験バイナリを包み、期限切れ時に診断を出して子孫を回収する。
# platform-ci の `scripts/run-in-user-scope.sh`（#3486）が委譲スコープの 8 ステップを担うのと対になる。
#
# 期限を使う条件（上から順に判定し、使わないときは何も足さず exec する。403 回呼ばれる経路なので軽く保つ）:
#   1. 引数に `--bench` がある（cargo bench のバイナリ。各スクリプトの期限に任せる）→ 素通し
#   2. FANDHE_CONTAINER_TEST_BIN_DEADLINE_SECS が `off` または `0` → 素通し
#   3. 同変数が 1〜3600 の整数 → その秒数。それ以外の値は fail-closed（終了コード 2）
#   4. 未設定で引数に `--ignored` がある → 素通し（platform-ci の実機前提テスト。各ステップが 10 分前後の
#      timeout-minutes・540 秒級の予算や試験自身の watchdog を持つため、一律 300 秒で偽陰性にしない。
#      個別に包みたいときは変数で明示する）
#   5. 未設定で GITHUB_ACTIONS=true → 既定 300 秒（正常時の最長 33 秒の約 9 倍。根拠は .claude/rules/ci.md）
#   6. 未設定で CI 外 → 素通し（手元の cargo run・デバッグを変えない）
#
# 終了コードの契約: 子の終了コードをそのまま返す。子がシグナル N で死んだときは cargo に同じ「signal: N」と
# 見えるよう、自分も同じシグナルで終わる（終わらないシグナルは 128+N で exit）。期限切れは 124（run_limited・
# run-in-user-scope.sh と同じ）で、先に子孫を凍結 → 診断を stderr へ出す → SIGKILL で回収する。引数の誤りは 2。
#
# 設計上の注意:
#   - プロセスグループは変えない（set -m を使わない）。試験本体がグループリーダーになると setsid が EPERM になるため
#   - 見張り役は stdin / stdout / stderr を /dev/null にする。孤児の sleep が cargo の出力 pipe の書き込み端を
#     持って待ちを戻さなくなる事故（#3486）を避ける
#   - bash はジョブ制御なしの背景子に SIGINT / SIGQUIT を無視させ、exec 後も引き継がれる。子は副シェルで trap - して
#     既定動作へ戻してから exec する（戻さないと cli の logs --follow 等が INT で止まらない）。INT は子へ転送する
#   - 「本当に 128+N で exit した子」と「シグナルで死んだ子」は区別できず、どちらもシグナルとして送り直す
#   - 残余: D 状態で KILL が効かない子は wait が戻らない（最終の歯止めはジョブ上限）。列挙前に init へ付け替わった孤児は捕まえられない
#   - lib.sh は source しない（source 時の cd と set -e の影響を避け、起動を軽く保つため）
# 実行対象は Linux のみ（/proc に依存）。bash 3.2 互換で書く。
# shellcheck disable=SC2329 # 関数は trap 経由・後続の本体から呼ぶ（静的解析が追えない）
set -u

if [ "$#" -lt 1 ]; then
  echo "usage: test-bin-watchdog.sh <test binary> [args...]" >&2
  exit 2
fi

for a in "$@"; do
  if [ "${a}" = "--bench" ]; then
    exec "$@"
  fi
done

deadline=""
if [ "${FANDHE_CONTAINER_TEST_BIN_DEADLINE_SECS+set}" = "set" ]; then
  v="${FANDHE_CONTAINER_TEST_BIN_DEADLINE_SECS}"
  case "${v}" in
    off | 0) exec "$@" ;;
    '' | *[!0-9]* | ??????????*)
      echo "error: code=invalid-argument message=FANDHE_CONTAINER_TEST_BIN_DEADLINE_SECS must be off or an integer in 1..3600" >&2
      exit 2
      ;;
  esac
  # 先頭ゼロを 10 進にそろえる（算術で 8 進と解釈されないように）。
  while [ "${#v}" -gt 1 ] && [ "${v#0}" != "${v}" ]; do v="${v#0}"; done
  if [ "${v}" -lt 1 ] || [ "${v}" -gt 3600 ]; then
    echo "error: code=invalid-argument message=FANDHE_CONTAINER_TEST_BIN_DEADLINE_SECS must be off or an integer in 1..3600" >&2
    exit 2
  fi
  deadline="${v}"
elif [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  for a in "$@"; do
    if [ "${a}" = "--ignored" ]; then
      exec "$@"
    fi
  done
  deadline=300
else
  exec "$@"
fi

main_pid=$$
bin_base="${1##*/}"
safe_base="$(printf '%s' "${bin_base}" | tr -c 'A-Za-z0-9._-' '_')"

# /proc/<pid>/stat から "ppid starttime" を読む。comm に空白や ')' を含み得るため最後の ')' 以降を切り出す。
# 読めない（既に終了した）ときは 1 を返す。
read_stat() {
  local s rest
  s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  rest="${s##*) }"
  # shellcheck disable=SC2086
  set -- ${rest}
  # $1=state $2=ppid ... $20=starttime
  [ "$#" -ge 20 ] || return 1
  STAT_PPID="$2"
  STAT_START="${20}"
  return 0
}

# 子孫の列挙。結果は DESC（"pid/starttime" の空白区切り）に入れる。増えなくなるまで最大 8 周で有界。
collect_descendants() {
  local pids=" ${1} " round=0 grew p
  DESC=""
  while [ "${round}" -lt 8 ]; do
    grew=0
    for d in /proc/[0-9]*; do
      p="${d#/proc/}"
      case "${pids}" in *" ${p} "*) continue ;; esac
      read_stat "${p}" || continue
      case "${pids}" in
        *" ${STAT_PPID} "*)
          pids="${pids}${p} "
          grew=1
          ;;
      esac
    done
    [ "${grew}" -eq 1 ] || break
    round=$((round + 1))
  done
  for p in ${pids}; do
    if read_stat "${p}"; then
      DESC="${DESC}${p}/${STAT_START} "
    fi
  done
}

# 列挙した各プロセスへシグナルを送る。送る直前に starttime を照合し、pid が再利用された別プロセスを撃たない。
signal_all() {
  local sig="$1" e p st
  for e in ${DESC}; do
    p="${e%%/*}"
    st="${e##*/}"
    read_stat "${p}" || continue
    [ "${STAT_START}" = "${st}" ] || continue
    kill "-${sig}" "${p}" 2>/dev/null || true
  done
}

# 子孫のスレッド名（libtest は試験名）と待ち状態を出す。SIGSTOP 後は wchan が do_signal_stop に変わるため、凍結の前に呼ぶ。
emit_threads() {
  local e p t n tc
  echo "watchdog: threads of the tree before freezing (name = libtest test name, truncated to 15 chars)" >&2
  for e in ${DESC}; do
    p="${e%%/*}"
    echo "  pid=${p} $(grep -m1 '^State:' "/proc/${p}/status" 2>/dev/null | tr -s '[:space:]' ' ')" >&2
    n=0
    for t in /proc/"${p}"/task/[0-9]*; do
      n=$((n + 1))
      [ "${n}" -le 64 ] || {
        echo "    ... more threads omitted" >&2
        break
      }
      tc="$(cat "${t}/comm" 2>/dev/null)"
      echo "    tid=${t##*/} comm=${tc} wchan=$(cat "${t}/wchan" 2>/dev/null)" >&2
    done
  done
}

# 期限切れの診断を stderr へ出す（上限つき）。
emit_diagnostics() {
  local e p t n tc
  echo "error: code=deadline_exceeded message=binary=${bin_base} deadline_secs=${deadline} pid=${child}" >&2
  echo "watchdog: arguments follow, one per line" >&2
  for a in "$@"; do
    echo "  arg: ${a}" >&2
  done
  echo "watchdog: process tree" >&2
  if command -v ps >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
      timeout 10 ps -eo pid,ppid,pgid,etime,stat,cmd --forest >&2 2>&1 || true
    else
      ps -eo pid,ppid,pgid,etime,stat,cmd --forest >&2 2>&1 || true
    fi
  else
    echo "  PID PPID PGID STATE CMD (ps not found; from /proc)" >&2
    for e in ${DESC}; do
      p="${e%%/*}"
      echo "  ${p} $(tr '\0' ' ' <"/proc/${p}/cmdline" 2>/dev/null | cut -c1-300) :: $(cut -d' ' -f1-2 "/proc/${p}/stat" 2>/dev/null)" >&2
    done
  fi
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    # 値は basename（許可文字のみに置換済み）と数値だけ。引数は入れない（ワークフローコマンドの注入を避ける）。
    echo "::error::test-bin-watchdog deadline_exceeded binary=${safe_base} deadline_secs=${deadline}"
  fi
}

on_deadline() {
  trap '' USR1
  collect_descendants "${child}"
  emit_threads
  signal_all STOP
  collect_descendants "${child}"
  signal_all STOP
  emit_diagnostics "$@"
  signal_all KILL
  wait "${child}" 2>/dev/null
  exit 124
}

# シグナルを子へ転送し、子の終了を待ってから自分も同じシグナルで終わる。
forward_signal() {
  local num="$1"
  kill "-${num}" "${child}" 2>/dev/null || true
  wait "${child}" 2>/dev/null
  stop_watchdog
  reraise $((128 + num))
}

stop_watchdog() {
  if [ -n "${wd:-}" ]; then
    kill -TERM "${wd}" 2>/dev/null || true
    wait "${wd}" 2>/dev/null || true
    wd=""
  fi
}

# 128+N の終了状態を、同じシグナルで自分が死ぬことで cargo へ伝える。
# 終了シグナルでないもの（CHLD・CONT・STOP・TSTP・TTIN・TTOU・URG・WINCH）は再送せず、そのままの終了コードで抜ける
# （子の通常の終了コード 147 を SIGSTOP と誤解して自分を止めない）。
reraise() {
  local status="$1" num
  if [ "${status}" -gt 128 ] && [ "${status}" -le 192 ]; then
    num=$((status - 128))
    case "${num}" in
      17 | 18 | 19 | 20 | 21 | 22 | 23 | 28) exit "${status}" ;;
    esac
    ulimit -c 0 2>/dev/null || true
    trap - "${num}" 2>/dev/null || true
    kill "-${num}" $$ 2>/dev/null || true
    sleep 1
  fi
  exit "${status}"
}

child=""
wd=""
args=("$@")
trap 'on_deadline "${args[@]}"' USR1
trap 'forward_signal 2' INT
trap 'forward_signal 15' TERM
trap 'forward_signal 1' HUP

# stdin は明示的に引き継ぐ（ジョブ制御なしの背景起動は既定で /dev/null になる）。
# bash はジョブ制御なしの背景子の SIGINT / SIGQUIT を無視に設定し、exec 後の試験バイナリと孫まで引き継がれる
# （cli の `logs --follow` が SIGINT で止まらなくなる。#3504）。子の副シェルで trap - により既定動作へ戻してから exec する。
(
  trap - INT QUIT
  exec "$@"
) <&0 &
child=$!

(
  exec </dev/null >/dev/null 2>&1
  sleep "${deadline}" &
  sp=$!
  trap 'kill "${sp}" 2>/dev/null; exit 0' TERM
  wait "${sp}"
  kill -USR1 "${main_pid}" 2>/dev/null
) &
wd=$!

status=0
wait "${child}"
status=$?
# 見張り役の trap（USR1）で wait が中断された場合は on_deadline が exit するのでここへは来ない。
stop_watchdog
reraise "${status}"
