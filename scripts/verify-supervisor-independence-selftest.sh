#!/usr/bin/env bash
# scripts/verify-supervisor-independence.sh の自己テスト（TASK-162・SUP-5・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へスタブ（CLI・systemd-run・supervisor の bin。supervisor スタブはコンテナ側プロセスを 1 つ起動して FCSUP1 OK を出す。
# 環境変数 STUB_MODE で巻き添え死・コンテナ死・再起動等の挙動を切り替える）を生成し、小さい N（5）で
# 終了コード・出力 JSON・後始末を具体値で照合する。実コンテナ・実ランタイム・root は使わない
# （実機での N=50 実証と SUP-5 の判定は #499・人間担当）。
# 呼び出し元は Makefile の `supervisor-independence-selftest` と CI の bench-regression ジョブ。
# 1 件でも期待と異なれば非ゼロで終了する（fail-closed）。Linux・非 root 限定で、前提を満たさない環境では
# skip せず失敗する（ci.md「skip で CI を通さない」）。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/verify-supervisor-independence.sh"

failures=0

if [ "$(uname -s)" != "Linux" ]; then
  echo "FAIL: selftest requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: selftest must not run as root (the operator-run verification is out of CI scope)" >&2
  exit 1
fi

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

pass() { echo "PASS: $1"; }
# 失敗時は現在の case の stderr を 1 case につき 1 回だけ出す（CI ログから原因を辿れるようにする。#2154・REPAIR-4）。
err_shown=""
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
  if [ -n "${ERR:-}" ] && [ "$err_shown" != "$ERR" ] && [ -s "$ERR" ]; then
    err_shown="$ERR"
    sed "s/^/  [case ${case_no:-0} err] /" "$ERR" >&2 || true
  fi
}

# スタブ群。実バイナリの契約（#1717・#1819）に合わせ、CLI は `--root R create --bundle B <id>`、systemd-run は
# `--user --scope --quiet -p Delegate=yes -- <cmd...>`（exec するので pid は変わらない）、supervisor は
# `start --root R [--restart P] <id>`（標準出力が FIFO でなければ ERR で終了）だけを受理し、他は終了コード 2 にする。
# supervisor スタブはコンテナ側プロセスを 1 つ起動して `FCSUP1 OK <pid>` を出す。
# STUB_MODE: normal（監視プロセスが死んでもコンテナは残る）/ collateral（対象の死で他の監視プロセスも死ぬ）/
# die_with_target（対象のコンテナが監視プロセスと共に死ぬ）/ other_dies（他コンテナが対象の死で死ぬ）/
# scrub_env（コンテナ側プロセスが環境変数を継承しない）/ no_ready（報告を出さない）/ err_report（FCSUP1 ERR）/ bad_report（書式不正）/ short_start（最後の launcher が起動直後に終了）/ restart（コンテナを再起動する）/ restart_aux（補助プロセスだけ増やす）/ restart_short（再起動後すぐ終了）/ restart_sup_dies（再起動後に監視プロセスが終了）/ restart_alias（同名・別コマンドの補助プロセスだけ増やす）/ many_kids（子孫が走査上限 512 件を超える）/ mid_only（対象だけ、一時的な中間プロセスを観測させた後、報告なしで終了し、木の外の init を残す）。
# split_report（対象の報告行を pid の途中で 2 回に分けて書く。#2154）。
# 待機はすべて組み込みの read -t（fork しない）で行い、一過性の子プロセスを作らない。
mkdir -m 0755 "${root}/bin"
cat >"${root}/bin/fandhe-container" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = --root ] && [ "$3" = stop ] && [ "$#" -eq 4 ]; then
  # stop スタブ。呼び出しを記録し、STUB_STOP で挙動を切り替える（ok / fail / ignore / hang）。
  echo "stop $4" >>"$STUB_DIR/cli.log"
  case "${STUB_STOP:-ok}" in
    ok)
      : >"$STUB_DIR/$4.stopped"
      read -r cp <"$STUB_DIR/$4.cpid" 2>/dev/null && kill -TERM "$cp" 2>/dev/null
      exit 0 ;;
    fail) echo '{"code":"UNAVAILABLE","message":"stub"}' >&2; exit 9 ;;
    ignore) exit 0 ;;
    hang)
      # fork せずに待つ（期限で打ち切られたとき、孤児の子を残さない）。
      mkfifo "$STUB_DIR/hang.$$" && exec 8<>"$STUB_DIR/hang.$$" && read -t 300 -u 8
      exit 0 ;;
  esac
  exit 2
fi
[ "$1" = --root ] && [ "$3" = create ] && [ "$4" = --bundle ] && [ "$#" -eq 6 ] || exit 2
[ -f "$5/config.json" ] && [ -d "$5/rootfs" ] || exit 2
echo "create $6" >>"$STUB_DIR/cli.log"
mkdir -p "$2/$6" && echo '{"status":"created"}' >"$2/$6/state.json"
STUB
cat >"${root}/systemd-run" <<'STUB'
#!/usr/bin/env bash
[ "$1" = --user ] && [ "$2" = --scope ] && [ "$3" = --quiet ] && [ "$4" = -p ] && [ "$5" = Delegate=yes ] && [ "$6" = -- ] || exit 2
shift 6
exec "$@"
STUB
cat >"${root}/bin/fandhe-container-supervisor" <<'STUB'
#!/usr/bin/env bash
[ "$1" = start ] && [ "$2" = --root ] || exit 2
id="${!#}"
[ -f "$3/$id/state.json" ] || exit 2
if [ ! -p /dev/stdout ]; then echo "FCSUP1 ERR INVALID_ARGUMENT 2 stdout is not a fifo"; exit 2; fi
if [ "$STUB_MODE" = err_report ] && [ "${id##*-}" = "$STUB_TARGET" ]; then echo "FCSUP1 ERR FAILED_PRECONDITION 1 stub"; exit 1; fi
n="${id##*-}"
if [ "$STUB_MODE" = short_start ] && [ "$n" = "$STUB_COUNT" ]; then exit 1; fi
mkfifo "$STUB_DIR/$id.fifo"
exec 9<>"$STUB_DIR/$id.fifo"
echo $$ >"$STUB_DIR/$id.pid"
tid="${STUB_PREFIX}-${STUB_TARGET}"
role=o
[ "$n" != "$STUB_TARGET" ] || role=t
start_container() {
  local watch=""
  case "$STUB_MODE:$role" in
    die_with_target:t) watch="$STUB_DIR/$id.pid" ;;
    other_dies:o) watch="$STUB_DIR/$tid.pid" ;;
  esac
  if [ -n "$watch" ]; then
    bash -c 'exec 8<>"$2"; while :; do if read -r p <"$1" 2>/dev/null; then kill -0 "$p" 2>/dev/null || break; fi; read -t 0.2 -u 8 || true; done' _ "$watch" "$STUB_DIR/$id.fifo" &
  elif [ "$STUB_MODE" = many_kids ]; then
    local k
    # 走査上限 512 件を超える木を 1 番目の launcher だけで作る（全体で約 520 プロセス。OOM・flake を避ける）。
    if [ "$n" = 1 ]; then
      for k in $(seq 1 520); do sleep 300 & done
    fi
    sleep 300 &
  elif [ "$STUB_MODE" = scrub_env ]; then
    # 環境変数を継承しないコンテナ側プロセス（実機の実装を模す）。
    env -i sleep 300 &
  else
    sleep 300 &
  fi
  c=$!
  echo "$c" >"$STUB_DIR/$id.cpid"
}
if [ "$STUB_MODE" = mid_only ] && [ "$role" = t ]; then
  # 一時的な中間プロセス（c）だけが子孫として観測され、init は二重 fork で孤児化した別プロセス（環境変数トークンも
  # 継承しない）。報告を出さないまま約 1.5 秒で終了する（init の記録なしに supervisor が消える経路）。
  sleep 300 &
  c=$!
  echo "$c" >"$STUB_DIR/$id.cpid"
  (env -u FANDHE_BENCH_OWNER sleep 300 &)
  trap 'kill "$c" 2>/dev/null; exit 0' TERM
  read -t 1.5 -u 9 || true
  kill "$c" 2>/dev/null
  exit 0
fi
start_container
trap 'kill "$c" 2>/dev/null; exit 0' TERM
case "$STUB_MODE" in
  no_ready) ;;
  bad_report) echo "FCSUP1 OK pid" ;;
  split_report)
    if [ "$role" = t ]; then
      # 本体の read -t 0.05 より長くあけ、期限切れが必ず行の途中で起きるようにする。
      printf 'FCSUP1 OK %s' "${c:0:1}"
      read -t 0.3 -u 9 || true
      echo "${c:1}"
    else
      echo "FCSUP1 OK $c"
    fi ;;
  *) echo "FCSUP1 OK $c" ;;
esac
while :; do
  if [ "$STUB_MODE" = collateral ] && [ "$role" = o ]; then
    read -r tp <"$STUB_DIR/$tid.pid" 2>/dev/null || { read -t 0.2 -u 9 || true; continue; }
    kill -0 "$tp" 2>/dev/null || exit 0
    read -t 0.2 -u 9 || true
    continue
  fi
  wait "$c" || true
  # CLI の stop 経由でコンテナが止められたとき（stop スタブが .stopped を作る）は終了コード 0 で終わる。
  if [ -e "$STUB_DIR/$id.stopped" ]; then exit 0; fi
  if [ "$STUB_MODE" = restart ] || [ "$STUB_MODE" = restart_sup_dies ]; then
    sleep 300 &
    c=$!
    if [ "$STUB_MODE" = restart_sup_dies ] && [ "$role" = o ] && [ "$n" = "$STUB_LAST" ]; then
      read -t 0.3 -u 9 || true
      exit 0
    fi
    continue
  fi
  if [ "$STUB_MODE" = restart_short ] && [ -z "${short_done:-}" ]; then
    # 旧コンテナと同じコマンド（sleep 300）で再起動し、約 1 秒後に終了させる（settle 内の liveness 再照合へ到達させる）。
    short_done=1
    sleep 300 &
    c=$!
    read -t 1 -u 9 || true
    kill "$c" 2>/dev/null
    continue
  fi
  if [ "$STUB_MODE" = restart_alias ] && [ -z "${aux_done:-}" ]; then
    # コンテナ（sleep 300）は再起動せず、同じ comm（sleep）で別コマンドラインの補助プロセスだけを起動する。
    aux_done=1
    sleep 301 &
    continue
  fi
  if [ "$STUB_MODE" = restart_aux ] && [ -z "${aux_done:-}" ]; then
    # 補助プロセスだけを起動する（コンテナは再起動しない）。
    aux_done=1
    bash -c 'sleep 300; :' &
    continue
  fi
  read -t 1 -u 9 || true
done
STUB
chmod 700 "${root}/bin/fandhe-container" "${root}/bin/fandhe-container-supervisor" "${root}/systemd-run"
mkdir "${root}/bundle" "${root}/bundle/rootfs"
echo "{}" >"${root}/bundle/config.json"

count=5
tindex=3
prefix="selfsi"

# json_get <キー> <ファイル>: 整形済み JSON（1 行 1 キー）から値を取り出す（文字列の引用符は外す）。
json_get() {
  sed -n "s/^  \"$1\": \(.*\)$/\1/p" "$2" | sed 's/,$//; s/^"//; s/"$//'
}

# 全ケース共通の実行。$1 = STUB_MODE、残りは本体スクリプトへの追加引数。結果は RC・OUT・ERR へ。
# 実行後、この実行が起動した全プロセス（トークンでなく SELFTEST_MARK を継承したもの。孤児を含む）の残存を照合する。
case_no=0
run_case() {
  local mode="$1" mark d p left=0 kept
  shift
  case_no=$((case_no + 1))
  mark="selftest-mark-${$}-${case_no}"
  d="${root}/c${case_no}"
  mkdir "$d"
  OUT="${d}/out"
  ERR="${d}/err"
  RC=0
  env STUB_MODE="$mode" STUB_DIR="$d" STUB_COUNT="$count" STUB_LAST="$count" STUB_TARGET="$tindex" STUB_PREFIX="$prefix" SELFTEST_MARK="$mark" \
    bash "$target" --bin-dir "${root}/bin" --systemd-run "${root}/systemd-run" --bundle "${root}/bundle" --count "$count" --target-index "$tindex" \
    --id-prefix "$prefix" --settle 1 --timeout 5 "$@" >"$OUT" 2>"$ERR" || RC=$?
  while IFS= read -r p; do
    p="${p#/proc/}"
    p="${p%%/*}"
    # ゾンビは残存に数えない。
    if [ -r "/proc/$p/stat" ] && ! sed 's/^.*) //' "/proc/$p/stat" | grep -q '^[ZX] '; then
      left=$((left + 1))
      kill -KILL "$p" 2>/dev/null || true
    fi
  done < <(grep -lzxF -- "SELFTEST_MARK=${mark}" /proc/[0-9]*/environ 2>/dev/null || true)
  if [ "${EXPECT_LEFTOVER:-0}" = 1 ]; then
    # 追跡できない init を残す経路（mid_only）。回収できないことを契約どおり（終了コード 4）に残し、テスト側で片付ける。
    if [ "$left" -ge 1 ]; then pass "case ${case_no} (${mode}): untracked init was left and reclaimed by the test"; else fail "case ${case_no} (${mode}): expected a leftover init"; fi
  elif [ "$left" -eq 0 ]; then pass "case ${case_no} (${mode}): no leftover processes"; else fail "case ${case_no} (${mode}): ${left} leftover processes"; fi
  # rc=4 では本体が作業ディレクトリを残して場所を通知する（SUP-5）。通知されたパスを回収して mktemp ツリーを残さない。
  # 残存プロセスの回収後に消す。$root 配下と mktemp の既定場所（TMPDIR）以外は消さない。
  kept="$(sed -n 's/.*kept the working directory for inspection: \(\/.*\)$/\1/p' "$ERR" | head -n 1)"
  if [ -n "$kept" ]; then
    case "$kept" in
      "${TMPDIR:-/tmp}"/tmp.* | "${root}"/*)
        if [ -d "$kept" ]; then rm -rf -- "$kept"; pass "case ${case_no} (${mode}): kept working directory reclaimed"; fi ;;
      *) fail "case ${case_no} (${mode}): unexpected kept path" ;;
    esac
  fi
}

expect_eq() { # <説明> <期待> <実際>
  if [ "$2" = "$3" ]; then pass "$1 = $2"; else fail "$1: expected '$2', got '$3'"; fi
}

# 1. 正常系（AC1・AC2・AC3）: 対象の監視プロセスだけを kill し、残り 4 個の生存・継続と孤児の稼働継続を確認。
run_case normal
expect_eq "normal: exit code" 0 "$RC"
expect_eq "normal: behavior" "SUP-5" "$(json_get behavior "$OUT")"
expect_eq "normal: task" "TASK-162" "$(json_get task "$OUT")"
expect_eq "normal: count" 5 "$(json_get count "$OUT")"
expect_eq "normal: target_index" 3 "$(json_get target_index "$OUT")"
expect_eq "normal: supervisors_expected_alive" 4 "$(json_get supervisors_expected_alive "$OUT")"
expect_eq "normal: supervisors_alive_after_kill" 4 "$(json_get supervisors_alive_after_kill "$OUT")"
expect_eq "normal: monitored_containers_alive" 4 "$(json_get monitored_containers_alive "$OUT")"
expect_eq "normal: target_supervisor_dead" true "$(json_get target_supervisor_dead "$OUT")"
expect_eq "normal: target_container_alive" true "$(json_get target_container_alive "$OUT")"
expect_eq "normal: restart_check" skipped "$(json_get restart_check "$OUT")"
expect_eq "normal: result" pass "$(json_get result "$OUT")"
if [[ "$(json_get target_container_reparented_to "$OUT")" =~ ^[1-9][0-9]*$ ]]; then
  pass "normal: orphaned container was reparented to a live pid"
else
  fail "normal: target_container_reparented_to is not a pid ($(json_get target_container_reparented_to "$OUT"))"
fi
if grep -q -e '/fandhe-container-supervisor' -e "${root}" "$OUT" "$ERR"; then fail "normal: output leaks a path"; else pass "normal: output has no binary/bundle path"; fi
# stop 経由の後始末（#2163・CLI-1・SUP-5）: 対象（-3）を除く 4 個へ stop を呼び、create の後に呼ぶ。
expect_eq "normal: stop calls" "selfsi-1 selfsi-2 selfsi-4 selfsi-5" "$(sed -n 's/^stop //p' "$(dirname "$OUT")/cli.log" | tr '\n' ' ' | sed 's/ $//')"
expect_eq "normal: create calls" 5 "$(grep -c '^create ' "$(dirname "$OUT")/cli.log")"
expect_eq "normal: first stop comes after the last create" "stop" "$(sed -n '6p' "$(dirname "$OUT")/cli.log" | cut -d' ' -f1)"
if grep -q 'info: cli-stop: 4/4 supervisors exited after stop' "$ERR"; then pass "normal: cli-stop info line is 4/4"; else fail "normal: cli-stop info line missing"; fi

# 1b. stop が失敗する（UNAVAILABLE 相当）→ fallback の SIGTERM／SIGKILL で回収され、判定は変わらない。
STUB_STOP=fail run_case normal
expect_eq "stop_fail: exit code" 0 "$RC"
expect_eq "stop_fail: result" pass "$(json_get result "$OUT")"
expect_eq "stop_fail: supervisors_alive_after_kill" 4 "$(json_get supervisors_alive_after_kill "$OUT")"
expect_eq "stop_fail: stop calls" 4 "$(grep -c '^stop ' "$(dirname "$OUT")/cli.log")"
if grep -q 'info: cli-stop: 0/4' "$ERR"; then pass "stop_fail: cli-stop info line is 0/4"; else fail "stop_fail: cli-stop info line missing"; fi

# 1c. stop が成功を返すが何も止まらない（PID 1 が SIGTERM を捨てる場合の模擬）→ fallback で回収される。
STUB_STOP=ignore run_case normal
expect_eq "stop_ignore: exit code" 0 "$RC"
expect_eq "stop_ignore: result" pass "$(json_get result "$OUT")"
if grep -q 'info: cli-stop: 0/4' "$ERR"; then pass "stop_ignore: cli-stop info line is 0/4"; else fail "stop_ignore: cli-stop info line missing"; fi

# 1d. stop がハングする → 呼び出しごとの期限と段全体の期限で打ち切られ、全体が上限内に終わる。
hang_t0=$SECONDS
# --timeout 3 では残り時間から強制終了猶予 3 秒を引くと 0 以下になり stop が一度も呼ばれないため、stop が実際に
# 送られる 8 秒を使う（最初の stop は上限 5 秒で打ち切られ、残りは段全体の期限で送られない）。
STUB_STOP=hang run_case normal --timeout 8
hang_el=$((SECONDS - hang_t0))
expect_eq "stop_hang: the hanging stop was entered (cli.log)" 1 "$(grep -c '^stop ' "$(dirname "$OUT")/cli.log")"
if [ "$hang_el" -ge 4 ]; then pass "stop_hang: per-call deadline was waited for (${hang_el}s >= 4s)"; else fail "stop_hang: returned in ${hang_el}s without waiting for the stop deadline"; fi
expect_eq "stop_hang: exit code" 0 "$RC"
expect_eq "stop_hang: result" pass "$(json_get result "$OUT")"
if [ "$hang_el" -le 60 ]; then pass "stop_hang: finished within the bound (${hang_el}s <= 60s)"; else fail "stop_hang: took ${hang_el}s"; fi

# 2. 巻き添え死: 対象の kill で他の監視プロセスも死ぬ → 判定不成立。--output は作られない。
run_case collateral --output "${root}/c2-result.json"
expect_eq "collateral: exit code" 1 "$RC"
expect_eq "collateral: supervisors_alive_after_kill" 0 "$(json_get supervisors_alive_after_kill "$OUT")"
expect_eq "collateral: result" fail "$(json_get result "$OUT")"
if [ -e "${root}/c2-result.json" ]; then fail "collateral: --output must not be created on failure"; else pass "collateral: no --output on failure"; fi

# 2b. 報告行が pid の途中で分かれて届いても、完全な 1 行になるまで待って受理する（#2154・SUP-5・REPAIR-5）。
run_case split_report
expect_eq "split_report: exit code" 0 "$RC"
expect_eq "split_report: supervisors_alive_after_kill" 4 "$(json_get supervisors_alive_after_kill "$OUT")"
expect_eq "split_report: target_container_alive" true "$(json_get target_container_alive "$OUT")"
expect_eq "split_report: result" pass "$(json_get result "$OUT")"

# 3. 対象のコンテナが監視プロセスと共に死ぬ（AC2 の検出）。
run_case die_with_target
expect_eq "die_with_target: exit code" 1 "$RC"
expect_eq "die_with_target: target_container_alive" false "$(json_get target_container_alive "$OUT")"
expect_eq "die_with_target: supervisors_alive_after_kill" 4 "$(json_get supervisors_alive_after_kill "$OUT")"

# 4. 他コンテナのプロセスが対象の死で死ぬ。
run_case other_dies
expect_eq "other_dies: exit code" 1 "$RC"
expect_eq "other_dies: monitored_containers_alive" 0 "$(json_get monitored_containers_alive "$OUT")"
expect_eq "other_dies: supervisors_alive_after_kill" 4 "$(json_get supervisors_alive_after_kill "$OUT")"

# 5. 報告を出さない → 結果を公開せず 1。
run_case no_ready --timeout 3
expect_eq "no_ready: exit code (init never reported => cannot prove tracking => untracked)" 4 "$RC"
expect_eq "no_ready: stdout is empty" "" "$(cat "$OUT")"

# 5b. FCSUP1 ERR を返す / 書式不正の報告 → 結果を公開しない。ERR を出して終了した supervisor は子プロセス不在を
# 確認できないため追跡不能（4）。書式不正の報告も init を特定できないので追跡不能（4）。
EXPECT_LEFTOVER=1 run_case mid_only
expect_eq "mid_only: exit code (transient helper is not proof of tracking the container => untracked)" 4 "$RC"
expect_eq "mid_only: stdout is empty" "" "$(cat "$OUT")"
if grep -q 'cleanup-failed' "$ERR"; then pass "mid_only: cleanup-failed reported"; else fail "mid_only: cleanup-failed missing"; fi
run_case err_report
expect_eq "err_report: exit code (ERR is not proof of no child => untracked)" 4 "$RC"
expect_eq "err_report: stdout is empty" "" "$(cat "$OUT")"
if grep -q 'FAILED_PRECONDITION' "$ERR"; then pass "err_report: error code is reported"; else fail "err_report: error code missing from stderr"; fi
run_case bad_report
expect_eq "bad_report: exit code (malformed report => init unknown => untracked)" 4 "$RC"
expect_eq "bad_report: stdout is empty" "" "$(cat "$OUT")"

# 6. N 個未満しか起動しない → 結果を公開せず 1。
run_case short_start --timeout 3
expect_eq "short_start: exit code (launcher vanished untracked => cleanup cannot be confirmed)" 4 "$RC"
expect_eq "short_start: stdout is empty" "" "$(cat "$OUT")"

# 7. --check-restart: コンテナを再起動するスタブ → 成功。
run_case restart --check-restart
expect_eq "restart: exit code" 0 "$RC"
expect_eq "restart: restart_check" pass "$(json_get restart_check "$OUT")"
expect_eq "restart: restart_confirmed" 4 "$(json_get restart_confirmed "$OUT")"
expect_eq "restart: stop is not called under --check-restart (SUP-9)" 0 "$(grep -c '^stop ' "$(dirname "$OUT")/cli.log")"

# 8. --check-restart: 再起動しないスタブ（現行 supervisor 相当）→ 失敗。
run_case normal --check-restart --timeout 3
expect_eq "no-restart: exit code" 1 "$RC"
expect_eq "no-restart: restart_check" fail "$(json_get restart_check "$OUT")"

# 8b. 補助プロセスが増えただけ（コンテナは再起動しない）→ 失敗。
run_case restart_aux --check-restart --timeout 3
expect_eq "restart_aux: exit code" 1 "$RC"
expect_eq "restart_aux: restart_check" fail "$(json_get restart_check "$OUT")"

# 8c. 再起動したコンテナが settle 内に終了する → 失敗（稼働継続の再照合）。
run_case restart_short --check-restart
expect_eq "restart_short: exit code" 1 "$RC"
expect_eq "restart_short: restart_check" fail "$(json_get restart_check "$OUT")"

# 8d. 再起動確認中に残りの監視プロセスが終了する → 失敗（再起動後の監視プロセス生存の再照合）。
run_case restart_sup_dies --check-restart
expect_eq "restart_sup_dies: exit code" 1 "$RC"
expect_eq "restart_sup_dies: restart_check" fail "$(json_get restart_check "$OUT")"

# 8e. 同名・別コマンドの補助プロセスだけでは再起動と認定しない（SUP-5・SUP-3）。
run_case restart_alias --check-restart --timeout 3
expect_eq "restart_alias: exit code" 1 "$RC"
expect_eq "restart_alias: restart_check" fail "$(json_get restart_check "$OUT")"

# 8f. 子孫が走査上限（512 件）を超えると判定不成立・追跡不能（4）。pass にならない。
run_case many_kids --count 2 --target-index 1 --timeout 10
expect_eq "many_kids: exit code" 4 "$RC"
expect_eq "many_kids: no result" "" "$(json_get result "$OUT")"

# 9. --output は新規ファイルへ公開する（正常系）。
run_case normal --output "${root}/c9-result.json"
expect_eq "output: exit code" 0 "$RC"
expect_eq "output: file result" pass "$(json_get result "${root}/c9-result.json")"
expect_eq "output: stdout is empty" "" "$(cat "$OUT")"

# 9b. 環境変数を継承しないコンテナ側プロセスも、後始末で記録した同一性により回収される（トークン照合だけでは漏れる）。
run_case scrub_env --output "${root}/c10-result.json"
expect_eq "scrub_env: exit code" 0 "$RC"
expect_eq "scrub_env: file result" pass "$(json_get result "${root}/c10-result.json")"
scrub_dir="${root}/c${case_no}"
scrub_left=0
for f in "${scrub_dir}"/*.cpid; do
  cp="$(cat "$f")"
  if [ -r "/proc/${cp}/stat" ] && ! sed 's/^.*) //' "/proc/${cp}/stat" | grep -q '^[ZX] '; then
    scrub_left=$((scrub_left + 1))
    kill -KILL "$cp" 2>/dev/null || true
  fi
done
expect_eq "scrub_env: env-less container processes left" 0 "$scrub_left"

# 10. 引数エラーは 2（起動もしない）。
arg_case() { # <説明> <引数...>
  local desc="$1" rc=0
  shift
  bash "$target" "$@" >/dev/null 2>"${root}/arg.err" || rc=$?
  expect_eq "args: ${desc}" 2 "$rc"
}
B="--systemd-run ${root}/systemd-run --bundle ${root}/bundle"
# shellcheck disable=SC2086
arg_case "relative bin-dir" --bin-dir bin $B
# shellcheck disable=SC2086
arg_case "legacy --launcher is rejected" --launcher "${root}/bin/fandhe-container-supervisor" $B
# shellcheck disable=SC2086
arg_case "count 1" --bin-dir "${root}/bin" $B --count 1
# shellcheck disable=SC2086
arg_case "target-index out of range" --bin-dir "${root}/bin" $B --count 5 --target-index 9
# shellcheck disable=SC2086
arg_case "min-procs 1" --bin-dir "${root}/bin" $B --min-procs 1
# shellcheck disable=SC2086
arg_case "bad id-prefix" --bin-dir "${root}/bin" $B --id-prefix 'a b'
arg_case "missing bundle" --bin-dir "${root}/bin" --systemd-run "${root}/systemd-run"
: >"${root}/existing.json"
# shellcheck disable=SC2086
arg_case "existing output" --bin-dir "${root}/bin" $B --output "${root}/existing.json"
# bin-dir の中身を差し替えた複製で、symlink・group 書き込み可・欠落を拒否する。
mkdir -m 0755 "${root}/bin-link" "${root}/bin-gw" "${root}/bin-missing"
cp "${root}/bin/fandhe-container" "${root}/bin-link/fandhe-container"
ln -s "${root}/bin/fandhe-container-supervisor" "${root}/bin-link/fandhe-container-supervisor"
cp "${root}/bin/fandhe-container" "${root}/bin/fandhe-container-supervisor" "${root}/bin-gw/"
chmod 770 "${root}/bin-gw/fandhe-container-supervisor"
cp "${root}/bin/fandhe-container" "${root}/bin-missing/"
# shellcheck disable=SC2086
arg_case "symlink supervisor" --bin-dir "${root}/bin-link" $B
# shellcheck disable=SC2086
arg_case "group-writable supervisor" --bin-dir "${root}/bin-gw" $B
# shellcheck disable=SC2086
arg_case "missing supervisor" --bin-dir "${root}/bin-missing" $B
ln -s "${root}/systemd-run" "${root}/systemd-run-link"
arg_case "symlink systemd-run" --bin-dir "${root}/bin" --systemd-run "${root}/systemd-run-link" --bundle "${root}/bundle"

# 10b. config.json の root.path が複製内の相対パスでなければ、複製・create・起動の前に 2 で拒否する
# （cp -a は root.path を書き換えず、絶対パスだと全コンテナが元の同じ rootfs を共有する。codex 指摘 PRRT_kwDOUq78ts6tKUN5）。
mk_bundle() { # <名前> <config.json の内容>
  mkdir -m 0755 "${root}/$1" "${root}/$1/rootfs"
  printf '%s\n' "$2" >"${root}/$1/config.json"
}
mk_bundle bundle-abs "{\"root\":{\"path\":\"${root}/bundle/rootfs\"}}"
mk_bundle bundle-dotdot '{"root":{"path":"../bundle/rootfs"}}'
mk_bundle bundle-nonstring '{"root":{"path":7}}'
mk_bundle bundle-self '{"root":{"path":"."}}'
mk_bundle bundle-symlink '{"root":{"path":"link"}}'
ln -s "${root}/bundle/rootfs" "${root}/bundle-symlink/link"
for b in bundle-abs bundle-dotdot bundle-nonstring bundle-self bundle-symlink; do
  arg_case "root.path rejected (${b})" --bin-dir "${root}/bin" --systemd-run "${root}/systemd-run" --bundle "${root}/${b}"
  if grep -q 'root.path\|config.json' "${root}/arg.err"; then pass "args: ${b} reports the root.path reason"; else fail "args: ${b} reason missing"; fi
done

# 11. AC3: スクリプト本文に SUP-5 のビヘイビア ID が明記されている。
if grep -q 'SUP-5' "$target"; then pass "script mentions SUP-5"; else fail "script does not mention SUP-5"; fi

if [ "$failures" -ne 0 ]; then
  echo "FAILED: ${failures} check(s)" >&2
  exit 1
fi
echo "OK: all supervisor-independence selftest checks passed"
