#!/usr/bin/env bash
# scripts/measure-restart-latency.sh の自己テスト（TASK-160・SUP-3・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へスタブ launcher（コンテナ役の sleep を 1 つ起動し、kill されたら
# 再起動して state.json とログを更新する。環境変数 STUB_MODE で挙動を切り替える）を生成し、終了コード・
# 出力 JSON・後始末（スタブ由来プロセスの残存 0）を具体値で照合する。実コンテナ・実ランタイム・root は
# 使わない（実機での実測と SUP-3 の判定は #491・TASK-160.h1 で人間が行う）。
# 呼び出し元は Makefile の `restart-latency-selftest` と CI の bench-regression ジョブ。
# 1 件でも期待と異なれば非ゼロで終了する（fail-closed）。Linux・非 root 限定で、前提を満たさない環境では
# skip せず失敗する（ci.md「skip で CI を通さない」）。
# 既知の未検証: 終了コード 4（SIGKILL でも消えない残存）は自己テストで再現できないため照合しない。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/measure-restart-latency.sh"

failures=0

if [ "$(uname -s)" != "Linux" ]; then
  echo "FAIL: selftest requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: selftest must not run as root (the operator-run measurement is out of CI scope)" >&2
  exit 1
fi
for req in jq setsid mkfifo; do
  command -v "$req" >/dev/null 2>&1 || { echo "FAIL: $req is required" >&2; exit 1; }
done

root="$(mktemp -d)"
foreign_pid=""
trap '[ -z "$foreign_pid" ] || kill "$foreign_pid" 2>/dev/null || true; rm -rf "$root"' EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

mkdir "$root/bundle"

# スタブ launcher。`run --id <id> --bundle <dir> --restart <p> --restart-backoff-ms 0` を受ける。
# STUB_MODE: normal / no_ready / early_exit / no_restart / same_pid / count_jump / foreign_pid /
# error_line / log_missing / log_short / log_garbage / deep（state.json の pid が孫プロセス）/
# late_start（SIGTERM 時に環境変数を継承しない新コンテナを起動して state.json へ書く）/
# late_two（全コンテナが環境変数を継承せず、SIGTERM 時にさらに新コンテナを起動。追跡済み pid も回収されること）/
# late_session（late_start と同じだが新コンテナが別 session・トークンなし。帰属不明のため kill されないこと）/ dead_new（再起動後の新 pid が既に終了）/
# log_late（restart ログを state.json 更新より後、最後の 1 行は SIGTERM 時に出す）。
# ログの elapsed_us は STUB_ELAPSED（空白区切り）を順に使う。STUB_DELAY（秒・空白区切り）は kill 検知後から
# 新コンテナ起動までの待ちを順に与える時間制御入力（observed の下限が決定的になる）。
cat >"${root}/launcher.sh" <<'STUB'
#!/usr/bin/env bash
id="$3"
sd="${XDG_RUNTIME_DIR}/fandhe-container/${id}"
mkdir -p "$sd"
count=0
idx=0
read -ra elapsed <<<"${STUB_ELAPSED:-}"
read -ra delays <<<"${STUB_DELAY:-}"
didx=0
child=""
shown=""
grand=""
pending=""
start_child() {
  if [ "$STUB_MODE" = deep ]; then
    gf="${STUB_DIR}/gc.${RANDOM}"
    bash -c 'sleep 300 & echo $! >"$1"; wait' _ "$gf" &
    child=$!
    while [ ! -s "$gf" ]; do sleep 0.01; done
    grand="$(<"$gf")"
    echo "$grand" >>"${STUB_DIR}/pids"
  elif [ "$STUB_MODE" = late_two ]; then
    env -u FANDHE_BENCH_OWNER sleep 300 &
    child=$!
  else
    sleep 300 &
    child=$!
  fi
  echo "$child" >>"${STUB_DIR}/pids"
}
late_term() {
  if [ "$STUB_MODE" = late_session ]; then
    setsid env -u FANDHE_BENCH_OWNER sleep 300 &
  else
    env -u FANDHE_BENCH_OWNER sleep 300 &
  fi
  child=$!
  echo "$child" >>"${STUB_DIR}/pids"
  write_state "$child"
  exit 0
}
write_state() {
  local shown_pid="$1"
  printf '{"ociVersion":"1.0.2","id":"%s","status":"running","pid":%s,"bundle":"/x","revision":1,"restartCount":%s}\n' \
    "$id" "$shown_pid" "$count" >"${sd}/state.tmp"
  mv "${sd}/state.tmp" "${sd}/state.json"
}
term_handler() {
  [ -z "$pending" ] || echo "$pending" >&2
  kill "$child" 2>/dev/null
  exit 0
}
case "$STUB_MODE" in
  late_start | late_two | late_session) trap late_term TERM ;;
  *) trap term_handler TERM ;;
esac
start_child
shown="$child"
[ "$STUB_MODE" != deep ] || shown="$grand"
[ "$STUB_MODE" != foreign_pid ] || shown="$(<"${STUB_FOREIGN}")"
write_state "$shown"
[ "$STUB_MODE" = no_ready ] || echo READY
[ "$STUB_MODE" != early_exit ] || exit 1
while :; do
  wait "$child" 2>/dev/null || true
  if [ "$STUB_MODE" = no_restart ]; then
    while :; do sleep 0.2; done
  fi
  d="${delays[$didx]:-}"
  didx=$((didx + 1))
  [ -z "$d" ] || sleep "$d"
  start_child
  if [ "$STUB_MODE" = dead_new ]; then
    true &
    dp=$!
    wait "$dp"
    count=$((count + 1))
    write_state "$dp"
    while :; do sleep 0.2; done
  fi
  case "$STUB_MODE" in
    count_jump) count=$((count + 2)) ;;
    *) count=$((count + 1)) ;;
  esac
  shown="$child"
  [ "$STUB_MODE" != deep ] || shown="$grand"
  [ "$STUB_MODE" != same_pid ] || shown="$(sed -n 's/.*"pid":\([0-9]*\).*/\1/p' "${sd}/state.json")"
  write_state "$shown"
  e="${elapsed[$idx]:-1000}"
  idx=$((idx + 1))
  line="{\"component\":\"supervisor.monitor\",\"operation\":\"restart\",\"result\":\"ok\",\"elapsed_us\":${e}}"
  case "$STUB_MODE" in
    log_missing) ;;
    log_late) [ -z "$pending" ] || echo "$pending" >&2; pending="$line" ;;
    log_short) if [ "$idx" -ge 2 ]; then echo "$line" >&2; fi ;;
    log_garbage) echo "not json" >&2; echo '{"component":"supervisor.monitor","operation":"restart","result":"ok","elapsed_us":"x"}' >&2 ;;
    error_line) echo "{\"component\":\"supervisor.monitor\",\"operation\":\"restart\",\"result\":\"error\",\"code\":\"x\",\"elapsed_us\":${e}}" >&2 ;;
    *) echo "$line" >&2 ;;
  esac
done
STUB
chmod 700 "${root}/launcher.sh" "$root"

# 実行ごとにスタブ由来プロセスの残存がないことを確認する（ゾンビは除外）。
no_residue() { # <STUB_DIR>
  local p s bad
  [ -f "$1/pids" ] || return 0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    bad=0
    while read -r p; do
      if [ -r "/proc/$p/stat" ]; then
        s="$(<"/proc/$p/stat")" 2>/dev/null || continue
        [[ "$s" == *") Z "* ]] || bad=1
      fi
    done <"$1/pids"
    [ "$bad" -eq 0 ] && return 0
    sleep 0.2
  done
  return 1
}

# run_case <名前> <期待終了コード> <STUB_MODE> <STUB_ELAPSED> <script 引数...>。結果は ${root}/<名前>.out に残る。
run_case() {
  local name="$1" want="$2" mode="$3" elapsed="$4" rc=0
  shift 4
  mkdir -p "${root}/d-${name}"
  STUB_MODE="$mode" STUB_ELAPSED="$elapsed" STUB_DELAY="${STUB_DELAY:-}" STUB_DIR="${root}/d-${name}" STUB_FOREIGN="${root}/foreign.pid" \
    bash "$target" --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --settle-ms 5 "$@" \
    >"${root}/${name}.out" 2>"${root}/${name}.err" </dev/null || rc=$?
  if [ "$rc" -ne "$want" ]; then
    fail "${name}: exit code ${rc}, want ${want}"
    return 1
  fi
  if ! no_residue "${root}/d-${name}"; then fail "${name}: stub processes remain"; return 1; fi
  pass "${name}: exit ${rc}"
}

jq_eq() { # <名前> <ファイル> <jq 式> <期待値>
  local got
  got="$(jq -c "$3" "$2" 2>/dev/null || echo "<jq-error>")"
  if [ "$got" = "$4" ]; then pass "$1: $3 == $4"; else fail "$1: $3 got ${got}, want $4"; fi
}

# --- 正常系: trials=5・warmup=1。warmup の 100000us は集計から除く。中央値 3.000・p95 は 5 番目で 5.000 ---
if run_case normal 0 normal "100000 1000 2000 3000 4000 5000" --trials 5 --warmup 1 --timeout 10 --label selftest; then
  o="${root}/normal.out"
  jq_eq normal "$o" '.schema' '"fandhe-container.restart-latency/v1"'
  jq_eq normal "$o" '.behavior' '"SUP-3"'
  jq_eq normal "$o" '.task' '"TASK-160"'
  jq_eq normal "$o" '[.trials, .warmup, .backoff_ms, .label, .unit]' '[5,1,0,"selftest","ms"]'
  jq_eq normal "$o" '.observed.samples' '5'
  jq_eq normal "$o" '(.observed.values | length)' '5'
  jq_eq normal "$o" '(.observed.median > 0)' 'true'
  jq_eq normal "$o" '.supervisor_reported | [.samples, .median, .p95, .min, .max]' '[5,3,5,1,5]'
  jq_eq normal "$o" '[has("pass"), has("verdict"), has("ok")]' '[false,false,false]'
  if grep -qF "$root" "$o"; then fail "normal: output contains a path"; else pass "normal: output has no paths"; fi
fi

# --- observed 系列の具体値: 時間制御入力（kill 検知後の待ち 0.1〜0.3 秒）で下限が決まる。warmup 0.8 秒は除外される ---
# delay は新コンテナ起動前の sleep なので observed >= delay（上限はポーリング・fork の余裕 0.2 秒）。
# 試行値（昇順）の期待下限 [100,150,200,250,300]ms・中央値 200..400ms・p95（5 番目）300..550ms・warmup 除外なら最大 < 700ms。
STUB_DELAY="0.8 0.1 0.15 0.2 0.25 0.3"
if run_case observed_vals 0 normal "9 1000 2000 3000 4000 5000" --trials 5 --warmup 1 --timeout 20; then
  o="${root}/observed_vals.out"
  jq_eq observed_vals "$o" '.observed.samples' '5'
  jq_eq observed_vals "$o" '(.observed.values | sort) as $v | [$v[0] >= 100, $v[1] >= 150, $v[2] >= 200, $v[3] >= 250, $v[4] >= 300, $v[4] < 700]' '[true,true,true,true,true,true]'
  jq_eq observed_vals "$o" '[.observed.median >= 200, .observed.median <= 400]' '[true,true]'
  jq_eq observed_vals "$o" '[.observed.p95 >= 300, .observed.p95 <= 550, .observed.p95 == .observed.max]' '[true,true,true]'
  jq_eq observed_vals "$o" '[.observed.min >= 100, .observed.max < 700]' '[true,true]'
fi
STUB_DELAY=""

# state.json の pid が launcher の孫プロセスでも同一性確認が成立する（祖先の起動時刻と取り違えない）
run_case deep 0 deep "1000 1000" --trials 2 --warmup 0 --timeout 10 || true

# launcher が SIGTERM 時に環境変数を継承しない新コンテナを起動しても、state.json の pid から回収される
run_case late_start 0 late_start "" --trials 1 --warmup 0 --timeout 10 || true

# 全コンテナが環境変数を継承しない場合も、追跡した全 pid（再起動後の生存コンテナ）と SIGTERM 時の新コンテナを回収する
run_case late_two 0 late_two "1000" --trials 1 --warmup 0 --timeout 10 || true
# SIGTERM 時に別 session・トークンなしで起動された新 pid は本計測への帰属を確認できないため kill しない
# （起動時刻が launcher 以降というだけでは回収しない。警告を出し、テスト側で後始末する）
mkdir -p "${root}/d-late_session"
late_rc=0
STUB_MODE=late_session STUB_ELAPSED="" STUB_DELAY="" STUB_DIR="${root}/d-late_session" STUB_FOREIGN="${root}/foreign.pid" \
  bash "$target" --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --settle-ms 5 --trials 1 --warmup 0 --timeout 10 \
  >"${root}/late_session.out" 2>"${root}/late_session.err" </dev/null || late_rc=$?
if [ "$late_rc" -eq 0 ]; then pass "late_session: exit 0"; else fail "late_session: exit code ${late_rc}, want 0"; fi
late_alive=0
late_pid="$(tail -n 1 "${root}/d-late_session/pids" 2>/dev/null || true)"
if [ -n "$late_pid" ] && kill -0 "$late_pid" 2>/dev/null; then late_alive=1; fi
if [ "$late_alive" -eq 1 ]; then pass "late_session: unattributable new pid was not killed"; else fail "late_session: unattributable new pid was killed"; fi
if grep -q 'cannot be attributed' "${root}/late_session.err"; then pass "late_session: warning logged"; else fail "late_session: no attribution warning"; fi
[ -z "$late_pid" ] || kill -KILL "$late_pid" 2>/dev/null || true
# restart ログが state.json 更新より後（最後の 1 行は停止時）でも、launcher 停止後に集計して副系列が欠損しない
if run_case log_late 0 log_late "9 1000 2000 3000" --trials 3 --warmup 1 --timeout 10; then
  jq_eq log_late "${root}/log_late.out" '.supervisor_reported | [.samples, .median, .p95]' '[3,2,3]'
fi

# 偶数個: 1000..4000 → 中央値 2.5・p95 は ceil(3.8)-1=3 番目で 4.000
if run_case even 0 normal "9 1000 2000 3000 4000" --trials 4 --warmup 1 --timeout 10; then
  jq_eq even "${root}/even.out" '.supervisor_reported | [.samples, .median, .p95]' '[4,2.5,4]'
fi
# 1 試行・warmup 0
if run_case single 0 normal "7000" --trials 1 --warmup 0 --timeout 10; then
  jq_eq single "${root}/single.out" '.supervisor_reported | [.samples, .median, .p95]' '[1,7,7]'
fi

# --- 副系列が信頼できないとき null（主系列は成立するので終了コード 0） ---
for m in log_missing log_short log_garbage; do
  if run_case "$m" 0 "$m" "1000 1000 1000 1000" --trials 3 --warmup 1 --timeout 10; then
    jq_eq "$m" "${root}/${m}.out" '.supervisor_reported' 'null'
    jq_eq "$m" "${root}/${m}.out" '.observed.samples' '3'
  fi
done

# --- 失敗系（期限は 2 秒に絞る。失敗時は結果を公開しない） ---
run_case no_ready 1 no_ready "" --trials 1 --warmup 0 --timeout 2 || true
run_case early_exit 1 early_exit "" --trials 1 --warmup 0 --timeout 2 || true
run_case no_restart 1 no_restart "" --trials 1 --warmup 0 --timeout 2 || true
run_case same_pid 1 same_pid "" --trials 1 --warmup 0 --timeout 2 || true
run_case count_jump 1 count_jump "" --trials 1 --warmup 0 --timeout 2 || true
run_case dead_new 1 dead_new "" --trials 1 --warmup 0 --timeout 3 || true
run_case error_line 1 error_line "1000 1000" --trials 1 --warmup 0 --timeout 2 || true
for m in no_ready early_exit no_restart same_pid count_jump dead_new error_line; do
  if [ -s "${root}/${m}.out" ]; then fail "${m}: stdout must be empty on failure"; else pass "${m}: no result published"; fi
done

# state.json の pid が launcher の子孫でないときは kill せず失敗する（偽造 state.json 対策）
sleep 300 &
foreign_pid=$!
echo "$foreign_pid" >"${root}/foreign.pid"
run_case foreign_pid 1 foreign_pid "" --trials 1 --warmup 0 --timeout 2 || true
if kill -0 "$foreign_pid" 2>/dev/null; then pass "foreign_pid: unrelated process was not signaled"; else fail "foreign_pid: unrelated process was killed"; fi
kill "$foreign_pid" 2>/dev/null || true
foreign_pid=""

# --- 引数・入力エラーは 2 ---
chk2() { # <名前> <script 引数...>
  local name="$1" rc=0
  shift
  bash "$target" "$@" >"${root}/${name}.out" 2>"${root}/${name}.err" </dev/null || rc=$?
  if [ "$rc" -eq 2 ]; then pass "${name}: exit 2"; else fail "${name}: exit ${rc}, want 2"; fi
}
ln -s "${root}/launcher.sh" "${root}/link.sh"
: >"${root}/existing.json"
chk2 rel_launcher --launcher launcher.sh --bundle "${root}/bundle"
chk2 sym_launcher --launcher "${root}/link.sh" --bundle "${root}/bundle"
chk2 bad_trials --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --trials 0
chk2 big_trials --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --trials 201
chk2 bad_label --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --label 'a b'
chk2 bad_policy --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --policy never
chk2 no_bundle --launcher "${root}/launcher.sh" --bundle "${root}/missing"
chk2 existing_output --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --output "${root}/existing.json"
chk2 unknown_opt --bogus
chk2 missing_launcher --bundle "${root}/bundle"

# --help は冒頭コメントを出し、SUP-3 を明記している
if bash "$target" --help | grep -q 'SUP-3'; then pass "help: mentions SUP-3"; else fail "help: SUP-3 missing"; fi

# --output は新規ファイルにだけ書く
if run_case output_file 0 normal "" --trials 1 --warmup 0 --timeout 10 --output "${root}/result.json"; then
  jq_eq output_file "${root}/result.json" '.behavior' '"SUP-3"'
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL: ${failures} check(s) failed" >&2
  exit 1
fi
echo "OK: all checks passed"
