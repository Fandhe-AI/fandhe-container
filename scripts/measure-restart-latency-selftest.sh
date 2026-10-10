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
# 終了コード 4 は「帰属を証明できない生存 pid」の経路（late_session・late_orphan・foreign_young）で照合する。
# 既知の未検証: SIGKILL でも消えない残存による 4・外側 timeout の SIGKILL（Makefile の 137 → 4）・照合と kill の間の
# pid 再利用（再現不能。sig_same_proc の関数単体テストで代替）・exit 3（非 Linux 等の前提欠如）。

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
for req in jq setsid mkfifo timeout make; do
  command -v "$req" >/dev/null 2>&1 || { echo "FAIL: $req is required" >&2; exit 1; }
done

root="$(mktemp -d)"
foreign_pid=""
# 自己テスト自身が起動した補助プロセス（直接の子）。途中で中断しても残さない。
helper_pids=()
# pid が自己テスト（$$）の直接の子として今も存在するか（wait 済みの pid が再利用されていても送らないため）。
is_my_child() { # <pid>
  local st="" rest
  local -a fl=()
  { IFS= read -r -d '' st <"/proc/$1/stat" || true; } 2>/dev/null
  [ -n "$st" ] || return 1
  rest="${st##*) }"
  read -ra fl <<<"$rest"
  [ "${fl[1]:-}" = "$$" ]
}
on_selftest_exit() {
  local hp
  [ -z "$foreign_pid" ] || kill "$foreign_pid" 2>/dev/null || true
  for hp in ${helper_pids[@]+"${helper_pids[@]}"}; do
    if is_my_child "$hp"; then kill -KILL "$hp" 2>/dev/null || true; fi
    wait "$hp" 2>/dev/null || true
  done
  # 意図的に残る「帰属不明・無関係」役のプロセス（スタブ・spawner が pid を記録したもの）を片付ける。
  # 本体が回収に失敗したケース（FAIL 済み）のスタブ由来プロセス（pids）も CI ランナーに残さない。
  for hp in $(cat "$root"/d-*/leftover "$root"/d-*/pids "$root/spawned" 2>/dev/null || true); do kill -KILL "$hp" 2>/dev/null || true; done
  rm -rf "$root"
}
trap on_selftest_exit EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

mkdir "$root/bundle"

# spawner: スタブ launcher の依頼（"<返信ファイル>\t<環境変数の代入>"）を FIFO で受け、launcher の子孫でない
# 別 session のプロセス（sleep 300）を起動して pid を返す常駐ループ。自己テストの直接の子で、終了時に片付ける。
mkfifo "$root/spawn.req"
: >"$root/spawned"
(
  exec 3<>"$root/spawn.req"
  while IFS=$'\t' read -r -u 3 reply assign; do
    setsid env "$assign" sleep 300 >/dev/null 2>&1 </dev/null &
    echo "$!" >>"$root/spawned"
    echo "$!" >"${reply}.tmp"
    mv "${reply}.tmp" "$reply"
  done
) &
helper_pids+=("$!")

# スタブ launcher。`run --id <id> --bundle <dir> --restart <p> --restart-backoff-ms 0` を受ける。
# STUB_MODE: normal / foreign_new（再起動後の state.json の pid が子孫でない無関係プロセス）/ no_ready / early_exit / no_restart / same_pid / count_jump / foreign_pid /
# error_line / log_missing / log_short / log_garbage / deep（state.json の pid が孫プロセス）/
# late_start（SIGTERM 時に環境変数を継承しない新コンテナを起動して state.json へ書く）/
# late_two（全コンテナが環境変数を継承せず、SIGTERM 時にさらに新コンテナを起動。追跡済み pid も回収されること）/
# late_session（late_start と同じだが新コンテナが別 session・トークンなし。帰属不明のため kill されず、終了コード 4 で結果を公開しないこと）/ dead_new（再起動後の新 pid が既に終了）/
# decoy（所有トークンを「部分文字列」として含む環境変数を持つプロセスを launcher の木から切り離して起動する。
#   子孫でもトークン完全一致でもないので回収で kill されないこと）/
# stray（launcher の子孫だがトークンを継承せず別 session で state.json にも現れない補助プロセス。子孫スナップショットで回収されること）/
# late_orphan（SIGTERM 時に既存コンテナを止めてから、トークンなし・同じ session の新コンテナを起動する。session の
#   継続を証明する追跡済みプロセスが残っていないため帰属不明で kill されず、終了コード 4）/
# foreign_young（state.json の pid が launcher 起動後に生まれた、木から切り離された別 session・トークンなしのプロセス。
#   子孫でないので kill されず計測失敗。無関係と確定できないため終了コード 4）/
# log_late（restart ログを state.json 更新より後、最後の 1 行は SIGTERM 時に出す）。
# ログの elapsed_us は STUB_ELAPSED（空白区切り）を順に使う。STUB_DELAY（秒・空白区切り）は kill 検知後から
# 新コンテナ起動までの待ちを順に与える時間制御入力（observed の下限が決定的になる）。
cat >"${root}/launcher.sh" <<'STUB'
#!/usr/bin/env bash
id="$3"
sd="${FANDHE_BENCH_STATE_ROOT:?}/${id}"
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
  if [ "$STUB_MODE" = late_orphan ]; then
    kill -KILL "$child" 2>/dev/null
    wait "$child" 2>/dev/null
  fi
  if [ "$STUB_MODE" = late_session ]; then
    setsid env -u FANDHE_BENCH_OWNER sleep 300 &
  else
    env -u FANDHE_BENCH_OWNER sleep 300 &
  fi
  child=$!
  case "$STUB_MODE" in
    late_session | late_orphan) echo "$child" >>"${STUB_DIR}/leftover" ;;
    *) echo "$child" >>"${STUB_DIR}/pids" ;;
  esac
  write_state "$child"
  exit 0
}
# launcher の木に一度も属さない別 session・トークンなしのプロセスを、自己テスト側の spawner（launcher の子孫でない
# 常駐ループ）に起動させ、その pid が <ファイル> に書かれるまで待つ。launcher が自分で fork して切り離す方法は、
# 切り離す前の一瞬だけ子孫として見えてしまい、子孫スナップショットとの競合でテストが不安定になるため使わない。
detached() { # <ファイル> <環境変数の代入 1 個>
  printf '%s\t%s\n' "$1" "$2" >"${STUB_SPAWN}"
  while [ ! -s "$1" ]; do sleep 0.01; done
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
  late_start | late_two | late_session | late_orphan) trap late_term TERM ;;
  *) trap term_handler TERM ;;
esac
start_child
if [ "$STUB_MODE" = decoy ]; then
  # トークンを含むが FANDHE_BENCH_OWNER=<token> の完全一致エントリではない（grep -F の部分一致なら誤検出する）。
  detached "${STUB_DIR}/decoy" "DECOY=x_FANDHE_BENCH_OWNER=${FANDHE_BENCH_OWNER}"
fi
if [ "$STUB_MODE" = stray ]; then
  setsid env -u FANDHE_BENCH_OWNER sleep 300 &
  echo "$!" >>"${STUB_DIR}/pids"
fi
shown="$child"
[ "$STUB_MODE" != deep ] || shown="$grand"
if [ "$STUB_MODE" = foreign_young ]; then
  detached "${STUB_DIR}/young" "YOUNG=1"
  shown="$(<"${STUB_DIR}/young")"
fi
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
  [ "$STUB_MODE" != foreign_new ] || shown="$(<"${STUB_FOREIGN}")"
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
# 本体がハングしても CI ステップを止めないよう 1 ケース 120 秒で打ち切る（--preserve-status なので期待終了コードと
# 一致せず FAIL になる。REPAIR-5）。
run_case() {
  local name="$1" want="$2" mode="$3" elapsed="$4" rc=0
  shift 4
  mkdir -p "${root}/d-${name}"
  STUB_MODE="$mode" STUB_ELAPSED="$elapsed" STUB_DELAY="${STUB_DELAY:-}" STUB_DIR="${root}/d-${name}" STUB_FOREIGN="${root}/foreign.pid" STUB_SPAWN="${root}/spawn.req" \
    timeout --preserve-status --kill-after=10 120 bash "$target" --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --settle-ms 5 "$@" \
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
  # shellcheck disable=SC2016 # jq の変数（シェル展開させない）
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
# 以降の「意図的に生存プロセスが残る」ケース用。run_case と同じだが残存検査をせず、終了コードだけ照合する。
run_leftover_case() { # <名前> <期待終了コード> <STUB_MODE> <script 引数...>
  local name="$1" want="$2" mode="$3" rc=0
  shift 3
  mkdir -p "${root}/d-${name}"
  STUB_MODE="$mode" STUB_ELAPSED="" STUB_DELAY="" STUB_DIR="${root}/d-${name}" STUB_FOREIGN="${root}/foreign.pid" STUB_SPAWN="${root}/spawn.req" \
    timeout --preserve-status --kill-after=10 120 bash "$target" --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --settle-ms 5 "$@" \
    >"${root}/${name}.out" 2>"${root}/${name}.err" </dev/null || rc=$?
  if [ "$rc" -eq "$want" ]; then pass "${name}: exit ${rc}"; else fail "${name}: exit code ${rc}, want ${want}"; fi
}
# <名前> <pid を 1 行で持つファイル>: その pid が生存している（シグナルを送られていない）ことを照合し、片付ける。
expect_survivor() {
  local name="$1" sp
  sp="$(tail -n 1 "$2" 2>/dev/null || true)"
  if [ -n "$sp" ] && kill -0 "$sp" 2>/dev/null; then pass "${name}: process was not signaled"; else fail "${name}: process was killed or never started"; fi
  [ -z "$sp" ] || kill -KILL "$sp" 2>/dev/null || true
}
expect_unpublished() { # <名前>: 結果を公開していない（標準出力が空）
  if [ ! -s "${root}/$1.out" ]; then pass "$1: no result published"; else fail "$1: result published"; fi
}
expect_warning() { # <名前>: 帰属不明の警告と cleanup-failed を出している
  if grep -q 'cannot be attributed' "${root}/$1.err" && grep -q 'cleanup-failed' "${root}/$1.err"; then
    pass "$1: attribution warning and cleanup-failed logged"
  else
    fail "$1: attribution warning or cleanup-failed missing"
  fi
}

# SIGTERM 時に別 session・トークンなしで起動された新 pid は本計測への帰属を証明できないため kill しない
# （起動時刻が launcher 以降というだけでは回収しない。警告を出して終了コード 4・結果は公開しない）
run_leftover_case late_session 4 late_session --trials 1 --warmup 0 --timeout 10
expect_unpublished late_session
expect_survivor late_session "${root}/d-late_session/leftover"
expect_warning late_session

# SIGTERM 時に既存コンテナを止めてから同じ session で起動された新 pid は、session の継続を証明できる追跡済みの
# 生存プロセスが無いため帰属不明（session 番号の一致だけでは回収しない）。kill せず終了コード 4
run_leftover_case late_orphan 4 late_orphan --trials 1 --warmup 0 --timeout 10
expect_unpublished late_orphan
expect_survivor late_orphan "${root}/d-late_orphan/leftover"
expect_warning late_orphan

# state.json の pid が launcher 起動後に生まれた子孫でないプロセス（契約違反で木から外れたコンテナに相当）:
# シグナルは送らず計測失敗。無関係とも本計測の生成物とも証明できず生存しているので終了コード 4
run_leftover_case foreign_young 4 foreign_young --trials 1 --warmup 0 --timeout 10
expect_unpublished foreign_young
expect_survivor foreign_young "${root}/d-foreign_young/young"
expect_warning foreign_young
if grep -q 'refusing to send a signal' "${root}/foreign_young.err"; then pass "foreign_young: refused to signal"; else fail "foreign_young: refusal message missing"; fi

# 所有トークンを部分文字列として含む環境変数を持つ無関係プロセスは、完全一致しないため kill しない
run_leftover_case decoy 0 decoy --trials 1 --warmup 0 --timeout 10
expect_survivor decoy "${root}/d-decoy/decoy"
if no_residue "${root}/d-decoy"; then pass "decoy: no stub residue"; else fail "decoy: stub processes remain"; fi

# launcher の子孫だがトークンを継承せず別 session で state.json にも現れない補助プロセスは、launcher 停止前の
# 子孫スナップショットで帰属を証明して回収する（run_case が pids の残存 0 を照合する）
run_case stray 0 stray "" --trials 1 --warmup 0 --timeout 10 || true
if [ "$(wc -l <"${root}/d-stray/pids" 2>/dev/null || echo 0)" -ge 3 ]; then pass "stray: stray pid recorded"; else fail "stray: stub did not record the stray pid"; fi

# 計測中に SIGTERM を受けたら後始末を終えてから 143 で終わり、結果を公開しない（外側 timeout の期限切れと同じ経路）
mkdir -p "${root}/d-term"
STUB_MODE=no_restart STUB_ELAPSED="" STUB_DELAY="" STUB_DIR="${root}/d-term" STUB_FOREIGN="${root}/foreign.pid" STUB_SPAWN="${root}/spawn.req" \
  bash "$target" --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --trials 1 --warmup 0 --timeout 60 \
  >"${root}/term.out" 2>"${root}/term.err" </dev/null &
term_pid=$!
helper_pids+=("$term_pid")
for _ in $(seq 1 100); do [ -s "${root}/d-term/pids" ] && break; sleep 0.1; done
sleep 0.5
kill -TERM "$term_pid" 2>/dev/null || true
term_rc=0
wait "$term_pid" || term_rc=$?
if [ "$term_rc" -eq 143 ]; then pass "term: exit 143"; else fail "term: exit code ${term_rc}, want 143"; fi
expect_unpublished term
if no_residue "${root}/d-term"; then pass "term: no stub residue"; else fail "term: stub processes remain"; fi

# 想定外の内部エラー（集計の jq が終了コード 4 で失敗）は 1 に正規化し、後始末失敗（4）と取り違えさせない
mkdir -p "${root}/fakebin"
real_jq="$(command -v jq)"
cat >"${root}/fakebin/jq" <<FAKE
#!/usr/bin/env bash
for a in "\$@"; do case "\$a" in *'def stats'*) exit 4 ;; esac; done
exec "${real_jq}" "\$@"
FAKE
chmod 700 "${root}/fakebin/jq"
PATH="${root}/fakebin:${PATH}" run_case internal_error 1 normal "1000" --trials 1 --warmup 0 --timeout 10 || true
expect_unpublished internal_error
if grep -q 'unexpected internal failure' "${root}/internal_error.err"; then pass "internal_error: reported as measurement failure"; else fail "internal_error: message missing"; fi

# 同一性照合・シグナル送信の関数単体（PID 再利用・部分一致・comm 偽装の再現）。本体から定義だけを取り出して検証する。
fn_src="$(sed -n '/^readonly [a-z]*_re=/p;/^proc_info() {/,/^}/p;/^alive() {/,/^}/p;/^same_proc() {/,/^}/p;/^sig_same_proc() {/,/^}/p;/^env_owned() {/,/^}/p' "$target")"
if [[ "$fn_src" == *'proc_info() {'*'alive() {'*'same_proc() {'*'sig_same_proc() {'*'env_owned() {'* ]]; then
  eval "$fn_src"
  # 本体の kill 送信はすべて sig_same_proc を通る（直接の kill 呼び出しが他に無いことを照合する）
  kill_calls="$(grep -vE '^[[:space:]]*#' "$target" | grep -cE '(^|[;&|{(]|[[:space:]])kill[[:space:]]+["-]' || true)"
  if [ "$kill_calls" = "1" ]; then pass "target: kill is called only inside sig_same_proc"; else fail "target: found ${kill_calls} kill call sites, want 1"; fi
  sleep 300 &
  fn_pid=$!
  helper_pids+=("$fn_pid")
  proc_info "$fn_pid"
  fn_start="$REPLY_START"
  if [ "$REPLY_PPID" = "$$" ] && [ "$REPLY_STATE" != "Z" ]; then pass "proc_info: ppid and state of a live child"; else fail "proc_info: got ppid ${REPLY_PPID} state ${REPLY_STATE}"; fi
  if same_proc "$fn_pid" "$fn_start"; then pass "same_proc: matching start time"; else fail "same_proc: matching start time rejected"; fi
  if same_proc "$fn_pid" "$fn_start" "$$"; then pass "same_proc: matching parent"; else fail "same_proc: matching parent rejected"; fi
  if same_proc "$fn_pid" "$fn_start" "1"; then fail "same_proc: wrong parent accepted"; else pass "same_proc: wrong parent rejected"; fi
  # PID 再利用の再現: 同じ pid で起動時刻が異なる（記録が古い）場合は不一致
  if same_proc "$fn_pid" "$((fn_start + 1))"; then fail "same_proc: reused pid (different start time) accepted"; else pass "same_proc: reused pid rejected"; fi
  if same_proc "$fn_pid" ""; then fail "same_proc: empty record accepted"; else pass "same_proc: empty record rejected"; fi
  # sig_same_proc: 記録と起動時刻が違う（PID 再利用に相当）ならシグナルを送らず 1 を返し、プロセスは生存する
  sig_rc=0
  sig_same_proc KILL "$fn_pid" "$((fn_start + 1))" || sig_rc=$?
  sleep 0.2
  if [ "$sig_rc" -eq 1 ] && same_proc "$fn_pid" "$fn_start"; then pass "sig_same_proc: reused pid is not signaled (rc 1)"; else fail "sig_same_proc: reused pid rc ${sig_rc} or process died"; fi
  sig_rc=0
  sig_same_proc KILL "$fn_pid" "$fn_start" "1" || sig_rc=$?
  sleep 0.2
  if [ "$sig_rc" -eq 1 ] && same_proc "$fn_pid" "$fn_start"; then pass "sig_same_proc: wrong parent is not signaled (rc 1)"; else fail "sig_same_proc: wrong parent rc ${sig_rc} or process died"; fi
  # 自分自身・pid 1・数値でない pid（負数＝プロセスグループ宛を含む）には送らない
  for bad in "$$" 1 0 "-${fn_pid}" "x"; do
    sig_rc=0
    sig_same_proc KILL "$bad" "$fn_start" || sig_rc=$?
    if [ "$sig_rc" -eq 1 ] && same_proc "$fn_pid" "$fn_start"; then pass "sig_same_proc: refuses pid '${bad}'"; else fail "sig_same_proc: pid '${bad}' rc ${sig_rc}"; fi
  done
  # 同一性が一致すれば送信して 0 を返す
  sig_rc=0
  sig_same_proc KILL "$fn_pid" "$fn_start" "$$" || sig_rc=$?
  wait "$fn_pid" 2>/dev/null || true
  if [ "$sig_rc" -eq 0 ] && ! same_proc "$fn_pid" "$fn_start"; then pass "sig_same_proc: matching process is killed (rc 0)"; else fail "sig_same_proc: matching process rc ${sig_rc} or still alive"; fi
  if same_proc "$fn_pid" "$fn_start"; then fail "same_proc: dead pid accepted"; else pass "same_proc: dead pid rejected"; fi
  # comm 偽装: 実行ファイル名に ") Z (" を含めて stat の状態欄をゾンビに見せかけても、生存と判定する
  spoof="${root}/a) Z (b"
  mkfifo "${root}/spoof.fifo"
  # shellcheck disable=SC2016 # 生成するスクリプト側で展開させる
  printf '#!/bin/bash\nexec 3<>"$1"\nread -r -t 300 -u 3 || true\n' >"$spoof"
  chmod 700 "$spoof"
  "$spoof" "${root}/spoof.fifo" &
  spoof_pid=$!
  helper_pids+=("$spoof_pid")
  for _ in $(seq 1 50); do [ "$(cat "/proc/${spoof_pid}/comm" 2>/dev/null || true)" = "a) Z (b" ] && break; sleep 0.05; done
  if [ "$(cat "/proc/${spoof_pid}/comm" 2>/dev/null || true)" = "a) Z (b" ]; then pass "spoof: comm is 'a) Z (b'"; else fail "spoof: could not set up the comm spoof"; fi
  if alive "$spoof_pid" && [ "$REPLY_PPID" = "$$" ] && [ "$REPLY_STATE" != "Z" ]; then pass "alive: comm spoofing a zombie state is still alive"; else fail "alive: comm spoof treated as dead"; fi
  kill -KILL "$spoof_pid" 2>/dev/null || true
  wait "$spoof_pid" 2>/dev/null || true
  # env_owned: 完全一致のみ所有と認める
  # shellcheck disable=SC2034 # eval で取り込んだ env_owned が参照する
  owner_tok="tok123"
  env "FANDHE_BENCH_OWNER=tok123" sleep 300 &
  own_pid=$!
  env "DECOY=x_FANDHE_BENCH_OWNER=tok123" sleep 300 &
  dec_pid=$!
  env "FANDHE_BENCH_OWNER=tok1234" sleep 300 &
  pre_pid=$!
  helper_pids+=("$own_pid" "$dec_pid" "$pre_pid")
  sleep 0.2
  if env_owned "$own_pid"; then pass "env_owned: exact entry owned"; else fail "env_owned: exact entry rejected"; fi
  if env_owned "$dec_pid"; then fail "env_owned: substring-in-other-var accepted"; else pass "env_owned: substring-in-other-var rejected"; fi
  if env_owned "$pre_pid"; then fail "env_owned: longer token (prefix match) accepted"; else pass "env_owned: longer token rejected"; fi
  kill -KILL "$own_pid" "$dec_pid" "$pre_pid" 2>/dev/null || true
  wait "$own_pid" "$dec_pid" "$pre_pid" 2>/dev/null || true
else
  fail "function extraction from target failed"
fi

# --print-budget: 全体期限の上限（秒）の具体値。既定 = (20+1+2)*30 + 21*(1+2) + 60 = 813。
# trials 5・warmup 1・timeout 10・settle 1500ms = (5+1+2)*10 + 6*(2+2) + 60 = 164。launcher は不要
budget_default="$(bash "$target" --print-budget 2>/dev/null || echo "<error>")"
if [ "$budget_default" = "813" ]; then pass "print-budget: default is 813"; else fail "print-budget: default got ${budget_default}, want 813"; fi
budget_custom="$(bash "$target" --print-budget --trials 5 --warmup 1 --timeout 10 --settle-ms 1500 2>/dev/null || echo "<error>")"
if [ "$budget_custom" = "164" ]; then pass "print-budget: custom is 164"; else fail "print-budget: custom got ${budget_custom}, want 164"; fi
# 既定の全体期限は「全試行が待機上限まで掛かる場合」（23 回 × 30 秒 = 690 秒）より長い
if [ "$budget_default" -gt 690 ] 2>/dev/null; then pass "print-budget: default exceeds the sum of per-wait limits (690)"; else fail "print-budget: default does not exceed 690"; fi

# Makefile の restart-latency: 全体期限を --print-budget から決め、スクリプトの終了コードを保って返す
repo_root="$(cd "${script_dir}/.." && pwd)"
make_case() { # <名前> <STUB_MODE> <make 変数...> → 終了コードを MAKE_RC、出力を ${root}/<名前>.out / .err へ
  local name="$1" mode="$2"
  shift 2
  MAKE_RC=0
  mkdir -p "${root}/d-${name}"
  STUB_MODE="$mode" STUB_ELAPSED="" STUB_DELAY="" STUB_DIR="${root}/d-${name}" STUB_FOREIGN="${root}/foreign.pid" STUB_SPAWN="${root}/spawn.req" \
    MAKEFLAGS="" make --no-print-directory -C "$repo_root" restart-latency LAUNCHER="${root}/launcher.sh" BUNDLE="${root}/bundle" WARMUP=0 "$@" \
    >"${root}/${name}.out" 2>"${root}/${name}.err" </dev/null || MAKE_RC=$?
}
make_case make_ok normal TRIALS=2
if [ "$MAKE_RC" -eq 0 ]; then pass "make_ok: exit 0"; else fail "make_ok: exit ${MAKE_RC}, want 0"; fi
jq_eq make_ok "${root}/make_ok.out" '[.behavior, .trials, .warmup, .observed.samples]' '["SUP-3",2,0,2]'
if grep -q 'warning: RESTART_LATENCY_TIMEOUT' "${root}/make_ok.err"; then fail "make_ok: unexpected budget warning"; else pass "make_ok: computed budget is used without a warning"; fi
if no_residue "${root}/d-make_ok"; then pass "make_ok: no stub residue"; else fail "make_ok: stub processes remain"; fi
# 全体期限切れ: スクリプトは TERM を受けて後始末を終え、make のレシピは 1（Error 1）で結果を公開しない
make_case make_timeout no_restart TRIALS=1 RESTART_LATENCY_WAIT_TIMEOUT=60 RESTART_LATENCY_TIMEOUT=2
if [ "$MAKE_RC" -ne 0 ] && grep -q 'Error 1$' "${root}/make_timeout.err" && grep -q 'error: timeout:' "${root}/make_timeout.err"; then
  pass "make_timeout: recipe exit 1 with the timeout message"
else
  fail "make_timeout: make exit ${MAKE_RC} or message missing"
fi
if grep -q 'warning: RESTART_LATENCY_TIMEOUT=2s is shorter than the worst-case duration 243s' "${root}/make_timeout.err"; then pass "make_timeout: short limit warned (budget (1+0+2)*60 + 1*3 + 60 = 243)"; else fail "make_timeout: budget warning missing"; fi
expect_unpublished make_timeout
if no_residue "${root}/d-make_timeout"; then pass "make_timeout: no stub residue"; else fail "make_timeout: stub processes remain"; fi
# 後始末失敗の 4 は make 経由でも 4（Error 4）のまま返る
make_case make_leftover late_session TRIALS=1
if [ "$MAKE_RC" -ne 0 ] && grep -q 'Error 4$' "${root}/make_leftover.err"; then pass "make_leftover: recipe exit 4"; else fail "make_leftover: make exit ${MAKE_RC} or Error 4 missing"; fi
expect_unpublished make_leftover
expect_survivor make_leftover "${root}/d-make_leftover/leftover"

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
sleep 0.1 # 起動時刻（1/100 秒刻み）が launcher より確実に前になるようにする（無関係と確定 → 終了コード 4 にしない）
run_case foreign_pid 1 foreign_pid "" --trials 1 --warmup 0 --timeout 2 || true
if kill -0 "$foreign_pid" 2>/dev/null; then pass "foreign_pid: unrelated process was not signaled"; else fail "foreign_pid: unrelated process was killed"; fi
kill "$foreign_pid" 2>/dev/null || true
foreign_pid=""

# 再起動後の新 pid が launcher の子孫でないときも無関係プロセスとして扱い、kill せず終了コード 1（4 にしない）
sleep 300 &
foreign_pid=$!
echo "$foreign_pid" >"${root}/foreign.pid"
sleep 0.1
run_case foreign_new 1 foreign_new "" --trials 1 --warmup 0 --timeout 2 || true
if kill -0 "$foreign_pid" 2>/dev/null; then pass "foreign_new: unrelated restarted pid was not signaled"; else fail "foreign_new: unrelated restarted pid was killed"; fi
kill "$foreign_pid" 2>/dev/null || true
foreign_pid=""

# --state-root は FANDHE_BENCH_STATE_ROOT として launcher へ渡る（スタブは XDG を見ず、この変数の下へ書く）
mkdir -m 0700 "${root}/sr"
run_case state_root 0 normal "1000 1000" --trials 1 --warmup 0 --timeout 10 --state-root "${root}/sr" || true
if [ -s "${root}/state_root.out" ]; then pass "state_root: result published"; else fail "state_root: no result"; fi

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
mkdir -m 0777 "${root}/open-sr"
chk2 unsafe_state_root --launcher "${root}/launcher.sh" --bundle "${root}/bundle" --state-root "${root}/open-sr"
chk2 bad_budget_arg --print-budget --trials 0
chk2 unknown_opt --bogus
chk2 missing_launcher --bundle "${root}/bundle"

# --help は冒頭コメントを出し、SUP-3 を明記している。出力（約 10 KB）を grep -q へ直接パイプすると、
# grep が一致して先に終わった後の sed の書き込みが SIGPIPE（141）になり pipefail で偶発的に失敗するため、
# 変数に取ってから照合する（#1726）。
if help_out="$(bash "$target" --help)" && grep -q 'SUP-3' <<<"$help_out"; then pass "help: mentions SUP-3"; else fail "help: SUP-3 missing"; fi

# --output は新規ファイルにだけ書く
if run_case output_file 0 normal "" --trials 1 --warmup 0 --timeout 10 --output "${root}/result.json"; then
  jq_eq output_file "${root}/result.json" '.behavior' '"SUP-3"'
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL: ${failures} check(s) failed" >&2
  exit 1
fi
echo "OK: all checks passed"
