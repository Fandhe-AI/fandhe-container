#!/usr/bin/env bash
# scripts/bench/concurrent_50_memory.sh の自己テスト（TASK-50.1・CORE-9・SUP-1・REPAIR-12）。
#
# 役割: bash 製のスタブ launcher（`run --id <id> --bundle <dir>` を受け、子として sleep を起動して
# 待つ）で計測スクリプトを実行し、終了コード・出力・後始末を具体値で照合する。実ランタイム・root・
# 実コンテナは使わない。メモリ値の照合は、スタブが mktemp -d 配下の疑似 /proc（--proc-root）へ
# 書く値で行う。呼び出し元は Makefile の `concurrent-memory-selftest`。
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。前提を満たさない環境では skip せず
# 失敗する（ci.md「skip で CI を通さない」）。
#
# スタブの挙動は環境変数で切り替える（計測スクリプトから launcher へ継承される）:
#   STUB_MODE: ok | nochild（子を作らない）| ignoreterm（SIGTERM を無視）| hang（何もせず待つ）|
#     dieafter（子を作った 1 秒後に launcher だけが終了し、子が孤児として残る）|
#     diefast（子を作って即座に launcher だけが終了。親子関係を一度も観測できない）|
#     noready（子は作るが READY 行を出さない）
#   STUB_PIDFILE: スタブが起動した sleep の「pid 起動時刻」を追記するファイル（孤児確認をこの
#     selftest が起動した sleep に限定するため。無関係な sleep 300 を数えない）
#   STUB_NO_READY=1: READY 行を出さない（STUB_MODE と併用できる）
#   STUB_BIGWRITE=<パス接頭辞>: READY の前に、子プロセス（head）で 3 MiB（3145728 バイト）のファイルを
#     <接頭辞>.<i> へ書く。書けなければ READY を出さずに終了する（launcher の子孫へのファイルサイズ
#     制限の有無を照合する）
#   STUB_TOUCH=<パス>: READY の前にそのパスへ `raced` と書く（計測中に出力先が作られる状況の模擬）
#   STUB_NOISE_KIB=<N>: READY の前に N KiB を標準出力へ書く（ログ上限超過の模擬）
#   STUB_MID=launcher|child（疑似 /proc 使用時のみ）: 1 番目のコンテナが「自分の集計が始まった瞬間」に
#     launcher ごと（launcher）または子だけ（child）終了する。子の smaps_rollup を FIFO にして計測
#     スクリプトの読み取りと同期し、2 番目以降は 1 番目の終了を待ってから値を返す（集計中の終了を
#     時間待ちに頼らず決定的に再現する）。STUB_MID_DIR に同期用のファイルを置く
#   STUB_DEEP=1: 疑似 /proc に MAX_DEPTH（16）を超える深さの子孫チェーンを書く
#   STUB_DIE_I: i 番目（1 始まり）のコンテナは即終了する
#   STUB_PSS_BY_TRIAL: 試行ごとの子の Pss（kB。カンマ区切り。疑似 /proc 使用時のみ）
#   STUB_LAUNCHER_PSS: launcher 自身の Pss（既定 100）
#   STUB_NO_SMAPS=1: smaps_rollup を書かない（読めない値の模擬）
#   FAKE_PROC: 疑似 /proc のルート（設定時のみ疑似エントリを書く）

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/concurrent_50_memory.sh"
bench_check="${script_dir}/../check-bench-regression.sh"
bash_bin="$(command -v bash)"

if [ "$(uname -s)" != "Linux" ] || [ ! -r /proc/self/smaps_rollup ]; then
  echo "FAIL: selftest requires Linux with /proc/<pid>/smaps_rollup" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: selftest requires jq" >&2
  exit 1
fi

# pid の状態を判定する補助（stat の起動時刻と状態文字。pid 再利用・ゾンビを数えない）。
pid_starttime() { # <pid> → 22 番目のフィールド
  local s rest f
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  printf '%s' "${f[19]:-}"
}
pid_state() { # <pid> → 状態文字
  local s rest
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  printf '%s' "${rest:0:1}"
}
# STUB_PIDFILE に記録された（pid, 起動時刻が一致する）生存中の sleep だけを列挙する。
recorded_alive() {
  local pid st cur state
  [ -f "$STUB_PIDFILE" ] || return 0
  while read -r pid st; do
    [ -n "${pid:-}" ] || continue
    cur="$(pid_starttime "$pid" 2>/dev/null || true)"
    [ "$cur" = "$st" ] || continue
    state="$(pid_state "$pid" 2>/dev/null || true)"
    case "$state" in Z | X | x | '') continue ;; esac
    printf '%s\n' "$pid"
  done <"$STUB_PIDFILE"
}
kill_recorded() {
  local pid
  for pid in $(recorded_alive); do kill -KILL "$pid" 2>/dev/null || true; done
}

work="$(mktemp -d)"
export STUB_PIDFILE="$work/stub-pids"
: >"$STUB_PIDFILE"
cleanup() {
  # 失敗時にスタブの残存があっても作業ディレクトリ配下の sleep は終了させる。
  pkill -f -- "${work}/" 2>/dev/null || true
  kill_recorded
  rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }
expect_eq() { # <名前> <期待> <実際>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=$2, actual=$3)"; fi
}
expect_has() { # <名前> <ファイル> <部分文字列>
  if grep -qF -- "$3" "$2"; then pass "$1"; else fail "$1 (missing: $3)"; fi
}

mkdir -p "$work/bundle" "$work/fake"
stub="$work/stub-launcher"
{
  printf '#!%s\n' "$bash_bin"
  cat <<'STUB'
# スタブ launcher。$1=run $2=--id $3=<id> $4=--bundle $5=<dir>
id="$3"
rest="${id#*-}"; rest="${rest#*-}"      # <trial>-<i>
trial="${rest%%-*}"; idx="${rest##*-}"
if [ -n "${STUB_DIE_I:-}" ] && [ "$idx" = "$STUB_DIE_I" ]; then echo "stub: boom" >&2; exit 7; fi
mode="${STUB_MODE:-ok}"
child=""
cleanup() { [ -z "$child" ] || kill "$child" 2>/dev/null || true; exit 0; }
if [ "$mode" = "ignoreterm" ]; then trap '' TERM; else trap cleanup TERM INT; fi
record_child() { # この selftest が起動した sleep の pid と起動時刻を記録する
  [ -n "${STUB_PIDFILE:-}" ] || return 0
  local s rest f
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 0
  rest="${s##*) }"
  read -ra f <<<"$rest"
  printf '%s %s\n' "$1" "${f[19]:-}" >>"$STUB_PIDFILE"
}
if [ "$mode" = "dieafter" ]; then sleep 300 & record_child $!; sleep 1; exit 0; fi
if [ "$mode" = "diefast" ]; then sleep 300 & record_child $!; exit 0; fi
if [ "$mode" != "nochild" ] && [ "$mode" != "hang" ]; then
  sleep 300 &
  child=$!
  record_child "$child"
fi
if [ -n "${STUB_BIGWRITE:-}" ]; then
  head -c 3145728 /dev/zero >"${STUB_BIGWRITE}.${idx}" || { echo "stub: bigwrite failed" >&2; exit 9; }
fi
if [ -n "${STUB_TOUCH:-}" ]; then echo raced >"$STUB_TOUCH"; fi
if [ -n "${STUB_NOISE_KIB:-}" ]; then
  head -c "$((STUB_NOISE_KIB * 1024))" /dev/zero | tr '\0' 'x'
  echo
fi
if [ -n "${FAKE_PROC:-}" ] && [ "$mode" != "hang" ]; then
  IFS=, read -ra vals <<<"${STUB_PSS_BY_TRIAL:-1000}"
  v="${vals[$((trial - 1))]:-${vals[0]}}"
  lp="${STUB_LAUNCHER_PSS:-100}"
  mk() { # <pid> <pss>
    mkdir -p "$FAKE_PROC/$1/task/$1"
    if [ -z "${STUB_NO_SMAPS:-}" ]; then printf 'Rss: 1 kB\nPss: %s kB\n' "$2" >"$FAKE_PROC/$1/smaps_rollup"; fi
    printf 'Name: x\nVmRSS: %s kB\n' "$(( ${2//[^0-9]/0} * 2 ))" >"$FAKE_PROC/$1/status"
    : >"$FAKE_PROC/$1/task/$1/children"
    if [ -z "${STUB_NO_ENVIRON:-}" ]; then printf 'FANDHE_BENCH_OWNER=%s\0' "${FANDHE_BENCH_OWNER:-}" >"$FAKE_PROC/$1/environ"; fi
  }
  [ -z "$child" ] || mk "$child" "$v"
  mk "$$" "$lp"
  [ -z "$child" ] || printf '%s \n' "$child" >"$FAKE_PROC/$$/task/$$/children"
  if [ -n "${STUB_MID:-}" ] && [ -n "$child" ]; then
    fifo="$FAKE_PROC/$child/smaps_rollup"
    rm -f "$fifo"
    mkfifo "$fifo"
    if [ "$idx" = "1" ]; then
      echo "$$" >"$STUB_MID_DIR/l1.pid"
      (
        # 計測スクリプトがこの FIFO を開く（= 1 番目の集計が始まる）まで書き込みの open で待つ。
        printf 'Rss: 1 kB\nPss: %s kB\n' "$v" >"$fifo"
        if [ "$STUB_MID" = "launcher" ]; then
          kill -KILL "$child" "$$" 2>/dev/null || true
        else
          kill -KILL "$child" 2>/dev/null || true
          : >"$FAKE_PROC/$$/task/$$/children"
        fi
        : >"$STUB_MID_DIR/done"
      ) &
    else
      (
        exec 3>"$fifo"
        # 1 番目の終了が完了する（launcher モードでは launcher が消滅・ゾンビになる）まで値を返さない。
        for _ in $(seq 1 100); do
          if [ -e "$STUB_MID_DIR/done" ]; then
            if [ "$STUB_MID" != "launcher" ]; then break; fi
            l1="$(cat "$STUB_MID_DIR/l1.pid" 2>/dev/null || true)"
            s=""
            { IFS= read -r s <"/proc/$l1/stat"; } 2>/dev/null || break
            s="${s##*) }"
            case "${s:0:1}" in Z | X | x) break ;; esac
          fi
          sleep 0.1
        done
        printf 'Rss: 1 kB\nPss: %s kB\n' "$v" >&3
      ) &
    fi
  fi
  if [ -n "${STUB_DEEP:-}" ]; then
    # launcher -> 900000+idx*100 -> 次 ... と 20 段のチェーン（実在しない pid。疑似 /proc 上のみ）。
    base=$((900000 + idx * 100))
    printf '%s \n' "$base" >"$FAKE_PROC/$$/task/$$/children"
    for d in $(seq 0 19); do
      mkdir -p "$FAKE_PROC/$((base + d))/task/$((base + d))"
      printf 'FANDHE_BENCH_OWNER=%s\0' "${FANDHE_BENCH_OWNER:-}" >"$FAKE_PROC/$((base + d))/environ"
      if [ "$d" -lt 19 ]; then printf '%s \n' "$((base + d + 1))" >"$FAKE_PROC/$((base + d))/task/$((base + d))/children"; else : >"$FAKE_PROC/$((base + d))/task/$((base + d))/children"; fi
    done
  fi
fi
# 起動完了の明示的な通知（ready 状態）。hang・noready は出さない。
if [ "$mode" != "hang" ] && [ "$mode" != "noready" ] && [ -z "${STUB_NO_READY:-}" ]; then echo READY; fi
# SIGTERM を即座に処理するため、sleep を待つ形で待機する。
while :; do sleep 1 & wait $! || true; done
STUB
} >"$stub"
chmod +x "$stub"

out="$work/out.json"
errf="$work/err.txt"
rc=0
# 計測スクリプトの前に付けるコマンド（FIFO で同期するケースだけ timeout で包み、同期の失敗でハングさせない）。
run_wrap=()

# 計測スクリプトを実行し rc・$out・$errf を更新する。
run_target() {
  rc=0
  : >"$out"; : >"$errf"
  "${run_wrap[@]}" "$bash_bin" "$target" --launcher "$stub" --bundle "$work/bundle" --target own --settle 0 "$@" >"$out" 2>"$errf" || rc=$?
}
run_fake() { # 疑似 /proc を使う（メモリ値の具体照合）
  rm -rf "$work/fake"; mkdir -p "$work/fake"
  FAKE_PROC="$work/fake" FANDHE_CONCURRENT_MEMORY_SELFTEST=1 run_target --proc-root "$work/fake" "$@"
}
# SIGKILL 直後はカーネルが終了処理中のことがあるため、孤児 sleep の残数は最大 3 秒ポーリングして 0 を待つ。
# 数えるのはスタブが記録した pid（起動時刻一致）だけで、ホスト上の無関係な sleep 300 は数えない。
orphan_sleep_count() {
  local n=0
  for _ in $(seq 1 15); do
    n="$(recorded_alive | wc -l)"
    [ "${n:-0}" != "0" ] || break
    sleep 0.2
  done
  printf '%s' "${n:-0}"
}
alive_stub_count() { pgrep -fc -- "${work}/stub-launcher" 2>/dev/null || true; }

# --- 1. 正常系（疑似 /proc）: 5 個・3 試行。コンテナ PSS = 100 + 子 → 5*(100+x) ---
export STUB_PSS_BY_TRIAL="1000,3000,2000"
run_fake --count 5 --trials 3
expect_eq "ok-exit0" 0 "$rc"
expect_eq "ok-n-started-min" 5 "$(jq -r '.n_started_min' "$out")"
expect_eq "ok-pss-median" 10500 "$(jq -r '.metrics.concurrent_5_pss_median_kb.value' "$out")"
expect_eq "ok-rss-median" 21000 "$(jq -r '.metrics.concurrent_5_rss_median_kb.value' "$out")"
expect_eq "ok-trial-started" "5,5,5" "$(jq -r '[.trial_results[].n_started] | join(",")' "$out")"
expect_eq "ok-trial-pss" "5500,15500,10500" "$(jq -r '[.trial_results[].pss_total_kb] | join(",")' "$out")"
expect_eq "ok-process-count" 10 "$(jq -r '.trial_results[0].process_count' "$out")"
expect_eq "ok-behavior" "CORE-9,SUP-1" "$(jq -r '.behavior | join(",")' "$out")"
expect_eq "ok-no-path-leak" 0 "$(grep -c -F "$work" "$out" || true)"
expect_eq "ok-no-residual" 0 "$(alive_stub_count)"

# --- 2. 出力が check-bench-regression.sh のスキーマと互換 ---
cat >"$work/baseline.json" <<'JSON'
{
  "schema_version": 1,
  "metrics": {
    "concurrent_5_pss_median_kb": {"value": 100000, "unit": "kB", "direction": "lower_is_better"},
    "concurrent_5_rss_median_kb": {"value": 100000, "unit": "kB", "direction": "lower_is_better"}
  }
}
JSON
rc2=0
"$bash_bin" "$bench_check" "$work/baseline.json" "$out" >/dev/null 2>&1 || rc2=$?
expect_eq "bench-regression-schema-compat" 0 "$rc2"

# --- 3. 中央値の定義: 偶数試行は中央 2 値の平均（小数 1 桁） ---
export STUB_PSS_BY_TRIAL="1000,3000,2000,4000"
run_fake --count 5 --trials 4
expect_eq "even-trials-exit0" 0 "$rc"
expect_eq "even-trials-median" 13000.0 "$(jq -r '.metrics.concurrent_5_pss_median_kb.value | tostring | if test("\\.") then . else . + ".0" end' "$out")"
unset STUB_PSS_BY_TRIAL

# --- 3b. トークンを継承しない子孫（追跡不能）は失敗にする（P1・後始末で回収できない） ---
STUB_NO_ENVIRON=1 run_fake --count 2 --trials 1
expect_eq "untracked-exit1" 1 "$rc"
expect_has "untracked-stderr" "$errf" "untracked-process"
expect_eq "untracked-no-residual" 0 "$(alive_stub_count)"

# --- 4. text 形式と --output（成功時のみ公開） ---
run_fake --count 3 --trials 1 --format text --output "$work/pub.txt"
expect_eq "text-exit0" 0 "$rc"
expect_has "text-started" "$work/pub.txt" "started=3/3"
expect_has "text-pss" "$work/pub.txt" "pss_median_kb=3300"
expect_eq "text-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "no-leftover-tmp" 1 "$(find "$work" -maxdepth 1 -name 'pub.txt*' | wc -l)"

# --- 4b. --output は新規ファイルに限る: 既存ファイルは計測前に拒否し、内容を変えない ---
echo keep >"$work/existing.json"
run_fake --count 2 --trials 1 --output "$work/existing.json"
expect_eq "output-exists-exit2" 2 "$rc"
expect_has "output-exists-stderr" "$errf" "output path already exists"
expect_eq "output-exists-unchanged" keep "$(cat "$work/existing.json")"
expect_eq "output-exists-no-residual" 0 "$(alive_stub_count)"
# 計測中に同名のファイルが作られた場合も上書きしない（公開は ln -T。一時ファイルも残さない）
STUB_TOUCH="$work/raced.json" run_fake --count 1 --trials 1 --output "$work/raced.json"
expect_eq "output-raced-exit2" 2 "$rc"
expect_has "output-raced-stderr" "$errf" "output-failed: cannot publish output"
expect_eq "output-raced-unchanged" raced "$(cat "$work/raced.json")"
expect_eq "output-raced-no-leftover-tmp" 1 "$(find "$work" -maxdepth 1 -name 'raced.json*' | wc -l)"
expect_eq "output-raced-stdout-empty" 0 "$(wc -c <"$out")"

# --- 5. 既定 --count は 50（実 /proc・疑似 /proc いずれでも 50/50 起動できる） ---
run_fake --trials 1 --timeout 60
expect_eq "default-count50-exit0" 0 "$rc"
expect_eq "default-count50-started" 50 "$(jq -r '.n_started_min' "$out")"
expect_eq "default-count50-metric" "concurrent_50_pss_median_kb" "$(jq -r '.metrics | keys[] | select(test("pss"))' "$out")"
expect_eq "default-count50-no-residual" 0 "$(alive_stub_count)"

# --- 6. 起動不足: 1 個が即終了 → exit 1・結果は公開されない ---
STUB_DIE_I=3 run_fake --count 5 --trials 1 --output "$work/never.json"
expect_eq "startup-incomplete-exit1" 1 "$rc"
expect_eq "startup-incomplete-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "startup-incomplete-no-output-file" 0 "$(find "$work" -maxdepth 1 -name 'never.json*' | wc -l)"
expect_has "startup-incomplete-stderr" "$errf" "startup-incomplete: trial=1 started=4/5"
expect_has "startup-incomplete-id" "$errf" "id=fc-bench50-1-3"
expect_has "startup-incomplete-log-tail" "$errf" "stub: boom"
expect_eq "startup-incomplete-no-residual" 0 "$(alive_stub_count)"

# --- 7. --min-procs 未達（子を作らない launcher）→ exit 1。期限は短く ---
start=$SECONDS
STUB_MODE=nochild run_fake --count 2 --trials 1 --timeout 2
expect_eq "min-procs-exit1" 1 "$rc"
expect_has "min-procs-stderr" "$errf" "started=0/2"
if [ $((SECONDS - start)) -le 20 ]; then pass "min-procs-bounded-time"; else fail "min-procs-bounded-time"; fi
expect_eq "min-procs-no-residual" 0 "$(alive_stub_count)"

# --- 8. 期限切れ（起動完了しない launcher）→ exit 1 かつ所定時間内 ---
start=$SECONDS
STUB_MODE=hang run_fake --count 2 --trials 1 --timeout 2
expect_eq "timeout-exit1" 1 "$rc"
if [ $((SECONDS - start)) -le 20 ]; then pass "timeout-bounded-time"; else fail "timeout-bounded-time"; fi
expect_eq "timeout-no-residual" 0 "$(alive_stub_count)"

# --- 9. PSS 0 / 非数値 / 読めない値は合算せず exit 1 ---
STUB_PSS_BY_TRIAL="0" STUB_LAUNCHER_PSS=0 run_fake --count 3 --trials 1
expect_eq "zero-pss-exit1" 1 "$rc"
expect_has "zero-pss-stderr" "$errf" "zero_pss_count=3"
expect_eq "zero-pss-stdout-empty" 0 "$(wc -c <"$out")"
STUB_PSS_BY_TRIAL="12abc" run_fake --count 2 --trials 1
expect_eq "non-numeric-exit1" 1 "$rc"
expect_has "non-numeric-stderr" "$errf" "non-numeric-memory-value"
STUB_NO_SMAPS=1 run_fake --count 2 --trials 1
expect_eq "unreadable-exit1" 1 "$rc"
expect_has "unreadable-stderr" "$errf" "unreadable-memory-value"
expect_eq "measure-failure-no-residual" 0 "$(alive_stub_count)"

# --- 10. 実 /proc での正常系（スタブ sleep の実 Pss は正の値になる） ---
run_target --count 2 --trials 1
expect_eq "real-proc-exit0" 0 "$rc"
if [ "$(jq -r '.metrics.concurrent_2_pss_median_kb.value > 0' "$out")" = "true" ]; then pass "real-proc-pss-positive"; else fail "real-proc-pss-positive"; fi
expect_eq "real-proc-no-residual" 0 "$(alive_stub_count)"

# --- 11. SIGTERM を無視する launcher は SIGKILL で回収され、終了コードは元のまま ---
: >"$STUB_PIDFILE"
STUB_MODE=ignoreterm run_fake --count 2 --trials 1 --timeout 2
expect_eq "ignoreterm-exit0" 0 "$rc"
expect_eq "ignoreterm-no-residual" 0 "$(alive_stub_count)"
expect_eq "ignoreterm-no-orphan-child" 0 "$(orphan_sleep_count)"

# --- 12. 回収不能（selftest 専用フックで SIGKILL を抑止）は exit 4 ---
STUB_MODE=ignoreterm FANDHE_CONCURRENT_MEMORY_SELFTEST_NOKILL=1 run_fake --count 2 --trials 1 --timeout 1
expect_eq "cleanup-failed-exit4" 4 "$rc"
expect_has "cleanup-failed-stderr" "$errf" "cleanup-failed"
# 残存を片付ける（stderr に出た pid のみ）。
for p in $(grep -o 'pid=[0-9]*' "$errf" | cut -d= -f2); do kill -KILL "$p" 2>/dev/null || true; done
kill_recorded
sleep 0.5

# --- 12b. 深さ上限（MAX_DEPTH=16）超のツリーは過少計上になるため成功にしない ---
STUB_DEEP=1 run_fake --count 2 --trials 1 --timeout 2
expect_eq "deep-tree-exit1" 1 "$rc"
expect_eq "deep-tree-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "deep-tree-no-residual" 0 "$(alive_stub_count)"

# --- 12c. launcher が子孫より先に死んでも、孫は所有トークンで追跡して後始末で回収する ---
: >"$STUB_PIDFILE"
STUB_MODE=dieafter run_target --count 2 --trials 1 --settle 3 --timeout 10
expect_eq "dead-launcher-exit1" 1 "$rc"
expect_has "dead-launcher-stderr" "$errf" "startup-incomplete"
expect_eq "dead-launcher-no-orphan-child" 0 "$(orphan_sleep_count)"

# --- 12d. launcher が子を作って即死しても（親子関係を一度も観測できなくても）残存させない ---
: >"$STUB_PIDFILE"
STUB_MODE=diefast run_target --count 2 --trials 1 --settle 1 --timeout 5
expect_eq "diefast-exit1" 1 "$rc"
expect_eq "diefast-no-orphan-child" 0 "$(orphan_sleep_count)"

# --- 12e. READY 行を出さない launcher は、プロセス数が足りていても起動完了と見なさない ---
STUB_MODE=noready run_target --count 2 --trials 1 --timeout 2
expect_eq "noready-exit1" 1 "$rc"
expect_has "noready-stderr" "$errf" "started=0/2"
expect_eq "noready-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "noready-no-residual" 0 "$(alive_stub_count)"

# --- 12f. launcher の子孫へファイルサイズ制限を掛けない（CORE-9。ulimit -f を継承させると、コンテナ内の
#          書き込みが SIGXFSZ で失敗して計測条件が変わる）。子が 3 MiB を書けて N/N 起動になる ---
STUB_BIGWRITE="$work/big" run_fake --count 2 --trials 1
expect_eq "bigwrite-exit0" 0 "$rc"
expect_eq "bigwrite-started" 2 "$(jq -r '.n_started_min' "$out")"
expect_eq "bigwrite-size-1" 3145728 "$(wc -c <"$work/big.1" 2>/dev/null || echo missing)"
expect_eq "bigwrite-size-2" 3145728 "$(wc -c <"$work/big.2" 2>/dev/null || echo missing)"
expect_eq "bigwrite-no-residual" 0 "$(alive_stub_count)"

# --- 12g. ログの上限は収集側で設ける: 上限（2048 KiB）を超えるログを出す launcher は計測失敗にして
#          停止する（結果は公開しない。REPAIR-5 のリソース上限） ---
start=$SECONDS
STUB_NOISE_KIB=3072 run_fake --count 1 --trials 1 --timeout 20
expect_eq "log-limit-exit1" 1 "$rc"
expect_has "log-limit-stderr" "$errf" "log-limit-exceeded: trial=1 id=fc-bench50-1-1 limit_kib=2048"
expect_eq "log-limit-stdout-empty" 0 "$(wc -c <"$out")"
if [ $((SECONDS - start)) -le 15 ]; then pass "log-limit-detected-before-timeout"; else fail "log-limit-detected-before-timeout"; fi
expect_eq "log-limit-no-residual" 0 "$(alive_stub_count)"

# --- 12h. 集計中に終了したコンテナを検出する（CORE-9・SUP-1。先に集計したコンテナの launcher が、後続の
#          集計中に終了しても N/N として公開しない） ---
mkdir -p "$work/mid"
run_wrap=(timeout --kill-after=5 60)
rm -f "$work/mid/"*
STUB_MID=launcher STUB_MID_DIR="$work/mid" run_fake --count 2 --trials 1 --output "$work/mid-never.json"
expect_eq "mid-launcher-exit1" 1 "$rc"
expect_has "mid-launcher-stderr" "$errf" "measurement-failed: trial=1 running_after_measurement=1/2 reason=container-exited-during-measurement"
expect_has "mid-launcher-id" "$errf" "unstarted: id=fc-bench50-1-1"
expect_eq "mid-launcher-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "mid-launcher-no-output-file" 0 "$(find "$work" -maxdepth 1 -name 'mid-never.json*' | wc -l)"
expect_eq "mid-launcher-no-residual" 0 "$(alive_stub_count)"

# --- 12i. 集計中に launcher は残り子プロセスだけが終了した場合も検出する（必要な子プロセスの生存） ---
rm -f "$work/mid/"*
STUB_MID=child STUB_MID_DIR="$work/mid" run_fake --count 2 --trials 1
expect_eq "mid-child-exit1" 1 "$rc"
expect_has "mid-child-stderr" "$errf" "measurement-failed: trial=1 running_after_measurement=1/2 reason=container-exited-during-measurement"
expect_eq "mid-child-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "mid-child-no-residual" 0 "$(alive_stub_count)"
run_wrap=()

# --- 12j. 記録した起動時刻と一致しない pid（再利用された pid の模擬。selftest 専用フック）へはシグナルを
#          送らない。launcher は生存扱いにもならず起動数不足になり、プロセスは終了させられずに残る
#          （環境変数トークンを持たないので所有プロセスとしても回収されない）。直接の子として生存して
#          いるものは黙って残さず、後始末失敗（exit 4）として pid を報告する ---
: >"$STUB_PIDFILE"
STUB_NO_ENVIRON=1 FANDHE_CONCURRENT_MEMORY_SELFTEST_STALE_START=1 run_fake --count 2 --trials 1 --timeout 2
expect_eq "stale-start-exit4" 4 "$rc"
expect_has "stale-start-stderr" "$errf" "startup-incomplete: trial=1 started=0/2"
expect_has "stale-start-reported" "$errf" "cleanup-failed: processes still running: pid="
expect_eq "stale-start-stdout-empty" 0 "$(wc -c <"$out")"
expect_eq "stale-start-not-signalled" 2 "$(alive_stub_count)"
pkill -TERM -f -- "${work}/stub-launcher" 2>/dev/null || true
kill_recorded
for _ in $(seq 1 15); do [ "$(alive_stub_count)" != "0" ] || break; sleep 0.2; done
expect_eq "stale-start-test-cleanup" 0 "$(alive_stub_count)"

# --- 12k. 後始末中に 2 回目以降のシグナル（TERM・HUP）を受けても後始末を最後まで行う（REPAIR-5。
#          SIGTERM を無視する launcher の終了待ち中に再送しても、launcher・子を残さない） ---
: >"$STUB_PIDFILE"
: >"$out"; : >"$errf"
STUB_MODE=ignoreterm STUB_NO_READY=1 "$bash_bin" "$target" --launcher "$stub" --bundle "$work/bundle" --target own \
  --count 2 --trials 1 --timeout 20 >"$out" 2>"$errf" &
sig_pid=$!
for _ in $(seq 1 50); do [ "$(wc -l <"$STUB_PIDFILE")" -lt 2 ] || break; sleep 0.2; done
expect_eq "resignal-stubs-started" 2 "$(wc -l <"$STUB_PIDFILE")"
kill -TERM "$sig_pid"
# 1 回目のシグナルが処理され後始末が始まった（interrupted が出た）ことを確認してから再送する。
for _ in $(seq 1 50); do
  if grep -qF "interrupted" "$errf"; then break; fi
  sleep 0.1
done
expect_has "resignal-first-signal-handled" "$errf" "interrupted: received signal (exit 143); running cleanup"
kill -TERM "$sig_pid" 2>/dev/null || true
sleep 0.3
kill -HUP "$sig_pid" 2>/dev/null || true
r=0
wait "$sig_pid" || r=$?
expect_eq "resignal-exit143" 143 "$r"
expect_eq "resignal-no-residual" 0 "$(alive_stub_count)"
expect_eq "resignal-no-orphan-child" 0 "$(orphan_sleep_count)"

# --- 13. 引数エラーは exit 2 ---
expect_rc2() { # <名前> <引数...>
  local name="$1"; shift
  local r=0
  "$bash_bin" "$target" "$@" >/dev/null 2>&1 || r=$?
  expect_eq "$name" 2 "$r"
}
base=(--launcher "$stub" --bundle "$work/bundle" --target own)
expect_rc2 "arg-relative-launcher" --launcher stub-launcher --bundle "$work/bundle" --target own
expect_rc2 "arg-missing-launcher" --bundle "$work/bundle" --target own
expect_rc2 "arg-count-zero" "${base[@]}" --count 0
expect_rc2 "arg-count-over-limit" "${base[@]}" --count 1025
expect_rc2 "arg-count-leading-zero" "${base[@]}" --count 08
expect_rc2 "arg-trials-zero" "${base[@]}" --trials 0
expect_rc2 "arg-bad-target" --launcher "$stub" --bundle "$work/bundle" --target 'Bad Target'
expect_rc2 "arg-missing-target" --launcher "$stub" --bundle "$work/bundle"
expect_rc2 "arg-mode-docker" "${base[@]}" --mode docker
expect_rc2 "arg-proc-root-without-env" "${base[@]}" --proc-root "$work/fake"
expect_rc2 "arg-bad-bundle" --launcher "$stub" --bundle "$work/nonexistent" --target own
expect_rc2 "arg-bad-format" "${base[@]}" --format yaml
expect_rc2 "arg-unknown" "${base[@]}" --bogus
expect_rc2 "arg-output-dir" "${base[@]}" --output "$work"
mkdir -p "$work/ow" "$work/oreal"
chmod 777 "$work/ow"
chmod 700 "$work/oreal"
ln -s "$work/oreal" "$work/olink"
expect_rc2 "arg-output-parent-world-writable" "${base[@]}" --output "$work/ow/o.json"
expect_rc2 "arg-output-parent-symlink" "${base[@]}" --output "$work/olink/o.json"
mkdir -p "$work/oreal/sub"
chmod 700 "$work/oreal/sub"
expect_rc2 "arg-output-ancestor-symlink" "${base[@]}" --output "$work/olink/sub/o.json"
expect_rc2 "arg-output-dotdot" "${base[@]}" --output "$work/oreal/../oreal/o.json"
expect_rc2 "arg-min-procs-one" "${base[@]}" --min-procs 1
expect_rc2 "arg-bad-id-prefix" "${base[@]}" --id-prefix 'A;b'

# --help は 0
r=0
"$bash_bin" "$target" --help >"$out" 2>/dev/null || r=$?
expect_eq "help-exit0" 0 "$r"
expect_has "help-mentions-task" "$out" "TASK-50.1"

# --- 14. 前提欠如（bash 5 未満・非 Linux）は 0 を返さない。非 Linux は uname を差し替えて模擬 ---
mkdir -p "$work/fakebin"
printf '#!%s\necho Darwin\n' "$bash_bin" >"$work/fakebin/uname"
chmod +x "$work/fakebin/uname"
r=0
PATH="$work/fakebin:$PATH" "$bash_bin" "$target" "${base[@]}" >/dev/null 2>"$errf" || r=$?
expect_eq "non-linux-exit3" 3 "$r"
expect_has "non-linux-stderr" "$errf" "unsupported-os"

if [ "$failures" -ne 0 ]; then
  echo "concurrent_50_memory selftest: ${failures} failure(s)" >&2
  exit 1
fi
echo "concurrent_50_memory selftest: all passed"
