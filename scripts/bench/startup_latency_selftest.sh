#!/usr/bin/env bash
# scripts/bench/startup_latency.sh の自己テスト（TASK-46.1・TASK-46.2・CORE-10・REPAIR-12）。
#
# 役割: 実ランタイム・root を使わず、bash のスタブランタイム（create / start / delete /
# kill を模し、固定 sleep と呼び出しログを持つ）で、終了コード・出力 JSON の値・呼び出し
# 順序・タイムアウト・後始末を具体値で機械照合する。own 実装の実測そのものは行わない
# （CLI 提供後に人間が #213 で実施する。startup_latency.sh 冒頭の「現状の制約」参照）。
# 呼び出し元は Makefile の `startup-latency-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。各ケースの失敗は
# failures に数えて最後まで実行を続け、末尾のサマリーで判定する。

set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/startup_latency.sh"
bench_check_script="${script_dir}/../check-bench-regression.sh"
# PATH を絞るケースで bash 自体が解決できなくなるため、絶対パスを先に確定する。
bash_bin="$(command -v bash)"

failures=0
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

last_output=""
last_stdout=""
last_rc=0

print_indented() {
  local line
  while IFS= read -r line; do
    printf '  | %s\n' "$line" >&2
  done <<<"$1"
}

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

pass() {
  echo "PASS: $1"
}

# 各ケースで既定として渡す引数（必須の --target）。--target 自体を検査するケースだけ空にする。
default_args=(--target own)

# 対象スクリプトを実行し、stdout・stdout+stderr・終了コードを保持する（常に 0 を返す）。
run_target() {
  local errfile="$tmp_root/stderr.txt"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" "${default_args[@]}" "$@" 2>"$errfile")" || last_rc=$?
  last_output="${last_stdout}"$'\n'"$(cat "$errfile")"
}

# 期待終了コードを照合する。引数: <名前> <期待 rc> <対象への引数...>
expect_rc() {
  local name="$1" expected="$2"
  shift 2
  run_target "$@"
  if [ "$last_rc" -eq "$expected" ]; then
    pass "$name (exit=$last_rc)"
  else
    fail "$name (expected exit=$expected, actual exit=$last_rc)"
    print_indented "$last_output"
  fi
}

expect_contains() {
  local name="$1" needle="$2"
  if [[ "$last_output" == *"$needle"* ]]; then
    pass "$name"
  else
    fail "$name (output lacks '$needle')"
    print_indented "$last_output"
  fi
}

expect_eq() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    pass "$name"
  else
    fail "$name (expected '$expected', actual '$actual')"
  fi
}

# --- フィクスチャ: スタブランタイムとダミー bundle ---
work="$tmp_root/work"
mkdir -p "$work/bundle"
echo '{}' >"$work/bundle/config.json"
stub_log="$work/stub.log"

stub="$work/stub-runtime"
stub_state="$work/stub-state"
mkdir -p "$stub_state"
# シバンだけ展開し、本体は展開なし（'STUB'）で書く。
printf '#!%s\n' "$bash_bin" >"$stub"
cat >>"$stub" <<'STUB'
# スタブランタイム。OCI Runtime CLI（state / create / start / kill / delete）を模し、
# コンテナの状態を $STUB_STATE 配下のマーカーファイルで持つ。STUB_MODE:
#   ok: create -> created、start 後の state は stopped（`true` 相当で即終了）
#   create-fail / create-fail-gone: create が何も作らず失敗（delete・state は不存在エラー）
#   create-fail-delete-fail: create が途中まで作って失敗し、delete も常に失敗（state は created）
#   create-timeout: create が何も作らずハングする（--timeout で打ち切られる）
#   foreign-perm: 同じ ID の他者のコンテナが既にあり、state は常に権限エラー、create は
#                 ID 重複で失敗する（delete / kill が届くと FOREIGN-TOUCHED を記録する）
#   foreign-late: foreign-perm と同じだが、2 回目以降の state は他者のコンテナを返す
#   foreign-race: create 前の state は NOT_FOUND だが、その直後に他者が同じ ID で作成し、
#                 create は ID 重複で失敗する（以後の state は他者のコンテナを返す）
#   create-fail-state-error: create 未作成で失敗し、以後の state が構造化された権限エラー
#                            （code: PERMISSION_DENIED）を返す
#   create-fail-notfound-text: create 未作成で失敗し、以後の state が自由文の権限エラー
#                              （文言に "not found" を含む）を返す
#   create-fail-mixed-codes: create 未作成で失敗し、以後の state が NOT_FOUND と
#                            PERMISSION_DENIED の両方を返す
#   create-fail-plain: create が何も作らず失敗し、不存在エラーが自由文だけ（runc 相当）
#   create-fail-nf-plus-text / -nf-plus-badjson / -nf-plus-nonstring: create 未作成で失敗し、
#     以後の state が NOT_FOUND に加えて自由文・不正な JSON・code が文字列でない行を返す
#   create-fail-nf-badmsg: create 未作成で失敗し、以後の state が message が文字列でない
#     NOT_FOUND を返す
#   start-fail / start-hang / start-flood: start が失敗 / ハング / 無限の大量出力
#               （start-flood は delete 時に、収集プロセスが記録した start ログの大きさを
#                $STUB_STATE/flood-size へ残す）
#   fsize-probe: create が自身の RLIMIT_FSIZE（ulimit -f）を $STUB_STATE/fsize へ記録し、
#                継承したログへ 2 MiB を書いて、その終了ステータスを $STUB_STATE/flood-rc へ記録する
#   delete-fail: 計測は成功するが delete が常に失敗
#   exec-delayed: start 後の state が created を 2 回返してから stopped
#   exec-never: start 後の state が created のまま
#   exec-late: start 後の state が 0.6 秒かけて created、次に 0.6 秒かけて running を返す
#              （--timeout 1 では観測の完了が期限を過ぎる）
#   running-race: start 後は running。実行中の delete を拒否し、kill 後も 2 回は拒否する
#   never-stops: start 後は running のままで kill も効かない
#   cleanup-hang: start 後は running のままで、delete・kill がいずれも応答しない（ハング）
#   exec-hang-poll: start 後の state が 1.5 秒かけて created を返し、2 回目以降はハングする
#   exec-after-1s: start 後 1 秒間は state が即座に created を返し、その後 running を返す
#   log-holder: create・start・delete がそれぞれ、ログ（stdout / stderr）を開いたまま 3 秒残る
#               子プロセスを起こしてから正常終了する（子の PID を $STUB_STATE/holders に記録）
#   id-in-use: create 前から同じ ID のコンテナが存在する
mode="${STUB_MODE:-ok}"
cmd="$1"
shift
case "$cmd" in
  create) id="${*: -1}" ;;
  *) id="$1" ;;
esac
echo "$cmd $id" >>"$STUB_LOG"
if [ "$mode" = log-holder ] && { [ "$cmd" = create ] || [ "$cmd" = start ] || [ "$cmd" = delete ]; }; then
  # stdout / stderr（run_rt が向けたログファイル）を継承したまま残る子プロセス。
  sleep 3 &
  echo "$!" >>"$STUB_STATE/holders"
fi
m="$STUB_STATE/$id"
# bundle は create が受け取った --bundle を返す（OCI state の bundle は絶対パス）。
state_json() {
  printf '{"ociVersion":"1.0.2","id":"%s","status":"%s","pid":0,"bundle":"%s"}\n' \
    "$id" "$1" "$(cat "$m.bundle" 2>/dev/null || echo /other)"
}
# 不存在エラー。ERR-1 の構造化エラー（code: NOT_FOUND）を出す。create-fail-plain では
# 自由文だけ（構造化エラーを持たないランタイム相当）。
not_exist() {
  if [ "$mode" = create-fail-plain ]; then
    echo "time=\"$(date +%s)\" level=error msg=\"container $id does not exist\"" >&2
  else
    printf '{"code":"NOT_FOUND","message":"container %s does not exist"}\n' "$id" >&2
  fi
  exit 1
}
if [ "$mode" = foreign-perm ] || [ "$mode" = foreign-late ] || [ "$mode" = foreign-race ]; then
  case "$cmd" in
    state)
      if [ "$mode" != foreign-perm ] && [ -e "$m.probed" ]; then state_json created; exit 0; fi
      touch "$m.probed"
      if [ "$mode" = foreign-race ]; then
        printf '{"code":"NOT_FOUND","message":"container %s does not exist"}\n' "$id" >&2
      else
        echo "stub: open state.json: permission denied" >&2
      fi
      exit 1
      ;;
    create)
      sleep 0.05
      # 他者のコンテナと同じ bundle を返すように記録する（bundle 一致が所有の証明にならない確認）。
      [ "$1" = --bundle ] && printf '%s' "$2" >"$m.bundle"
      echo "stub: container with id $id already exists" >&2
      exit 1
      ;;
    delete | kill) echo "FOREIGN-TOUCHED $id" >>"$STUB_LOG"; exit 0 ;;
  esac
fi
case "$cmd" in
  create)
    sleep 0.05
    touch "$m.attempted"
    [ "$mode" = create-timeout ] && exec sleep 30
    # 出力先の作成競合を再現するフック（--output の検証後にファイル・FIFO を作る）。
    [ -n "${STUB_CREATE_HOOK:-}" ] && [ ! -e "$STUB_CREATE_HOOK" ] && echo preexisting >"$STUB_CREATE_HOOK"
    [ -n "${STUB_CREATE_FIFO:-}" ] && [ ! -e "$STUB_CREATE_FIFO" ] && mkfifo "$STUB_CREATE_FIFO"
    [ "$1" = --bundle ] && printf '%s' "$2" >"$m.bundle"
    case "$mode" in
      create-fail | create-fail-gone | create-fail-state-error | create-fail-notfound-text | create-fail-mixed-codes | create-fail-plain | create-fail-nf-*)
        echo "stub: create failed" >&2; exit 1 ;;
      create-fail-delete-fail) touch "$m.created"; echo "stub: create failed" >&2; exit 1 ;;
    esac
    touch "$m.created"
    if [ "$mode" = fsize-probe ]; then
      ulimit -f >"$STUB_STATE/fsize"
      rc=0
      head -c 2097152 /dev/zero || rc=$?
      echo "$rc" >"$STUB_STATE/flood-rc"
    fi
    ;;
  start)
    [ -e "$m.created" ] || not_exist
    [ "$mode" = start-fail ] && { echo "stub: start failed" >&2; exit 1; }
    [ "$mode" = start-hang ] && exec sleep 30
    [ "$mode" = start-flood ] && exec yes
    sleep 0.10
    echo "${EPOCHREALTIME/./}" >"$m.started"
    ;;
  state)
    if [ "$mode" = id-in-use ]; then state_json created; exit 0; fi
    if [ -e "$m.attempted" ] && [ ! -e "$m.created" ]; then
      [ "$mode" = create-fail-state-error ] && { echo '{"code":"PERMISSION_DENIED","message":"open state.json: permission denied"}' >&2; exit 1; }
      case "$mode" in
        create-fail-nf-plus-text) printf '{"code":"NOT_FOUND","message":"x"}\nstub: permission denied\n' >&2; exit 1 ;;
        create-fail-nf-plus-badjson) printf '{"code":"NOT_FOUND","message":"x"}\n{"code":"PERMISSION_DENIED",\n' >&2; exit 1 ;;
        create-fail-nf-plus-nonstring) printf '{"code":"NOT_FOUND","message":"x"}\n{"code":13,"message":"y"}\n' >&2; exit 1 ;;
        create-fail-nf-badmsg) printf '{"code":"NOT_FOUND","message":5}\n' >&2; exit 1 ;;
      esac
      if [ "$mode" = create-fail-mixed-codes ]; then
        printf '{"code":"NOT_FOUND","message":"x"}\n{"code":"PERMISSION_DENIED","message":"y"}\n' >&2
        exit 1
      fi
      [ "$mode" = create-fail-notfound-text ] && { echo "stub: permission denied (state file not found in cache)" >&2; exit 1; }
    fi
    [ -e "$m.created" ] || not_exist
    if [ ! -e "$m.started" ]; then state_json created; exit 0; fi
    case "$mode" in
      exec-delayed)
        n=$(($(cat "$m.polls" 2>/dev/null || echo 0) + 1))
        echo "$n" >"$m.polls"
        if [ "$n" -le 2 ]; then state_json created; else state_json stopped; fi
        ;;
      exec-never) state_json created ;;
      exec-after-1s)
        if [ $((${EPOCHREALTIME/./} - $(cat "$m.started"))) -ge 1000000 ]; then state_json running; else state_json created; fi
        ;;
      exec-hang-poll)
        if [ -e "$m.polled" ]; then exec sleep 30; fi
        touch "$m.polled"
        sleep 1.5
        state_json created
        ;;
      exec-late)
        sleep 0.6
        if [ -e "$m.polled" ]; then state_json running; else touch "$m.polled"; state_json created; fi
        ;;
      running-race | never-stops | cleanup-hang)
        if [ -e "$m.killed" ] && [ "$mode" = running-race ]; then state_json stopped; else state_json running; fi
        ;;
      *) state_json stopped ;;
    esac
    ;;
  kill)
    [ -e "$m.created" ] || not_exist
    [ "$mode" = cleanup-hang ] && exec sleep 30
    touch "$m.killed"
    ;;
  delete)
    [ -e "$m.created" ] || not_exist
    case "$mode" in
      cleanup-hang) exec sleep 30 ;;
      delete-fail | create-fail-delete-fail) echo "stub: delete failed" >&2; exit 1 ;;
      never-stops) [ -e "$m.started" ] && { echo "stub: cannot delete running container" >&2; exit 1; } ;;
      running-race)
        if [ -e "$m.started" ]; then
          [ -e "$m.killed" ] || { echo "stub: cannot delete running container" >&2; exit 1; }
          n=$(($(cat "$m.delete-after-kill" 2>/dev/null || echo 0) + 1))
          echo "$n" >"$m.delete-after-kill"
          [ "$n" -le 2 ] && { echo "stub: container is still running" >&2; exit 1; }
        fi
        ;;
    esac
    if [ "$mode" = start-flood ]; then
      cat "$TMPDIR"/*/start-*.log 2>/dev/null | wc -c >"$STUB_STATE/flood-size"
    fi
    rm -f -- "$m".*
    ;;
esac
exit 0
STUB
chmod 755 "$stub"
export STUB_LOG="$stub_log"
export STUB_STATE="$stub_state"

reset_log() {
  : >"$stub_log"
  rm -f -- "$stub_state"/*
}

# --- 1. 正常系 ---
reset_log
export STUB_MODE=ok
expect_rc "normal-run" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 3 --warmup 1
normal_json="$last_stdout"
expect_eq "normal-schema_version" "1" "$(jq -r '.schema_version' <<<"$normal_json")"
expect_eq "normal-benchmark" "startup_latency" "$(jq -r '.benchmark' <<<"$normal_json")"
expect_eq "normal-target" "own" "$(jq -r '.target' <<<"$normal_json")"
expect_eq "normal-samples-count" "3" "$(jq -r '.samples_us | length' <<<"$normal_json")"
expect_eq "normal-total-consistent" "true" "$(jq -r 'all(.samples_us[]; .total_us >= .create_us + .start_us + .observe_us and .total_us >= 150000)' <<<"$normal_json")"
# ok モードの state は start 直後から stopped を返すため、実行開始の観測は各回 1 回の照会で済む。
expect_eq "normal-state-polls" "1 1 1" "$(jq -r '[.samples_us[].state_polls] | map(tostring) | join(" ")' <<<"$normal_json")"
expect_eq "normal-p50-unit" "ms" "$(jq -r '.metrics.startup_latency_p50_ms.unit' <<<"$normal_json")"
expect_eq "normal-no-path-leak" "false" "$(jq -r --arg p "$work" 'tostring | contains($p)' <<<"$normal_json")"

# --- 2. 中央値・min・max を awk で独立再計算（奇数・偶数） ---
verify_stats() {
  local name="$1" json="$2" exp
  exp="$(jq -r '.samples_us[].total_us' <<<"$json" | sort -n | awk '
    { a[NR] = $1 }
    END {
      if (NR % 2) m = a[(NR + 1) / 2]; else m = (a[NR / 2] + a[NR / 2 + 1]) / 2
      printf "%.6f %.6f %.6f\n", m / 1000, a[1] / 1000, a[NR] / 1000
    }')"
  local got
  got="$(jq -r '[.metrics.startup_latency_p50_ms.value, .metrics.startup_latency_min_ms.value, .metrics.startup_latency_max_ms.value] | map(. * 1000000 | round / 1000000) | map(tostring) | join(" ")' <<<"$json")"
  # 比較は数値として行う（表記ゆれを避ける）。
  local ok
  ok="$(awk -v e="$exp" -v g="$got" 'BEGIN {
    split(e, ea, " "); split(g, ga, " ")
    ok = 1
    for (i = 1; i <= 3; i++) { d = ea[i] - ga[i]; if (d < 0) d = -d; if (d > 0.0001) ok = 0 }
    print ok }')"
  expect_eq "$name" "1" "$ok"
}
verify_stats "median-odd(3)" "$normal_json"
reset_log
expect_rc "even-run" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 4 --warmup 0
verify_stats "median-even(4)" "$last_stdout"

# --- 3. 呼び出し順: warmup 込み 4 回・ID 一意・state（ID 未使用確認）-> create -> start ->
#        state（実行開始の観測。CORE-10）-> delete ---
reset_log
expect_rc "call-order-run" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 3 --warmup 1
mapfile -t log_lines <"$stub_log"
expect_eq "call-order-line-count" "20" "${#log_lines[@]}"
order_ok=1
declare -A seen_ids=()
for ((i = 0; i + 4 < ${#log_lines[@]}; i += 5)); do
  cmds=""
  first_id=""
  for ((j = 0; j < 5; j++)); do
    read -r c cid <<<"${log_lines[$((i + j))]}"
    cmds="$cmds $c"
    [ -z "$first_id" ] && first_id="$cid"
    [ "$cid" = "$first_id" ] || order_ok=0
  done
  [ "$cmds" = " state create start state delete" ] || order_ok=0
  seen_ids["$first_id"]=1
done
expect_eq "call-order-sequence" "1" "$order_ok"
expect_eq "call-order-unique-ids" "4" "${#seen_ids[@]}"

# --- 4. --output ---
out_file="$work/result.json"
reset_log
expect_rc "output-write" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 2 --warmup 0 --output "$out_file"
expect_eq "output-file-equals-stdout" "$last_stdout" "$(cat "$out_file")"
expect_eq "output-write-no-staging" "" "$(find "$work" -maxdepth 1 -name '.startup_latency.*' -print)"
expect_rc "output-existing-file" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$out_file"
ln -s "$work/nonexistent-target" "$work/link.json"
expect_rc "output-existing-symlink" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/link.json"
expect_rc "output-parent-missing" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/nodir/x.json"
# 検証後・書き込み前に作られたファイルで作成に失敗した場合（Codex P2）: exit 2 かつ stdout は空。
# 計測中（create 呼び出し時）に出力先を作って競合を再現する。
race_out="$work/race.json"
reset_log
STUB_CREATE_HOOK="$race_out" expect_rc "output-create-race" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$race_out"
expect_eq "output-create-race-stdout-empty" "" "$last_stdout"
expect_eq "output-create-race-file-untouched" "preexisting" "$(cat "$race_out")"
expect_eq "output-create-race-no-staging" "" "$(find "$work" -maxdepth 1 -name '.startup_latency.*' -print)"
# 検証後に出力先が FIFO へ差し替えられた場合（Codex P0）: 開かずに exit 2 で終わり、
# 無期限に待機しない。回帰時に自己テスト自体が止まらないよう外側にも timeout を掛ける。
race_fifo="$work/race.fifo"
reset_log
rc=0
started="$SECONDS"
STUB_CREATE_FIFO="$race_fifo" timeout 60 "$bash_bin" "$target_script" --target own --runtime "$stub" --bundle "$work/bundle" \
  --iterations 1 --warmup 0 --timeout 2 --output "$race_fifo" >"$work/fifo.stdout" 2>/dev/null || rc=$?
elapsed=$((SECONDS - started))
expect_eq "output-fifo-race-exit" "2" "$rc"
if [ "$elapsed" -lt 30 ]; then pass "output-fifo-race-bounded (${elapsed}s < 30s)"; else fail "output-fifo-race-bounded (${elapsed}s)"; fi
expect_eq "output-fifo-race-stdout-empty" "" "$(cat "$work/fifo.stdout")"
if [ -p "$race_fifo" ]; then pass "output-fifo-race-still-fifo"; else fail "output-fifo-race-still-fifo"; fi
expect_eq "output-fifo-race-no-staging" "" "$(find "$work" -maxdepth 1 -name '.startup_latency.*' -print)"
# 書き込みが途中で失敗した場合（Codex P2）: 不完全な内容を出力先に残さず exit 2、一時ファイルも
# 残さない。途中まで書いて失敗する dd を PATH の先頭に置いて再現する。
mkdir -p "$work/faildd" "$work/partial"
cat >"$work/faildd/dd" <<'FAILDD'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in of=*) printf '{"partial' >"${a#of=}" ;; esac
done
exit 1
FAILDD
chmod 755 "$work/faildd/dd"
reset_log
rc=0
PATH="$work/faildd:$PATH" "$bash_bin" "$target_script" --target own --runtime "$stub" --bundle "$work/bundle" \
  --iterations 1 --warmup 0 --output "$work/partial/out.json" >"$work/partial.stdout" 2>/dev/null || rc=$?
expect_eq "output-partial-write-exit" "2" "$rc"
expect_eq "output-partial-write-no-file" "" "$(find "$work/partial" -mindepth 1 -print)"
expect_eq "output-partial-write-stdout-empty" "" "$(cat "$work/partial.stdout")"
# 一時ファイルの作成が名前の衝突等で失敗した場合（Codex P1）: 既存のファイルを消さずに exit 2。
# mktemp が既存の名前を返す（作成していない）状況を、既存ファイルのパスを返して失敗する
# mktemp で再現し、そのファイルが残ることを確かめる。
mkdir -p "$work/failmktemp" "$work/collide"
echo other >"$work/collide/.startup_latency.taken"
cat >"$work/failmktemp/mktemp" <<FAILMKTEMP
#!/usr/bin/env bash
case "\$*" in *startup_latency*) echo "$work/collide/.startup_latency.taken"; exit 1 ;; esac
exec "$(command -v mktemp)" "\$@"
FAILMKTEMP
chmod 755 "$work/failmktemp/mktemp"
reset_log
rc=0
PATH="$work/failmktemp:$PATH" "$bash_bin" "$target_script" --target own --runtime "$stub" --bundle "$work/bundle" \
  --iterations 1 --warmup 0 --output "$work/collide/out.json" >/dev/null 2>&1 || rc=$?
expect_eq "output-staging-collision-exit" "2" "$rc"
expect_eq "output-staging-collision-kept" "other" "$(cat "$work/collide/.startup_latency.taken")"
expect_eq "output-staging-collision-no-output" "" "$(find "$work/collide" -name out.json -print)"
# 出力先の祖先ディレクトリを他のユーザーが差し替えられる場合は拒否する（Codex P0 / Bugbot:
# 一時ファイルのパス差し替えで別ファイルの権限・内容を変更させない）。計測前に exit 2。
mkdir -p "$work/gw" "$work/ow" "$work/sticky" "$work/ow2/target"
chmod 0775 "$work/gw"
chmod 0777 "$work/ow"
chmod 1777 "$work/sticky"
chmod 0777 "$work/ow2"
ln -s "$work/ow2/target" "$work/linkdir"
for case_dir in gw ow linkdir; do
  reset_log
  expect_rc "output-unsafe-dir-$case_dir" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/$case_dir/out.json"
  expect_contains "output-unsafe-dir-$case_dir-error" "invalid-output"
  expect_eq "output-unsafe-dir-$case_dir-no-runtime-call" "0" "$(wc -l <"$stub_log" | tr -d ' ')"
done
# sticky ビット付きの共有ディレクトリ（/tmp 相当）は他人が自分のエントリを差し替えられないため許可する。
reset_log
expect_rc "output-sticky-dir" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/sticky/out.json"
expect_eq "output-sticky-dir-written" "$last_stdout" "$(cat "$work/sticky/out.json")"
# 先頭が "//" のパスでも祖先の検査が終わる（Bugbot: GNU dirname の不動点 "//" で止まる）。
# 回帰時に自己テスト自体が止まらないよう外側に timeout を掛ける。
reset_log
rc=0
timeout 60 "$bash_bin" "$target_script" --target own --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 \
  --output "/$work/sticky/out2.json" >/dev/null 2>&1 || rc=$?
expect_eq "output-double-slash-exit" "0" "$rc"
expect_eq "output-double-slash-written" "own" "$(jq -r '.target' "$work/sticky/out2.json" 2>/dev/null)"
# sticky な共有ディレクトリにある symlink（他人が所有すれば検査後に差し替えられる）を経由する
# 出力先は、参照先が安全でも拒否する（Codex P0: パス上の symlink を拒否する）。
mkdir -p "$work/safe-target"
ln -s "$work/safe-target" "$work/sticky/link"
reset_log
expect_rc "output-symlink-in-sticky" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --output "$work/sticky/link/out.json"
expect_contains "output-symlink-in-sticky-error" "invalid-output"
expect_eq "output-symlink-in-sticky-no-runtime-call" "0" "$(wc -l <"$stub_log" | tr -d ' ')"
# 出力ファイルのパーミッションは umask に従う（umask 022 で 644）。
expect_eq "output-mode-follows-umask" "644" "$(stat -c '%a' "$out_file" 2>/dev/null || stat -f '%Lp' "$out_file")"

# --- 5. 入力エラー（exit 2） ---
expect_rc "input-runtime-missing" 2 --bundle "$work/bundle"
expect_rc "input-runtime-relative" 2 --runtime stub-runtime --bundle "$work/bundle"
cp "$stub" "$work/not-exec"
chmod 644 "$work/not-exec"
expect_rc "input-runtime-not-executable" 2 --runtime "$work/not-exec" --bundle "$work/bundle"
expect_rc "input-bundle-missing" 2 --runtime "$stub"
expect_rc "input-bundle-not-found" 2 --runtime "$stub" --bundle "$work/nodir"
mkdir -p "$work/nocfg"
expect_rc "input-config-missing" 2 --runtime "$stub" --bundle "$work/nocfg"
mkdir -p "$work/cfglink"
ln -s "$work/bundle/config.json" "$work/cfglink/config.json"
expect_rc "input-config-symlink" 2 --runtime "$stub" --bundle "$work/cfglink"
ln -s "$work/bundle" "$work/bundlelink"
expect_rc "input-bundle-symlink" 2 --runtime "$stub" --bundle "$work/bundlelink"
for v in 0 1001 abc 01 -1; do
  expect_rc "input-iterations-$v" 2 --runtime "$stub" --bundle "$work/bundle" --iterations "$v"
done
for v in 0 61; do
  expect_rc "input-timeout-$v" 2 --runtime "$stub" --bundle "$work/bundle" --timeout "$v"
done
expect_rc "input-warmup-101" 2 --runtime "$stub" --bundle "$work/bundle" --warmup 101
expect_rc "input-label-invalid" 2 --runtime "$stub" --bundle "$work/bundle" --label 'a b;c'
expect_rc "input-unknown-option" 2 --runtime "$stub" --bundle "$work/bundle" --bogus
expect_rc "input-duplicate-option" 2 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --iterations 2
expect_rc "input-value-missing" 2 --runtime "$stub" --bundle
# --target は必須で、出力の target にそのまま記録する（Codex P2: 任意のランタイムを own と
# 記録しない）。
default_args=()
expect_rc "input-target-missing" 2 --runtime "$stub" --bundle "$work/bundle"
expect_contains "input-target-missing-error" "missing-target"
expect_rc "input-target-invalid" 2 --runtime "$stub" --bundle "$work/bundle" --target 'run c'
reset_log
expect_rc "target-recorded" 0 --runtime "$stub" --bundle "$work/bundle" --target runc --iterations 1 --warmup 0
expect_eq "target-recorded-value" "runc" "$(jq -r '.target' <<<"$last_stdout")"
# --label を省略すると label は target と同じ値になる（Codex P2: target と label を食い違わせない）。
expect_eq "target-default-label" "runc" "$(jq -r '.label' <<<"$last_stdout")"
reset_log
expect_rc "target-explicit-label" 0 --runtime "$stub" --bundle "$work/bundle" --target runc --label baseline-1 --iterations 1 --warmup 0
expect_eq "target-explicit-label-value" "runc baseline-1" "$(jq -r '"\(.target) \(.label)"' <<<"$last_stdout")"
default_args=(--target own)
expect_rc "help" 0 --help

# --- 6. create / start 失敗 ---
# create がランタイム自身のエラーで終了し、state が構造化された NOT_FOUND を返せば未作成と
# 確定し、delete / kill を送らずに exit 1。
reset_log
STUB_MODE=create-fail expect_rc "create-fail" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "create-fail-log-tail" "stub: create failed"
expect_eq "create-fail-sequence" "state create state" "$(cut -d' ' -f1 "$stub_log" | tr '\n' ' ' | sed 's/ $//')"
# create が途中まで作って失敗した場合: 今回の作成物か他者の作成物かを区別できないため
# delete / kill を送らず、残存 ID を報告して exit 4（Codex P0: create 未成功の ID に破壊的
# 操作を送らない）。
reset_log
STUB_MODE=create-fail-delete-fail expect_rc "create-fail-partial" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
expect_contains "create-fail-leftover-id" "containers left behind: fandhe-startup-"
expect_contains "create-fail-partial-warning" "inspect it manually"
expect_eq "create-fail-partial-sequence" "state create state" "$(cut -d' ' -f1 "$stub_log" | tr '\n' ' ' | sed 's/ $//')"
# create 失敗でコンテナ未作成なら、state が明確な不存在応答（NOT_FOUND）を返すため後始末
# 失敗にせず、契約どおり exit 1（Codex P1 / Bugbot 指摘）。
reset_log
STUB_MODE=create-fail-gone expect_rc "create-fail-gone" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "create-fail-gone-create-error" "runtime-create-failed"
if [[ "$last_output" == *"containers left behind"* ]]; then fail "create-fail-gone-no-false-leftover"; else pass "create-fail-gone-no-false-leftover"; fi
expect_eq "create-fail-gone-state-probed" "2" "$(grep -c '^state ' "$stub_log")"
# state が不存在以外の構造化エラー（権限エラー等）を返した場合は残存の可能性ありとして exit 4。
reset_log
STUB_MODE=create-fail-state-error expect_rc "create-fail-state-error" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
expect_contains "create-fail-state-error-leftover" "containers left behind: fandhe-startup-"
# 文言に "not found" を含む自由文の権限エラーは明確な不存在応答ではないため exit 4（Codex P1:
# 文言だけで消滅を確定しない）。
reset_log
STUB_MODE=create-fail-notfound-text expect_rc "create-fail-notfound-text" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
expect_contains "create-fail-notfound-text-leftover" "containers left behind: fandhe-startup-"
expect_contains "create-fail-notfound-text-warning" "its absence could not be confirmed"
# 所有を確かめられない ID には delete / kill を送らない（Codex P0）。
if grep -qE '^(delete|kill) ' "$stub_log"; then fail "create-fail-notfound-text-untouched"; else pass "create-fail-notfound-text-untouched"; fi
# create がタイムアウトした場合は途中状態が残り得るため、state が不存在を示しても
# 未作成とは確定せず exit 4（所有も確かめられないので delete / kill は送らない）。
reset_log
STUB_MODE=create-timeout expect_rc "create-timeout" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
expect_contains "create-timeout-leftover" "containers left behind: fandhe-startup-"
if grep -qE '^(delete|kill) ' "$stub_log"; then fail "create-timeout-untouched"; else pass "create-timeout-untouched"; fi
# NOT_FOUND と別のエラーが混在する応答は明確な不存在応答ではないため exit 4。
reset_log
STUB_MODE=create-fail-mixed-codes expect_rc "create-fail-mixed-codes" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
if grep -qE '^(delete|kill) ' "$stub_log"; then fail "create-fail-mixed-codes-untouched"; else pass "create-fail-mixed-codes-untouched"; fi
# NOT_FOUND に自由文・不正な JSON・code が文字列でない行が混ざる応答や、message が文字列で
# ない NOT_FOUND も判定不能として exit 4（Codex P1: 解析できない行を捨てて不存在と判定しない）。
for m in nf-plus-text nf-plus-badjson nf-plus-nonstring nf-badmsg; do
  reset_log
  STUB_MODE="create-fail-$m" expect_rc "create-fail-$m" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
  if grep -qE '^(delete|kill) ' "$stub_log"; then fail "create-fail-$m-untouched"; else pass "create-fail-$m-untouched"; fi
done
# 構造化エラーを持たないランタイム（runc 相当）では create 失敗時に未作成を確定できない
# ため、操作を送らずに exit 4（スクリプト冒頭「現状の制約」に記載の挙動）。
reset_log
STUB_MODE=create-fail-plain expect_rc "create-fail-plain" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "create-fail-plain-sequence" "state create state" "$(cut -d' ' -f1 "$stub_log" | tr '\n' ' ' | sed 's/ $//')"
# 同じ ID の他者のコンテナがあり state が権限エラーを返す場合（Codex P0）: create 前の不存在を
# 確認できないため、create が ID 重複で失敗した後もその ID に delete / kill を送らず exit 4。
reset_log
STUB_MODE=foreign-perm expect_rc "foreign-perm" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "foreign-perm-sequence" "state create state" "$(cut -d' ' -f1 "$stub_log" | tr '\n' ' ' | sed 's/ $//')"
if grep -q '^FOREIGN-TOUCHED ' "$stub_log"; then fail "foreign-perm-untouched"; else pass "foreign-perm-untouched"; fi
# 後続の state が他者のコンテナ（同じ ID・同じ bundle）を返しても操作を送らない（Codex P0:
# bundle 一致は所有の証明にならない）。
reset_log
STUB_MODE=foreign-late expect_rc "foreign-late" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
if grep -q '^FOREIGN-TOUCHED ' "$stub_log"; then fail "foreign-late-untouched"; else pass "foreign-late-untouched"; fi
# create 前の state が NOT_FOUND でも、その直後に他者が同じ ID で作成して create が ID 重複で
# 失敗した場合は他者のコンテナに操作を送らない（Codex P0: 作成前の不存在は所有の証明に
# ならない）。
reset_log
STUB_MODE=foreign-race expect_rc "foreign-race" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "foreign-race-sequence" "state create state" "$(cut -d' ' -f1 "$stub_log" | tr '\n' ' ' | sed 's/ $//')"
if grep -q '^FOREIGN-TOUCHED ' "$stub_log"; then fail "foreign-race-untouched"; else pass "foreign-race-untouched"; fi
# create 前から同じ ID が存在する場合は触らずに exit 1（create・delete・kill を呼ばない）。
reset_log
STUB_MODE=id-in-use expect_rc "id-in-use" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "id-in-use-error" "container-id-in-use"
expect_eq "id-in-use-untouched" "state" "$(cut -d' ' -f1 "$stub_log" | sort -u | tr '\n' ' ' | sed 's/ $//')"
reset_log
STUB_MODE=start-fail expect_rc "start-fail" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
if grep -q '^delete ' "$stub_log"; then pass "start-fail-delete-called"; else fail "start-fail-delete-called"; fi

# --- 7. start ハング（REPAIR-5）: timeout で打ち切り、delete が呼ばれる ---
reset_log
started="$SECONDS"
STUB_MODE=start-hang expect_rc "start-hang" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "start-hang-elapsed (${elapsed}s < 15s)"; else fail "start-hang-elapsed (${elapsed}s)"; fi
if grep -q '^delete ' "$stub_log"; then pass "start-hang-delete-called"; else fail "start-hang-delete-called"; fi

# --- 7b. ログ出力の無制限書き込み: 書き手は止めず、収集側が先頭 LOG_MAX_KIB（1024 KiB）だけを記録する
#         （ランタイムに rlimit を掛けない）。書き手は --timeout で打ち切られ計測失敗（exit 1） ---
reset_log
flood_tmp="$work/flood-tmp"
mkdir -p "$flood_tmp"
started="$SECONDS"
TMPDIR="$flood_tmp" STUB_MODE=start-flood expect_rc "start-flood" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "start-flood-elapsed (${elapsed}s < 15s)"; else fail "start-flood-elapsed (${elapsed}s)"; fi
if grep -q '^delete ' "$stub_log"; then pass "start-flood-delete-called"; else fail "start-flood-delete-called"; fi
expect_contains "start-flood-truncated-warning" "runtime-log-truncated: start-1.log limit_kib=1024"
expect_eq "start-flood-log-size" "1048576" "$(tr -d ' \n' <"$stub_state/flood-size" 2>/dev/null)"

# --- 7c. ランタイムとその子孫は RLIMIT_FSIZE を継承しない（ulimit -f を掛けない） ---
reset_log
STUB_MODE=fsize-probe expect_rc "fsize-probe" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "fsize-not-inherited" "$(ulimit -f)" "$(cat "$stub_state/fsize" 2>/dev/null)"
expect_eq "fsize-flood-rc" "0" "$(cat "$stub_state/flood-rc" 2>/dev/null)"

# --- 7d. 後始末中の 2 回目のシグナルで後始末が中断されない（終了コード 4 を保つ） ---
for sig in INT TERM HUP; do
  reset_log
  started="$SECONDS"
  STARTUP_LATENCY_TEST_SIGNAL_IN_CLEANUP="$sig" STUB_MODE=never-stops expect_rc "signal-in-cleanup-$sig" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
  elapsed=$((SECONDS - started))
  if [ "$elapsed" -lt 15 ]; then pass "signal-in-cleanup-$sig-bounded (${elapsed}s < 15s)"; else fail "signal-in-cleanup-$sig-bounded (${elapsed}s)"; fi
  expect_contains "signal-in-cleanup-$sig-leftover-id" "containers left behind: fandhe-startup-"
done

# --- 7e. 計測中の HUP でも後始末が走り、最初のシグナルの終了コード 129 を返す ---
# 対象を背景で起動し、start 後の state ポーリング区間（exec-after-1s は約 1 秒続く）で HUP を送る。
# 引数: <名前> <後始末中に送る 2 回目のシグナル（空なら送らない）>
run_hup_case() {
  local name="$1" second="$2" i=0 bg_pid rc=0 t0 ms
  reset_log
  t0="${EPOCHREALTIME/./}"
  STARTUP_LATENCY_TEST_SIGNAL_IN_CLEANUP="$second" STUB_MODE=exec-after-1s \
    "$bash_bin" "$target_script" "${default_args[@]}" --runtime "$stub" --bundle "$work/bundle" \
    --iterations 1 --warmup 0 --timeout 3 >"$tmp_root/bg.out" 2>"$tmp_root/bg.err" </dev/null &
  bg_pid=$!
  while ! grep -q '^start ' "$stub_log" && [ "$i" -lt 100 ]; do
    sleep 0.05
    i=$((i + 1))
  done
  if ! grep -q '^start ' "$stub_log"; then
    fail "$name (start was not observed)"
  fi
  kill -HUP "$bg_pid" 2>/dev/null || true
  wait "$bg_pid" || rc=$?
  ms=$(((${EPOCHREALTIME/./} - t0) / 1000))
  last_output="$(cat "$tmp_root/bg.out")"$'\n'"$(cat "$tmp_root/bg.err")"
  expect_eq "$name-rc" "129" "$rc"
  expect_eq "$name-stdout-empty" "" "$(cat "$tmp_root/bg.out")"
  expect_contains "$name-interrupted" "interrupted"
  if grep -q '^delete ' "$stub_log"; then pass "$name-delete-called"; else fail "$name-delete-called"; fi
  expect_eq "$name-no-container-left" "" "$(ls -A "$stub_state")"
  if [ "$ms" -lt 6000 ]; then pass "$name-bounded (${ms}ms < 6000ms)"; else fail "$name-bounded (${ms}ms)"; fi
}
run_hup_case "hup-cleanup" ""
# 残存なしで後始末中に INT が重なっても、最初のシグナル（HUP=129）の終了コードを返す。
run_hup_case "hup-then-int-in-cleanup" "INT"

# --- 8. delete 失敗: 計測成功でも exit 4、残存 ID を出力 ---
reset_log
STUB_MODE=delete-fail expect_rc "delete-fail" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
expect_contains "delete-fail-leftover-id" "fandhe-startup-"

# --- 8b. 実行中コンテナの後始末（Bugbot 指摘）: delete 拒否 -> kill -> 終了待ちの delete 再試行で
#         成功し exit 0。kill 後も 2 回拒否されるため、delete は計 4 回呼ばれる ---
reset_log
STUB_MODE=running-race expect_rc "running-race" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "running-race-sequence" "state create start state delete kill delete delete delete" \
  "$(cut -d' ' -f1 "$stub_log" | tr '\n' ' ' | sed 's/ $//')"
# kill 後も停止しない場合は --timeout 秒で待機を打ち切り exit 4（REPAIR-5）。
reset_log
started="$SECONDS"
STUB_MODE=never-stops expect_rc "never-stops" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "never-stops-bounded (${elapsed}s < 15s)"; else fail "never-stops-bounded (${elapsed}s)"; fi
expect_contains "never-stops-leftover-id" "containers left behind: fandhe-startup-"

# 後始末の delete・kill がいずれもハングしても、後始末全体を 1 つの期限（--timeout 2 秒）内に
# 収めて exit 4（Codex P1。REPAIR-5）。期限が呼び出しごとに延びる実装（delete・kill が各
# --timeout 秒＋KILL 猶予を使い、その後さらに再試行）では 6 秒を超える。
reset_log
cleanup_t0="${EPOCHREALTIME/./}"
STUB_MODE=cleanup-hang expect_rc "cleanup-hang" 4 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 2
cleanup_ms=$(((${EPOCHREALTIME/./} - cleanup_t0) / 1000))
if [ "$cleanup_ms" -lt 4000 ]; then pass "cleanup-hang-bounded (${cleanup_ms}ms < 4000ms)"; else fail "cleanup-hang-bounded (${cleanup_ms}ms)"; fi
expect_contains "cleanup-hang-leftover-id" "containers left behind: fandhe-startup-"

# --- 8c. プロセス実行開始の観測（CORE-10）: state が running / stopped を返すまで照会する ---
reset_log
STUB_MODE=exec-delayed expect_rc "exec-delayed" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "exec-delayed-state-polls" "3" "$(jq -r '.samples_us[0].state_polls' <<<"$last_stdout")"
expect_eq "exec-delayed-total" "true" "$(jq -r '.samples_us[0] | .total_us >= .create_us + .start_us + .observe_us' <<<"$last_stdout")"
reset_log
started="$SECONDS"
STUB_MODE=exec-never expect_rc "exec-never" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "exec-never-bounded (${elapsed}s < 15s)"; else fail "exec-never-bounded (${elapsed}s)"; fi
expect_contains "exec-never-error" "runtime-exec-not-observed"
if grep -q '^delete ' "$stub_log"; then pass "exec-never-delete-called"; else fail "exec-never-delete-called"; fi
# running を観測した照会の完了が期限（--timeout 1 秒）を過ぎた場合は成功結果に混ぜず exit 1
# （Codex P1）。照会は 2 回（0.6 秒 + 0.6 秒）。
reset_log
STUB_MODE=exec-late expect_rc "exec-late" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 1
expect_contains "exec-late-error" "runtime-exec-not-observed"
expect_eq "exec-late-stdout-empty" "" "$last_stdout"
expect_eq "exec-late-state-count" "3" "$(grep -c '^state ' "$stub_log")"
# 実行開始まで 1 秒かかるランタイムでも、照会回数ではなく期限（--timeout 3 秒）で打ち切る
# ため成功し、照会は間隔（10ms）を空けるので回数が 1 秒 / 10ms 程度に収まる（Codex P1）。
reset_log
STUB_MODE=exec-after-1s expect_rc "exec-after-1s" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 3
polls="$(jq -r '.samples_us[0].state_polls' <<<"$last_stdout")"
if [ "$polls" -ge 2 ] && [ "$polls" -le 110 ]; then pass "exec-after-1s-poll-count ($polls in 2..110)"; else fail "exec-after-1s-poll-count ($polls)"; fi
# スタブは start の終了直前に時刻を記録し、その 1 秒後から running を返す。この時刻は
# create 復帰（t1）より後なので、t1 からの経過（start_us + observe_us）は必ず 1 秒以上になる
# （observe_us だけだと start 復帰〔ts〕との時刻差で 1 秒をわずかに下回り得る）。
expect_eq "exec-after-1s-observe" "true" "$(jq -r '.samples_us[0] | .start_us + .observe_us >= 1000000' <<<"$last_stdout")"
# 2 回目の照会がハングしても、観測期限（--timeout 3 秒）までの残り時間しか待たない（Codex P1。
# REPAIR-5）。照会ごとに --timeout 秒を渡す実装では 1.5 + 3 秒を超える。
reset_log
observe_t0="${EPOCHREALTIME/./}"
STUB_MODE=exec-hang-poll expect_rc "exec-hang-poll" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 3
observe_ms=$(((${EPOCHREALTIME/./} - observe_t0) / 1000))
if [ "$observe_ms" -lt 4000 ]; then pass "exec-hang-poll-bounded (${observe_ms}ms < 4000ms)"; else fail "exec-hang-poll-bounded (${observe_ms}ms)"; fi
expect_contains "exec-hang-poll-error" "runtime-exec-not-observed"

# ランタイムの子プロセスがログファイルを開いたまま残っても、スクリプトはそれを待たない
# （Codex P0 の確認）。ランタイムの stdout / stderr はパイプでなくファイルへ向け、stdin は
# /dev/null のため、子の終了や EOF を待つ箇所がない。子が残る 3 秒より十分短く終わること。
reset_log
holder_t0="${EPOCHREALTIME/./}"
STUB_MODE=log-holder expect_rc "log-holder" 0 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
holder_ms=$(((${EPOCHREALTIME/./} - holder_t0) / 1000))
if [ "$holder_ms" -lt 2500 ]; then pass "log-holder-not-waited (${holder_ms}ms < 2500ms)"; else fail "log-holder-not-waited (${holder_ms}ms)"; fi
expect_eq "log-holder-children-spawned" "3" "$(wc -l <"$stub_state/holders" | tr -d ' ')"
while read -r holder_pid; do kill "$holder_pid" 2>/dev/null || true; done <"$stub_state/holders"

# --- 8d. 計測中の時計の変更（Codex P1）: 壁時計の区間を単調時計（/proc/uptime）と照合し、
#         食い違えばその回を結果に使わず exit 1、stdout は空。単調時計が進まない読み元に
#         差し替えて、壁時計だけが 150ms 以上進む状況（時計の変更と同じ食い違い）を再現する ---
echo "100.00 0.00" >"$work/frozen-uptime"
reset_log
STARTUP_LATENCY_TEST_UPTIME_FILE="$work/frozen-uptime" expect_rc "clock-changed" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_contains "clock-changed-error" "clock-changed"
expect_eq "clock-changed-stdout-empty" "" "$last_stdout"
if grep -q '^delete ' "$stub_log"; then pass "clock-changed-delete-called"; else fail "clock-changed-delete-called"; fi
# 単調時計の読み元が読めなければ前提欠如として exit 3。
STARTUP_LATENCY_TEST_UPTIME_FILE="$work/no-such-uptime" expect_rc "missing-monotonic-clock" 3 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0

# --- 9. 前提ツール欠如: jq を含まない PATH で exit 3 ---
mkdir -p "$work/emptybin"
rc=0
PATH="$work/emptybin" "$bash_bin" "$target_script" --target own --runtime "$stub" --bundle "$work/bundle" >/dev/null 2>&1 || rc=$?
expect_eq "missing-jq-exit3" "3" "$rc"

# --- 10. 出力が check-bench-regression.sh のスキーマと互換（機械照合） ---
export STUB_MODE=ok
run_target --runtime "$stub" --bundle "$work/bundle" --iterations 2 --warmup 0
printf '%s\n' "$last_stdout" >"$work/results.json"
cat >"$work/baseline.json" <<'JSON'
{
  "schema_version": 1,
  "metrics": {
    "startup_latency_p50_ms": {"value": 100000, "unit": "ms", "direction": "lower_is_better"},
    "startup_latency_min_ms": {"value": 100000, "unit": "ms", "direction": "lower_is_better"},
    "startup_latency_max_ms": {"value": 100000, "unit": "ms", "direction": "lower_is_better"}
  }
}
JSON
rc=0
"$bash_bin" "$bench_check_script" "$work/baseline.json" "$work/results.json" >/dev/null 2>&1 || rc=$?
expect_eq "bench-regression-schema-compat" "0" "$rc"

# ===========================================================================
# TASK-46.2: docker モードと report モード（CORE-10）。スタブ docker CLI で完結し、実 Docker・
# root は使わない。実機での Docker 実測は #213（TASK-46.h1）で人間が行う。
# ===========================================================================

dstub="$work/stub-docker"
dstub_state="$work/dstub-state"
dstub_log="$work/dstub.log"
printf '#!%s\n' "$bash_bin" >"$dstub"
cat >>"$dstub" <<'DSTUB'
# スタブ docker CLI。image inspect / run / ps / rm だけを模し、呼び出しを $DSTUB_LOG へ記録する。
# コンテナは $DSTUB_STATE/containers/<cid> のマーカーで表す。DSTUB_MODE:
#   ok: run が cidfile に ID を書いて成功し、--rm でコンテナは残らない
#   leftover-after-rm: ok と同じだが、run 後もコンテナが残る（rm -f で片付く）
#   rm-fail: leftover-after-rm と同じで、rm -f が常に失敗する
#   list-fail: ok と同じだが、run 後の ps が失敗する
#   image-missing: image inspect が失敗する
#   run-fail-no-cid: run が cidfile を書かず失敗する（終了コード 125 = timeout の 125 と同値）
#   run-hang-cid-written: cidfile を書きコンテナを作ってからハングする
#   run-hang-no-cid-listed: cidfile を書かずコンテナだけ作ってハングする
mode="${DSTUB_MODE:-ok}"
echo "$*" >>"$DSTUB_LOG"
cmd="$1"
shift
mkdir -p "$DSTUB_STATE/containers"
case "$cmd" in
  image)
    [ "$mode" = image-missing ] && { echo "Error: No such image" >&2; exit 1; }
    echo "sha256:0000"
    ;;
  run)
    cidfile=""
    args=("$@")
    for ((i = 0; i < ${#args[@]}; i++)); do
      [ "${args[$i]}" = --cidfile ] && cidfile="${args[$((i + 1))]}"
    done
    touch "$DSTUB_STATE/ran"
    n=$(($(cat "$DSTUB_STATE/counter" 2>/dev/null || echo 0) + 1))
    echo "$n" >"$DSTUB_STATE/counter"
    cid="$(printf '%064x' "$n")"
    case "$mode" in
      run-fail-no-cid) echo "docker: daemon error" >&2; exit 125 ;;
      ok | list-fail) printf '%s' "$cid" >"$cidfile"; sleep 0.05 ;;
      leftover-after-rm | rm-fail) printf '%s' "$cid" >"$cidfile"; touch "$DSTUB_STATE/containers/$cid"; sleep 0.05 ;;
      run-hang-cid-written) printf '%s' "$cid" >"$cidfile"; touch "$DSTUB_STATE/containers/$cid"; exec sleep 30 ;;
      run-hang-no-cid-listed) touch "$DSTUB_STATE/containers/$cid"; exec sleep 30 ;;
    esac
    ;;
  ps)
    [ "$mode" = list-fail ] && [ -e "$DSTUB_STATE/ran" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
    for f in "$DSTUB_STATE"/containers/*; do
      [ -e "$f" ] && basename "$f"
    done
    ;;
  rm)
    cid="${*: -1}"
    [ "$mode" = rm-fail ] && { echo "stub: rm failed" >&2; exit 1; }
    [ -e "$DSTUB_STATE/containers/$cid" ] || { echo "Error: No such container" >&2; exit 1; }
    rm -f -- "$DSTUB_STATE/containers/$cid"
    echo "$cid"
    ;;
  *) echo "stub: unsupported command $cmd" >&2; exit 1 ;;
esac
exit 0
DSTUB
chmod 755 "$dstub"
export DSTUB_LOG="$dstub_log"
export DSTUB_STATE="$dstub_state"

reset_dlog() {
  : >"$dstub_log"
  rm -rf -- "$dstub_state"
  mkdir -p "$dstub_state"
}
dlog_cmds() {
  cut -d' ' -f1 "$dstub_log" | tr '\n' ' ' | sed 's/ $//'
}

# 他のケースで使う引数（--target を含まない既定）を docker 用に差し替える。
default_args=(--mode docker --target docker)

# --- D1. 正常系: argv・出力スキーマ・統計の独立再計算 ---
reset_dlog
export DSTUB_MODE=ok
expect_rc "docker-ok" 0 --runtime "$dstub" --iterations 3 --warmup 1
docker_json="$last_stdout"
expect_eq "docker-ok-schema_version" "1" "$(jq -r '.schema_version' <<<"$docker_json")"
expect_eq "docker-ok-benchmark" "startup_latency" "$(jq -r '.benchmark' <<<"$docker_json")"
expect_eq "docker-ok-mode" "docker" "$(jq -r '.mode' <<<"$docker_json")"
expect_eq "docker-ok-method" "docker-run-rm-total" "$(jq -r '.method' <<<"$docker_json")"
expect_eq "docker-ok-target" "docker" "$(jq -r '.target' <<<"$docker_json")"
expect_eq "docker-ok-image" "alpine:3.20" "$(jq -r '.params.image' <<<"$docker_json")"
expect_eq "docker-ok-samples-count" "3" "$(jq -r '.samples_us | length' <<<"$docker_json")"
expect_eq "docker-ok-sample-keys" "run_us total_us" "$(jq -r '.samples_us[0] | keys_unsorted | join(" ")' <<<"$docker_json")"
expect_eq "docker-ok-run-ge-50ms" "true" "$(jq -r 'all(.samples_us[]; .total_us >= 50000 and .run_us == .total_us)' <<<"$docker_json")"
expect_eq "docker-ok-no-path-leak" "false" "$(jq -r --arg p "$work" 'tostring | contains($p)' <<<"$docker_json")"
verify_stats "docker-median-odd(3)" "$docker_json"
# warmup 込み 4 回: image inspect -> 事前の一覧 -> (run -> 後始末の一覧) x 4。rm は送られない。
expect_eq "docker-ok-call-sequence" "image ps run ps run ps run ps run ps" "$(dlog_cmds)"
run_line="$(grep '^run ' "$dstub_log" | head -n 1)"
if [[ "$run_line" =~ ^run\ --rm\ --pull\ never\ --cidfile\ /[^\ ]+/cid-[0-9]+\ --name\ fandhe-startup-[A-Za-z0-9]+-[0-9]+-[0-9]+\ --label\ fandhe\.startup-latency\.run=[A-Za-z0-9]+\ --entrypoint\ true\ alpine:3\.20$ ]]; then
  pass "docker-ok-run-argv"
else
  fail "docker-ok-run-argv ($run_line)"
fi
expect_eq "docker-ok-unique-names" "4" "$(grep '^run ' "$dstub_log" | sed 's/.*--name \([^ ]*\) .*/\1/' | sort -u | wc -l | tr -d ' ')"
expect_eq "docker-ok-ps-argv" "true" "$(grep -c '^ps -a -q --no-trunc --filter label=fandhe\.startup-latency\.run=[A-Za-z0-9]*$' "$dstub_log" | awk '{print ($1 == 5) ? "true" : "false"}')"
reset_dlog
expect_rc "docker-even-run" 0 --runtime "$dstub" --iterations 4 --warmup 0
verify_stats "docker-median-even(4)" "$last_stdout"
# --output は oci モードと同じ公開手順で書かれる。
reset_dlog
docker_out="$work/docker-result.json"
expect_rc "docker-output-write" 0 --runtime "$dstub" --iterations 2 --warmup 0 --output "$docker_out"
expect_eq "docker-output-equals-stdout" "$last_stdout" "$(cat "$docker_out")"

# --- D2. イメージ指定 ---
reset_dlog
expect_rc "docker-image-custom" 0 --runtime "$dstub" --iterations 1 --warmup 0 --image alpine:3.19
expect_eq "docker-image-custom-param" "alpine:3.19" "$(jq -r '.params.image' <<<"$last_stdout")"
if grep -q '^run .* --entrypoint true alpine:3\.19$' "$dstub_log"; then pass "docker-image-custom-argv"; else fail "docker-image-custom-argv"; fi
reset_dlog
DSTUB_MODE=image-missing expect_rc "docker-image-missing" 1 --runtime "$dstub" --iterations 1 --warmup 0
expect_contains "docker-image-missing-error" "image-not-present"
expect_eq "docker-image-missing-sequence" "image" "$(dlog_cmds)"

# --- D3. 後始末: 所有の証明（cidfile）とラベル一覧 ---
# run が失敗して cidfile がなく、一覧も空なら何も送らず exit 1（終了コード 125 は GNU timeout の
# 125 と同値だが、docker モードは終了コードで所有を判定しない）。
reset_dlog
DSTUB_MODE=run-fail-no-cid expect_rc "docker-run-fail-no-cid" 1 --runtime "$dstub" --iterations 1 --warmup 0
expect_contains "docker-run-fail-no-cid-error" "docker-run-failed"
if grep -q '^rm ' "$dstub_log"; then fail "docker-run-fail-no-cid-no-rm"; else pass "docker-run-fail-no-cid-no-rm"; fi
# run がハングし cidfile が書かれていれば、その ID だけに rm -f を 1 回送る。
reset_dlog
started="$SECONDS"
DSTUB_MODE=run-hang-cid-written expect_rc "docker-run-hang-cid-written" 1 --runtime "$dstub" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "docker-run-hang-bounded (${elapsed}s < 15s)"; else fail "docker-run-hang-bounded (${elapsed}s)"; fi
expect_eq "docker-run-hang-cid-written-rm" "rm -f $(printf '%064x' 1)" "$(grep '^rm ' "$dstub_log")"
# cidfile がなく一覧にコンテナが見つかる場合は所有を証明できないので何も送らず exit 4。
reset_dlog
DSTUB_MODE=run-hang-no-cid-listed expect_rc "docker-run-hang-no-cid-listed" 4 --runtime "$dstub" --iterations 1 --warmup 0 --timeout 1
expect_contains "docker-run-hang-no-cid-listed-leftover" "containers left behind: $(printf '%064x' 1)"
if grep -q '^rm ' "$dstub_log"; then fail "docker-run-hang-no-cid-listed-untouched"; else pass "docker-run-hang-no-cid-listed-untouched"; fi
# rm -f が失敗し続けたら期限内で打ち切って exit 4。
reset_dlog
started="$SECONDS"
DSTUB_MODE=rm-fail expect_rc "docker-rm-fail" 4 --runtime "$dstub" --iterations 1 --warmup 0 --timeout 1
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 15 ]; then pass "docker-rm-fail-bounded (${elapsed}s < 15s)"; else fail "docker-rm-fail-bounded (${elapsed}s)"; fi
expect_contains "docker-rm-fail-leftover" "containers left behind: $(printf '%064x' 1)"
# 一覧の取得に失敗したら削除の確認ができないので exit 4。
reset_dlog
DSTUB_MODE=list-fail expect_rc "docker-list-fail" 4 --runtime "$dstub" --iterations 1 --warmup 0 --timeout 1
expect_contains "docker-list-fail-leftover" "containers left behind: $(printf '%064x' 1)"
# 一覧が取れない状態では所有・残存を確認できないので rm -f を送らない（fail-closed）。
if grep -q '^rm ' "$dstub_log"; then fail "docker-list-fail-no-rm"; else pass "docker-list-fail-no-rm"; fi
# --rm の後にコンテナが残っていれば、cidfile の ID を指定した rm -f で片付けて成功する。
reset_dlog
DSTUB_MODE=leftover-after-rm expect_rc "docker-leftover-after-rm" 0 --runtime "$dstub" --iterations 1 --warmup 0
expect_eq "docker-leftover-after-rm-rm" "rm -f $(printf '%064x' 1)" "$(grep '^rm ' "$dstub_log")"
expect_eq "docker-leftover-after-rm-cleaned" "" "$(find "$dstub_state/containers" -type f -print)"

# --- D4. 入力エラー（exit 2） ---
reset_dlog
expect_rc "docker-bundle-given" 2 --runtime "$dstub" --bundle "$work/bundle"
expect_contains "docker-bundle-given-error" "invalid-option-for-mode"
expect_rc "docker-image-invalid-dash" 2 --runtime "$dstub" --image -v
expect_rc "docker-image-invalid-space" 2 --runtime "$dstub" --image "alpine 3"
expect_rc "docker-image-invalid-semicolon" 2 --runtime "$dstub" --image 'alpine;id'
expect_rc "docker-image-duplicate" 2 --runtime "$dstub" --image a --image b
expect_rc "docker-runtime-relative" 2 --runtime docker
expect_eq "docker-input-errors-no-calls" "" "$(cat "$dstub_log")"
default_args=(--target own)
expect_rc "image-in-oci-mode" 2 --runtime "$stub" --bundle "$work/bundle" --image alpine:3.20
expect_contains "image-in-oci-mode-error" "invalid-option-for-mode"
expect_rc "mode-invalid" 2 --mode podman --runtime "$stub" --bundle "$work/bundle"
expect_contains "mode-invalid-error" "invalid-mode"
expect_rc "mode-duplicate" 2 --mode oci --mode docker --runtime "$stub" --bundle "$work/bundle"
expect_rc "mode-oci-explicit" 0 --mode oci --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0
expect_eq "oci-mode-field" "oci" "$(jq -r '.mode' <<<"$last_stdout")"
expect_eq "oci-method-field" "create-to-exec-observed" "$(jq -r '.method' <<<"$last_stdout")"
expect_eq "oci-no-image-param" "false" "$(jq -r '.params | has("image")' <<<"$last_stdout")"
oci_json="$last_stdout"

# --- D5. check-bench-regression.sh のスキーマ互換（docker・oci 両方） ---
reset_dlog
default_args=(--mode docker --target docker)
run_target --runtime "$dstub" --iterations 2 --warmup 0
printf '%s\n' "$last_stdout" >"$work/docker-results.json"
rc=0
"$bash_bin" "$bench_check_script" "$work/baseline.json" "$work/docker-results.json" >/dev/null 2>&1 || rc=$?
expect_eq "docker-bench-regression-schema-compat" "0" "$rc"
printf '%s\n' "$oci_json" >"$work/oci-results.json"
rc=0
"$bash_bin" "$bench_check_script" "$work/baseline.json" "$work/oci-results.json" >/dev/null 2>&1 || rc=$?
expect_eq "oci-bench-regression-schema-compat-with-mode" "0" "$rc"

# --- R. report モード ---
default_args=()
own_fixture="$work/own-fixture.json"
docker_fixture="$work/docker-fixture.json"
cat >"$own_fixture" <<'JSON'
{"schema_version":1,"benchmark":"startup_latency","mode":"oci","method":"create-to-exec-observed","target":"own","label":"own","params":{"iterations":3,"warmup":1,"timeout_secs":10},"samples_us":[{"total_us":230000},{"total_us":240000},{"total_us":250000}],"metrics":{"startup_latency_p50_ms":{"value":240,"unit":"ms"},"startup_latency_min_ms":{"value":230,"unit":"ms"},"startup_latency_max_ms":{"value":250,"unit":"ms"}}}
JSON
cat >"$docker_fixture" <<'JSON'
{"schema_version":1,"benchmark":"startup_latency","mode":"docker","method":"docker-run-rm-total","target":"docker","label":"docker","params":{"iterations":3,"warmup":1,"timeout_secs":10,"image":"alpine:3.20"},"samples_us":[{"run_us":290000,"total_us":290000},{"run_us":300000,"total_us":300000},{"run_us":310000,"total_us":310000}],"metrics":{"startup_latency_p50_ms":{"value":300,"unit":"ms"},"startup_latency_min_ms":{"value":290,"unit":"ms"},"startup_latency_max_ms":{"value":310,"unit":"ms"}}}
JSON
expect_rc "report-ok" 0 --mode report --own-result "$own_fixture" --docker-result "$docker_fixture"
report_json="$last_stdout"
expect_eq "report-benchmark" "startup_latency_report" "$(jq -r '.benchmark' <<<"$report_json")"
expect_eq "report-schema_version" "1" "$(jq -r '.schema_version' <<<"$report_json")"
expect_eq "report-comparison" "240 300 0.8 true" "$(jq -r '.comparison | [.own_p50_ms, .docker_p50_ms, .p50_ratio_own_to_docker, .methods_differ] | map(tostring) | join(" ")' <<<"$report_json")"
expect_eq "report-results-embedded" "own docker" "$(jq -r '[.results.own.target, .results.docker.target] | join(" ")' <<<"$report_json")"
expect_eq "report-no-verdict" "false" "$(jq -r '[.. | objects | keys[]] | any(test("^(verdict|pass|passed|fail|failed|go)$"; "i"))' <<<"$report_json")"
expect_eq "report-no-path-leak" "false" "$(jq -r --arg p "$work" 'tostring | contains($p)' <<<"$report_json")"
report_out="$work/report.json"
expect_rc "report-output-write" 0 --mode report --own-result "$own_fixture" --docker-result "$docker_fixture" --output "$report_out"
expect_eq "report-output-equals-stdout" "$last_stdout" "$(cat "$report_out")"
expect_rc "report-output-existing" 2 --mode report --own-result "$own_fixture" --docker-result "$docker_fixture" --output "$report_out"
# 実際の own / docker の出力（スタブ計測）からも統合できる。
printf '%s\n' "$oci_json" >"$work/oci-real.json"
expect_rc "report-from-real-outputs" 0 --mode report --own-result "$work/oci-real.json" --docker-result "$work/docker-results.json"
expect_eq "report-from-real-outputs-differ" "true" "$(jq -r '.comparison.methods_differ' <<<"$last_stdout")"

# report の入力エラー（exit 2）。
echo 'not json' >"$work/bad-notjson.json"
expect_rc "report-not-json" 2 --mode report --own-result "$work/bad-notjson.json" --docker-result "$docker_fixture"
expect_contains "report-not-json-error" "invalid-result"
jq '.benchmark = "other"' "$own_fixture" >"$work/bad-benchmark.json"
expect_rc "report-benchmark-mismatch" 2 --mode report --own-result "$work/bad-benchmark.json" --docker-result "$docker_fixture"
expect_rc "report-mode-swapped" 2 --mode report --own-result "$docker_fixture" --docker-result "$own_fixture"
# method は mode ごとに固定値のみ許可する（両入力を同一 method へ書き換えて methods_differ を偽装させない）。
jq '.method = "docker-run-rm-total"' "$own_fixture" >"$work/bad-method-own.json"
expect_rc "report-method-forged-same" 2 --mode report --own-result "$work/bad-method-own.json" --docker-result "$docker_fixture"
expect_contains "report-method-forged-error" "invalid-result"
jq '.method = "create-to-exec-observed"' "$docker_fixture" >"$work/bad-method-docker.json"
expect_rc "report-method-forged-docker" 2 --mode report --own-result "$own_fixture" --docker-result "$work/bad-method-docker.json"
jq '.method = "other"' "$own_fixture" >"$work/bad-method-other.json"
expect_rc "report-method-unknown" 2 --mode report --own-result "$work/bad-method-other.json" --docker-result "$docker_fixture"
# samples_us と整合しない p50・件数不一致・不正なサンプルは拒否する（p50 だけの書き換えを防ぐ）。
jq '.metrics.startup_latency_p50_ms.value = 1' "$own_fixture" >"$work/bad-p50-forged.json"
expect_rc "report-p50-forged" 2 --mode report --own-result "$work/bad-p50-forged.json" --docker-result "$docker_fixture"
expect_contains "report-p50-forged-error" "invalid-result"
jq '.params.iterations = 5' "$docker_fixture" >"$work/bad-iter-count.json"
expect_rc "report-iterations-mismatch" 2 --mode report --own-result "$own_fixture" --docker-result "$work/bad-iter-count.json"
jq '.samples_us = []' "$own_fixture" >"$work/bad-samples-empty.json"
expect_rc "report-samples-empty" 2 --mode report --own-result "$work/bad-samples-empty.json" --docker-result "$docker_fixture"
jq '.samples_us[0].total_us = "x"' "$own_fixture" >"$work/bad-sample-type.json"
expect_rc "report-sample-nonnumber" 2 --mode report --own-result "$work/bad-sample-type.json" --docker-result "$docker_fixture"
jq '.metrics.startup_latency_max_ms.value = 999' "$docker_fixture" >"$work/bad-max-forged.json"
expect_rc "report-max-forged" 2 --mode report --own-result "$own_fixture" --docker-result "$work/bad-max-forged.json"
jq '.metrics.startup_latency_p50_ms.value = 0' "$own_fixture" >"$work/bad-zero.json"
expect_rc "report-p50-zero" 2 --mode report --own-result "$work/bad-zero.json" --docker-result "$docker_fixture"
jq 'del(.metrics.startup_latency_p50_ms)' "$docker_fixture" >"$work/bad-missing.json"
expect_rc "report-p50-missing" 2 --mode report --own-result "$own_fixture" --docker-result "$work/bad-missing.json"
jq '.metrics.startup_latency_p50_ms.unit = "s"' "$own_fixture" >"$work/bad-unit.json"
expect_rc "report-unit-mismatch" 2 --mode report --own-result "$work/bad-unit.json" --docker-result "$docker_fixture"
jq '.schema_version = 2' "$own_fixture" >"$work/bad-version.json"
expect_rc "report-schema-version" 2 --mode report --own-result "$work/bad-version.json" --docker-result "$docker_fixture"
cat "$own_fixture" "$own_fixture" >"$work/bad-two-docs.json"
expect_rc "report-two-documents" 2 --mode report --own-result "$work/bad-two-docs.json" --docker-result "$docker_fixture"
ln -sf "$own_fixture" "$work/own-link.json"
expect_rc "report-symlink" 2 --mode report --own-result "$work/own-link.json" --docker-result "$docker_fixture"
expect_rc "report-missing-file" 2 --mode report --own-result "$work/no-such.json" --docker-result "$docker_fixture"
head -c 1048577 /dev/zero | tr '\0' ' ' >"$work/bad-big.json"
expect_rc "report-too-big" 2 --mode report --own-result "$work/bad-big.json" --docker-result "$docker_fixture"
expect_rc "report-missing-arg" 2 --mode report --own-result "$own_fixture"
expect_rc "report-extra-runtime" 2 --mode report --own-result "$own_fixture" --docker-result "$docker_fixture" --runtime "$dstub"
expect_rc "report-extra-bundle" 2 --mode report --own-result "$own_fixture" --docker-result "$docker_fixture" --bundle "$work/bundle"
expect_rc "report-extra-iterations" 2 --mode report --own-result "$own_fixture" --docker-result "$docker_fixture" --iterations 3
expect_rc "own-result-in-oci-mode" 2 --mode oci --target own --runtime "$stub" --bundle "$work/bundle" --own-result "$own_fixture"
default_args=(--target own)

if [ "$failures" -ne 0 ]; then
  echo "startup_latency_selftest: $failures failure(s)" >&2
  exit 1
fi
echo "startup_latency_selftest: all cases passed"
