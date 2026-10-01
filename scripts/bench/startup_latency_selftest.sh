#!/usr/bin/env bash
# scripts/bench/startup_latency.sh の自己テスト（TASK-46.1・CORE-10・REPAIR-12）。
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

# 対象スクリプトを実行し、stdout・stdout+stderr・終了コードを保持する（常に 0 を返す）。
run_target() {
  local errfile="$tmp_root/stderr.txt"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" "$@" 2>"$errfile")" || last_rc=$?
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
#   start-fail / start-hang / start-flood: start が失敗 / ハング / 大量出力
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
#   id-in-use: create 前から同じ ID のコンテナが存在する
mode="${STUB_MODE:-ok}"
cmd="$1"
shift
case "$cmd" in
  create) id="${*: -1}" ;;
  *) id="$1" ;;
esac
echo "$cmd $id" >>"$STUB_LOG"
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
STUB_CREATE_FIFO="$race_fifo" timeout 60 "$bash_bin" "$target_script" --runtime "$stub" --bundle "$work/bundle" \
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
PATH="$work/faildd:$PATH" "$bash_bin" "$target_script" --runtime "$stub" --bundle "$work/bundle" \
  --iterations 1 --warmup 0 --output "$work/partial/out.json" >"$work/partial.stdout" 2>/dev/null || rc=$?
expect_eq "output-partial-write-exit" "2" "$rc"
expect_eq "output-partial-write-no-file" "" "$(find "$work/partial" -mindepth 1 -print)"
expect_eq "output-partial-write-stdout-empty" "" "$(cat "$work/partial.stdout")"

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

# --- 7b. ログ出力の無制限書き込み（ulimit -f 上限超過）は計測失敗になる ---
reset_log
STUB_MODE=start-flood expect_rc "start-flood" 1 --runtime "$stub" --bundle "$work/bundle" --iterations 1 --warmup 0 --timeout 5
if grep -q '^delete ' "$stub_log"; then pass "start-flood-delete-called"; else fail "start-flood-delete-called"; fi

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

# --- 9. 前提ツール欠如: jq を含まない PATH で exit 3 ---
mkdir -p "$work/emptybin"
rc=0
PATH="$work/emptybin" "$bash_bin" "$target_script" --runtime "$stub" --bundle "$work/bundle" >/dev/null 2>&1 || rc=$?
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

if [ "$failures" -ne 0 ]; then
  echo "startup_latency_selftest: $failures failure(s)" >&2
  exit 1
fi
echo "startup_latency_selftest: all cases passed"
