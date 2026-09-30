#!/usr/bin/env bash
# own 実装の起動時間計測スクリプト（TASK-46.1・CORE-10・MS-2 Phase 3）。
#
# 役割: OCI Runtime の CLI 契約に従うランタイム実行ファイルを `--runtime` で受け取り、
# `create` 開始からコンテナのプロセス実行開始（state が running / stopped を返した時点）
# までの壁時計時間を複数回計測して中央値を出す。
# CORE-10 は「create からプロセス実行開始までの起動時間の中央値が Docker 比で同等以下」
# を求める（Linux の Docker ベースラインは 0.290〜0.298 秒・node4 実測）。本スクリプトは
# TASK-46（担当: 人間）のうち Claude Code 担当分である計測ハーネスの準備までを担い、
# 実機での実測・Docker 比較・Conditional Go 条件 1 の判定は #213（TASK-46.h1）で人間が行う。
# Docker 側の同一手法計測は #842（TASK-46.2）が本スクリプトを拡張して追加する
# （1 回分の計測を measure_once に分け、出力に計測対象ラベル `target` を持たせてある）。
#
# 現状の制約（REPAIR-3: 実装済みを装わない）:
#   - crates/cli は雛形で fandhe-container バイナリは未提供（TASK-79 で追加予定）。
#   - oci_runtime::start の本番 ProcessLauncher は未提供（制限ステージ TASK-37〜39・
#     TASK-157 待ち）、ファイルベース StateStore は TASK-31 待ちのため、現時点では
#     own 実装を CLI からエンドツーエンドで起動できない。own の実測は CLI 提供後。
#   - fandhe-container の CLI が下記契約と異なる形になった場合は、ランタイム呼び出し部
#     （rt_create / rt_start / rt_delete / rt_kill / rt_state / rt_is_not_found の 6 関数）
#     だけを差し替える。
#   - create が成功しなかった場合の未作成判定は、ERR-1 の構造化エラー（code: NOT_FOUND）を
#     明確な不存在応答として使う（rt_is_not_found）。構造化エラーを出さないランタイム（runc 等）
#     では create 失敗時に未作成を確定できず、その ID に操作を送らずに exit 4 で報告する。
#
# 呼び出し元: Makefile の `startup-latency` ターゲット（自己テストは
# scripts/bench/startup_latency_selftest.sh・`startup-latency-selftest` ターゲット）。
# 実機前提のため `make ci` には含めない（.claude/rules/ci.md「実機前提テスト」）。
#
# 計測対象の起動契約（opencontainers/runtime-tools の command-line-interface・runc 互換）:
#   <runtime> state <id>                       # create 前の ID 未使用確認（計測対象外）と実行開始の観測
#   <runtime> create --bundle <bundle> <id>    # 計測対象
#   <runtime> start <id>                       # 計測対象
#   <runtime> delete <id>                      # 後始末（計測対象外）。失敗時は kill <id> KILL → 待機付き delete
#   「プロセス実行開始」の定義（CORE-10 の前提「create からプロセス実行開始までの時間」）:
#   OCI Runtime Spec の start 成功はユーザー指定プログラムの実行開始時刻を返す契約では
#   ないため、start 復帰後に state を照会し、status が running（プログラム実行済み・未終了）
#   または stopped（終了済み）を初めて返した時点を実行開始の観測点とする。計測値 total は
#   create 呼び出し直前からその state 復帰直後まで（実行開始時刻の上側推定。内訳として
#   create・start・観測待ち observe と state 照会回数を記録する）。
#
# 使い方:
#   startup_latency.sh --runtime <絶対パス> --bundle <dir> [--iterations N] [--warmup N]
#                      [--timeout SECS] [--label NAME] [--output FILE]
#   bundle は人間が用意する（rootfs と config.json。基準ワークロードは alpine:3.20 相当の
#   軽量プロセス。rootfs・config.json の生成は本スクリプトでは行わない）。
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: ランタイムの create / start / state の失敗・タイムアウト、実行開始を観測できない、
#      ID が既に使用中
#   2: 入力エラー（引数・bundle・output の検証失敗）
#   3: 前提ツール欠如（bash 5 以上・jq・GNU timeout・mktemp・sleep 等）
#   4: 後始末失敗（作成済みコンテナを delete できない、create 失敗後に未作成を確定できない等。
#      残存の可能性がある ID を stderr に出す。最優先）
#
# 出力（stdout。--output 指定時は同一内容をファイルにも書く。進捗・サマリーは stderr）:
#   scripts/check-bench-regression.sh の results.json スキーマ（schema_version: 1・
#   metrics.<name>.{value(>0), unit}）と互換。ランタイム・bundle の絶対パスは出力に含めない。
#
# セキュリティ: 引数は許可リストで検証し、ランタイムは配列で直接 exec する（eval・
# sh -c・文字列連結なし）。sudo は内部で呼ばない（root を要する実測は人間が明示実行する）。
# 各ランタイム呼び出しは timeout で上限を掛け、ログ出力量にも上限（ulimit -f）を掛ける。
# 実行開始の観測・後始末の待機にも時間と回数の上限を設ける（REPAIR-5）。

set -euo pipefail
# EPOCHREALTIME の小数点がロケール依存になるのを防ぐ。
export LC_ALL=C

readonly EXIT_RUNTIME=1
readonly EXIT_INPUT=2
readonly EXIT_PREREQ=3
readonly EXIT_CLEANUP=4
# timeout 満了後に KILL へ切り替えるまでの猶予秒。
readonly KILL_AFTER_SECS=5
# 失敗時に stderr へ出すログ末尾の行数上限。
readonly LOG_TAIL_LINES=20
# ランタイム 1 呼び出しがログファイルへ書ける最大サイズ（KiB。ulimit -f の単位）。
# 超過した呼び出しは SIGXFSZ で打ち切られ計測失敗になる（ディスク枯渇防止。REPAIR-5）。
readonly LOG_MAX_KIB=1024
# start 復帰後に state で実行開始（running / stopped）を観測する最大照会回数。
# 時間上限は --timeout 秒（REPAIR-5）で、先に達した方で打ち切る。
readonly STATE_POLL_MAX=500
# kill 後に delete を再試行する最大回数と間隔（秒）。時間上限は --timeout 秒。
readonly DELETE_RETRY_MAX=100
readonly DELETE_RETRY_INTERVAL=0.1

usage() {
  cat >&2 <<'USAGE'
usage: startup_latency.sh --runtime <abs-path> --bundle <dir> [options]
  --runtime <path>     OCI runtime executable (absolute path, required)
  --bundle <dir>       OCI bundle directory containing config.json (required)
  --iterations <1-1000> measured iterations (default: 10)
  --warmup <0-100>     warmup iterations excluded from statistics (default: 1)
  --timeout <1-60>     per runtime command timeout in seconds (default: 10)
  --label <name>       label recorded in the output (default: own)
  --output <file>      also write the JSON result to a new file (must not exist)
  -h, --help           show this help
USAGE
}

err() {
  echo "error: $1: $2" >&2
}

runtime=""
bundle=""
iterations=10
warmup=1
timeout_secs=10
label="own"
output=""
seen_opts=" "

# 値付きオプションの重複・値欠落を検出する（exit 2）。
take_value() {
  local opt="$1"
  if [[ "$seen_opts" == *" $opt "* ]]; then
    err "duplicate-option" "$opt given more than once"
    exit "$EXIT_INPUT"
  fi
  seen_opts="${seen_opts}${opt} "
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --runtime | --bundle | --iterations | --warmup | --timeout | --label | --output)
      opt="$1"
      if [ "$#" -lt 2 ]; then
        err "missing-value" "$opt requires a value"
        exit "$EXIT_INPUT"
      fi
      take_value "$opt"
      case "$opt" in
        --runtime) runtime="$2" ;;
        --bundle) bundle="$2" ;;
        --iterations) iterations="$2" ;;
        --warmup) warmup="$2" ;;
        --timeout) timeout_secs="$2" ;;
        --label) label="$2" ;;
        --output) output="$2" ;;
      esac
      shift 2
      ;;
    *)
      err "unknown-option" "unexpected argument: $1"
      usage
      exit "$EXIT_INPUT"
      ;;
  esac
done

# 10 進整数（先頭ゼロなし・最大 4 桁）かつ範囲内であることを検証する。
check_int() {
  local name="$1" value="$2" min="$3" max="$4"
  if ! [[ "$value" =~ ^(0|[1-9][0-9]{0,3})$ ]] || [ "$value" -lt "$min" ] || [ "$value" -gt "$max" ]; then
    err "invalid-$name" "$name must be an integer in $min..$max"
    exit "$EXIT_INPUT"
  fi
}

if [ -z "$runtime" ]; then
  err "missing-runtime" "--runtime is required"
  exit "$EXIT_INPUT"
fi
if [[ "$runtime" != /* ]] || [ ! -f "$runtime" ] || [ ! -x "$runtime" ]; then
  err "invalid-runtime" "--runtime must be an absolute path to an executable file"
  exit "$EXIT_INPUT"
fi
if [ -z "$bundle" ]; then
  err "missing-bundle" "--bundle is required"
  exit "$EXIT_INPUT"
fi
if [ -L "$bundle" ] || [ ! -d "$bundle" ]; then
  err "invalid-bundle" "--bundle must be an existing directory (symlink not allowed)"
  exit "$EXIT_INPUT"
fi
if [ -L "$bundle/config.json" ] || [ ! -f "$bundle/config.json" ]; then
  err "invalid-bundle" "bundle must contain a regular file config.json (symlink not allowed)"
  exit "$EXIT_INPUT"
fi
check_int iterations "$iterations" 1 1000
check_int warmup "$warmup" 0 100
check_int timeout "$timeout_secs" 1 60
if ! [[ "$label" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  err "invalid-label" "label must match ^[A-Za-z0-9._-]{1,64}$"
  exit "$EXIT_INPUT"
fi
if [ -n "$output" ]; then
  if [ -e "$output" ] || [ -L "$output" ]; then
    err "invalid-output" "--output must not already exist"
    exit "$EXIT_INPUT"
  fi
  output_dir="$(dirname -- "$output")"
  if [ ! -d "$output_dir" ]; then
    err "invalid-output" "parent directory of --output must exist"
    exit "$EXIT_INPUT"
  fi
fi

# 前提ツールの検証（bash 5 以上は EPOCHREALTIME のため）。
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
  err "missing-prerequisite" "bash 5 or later is required (EPOCHREALTIME)"
  exit "$EXIT_PREREQ"
fi
for tool in jq timeout mktemp tail rm sleep; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing-prerequisite" "required tool not found: $tool"
    exit "$EXIT_PREREQ"
  fi
done

tmpdir="$(mktemp -d)"
# コンテナ ID の実行固有部。PID だけでは過去の実行で残ったコンテナと再利用時に衝突し、
# create 失敗時の後始末が無関係な既存コンテナを delete / kill し得るため、mktemp が返す
# ランダムな接尾辞（実行ごとに一意）を含める。英数字以外は除去して ID に使える形にする。
# 加えて create 前に state で ID が未使用であることを確認する（measure_once）。
run_tag="${tmpdir##*/}"
run_tag="${run_tag//[!A-Za-z0-9]/}"
if [ -z "$run_tag" ]; then
  rm -rf -- "$tmpdir"
  err "missing-prerequisite" "could not derive a unique run id from mktemp"
  exit "$EXIT_PREREQ"
fi
seq_no=0
# 現在の試行で後始末対象のコンテナ ID（1 試行につき 1 つ）と、削除できなかった ID の一覧。
live_id=""
# create が成功していれば 1。0 の間（create の成否未確定・失敗）は、後始末の前に state で
# 未作成か今回作ったものかを確かめる（finish_container）。
live_created=0
# create 前の state が明確な不存在応答（state_not_found）だったら 1。このときに限り、
# create 未成功後に同じ ID のコンテナが見えれば今回の create が作ったものと判定できる。
pre_absent=0
leftover_ids=()
rc=0
# create の終了コード（create 未成功時の未作成判定に使う）。
create_rc=0
# query_state の結果（終了コード・status）。
state_rc=0
state_status=""

# ランタイム呼び出し本体。stdout/stderr はファイルへ逃がす（コンテナ側がパイプを
# 保持して create が戻らないランタイムへの対策）。stdin は /dev/null。
# 引数: <stdout ファイル> <stderr ファイル（stdout と同じパスなら併合）> <ランタイム引数...>
run_rt() {
  local out="$1" errf="$2"
  shift 2
  local status=0
  # サブシェルで ulimit -f を掛け、出力量が上限を超えたら SIGXFSZ で失敗させる
  # （--timeout は出力量を制限しないため）。上限はサブシェル内に閉じる。
  (
    ulimit -f "$LOG_MAX_KIB"
    if [ "$out" = "$errf" ]; then
      exec timeout --kill-after="$KILL_AFTER_SECS" "$timeout_secs" "$runtime" "$@" </dev/null >"$out" 2>&1
    fi
    exec timeout --kill-after="$KILL_AFTER_SECS" "$timeout_secs" "$runtime" "$@" </dev/null >"$out" 2>"$errf"
  ) || status=$?
  return "$status"
}

# --- ランタイム呼び出し部（CLI 契約が変わった場合はこの 6 関数のみ差し替える） ---
rt_create() { run_rt "$1" "$1" create --bundle "$bundle" "$2"; }
rt_start() { run_rt "$1" "$1" start "$2"; }
rt_delete() { run_rt "$1" "$1" delete "$2"; }
rt_kill() { run_rt "$1" "$1" kill "$2" KILL; }
# state は stdout（OCI state JSON）と stderr を分けて受け取る。引数: <stdout> <stderr> <id>
rt_state() { run_rt "$1" "$2" state "$3"; }
# state の stderr（引数のファイル）が「コンテナが存在しない」ことを明確に示すか。OCI の CLI
# 契約には不存在専用の応答がないため、fandhe-container の CLI のエラー形式（ERR-1: stderr へ
# 機械可読な code / message の構造化エラー。不存在は ERR-3 / ERR-5 と同じ NOT_FOUND）に
# 合わせ、JSON オブジェクト行の code がすべて NOT_FOUND（1 件以上）の場合だけ真にする。
# 自由文の文言は解釈しない（runc 等の構造化エラーを持たないランタイムは常に偽＝不明扱い）。
# CLI（TASK-79）のエラー形式が確定したらこの関数を合わせる。
rt_is_not_found() {
  local codes code
  codes="$(jq -Rr 'fromjson? | objects | .code | strings' <"$1" 2>/dev/null)" || return 1
  [ -n "$codes" ] || return 1
  while IFS= read -r code; do
    [ "$code" = "NOT_FOUND" ] || return 1
  done <<<"$codes"
  return 0
}
# ---------------------------------------------------------------------------

# 失敗したコマンドのログ末尾を stderr へ出す。
show_log() {
  echo "--- last output of failed runtime command ---" >&2
  tail -n "$LOG_TAIL_LINES" -- "$1" >&2 || true
}

# 現在時刻（マイクロ秒）。EPOCHREALTIME は LC_ALL=C で小数点が "." に固定される。
now_us() {
  echo "${EPOCHREALTIME/./}"
}

# state を 1 回呼び、state_rc・state_status を設定する。state_status は stdout が単一の
# OCI state JSON で id が一致するときだけその status、それ以外は空文字。
query_state() {
  local id="$1" out="$tmpdir/state.out"
  state_rc=0
  rt_state "$out" "$tmpdir/state.err" "$id" || state_rc=$?
  state_status=""
  if [ "$state_rc" -eq 0 ]; then
    state_status="$(jq -rs --arg id "$id" \
      'if length == 1 and (.[0] | type) == "object" and .[0].id == $id and (.[0].status | type) == "string" then .[0].status else "" end' \
      <"$out" 2>/dev/null)" || state_status=""
  fi
}

# ランタイム自身が返したエラー終了か（timeout の 124・timeout 自体の失敗 125・
# 実行不能 126/127・シグナル終了 128 以上を除く 1〜123）。
is_runtime_error() {
  [ "$1" -ge 1 ] && [ "$1" -le 123 ]
}

# 直前の query_state が明確な不存在応答だったか（ランタイム自身のエラー終了かつ
# rt_is_not_found）。タイムアウト・権限エラー・自由文だけのエラーは不明として偽になる。
state_not_found() {
  is_runtime_error "$state_rc" && rt_is_not_found "$tmpdir/state.err"
}

# create 未成功の ID についてコンテナが作られなかったことを確かめる。OCI Runtime Spec は
# 操作がエラーを返した場合に環境を操作前の状態に保つことを求めるため、(a) create が
# ランタイム自身のエラーで終了し（タイムアウト・シグナル終了は途中状態が残り得るので除く）、
# かつ (b) state が明確な不存在応答を返した場合だけ未作成とみなす。
create_not_made() {
  is_runtime_error "$create_rc" && state_not_found
}

# create 未成功の ID に見えるコンテナが今回の create で作られたものか。create 前の state が
# 明確な不存在応答だった（pre_absent=1）ときに限り、その後に現れた同じ ID のコンテナを
# 今回のものと判定する。それ以外（作成前の不存在を確認できなかった ID）には操作を送らない。
state_is_ours() {
  [ "$pre_absent" = "1" ] && [ "$state_rc" -eq 0 ] && [ -n "$state_status" ]
}

# コンテナを削除する。delete が失敗したら kill KILL を送り、プロセスの終了を待ちながら
# delete を再試行する（OCI の delete は実行中コンテナを拒否し、kill は終了を待たないため）。
# 待機は --timeout 秒・DELETE_RETRY_MAX 回で打ち切る（REPAIR-5）。それでも残れば
# leftover_ids に記録して非ゼロを返す。
# 引数: <id> <created>
#   created=1: create 成功済み。OCI の create は ID 重複時に必ず失敗するため、この ID の
#              コンテナは今回作ったものであり、そのまま delete / kill を送る。
#   created=0: create 未成功。まず state で確かめ、未作成（create_not_made）なら何もせず
#              成功、今回作ったもの（state_is_ours）なら削除へ進み、どちらも確かめられ
#              なければ操作を送らずに残存の可能性ありとして記録する（所有を証明できない
#              コンテナへ破壊的操作を送らない。特権操作の後始末）。
finish_container() {
  local id="$1" created="$2"
  local log="$tmpdir/cleanup-$id.log"
  if [ "$created" = "0" ]; then
    query_state "$id"
    if create_not_made; then
      return 0
    fi
    if ! state_is_ours; then
      echo "warning: could not confirm whether $id was created by this run (state exit $state_rc, create exit $create_rc); not touching it and assuming it may be left behind" >&2
      leftover_ids+=("$id")
      return 1
    fi
  fi
  if rt_delete "$log" "$id"; then
    return 0
  fi
  rt_kill "$log" "$id" || true
  local deadline tries=0
  deadline=$(($(now_us) + timeout_secs * 1000000))
  while [ "$tries" -lt "$DELETE_RETRY_MAX" ] && [ "$(now_us)" -lt "$deadline" ]; do
    tries=$((tries + 1))
    if rt_delete "$log" "$id"; then
      return 0
    fi
    sleep "$DELETE_RETRY_INTERVAL"
  done
  leftover_ids+=("$id")
  return 1
}

# EXIT / INT / TERM で呼ばれる後始末。未削除のコンテナを削除し、一時ディレクトリを消す。
# 後始末に失敗した場合は他の終了コードより優先して exit 4 にする。
cleanup() {
  local final="$?"
  trap - EXIT INT TERM
  if [ -n "$live_id" ]; then
    # live_id は ID 未使用の確認後・create 試行の直前に設定される（create 失敗で中途半端に
    # 残った場合も対象）。削除できなければ finish_container が leftover_ids へ記録し、
    # 下で exit 4 にする。
    finish_container "$live_id" "$live_created" || true
    live_id=""
    live_created=0
  fi
  if ! rm -rf -- "$tmpdir"; then
    echo "error: cleanup-failed: could not remove temporary directory" >&2
    final="$EXIT_CLEANUP"
  fi
  if [ "${#leftover_ids[@]}" -gt 0 ]; then
    echo "error: cleanup-failed: containers left behind: ${leftover_ids[*]}" >&2
    final="$EXIT_CLEANUP"
  fi
  exit "$final"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 1 回分の計測。成功すると create_us・start_us・observe_us・total_us・state_polls を
# グローバルへ設定する。引数: <id>。失敗時は非ゼロを返す（呼び出し側が exit 1 に変換する）。
#
# 計測点（CORE-10「create からプロセス実行開始まで」）:
#   t0: create 呼び出し直前 / t1: create 復帰 / ts: start 復帰
#   t2: state が running / stopped を返した時点（OCI Runtime Spec の state は running を
#       「ユーザー指定プログラムを実行済みで未終了」、stopped を「プロセスが終了済み」と
#       定義する）。start の復帰はプロセスの実行開始を保証しないため、実行開始を state で
#       観測する。t2 は state 呼び出しの復帰後に取るため、実行開始時刻の上側推定になる
#       （state 1 回分の所要時間を含み、Docker 比では own に不利な側へ偏る）。
measure_once() {
  local id="$1" t0 t1 ts t2 deadline
  # create 前に state を照会する（計測区間外）。存在を示せば触らずに中止する。明確な
  # 不存在応答なら pre_absent=1 とし、create 失敗後に現れた同じ ID のコンテナを今回の
  # ものとして後始末できるようにする。それ以外の照会エラーは不存在の保証にならないため
  # pre_absent=0 のまま進み、create が成功しなかった場合はその ID に操作を送らない。
  pre_absent=0
  query_state "$id"
  if [ "$state_rc" -eq 0 ]; then
    err "container-id-in-use" "container $id already exists; refusing to touch it"
    return 1
  fi
  if state_not_found; then
    pre_absent=1
  fi
  t0="$(now_us)"
  # create が途中まで進んでから失敗・タイムアウトしても特権リソースが残り得るため、
  # 作成を試みた時点で後始末対象として保持する。失敗時の delete（kill → delete の再試行）と
  # 残存時の exit 4 は EXIT trap の cleanup が担う。
  live_id="$id"
  live_created=0
  create_rc=0
  rt_create "$tmpdir/create.log" "$id" || create_rc=$?
  if [ "$create_rc" -ne 0 ]; then
    err "runtime-create-failed" "create failed or timed out for $id"
    show_log "$tmpdir/create.log"
    return 1
  fi
  live_created=1
  t1="$(now_us)"
  if ! rt_start "$tmpdir/start.log" "$id"; then
    err "runtime-start-failed" "start failed or timed out for $id"
    show_log "$tmpdir/start.log"
    return 1
  fi
  ts="$(now_us)"
  state_polls=0
  deadline=$((ts + timeout_secs * 1000000))
  while :; do
    state_polls=$((state_polls + 1))
    query_state "$id"
    case "$state_status" in
      running | stopped) break ;;
      created) ;;
      *)
        err "runtime-state-failed" "state for $id failed or returned an unexpected status (exit $state_rc)"
        show_log "$tmpdir/state.err"
        return 1
        ;;
    esac
    if [ "$state_polls" -ge "$STATE_POLL_MAX" ] || [ "$(now_us)" -ge "$deadline" ]; then
      err "runtime-exec-not-observed" "container $id did not reach running/stopped within ${timeout_secs}s"
      return 1
    fi
  done
  t2="$(now_us)"
  create_us=$((t1 - t0))
  start_us=$((ts - t1))
  observe_us=$((t2 - ts))
  total_us=$((t2 - t0))
  return 0
}

samples="[]"
total_runs=$((warmup + iterations))
echo "startup_latency: target=own label=$label warmup=$warmup iterations=$iterations timeout=${timeout_secs}s" >&2
run_no=0
while [ "$run_no" -lt "$total_runs" ]; do
  run_no=$((run_no + 1))
  seq_no=$((seq_no + 1))
  id="fandhe-startup-$run_tag-$$-$seq_no"
  create_us=0
  start_us=0
  observe_us=0
  total_us=0
  state_polls=0
  if ! measure_once "$id"; then
    rc="$EXIT_RUNTIME"
    break
  fi
  if ! finish_container "$id" 1; then
    live_id=""
    err "cleanup-failed" "could not delete container $id"
    exit "$EXIT_CLEANUP"
  fi
  live_id=""
  live_created=0
  if [ "$run_no" -gt "$warmup" ]; then
    samples="$(jq -c --argjson c "$create_us" --argjson s "$start_us" --argjson o "$observe_us" \
      --argjson t "$total_us" --argjson p "$state_polls" \
      '. + [{create_us: $c, start_us: $s, observe_us: $o, total_us: $t, state_polls: $p}]' <<<"$samples")"
  fi
  echo "  run $run_no/$total_runs: create=${create_us}us start=${start_us}us observe=${observe_us}us total=${total_us}us polls=${state_polls}$([ "$run_no" -le "$warmup" ] && echo ' (warmup)')" >&2
done

if [ "$rc" -ne 0 ]; then
  # 失敗時の後始末は trap の cleanup が担う。
  exit "$rc"
fi

# total_us の中央値（偶数件は中央 2 件の平均）・最小・最大を ms で集計して JSON を組み立てる。
result="$(jq -n \
  --arg label "$label" \
  --argjson iterations "$iterations" \
  --argjson warmup "$warmup" \
  --argjson timeout "$timeout_secs" \
  --argjson samples "$samples" '
  ($samples | map(.total_us) | sort) as $t
  | ($t | length) as $n
  | (if $n % 2 == 1 then $t[($n - 1) / 2] else ($t[$n / 2 - 1] + $t[$n / 2]) / 2 end) as $p50
  | {
      schema_version: 1,
      benchmark: "startup_latency",
      target: "own",
      label: $label,
      params: {iterations: $iterations, warmup: $warmup, timeout_secs: $timeout},
      samples_us: $samples,
      metrics: {
        startup_latency_p50_ms: {value: ($p50 / 1000), unit: "ms"},
        startup_latency_min_ms: {value: ($t[0] / 1000), unit: "ms"},
        startup_latency_max_ms: {value: ($t[$n - 1] / 1000), unit: "ms"}
      }
    }')"

# --output 指定時はファイル作成に成功してから stdout へ出す（作成失敗時に成功結果を
# stdout へ残さず、呼び出し元が失敗した計測を取り込まないようにする）。
if [ -n "$output" ]; then
  # noclobber で上書き・symlink 追従を防ぐ（検証後に作られたパスも拒否する）。
  if ! (
    set -o noclobber
    printf '%s\n' "$result" >"$output"
  ); then
    err "output-write-failed" "could not create --output file"
    exit "$EXIT_INPUT"
  fi
fi
printf '%s\n' "$result"
echo "startup_latency: p50=$(jq -r '.metrics.startup_latency_p50_ms.value' <<<"$result")ms over $iterations runs" >&2
