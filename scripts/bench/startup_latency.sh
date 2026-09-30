#!/usr/bin/env bash
# own 実装の起動時間計測スクリプト（TASK-46.1・CORE-10・MS-2 Phase 3）。
#
# 役割: OCI Runtime の CLI 契約に従うランタイム実行ファイルを `--runtime` で受け取り、
# `create` 開始から `start` 正常復帰までの壁時計時間を複数回計測して中央値を出す。
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
#     （rt_create / rt_start / rt_delete / rt_kill の 4 関数）だけを差し替える。
#
# 呼び出し元: Makefile の `startup-latency` ターゲット（自己テストは
# scripts/bench/startup_latency_selftest.sh・`startup-latency-selftest` ターゲット）。
# 実機前提のため `make ci` には含めない（.claude/rules/ci.md「実機前提テスト」）。
#
# 計測対象の起動契約（opencontainers/runtime-tools の command-line-interface・runc 互換）:
#   <runtime> create --bundle <bundle> <id>    # 計測対象
#   <runtime> start <id>                       # 計測対象。正常復帰時点を「exec 開始」とみなす
#   <runtime> delete <id>                      # 後始末（計測対象外）。失敗時は kill <id> KILL → delete
#   「exec 開始」の定義: OCI Runtime Spec の start 操作は「ユーザー指定プログラムの実行」で
#   あり、その正常復帰をプロセス実行開始とみなす。計測値 total は create 呼び出し直前から
#   start 正常復帰直後まで（create 単体・start 単体も内訳として記録する）。
#
# 使い方:
#   startup_latency.sh --runtime <絶対パス> --bundle <dir> [--iterations N] [--warmup N]
#                      [--timeout SECS] [--label NAME] [--output FILE]
#   bundle は人間が用意する（rootfs と config.json。基準ワークロードは alpine:3.20 相当の
#   軽量プロセス。rootfs・config.json の生成は本スクリプトでは行わない）。
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: ランタイムの create / start の失敗またはタイムアウト
#   2: 入力エラー（引数・bundle・output の検証失敗）
#   3: 前提ツール欠如（bash 5 以上・jq・GNU timeout・mktemp・sort 等）
#   4: 後始末失敗（作成済みコンテナを delete できない等。残存 ID を stderr に出す。最優先）
#
# 出力（stdout。--output 指定時は同一内容をファイルにも書く。進捗・サマリーは stderr）:
#   scripts/check-bench-regression.sh の results.json スキーマ（schema_version: 1・
#   metrics.<name>.{value(>0), unit}）と互換。ランタイム・bundle の絶対パスは出力に含めない。
#
# セキュリティ: 引数は許可リストで検証し、ランタイムは配列で直接 exec する（eval・
# sh -c・文字列連結なし）。sudo は内部で呼ばない（root を要する実測は人間が明示実行する）。
# 各ランタイム呼び出しは timeout で上限を掛け、ログ出力量にも上限（ulimit -f）を掛ける（REPAIR-5）。

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
for tool in jq timeout mktemp tail rm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing-prerequisite" "required tool not found: $tool"
    exit "$EXIT_PREREQ"
  fi
done

tmpdir="$(mktemp -d)"
seq_no=0
# 現在作成済みで未削除のコンテナ ID（1 試行につき 1 つ）と、削除できなかった ID の一覧。
live_id=""
# create 試行中（成否未確定）は 1。create 失敗でコンテナが未作成だった場合、OCI 準拠
# ランタイムは存在しない ID の delete を拒否するため、残存確認（state）できた場合だけ
# 後始末失敗とする。create 成功後は 0（delete 失敗は常に後始末失敗）。
live_unverified=0
leftover_ids=()
rc=0

# ランタイム呼び出し本体。stdout/stderr はログファイルへ逃がす（コンテナ側が
# パイプを保持して create が戻らないランタイムへの対策）。stdin は /dev/null。
# 引数: <ログファイル> <ランタイム引数...>
run_rt() {
  local log="$1"
  shift
  local status=0
  # サブシェルで ulimit -f を掛け、出力量が上限を超えたら SIGXFSZ で失敗させる
  # （--timeout は出力量を制限しないため）。上限はサブシェル内に閉じる。
  (
    ulimit -f "$LOG_MAX_KIB"
    exec timeout --kill-after="$KILL_AFTER_SECS" "$timeout_secs" "$runtime" "$@" </dev/null >"$log" 2>&1
  ) || status=$?
  return "$status"
}

# --- ランタイム呼び出し部（CLI 契約が変わった場合はこの 4 関数のみ差し替える） ---
rt_create() { run_rt "$1" create --bundle "$bundle" "$2"; }
rt_start() { run_rt "$1" start "$2"; }
rt_delete() { run_rt "$1" delete "$2"; }
rt_kill() { run_rt "$1" kill "$2" KILL; }
rt_state() { run_rt "$1" state "$2"; }
# ---------------------------------------------------------------------------

# 失敗したコマンドのログ末尾を stderr へ出す。
show_log() {
  echo "--- last output of failed runtime command ---" >&2
  tail -n "$LOG_TAIL_LINES" -- "$1" >&2 || true
}

# コンテナを削除する。失敗時は kill → delete を試み、それでも残れば leftover に記録する。
# 引数: <id> [probe]（probe=1 のときは削除失敗後に state で実在を確認し、
# 応答が不存在を明示した場合のみ create が何も作らなかったとみなして成功扱いにし、照会不能なら残存扱い）
finish_container() {
  local id="$1" probe="${2:-0}"
  local log="$tmpdir/cleanup-$id.log"
  if rt_delete "$log" "$id"; then
    return 0
  fi
  rt_kill "$log" "$id" || true
  if rt_delete "$log" "$id"; then
    return 0
  fi
  if [ "$probe" = "1" ]; then
    local st=0
    rt_state "$log" "$id" || st=$?
    if [ "$st" -eq 0 ]; then
      : # コンテナが実在するので残存扱い（下で leftover へ記録）
    elif [ "$st" -ne 124 ] && [ "$st" -ne 137 ] && grep -qiE 'does not exist|not found|no such container' -- "$log"; then
      # state の応答が不存在を明示した場合だけ「create が何も作らなかった」とみなす。
      # タイムアウト・権限エラー等の照会不能は残存の可能性ありとして扱う（特権操作の後始末）。
      return 0
    else
      echo "warning: could not verify container absence for $id (state exit $st); assuming it may be left behind" >&2
    fi
  fi
  leftover_ids+=("$id")
  return 1
}

# EXIT / INT / TERM で呼ばれる後始末。未削除のコンテナを削除し、一時ディレクトリを消す。
# 後始末に失敗した場合は他の終了コードより優先して exit 4 にする。
cleanup() {
  local final="$?"
  trap - EXIT INT TERM
  if [ -n "$live_id" ]; then
    # live_id は create 試行の直前に設定される（create 失敗で中途半端に残った場合も対象。
    # ただし create 未成功の間は state で実在を確認できた場合のみ残存扱い）。
    # delete 失敗時は finish_container が kill → delete を再試行し、それでも残れば
    # leftover_ids へ記録して下で exit 4 にする。
    finish_container "$live_id" "$live_unverified" || true
    live_id=""
    live_unverified=0
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

# 1 回分の計測。成功すると create_us・start_us・total_us をグローバルへ設定する。
# 引数: <id>。失敗時は非ゼロを返す（呼び出し側が exit 1 に変換する）。
measure_once() {
  local id="$1" t0 t1 t2
  t0="${EPOCHREALTIME/./}"
  # create が途中まで進んでから失敗・タイムアウトしても特権リソースが残り得るため、
  # 作成を試みた時点で後始末対象として保持する。失敗時の delete（kill → delete の再試行）と
  # 残存時の exit 4 は EXIT trap の cleanup が担う。
  live_id="$id"
  live_unverified=1
  if ! rt_create "$tmpdir/create.log" "$id"; then
    err "runtime-create-failed" "create failed or timed out for $id"
    show_log "$tmpdir/create.log"
    return 1
  fi
  live_unverified=0
  t1="${EPOCHREALTIME/./}"
  if ! rt_start "$tmpdir/start.log" "$id"; then
    err "runtime-start-failed" "start failed or timed out for $id"
    show_log "$tmpdir/start.log"
    return 1
  fi
  t2="${EPOCHREALTIME/./}"
  create_us=$((t1 - t0))
  start_us=$((t2 - t1))
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
  id="fandhe-startup-$$-$seq_no"
  create_us=0
  start_us=0
  total_us=0
  if ! measure_once "$id"; then
    rc="$EXIT_RUNTIME"
    break
  fi
  if ! finish_container "$id"; then
    live_id=""
    err "cleanup-failed" "could not delete container $id"
    exit "$EXIT_CLEANUP"
  fi
  live_id=""
  if [ "$run_no" -gt "$warmup" ]; then
    samples="$(jq -c --argjson c "$create_us" --argjson s "$start_us" --argjson t "$total_us" \
      '. + [{create_us: $c, start_us: $s, total_us: $t}]' <<<"$samples")"
  fi
  echo "  run $run_no/$total_runs: create=${create_us}us start=${start_us}us total=${total_us}us$([ "$run_no" -le "$warmup" ] && echo ' (warmup)')" >&2
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

printf '%s\n' "$result"
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
echo "startup_latency: p50=$(jq -r '.metrics.startup_latency_p50_ms.value' <<<"$result")ms over $iterations runs" >&2
