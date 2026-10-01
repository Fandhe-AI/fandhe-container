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
#   - Linux 専用（単調時計として /proc/uptime を使う。CORE-10 の比較対象も Linux）。各区間の
#     値は壁時計（EPOCHREALTIME）で測り、単調時計と照合して時計の変更を検出した回は失敗にする。
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
#   <runtime> delete <id>                      # 後始末（計測対象外。create 成功済みの ID のみ）。
#                                              # 失敗時は kill <id> KILL → 待機付き delete
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
#      ID が既に使用中、計測中の時計の変更を検出した
#   2: 入力エラー（引数・bundle・output の検証失敗）
#   3: 前提ツール欠如（Linux の /proc/uptime・bash 5 以上・jq・GNU timeout・GNU dd〔oflag=nofollow,nonblock〕・GNU ln〔-T〕・mktemp・sleep 等）
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
# 実行開始の観測と後始末は、複数回の呼び出し・待機をまとめて --timeout 秒の期限で縛る
# （後始末の delete 再試行には回数の上限も設ける。REPAIR-5）。

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
# start 復帰後に state で実行開始（running / stopped）を観測する照会の間隔（秒）。
# 打ち切りは --timeout 秒の観測期限だけで判定し（REPAIR-5）、照会回数は間隔により
# 期限 / 間隔 程度に収まる。観測点の上側推定は最大でこの間隔＋state 1 回分だけ遅れる。
readonly STATE_POLL_INTERVAL=0.01
readonly STATE_POLL_INTERVAL_US=10000
# kill 後に delete を再試行する最大回数と間隔（秒）。時間上限は --timeout 秒。
readonly DELETE_RETRY_MAX=100
readonly DELETE_RETRY_INTERVAL=0.1
readonly DELETE_RETRY_INTERVAL_US=100000
# 期限付きの呼び出し（実行開始の観測・後始末）で残り時間がこれ（マイクロ秒）を
# 下回ったらランタイムを呼ばずに打ち切る。
readonly MIN_CALL_BUDGET_US=100000
# 計測区間の壁時計と単調時計（/proc/uptime。分解能 10ms）の許容差（マイクロ秒）。
# 単調時計の読み取り 2 回分の丸め（各 10ms）に余裕を持たせた値。これを超える時計の
# 変更を検出して、その回を失敗にする。
readonly CLOCK_TOLERANCE_US=30000
# --output の祖先ディレクトリ検査でたどる段数の上限。
readonly PATH_DEPTH_MAX=256

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

# 壁時計の現在時刻（マイクロ秒）。計測区間の値（create_us 等）にだけ使う。EPOCHREALTIME は
# LC_ALL=C で小数点が "." に固定される。bash には高分解能の単調時計がなく、外部コマンドで
# 単調時計を読むと起動の遅延が各区間に上乗せされるため、分解能は壁時計で得て、時計の変更
# （時刻同期のステップ・手動変更）は mono_us との照合で検出する（measure_once）。
wall_us() {
  echo "${EPOCHREALTIME/./}"
}

# 単調時計の現在時刻（マイクロ秒。分解能 10ms）。Linux の /proc/uptime（CLOCK_BOOTTIME。
# 時計の変更の影響を受けない）を読む。期限（観測・後始末）の判定と、計測値の照合に使う。
# 自己テストだけが STARTUP_LATENCY_TEST_UPTIME_FILE で読み元を差し替える（時計の変更の再現用）。
mono_us() {
  local up rest
  read -r up rest <"${STARTUP_LATENCY_TEST_UPTIME_FILE:-/proc/uptime}" || return 1
  [[ "$up" =~ ^[0-9]+\.[0-9]{2}$ ]] || return 1
  up="${up/./}"
  echo $((10#$up * 10000))
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
# 引数のディレクトリ 1 つが、他のユーザーに中のエントリを差し替えられないことを確かめる。
# symlink でない実ディレクトリで、所有者が実行ユーザーか root で、group / other の書き込み権が
# ないか sticky ビット付き（sticky なら他人は自分のエントリを rename / unlink できない）で
# あること。find は引数の symlink を辿らない（-P）ため、symlink は -type d に一致せず拒否される。
dir_is_safe() {
  local d="$1" uid
  uid="$(id -u)"
  [ -n "$(find -P "$d" -maxdepth 0 -type d \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) ! -perm -1000 -print 2>/dev/null)" ]
}

# --output の親ディレクトリから / までの全ディレクトリが dir_is_safe であることを確かめる。
# パスに symlink を含むものは拒否する（論理パスと物理パスが一致すること）。sticky な共有
# ディレクトリ（/tmp 等）にある他人の symlink は、その所有者が検査後に差し替えられるため。
# これにより、一時ファイルの作成から公開まで（mktemp・chmod・dd・ln）の間に他のユーザーが
# パスを差し替えられないことを保証する（root での実測で別ファイルを変更させないため）。
# 祖先は dirname が変化しなくなる点（"/"。先頭が "//" のパスでは "//"）で止め、念のため
# 段数にも上限（PATH_DEPTH_MAX）を設ける（無限ループ防止）。
output_path_is_safe() {
  local logical physical d parent depth
  logical="$(cd -- "$1" && pwd -L)" || return 1
  physical="$(cd -- "$1" && pwd -P)" || return 1
  [ "$logical" = "$physical" ] || return 1
  d="$physical"
  depth=0
  while :; do
    dir_is_safe "$d" || return 1
    parent="$(dirname -- "$d")"
    [ "$parent" = "$d" ] && break
    depth=$((depth + 1))
    [ "$depth" -le "$PATH_DEPTH_MAX" ] || return 1
    d="$parent"
  done
  return 0
}

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
for tool in jq timeout mktemp tail rm sleep dd ln chmod find id; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing-prerequisite" "required tool not found: $tool"
    exit "$EXIT_PREREQ"
  fi
done
# 単調時計（mono_us）の読み元。Linux の /proc/uptime が必要。
if ! mono_us >/dev/null; then
  err "missing-prerequisite" "a readable /proc/uptime (Linux) is required as the monotonic clock"
  exit "$EXIT_PREREQ"
fi
# 出力先の祖先ディレクトリの検証は find・id を使うため前提ツールの確認後に行う。
if [ -n "$output" ] && ! output_path_is_safe "$output_dir"; then
  err "invalid-output" "the path of --output must not contain symlinks, and every directory above it must be owned by you or root and not writable by others (unless sticky)"
  exit "$EXIT_INPUT"
fi

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
# create が成功していれば 1。0 の間（create の成否未確定・失敗）は破壊的操作を送らず、
# state で未作成を確定できなければ残存の可能性ありとして報告する（finish_container）。
live_created=0
leftover_ids=()
rc=0
# create の終了コード（create 未成功時の未作成判定に使う）。
create_rc=0
# 複数回の呼び出しをまとめて縛る期限（マイクロ秒）。空でなければ run_rt は各呼び出しへ
# 残り時間だけを渡す（実行開始の観測ループと finish_container が設定・解除する。REPAIR-5）。
rt_deadline_us=""
# query_state の結果（終了コード・status）。
state_rc=0
state_status=""

# ランタイム呼び出し本体。stdout/stderr はファイルへ逃がす（コンテナ側がパイプを
# 保持して create が戻らないランタイムへの対策）。stdin は /dev/null。
# 引数: <stdout ファイル> <stderr ファイル（stdout と同じパスなら併合）> <ランタイム引数...>
# 時間上限: 通常は 1 呼び出しにつき --timeout 秒（TERM 後の KILL 猶予 KILL_AFTER_SECS 秒）。
# rt_deadline_us が設定されている間（実行開始の観測中・後始末中）は、TERM までの時間と KILL 猶予の合計が
# 期限までの残り時間に収まるよう配分し、残りが MIN_CALL_BUDGET_US 未満なら呼ばずに
# 124（timeout と同じ値）を返す。
run_rt() {
  local out="$1" errf="$2"
  shift 2
  local status=0 limit="$timeout_secs" grace="$KILL_AFTER_SECS"
  if [ -n "$rt_deadline_us" ]; then
    local rem g
    rem=$((rt_deadline_us - $(mono_us)))
    if [ "$rem" -lt "$MIN_CALL_BUDGET_US" ]; then
      return 124
    fi
    # KILL 猶予は残り時間の 1/10（最大 1 秒）とし、残りを TERM までの時間にする
    # （1 回目の呼び出しが期限のほぼ全体を使えるようにする）。
    g=$((rem / 10))
    [ "$g" -gt 1000000 ] && g=1000000
    limit="$(us_to_secs $((rem - g)))"
    grace="$(us_to_secs "$g")"
  fi
  # サブシェルで ulimit -f を掛け、出力量が上限を超えたら SIGXFSZ で失敗させる
  # （--timeout は出力量を制限しないため）。上限はサブシェル内に閉じる。
  (
    ulimit -f "$LOG_MAX_KIB"
    if [ "$out" = "$errf" ]; then
      exec timeout --kill-after="$grace" "$limit" "$runtime" "$@" </dev/null >"$out" 2>&1
    fi
    exec timeout --kill-after="$grace" "$limit" "$runtime" "$@" </dev/null >"$out" 2>"$errf"
  ) || status=$?
  return "$status"
}

# マイクロ秒を timeout(1) が受け付ける秒の小数表記にする（例: 1500000 -> 1.500000）。
us_to_secs() {
  printf '%d.%06d' $(($1 / 1000000)) $(($1 % 1000000))
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
# 合わせる。空行を除く全行が「code・message が文字列の JSON オブジェクト」で、code がすべて
# NOT_FOUND（1 行以上）の場合だけ真にする。自由文・不正な JSON・code が文字列でない行・
# 別の code が 1 行でも混ざれば判定不能として偽にする（runc 等の構造化エラーを持たない
# ランタイムは常に偽＝不明扱い）。CLI（TASK-79）のエラー形式が確定したらこの関数を合わせる。
rt_is_not_found() {
  jq -Rse '
    [split("\n")[] | select(length > 0)] as $lines
    | ($lines | length) > 0
      and all($lines[];
        (try fromjson catch null) as $o
        | ($o | type) == "object"
          and ($o.code | type) == "string" and ($o.message | type) == "string"
          and $o.code == "NOT_FOUND")' <"$1" >/dev/null 2>&1
}
# ---------------------------------------------------------------------------

# 失敗したコマンドのログ末尾を stderr へ出す。
show_log() {
  echo "--- last output of failed runtime command ---" >&2
  tail -n "$LOG_TAIL_LINES" -- "$1" >&2 || true
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

# コンテナを削除する。delete が失敗したら kill KILL を送り、プロセスの終了を待ちながら
# delete を再試行する（OCI の delete は実行中コンテナを拒否し、kill は終了を待たないため）。
# 後始末全体（state・delete・kill・再試行と待機）を開始時に決めた 1 つの期限（--timeout 秒）
# 内に収め、各ランタイム呼び出しには残り時間だけを渡す（run_rt。REPAIR-5）。再試行は
# DELETE_RETRY_MAX 回でも打ち切る。それでも残れば leftover_ids に記録して非ゼロを返す。
# 引数: <id> <created>
#   created=1: create 成功済み。OCI の create は ID 重複時に必ず失敗するため、この ID の
#              コンテナは今回作ったものであり、そのまま delete / kill を送る。
#   created=0: create 未成功。同じ ID のコンテナが見えても、今回の create が作ったもの
#              （途中まで作って失敗）か、照会後に別のプロセスが作ったもの（こちらの create は
#              ID 重複で失敗）かを区別できないため、delete / kill は一切送らない。state で
#              未作成（create_not_made）を確定できれば成功、できなければ残存の可能性ありとして
#              記録し、手動での確認を促す（所有を証明できないコンテナへ破壊的操作を送らない。
#              特権操作の後始末）。
finish_container() {
  local status=0
  rt_deadline_us=$(($(mono_us) + timeout_secs * 1000000))
  finish_container_within_deadline "$@" || status=$?
  rt_deadline_us=""
  return "$status"
}

# finish_container の本体（rt_deadline_us が設定された状態で呼ばれる）。
finish_container_within_deadline() {
  local id="$1" created="$2"
  local log="$tmpdir/cleanup-$id.log"
  if [ "$created" = "0" ]; then
    query_state "$id"
    if create_not_made; then
      return 0
    fi
    echo "warning: create did not succeed for $id and its absence could not be confirmed (state exit $state_rc, create exit $create_rc); not touching it because ownership cannot be proven, inspect it manually" >&2
    leftover_ids+=("$id")
    return 1
  fi
  if rt_delete "$log" "$id"; then
    return 0
  fi
  rt_kill "$log" "$id" || true
  local tries=0
  while [ "$tries" -lt "$DELETE_RETRY_MAX" ] && [ $((rt_deadline_us - $(mono_us))) -ge "$MIN_CALL_BUDGET_US" ]; do
    tries=$((tries + 1))
    if rt_delete "$log" "$id"; then
      return 0
    fi
    # 待機後に呼び出せる残り時間がなければ期限を越えて待たずに打ち切る。
    if [ $((rt_deadline_us - $(mono_us))) -lt $((DELETE_RETRY_INTERVAL_US + MIN_CALL_BUDGET_US)) ]; then
      break
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
    # live_id は create 試行の直前に設定される（create 失敗で中途半端に残った場合も対象）。
    # 削除できない・create 未成功で未作成を確定できない場合は finish_container が
    # leftover_ids へ記録し、下で exit 4 にする。
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
  local id="$1" t0 t1 ts t2 m0 m2 deadline wall_total mono_total diff
  # create 前に state を照会する（計測区間外）。存在を示せば create せずに中止する
  # （既存コンテナとの衝突を分かりやすく報告するため。安全性は finish_container が
  # create 未成功の ID に破壊的操作を送らないことで担保する）。
  query_state "$id"
  if [ "$state_rc" -eq 0 ]; then
    err "container-id-in-use" "container $id already exists; refusing to touch it"
    return 1
  fi
  m0="$(mono_us)"
  t0="$(wall_us)"
  # create が途中まで進んでから失敗・タイムアウトしても特権リソースが残り得るため、
  # 作成を試みた時点で後始末対象として保持する。create 成功後の失敗は delete（kill →
  # 待機付き delete）で片付け、create 未成功時は未作成を確定できなければ残存として報告する。
  # いずれも EXIT trap の cleanup が担い、残存時は exit 4 にする。
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
  t1="$(wall_us)"
  if ! rt_start "$tmpdir/start.log" "$id"; then
    err "runtime-start-failed" "start failed or timed out for $id"
    show_log "$tmpdir/start.log"
    return 1
  fi
  ts="$(wall_us)"
  state_polls=0
  # 観測期限は単調時計で決める（時計の変更で期限が延び縮みしないように）。
  deadline=$(($(mono_us) + timeout_secs * 1000000))
  while :; do
    state_polls=$((state_polls + 1))
    # 各照会には観測期限までの残り時間だけを渡す。残りがなければ呼ばずに 124 になる。
    rt_deadline_us="$deadline"
    query_state "$id"
    rt_deadline_us=""
    t2="$(wall_us)"
    m2="$(mono_us)"
    # 期限は照会完了時刻で判定する。running / stopped を観測した照会でも、完了が期限を
    # 過ぎていれば --timeout 内に観測できなかった計測として失敗にする（成功結果に混ぜない）。
    # 照会が時間切れ（124）になった場合も同じ扱いにする。
    if [ "$m2" -gt "$deadline" ] || [ "$state_rc" -eq 124 ]; then
      err "runtime-exec-not-observed" "container $id did not reach running/stopped within ${timeout_secs}s"
      return 1
    fi
    case "$state_status" in
      running | stopped) break ;;
      created) ;;
      *)
        err "runtime-state-failed" "state for $id failed or returned an unexpected status (exit $state_rc)"
        show_log "$tmpdir/state.err"
        return 1
        ;;
    esac
    # created のままなら間隔を空けて再照会する。待機後に照会 1 回分の残り時間
    # （MIN_CALL_BUDGET_US）が残らない場合は待たずに次の照会へ進み、最後の照会の時間を
    # 待機で失わないようにする（後始末の delete 再試行と同じ判定）。
    if [ $((deadline - $(mono_us))) -ge $((STATE_POLL_INTERVAL_US + MIN_CALL_BUDGET_US)) ]; then
      sleep "$STATE_POLL_INTERVAL"
    fi
  done
  # 壁時計の区間を単調時計と照合する。順序が逆転している、または全体の経過が単調時計と
  # CLOCK_TOLERANCE_US を超えて食い違う場合は、計測中に時計が変更されたとみなし、この回の
  # 値を結果に使わずに失敗にする（中央値・ベンチ比較を壊さない）。
  wall_total=$((t2 - t0))
  mono_total=$((m2 - m0))
  diff=$((wall_total - mono_total))
  [ "$diff" -lt 0 ] && diff=$((-diff))
  if [ "$t1" -lt "$t0" ] || [ "$ts" -lt "$t1" ] || [ "$t2" -lt "$ts" ] || [ "$diff" -gt "$CLOCK_TOLERANCE_US" ]; then
    err "clock-changed" "wall clock changed during the measurement of $id (wall ${wall_total}us vs monotonic ${mono_total}us); result discarded"
    return 1
  fi
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
  # 完成した結果だけを出力先に公開する（書き込みが途中で失敗しても不完全な JSON を
  # 出力先に残さない）。手順:
  #   1. 結果を非公開の tmpdir に書く。
  # 前提: output_path_is_safe により、出力先のディレクトリと祖先は他のユーザーがエントリを
  # 差し替えられない（以下のパス指定の操作が、今回作った一時ファイル以外を指さない）。
  #   2. 出力先と同じディレクトリに mktemp で一時ファイルを作る。mktemp は O_CREAT|O_EXCL で
  #      未使用の名前を作成して返すため、返されたパスは今回作った通常ファイルであり、既存の
  #      ファイルを再利用しない（失敗時に消してよいのはこのパスだけ）。
  #   3. dd で一時ファイルへ書き込み fsync する。oflag=nofollow で symlink を辿らず、
  #      oflag=nonblock で読み手のいない FIFO に差し替えられていても待たずに失敗する。
  #   4. ln -T（link(2)）で一時ファイルを出力先へ公開する。link は出力先が種別を問わず既に
  #      存在すれば EEXIST で失敗し、symlink を辿らず、-T によりディレクトリ内へも作らない。
  #   5. 一時ファイルを消す（成功時は出力先が同じ実体を指して残る）。
  # 失敗時は今回作成した一時ファイルだけを消して exit 2 にする。dd・ln には timeout で上限を
  # 掛ける（REPAIR-5）。出力先のパーミッションは umask に従う（mktemp の既定 0600 を直す）。
  printf '%s\n' "$result" >"$tmpdir/result.json"
  staging=""
  if ! staging="$(mktemp -- "$output_dir/.startup_latency.XXXXXXXXXX" 2>/dev/null)" || [ -z "$staging" ]; then
    err "output-write-failed" "could not create a temporary file next to --output"
    exit "$EXIT_INPUT"
  fi
  if ! chmod "$(printf '%04o' $((0666 & ~0$(umask))))" -- "$staging" ||
    ! timeout --kill-after="$KILL_AFTER_SECS" "$timeout_secs" \
      dd if="$tmpdir/result.json" of="$staging" conv=notrunc,fsync oflag=nofollow,nonblock status=none 2>/dev/null; then
    rm -f -- "$staging" || true
    err "output-write-failed" "could not write the --output file"
    exit "$EXIT_INPUT"
  fi
  if ! timeout --kill-after="$KILL_AFTER_SECS" "$timeout_secs" ln -T -- "$staging" "$output" 2>/dev/null; then
    rm -f -- "$staging" || true
    err "output-write-failed" "could not create --output file (it may already exist, or hard links are unsupported)"
    exit "$EXIT_INPUT"
  fi
  if ! rm -f -- "$staging"; then
    echo "warning: could not remove the temporary file next to --output" >&2
  fi
fi
printf '%s\n' "$result"
echo "startup_latency: p50=$(jq -r '.metrics.startup_latency_p50_ms.value' <<<"$result")ms over $iterations runs" >&2
