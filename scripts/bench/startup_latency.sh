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
# Docker 側の計測と own・Docker の統合レポートは TASK-46.2（#842）で本スクリプトの
# `--mode docker` / `--mode report` として追加した（下記「モード」）。
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
# 呼び出し元: Makefile の `startup-latency`・`startup-latency-docker`・`startup-latency-report`
# ターゲット（自己テストは scripts/bench/startup_latency_selftest.sh・
# `startup-latency-selftest` ターゲット）。
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
# モード（--mode。既定 oci。TASK-46.2・CORE-10）:
#   oci:    上記の own（OCI Runtime CLI 契約）計測。method = "create-to-exec-observed"。
#   docker: `docker run --rm --pull never ... --entrypoint true <image>` 全体の壁時計時間を計測する
#           （イメージの ENTRYPOINT は `--entrypoint true` で明示的に上書きし、固定ワークロードを保つ）
#           （spec の Docker ベースライン 0.290〜0.298 秒と同じ手法）。method = "docker-run-rm-total"。
#           --runtime は docker CLI の絶対パス。イメージは事前にローカルへ用意する（自動 pull
#           しない）。実行コマンドは `true` に固定する。
#   report: --own-result（oci の出力）と --docker-result（docker の出力）を 1 つの JSON に統合する。
#   計測区間の不一致（REPAIR-3: 実装済みを装わない）: oci は create 直前から state が
#   running / stopped を返すまで、docker は run 全体（プロセス終了・コンテナ削除・デーモン
#   経由のオーバーヘッドを含む）で区間が異なる。出力に method を記録し、レポートは
#   methods_differ: true を出す。合否判定（Conditional Go 条件 1）は出さず、#213（TASK-46.h1）
#   で人間が行う。区間をそろえる方法は spec 側の判断事項（TASK-46.2 の報告事項）。
#
# 使い方:
#   startup_latency.sh --runtime <絶対パス> --bundle <dir> --target <名前> [--iterations N]
#                      [--warmup N] [--timeout SECS] [--label NAME] [--output FILE]
#   --target は計測対象のランタイムの名前（own・runc 等）で、出力の target に記録する。
#   任意の実行ファイルを --runtime に渡せるため、取り違えを防ぐよう既定値を持たせず必須にする。
#   bundle は人間が用意する（rootfs と config.json。基準ワークロードは alpine:3.20 相当の
#   軽量プロセス。rootfs・config.json の生成は本スクリプトでは行わない）。
#   startup_latency.sh --mode docker --runtime <docker の絶対パス> --target <名前> [--image <ref>]
#                      [--iterations N] [--warmup N] [--timeout SECS] [--label NAME] [--output FILE]
#   startup_latency.sh --mode report --own-result <file> --docker-result <file> [--timeout SECS] [--output FILE]
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: ランタイムの create / start / state（docker モードは image inspect / run）の失敗・タイムアウト、実行開始を観測できない、
#      ID が既に使用中、計測中の時計の変更を検出した
#   2: 入力エラー（引数・bundle・output の検証失敗）
#   3: 前提ツール欠如（Linux の /proc/uptime・bash 5 以上・jq・GNU timeout・GNU dd〔oflag=nofollow,nonblock〕・GNU ln〔-T〕・mktemp・sleep 等）
#   4: 後始末失敗（作成済みコンテナを delete できない〔docker モードは cidfile の ID で rm -f できない、
#      ラベル一覧を取得できない・所有を証明できないコンテナが残っている〕、create 失敗後に未作成を確定できない等。
#      残存の可能性がある ID を stderr に出す。最優先）
#
# 出力（stdout。--output 指定時は同一内容をファイルにも書く。進捗・サマリーは stderr）:
#   scripts/check-bench-regression.sh の results.json スキーマ（schema_version: 1・
#   metrics.<name>.{value(>0), unit}）と互換（oci・docker 共通。mode・method を追加で持つ）。
#   ランタイム・bundle の絶対パスは出力に含めない。report モードの出力は
#   benchmark: "startup_latency_report"（results.{own,docker}・comparison・notes）。
#
# セキュリティ: 引数は許可リストで検証し、ランタイムは配列で直接 exec する（eval・
# sh -c・文字列連結なし）。sudo は内部で呼ばない（root を要する実測は人間が明示実行する）。
# 各ランタイム呼び出しは timeout で上限を掛ける。ログ出力量の上限は収集側（本スクリプトの
# 直接の子の収集プロセスが先頭 LOG_MAX_KIB KiB だけ記録し、超過分は読み捨てる）で掛け、
# ランタイムとその子孫（コンテナのワークロード）には rlimit を一切掛けない（RLIMIT_FSIZE は
# exec で継承され、ワークロードの書き込みが失敗して計測条件が変わるため）。
# 後始末（EXIT・INT・TERM・HUP で起動）の間は INT・TERM・HUP を無処理にして後始末を最後まで
# 行う。終了コードは後始末の後に決め、残存があれば 4 を優先し、なければ最初に受けた
# シグナルの 128+N（INT=130・TERM=143・HUP=129）を返す。bash は前景の子（timeout＋ランタイム）が
# 戻るまで trap を実行しないため、1 回目のシグナルは進行中のランタイム呼び出しが戻ってから効く
# （最大で期限まで。背景起動＋wait による即応化は範囲外）。
# 実行開始の観測と後始末は、複数回の呼び出し・待機をまとめて --timeout 秒の期限で縛る
# （後始末の delete 再試行には回数の上限も設ける。REPAIR-5）。
# docker モードの後始末は「所有の証明」で分ける。今回の docker client が cidfile に書いた
# 64 桁 16 進 ID だけを `rm -f` する。cidfile がなければラベルの一覧が空のときだけ未作成と
# みなし、1 件でも見つかれば所有を証明できないので何も送らず exit 4 にする
# （--filter name= は部分一致のため使わない。ラベルの key=value は完全一致）。
# docker の終了コード 125 は GNU timeout の 125 と重なるため、is_runtime_error は使わない。
# report モードの入力 JSON は非信頼として検証する（symlink 拒否・サイズ上限・スキーマ・mode・値）。

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
# 収集プロセスがランタイム 1 呼び出しあたりログファイルへ記録する最大サイズ（KiB）。
# 超過分は読み捨てる（ディスク枯渇防止。REPAIR-5）。書き手は止めない。
readonly LOG_MAX_KIB=1024
# 状態・一覧など出力を解析する呼び出しの後に、その出力の収集プロセスの終了を待つ上限（マイクロ秒）。
# 超えたら出力が不完全になり得るので、その呼び出しを失敗として扱う（fail-closed）。
readonly LOG_FLUSH_WAIT_US=200000
# 後始末で収集プロセスの自然終了を待つ上限（マイクロ秒）。超えたら SIGKILL で回収する。
readonly LOG_REAP_WAIT_US=500000
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
# report モードで読む入力 JSON の最大サイズ（バイト。jq に渡す前に検査する）。
readonly RESULT_MAX_BYTES=1048576

usage() {
  cat >&2 <<'USAGE'
usage: startup_latency.sh [--mode oci|docker|report] [options]
  --mode <name>        oci (default), docker, or report
  --runtime <path>     oci: OCI runtime executable / docker: docker CLI (absolute path, required)
  --bundle <dir>       OCI bundle directory containing config.json (oci mode only, required there)
  --image <ref>        image to run in docker mode (default: alpine:3.20; must exist locally)
  --own-result <file>  report mode: result JSON of an oci-mode run (required there)
  --docker-result <file> report mode: result JSON of a docker-mode run (required there)
  --target <name>      name of the measured runtime recorded as "target" (required except report mode, e.g. own, docker)
  --iterations <1-1000> measured iterations (default: 10)
  --warmup <0-100>     warmup iterations excluded from statistics (default: 1)
  --timeout <1-60>     per runtime command timeout in seconds (default: 10)
  --label <name>       label recorded in the output (default: same as --target)
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

mode="oci"
image=""
own_result=""
docker_result=""
runtime=""
bundle=""
iterations=10
warmup=1
timeout_secs=10
label=""
target=""
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
    --mode | --image | --own-result | --docker-result | --runtime | --bundle | --target | --iterations | --warmup | --timeout | --label | --output)
      opt="$1"
      if [ "$#" -lt 2 ]; then
        err "missing-value" "$opt requires a value"
        exit "$EXIT_INPUT"
      fi
      take_value "$opt"
      case "$opt" in
        --mode) mode="$2" ;;
        --image) image="$2" ;;
        --own-result) own_result="$2" ;;
        --docker-result) docker_result="$2" ;;
        --runtime) runtime="$2" ;;
        --bundle) bundle="$2" ;;
        --iterations) iterations="$2" ;;
        --warmup) warmup="$2" ;;
        --timeout) timeout_secs="$2" ;;
        --label) label="$2" ;;
        --target) target="$2" ;;
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

# モードと引数の組み合わせの検証（前提ツールの検証より前。違反は exit 2）。
case "$mode" in
  oci | docker | report) ;;
  *)
    err "invalid-mode" "--mode must be one of: oci, docker, report"
    exit "$EXIT_INPUT"
    ;;
esac
# 指定済みのオプション（seen_opts）が、現在のモードで許可されていなければ拒否する。
reject_opts() {
  local o
  for o in "$@"; do
    if [[ "$seen_opts" == *" $o "* ]]; then
      err "invalid-option-for-mode" "$o cannot be used with --mode $mode"
      exit "$EXIT_INPUT"
    fi
  done
}
case "$mode" in
  oci) reject_opts --image --own-result --docker-result ;;
  docker) reject_opts --bundle --own-result --docker-result ;;
  report) reject_opts --runtime --bundle --image --iterations --warmup --target --label ;;
esac

if [ "$mode" != "report" ]; then
  if [ -z "$runtime" ]; then
    err "missing-runtime" "--runtime is required"
    exit "$EXIT_INPUT"
  fi
  if [[ "$runtime" != /* ]] || [ ! -f "$runtime" ] || [ ! -x "$runtime" ]; then
    err "invalid-runtime" "--runtime must be an absolute path to an executable file"
    exit "$EXIT_INPUT"
  fi
  if [ "$mode" = "oci" ] && [ -z "$bundle" ]; then
    err "missing-bundle" "--bundle is required"
    exit "$EXIT_INPUT"
  fi
  if [ -z "$target" ]; then
    err "missing-target" "--target is required (name of the measured runtime, e.g. own)"
    exit "$EXIT_INPUT"
  fi
  if ! [[ "$target" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
    err "invalid-target" "target must match ^[A-Za-z0-9._-]{1,32}$"
    exit "$EXIT_INPUT"
  fi
fi
if [ "$mode" = "oci" ]; then
  if [ -L "$bundle" ] || [ ! -d "$bundle" ]; then
    err "invalid-bundle" "--bundle must be an existing directory (symlink not allowed)"
    exit "$EXIT_INPUT"
  fi
  if [ -L "$bundle/config.json" ] || [ ! -f "$bundle/config.json" ]; then
    err "invalid-bundle" "bundle must contain a regular file config.json (symlink not allowed)"
    exit "$EXIT_INPUT"
  fi
fi
if [ "$mode" = "docker" ]; then
  # 既定イメージは spec のベースライン（CORE-10）と同じ alpine:3.20。先頭が英数字で、
  # 空白・シェルのメタ文字・先頭 "-"（オプション注入）を許さない許可リストで検証する。
  [ -n "$image" ] || image="alpine:3.20"
  if ! [[ "$image" =~ ^[a-z0-9][a-z0-9._/:@-]{0,127}$ ]]; then
    err "invalid-image" "image must match ^[a-z0-9][a-z0-9._/:@-]{0,127}\$"
    exit "$EXIT_INPUT"
  fi
fi
if [ "$mode" = "report" ]; then
  if [ -z "$own_result" ] || [ -z "$docker_result" ]; then
    err "missing-result" "--own-result and --docker-result are required with --mode report"
    exit "$EXIT_INPUT"
  fi
fi
check_int iterations "$iterations" 1 1000
check_int warmup "$warmup" 0 100
check_int timeout "$timeout_secs" 1 60
# ラベルの既定値は計測対象名（target と label が食い違って取り違えないように）。
if [ -z "$label" ]; then
  label="$target"
fi
if [ "$mode" != "report" ] && ! [[ "$label" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
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
  # 先頭の連続した "/"（"//" は処理系定義で、Linux では "/" と同じ）を 1 つにそろえてから
  # 比べる（pwd -L / -P で "//" の扱いが異なる環境でも symlink と誤認しない）。
  while [[ "$logical" == //* ]]; do logical="${logical#/}"; done
  while [[ "$physical" == //* ]]; do physical="${physical#/}"; done
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
for tool in jq timeout mktemp tail rm sleep dd ln chmod find id wc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing-prerequisite" "required tool not found: $tool"
    exit "$EXIT_PREREQ"
  fi
done
# 単調時計（mono_us）の読み元。Linux の /proc/uptime が必要。
if [ "$mode" != "report" ] && ! mono_us >/dev/null; then
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
# docker モードで現在の試行の cidfile（docker client が作成したコンテナ ID を書く。所有の証明に使う）。
live_cidfile=""
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
# run_rt が起動した収集プロセスの pid（全件は cleanup が回収する。直前の 1 呼び出し分は flush_last_call が待つ）。
collector_pids=()
last_collector_pids=()
# query_state で state の復帰直後（収集の完了待ちの前）に取った時刻。実行開始の観測点に使う。
state_wall_us=0
state_mono_us=0

# 収集プロセス（run_rt が起動する、本スクリプトの直接の子）。ランタイムの出力をパイプで受け、
# 先頭 LOG_MAX_KIB KiB だけをファイルへ書き、残りは EOF まで読み捨てる。書き手（ランタイムと
# コンテナのワークロード）の書き込みを止めず SIGPIPE も起こさないので、ランタイム側に rlimit
# （RLIMIT_FSIZE）を掛ける必要がない。端末の Ctrl+C・外側 timeout のプロセスグループ宛て
# シグナルで死ぬとワークロードが SIGPIPE を受けるため INT / TERM / HUP は無視する
# （GNU timeout は自身のプロセスグループを作るので、期限切れのシグナルの対象にもならない）。
# 超過時は stderr へ警告を 1 行出す。引数: <記録先ファイル>
log_collect() {
  trap '' INT TERM HUP
  local extra dd_target="$1" ok=1
  # 自己テストだけが、指定ファイル名の記録先を /dev/full へ差し替えて ENOSPC を再現する。
  [ -n "${STARTUP_LATENCY_TEST_COLLECT_FULL:-}" ] && [ "${1##*/}" = "$STARTUP_LATENCY_TEST_COLLECT_FULL" ] && dd_target=/dev/full
  # dd は読めた分をその都度 write するので、書き手が EOF にならなくても到着済みの出力をファイルで読める
  # （head -c は stdout を stdio 経由でバッファし、終了時まで書き出さない。REPAIR-4）。
  # 書き込み失敗（ENOSPC 等）は完了目印を置かないことで親へ伝える（log_incomplete。fail-closed）。
  dd of="$dd_target" bs=4096 iflag=count_bytes count="$((LOG_MAX_KIB * 1024))" status=none 2>/dev/null || ok=0
  extra="$(wc -c)" || extra=0
  extra="${extra//[!0-9]/}"
  if [ "${extra:-0}" -gt 0 ]; then
    # 解析側が不完全な出力を受理しないよう、切り詰めた事実を目印ファイルで親へ伝える（log_truncated）。
    : >"$1.truncated" 2>/dev/null || ok=0
    echo "warning: runtime-log-truncated: ${1##*/} limit_kib=$LOG_MAX_KIB" >&2
  fi
  # 完了目印は記録に成功したときだけ置く。置けなければ未完了として扱われる。
  if [ "$ok" -eq 1 ]; then : >"$1.done" 2>/dev/null || true; fi
}

# 記録先ファイルの収集が正常に完了していないか（書き込み失敗・収集プロセスの異常終了・未終了）。
# 解析する呼び出しは flush_last_call の後にこれを見て、完了目印がなければ出力を受理しない
# （空に見える出力を「正常な空」と誤認して不存在を確定しない。fail-closed）。引数: <記録先ファイル>
log_incomplete() {
  [ ! -e "$1.done" ]
}

# 記録先ファイルが上限超過で切り詰められたか（log_collect が置く目印）。解析する呼び出しだけが
# 参照し、切り詰められた出力は判定不能として扱う（診断用ログの読み捨ては維持する）。引数: <記録先ファイル>
log_truncated() {
  [ -e "$1.truncated" ]
}

# pid が本スクリプトの生きている直接の子か（pid の再利用による誤爆を避けるため /proc の親 pid で確かめる）。
child_alive() {
  local line st ppid
  { read -r line </proc/"$1"/stat; } 2>/dev/null || return 1
  read -r st ppid _ <<<"${line##*) }"
  [ "$ppid" = "$$" ] && [ "$st" != "Z" ]
}

# 引数の pid がすべて終了するのを最大 <budget_us> 待つ（時計に依存せず、回数で上限を掛ける）。
# 終了していれば 0、時間切れなら 1。引数: <budget_us> <pid...>
wait_children() {
  local budget="$1" p alive spins=0 sleeps
  shift
  [ "$#" -gt 0 ] || return 0
  [ "$budget" -gt 0 ] || budget=0
  sleeps=$((budget / 5000))
  while :; do
    alive=0
    for p in "$@"; do
      if child_alive "$p"; then alive=1; break; fi
    done
    [ "$alive" -eq 0 ] && return 0
    # 最初の数百回は組み込みだけで確認し、起動直後の終了を待つために fork しない。
    if [ "$spins" -lt 300 ]; then
      spins=$((spins + 1))
      continue
    fi
    [ "$sleeps" -gt 0 ] || return 1
    sleeps=$((sleeps - 1))
    sleep 0.005
  done
}

# 直前の run_rt の収集プロセスの終了を待つ。出力を解析する呼び出しの直後にだけ使う。
# 待機の上限は LOG_FLUSH_WAIT_US と、期限（rt_deadline_us）までの残りの小さい方。
# create / start / delete 等の直後には使わない: runc 系の create は init がランタイムの stdio を
# 保持するため収集プロセスがコンテナの終了まで EOF にならず、待つと create_us が待機上限分だけ
# 水増しされる（それらの出力は失敗時の診断にしか使わない）。
flush_last_call() {
  local budget="$LOG_FLUSH_WAIT_US" rem
  if [ -n "$rt_deadline_us" ]; then
    rem=$((rt_deadline_us - $(mono_us)))
    [ "$rem" -lt "$budget" ] && budget="$rem"
  fi
  wait_children "$budget" "${last_collector_pids[@]}"
}

# ランタイム呼び出し本体。stdout/stderr は収集プロセス（log_collect）経由でファイルへ記録する
# （コンテナ側がパイプを保持して create が戻らないランタイムへの対策。ログ量は収集側で制限）。
# stdin は /dev/null。待つのは timeout（直接の子）の終了だけで、ランタイムの子孫が出力を開いたまま
# 残っても EOF や子孫の終了は待たない（出力が必要な呼び出しだけ flush_last_call で待つ）。
# 期限切れ時は GNU timeout が自身のプロセスグループ（ランタイムと、別グループへ移っていない
# 子孫）へシグナルを送る。create が起動したコンテナのプロセスの後始末は delete / kill が担う。
# 引数: <stdout ファイル> <stderr ファイル（stdout と同じパスなら併合）> <ランタイム引数...>
# 時間上限: 通常は 1 呼び出しにつき --timeout 秒（TERM 後の KILL 猶予 KILL_AFTER_SECS 秒）。
# rt_deadline_us が設定されている間（実行開始の観測中・後始末中）は、TERM までの時間と KILL 猶予の合計が
# 期限までの残り時間に収まるよう配分し、残りが MIN_CALL_BUDGET_US 未満なら呼ばずに
# 124（timeout と同じ値）を返す。収集プロセスは cleanup が回収する（collector_pids）。
# 計測区間への影響: 収集プロセスの fork は計時点の内側で行われ、oci・docker の両モードに
# 一律に上乗せされる（process substitution の fork 1〜2 回分）。
run_rt() {
  local out="$1" errf="$2"
  shift 2
  local status=0 limit="$timeout_secs" grace="$KILL_AFTER_SECS" ofd efd
  last_collector_pids=()
  rm -f -- "$out.truncated" "$errf.truncated" "$out.done" "$errf.done"
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
  exec {ofd}> >(log_collect "$out" >/dev/null)
  last_collector_pids+=("$!")
  collector_pids+=("$!")
  if [ "$out" = "$errf" ]; then
    timeout --kill-after="$grace" "$limit" "$runtime" "$@" </dev/null >&"$ofd" 2>&1 {ofd}>&- || status=$?
  else
    exec {efd}> >(log_collect "$errf" >/dev/null)
    last_collector_pids+=("$!")
    collector_pids+=("$!")
    timeout --kill-after="$grace" "$limit" "$runtime" "$@" </dev/null >&"$ofd" 2>&"$efd" {ofd}>&- {efd}>&- || status=$?
    exec {efd}>&-
  fi
  exec {ofd}>&-
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
  # 観測点は state の復帰直後に取る（下の収集の完了待ちを区間に含めない）。
  state_wall_us="$(wall_us)"
  state_mono_us="$(mono_us)"
  # 出力（stdout の JSON と、不存在判定に使う stderr）を読む前に収集の完了を待つ。上限内に
  # 終わらなければ出力が不完全になり得るので失敗として扱う（fail-closed。124 は維持する）。
  if ! flush_last_call && [ "$state_rc" -ne 124 ]; then
    state_rc=125
  fi
  # 切り詰められた応答は不完全なので解析しない（先頭が有効でも後続が捨てられている）。
  if { log_truncated "$out" || log_incomplete "$out" || log_incomplete "$tmpdir/state.err"; } && [ "$state_rc" -ne 124 ]; then
    state_rc=125
  fi
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
  # stderr が切り詰められていれば NOT_FOUND の後ろの別エラーが捨てられ得るので不明とする。
  ! log_truncated "$tmpdir/state.err" || return 1
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

# --- docker 呼び出し部（docker CLI の差分が出たらこの 4 関数のみ差し替える。TASK-46.2） ---
# docker のラベル（key=value は完全一致）。--filter name= は部分一致のため所有判定に使わない。
readonly DOCKER_LABEL_KEY="fandhe.startup-latency.run"
# 計測対象。--pull never はイメージ未取得時に暗黙の pull（ネットワーク・計測の歪み）をさせない。
# 実行コマンドは `true` に固定し、任意コマンドを受け付けない。引数: <log> <cidfile> <name>
dk_run() { run_rt "$1" "$1" run --rm --pull never --cidfile "$2" --name "$3" --label "$DOCKER_LABEL_KEY=$run_tag" --entrypoint true "$image"; }
# 所有を証明した ID（cidfile の 64 桁 16 進）だけに送る。引数: <log> <cid>
dk_rm() { run_rt "$1" "$1" rm -f "$2"; }
# この実行のラベルが付いた全コンテナ ID（停止中を含む）。引数: <stdout> <stderr>
dk_list_by_label() { run_rt "$1" "$2" ps -a -q --no-trunc --filter "label=$DOCKER_LABEL_KEY=$run_tag"; }
# イメージがローカルにあるか。引数: <log>
dk_image_present() { run_rt "$1" "$1" image inspect --format '{{.Id}}' "$image"; }
# ---------------------------------------------------------------------------

# cidfile から docker client が書いたコンテナ ID を読む。64 桁の 16 進数（小文字）だけを
# 今回作成した証明として返す（それ以外・未作成・symlink は空）。ID は docker が cidfile へ
# 書く値で、コンテナ作成時に client 自身が得たものなので、この ID は今回の run のものと言える。
read_cidfile() {
  local f="$1" line=""
  if [ -n "$f" ] && [ ! -L "$f" ] && [ -f "$f" ]; then
    IFS= read -r -n 128 line <"$f" || true
  fi
  if [[ "$line" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s' "$line"
  fi
}

# dk_list_by_label の結果を listed_ids（64 桁 16 進の ID 配列）へ入れる。取得失敗・想定外の
# 出力は非ゼロを返す（未作成を確定できない）。呼び出しは期限内（rt_deadline_us 設定中）で行う。
list_run_containers() {
  local out="$tmpdir/list.out" line rc=0
  listed_ids=()
  dk_list_by_label "$out" "$tmpdir/list.err" || rc=$?
  # 出力を読む前に収集の完了を待つ（上限内に終わらなければ不完全として失敗。fail-closed）。
  flush_last_call || return 1
  [ "$rc" -eq 0 ] || return 1
  # 切り詰められた一覧は不完全（未作成を誤って確定し得る）なので失敗として扱う。
  ! log_truncated "$out" || return 1
  # 記録に失敗した（ENOSPC 等）出力は空でも「コンテナなし」を意味しない。
  ! log_incomplete "$out" || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    [[ "$line" =~ ^[0-9a-f]{64}$ ]] || return 1
    listed_ids+=("$line")
  done <"$out"
  return 0
}

# docker モードの後始末（finish_container の docker 版）。全体を --timeout 秒の 1 つの期限に
# 収める（REPAIR-5）。引数: <name> <cidfile>
#   cidfile に有効な ID がある: 今回の run が作ったコンテナと証明できる。--rm で削除済みなら
#     何もしない。残っていれば `rm -f <cid>` を期限と回数の上限内で再試行する。
#   cidfile がない・不正: ラベル一覧が空なら未作成とみなす。1 件でも見つかれば所有を証明
#     できないので何も送らず exit 4 の対象にする。一覧の取得失敗も未作成を確定できないので同様。
finish_container_docker() {
  local status=0
  rt_deadline_us=$(($(mono_us) + timeout_secs * 1000000))
  finish_container_docker_within_deadline "$@" || status=$?
  rt_deadline_us=""
  return "$status"
}

finish_container_docker_within_deadline() {
  local id="$1"
  local cid log="$tmpdir/cleanup-$id.log" tries=0 present x
  cid="$(read_cidfile "$2")"
  if [ -z "$cid" ]; then
    if ! list_run_containers; then
      echo "warning: could not list containers labeled $DOCKER_LABEL_KEY=$run_tag for $id; absence cannot be confirmed, inspect it manually" >&2
      leftover_ids+=("$id")
      return 1
    fi
    if [ "${#listed_ids[@]}" -eq 0 ]; then
      return 0
    fi
    echo "warning: containers labeled $DOCKER_LABEL_KEY=$run_tag exist but no valid cidfile proves ownership; not touching them, inspect manually" >&2
    leftover_ids+=("${listed_ids[@]}")
    return 1
  fi
  while [ "$tries" -lt "$DELETE_RETRY_MAX" ]; do
    tries=$((tries + 1))
    # 一覧の取得に失敗したら残存状態を確認できないので、削除せず未確認として exit 4 の対象にする
    # （fail-closed。daemon 接続失敗等で盲目的に rm -f しない）。
    if ! list_run_containers; then
      echo "warning: could not list containers labeled $DOCKER_LABEL_KEY=$run_tag for $id; leftover state of $cid cannot be confirmed, not removing it, inspect manually" >&2
      leftover_ids+=("$cid")
      return 1
    fi
    present=0
    for x in "${listed_ids[@]}"; do
      [ "$x" = "$cid" ] && present=1
    done
    # --rm で削除済み（一覧が取れて ID がない）なら完了。
    [ "$present" -eq 0 ] && return 0
    if dk_rm "$log" "$cid"; then
      return 0
    fi
    if [ $((rt_deadline_us - $(mono_us))) -lt $((DELETE_RETRY_INTERVAL_US + MIN_CALL_BUDGET_US)) ]; then
      break
    fi
    sleep "$DELETE_RETRY_INTERVAL"
  done
  leftover_ids+=("$cid")
  return 1
}

# pid の起動時刻（/proc/<pid>/stat の starttime。clock tick 単位）を標準出力へ出す。読めなければ
# 非 0 で何も出さない。stat の comm 欄は空白や ')' を含み得るため、最後の ') ' より後ろで区切る
# （その後ろの先頭が state=3 欄目なので starttime=22 欄目は 20 番目）。引数: <pid>
proc_starttime() {
  local line rest
  { read -r line <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${line##*) }"
  # shellcheck disable=SC2086
  set -- $rest
  [ -n "${20:-}" ] || return 1
  echo "${20}"
}

# pid の起動時刻が列挙時のもの（<pid>:<starttime> 形式の引数）と一致するときだけ SIGKILL を送る。
# 列挙後に pid が終了して再利用された場合や、起動時刻を確認できない場合は何も送らない（無関係な
# プロセスを kill しない）。引数: <pid:starttime>
kill_if_same() {
  local p="${1%%:*}" st="${1#*:}" now
  case "$p" in '' | *[!0-9]*) return 0 ;; esac
  { [ -n "$st" ] && [ "$st" != "$1" ]; } || return 0
  now="$(proc_starttime "$p")" || return 0
  [ "$now" = "$st" ] || return 0
  kill -KILL "$p" 2>/dev/null || true
}

# pid の子孫（再帰）を /proc の親 pid から列挙して標準出力へ 1 行 1 件（<pid>:<starttime>）で出す。
# 収集プロセスは dd / wc（コマンド置換内）を子に持つので、親を殺す前に列挙する。起動時刻は
# kill_if_same が送信直前に照合する。引数: <pid>
descendant_pids() {
  local f line ppid p q rest
  local -a pids=() ppids=() starts=() queue=("$1")
  for f in /proc/[0-9]*/stat; do
    { read -r line <"$f"; } 2>/dev/null || continue
    p="${f#/proc/}"
    p="${p%/stat}"
    rest="${line##*) }"
    # shellcheck disable=SC2086
    set -- $rest
    [ -n "${20:-}" ] || continue
    pids+=("$p")
    ppids+=("$2")
    starts+=("${20}")
  done
  while [ "${#queue[@]}" -gt 0 ]; do
    q="${queue[0]}"
    queue=("${queue[@]:1}")
    for f in "${!pids[@]}"; do
      if [ "${ppids[$f]}" = "$q" ]; then
        echo "${pids[$f]}:${starts[$f]}"
        queue+=("${pids[$f]}")
      fi
    done
  done
}

# 収集プロセスを回収する。コンテナの処理を終えた後（削除済みなら出力の書き手が閉じて自然に
# 終わる）に呼び、LOG_REAP_WAIT_US 待って残るものを SIGKILL する。コンテナの削除前には
# 呼ばない（ワークロードが SIGPIPE を受けるため）。pid は child_alive で自分の子と確かめてから
# 送る。残存は終了コードに影響させない（計測対象ではなく、本スクリプトの直接の子のため）。
reap_collectors() {
  local p
  [ "${#collector_pids[@]}" -gt 0 ] || return 0
  wait_children "$LOG_REAP_WAIT_US" "${collector_pids[@]}" || true
  for p in "${collector_pids[@]}"; do
    if child_alive "$p"; then
      # 子孫（読み取り中の dd / wc）は親の死後に孤児として残るので、先に列挙してから親→子孫の順に KILL する。
      local desc d
      desc="$(descendant_pids "$p")"
      kill -KILL "$p" 2>/dev/null || true
      for d in $desc; do
        kill_if_same "$d"
      done
    fi
  done
  wait "${collector_pids[@]}" 2>/dev/null || true
  collector_pids=()
}

# EXIT で呼ばれる後始末（INT / TERM / HUP は on_signal が exit して EXIT 経由で入る）。未削除の
# コンテナを削除し、収集プロセスを回収して一時ディレクトリを消す。後始末の間に届く INT / TERM /
# HUP は無処理（':'）にして中断させず、終了コードは後始末の後に決める（最初のシグナルの 128+N か
# 本来の終了コード。後始末に失敗した場合は他の終了コードより優先して 4。concurrent_50_memory.sh と同じ方式）。
cleanup() {
  local final="$?"
  # 先にシグナルを無処理にしてから EXIT trap を外す（逆順だと、その間に届いたシグナルの既定動作で
  # 後始末を通らずに終了する）。'' ではなく ':' を使うのは、'' の無視が子へ継承され、後始末中に
  # 起動するランタイムが TERM を無視してしまうため（':' は子では既定動作に戻る）。
  trap ':' TERM INT HUP
  trap - EXIT
  # 自己テスト専用: 後始末中の 2 回目のシグナルを決定的に再現する（許可リストで検証）。
  case "${STARTUP_LATENCY_TEST_SIGNAL_IN_CLEANUP:-}" in
    INT | TERM | HUP) kill -s "$STARTUP_LATENCY_TEST_SIGNAL_IN_CLEANUP" "$$" || true ;;
    *) ;;
  esac
  if [ -n "$live_id" ]; then
    # live_id は create 試行の直前に設定される（create 失敗で中途半端に残った場合も対象）。
    # 削除できない・create 未成功で未作成を確定できない場合は finish_container が
    # leftover_ids へ記録し、下で exit 4 にする。
    if [ "$mode" = "docker" ]; then
      finish_container_docker "$live_id" "$live_cidfile" || true
    else
      finish_container "$live_id" "$live_created" || true
    fi
    live_id=""
    live_created=0
    live_cidfile=""
  fi
  reap_collectors
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

# INT / TERM / HUP を受けたら 128+N で exit し、EXIT trap の cleanup を必ず通す。以降のシグナルは
# 無処理にして、後始末へ入るまでの間に 2 回目のシグナルで exit し直さないようにする。
on_signal() { # <終了コード>
  trap ':' TERM INT HUP
  err "interrupted" "received signal (exit $1); running cleanup"
  exit "$1"
}
trap 'on_signal 143' TERM
trap 'on_signal 130' INT
trap 'on_signal 129' HUP

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
  rt_create "$tmpdir/create-$seq_no.log" "$id" || create_rc=$?
  if [ "$create_rc" -ne 0 ]; then
    err "runtime-create-failed" "create failed or timed out for $id"
    show_log "$tmpdir/create-$seq_no.log"
    return 1
  fi
  live_created=1
  t1="$(wall_us)"
  if ! rt_start "$tmpdir/start-$seq_no.log" "$id"; then
    err "runtime-start-failed" "start failed or timed out for $id"
    show_log "$tmpdir/start-$seq_no.log"
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
    t2="$state_wall_us"
    m2="$state_mono_us"
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

# docker モードの 1 回分の計測。成功すると total_us・run_us（同値）を設定する。引数: <id> <cidfile>
# 計測区間は `docker run --rm ... --entrypoint true <image>` 全体の壁時計時間（spec のベースラインと同じ手法）。
# oci モードの区間（create 直前から実行開始の観測まで）とは異なる（冒頭「モード」参照）。
# 失敗（run の非ゼロ終了・タイムアウト・時計の変更）は非ゼロを返し、後始末は cleanup が担う。
measure_once_docker() {
  local id="$1" cidfile="$2" m0 m1 t0 t1 wall_total mono_total diff run_rc=0
  m0="$(mono_us)"
  t0="$(wall_us)"
  dk_run "$tmpdir/run-$seq_no.log" "$cidfile" "$id" || run_rc=$?
  t1="$(wall_us)"
  m1="$(mono_us)"
  if [ "$run_rc" -ne 0 ]; then
    err "docker-run-failed" "docker run failed or timed out for $id (exit $run_rc)"
    show_log "$tmpdir/run-$seq_no.log"
    return 1
  fi
  wall_total=$((t1 - t0))
  mono_total=$((m1 - m0))
  diff=$((wall_total - mono_total))
  [ "$diff" -lt 0 ] && diff=$((-diff))
  if [ "$t1" -lt "$t0" ] || [ "$diff" -gt "$CLOCK_TOLERANCE_US" ]; then
    err "clock-changed" "wall clock changed during the measurement of $id (wall ${wall_total}us vs monotonic ${mono_total}us); result discarded"
    return 1
  fi
  run_us="$wall_total"
  total_us="$wall_total"
  return 0
}

# 結果 JSON を --output（指定時）と stdout へ公開する。引数: <result json>
publish_result() {
  local result="$1"
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
}

# report モードの入力 1 ファイルを非信頼 JSON として検証し、compact な JSON を stdout へ返す。
# symlink・非通常ファイル・サイズ上限超過・単一オブジェクトでない・schema_version / benchmark /
# mode の不一致・p50 が正の数でない / unit が ms でないものは exit 2（取り違え・改ざんされた
# 結果を統合しない）。引数: <オプション名> <file> <期待する mode>
load_result_file() {
  local opt="$1" f="$2" want="$3" size obj want_method
  # mode ごとの計測区間（method）は固定値で検証する。入力の自己申告で methods_differ を偽装させない。
  case "$want" in
    oci) want_method="create-to-exec-observed" ;;
    docker) want_method="docker-run-rm-total" ;;
    *) err "invalid-result" "unsupported mode $want"; exit "$EXIT_INPUT" ;;
  esac
  if [ -L "$f" ] || [ ! -f "$f" ]; then
    err "invalid-result" "$opt must be a regular file (symlink not allowed)"
    exit "$EXIT_INPUT"
  fi
  size="$(wc -c <"$f" 2>/dev/null | tr -d ' ')" || size=""
  if ! [[ "$size" =~ ^[0-9]+$ ]] || [ "$size" -gt "$RESULT_MAX_BYTES" ]; then
    err "invalid-result" "$opt must be at most $RESULT_MAX_BYTES bytes"
    exit "$EXIT_INPUT"
  fi
  if ! obj="$(jq -cs --arg mode "$want" --arg method "$want_method" '
    if length == 1 then .[0] else error("not a single JSON value") end
    | if (type == "object" and .schema_version == 1 and .benchmark == "startup_latency"
        and .mode == $mode and .method == $method
        and (.metrics.startup_latency_p50_ms | type) == "object"
        and (.metrics.startup_latency_p50_ms.value | type) == "number"
        and .metrics.startup_latency_p50_ms.value > 0
        and .metrics.startup_latency_p50_ms.unit == "ms")
      then . else error("unexpected result schema") end
    # samples_us と params.iterations・metrics の整合を検証する（p50 だけ書き換えた入力を拒否する）。
    # p50・min・max は samples_us の total_us から再計算し、1e-6 ms 以上の差は不一致とする。
    | (.params.iterations) as $it
    | ([.samples_us[]? | .total_us]) as $raw
    | if (.samples_us | type) == "array" and ($it | type) == "number" and $it == ($it | floor)
        and $it >= 1 and $it <= 1000 and ($raw | length) == $it
        and ($raw | all(type == "number" and . > 0))
      then ($raw | sort) as $t
        | ($t | length) as $n
        | (if $n % 2 == 1 then $t[($n - 1) / 2] else ($t[$n / 2 - 1] + $t[$n / 2]) / 2 end) as $p50
        | def near($a; $b): (($a - $b) | if . < 0 then -. else . end) < 0.000001;
          if (.metrics.startup_latency_min_ms.value | type) == "number"
            and (.metrics.startup_latency_max_ms.value | type) == "number"
            and near(.metrics.startup_latency_p50_ms.value; $p50 / 1000)
            and near(.metrics.startup_latency_min_ms.value; $t[0] / 1000)
            and near(.metrics.startup_latency_max_ms.value; $t[$n - 1] / 1000)
          then . else error("metrics do not match samples_us") end
      else error("samples_us inconsistent with params.iterations") end' "$f" 2>/dev/null)"; then
    err "invalid-result" "$opt is not a valid startup_latency result with mode=$want method=$want_method (schema_version 1, positive p50 in ms, samples_us count equal to params.iterations, p50/min/max recomputed from samples_us)"
    exit "$EXIT_INPUT"
  fi
  printf '%s' "$obj"
}

# own・Docker の結果を 1 つのレポートにまとめる（TASK-46.2・CORE-10）。合否判定は出さない
# （Conditional Go 条件 1 の判定は #213 で人間が行う）。計測区間が異なるため methods_differ を
# 明示し、比率は参考値として扱わせる（REPAIR-3）。
run_report() {
  local own docker report
  own="$(load_result_file --own-result "$own_result" oci)"
  docker="$(load_result_file --docker-result "$docker_result" docker)"
  report="$(jq -n --argjson own "$own" --argjson docker "$docker" '
    {
      schema_version: 1,
      benchmark: "startup_latency_report",
      results: {own: $own, docker: $docker},
      comparison: {
        own_p50_ms: $own.metrics.startup_latency_p50_ms.value,
        docker_p50_ms: $docker.metrics.startup_latency_p50_ms.value,
        p50_ratio_own_to_docker: ($own.metrics.startup_latency_p50_ms.value / $docker.metrics.startup_latency_p50_ms.value),
        methods_differ: ($own.method != $docker.method)
      },
      notes: [
        "own and docker measure different intervals (see method); the ratio is informational only.",
        "no pass/fail verdict is produced; the Conditional Go decision is made by a human (issue 213)."
      ]
    }')"
  publish_result "$report"
  echo "startup_latency_report: own p50=$(jq -r '.comparison.own_p50_ms' <<<"$report")ms docker p50=$(jq -r '.comparison.docker_p50_ms' <<<"$report")ms ratio=$(jq -r '.comparison.p50_ratio_own_to_docker' <<<"$report") methods_differ=$(jq -r '.comparison.methods_differ' <<<"$report")" >&2
  echo "startup_latency_report: intervals differ between modes; no verdict is produced (human decision, issue 213)" >&2
}

if [ "$mode" = "report" ]; then
  run_report
  exit 0
fi

if [ "$mode" = "oci" ]; then
  method="create-to-exec-observed"
else
  method="docker-run-rm-total"
  # 計測区間外の事前確認。イメージが無ければ自動 pull せず（ネットワーク副作用・計測の歪み）
  # 手動での取得を案内して終了する。
  if ! dk_image_present "$tmpdir/image.log"; then
    err "image-not-present" "image $image is not available locally (or docker failed); run 'docker pull $image' yourself first"
    show_log "$tmpdir/image.log"
    exit "$EXIT_RUNTIME"
  fi
  if ! list_run_containers; then
    err "docker-list-failed" "could not list containers for this run before measuring"
    exit "$EXIT_RUNTIME"
  fi
  if [ "${#listed_ids[@]}" -ne 0 ]; then
    err "container-id-in-use" "containers labeled $DOCKER_LABEL_KEY=$run_tag already exist; refusing to touch them"
    exit "$EXIT_RUNTIME"
  fi
fi

samples="[]"
total_runs=$((warmup + iterations))
echo "startup_latency: mode=$mode target=$target label=$label warmup=$warmup iterations=$iterations timeout=${timeout_secs}s" >&2
run_no=0
while [ "$run_no" -lt "$total_runs" ]; do
  run_no=$((run_no + 1))
  seq_no=$((seq_no + 1))
  id="fandhe-startup-$run_tag-$$-$seq_no"
  create_us=0
  start_us=0
  observe_us=0
  total_us=0
  run_us=0
  state_polls=0
  if [ "$mode" = "docker" ]; then
    # 作成を試みる前から後始末対象にする（run がハングしても cleanup が cidfile で所有を判定する）。
    # docker は cidfile が既にあると失敗するため、毎回新しいパスにする。
    live_id="$id"
    live_cidfile="$tmpdir/cid-$seq_no"
    if ! measure_once_docker "$id" "$live_cidfile"; then
      rc="$EXIT_RUNTIME"
      break
    fi
    if ! finish_container_docker "$id" "$live_cidfile"; then
      live_id=""
      live_cidfile=""
      err "cleanup-failed" "could not confirm removal of container $id"
      exit "$EXIT_CLEANUP"
    fi
    live_id=""
    live_cidfile=""
  else
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
  fi
  if [ "$run_no" -gt "$warmup" ]; then
    if [ "$mode" = "docker" ]; then
      samples="$(jq -c --argjson r "$run_us" --argjson t "$total_us" \
        '. + [{run_us: $r, total_us: $t}]' <<<"$samples")"
    else
      samples="$(jq -c --argjson c "$create_us" --argjson s "$start_us" --argjson o "$observe_us" \
        --argjson t "$total_us" --argjson p "$state_polls" \
        '. + [{create_us: $c, start_us: $s, observe_us: $o, total_us: $t, state_polls: $p}]' <<<"$samples")"
    fi
  fi
  if [ "$mode" = "docker" ]; then
    echo "  run $run_no/$total_runs: total=${total_us}us$([ "$run_no" -le "$warmup" ] && echo ' (warmup)')" >&2
  else
    echo "  run $run_no/$total_runs: create=${create_us}us start=${start_us}us observe=${observe_us}us total=${total_us}us polls=${state_polls}$([ "$run_no" -le "$warmup" ] && echo ' (warmup)')" >&2
  fi
done

if [ "$rc" -ne 0 ]; then
  # 失敗時の後始末は trap の cleanup が担う。
  exit "$rc"
fi

# total_us の中央値（偶数件は中央 2 件の平均）・最小・最大を ms で集計して JSON を組み立てる
# （oci・docker とも total_us から同じ方法で算出する）。mode・method は計測区間を機械可読に
# 区別するための追加フィールド。params.image は docker モードのみ（パスは含めない）。
result="$(jq -n \
  --arg label "$label" \
  --arg target "$target" \
  --arg mode "$mode" \
  --arg method "$method" \
  --arg image "$image" \
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
      mode: $mode,
      method: $method,
      target: $target,
      label: $label,
      params: ({iterations: $iterations, warmup: $warmup, timeout_secs: $timeout}
        + (if $mode == "docker" then {image: $image} else {} end)),
      samples_us: $samples,
      metrics: {
        startup_latency_p50_ms: {value: ($p50 / 1000), unit: "ms"},
        startup_latency_min_ms: {value: ($t[0] / 1000), unit: "ms"},
        startup_latency_max_ms: {value: ($t[$n - 1] / 1000), unit: "ms"}
      }
    }')"

publish_result "$result"
echo "startup_latency: p50=$(jq -r '.metrics.startup_latency_p50_ms.value' <<<"$result")ms over $iterations runs" >&2
