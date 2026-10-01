#!/usr/bin/env bash
# 50 コンテナ同時起動時の集約メモリ計測スクリプト（own 側。TASK-50.1・CORE-9・SUP-1）。
#
# 役割: N（既定 50）個のコンテナを完全に同時に起動し、全コンテナが起動し終えた状態の PSS 合計
# （主指標）と RSS 合計（参考）を /proc から集計して、試行ごとの中央値を出力する。CORE-9（50 コンテナ
# 同時起動時の集約メモリ。PSS 合計が主指標）と SUP-1（監視プロセス込みの集約メモリが Docker の 80%
# 以下）は同一の測定で、本スクリプトはその own 側の計測ハーネスである。Docker 側の同一手法の計測は
# TASK-50.2（#218）、実機での実測と合否判定は人間担当の TASK-50.h1（#219）で行う。
# 呼び出し元は Makefile の `concurrent-memory` ターゲット。アイドル時メモリ（idle_memory.sh。TASK-45.1）
# と起動時間（startup_latency.sh。TASK-46.1）の計測スクリプトと同じ流儀（fail-closed・終了コード・
# 出力スキーマ）に揃えてある。
#
# PoC-17（supervisor-model）の教訓: 当初の実測値は起動競合（pivot_root・cgroup 参加の ENOENT）で
# 試行ごとに最大 20 個が未起動のまま合算され、無効だった。そのため本スクリプトは次を中核要件とする。
#   - 起動完了数が N 未満なら失敗として報告する（非ゼロ終了。結果は標準出力にも --output にも公開しない）
#   - PSS が 0 のコンテナ・読めない値・数値でない値を黙って合算しない
#   - 起動をずらさない（PoC-17 でも、ずらしは起動競合を隠す回避策として撤去された。競合そのものを
#     計測条件に含め、起動失敗として顕在化させる）
#
# 使い方:
#   concurrent_50_memory.sh --launcher <絶対パス> --bundle <dir> --target <名前>
#       [--mode own] [--count N] [--trials N] [--min-procs N] [--settle SECS] [--timeout SECS]
#       [--id-prefix STR] [--format json|text] [--output FILE] [--help]
#
# launcher 契約（差し替え点は ln_spawn / ln_stop / ln_collect_pids の 3 関数に隔離している）:
#   - 起動: `<launcher> run --id <id> --bundle <bundle>` を本スクリプトの直接の子としてバックグラウンドで
#     起動する。launcher は「コンテナ 1 つを監視するプロセス」としてフォアグラウンドに留まる
#     （デーモン化・二重 fork で親子関係を切らない。SUP-1 のコンテナごとの監視プロセスと一致する）。
#   - 起動完了の通知: コンテナが実際に起動し終えたら、launcher は標準出力へ `READY` だけの行を 1 行出す
#     （ログへ記録される）。本スクリプトはこの行を起動完了の明示的な ready 状態として扱い、プロセス数
#     （--min-procs）だけでは完了と判定しない（起動途中の一時的な子プロセスで N/N 起動と誤判定しない）。
#     ready 行は起動完了待ち・計測直前（measure_container）・全コンテナ集計後の再確認で確認する。
#   - ログ: launcher とその子孫（コンテナ内の処理）へはリソース制限（ulimit -f 等）を掛けない（計測条件を
#     変えないため）。ログの上限は収集側（本スクリプト）で設ける: launcher の標準出力・標準エラーは
#     コンテナごとの FIFO へ流し、本スクリプトの直接の子である収集プロセスが先頭 LOG_MAX_KIB KiB だけを
#     ログファイルへ書き、それ以降は読み捨てる（launcher は書き込みを拒否されず、SIGPIPE・SIGXFSZ も
#     受けない）。ディスク消費は「起動数 × LOG_MAX_KIB KiB」を超えない（REPAIR-5）。READY 行は先頭
#     LOG_MAX_KIB KiB 以内に出すこと（それより後の READY は記録されず、起動未完了として失敗になる）。
#     収集プロセスは launcher の子孫ではないので PSS・RSS の集計には入らない（参考値の
#     mem_available_delta_kb には、コンテナごとに 2 プロセス程度の分が含まれる）。
#   - 停止: 直接の子へ SIGTERM、期限内に終了しなければ SIGKILL。launcher は SIGTERM でコンテナも
#     終了させる。シグナルは、起動直後に記録した起動時刻（/proc/<pid>/stat の 22 番目）と親 pid が
#     一致する場合にだけ送る（launcher の終了後に pid が再利用されても無関係なプロセスへ送らない）。
#     launcher が先に死んで子孫が再親化（孤児化）しても回収できるよう、起動時に環境変数
#     FANDHE_BENCH_OWNER=<実行ごとの乱数トークン> を launcher へ渡し、後始末では /proc/*/environ の
#     トークン一致で所有プロセスを列挙して SIGKILL・残存確認する（子孫は環境を継承する。cgroup の作成には
#     特権が要るためトークン方式にしている）。
#   - 集計対象: launcher の pid を根とする子孫プロセスの全体（/proc/<pid>/task/<tid>/children を
#     幅優先でたどる。読めない環境では status の PPid 走査）。supervisor はコンテナ用 cgroup に入らない
#     （crates/core/src/cgroups.rs の fc-runtime リーフ）ため、cgroup.procs の列挙では監視プロセス込みに
#     ならない。
#   - 現状（REPAIR-3）: own 実装はエンドツーエンドで起動できない。CLI（fandhe-container バイナリ。
#     TASK-79）・supervisor のバイナリ入口・本番 ProcessLauncher が未提供のため、上の `run --id --bundle`
#     形は暫定の契約であり、実 CLI が提供されたら ln_spawn の起動行だけを実形へ合わせる。本スクリプトの
#     受け入れは自己テスト（スタブ launcher・疑似 /proc）で照合しており、own の実測値は未取得。
#
# 計測手順（1 試行）: N 個を同時起動 → 起動完了待ち（期限 --timeout。launcher が生存し、READY 行を
#   出力済みで、ツリーのプロセス数が --min-procs 以上）→ --settle 秒待機して再確認 → 全ツリーの Pss（smaps_rollup）・
#   VmRSS（status）を合算 → 全コンテナの起動条件を再確認（集計中に終了したコンテナがあれば失敗）→
#   全 launcher を停止・回収。--trials 回繰り返し、試行ごとの集約 PSS の
#   中央値（偶数試行は中央 2 値の平均を小数 1 桁）を出力する。1 試行でも無効なら全体を失敗にする。
#
# 終了コード:
#   0 = 全試行で N/N 起動し計測成功
#   1 = 起動数不足・PSS 0 混入・メモリ値を読めない／数値でない・起動完了待ちの期限切れ・トークンを
#       継承しない（後始末で回収できない）プロセスの混入・集計中のコンテナ終了・子プロセス一覧を
#       読めない（結果は公開しない）
#   2 = 引数・入力エラー（--proc-root は FANDHE_CONCURRENT_MEMORY_SELFTEST=1 なしでは拒否）、出力先エラー、
#       未対応の --mode（docker は TASK-50.2 で追加予定）
#   3 = 前提欠如（非 Linux・smaps_rollup 非対応・bash 5 未満等。0 を返して合格に見せない）
#   4 = 後始末失敗（起動したプロセスが残存。他の失敗より優先して返す）
#   129 / 130 / 143 = HUP / INT / TERM による中断（後始末は必ず実行し、残存があれば 4 を優先する。
#       後始末中に再度シグナルを受けても後始末を最後まで続ける）
#   上記以外の値（set -e の暗黙終了等）を返さないよう、失敗しうる操作は明示的に分岐する。
#
# 出力（JSON。scripts/check-bench-regression.sh の results.json 互換）: schema_version・benchmark・
#   behavior・task・mode・target・timestamp・kernel・arch・count・trials・n_started_min・metrics
#   （concurrent_<count>_pss_median_kb と参考の ..._rss_median_kb。unit kB）・trial_results[]。
#   launcher・bundle のパス、cmdline、環境変数は出力しない。
#
# 既知の制約:
#   - launcher が親子関係を切ると過少計上になる。--min-procs 未達として検出し失敗にする。
#   - 退避リーフ fc-runtime に入る共有プロセスが launcher ツリー外に出る構成になった場合は、列挙方法
#     （cgroup 併用）を見直す。
#   - user namespace 内のプロセスの smaps_rollup は権限不足で読めないことがある。0 として足さず失敗に
#     する。操作者が権限付きシェルから実行する（スクリプト内で sudo は呼ばない）。
#   - 後始末は環境変数トークンで所有プロセスを追跡する。計測時に子孫の environ がトークンを持たない・
#     読めない場合（環境を消去して exec・別ユーザー権限）は追跡不能として失敗にする（成功を公開しない）。
#     launcher 正常終了後に新規に生じてトークンを持たない子孫までは検出できない（cgroup 方式は特権要）。
#   - --output は新規ファイルに限る（既存のパスは拒否し、上書きしない）。公開は ln -T（hard link）で行う。
#   - --output の親ディレクトリは実行ユーザー所有・group/other 書き込み不可で、祖先を含む全パス要素が非 symlink（".." 不可）に限る。
#     / までの祖先ディレクトリは、所有者が実行ユーザーか root で、group/other 書き込み不可か sticky 付きに限る
#     （startup_latency.sh・idle_memory_supervised.sh と同じ規則）。
#   - 集計後の再確認は「launcher の生存・READY・プロセス数」を見る。集計中に子孫が入れ替わっても
#     プロセス数が --min-procs 以上なら検出しない。
#   - 起動時刻の照合からシグナル送信までの間に pid が再利用される可能性は残る（bash からは pidfd を
#     使えない）。照合の直後に送ることで窓を最小にしている。
#   - /proc の読み取り自体にはタイムアウトがない（Makefile の concurrent-memory が timeout で包む）。
#   - stderr に出す外部由来の文字列（ログ末尾等）は印字可能な ASCII 以外を `?` に置換する。

set -euo pipefail

readonly MAX_TREE=4096
readonly MAX_DEPTH=16
readonly MAX_SCAN_ATTEMPTS=10
readonly POLL_INTERVAL=0.2
readonly MAX_REPORT_IDS=5
readonly MAX_LOG_TAIL=5
# launcher 1 つのログの上限（KiB）。収集プロセスがこの量だけをログへ書き、以降は読み捨てる（launcher へ
# ulimit は掛けない）。ディスク消費の上限は「--count の最大 1024 × 256 KiB = 256 MiB」になる。
readonly LOG_MAX_KIB=256
# 10 進整数（先頭 0 付きは bash 算術で 8 進になるため拒否。13 桁まで）。
readonly num_re='^(0|[1-9][0-9]{0,12})$'

err() {
  local LC_ALL=C msg
  msg="error: $1: $2"
  msg="${msg//[^[:print:]]/?}"
  printf '%s\n' "$msg" >&2 || true
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

launcher=""
bundle=""
target_name=""
mode="own"
count=50
trials=3
min_procs=2
settle=2
timeout_s=30
id_prefix="fc-bench50"
format="json"
output=""
proc_root=""
proc_root_given=0

need_val() { [ "$1" -ge 2 ] || { err "invalid-argument" "$2 requires a value"; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --launcher) need_val $# "$1"; launcher="$2"; shift 2 ;;
    --bundle) need_val $# "$1"; bundle="$2"; shift 2 ;;
    --target) need_val $# "$1"; target_name="$2"; shift 2 ;;
    --mode) need_val $# "$1"; mode="$2"; shift 2 ;;
    --count) need_val $# "$1"; count="$2"; shift 2 ;;
    --trials) need_val $# "$1"; trials="$2"; shift 2 ;;
    --min-procs) need_val $# "$1"; min_procs="$2"; shift 2 ;;
    --settle) need_val $# "$1"; settle="$2"; shift 2 ;;
    --timeout) need_val $# "$1"; timeout_s="$2"; shift 2 ;;
    --id-prefix) need_val $# "$1"; id_prefix="$2"; shift 2 ;;
    --format) need_val $# "$1"; format="$2"; shift 2 ;;
    --output) need_val $# "$1"; output="$2"; shift 2 ;;
    --proc-root) need_val $# "$1"; proc_root="$2"; proc_root_given=1; shift 2 ;;
    --help | -h)
      if ! usage 2>/dev/null; then err "output-failed" "cannot write usage to stdout"; exit 2; fi
      exit 0
      ;;
    *) err "invalid-argument" "unknown argument: $1"; exit 2 ;;
  esac
done

# 数値引数は許可リスト（10 進整数と範囲）で検証する。
check_range() { # <名前> <値> <最小> <最大>
  if ! [[ "$2" =~ $num_re ]] || [ "$2" -lt "$3" ] || [ "$2" -gt "$4" ]; then
    err "invalid-argument" "$1 must be an integer from $3 to $4"
    exit 2
  fi
}
check_range --count "$count" 1 1024
check_range --trials "$trials" 1 20
# launcher 自身も 1 プロセスとして数えるため、2 未満だと launcher だけが生存していても起動完了になる（CORE-9）。
check_range --min-procs "$min_procs" 2 16
check_range --settle "$settle" 0 600
check_range --timeout "$timeout_s" 1 3600

[[ "$target_name" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || { err "invalid-argument" "--target is required (^[a-z0-9][a-z0-9._-]{0,31}\$)"; exit 2; }
[[ "$id_prefix" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || { err "invalid-argument" "--id-prefix must match ^[a-z0-9][a-z0-9-]{0,31}\$"; exit 2; }
case "$format" in json | text) ;; *) err "invalid-argument" "--format must be json or text"; exit 2 ;; esac
case "$mode" in
  own) ;;
  docker) err "unsupported-mode" "docker mode is added by TASK-50.2"; exit 2 ;;
  *) err "invalid-argument" "--mode must be own"; exit 2 ;;
esac

case "$launcher" in
  /*) ;;
  *) err "invalid-argument" "--launcher must be an absolute path (no default: avoids measuring the wrong binary)"; exit 2 ;;
esac
{ [ -f "$launcher" ] && [ -x "$launcher" ]; } || { err "invalid-argument" "--launcher is not an executable file"; exit 2; }
case "$bundle" in
  '' | -*) err "invalid-argument" "--bundle is required and must not start with '-'"; exit 2 ;;
esac
[ -d "$bundle" ] || { err "invalid-argument" "--bundle is not a directory"; exit 2; }

# --proc-root（疑似 /proc）は selftest 専用。通常利用で実 /proc を迂回できないようにする。
if [ "$proc_root_given" -eq 1 ]; then
  if [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST:-}" != "1" ]; then
    err "invalid-argument" "--proc-root is for selftest only (set FANDHE_CONCURRENT_MEMORY_SELFTEST=1)"
    exit 2
  fi
  case "$proc_root" in -* | '') err "invalid-argument" "invalid proc root"; exit 2 ;; esac
  [ -d "$proc_root" ] || { err "invalid-argument" "proc root is not a directory"; exit 2; }
fi

# 引数のディレクトリ 1 つが、他のユーザーに中のエントリを差し替えられないことを確かめる
# （startup_latency.sh・idle_memory_supervised.sh の dir_is_safe と同じ規則）。symlink でない実ディレクトリで、
# 所有者が実行ユーザーか root で、group / other の書き込み権がないか sticky ビット付きであること。
dir_is_safe() {
  local d="$1" uid
  uid="$(id -u)"
  [ -n "$(find -P "$d" -maxdepth 0 -type d \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) ! -perm -1000 -print 2>/dev/null)" ]
}

# --output の親ディレクトリから / までの全ディレクトリが dir_is_safe で、パスに symlink を含まない
# （論理パスと物理パスが一致する）ことを確かめる（startup_latency.sh・idle_memory_supervised.sh の
# output_path_is_safe と同じ規則）。権限付きで実行したときに、検査後に他のユーザーが祖先ディレクトリを
# 差し替えて、後段の mktemp・ln を意図しない場所へ誘導する経路を塞ぐ。経路上の全ディレクトリへ
# 書き込めるのが実行ユーザーと root だけであることが、検証から公開までパスが変わらないことの根拠になる。
output_path_is_safe() {
  local logical physical d parent depth
  logical="$(cd -- "$1" && pwd -L)" || return 1
  physical="$(cd -- "$1" && pwd -P)" || return 1
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
    [ "$depth" -le 256 ] || return 1
    d="$parent"
  done
  return 0
}

if [ -n "$output" ]; then
  # 既存のパス（種別を問わない。symlink・ディレクトリを含む）は拒否し、上書きしない（出力先の取り違えで
  # 既存データを失わない。startup_latency.sh の --output と同じ契約）。計測前に検査して早く止め、公開時にも
  # ln -T で「存在しない場合だけ作成」を保証する。
  if [ -e "$output" ] || [ -L "$output" ]; then
    err "invalid-argument" "output path already exists (refusing to overwrite; --output must be a new file)"
    exit 2
  fi
  output_dir="${output%/*}"
  [ "$output_dir" != "$output" ] || output_dir="."
  [ -n "$output_dir" ] || output_dir="/"
  [ -d "$output_dir" ] || { err "invalid-argument" "output directory does not exist"; exit 2; }
  # 権限付きで実行されても書き込み先を誘導されないよう、出力先ディレクトリ自体の symlink を拒否し、
  # 物理パスへ正規化したうえで所有者（実行ユーザー）と書き込み権限（group・other 不可）を検証する。
  # 正規化後のパスだけを以降の mktemp・mv に使う（親ディレクトリの symlink を辿らせない）。
  # 祖先を含む全パス要素の symlink を拒否する（cd -P は祖先の symlink を辿るため、末尾要素の検査だけでは
  # 攻撃者制御の接頭辞経由で別ディレクトリへ誘導される）。相対パスは物理 cwd を起点にし、".." は拒否する。
  case "$output_dir" in
    /*) od_walk="$output_dir" od_cur="" ;;
    *)
      if ! od_cur="$(pwd -P 2>/dev/null)"; then err "invalid-argument" "cannot resolve current directory"; exit 2; fi
      [ "$od_cur" != "/" ] || od_cur=""
      od_walk="$output_dir"
      ;;
  esac
  od_rest="$od_walk"
  while [ -n "$od_rest" ]; do
    od_rest="${od_rest#/}"
    [ -n "$od_rest" ] || break
    od_part="${od_rest%%/*}"
    case "$od_rest" in */*) od_rest="${od_rest#*/}" ;; *) od_rest="" ;; esac
    case "$od_part" in
      '' | .) continue ;;
      ..) err "invalid-argument" "output directory must not contain '..'"; exit 2 ;;
    esac
    od_cur="${od_cur}/${od_part}"
    [ ! -L "$od_cur" ] || { err "invalid-argument" "output directory path contains a symlink"; exit 2; }
  done
  if ! output_dir="$(cd -P -- "$output_dir" 2>/dev/null && pwd -P)"; then
    err "invalid-argument" "cannot resolve output directory"
    exit 2
  fi
  if ! od_stat="$(stat -c '%u %a' -- "$output_dir" 2>/dev/null)"; then
    err "invalid-argument" "cannot inspect output directory"
    exit 2
  fi
  od_uid="${od_stat%% *}"
  od_mode="${od_stat##* }"
  [[ "$od_uid" =~ $num_re ]] && [[ "$od_mode" =~ ^[0-7]{3,4}$ ]] || { err "invalid-argument" "cannot inspect output directory"; exit 2; }
  if [ "$od_uid" != "$(id -u)" ]; then
    err "invalid-argument" "output directory is not owned by the current user"
    exit 2
  fi
  if [ $((8#$od_mode & 8#022)) -ne 0 ]; then
    err "invalid-argument" "output directory is writable by group or others"
    exit 2
  fi
  # 親だけでなく / までの祖先ディレクトリも検証する（他のユーザーが書き込める祖先があると、検査後に
  # 途中のディレクトリを差し替えられる）。親ディレクトリには上の検査（実行ユーザー所有・group / other
  # 書き込み不可）をそのまま課し、祖先には main の他の計測スクリプトと同じ規則を使う。
  if ! command -v find >/dev/null 2>&1 || ! command -v id >/dev/null 2>&1 || ! command -v dirname >/dev/null 2>&1; then
    err "unsupported-os" "find, id and dirname are required to validate the output directory"
    exit 3
  fi
  if ! output_path_is_safe "$output_dir"; then
    err "invalid-argument" "the path of --output must not contain symlinks, and every directory above it must be owned by you or root and not writable by others (unless sticky)"
    exit 2
  fi
  case "$output_dir" in
    /) output="/${output##*/}" ;;
    *) output="${output_dir}/${output##*/}" ;;
  esac
fi

# --- 前提確認（欠如は 3。0 を返して合格に見せない） ---
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then err "unsupported-os" "bash 5 or later is required"; exit 3; fi
if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then err "unsupported-os" "only Linux is supported"; exit 3; fi
if [ "$proc_root_given" -eq 0 ]; then
  proc="/proc"
  [ -r /proc/self/smaps_rollup ] || { err "unsupported-os" "/proc/<pid>/smaps_rollup is not available (Linux 4.14+ required)"; exit 3; }
else
  proc="${proc_root%/}"
fi
for req in sleep mktemp grep tail ln mkfifo dd cat wc; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "sleep, mktemp, grep, tail, ln, mkfifo, dd, cat and wc are required"; exit 3; }
done
# ログ収集は dd の status=none（進捗を stderr へ出さない指定）を使う。使えない dd では止める。
if [ "$(printf 'xy' | dd bs=1 count=1 status=none 2>/dev/null || true)" != "x" ]; then
  err "unsupported-os" "dd with status=none is required (GNU coreutils 8.21 or later)"
  exit 3
fi
[ -r /proc/self/stat ] || { err "unsupported-os" "/proc/<pid>/stat is not available"; exit 3; }

# --- 状態 ---
tmpdir=""
out_tmp=""
pids=()
pstart=()
cpids=()
cstart=()
snaps=()
known=()
# 起動した子プロセス（収集プロセス・launcher）を配列へ登録し終えるまでの間は 1。この間に受けた
# TERM / INT / HUP は pending_sig へ記録するだけにして、登録後に処理する（on_signal・spawn_section_end）。
in_spawn=0
pending_sig=""
# launcher を起動し得る区間へ入ったら 1。pids が空でも、所有トークンでの走査・回収を省略しない。
need_sweep=0
owner_tok=""
OWNED=()
tree_pids=()
children=()
ok_flags=()

# 外部由来の文字列を stderr 用に無害化する（印字可能な ASCII 以外を ? へ）。
sanitize() { local LC_ALL=C s="$1"; printf '%s' "${s//[^[:print:]]/?}"; }

# 実 /proc 上で pid が生存（ゾンビ・消滅でない）か。launcher は本スクリプトの子のため生存確認に使う。
proc_alive() {
  local s rest
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  case "${rest:0:1}" in Z | X | x) return 1 ;; esac
  return 0
}

# pid の起動時刻（pid 再利用の判別用。/proc/<pid>/stat の 22 番目）を ST へ入れる。読めなければ 1。
# 同時起動の直後にも呼ぶため、コマンド置換（fork）を使わず変数で返す。
read_starttime() {
  local s rest f
  ST=""
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  [ -n "${f[19]:-}" ] || return 1
  ST="${f[19]}"
}

# pid が「記録した起動時刻のまま生存している同一プロセス」か。消滅・ゾンビ・起動時刻の不一致（pid の
# 再利用）・起動時刻を記録できなかった場合は 1。第 3 引数（親 pid）を渡すと親の一致も要求する。
# stat を 1 回だけ読んで状態・親・起動時刻を同じ時点の値で判定する。
same_proc_alive() { # <pid> <起動時刻> [<親 pid>]
  local s rest f
  [ -n "${2:-}" ] || return 1
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  case "${f[0]:-}" in Z | X | x | '') return 1 ;; esac
  [ "${f[19]:-}" = "$2" ] || return 1
  [ -z "${3:-}" ] || [ "${f[1]:-}" = "$3" ]
}

# 起動時刻（と任意で親 pid）が一致する同一プロセスにだけシグナルを送る。本スクリプトのシグナル送信は
# すべてここを通す（launcher・観測済みの子孫・トークン所有プロセス。無関係なプロセスを終了させない）。
sig_same_proc() { # <シグナル名> <pid> <起動時刻> [<親 pid>]
  same_proc_alive "$2" "$3" "${4:-}" || return 0
  kill "-$1" "$2" 2>/dev/null || true
}

# コンテナ i の launcher が生存しているか（本スクリプトの直接の子で、起動時刻が起動直後の記録と一致）。
ln_alive() { # <i>
  same_proc_alive "${pids[$1]}" "${pstart[$1]:-}" "$$"
}

# pid が本スクリプトの直接の子として生存しているか（起動時刻は問わない）。起動時刻を照合できない
# launcher を「シグナルは送らないが残存として報告する」ために使う（黙って残さない）。
own_child_alive() { # <pid>
  local s rest f
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  case "${f[0]:-}" in Z | X | x | '') return 1 ;; esac
  [ "${f[1]:-}" = "$$" ]
}

# --- launcher 契約の差し替え点（実 CLI 提供後はここだけ合わせる。REPAIR-3） ---

# コンテナ 1 つ分のログ収集プロセスを起動し、pid を LAST_CPID、起動時刻を LAST_CSTART へ入れる。
# FIFO（<logfile>.fifo）から読み、先頭 LOG_MAX_KIB KiB だけを <logfile> へ書いて、以降は EOF まで
# 読み捨てる（読み手を残すことで launcher の書き込みを止めず、SIGPIPE も起こさない）。dd は bs=1 で
# 1 バイトずつ読んでその都度書く。FIFO からの read は書き込み単位ごとの部分読みになり、dd は部分読みも
# 1 レコードと数えるため、bs を大きくすると短い行を count 回読んだ時点で（上限バイト数より前に）打ち切って
# READY を取りこぼす。bs=1 なら count がそのままバイト数になり、READY 行も出力された時点でログに現れる
# （head -c は標準出力がファイルのとき stdio でバッファするため使わない）。launcher の起動を遅らせないよう、全コンテナ
# 分を launcher より先に起動しておく（FIFO の open は launcher 側の open と揃うまで待つ）。
# 本スクリプトの直接の子で、環境変数トークンを持たず launcher のツリーにも入らない。TERM / HUP / INT は
# 無視させ（外側 timeout はプロセスグループ全体へ送る）、全書き手の終了による EOF で自然に終わる。
# 残った場合は後始末（collectors_stop）が SIGKILL する。FIFO を作れなければ 1。
log_collector_start() { # <logfile>
  LAST_CPID=""
  LAST_CSTART=""
  # FANDHE_CONCURRENT_MEMORY_SELFTEST_FIFO_FAIL_AT は selftest が「途中のコンテナで FIFO を作れない」
  # 状況を模すための専用フック（それまでに起動した収集プロセスを残さないことを照合する）。
  if [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST:-}" = "1" ] && [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST_FIFO_FAIL_AT:-}" = "$((${#cpids[@]} + 1))" ]; then
    return 1
  fi
  mkfifo -m 600 -- "$1.fifo" 2>/dev/null || return 1
  (
    trap '' TERM HUP INT
    exec <"$1.fifo" >"$1" || exit 0
    dd bs=1 count="$((LOG_MAX_KIB * 1024))" status=none 2>/dev/null || true
    exec cat >/dev/null
  ) &
  LAST_CPID=$!
  if read_starttime "$LAST_CPID"; then LAST_CSTART="$ST"; fi
}

# 収集プロセスを回収する。launcher と子孫（FIFO の書き手）が全て終了していれば EOF で自然に終わるので、
# まず最大 2 秒待つ。残ったもの（書き手が残存している・FIFO の open 待ちのまま）は、起動時刻と親 pid を
# 照合してから SIGKILL する。収集プロセスが dd を実行中なら、その子（dd）も起動時刻を照合して終了させる。
collectors_stop() {
  local i waited=0 alive c desc kids
  [ "${#cpids[@]}" -gt 0 ] || return 0
  while [ "$waited" -lt 10 ]; do
    alive=0
    for i in "${!cpids[@]}"; do
      if same_proc_alive "${cpids[i]}" "${cstart[i]:-}" "$$"; then alive=1; break; fi
    done
    [ "$alive" -eq 1 ] || break
    sleep "$POLL_INTERVAL"
    waited=$((waited + 1))
  done
  for i in "${!cpids[@]}"; do
    if same_proc_alive "${cpids[i]}" "${cstart[i]:-}" "$$"; then
      kids=""
      c=()
      { read -ra c <"/proc/${cpids[i]}/task/${cpids[i]}/children"; } 2>/dev/null || true
      for desc in "${c[@]}"; do
        [[ "$desc" =~ $num_re ]] || continue
        if read_starttime "$desc"; then kids+="${desc}:${ST} "; fi
      done
      sig_same_proc KILL "${cpids[i]}" "${cstart[i]}" "$$"
      for desc in $kids; do
        sig_same_proc KILL "${desc%%:*}" "${desc#*:}"
      done
    fi
    # 終了済み・SIGKILL 済みの収集プロセスを回収する（照合できない生存プロセスは待たない）。
    if ! own_child_alive "${cpids[i]}" || [ -n "${cstart[i]:-}" ]; then
      wait "${cpids[i]}" 2>/dev/null || true
    fi
  done
  cpids=()
  cstart=()
}

# コンテナ 1 つ分の launcher を直接の子として起動し、pid を LAST_PID、起動時刻を LAST_START へ入れる
# （起動時刻を読めなければ空。空の launcher は以後「生存していない」と扱い、シグナルも送らない。
# その pid が直接の子として生存し続けていれば、後始末で残存として報告し終了コード 4 にする）。
# 引数は配列で直接 exec する（eval・sh -c を使わない）。launcher とその子孫へ ulimit 等のリソース制限は
# 掛けない（コンテナ内の書き込みが失敗して計測条件が変わるため）。標準出力・標準エラーは
# log_collector_start が用意した FIFO（<logfile>.fifo）へ流し、ログの上限は収集プロセス側で設ける。
ln_spawn() { # <id> <logfile>
  (
    FANDHE_BENCH_OWNER="$owner_tok" exec "$launcher" run --id "$1" --bundle "$bundle" </dev/null >"$2.fifo" 2>&1
  ) &
  LAST_PID=$!
  # FANDHE_CONCURRENT_MEMORY_SELFTEST_SIGNAL_IN_SPAWN は selftest が「launcher を起動した直後、pid を
  # 登録する前にシグナルを受ける」状況を模すための専用フック（その launcher も回収されることを照合する）。
  if [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST:-}" = "1" ] && [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST_SIGNAL_IN_SPAWN:-}" = "1" ]; then
    kill -TERM "$$"
  fi
  LAST_START=""
  if read_starttime "$LAST_PID"; then LAST_START="$ST"; fi
  # FANDHE_CONCURRENT_MEMORY_SELFTEST_STALE_START は selftest が「記録した起動時刻と一致しない pid
  # （再利用された pid）」を模すための専用フック。一致しない pid へはシグナルを送らないことを照合する。
  if [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST:-}" = "1" ] && [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST_STALE_START:-}" = "1" ]; then
    LAST_START="0"
  fi
}

# pid p の子（全スレッド分）を children へ入れる。children ファイルが無い環境では PPid 走査。
# 存在するのに読めない一覧（権限不足・スレッドの終了）が 1 つでもあれば 1 を返す。読めた分だけで成功に
# すると、読めなかったスレッドの子孫が集計から抜けて過少計上になるため（CORE-9・SUP-1）。プロセス p 自体が
# 消えた場合は 0（消滅は呼び出し側がメモリ値の読み取り時に検出して走査をやり直す）。
ln_children() {
  local p="$1" f d line got=0 ppid opened
  children=()
  for f in "$proc/$p/task/"*/children; do
    # glob が一致しない（children 非対応のカーネル）場合はパターン文字列のまま来るので除く。
    [ -e "$f" ] || continue
    got=1
    # 空の一覧（子なし）でも read は非 0 を返すので、終了コードでは open の失敗と区別できない。番兵を
    # 入れておき、read が実行されなかった（open に失敗した）場合だけ番兵が残ることで判定する。
    line=("unread")
    read -ra line 2>/dev/null <"$f" || true
    if [ "${line[0]:-}" = "unread" ]; then
      [ -d "$proc/$p" ] || return 0
      return 1
    fi
    children+=("${line[@]}")
  done
  [ "$got" -eq 0 ] || return 0
  [ -d "$proc/$p" ] || return 0
  for d in "$proc"/[0-9]*/status; do
    [ -e "$d" ] || continue
    ppid=""
    opened=0
    {
      opened=1
      while IFS= read -r line; do
        case "$line" in
          PPid:*)
            ppid="${line#PPid:}"
            ppid="${ppid//[[:space:]]/}"
            break
            ;;
        esac
      done
    } 2>/dev/null <"$d" || true
    if [ "$opened" -eq 0 ]; then
      # 走査中に終了したプロセスは対象外。存在するのに読めない status は親を判定できないので失敗。
      [ -e "$d" ] || continue
      return 1
    fi
    if [ "$ppid" = "$p" ]; then
      d="${d%/status}"
      children+=("${d##*/}")
    fi
  done
}

# launcher の pid を根とする子孫（根を含む）を tree_pids へ入れる。根が消えていれば 1、プロセス数の
# 上限超過は 2、深さ上限（MAX_DEPTH）に達しても未探索の子孫が残る場合は 3、子プロセス一覧を読めない
# プロセスがある場合は 4 を返す（過少計上を成功にしない）。失敗時の tree_pids は「それまでに見つけた分」で、後始末（ln_stop）が利用する。
ln_collect_pids() {
  local root="$1" depth=0 p c cur next
  tree_pids=()
  [ -d "$proc/$root" ] || return 1
  tree_pids=("$root")
  cur=("$root")
  while [ "${#cur[@]}" -gt 0 ] && [ "$depth" -lt "$MAX_DEPTH" ]; do
    next=()
    for p in "${cur[@]}"; do
      ln_children "$p" || return 4
      for c in "${children[@]}"; do
        [[ "$c" =~ $num_re ]] || continue
        tree_pids+=("$c")
        next+=("$c")
        [ "${#tree_pids[@]}" -le "$MAX_TREE" ] || return 2
      done
    done
    cur=("${next[@]}")
    depth=$((depth + 1))
  done
  [ "${#cur[@]}" -eq 0 ] || return 3
  return 0
}

# 直近の ln_collect_pids の結果（根を除く子孫）を「pid:起動時刻」で known[i] へ追記する。launcher が
# 子孫より先に死ぬと親子関係をたどれなくなる（子は親を失って再親化される）ため、生存中に観測した
# 子孫を覚えておき、後始末で起動時刻が一致するもの（pid 再利用でないもの）にだけ SIGKILL を送る。
record_tree() { # <i>
  local i="$1" pid desc
  for pid in "${tree_pids[@]:1}"; do
    if read_starttime "$pid"; then
      desc="${pid}:${ST}"
      case " ${known[i]:-} " in
        *" ${desc} "*) ;;
        *) known[i]="${known[i]:-}${desc} " ;;
      esac
    fi
  done
}

# launcher が標準出力（ログ）へ `READY` 行を出したか（起動完了の明示的な ready 状態）。
# ログは収集プロセスが LOG_MAX_KIB KiB で打ち切るため、読む量もその範囲に収まる。
ln_ready() { # <logfile>
  [ -r "$1" ] && grep -qxF -- "READY" "$1" 2>/dev/null
}

# 環境変数トークン FANDHE_BENCH_OWNER が一致する生存プロセス（launcher の孤児化した子孫を含む）を
# 「pid:起動時刻」で OWNED へ入れる。トークンは実行ごとの乱数。列挙からシグナル送信までの間の pid
# 再利用に備え、送信時は起動時刻とトークンを再照合する（owned_kill）。
owned_scan() {
  local f p
  OWNED=()
  [ -n "$owner_tok" ] || return 0
  while IFS= read -r f; do
    p="${f#"$proc"/}"
    p="${p%%/*}"
    [[ "$p" =~ $num_re ]] || continue
    if read_starttime "$p" && proc_alive "$p"; then OWNED+=("${p}:${ST}"); fi
  done < <(grep -lzxF -- "FANDHE_BENCH_OWNER=${owner_tok}" "$proc"/[0-9]*/environ 2>/dev/null || true)
}

# pid の environ が実行ごとのトークンを継承しているか（読めない・無ければ失敗）。
owned_by_token() { # <pid>
  [ -n "$owner_tok" ] || return 1
  [ -r "$proc/$1/environ" ] && grep -qzxF -- "FANDHE_BENCH_OWNER=${owner_tok}" "$proc/$1/environ" 2>/dev/null
}

# OWNED の各プロセスへ、トークンと起動時刻を再照合してから SIGKILL を送る。
owned_kill() {
  local desc pid
  for desc in "${OWNED[@]}"; do
    pid="${desc%%:*}"
    if owned_by_token "$pid"; then sig_same_proc KILL "$pid" "${desc#*:}"; fi
  done
}

any_alive() {
  local i
  for i in "${!pids[@]}"; do
    if ln_alive "$i"; then return 0; fi
  done
  return 1
}

# 全 launcher を停止・回収する（SIGTERM → 期限内に終了しなければ SIGKILL。launcher にも、launcher の
# 消滅後に残った子孫にも、起動時刻が一致するもの＝pid 再利用でないものにだけシグナルを送る）。
# 残存があれば 4 を返す。成功・失敗・シグナルのいずれでも呼ばれる（EXIT trap）。何度呼んでも安全。
ln_stop() {
  local i pid grace desc waited residual=()
  # launcher を 1 つも登録していなくても、先に起動した収集プロセスは必ず回収する（FIFO の作成失敗や、
  # 収集プロセスの起動中に受けたシグナルで終了する場合。FIFO の open 待ちのまま残さない）。
  # 起動区間へ入った後（need_sweep=1）は pids が空でも以降の処理を省略せず、所有トークンでの走査・
  # 回収・残存確認まで行う（配列は空なので launcher 向けのループは何もしない）。
  if [ "${#pids[@]}" -eq 0 ] && [ "$need_sweep" -eq 0 ]; then
    collectors_stop
    return 0
  fi
  grace="$timeout_s"
  [ "$grace" -le 10 ] || grace=10
  for i in "${!pids[@]}"; do
    # 失敗（根の消滅・上限超過）でも、見つかった分と生存中に記録した分を併せて後始末対象にする。
    ln_collect_pids "${pids[i]}" || true
    record_tree "$i"
    snaps[i]="${known[i]:-}"
  done
  for i in "${!pids[@]}"; do
    sig_same_proc TERM "${pids[i]}" "${pstart[i]:-}" "$$"
  done
  waited=0
  while [ "$waited" -lt "$((grace * 5))" ] && any_alive; do
    sleep "$POLL_INTERVAL"
    waited=$((waited + 1))
  done
  # FANDHE_CONCURRENT_MEMORY_SELFTEST_NOKILL は selftest が「回収不能」を模すための専用フック。
  if [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST:-}" != "1" ] || [ "${FANDHE_CONCURRENT_MEMORY_SELFTEST_NOKILL:-}" != "1" ]; then
    for i in "${!pids[@]}"; do
      sig_same_proc KILL "${pids[i]}" "${pstart[i]:-}" "$$"
    done
    waited=0
    while [ "$waited" -lt 25 ] && any_alive; do
      sleep "$POLL_INTERVAL"
      waited=$((waited + 1))
    done
    for i in "${!pids[@]}"; do
      for desc in ${snaps[i]}; do
        sig_same_proc KILL "${desc%%:*}" "${desc#*:}"
      done
    done
    # launcher が先に死んで再親化された子孫は、環境変数トークンで所有プロセスとして列挙して回収する。
    owned_scan
    owned_kill
    waited=0
    while [ "$waited" -lt 25 ]; do
      owned_scan
      [ "${#OWNED[@]}" -gt 0 ] || break
      sleep "$POLL_INTERVAL"
      waited=$((waited + 1))
    done
    sleep "$POLL_INTERVAL"
  fi
  # launcher と子孫の停止後にログ収集プロセスを回収する（残存の判定には含めない。本スクリプトが
  # 起動時刻を照合して SIGKILL する直接の子で、計測対象のプロセスではない）。
  collectors_stop
  for i in "${!pids[@]}"; do
    pid="${pids[i]}"
    # 終了済みの launcher だけを wait で回収する。起動時刻を照合できないが本スクリプトの直接の子として
    # 生存しているものは、シグナルを送らずに残存として報告する（黙って残さない）。それ以外の生存
    # プロセス（再利用された pid）は本スクリプトの launcher ではないので、残存にも数えず wait もしない。
    if ln_alive "$i" || own_child_alive "$pid"; then
      case " ${residual[*]:-} " in
        *" pid=${pid} "*) ;;
        *) residual+=("pid=${pid}") ;;
      esac
    elif ! proc_alive "$pid"; then
      wait "$pid" 2>/dev/null || true
    fi
    for desc in ${snaps[i]}; do
      pid="${desc%%:*}"
      if same_proc_alive "$pid" "${desc#*:}"; then
        residual+=("pid=${pid}")
      fi
    done
  done
  owned_scan
  for desc in "${OWNED[@]}"; do
    pid="${desc%%:*}"
    case " ${residual[*]:-} " in
      *" pid=${pid} "*) ;;
      *) residual+=("pid=${pid}") ;;
    esac
  done
  pids=()
  pstart=()
  snaps=()
  known=()
  need_sweep=0
  if [ "${#residual[@]}" -gt 0 ]; then
    err "cleanup-failed" "processes still running: ${residual[*]}"
    return 4
  fi
  return 0
}

# 終了時の後始末（EXIT trap）。後始末の途中で TERM / INT / HUP を再度受けても中断しないよう、最初に
# 3 つのシグナルを無処理（':'）へ切り替える（idle_memory_supervised.sh の cleanup と同じ方式。
# ln_stop は最大 20 秒ほど待つため、Ctrl+C の連打や外側 timeout の再送で launcher を残さない）。
on_exit() {
  local rc=$?
  # 先にシグナルを無処理にしてから EXIT trap を外す（逆順だと、その間に届いたシグナルの exit で
  # 後始末を通らずに終了する）。
  trap ':' TERM INT HUP
  trap - EXIT
  ln_stop || rc=4
  if [ -n "$out_tmp" ]; then rm -f "$out_tmp"; fi
  if [ -n "$tmpdir" ]; then rm -rf "$tmpdir"; fi
  exit "$rc"
}
trap on_exit EXIT

# TERM / INT / HUP を受けたら 128+signal で exit し、EXIT trap の後始末を必ず通す。以降のシグナルは
# 無処理にして、後始末へ入るまでの間に 2 回目のシグナルで exit し直さないようにする。
# 子プロセスの起動から配列への登録までの間（in_spawn=1）に受けた場合は、記録だけして戻る。登録前に
# 後始末へ入ると、起動済みで未登録の子（launcher は exec 前で所有トークンも持たない）を回収できない。
# 記録したシグナルは登録の直後に spawn_section_end が処理する。
on_signal() { # <終了コード>
  if [ "$in_spawn" -eq 1 ]; then
    pending_sig="$1"
    return 0
  fi
  trap ':' TERM INT HUP
  err "interrupted" "received signal (exit $1); running cleanup"
  exit "$1"
}
trap 'on_signal 143' TERM
trap 'on_signal 130' INT
trap 'on_signal 129' HUP

# 起動〜登録の区間を閉じ、区間中に受けたシグナルがあれば処理する（後始末へ進む）。
spawn_section_end() {
  in_spawn=0
  if [ -n "$pending_sig" ]; then on_signal "$pending_sig"; fi
}

if ! tmpdir="$(mktemp -d)"; then err "invalid-input" "cannot create a temporary directory"; exit 2; fi
# 所有プロセス追跡用の実行ごとの乱数トークン（mktemp が返す英数字のディレクトリ名を流用）。
owner_tok="owner-${tmpdir##*/}"
[[ "$owner_tok" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { err "invalid-input" "cannot derive an owner token"; exit 2; }

# --- メモリ値の読み取り（読めない・数値でないものは 0 として足さず失敗にする） ---

# <file> <key> → 値を READ_KB へ。0 = 成功、1 = 読めない／キー無し、3 = 数値でない。
read_kb() {
  local line v
  READ_KB=""
  [ -r "$1" ] || return 1
  while IFS= read -r line; do
    case "$line" in
      "$2:"*)
        v="${line#*:}"
        v="${v//[[:space:]]/}"
        v="${v%kB}"
        [[ "$v" =~ $num_re ]] || return 3
        READ_KB="$v"
        return 0
        ;;
    esac
  done <"$1" 2>/dev/null || return 1
  return 1
}

# コンテナ i のツリーを集計する。結果は m_pss・m_rss・m_n。0 = 成功、1 = 無効（m_reason に理由）。
measure_container() {
  local i="$1" attempt=0 pid rc vanished unreadable=0
  m_reason=""
  while [ "$attempt" -lt "$MAX_SCAN_ATTEMPTS" ]; do
    attempt=$((attempt + 1))
    m_pss=0
    m_rss=0
    m_n=0
    vanished=0
    rc=0
    ln_collect_pids "${pids[i]}" || rc=$?
    record_tree "$i"
    # 子プロセス一覧を読めない（4）のは、走査中のスレッド終了など一時的な場合があるのでやり直す。
    # 続く場合は試行回数の上限で process-tree-unreadable として失敗にする。
    if [ "$rc" -eq 4 ]; then unreadable=1; continue; fi
    unreadable=0
    if [ "$rc" -ne 0 ]; then m_reason="process-tree-unavailable"; return 1; fi
    # 計測時点でも起動条件（ツリーのプロセス数 >= --min-procs）を満たすこと。満たさなければ過少計上。
    if ! ln_alive "$i" || [ "${#tree_pids[@]}" -lt "$min_procs" ]; then
      m_reason="process-tree-too-small"
      return 1
    fi
    # 計測直前にも launcher の ready 状態を確認する（起動途中のプロセスを成功として公開しない）。
    if ! ln_ready "$tmpdir/${id_prefix}-${t}-$((i + 1)).log"; then
      m_reason="launcher-not-ready"
      return 1
    fi
    for pid in "${tree_pids[@]}"; do
      # 後始末（トークン照合）で回収できないプロセスを含む計測は成功にしない（所有権を追跡できない）。
      if ! owned_by_token "$pid"; then
        if [ ! -e "$proc/$pid" ]; then vanished=1; break; fi
        m_reason="untracked-process"
        return 1
      fi
      rc=0
      read_kb "$proc/$pid/smaps_rollup" Pss || rc=$?
      if [ "$rc" -eq 0 ]; then
        m_pss=$((m_pss + READ_KB))
        rc=0
        read_kb "$proc/$pid/status" VmRSS || rc=$?
        if [ "$rc" -eq 0 ]; then m_rss=$((m_rss + READ_KB)); fi
      fi
      if [ "$rc" -ne 0 ]; then
        if [ ! -e "$proc/$pid" ]; then vanished=1; break; fi
        m_reason="unreadable-memory-value"
        if [ "$rc" -eq 3 ]; then m_reason="non-numeric-memory-value"; fi
        return 1
      fi
      m_n=$((m_n + 1))
    done
    if [ "$vanished" -eq 0 ]; then return 0; fi
  done
  m_reason="process-tree-unstable"
  if [ "$unreadable" -eq 1 ]; then m_reason="process-tree-unreadable"; fi
  return 1
}

container_ok() { # <i>
  local rc=0
  ln_alive "$1" || return 1
  ln_ready "$tmpdir/${id_prefix}-${t}-$(($1 + 1)).log" || return 1
  ln_collect_pids "${pids[$1]}" || rc=$?
  record_tree "$1"
  [ "$rc" -eq 0 ] || return 1
  [ "${#tree_pids[@]}" -ge "$min_procs" ]
}

mem_available() {
  if read_kb /proc/meminfo MemAvailable; then printf '%s' "$READ_KB"; else printf '0'; fi
}

# 起動数不足の詳細（未起動 ID とログ末尾。件数・行数上限つき）を stderr へ出す。
report_unstarted() { # <trial>
  local i shown=0 id line sz
  for i in "${!pids[@]}"; do
    [ "${ok_flags[i]}" = "1" ] && continue
    [ "$shown" -lt "$MAX_REPORT_IDS" ] || break
    shown=$((shown + 1))
    id="${id_prefix}-$1-$((i + 1))"
    err "unstarted" "id=${id}"
    if [ -r "$tmpdir/$id.log" ]; then
      # ログが上限に達していれば、それ以降の出力（READY を含む）は記録されていないことを示す。
      sz="$(wc -c <"$tmpdir/$id.log" 2>/dev/null || true)"
      sz="${sz//[[:space:]]/}"
      if [[ "$sz" =~ $num_re ]] && [ "$sz" -ge "$((LOG_MAX_KIB * 1024))" ]; then
        err "unstarted-log-truncated" "id=${id} bytes=${sz} limit_kib=${LOG_MAX_KIB}"
      fi
      while IFS= read -r line; do
        err "unstarted-log" "${id}: $(sanitize "$line")"
      done < <(tail -n "$MAX_LOG_TAIL" "$tmpdir/$id.log" 2>/dev/null || true)
    fi
  done
}

# --- 計測本体 ---
trial_pss=()
trial_rss=()
trial_json=()
n_started_min="$count"

t=1
while [ "$t" -le "$trials" ]; do
  mem_before="$(mem_available)"
  pids=()
  pstart=()
  cpids=()
  cstart=()
  known=()
  ok_flags=()
  # ログ収集プロセスを全コンテナ分、launcher より先に起動する（launcher の同時起動の間に挟まない）。
  i=0
  while [ "$i" -lt "$count" ]; do
    id="${id_prefix}-${t}-$((i + 1))"
    in_spawn=1
    if ! log_collector_start "$tmpdir/$id.log"; then
      in_spawn=0
      err "measurement-failed" "trial=${t} id=${id} reason=cannot-create-log-fifo"
      exit 1
    fi
    cpids+=("$LAST_CPID")
    cstart+=("$LAST_CSTART")
    spawn_section_end
    i=$((i + 1))
  done
  i=0
  need_sweep=1
  # 起動をずらさず、できるだけ同時に起動する（起動競合も計測条件に含める）。
  while [ "$i" -lt "$count" ]; do
    id="${id_prefix}-${t}-$((i + 1))"
    in_spawn=1
    ln_spawn "$id" "$tmpdir/$id.log"
    pids+=("$LAST_PID")
    pstart+=("$LAST_START")
    ok_flags+=(0)
    spawn_section_end
    i=$((i + 1))
  done

  # 起動完了待ち（期限つき。REPAIR-5）。全コンテナが ready か終了済みになれば待たない。
  deadline=$((SECONDS + timeout_s))
  while :; do
    pending=0
    for i in "${!pids[@]}"; do
      [ "${ok_flags[i]}" = "1" ] && continue
      if container_ok "$i"; then
        ok_flags[i]=1
      elif ln_alive "$i"; then
        pending=1
      fi
    done
    [ "$pending" -eq 1 ] || break
    [ "$SECONDS" -lt "$deadline" ] || break
    sleep "$POLL_INTERVAL"
  done

  # settle 待機は 1 秒刻みにする（bash は実行中の sleep が終わるまで trap を動かさないため、長い sleep
  # 1 回だと TERM / INT / HUP を受けてから後始末を始めるまでが settle 秒だけ遅れる）。
  settled=0
  while [ "$settled" -lt "$settle" ]; do
    sleep 1
    settled=$((settled + 1))
  done
  n_started=0
  for i in "${!pids[@]}"; do
    if [ "${ok_flags[i]}" = "1" ] && container_ok "$i"; then
      n_started=$((n_started + 1))
    else
      ok_flags[i]=0
    fi
  done
  if [ "$n_started" -lt "$count" ]; then
    err "startup-incomplete" "trial=${t} started=${n_started}/${count}"
    report_unstarted "$t"
    exit 1
  fi
  if [ "$n_started" -lt "$n_started_min" ]; then n_started_min="$n_started"; fi

  pss_total=0
  rss_total=0
  zero_pss=0
  proc_count=0
  for i in "${!pids[@]}"; do
    if ! measure_container "$i"; then
      err "measurement-failed" "trial=${t} id=${id_prefix}-${t}-$((i + 1)) reason=${m_reason}"
      exit 1
    fi
    if [ "$m_pss" -le 0 ]; then zero_pss=$((zero_pss + 1)); fi
    pss_total=$((pss_total + m_pss))
    rss_total=$((rss_total + m_rss))
    proc_count=$((proc_count + m_n))
  done
  if [ "$zero_pss" -gt 0 ]; then
    err "measurement-failed" "trial=${t} zero_pss_count=${zero_pss} (refusing to sum containers with PSS 0)"
    exit 1
  fi
  # 集計は 1 コンテナずつ順に行うため、先に集計したコンテナが後続の集計中に終了し得る。全コンテナの
  # 集計後に起動条件（launcher の生存・READY・プロセス数 >= --min-procs）を全件で再確認し、1 つでも
  # 欠けていれば「N 個同時稼働時の集約値」ではないので失敗にする（CORE-9。過少計上を公開しない）。
  n_started=0
  for i in "${!pids[@]}"; do
    if container_ok "$i"; then
      n_started=$((n_started + 1))
    else
      ok_flags[i]=0
    fi
  done
  if [ "$n_started" -lt "$count" ]; then
    err "measurement-failed" "trial=${t} running_after_measurement=${n_started}/${count} reason=container-exited-during-measurement"
    report_unstarted "$t"
    exit 1
  fi
  mem_after="$(mem_available)"
  trial_pss+=("$pss_total")
  trial_rss+=("$rss_total")
  trial_json+=("$(printf '{"trial": %s, "n_expected": %s, "n_started": %s, "zero_pss_count": %s, "pss_total_kb": %s, "rss_total_kb": %s, "mem_available_delta_kb": %s, "process_count": %s}' \
    "$t" "$count" "$n_started" "$zero_pss" "$pss_total" "$rss_total" "$((mem_before - mem_after))" "$proc_count")")

  # 次の試行へ進む前に必ず後始末する（残存は 4 を最優先で返す）。
  ln_stop || exit 4
  t=$((t + 1))
done

# 中央値（偶数個は中央 2 値の平均を小数 1 桁。整数除算の丸めを避ける）。
median() {
  local sorted n sum
  mapfile -t sorted < <(printf '%s\n' "$@" | sort -n)
  n="${#sorted[@]}"
  if [ $((n % 2)) -eq 1 ]; then
    printf '%s' "${sorted[n / 2]}"
  else
    sum=$((sorted[n / 2 - 1] + sorted[n / 2]))
    printf '%s.%s' "$((sum / 2))" "$((sum % 2 * 5))"
  fi
}
pss_median="$(median "${trial_pss[@]}")"
rss_median="$(median "${trial_rss[@]}")"

if ! ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || ! kernel="$(uname -r)" || ! arch="$(uname -m)"; then
  err "measurement-failed" "cannot determine timestamp, kernel or arch"
  exit 1
fi
kernel="${kernel//[^A-Za-z0-9._+-]/}"
arch="${arch//[^A-Za-z0-9._-]/}"

# JSON へ埋め込む文字列は検証済み（target・mode）か上で安全な文字だけに絞った値のみ。
out_buf=""
if [ "$format" = "json" ]; then
  out_buf+='{'$'\n'
  out_buf+='  "schema_version": 1,'$'\n'
  out_buf+='  "benchmark": "concurrent_memory",'$'\n'
  out_buf+='  "behavior": ["CORE-9", "SUP-1"],'$'\n'
  out_buf+='  "task": "TASK-50",'$'\n'
  out_buf+="  \"mode\": \"${mode}\","$'\n'
  out_buf+="  \"target\": \"${target_name}\","$'\n'
  out_buf+="  \"timestamp\": \"${ts}\","$'\n'
  out_buf+="  \"kernel\": \"${kernel}\","$'\n'
  out_buf+="  \"arch\": \"${arch}\","$'\n'
  out_buf+="  \"count\": ${count},"$'\n'
  out_buf+="  \"trials\": ${trials},"$'\n'
  out_buf+="  \"n_started_min\": ${n_started_min},"$'\n'
  out_buf+='  "metrics": {'$'\n'
  out_buf+="    \"concurrent_${count}_pss_median_kb\": {\"value\": ${pss_median}, \"unit\": \"kB\"},"$'\n'
  out_buf+="    \"concurrent_${count}_rss_median_kb\": {\"value\": ${rss_median}, \"unit\": \"kB\"}"$'\n'
  out_buf+='  },'$'\n'
  out_buf+='  "trial_results": ['$'\n'
  for i in "${!trial_json[@]}"; do
    sep=","
    if [ "$i" -eq "$((${#trial_json[@]} - 1))" ]; then sep=""; fi
    out_buf+="    ${trial_json[i]}${sep}"$'\n'
  done
  out_buf+='  ]'$'\n'
  out_buf+='}'$'\n'
else
  out_buf+="started=${n_started_min}/${count}"$'\n'
  out_buf+="trials=${trials}"$'\n'
  out_buf+="pss_median_kb=${pss_median}"$'\n'
  out_buf+="rss_median_kb=${rss_median}"$'\n'
fi

# 公開は全試行の検証後に 1 回だけ行う（失敗した計測結果を正規の成果物として残さない）。
if [ -n "$output" ]; then
  if ! out_tmp="$(mktemp "${output}.XXXXXX" 2>/dev/null)"; then err "output-failed" "cannot create temporary file next to the output"; exit 2; fi
  if ! printf '%s' "$out_buf" 2>/dev/null >"$out_tmp"; then err "output-failed" "cannot write temporary file"; exit 2; fi
  # ln -T（link(2)）で公開する（startup_latency.sh の publish_result と同じ方式）。出力先が種別を問わず
  # 既に存在すれば失敗し、symlink を辿らず、ディレクトリ内へも作らない。計測中に同名のファイルが
  # 作られていても上書きしない。一時ファイルは成功・失敗のどちらでも消す（失敗時は EXIT trap）。
  if ! ln -T -- "$out_tmp" "$output" 2>/dev/null; then
    err "output-failed" "cannot publish output (it may already exist, or hard links are unsupported)"
    exit 2
  fi
  rm -f -- "$out_tmp" || true
  out_tmp=""
else
  if ! printf '%s' "$out_buf" 2>/dev/null; then err "output-failed" "cannot write to stdout"; exit 2; fi
fi
exit 0
