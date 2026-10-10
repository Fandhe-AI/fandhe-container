#!/usr/bin/env bash
# restart レイテンシ実機実測スクリプト（TASK-160・SUP-3・MS-9。実測・合否判定は #491・TASK-160.h1 で人間が行う）。
#
# 役割: バックオフ 0 の restart ポリシー下で、コンテナ側プロセスを SIGKILL してから supervisor が新しい
# コンテナを起動し終えるまでのレイテンシを複数試行計測し、中央値・p95 を JSON で出力する。
# SUP-3 の目標は「バックオフ 0 の再起動レイテンシ中央値 100ms 以下」（PoC-17 own 実測: 中央値 1.79ms・
# p95 2.29ms）。本スクリプトは合否を出さない（目標値との比較・レポート化は #491 の担当）。
# 実装済みを装わない（REPAIR-3）: 製品バイナリ（TASK-79 の CLI・本番 launcher）は未提供のため現時点では
# 実測できない。CI で動かすのはスタブ launcher の自己テスト scripts/measure-restart-latency-selftest.sh のみ。
#
# 呼び出し元: Makefile の `restart-latency`（操作者が明示実行。make ci には含めない）。sudo は呼ばない
# （権限が要る場合は操作者が権限付きシェルから実行する）。crates/supervisor の restart ループ
# （restart.rs の supervise_with_restart）と、state.json（crates/core の StateStore）を外から観測する。
#
# launcher 契約（scripts/verify-supervisor-independence.sh と同一の暫定契約＋再起動用の 2 引数。
# TASK-79 の CLI 確定後に起動行 build_launch_cmd だけ合わせる）:
#   <launcher> run --id <id> --bundle <bundle> --restart <policy> --restart-backoff-ms 0
#   をフォアグラウンドで実行（配列で直接 exec。eval・sh -c を使わない）。起動完了で標準出力に `READY` だけの
#   行を出し、環境変数 FANDHE_BENCH_OWNER の実行ごとのトークンを受け取る。停止は SIGTERM、期限超過で SIGKILL。
#   コンテナ側プロセスは launcher の子孫で、state.json（<state-root>/<id>/state.json。camelCase の
#   status・pid・restartCount）に実行中 pid と再起動回数を反映する。
#   状態保存先: 環境変数 FANDHE_BENCH_STATE_ROOT に state.json 群の親ディレクトリ（<state-root>）の絶対パスを渡す
#   （--state-root 指定時はその値。省略時は本スクリプトが決めた既定の場所。root で省略時は /run/fandhe-container）。
#   launcher は state.json をこの下の <id>/state.json へ書く。
#   restart のたびに構造化ログ {"component":"supervisor.monitor","operation":"restart","result":"ok",
#   "elapsed_us":N} を標準エラーへ出す（任意。無ければ supervisor_reported は null）。
#
# 計測区間（出力 method にも明記）:
#   observed            : コンテナ側プロセスへ SIGKILL を送る直前 → state.json が status=running・pid 変化・
#                         restartCount+1 を初めて返した時点。シグナル配送・終了検知・本スクリプトのポーリング粒度を
#                         含む上側推定（主系列）。
#   supervisor_reported : launcher ログの restart 行 elapsed_us（終了検知 → Running 記録完了。検知待ちを含まない。
#                         SUP-3 の定義に近い副系列）。件数が trials+warmup と一致しないときは null。
#   PoC-17 はワークロード自身が記録した「次の開始時刻 − 前の終了時刻」で区間が異なるため、直接比較しない。
# 集計: 中央値は偶数個のとき中央 2 値の平均。p95 は昇順の ceil(n*95/100)-1 番目（restart_latency.rs と同じ。
#   net_setup_timing.sh の p90 式とは別物）。
#
# 使い方:
#   measure-restart-latency.sh --launcher <絶対パス> --bundle <dir>
#       [--trials N（1〜200。既定 20＝PoC-17）] [--warmup W（0〜20。既定 1。集計から除外）]
#       [--timeout SECS（各待機の上限 1〜600。既定 30）] [--policy on-failure|always（既定 on-failure）]
#       [--state-root <絶対パス>] [--poll-us N（100〜100000。既定 1000）] [--settle-ms N（0〜5000。既定 50）]
#       [--label STR] [--id-prefix STR（既定 fc-restart-lat）] [--output FILE（新規ファイルのみ）]
#       [--print-budget（実行全体の所要時間の上限〔秒〕だけを出して終了。launcher は起動しない）] [--help]
#   --state-root 省略時: 非 root は一時ディレクトリを XDG_RUNTIME_DIR として launcher に渡す。root は
#   /run/fandhe-container を読む（crates/core の解決規則と同じ）。
#
# 出力: JSON（標準出力。--output 指定時はそのファイル）。launcher・bundle・state-root のパス、cmdline、環境変数は出さない。
#   結果は後始末の成功を確認した後にだけ公開する（失敗・中断・後始末失敗では標準出力・--output とも出さない）。
# 終了コード: 0 = 成功 / 1 = 計測失敗（READY なし・期限切れ・再起動未観測・時計変更・launcher 異常終了・想定外の
#   内部エラー）/ 2 = 引数・入力・出力先エラー / 3 = 前提欠如（非 Linux・bash 5 未満・jq・/proc。0 で合格に見せない）/
#   4 = 後始末失敗（残存プロセス・帰属を証明できない生存 pid。最優先）/ 129・130・143 = HUP・INT・TERM による中断
#   （後始末の完了後）。set -e による想定外の中断は、そのコマンドの終了コードに関わらず 1 に正規化する。
# 期限: 各待機（READY・running・試行ごとの再起動観測）は --timeout を上限とし、単調時計（/proc/uptime）で判定する。
#   実行全体の上限は --print-budget の値（既定の 20 試行・warmup 1・--timeout 30 で 813 秒）。本スクリプト自身は
#   全体期限を持たないので、外側で timeout をかける場合はこの値以上にする（Makefile の restart-latency は未指定時に
#   この値を使う）。
# 新プロセスの検証: 観測時と確定時に、新 pid が生存し（ゾンビ除外）launcher の子孫で、起動時刻が一致することを
#   確認する（SUP-3。state.json だけ残って新プロセスが終了した試行は採用しない）。
#
# シグナル送信の規則（実機でプロセスへシグナルを送るため、全経路で次を守る）:
#   - 送信先は「本計測が起動したと証明できたプロセス」だけ。証明の根拠は次のいずれか:
#       (a) launcher 本体: 本スクリプトの直接の子（親 pid = $$）で、起動直後に記録した起動時刻と一致する。
#       (b) launcher の子孫: launcher が (a) で生存中に PPid 連鎖が launcher へ届き、連鎖の全プロセスが辿った前後で
#           同じ起動時刻のまま存在する（試行で kill するコンテナ側プロセス・停止前に採取する子孫スナップショット）。
#       (c) 所有トークン: 環境変数に FANDHE_BENCH_OWNER=<本実行の 128 bit 乱数> の完全一致エントリを持つ。
#       (d) launcher 停止後に state.json へ現れた pid: (c) か、launcher の session に属し、かつ同じ session に
#           (b) で記録済みの生存プロセスがいる（session 番号が再利用されていないことの証明）場合だけ。
#     state.json の pid・起動時刻が launcher 以降・comm 名の一致は、いずれも単独では根拠にしない。
#   - 送信はすべて sig_same_proc を通し、pid 単体へ送る（プロセスグループ・session 宛や名前一致では送らない）。
#     直前に「記録した起動時刻のまま生存している同一プロセスか」を再照合する。
#   - 証明できない生存 pid（state.json にあるが子孫でも (c)(d) でもない）にはシグナルを送らず、警告を出して
#     終了コード 4 にする（結果は公開しない）。launcher より前から動いていたプロセスは無関係と確定するので 4 にしない。
# 後始末: launcher の子孫を記録 → launcher へ SIGTERM（5 秒で止まらなければ SIGKILL）→ 帰属不明 pid の再判定 →
#   所有トークン一致と記録済みのプロセスへ SIGKILL（最大 5 秒再試行）→ 最終走査で 1 つでも生存していれば 4。
#   restart ログの副系列は launcher 停止後に集計する（最後の restart ログが状態更新より遅れても欠損にしない）。
# 原理的に残る制約（sh では pidfd_open・pidfd_send_signal を使えないことによる。隠さず明記する）:
#   - 同一性の照合と kill(2) は不可分にできない。照合の直後に対象が終了し、その pid が kill までの間に別プロセスへ
#     割り当て直されると誤送信になる。窓は組み込みコマンド数個分（fork・待機なし）に絞ってあり、成立にはその間に
#     pid 空間が一巡する必要がある（Linux の pid 割り当ては循環式）。
#   - 起動時刻（/proc/<pid>/stat の field 22）は 1/100 秒刻み。同じ刻みの中で pid が再利用された場合は区別できない。
#   - 検出できない残存: トークンを継承せず、launcher 停止前の子孫スナップショットにも state.json にも現れない
#     プロセス（スナップショット後に生まれた孤児・launcher が記録前に異常終了した場合の孤児）は検出できない。
#     launcher が子孫を 1 度も記録できないまま終了した場合は標準エラーへ note を出す。
#   - 本スクリプト自身が SIGKILL された場合（外側 timeout の --kill-after を含む）は後始末できない。launcher は
#     setsid で別 session にあり、外側 timeout のシグナルは届かないため残存し得る。
set -euo pipefail

readonly num_re='^(0|[1-9][0-9]{0,8})$'
readonly pid_re='^[1-9][0-9]{0,9}$'
readonly dig_re='^[0-9]{1,18}$'
readonly id_re='^[A-Za-z0-9_-]{1,32}$'
readonly label_re='^[A-Za-z0-9._-]{1,64}$'

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
trials=20
warmup=1
timeout_s=30
policy="on-failure"
state_root=""
poll_us=1000
settle_ms=50
print_budget=0
label=""
id_prefix="fc-restart-lat"
output=""

need_val() { [ "$1" -ge 2 ] || { err "invalid-argument" "$2 requires a value"; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --launcher) need_val $# "$1"; launcher="$2"; shift 2 ;;
    --bundle) need_val $# "$1"; bundle="$2"; shift 2 ;;
    --trials) need_val $# "$1"; trials="$2"; shift 2 ;;
    --warmup) need_val $# "$1"; warmup="$2"; shift 2 ;;
    --timeout) need_val $# "$1"; timeout_s="$2"; shift 2 ;;
    --policy) need_val $# "$1"; policy="$2"; shift 2 ;;
    --state-root) need_val $# "$1"; state_root="$2"; shift 2 ;;
    --poll-us) need_val $# "$1"; poll_us="$2"; shift 2 ;;
    --settle-ms) need_val $# "$1"; settle_ms="$2"; shift 2 ;;
    --label) need_val $# "$1"; label="$2"; shift 2 ;;
    --id-prefix) need_val $# "$1"; id_prefix="$2"; shift 2 ;;
    --output) need_val $# "$1"; output="$2"; shift 2 ;;
    --print-budget) print_budget=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) err "invalid-argument" "unknown option"; exit 2 ;;
  esac
done

check_range() { # <名前> <値> <最小> <最大>
  [[ "$2" =~ $num_re ]] || { err "invalid-argument" "$1 must be a non-negative integer"; exit 2; }
  { [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; } || { err "invalid-argument" "$1 must be from $3 to $4"; exit 2; }
}

check_range "--trials" "$trials" 1 200
check_range "--warmup" "$warmup" 0 20
check_range "--timeout" "$timeout_s" 1 600
check_range "--poll-us" "$poll_us" 100 100000
check_range "--settle-ms" "$settle_ms" 0 5000
# --print-budget: 実行全体の所要時間の上限（秒）だけを出して終わる（launcher は起動しない）。外側の timeout
# （Makefile の restart-latency）はこの値を使う。内訳は「READY・running・各試行の待機 = (試行数 + 2) × --timeout」
# ＋「試行ごとの settle（秒へ切り上げ）と検証・子孫記録の余裕 2 秒」＋「後始末 60 秒（do_cleanup の上限約 20 秒に余裕）」。
if [ "$print_budget" -eq 1 ]; then
  printf '%s\n' "$(((trials + warmup + 2) * timeout_s + (trials + warmup) * ((settle_ms + 999) / 1000 + 2) + 60))"
  exit 0
fi
[ -n "$launcher" ] || { err "invalid-argument" "--launcher is required"; exit 2; }
[ -n "$bundle" ] || { err "invalid-argument" "--bundle is required"; exit 2; }
case "$policy" in on-failure | always) ;; *) err "invalid-argument" "--policy must be on-failure or always"; exit 2 ;; esac
[[ "$id_prefix" =~ $id_re ]] || { err "invalid-argument" "--id-prefix must match [A-Za-z0-9_-]{1,32}"; exit 2; }
if [ -n "$label" ] && ! [[ "$label" =~ $label_re ]]; then
  err "invalid-argument" "--label must match [A-Za-z0-9._-]{1,64}"; exit 2
fi
case "$launcher" in /*) ;; *) err "invalid-argument" "--launcher must be an absolute path"; exit 2 ;; esac
if [ -n "$state_root" ]; then
  case "$state_root" in /*) ;; *) err "invalid-argument" "--state-root must be an absolute path"; exit 2 ;; esac
fi
case "$launcher$bundle$state_root$output" in *$'\n'*) err "invalid-argument" "paths must not contain newlines"; exit 2 ;; esac
[ -d "$bundle" ] || { err "invalid-argument" "--bundle is not a directory"; exit 2; }
[ -z "$state_root" ] || [ -d "$state_root" ] || { err "invalid-argument" "--state-root is not a directory"; exit 2; }

# 祖先を含むディレクトリが他ユーザーに差し替えられないこと（verify-supervisor-independence.sh と同じ規則）。
dir_is_safe() {
  local d="$1" uid
  uid="$(id -u)"
  [ -n "$(find -P "$d" -maxdepth 0 -type d \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) ! -perm -1000 -print 2>/dev/null)" ]
}

path_chain_is_safe() { # <dir>
  local logical physical d parent depth=0
  logical="$(cd -- "$1" && pwd -L)" || return 1
  physical="$(cd -- "$1" && pwd -P)" || return 1
  [ "$logical" = "$physical" ] || return 1
  d="$physical"
  while :; do
    dir_is_safe "$d" || return 1
    parent="$(dirname -- "$d")"
    [ "$parent" = "$d" ] && break
    depth=$((depth + 1))
    [ "$depth" -le 256 ] || return 1
    d="$parent"
  done
}

for req in find id dirname; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
# --state-root の state.json は kill 対象 pid の入力になる。他ユーザーが差し替えられる場所は受け付けない。
if [ -n "$state_root" ] && ! path_chain_is_safe "$state_root"; then
  err "invalid-argument" "--state-root and the directories above it must be symlink-free, owned by you or root, and not writable by others (unless sticky)"
  exit 2
fi
if [ -L "$launcher" ] || [ ! -f "$launcher" ] || [ ! -x "$launcher" ]; then
  err "invalid-argument" "--launcher must be an executable regular file (not a symlink)"
  exit 2
fi
uid_now="$(id -u)"
if [ -z "$(find -P "$launcher" -maxdepth 0 -type f \( -user "$uid_now" -o -user 0 \) ! -perm -0020 ! -perm -0002 -print 2>/dev/null)" ]; then
  err "invalid-argument" "--launcher must be owned by you or root and not writable by group or others"
  exit 2
fi
if ! path_chain_is_safe "$(dirname -- "$launcher")"; then
  err "invalid-argument" "the directories above --launcher must be symlink-free, owned by you or root, and not writable by others (unless sticky)"
  exit 2
fi

if [ -n "$output" ]; then
  # 既存のパス（symlink・ディレクトリを含む）は拒否し上書きしない。公開は ln -T で「存在しない場合だけ作成」。
  if [ -e "$output" ] || [ -L "$output" ]; then
    err "invalid-argument" "output path already exists (refusing to overwrite; --output must be a new file)"
    exit 2
  fi
  output_dir="${output%/*}"
  [ "$output_dir" != "$output" ] || output_dir="."
  [ -n "$output_dir" ] || output_dir="/"
  [ -d "$output_dir" ] || { err "invalid-argument" "output directory does not exist"; exit 2; }
  if ! path_chain_is_safe "$output_dir"; then
    err "invalid-argument" "the path of --output must not contain symlinks, and every directory above it must be owned by you or root and not writable by others (unless sticky)"
    exit 2
  fi
  output_dir="$(cd -- "$output_dir" && pwd -P)" || { err "invalid-argument" "output directory cannot be resolved"; exit 2; }
  case "$output_dir" in
    /) output="/${output##*/}" ;;
    *) output="${output_dir}/${output##*/}" ;;
  esac
fi

# --- 前提確認（欠如は 3。0 を返して合格に見せない） ---
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then err "unsupported-os" "bash 5 or later is required"; exit 3; fi
if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then err "unsupported-os" "only Linux is supported"; exit 3; fi
for req in mktemp ln grep sleep kill uname od tr jq setsid env rm mkfifo; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
[ -r /proc/self/stat ] && [ -r /proc/uptime ] || { err "unsupported-os" "/proc is required"; exit 3; }

# --- 状態 ---
workdir=""
owner_tok=""
launcher_pid=""
launcher_start=""
intended_rc=""
in_launch=0
pending_rc=""
reported="null"
reported_err=0
collect_log=0
snap_seen=0
last_snap_cs=0
# 本計測への帰属を証明済みのプロセスの「pid → 起動時刻」（試行で kill 対象にしたコンテナ側プロセスと、launcher の
# 生存中に採取した子孫のスナップショット）。後始末で全件を同一性照合のうえ回収する。
declare -A tracked=()
# state.json に現れたが帰属を証明できなかった生存 pid の「pid → 起動時刻」。シグナルは送らず、後始末の最後まで
# 帰属を証明できずに生存していれば終了コード 4 にする。launcher より前に起動していたものは入れない（無関係と確定）。
declare -A suspects=()
cleaned=0
napfd=""
out_tmp=""
state_file=""
container_id=""

# 待機は組み込みの read -t（fork しない）で行う。ポーリング中に一過性の子プロセスを作らないため。
nap() { read -r -t "$1" -u "$napfd" || true; }

# マイクロ秒の現在時刻（EPOCHREALTIME の小数点は locale により , の場合がある）。計測値にだけ使う。
now_us() { local t="$EPOCHREALTIME"; t="${t/[.,]/}"; REPLY_US=$((10#$t)); }
# 単調時計（/proc/uptime。1/100 秒）。待機の期限はすべてこちらで判定する（壁時計の変更で期限がずれない）。
up_cs() { local up; read -r up _ </proc/uptime; up="${up/[.,]/}"; REPLY_CS=$((10#$up)); }

# /proc/<pid>/stat から状態・ppid・session・起動時刻（field 22）を得る。comm は空白・括弧・改行を含み得るため
# 全体を読み、最後の ") " 以降だけを使う（comm に ") Z " 等を仕込んでも状態を偽れない）。fork しない。
proc_info() { # <pid> → REPLY_STATE / REPLY_PPID / REPLY_SID / REPLY_START（読めない・形式不正は return 1）
  local s="" rest
  local -a f=()
  [[ "$1" =~ $pid_re ]] || return 1
  { IFS= read -r -d '' s <"/proc/$1/stat" || true; } 2>/dev/null
  [ -n "$s" ] || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  [ "${#f[@]}" -ge 20 ] || return 1
  [[ "${f[0]}" =~ ^[A-Za-z]$ && "${f[1]}" =~ $dig_re && "${f[3]}" =~ $dig_re && "${f[19]}" =~ $dig_re ]] || return 1
  REPLY_STATE="${f[0]}"
  REPLY_PPID="${f[1]}"
  REPLY_SID="${f[3]}"
  REPLY_START="${f[19]}"
}

# 生存判定。kill -0 はゾンビも真になるため /proc の状態が Z（ゾンビ）・X（終了済み）でないことを見る。
alive() { # <pid>
  proc_info "$1" || return 1
  case "$REPLY_STATE" in Z | X | x) return 1 ;; esac
  return 0
}

# pid が「記録した起動時刻のまま生存している同一プロセス」か（PID 再利用の判別）。記録が空なら不一致扱い
# （同一性を証明できないものには送らない）。第 3 引数（親 pid）を渡すと親の一致も要求する。
same_proc() { # <pid> <記録した起動時刻> [<親 pid>]
  [ -n "${2:-}" ] || return 1
  alive "$1" || return 1
  [ "$REPLY_START" = "$2" ] || return 1
  [ -z "${3:-}" ] || [ "$REPLY_PPID" = "$3" ]
}

# 本スクリプトのシグナル送信はすべてここを通す（kill を直接呼ぶ箇所は他にない）。送信先は pid 単体だけで、
# プロセスグループ・セッション宛（負の pid・0）や名前一致（pkill）では送らない。直前に same_proc で同一性を
# 再照合し、照合から kill(2) までは組み込みコマンドだけ（fork・待機なし）にして窓を最小にする。
# 戻り値: 0 = 送信した / 1 = 同一性を確認できず送信しなかった / 2 = kill が失敗した。
sig_same_proc() { # <シグナル名> <pid> <記録した起動時刻> [<親 pid>]
  [[ "$2" =~ $pid_re ]] || return 1
  if [ "$2" -le 1 ] || [ "$2" = "$$" ]; then return 1; fi
  same_proc "$2" "$3" "${4:-}" || return 1
  kill "-$1" "$2" 2>/dev/null || return 2
}

# launcher が起動時に記録した同一プロセスのまま生存しているか。launcher は本スクリプトの直接の子なので
# 起動時刻に加えて親 pid（$$）の一致も要求する。
launcher_ok() { [ -n "$launcher_pid" ] && same_proc "$launcher_pid" "$launcher_start" "$$"; }

# /proc/<pid>/environ の NUL 区切りエントリに FANDHE_BENCH_OWNER=<token> が完全一致で含まれるか。
# 他プロセスの環境変数値に部分文字列として含まれるだけの場合（grep -F の部分一致）は所有と認めない。
env_owned() { # <pid>
  local e
  [ -n "$owner_tok" ] || return 1
  while IFS= read -r -d '' e; do
    [ "$e" = "FANDHE_BENCH_OWNER=$owner_tok" ] && return 0
  done <"/proc/$1/environ" 2>/dev/null
  return 1
}

# pid が launcher の子孫か（PPid 連鎖を 64 段まで辿る）。成功時の REPLY_START は対象 pid 自身の起動時刻。
# 連鎖の途中で pid が再利用されても誤認しないよう、(1) 親の起動時刻は子以前、(2) launcher へ到達した後に
# launcher と連鎖の全プロセスが記録した起動時刻のまま存在すること、を確認する（辿っている間ずっと同じ
# プロセスだったことの証明。孤児の引き取り先は祖先か init なので (1) は正当な木で常に成り立つ）。
is_descendant() { # <pid>
  local p="$1" depth=0 i
  local -a cp=() cs=()
  [ -n "$launcher_pid" ] || return 1
  while [ "$depth" -lt 64 ]; do
    proc_info "$p" || return 1
    if [ "$depth" -gt 0 ] && [ "$REPLY_START" -gt "${cs[$((depth - 1))]}" ]; then return 1; fi
    cp+=("$p")
    cs+=("$REPLY_START")
    p="$REPLY_PPID"
    if [ "$p" = "$launcher_pid" ]; then
      [ "$launcher_start" -le "$REPLY_START" ] || return 1
      launcher_ok || return 1
      for i in "${!cp[@]}"; do
        proc_info "${cp[$i]}" || return 1
        [ "$REPLY_START" = "${cs[$i]}" ] || return 1
      done
      REPLY_START="${cs[0]}"
      return 0
    fi
    [ "$p" -gt 1 ] || return 1
    depth=$((depth + 1))
  done
  return 1
}

# 帰属を証明済みのプロセスとして記録する（同一 pid は起動時刻を更新。pid 再利用後の古い記録は死んでいるので無害）。
track_pid() { tracked["$1"]="$2"; }

# launcher の生存中に、その子孫（state.json に現れない補助プロセス・トークンを継承しないプロセスを含む）を
# 「pid → 起動時刻」で tracked へ記録する（scripts/verify-supervisor-independence.sh の track_descendants と同じ考え方）。
# launcher 停止後は親子関係が失われ、孤児の帰属を証明できなくなるため、停止前に採取する。
# /proc の走査は非アトミックなので、走査後に launcher の同一性を確認し、各子孫を親から順に「親が検証済み・
# 親の起動時刻は子以前・走査時と同じ起動時刻で今も存在」の条件で検証できたものだけ記録する。上限 4096 件。
snapshot_descendants() {
  local d p q e n=0
  local -A sp=() ss=() ch=() ok=()
  local -a queue=() next=() order=()
  launcher_ok || return 1
  for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    proc_info "$p" || continue
    sp["$p"]="$REPLY_PPID"
    ss["$p"]="$REPLY_START"
  done
  launcher_ok || return 1
  for p in "${!sp[@]}"; do ch["${sp[$p]}"]+=" $p"; done
  queue=("$launcher_pid")
  while [ "${#queue[@]}" -gt 0 ] && [ "$n" -lt 4096 ]; do
    next=()
    for q in "${queue[@]}"; do
      for p in ${ch[$q]:-}; do
        [ "$n" -lt 4096 ] || break
        order+=("$p:$q")
        next+=("$p")
        n=$((n + 1))
      done
    done
    queue=(${next[@]+"${next[@]}"})
  done
  ok["$launcher_pid"]=1
  ss["$launcher_pid"]="$launcher_start"
  for e in ${order[@]+"${order[@]}"}; do
    p="${e%%:*}"
    q="${e#*:}"
    [ -n "${ok[$q]:-}" ] || continue
    [ "${ss[$q]}" -le "${ss[$p]}" ] || continue
    proc_info "$p" || continue
    [ "$REPLY_START" = "${ss[$p]}" ] || continue
    ok["$p"]=1
    track_pid "$p" "${ss[$p]}"
  done
  snap_seen=1
  return 0
}

# 待機ループから呼ぶ間引きつきスナップショット（0.2 秒に 1 回まで）。launcher が途中で異常終了しても、
# それまでに見えた子孫は記録済みになる。
snapshot_throttled() {
  up_cs
  [ "$REPLY_CS" -ge $((last_snap_cs + 20)) ] || return 0
  last_snap_cs="$REPLY_CS"
  snapshot_descendants || true
}

# state.json を純 bash で読む（計測区間内で jq を fork しない）。1 MiB 上限・symlink 拒否・通常ファイルのみ。
# 結果: ST_STATUS / ST_PID / ST_COUNT / ST_RAW。読めない・途中の内容は return 1（呼び出し側が再ポーリング）。
read_state() {
  local c=""
  ST_STATUS="" ST_PID="" ST_COUNT="" ST_RAW=""
  [ -L "$state_file" ] && return 1
  [ -f "$state_file" ] || return 1
  IFS= read -r -d '' -N 1048577 c <"$state_file" 2>/dev/null || true
  [ "${#c}" -le 1048576 ] || return 1
  [[ "$c" =~ \"status\"[[:space:]]*:[[:space:]]*\"([a-z]+)\" ]] || return 1
  ST_STATUS="${BASH_REMATCH[1]}"
  [[ "$c" =~ \"restartCount\"[[:space:]]*:[[:space:]]*([0-9]{1,9})[^0-9] ]] || return 1
  ST_COUNT=$((10#${BASH_REMATCH[1]}))
  if [[ "$c" =~ \"pid\"[[:space:]]*:[[:space:]]*([0-9]{1,9})[^0-9] ]]; then ST_PID=$((10#${BASH_REMATCH[1]})); else ST_PID=""; fi
  ST_RAW="$c"
  return 0
}

# 観測が終わった後に state.json を再読込して jq で厳密検証する。id 一致・status=running・観測した新 pid・
# restartCount == 旧 + 1 のすべてを満たさなければ失敗（ポーリング後に状態が変わった試行は採用しない）。
# jq には read_state が上限つきで読んだ内容を渡す（jq にファイルを直接開かせない）。
validate_state_strict() { # <観測した新 pid> <期待 restartCount>
  read_state || return 1
  jq -e --arg id "$container_id" --argjson pid "$1" --argjson cnt "$2" \
    '.id == $id and .status == "running" and (.pid|type=="number") and .pid == $pid and (.restartCount|type=="number") and .restartCount == $cnt' \
    <<<"$ST_RAW" >/dev/null 2>&1
}

# launcher 起動行。TASK-79 の CLI 確定時はここだけ合わせる（暫定契約）。
build_launch_cmd() {
  local pol="$policy"
  [ "$policy" = "always" ] || pol="on-failure:$((trials + warmup))"
  LAUNCH_CMD=("$launcher" run --id "$container_id" --bundle "$bundle" --restart "$pol" --restart-backoff-ms 0)
}

# launcher ログから副系列を集計する（launcher 停止後に do_cleanup から呼ぶ。非信頼入力として値域を検証し、
# 数値のみ採用する）。結果は reported（null または改行区切り数値）・reported_err（失敗した restart 行の有無）。
collect_reported() {
  local -a rep=()
  [ -s "$workdir/err.log" ] || return 0
  # jq の出力を grep -q へ直接パイプすると、失敗行が多く出力が複数回の書き込みになったとき、grep が先に
  # 終わった後の jq の書き込みが SIGPIPE（141）になり、pipefail で判定が偽（失敗の見落とし）になる。
  # 変数に取ってから照合する（#1726）。
  local err_hits=""
  if err_hits="$(jq -Rre 'fromjson? | select(type=="object" and .component=="supervisor.monitor" and .operation=="restart" and .result=="error") | "x"' "$workdir/err.log" 2>/dev/null)" &&
    grep -q x <<<"$err_hits"; then
    reported_err=1
    return 0
  fi
  mapfile -t rep < <(jq -Rre 'fromjson? | select(type=="object" and .component=="supervisor.monitor" and .operation=="restart" and .result=="ok") | .elapsed_us | select(type=="number" and .>=0 and .==floor and .<=3600000000)' "$workdir/err.log" 2>/dev/null || true)
  if [ "${#rep[@]}" -eq "$total" ]; then
    reported="$(printf '%s\n' "${rep[@]:$warmup}")"
  fi
}

# state.json の pid のうち launcher の子孫と確認できなかった生存プロセスを記録する（試行中と後始末から呼ぶ）。
# launcher より前から動いていたプロセスは本計測の生成物ではあり得ない（無関係と確定）ので記録しない。
# それ以外は帰属不明として suspects に入れ、後始末で帰属を再判定する。いずれの場合もシグナルは送らない。
note_suspect() { # <pid>
  alive "$1" || return 0
  if [ -n "$launcher_start" ] && [ "$REPLY_START" -lt "$launcher_start" ]; then return 0; fi
  suspects["$1"]="$REPLY_START"
}

# 追跡済みで、いまも launcher の session に属して生存しているプロセスがあるか。あれば session 番号
# （= launcher の pid）は本計測の session に割り当てられたままで、再利用されていないと証明できる。
session_anchor_alive() {
  local a
  for a in "${!tracked[@]}"; do
    if same_proc "$a" "${tracked[$a]}" && [ "$REPLY_SID" = "$launcher_pid" ]; then return 0; fi
  done
  return 1
}

# 帰属不明の pid（suspects）と、launcher 停止後の state.json の pid を再判定する。launcher 停止後は子孫関係を
# 辿れないので、帰属の根拠は (1) 環境変数に本実行の所有トークン（128 bit 乱数）の完全一致エントリを持つ、
# (2) launcher（setsid の leader）の session に属し、かつ同じ session に追跡済みの生存プロセスがいる
# （session_anchor_alive。launcher 終了後に同じ番号の session が別物として作り直されていないことの証明）、
# のいずれかに限る。起動時刻が launcher 以降というだけでは根拠にしない。証明できたものは tracked へ移し、
# できないものは kill せず警告を出して 1 を返す（呼び出し側が終了コード 4 にする）。
# 追跡済みプロセスを回収する前に呼ぶこと（(2) の証明に追跡済みの生存プロセスを使うため）。
attribute_suspects() {
  local p s sid rc=0
  if [ -n "$state_file" ] && [ -n "$launcher_pid" ] && read_state && [ -n "$ST_PID" ]; then
    p="$ST_PID"
    if [ "$p" != "$$" ] && ! same_proc "$p" "${tracked[$p]:-}"; then note_suspect "$p"; fi
  fi
  for p in "${!suspects[@]}"; do
    s="${suspects[$p]}"
    same_proc "$p" "$s" || continue
    sid="$REPLY_SID"
    if env_owned "$p" && same_proc "$p" "$s"; then
      track_pid "$p" "$s"
    elif [ "$sid" = "$launcher_pid" ] && session_anchor_alive && same_proc "$p" "$s" && [ "$REPLY_SID" = "$launcher_pid" ]; then
      track_pid "$p" "$s"
    else
      printf 'warning: pid %s in state.json cannot be attributed to this run; not signaling it\n' "$p" >&2 || true
      rc=1
    fi
  done
  return "$rc"
}

# 環境変数トークンが完全一致する生存プロセス（孤児化した launcher の子孫を含む）を "pid:起動時刻" で OWNED へ入れる。
# grep -F は候補の絞り込みだけに使い、所有判定は env_owned で行う。起動時刻は environ を読む前に控え、後で再照合する。
owned_scan() {
  local f p s
  OWNED=()
  [ -n "$owner_tok" ] || return 0
  while IFS= read -r f; do
    p="${f#/proc/}"
    p="${p%%/*}"
    [ "$p" != "$$" ] || continue
    alive "$p" || continue
    s="$REPLY_START"
    env_owned "$p" || continue
    if same_proc "$p" "$s"; then OWNED+=("$p:$s"); fi
  done < <(grep -l -a -F -s -- "FANDHE_BENCH_OWNER=$owner_tok" /proc/[0-9]*/environ 2>/dev/null || true)
}

tracked_alive() {
  local p
  for p in "${!tracked[@]}"; do
    if same_proc "$p" "${tracked[$p]}"; then return 0; fi
  done
  return 1
}

# 回収。戻り値 0 = 回収確認済み / 非 0 = 残存または帰属不明（呼び出し側が終了コード 4 にする）。
# 所要時間の上限は約 20 秒（launcher の停止待ち 5 + 2 秒、回収の再試行 5 秒、/proc 走査）。--print-budget は 60 秒を見込む。
do_cleanup() {
  local i d p rc=0
  [ "$cleaned" -eq 0 ] || return 0
  cleaned=1
  trap '' INT TERM HUP
  # 1. launcher の生存中に子孫を記録する（停止後は親子関係を辿れない）。
  if launcher_ok; then
    snapshot_descendants || true
  elif [ -n "$launcher_pid" ] && [ "$snap_seen" -eq 0 ]; then
    printf 'note: the launcher exited before its process tree could be recorded; leftovers that neither inherit the owner token nor appear in state.json cannot be detected\n' >&2 || true
  fi
  # 2. launcher を止める（同一性を確認できる間だけ送る。先に終了して PID が再利用されていれば送らない）。
  if launcher_ok; then
    sig_same_proc TERM "$launcher_pid" "$launcher_start" "$$" || true
    for ((i = 0; i < 100; i++)); do
      launcher_ok || break
      nap 0.05
    done
    # TERM で止まらなかった場合だけ届く（既に終了していれば sig_same_proc は送らない）。
    sig_same_proc KILL "$launcher_pid" "$launcher_start" "$$" || true
    for ((i = 0; i < 40; i++)); do
      launcher_ok || break
      nap 0.05
    done
  fi
  # 3. 帰属不明の pid を再判定する（追跡済みプロセスを回収する前に行う）。証明できなければ残存として 4。
  attribute_suspects || rc=4
  # 4. launcher 停止後なので restart ログは出尽くしている。副系列はここで集計する。
  if [ "$collect_log" -eq 1 ]; then collect_reported; fi
  # 5. トークン一致の所有プロセスと追跡済みプロセスを回収する。消えるまで最大 5 秒再試行する。
  for ((i = 0; i < 25; i++)); do
    owned_scan
    if [ "${#OWNED[@]}" -eq 0 ] && ! tracked_alive; then break; fi
    for d in ${OWNED[@]+"${OWNED[@]}"}; do
      p="${d%%:*}"
      if env_owned "$p"; then sig_same_proc KILL "$p" "${d#*:}" || true; fi
    done
    for p in "${!tracked[@]}"; do sig_same_proc KILL "$p" "${tracked[$p]}" || true; done
    [ -n "$napfd" ] || break
    nap 0.2
  done
  # 6. 最終確認。再試行の後に現れたものを含め、所有・追跡済みプロセスが 1 つでも生存していれば残存。
  owned_scan
  if [ "${#OWNED[@]}" -gt 0 ] || tracked_alive; then rc=4; fi
  if [ -n "$launcher_pid" ]; then
    if launcher_ok; then
      rc=4
    elif [ -z "$launcher_start" ] && alive "$launcher_pid" && [ "$REPLY_PPID" = "$$" ]; then
      rc=4 # 起動時刻を記録できず同一性を確認できないまま生存している子（シグナルは送っていない）
    else
      wait "$launcher_pid" 2>/dev/null || true
    fi
  fi
  [ -z "$workdir" ] || rm -rf -- "$workdir" 2>/dev/null || true
  if [ -n "$state_root" ] && [ -n "$container_id" ] && [ "$rc" -eq 0 ]; then
    # --state-root は操作者の領域。<id>/ は削除しない（残置を通知する）。
    printf 'note: left state entry for id %s under --state-root (operator-owned)\n' "$container_id" >&2 || true
  fi
  return "$rc"
}

# 終了コードは finish 経由で明示したものだけを返す。set -e による想定外の中断（jq 等の終了コードが 2〜4 と
# 偶然一致する場合を含む）は計測失敗（1）に正規化し、引数エラー・前提欠如・後始末失敗と取り違えさせない。
finish() { intended_rc="$1"; exit "$1"; }

# shellcheck disable=SC2329 # EXIT trap から呼ぶ
on_exit() {
  local rc=$?
  trap '' INT TERM HUP
  if [ -n "$intended_rc" ]; then
    rc="$intended_rc"
  else
    err "measurement-failed" "unexpected internal failure (status $rc); no result is published"
    rc=1
  fi
  if ! do_cleanup; then
    err "cleanup-failed" "processes may remain after the run; inspect and kill them manually"
    rc=4
  fi
  [ -z "$out_tmp" ] || rm -f -- "$out_tmp" 2>/dev/null || true
  trap - EXIT
  exit "$rc"
}

# launcher の起動から pid・起動時刻の記録までの間に届いたシグナルは保留し、記録後に処理する
# （記録前に後始末へ入ると、起動直後の launcher を止められないまま終了し得る）。
# shellcheck disable=SC2329 # INT・TERM・HUP trap から呼ぶ
on_signal() {
  if [ "$in_launch" -eq 1 ]; then pending_rc="$1"; else finish "$1"; fi
}
trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP

fail() { err "measurement-failed" "$1"; finish 1; }

# --- 準備 ---
umask 077
workdir="$(mktemp -d)"
mkfifo "$workdir/nap.fifo"
exec {napfd}<>"$workdir/nap.fifo"
owner_tok="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$owner_tok" =~ ^[0-9a-f]{32}$ ]] || { err "unsupported-os" "cannot generate an owner token"; finish 3; }
rand8="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$rand8" =~ ^[0-9a-f]{8}$ ]] || { err "unsupported-os" "cannot generate a container id"; finish 3; }
container_id="${id_prefix}-${rand8}"
launcher_env=()
if [ -n "$state_root" ]; then
  state_dir="$state_root"
  launcher_env=("FANDHE_BENCH_STATE_ROOT=$state_root")
elif [ "$uid_now" -eq 0 ]; then
  state_dir="/run/fandhe-container"
  launcher_env=("FANDHE_BENCH_STATE_ROOT=$state_dir")
else
  mkdir -m 0700 "$workdir/xdg"
  launcher_env=("XDG_RUNTIME_DIR=$workdir/xdg" "FANDHE_BENCH_STATE_ROOT=$workdir/xdg/fandhe-container")
  state_dir="$workdir/xdg/fandhe-container"
fi
state_file="$state_dir/$container_id/state.json"
printf -v poll_s '0.%06d' "$poll_us"
printf -v settle_s '%d.%03d' "$((settle_ms / 1000))" "$((settle_ms % 1000))"
total=$((trials + warmup))

build_launch_cmd
in_launch=1
(
  ulimit -f 4096 2>/dev/null || true # 標準エラーの肥大化を 4 MiB で止める（超過で launcher が止まり計測失敗）
  exec setsid env "FANDHE_BENCH_OWNER=$owner_tok" "${launcher_env[@]}" "${LAUNCH_CMD[@]}" \
    >"$workdir/out.log" 2>"$workdir/err.log" </dev/null
) &
launcher_pid=$!
# 直接の子（親が $$）であることを確かめてから起動時刻を記録する。以後の同一性照合はこの記録だけを根拠にする。
if proc_info "$launcher_pid" && [ "$REPLY_PPID" = "$$" ]; then launcher_start="$REPLY_START"; fi
in_launch=0
[ -z "$pending_rc" ] || finish "$pending_rc"
[ -n "$launcher_start" ] || fail "could not record the launcher start time (the launcher exited immediately or /proc is unreadable)"

deadline_wait() { # <説明> : 条件関数 "$@" が真になるまで --timeout まで待つ（期限は単調時計）
  local what="$1" end
  shift
  up_cs
  end=$((REPLY_CS + timeout_s * 100))
  while ! "$@"; do
    launcher_ok || fail "launcher exited while waiting for $what"
    up_cs
    [ "$REPLY_CS" -lt "$end" ] || fail "timed out waiting for $what"
    snapshot_throttled
    nap "$poll_s"
  done
}

# shellcheck disable=SC2329 # deadline_wait へ関数名で渡す
ready_seen() { grep -qx 'READY' "$workdir/out.log" 2>/dev/null; }
running_seen() { read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ]; }

deadline_wait "READY" ready_seen
deadline_wait "the container to be running in state.json" running_seen

vals=()
for ((n = 1; n <= total; n++)); do
  if ! running_seen; then fail "state.json is not in the running state before trial $n"; fi
  old_pid="$ST_PID"
  old_count="$ST_COUNT"
  launcher_ok || fail "launcher exited before trial $n"
  # kill の条件: state.json の pid が launcher の子孫であること（帰属の証明）と、送信直前の同一性再照合。
  # 子孫と確認できない pid にはシグナルを送らず失敗にする（偽造・無関係・契約違反）。後始末で残存を判定する。
  if ! is_descendant "$old_pid"; then
    note_suspect "$old_pid"
    fail "pid in state.json is not a descendant of the launcher; refusing to send a signal"
  fi
  start1="$REPLY_START"
  track_pid "$old_pid" "$start1"
  up_cs; up0="$REPLY_CS"
  end_cs=$((up0 + timeout_s * 100))
  # 計測開始時刻は同一性の再照合（sig_same_proc 内）の前に取る。再照合の所要時間は observed に含まれるが
  # （上側推定のまま）、照合と kill(2) の間に時刻取得を挟まない。
  now_us; t0="$REPLY_US"
  sig_rc=0
  sig_same_proc KILL "$old_pid" "$start1" || sig_rc=$?
  case "$sig_rc" in
    0) ;;
    1) fail "container process changed or exited before the signal in trial $n; no signal was sent" ;;
    *) fail "could not signal the container process in trial $n" ;;
  esac
  t1=""
  while :; do
    if read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ] && [ "$ST_PID" != "$old_pid" ]; then
      now_us; t1="$REPLY_US"
      [ "$ST_COUNT" -eq $((old_count + 1)) ] || fail "restartCount jumped from $old_count to $ST_COUNT in trial $n"
      break
    fi
    launcher_ok || fail "launcher exited before the restart was observed in trial $n"
    up_cs
    [ "$REPLY_CS" -lt "$end_cs" ] || fail "restart was not observed within ${timeout_s}s in trial $n"
    nap "$poll_s"
  done
  up_cs; up1="$REPLY_CS"
  d_wall=$((t1 - t0))
  d_up=$(((up1 - up0) * 10000))
  diff=$((d_wall - d_up))
  [ "${diff#-}" -le 50000 ] || fail "clock changed during trial $n (wall and monotonic clocks disagree)"
  new_pid="$ST_PID"
  # 観測時: 新 pid が生存し launcher の子孫であること（SUP-3。state.json だけ残って新プロセスが既に終了した試行は採用しない）。
  # 計測区間（t1）の外で行うのでレイテンシには含まれない。起動時刻を控えて確定時に再照合する。
  if ! { alive "$new_pid" && is_descendant "$new_pid"; }; then
    note_suspect "$new_pid"
    fail "new container process is not alive as a launcher descendant at observation in trial $n"
  fi
  new_start="$REPLY_START"
  track_pid "$new_pid" "$new_start"
  validate_state_strict "$new_pid" "$((old_count + 1))" || fail "state.json failed strict validation in trial $n"
  # 確定時: 同じ新 pid・起動時刻のプロセスがまだ生存していること。
  same_proc "$new_pid" "$new_start" || fail "new container process exited before the trial $n result was confirmed"
  [ "$n" -le "$warmup" ] || vals+=("$d_wall")
  # 計測区間の外で launcher の子孫を記録する（launcher が後で異常終了しても回収対象に残る）。
  snapshot_descendants || true
  nap "$settle_s"
done

# --- 副系列は launcher 停止後（do_cleanup 内の collect_reported）に集計する。ここで停止・回収を先に行う ---
collect_log=1
if ! do_cleanup; then
  err "cleanup-failed" "processes may remain after the run; inspect and kill them manually"
  finish 4
fi
[ "$reported_err" -eq 0 ] || fail "launcher reported a failed restart"
[ "${#vals[@]}" -eq "$trials" ] || fail "collected ${#vals[@]} samples, want $trials"

# 集計（jq）。中央値は偶数個で中央 2 値の平均、p95 は昇順の ceil(n*95/100)-1 番目。単位は ms（小数 3 桁）。
# shellcheck disable=SC2016 # jq のフィルタ（$s・$n は jq の変数。シェル展開させない）
stats_filter='
  def r3: (. * 1000 | round) / 1000;
  def stats: sort as $s | ($s | length) as $n
    | { samples: $n,
        median: ((if ($n % 2) == 1 then $s[($n - 1) / 2] else ($s[$n / 2 - 1] + $s[$n / 2]) / 2 end) / 1000 | r3),
        p95: ($s[((($n * 95) / 100) | ceil) - 1] / 1000 | r3),
        min: ($s[0] / 1000 | r3), max: ($s[$n - 1] / 1000 | r3),
        mean: (($s | add) / $n / 1000 | r3),
        values: ($s | map(. / 1000 | r3)) };
'
observed_json="$(printf '%s\n' "${vals[@]}" | jq -s "$stats_filter stats")"
if [ "$reported" = "null" ]; then
  reported_json="null"
else
  reported_json="$(printf '%s\n' "$reported" | jq -s "$stats_filter stats")"
fi

result="$(jq -n \
  --arg label "$label" --arg policy "$policy" \
  --argjson trials "$trials" --argjson warmup "$warmup" \
  --argjson observed "$observed_json" --argjson reported "$reported_json" '
  { schema: "fandhe-container.restart-latency/v1", behavior: "SUP-3", task: "TASK-160", unit: "ms",
    label: $label, trials: $trials, warmup: $warmup, policy: $policy, backoff_ms: 0,
    observed: $observed, supervisor_reported: $reported,
    method: {
      observed: "SIGKILL to the container process until state.json shows running, a new pid and restartCount+1; includes the pre-signal identity check, signal delivery, exit detection and the polling granularity of this script (upper bound)",
      supervisor_reported: "elapsed_us of the supervisor.monitor restart log line (exit detected until the new Running state is recorded); null when the launcher log does not provide trials+warmup ok lines",
      poc17_difference: "PoC-17 measured the next start time minus the previous end time recorded by a self-exiting workload, which is a different interval; do not compare the numbers directly",
      percentile: "nearest-rank ceil(n*95/100)-1 on sorted samples; median averages the two middle values for an even count" } }')"

# 後始末は上で完了済み（残存があれば 4 で結果を出さない）。結果を公開する。
if [ -n "$output" ]; then
  out_tmp="$(mktemp "${output}.XXXXXX")"
  printf '%s\n' "$result" >"$out_tmp"
  if ! ln -T -- "$out_tmp" "$output" 2>/dev/null; then
    err "invalid-argument" "output path already exists or cannot be created"
    finish 2
  fi
  rm -f -- "$out_tmp"
  out_tmp=""
else
  printf '%s\n' "$result"
fi
finish 0
