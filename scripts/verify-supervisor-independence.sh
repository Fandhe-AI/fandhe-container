#!/usr/bin/env bash
# 監視プロセス独立性の実証スクリプト（TASK-162・SUP-5。実証は #499・TASK-162.h1 で人間が実機実行する）。
#
# 役割: N 個の監視プロセス（launcher。コンテナ 1 つにつき 1 つ）を同時に起動し、そのうち指定した 1 個
# だけを SIGKILL して、次を機械照合する。実行・判定は人間担当で、本スクリプトは準備物（REPAIR-3: 実装済みを
# 装わない。製品バイナリ〔TASK-79 の CLI・本番 launcher〕は未提供のため、CI で動かすのはスタブ launcher の
# 自己テスト scripts/verify-supervisor-independence-selftest.sh のみ）。
#   (a) 対象の監視プロセスが実際に消滅している（消えていなければ検証不成立。自明な合格を防ぐ）
#   (b) 残り N-1 個の監視プロセスが、記録した起動時刻のまま生存している（SUP-5 の「継続」）
#   (c) 残り N-1 個のコンテナ側プロセス（launcher の子孫）が、記録した pid・起動時刻・親 pid のまま生存
#       している（監視継続・巻き添えなし）
#   (d) 対象のコンテナ側プロセスが、記録した pid・起動時刻のまま生存している（孤児化しても稼働継続。
#       「同名のプロセスが居る」ではなく同一プロセスの照合）。再親化後の親 pid は参考値として出力する
# 「監視継続」は既定では (b)+(c) の生存照合で定義する。残り N-1 個のコンテナを kill して再起動を確認する
# PoC-17 相当の往復は --check-restart（opt-in・既定 off）で、SUP-3（restart ポリシー）の実装が前提のため
# 現行 supervisor では成立しない（SUP-3 実装後に有効）。
# 孤児コンテナの re-adopt・終了ポリシーは SUP-8・TASK-165 の課題で本スクリプトの範囲外。
#
# 呼び出し元: Makefile の `supervisor-independence`（操作者が明示実行。make ci には含めない）。
# 本スクリプトは sudo を呼ばない（権限が要る場合は操作者が権限付きシェルから実行する）。
#
# launcher 契約（scripts/bench/concurrent_50_memory.sh の own モードと同一。TASK-79 の CLI 提供後に起動行だけ
# 合わせる暫定契約）:
#   <launcher> run --id <id> --bundle <bundle> を本スクリプトの直接の子として起動する（配列で直接 exec。
#   eval・sh -c を使わない）。launcher はコンテナ 1 つを監視してフォアグラウンドに留まり、起動完了時に標準出力へ
#   `READY` だけの行を出す。環境変数 FANDHE_BENCH_OWNER に実行ごとの乱数トークンを渡し、後始末で
#   /proc/*/environ のトークン一致により孤児化した子孫も回収する。環境変数を継承しないコンテナ側プロセスは、
#   起動時に記録した pid・起動時刻の同一性でも追跡して回収する（回収できなければ終了コード 4）。
#   停止は SIGTERM、期限超過で SIGKILL。
#   launcher の標準出力・標準エラーは一時ファイルへ記録する（READY の確認用。実行後に削除する）。
#
# 使い方:
#   verify-supervisor-independence.sh --launcher <絶対パス> --bundle <dir>
#       [--count N（既定 50。2〜200）] [--target-index K（既定 N/2 の切り上げ。1〜N）]
#       [--min-procs N（各 launcher の木の最小プロセス数。既定 2〜64）] [--settle SECS（既定 2）]
#       [--timeout SECS（各待機の上限。既定 30）] [--id-prefix STR（既定 fc-sup-indep）]
#       [--check-restart] [--output FILE（新規ファイルのみ）] [--help]
#
# 出力: JSON（標準出力。--output 指定時はそのファイル）。launcher・bundle のパス、cmdline、環境変数は出さない。
# 終了コード: 0 = 全判定成立 / 1 = 判定不成立・起動数不足・期限切れ（起動数不足では結果を公開しない）/
#   2 = 引数・入力・出力先エラー / 3 = 前提欠如（非 Linux 等。0 で合格に見せない）/
#   4 = 後始末失敗（残存プロセス、または子孫を追跡しきれず回収を確認できない場合。最優先。結果ファイルは後始末の完了後に公開するため、4 のときは作られない）/ 129・130・143 = HUP・INT・TERM による中断（後始末の完了後）。
# 1 は機械照合できる事実の報告で、SUP-5 の合否判定・レポート化は #499（人間）が行う。
# 既知の制約: 起動時刻の照合でも列挙から送信までの極めて短い pid 再利用の窓は理論上残る。コンテナ側プロセスは
# 一過性の子を含めて「記録時点で存在した全プロセス」を対象にするため、一過性の子を持つ実装では不一致になり得る
# （その場合は不一致の内訳を #499 で確認する）。後始末の最中に届く INT・TERM・HUP は無視して回収を完遂する。
# 環境変数を継承せず、かつ記録後に新規 fork された子孫は、回収・残存検出のどちらも保証できない。そのため
# 起動直後から 0.1〜0.5 秒間隔で子孫を記録し続け、子孫を 1 つも観測できないまま消滅した launcher・走査上限
# （512 件）に達した木は追跡不能として終了コード 4 にする（回収成功とは判定しない）。
set -euo pipefail

readonly num_re='^(0|[1-9][0-9]{0,8})$'
readonly id_re='^[A-Za-z0-9_-]{1,32}$'

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
count=50
target_index=""
min_procs=2
settle=2
timeout_s=30
id_prefix="fc-sup-indep"
check_restart=0
output=""

need_val() { [ "$1" -ge 2 ] || { err "invalid-argument" "$2 requires a value"; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --launcher) need_val $# "$1"; launcher="$2"; shift 2 ;;
    --bundle) need_val $# "$1"; bundle="$2"; shift 2 ;;
    --count) need_val $# "$1"; count="$2"; shift 2 ;;
    --target-index) need_val $# "$1"; target_index="$2"; shift 2 ;;
    --min-procs) need_val $# "$1"; min_procs="$2"; shift 2 ;;
    --settle) need_val $# "$1"; settle="$2"; shift 2 ;;
    --timeout) need_val $# "$1"; timeout_s="$2"; shift 2 ;;
    --id-prefix) need_val $# "$1"; id_prefix="$2"; shift 2 ;;
    --check-restart) check_restart=1; shift ;;
    --output) need_val $# "$1"; output="$2"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) err "invalid-argument" "unknown option"; exit 2 ;;
  esac
done

check_range() { # <名前> <値> <最小> <最大>
  [[ "$2" =~ $num_re ]] || { err "invalid-argument" "$1 must be a non-negative integer"; exit 2; }
  { [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; } || { err "invalid-argument" "$1 must be from $3 to $4"; exit 2; }
}

[ -n "$launcher" ] || { err "invalid-argument" "--launcher is required"; exit 2; }
[ -n "$bundle" ] || { err "invalid-argument" "--bundle is required"; exit 2; }
check_range "--count" "$count" 2 200
[ -n "$target_index" ] || target_index=$(((count + 1) / 2))
check_range "--target-index" "$target_index" 1 "$count"
check_range "--min-procs" "$min_procs" 2 64
check_range "--settle" "$settle" 0 600
check_range "--timeout" "$timeout_s" 1 600
[[ "$id_prefix" =~ $id_re ]] || { err "invalid-argument" "--id-prefix must match [A-Za-z0-9_-]{1,32}"; exit 2; }
case "$launcher" in /*) ;; *) err "invalid-argument" "--launcher must be an absolute path"; exit 2 ;; esac
case "$launcher$bundle" in *$'\n'*) err "invalid-argument" "paths must not contain newlines"; exit 2 ;; esac
[ -d "$bundle" ] || { err "invalid-argument" "--bundle is not a directory"; exit 2; }

# 祖先を含むディレクトリが、他のユーザーに中のエントリを差し替えられないこと（concurrent_50_memory.sh の
# dir_is_safe と同じ規則）。実行ユーザーか root の所有で、group / other の書き込み権がないか sticky ビット付き。
dir_is_safe() {
  local d="$1" uid
  uid="$(id -u)"
  [ -n "$(find -P "$d" -maxdepth 0 -type d \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) ! -perm -1000 -print 2>/dev/null)" ]
}

# 物理パスと論理パスが一致する（symlink を含まない）ディレクトリで、/ までの全祖先が dir_is_safe であること。
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

# root 実行時に launcher を他ユーザーが差し替えられないこと: 非 symlink の通常ファイルで、実行可能、
# 所有者が実行ユーザーか root、group / other 書き込み不可、祖先ディレクトリも上記規則を満たす。
if ! command -v find >/dev/null 2>&1 || ! command -v id >/dev/null 2>&1 || ! command -v dirname >/dev/null 2>&1; then
  err "unsupported-os" "find, id and dirname are required"
  exit 3
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
  output_dir="$(cd -- "$output_dir" && pwd -P)"
  case "$output_dir" in
    /) output="/${output##*/}" ;;
    *) output="${output_dir}/${output##*/}" ;;
  esac
fi

# --- 前提確認（欠如は 3。0 を返して合格に見せない） ---
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then err "unsupported-os" "bash 5 or later is required"; exit 3; fi
if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then err "unsupported-os" "only Linux is supported"; exit 3; fi
for req in mktemp ln grep sleep kill uname date od head tr; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
[ -r /proc/self/stat ] || { err "unsupported-os" "/proc is required"; exit 3; }

# --- 状態 ---
pids=()
pstart=()
DESC=()
logdir=""
owner_tok=""
out_tmp=""
final_rc=0
spawned=0
declare -A SP SS SZ CH TRK SEEN
untracked=0
TREE_TRUNC=0
publish_pending=0
out_buf=""

# 実行ごとの乱数トークン（孤児化した子孫の所有証明用）。
owner_tok="$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
[[ "$owner_tok" =~ ^[0-9a-f]{32}$ ]] || { err "unsupported-os" "cannot generate an owner token"; exit 3; }

# pid の起動時刻（/proc/<pid>/stat の 22 番目。pid 再利用の判別用）を ST へ入れる。読めなければ 1。
read_starttime() {
  local s rest f
  ST=""
  { IFS= read -r s <"/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  [ -n "${f[19]:-}" ] || return 1
  ST="${f[19]}"
}

# pid が「記録した起動時刻のまま生存している同一プロセス」か。消滅・ゾンビ・起動時刻の不一致は 1。
# 第 3 引数（親 pid）を渡すと親の一致も要求する。
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
# すべてここかトークン照合（owned_kill）を通す。comm 名一致（pgrep・pkill）での送信はしない。
sig_same_proc() { # <シグナル名> <pid> <起動時刻> [<親 pid>]
  same_proc_alive "$2" "$3" "${4:-}" || return 0
  kill "-$1" "$2" 2>/dev/null || true
}

# pid の実行ファイル名（/proc/<pid>/comm。空白は _ に置換）を COMM へ入れる。読めなければ空。
read_comm() {
  COMM=""
  { IFS= read -r COMM <"/proc/$1/comm"; } 2>/dev/null || COMM=""
  COMM="${COMM// /_}"
}

# pid の識別シグネチャ（comm と完全な cmdline〔先頭 4096 バイト。NUL は \001、改行は \002 に置換〕）を SIG へ入れる。
# 再起動の照合で「kill した子と同じコマンド」であることを確認するために使う（comm だけでは同名の補助プロセスと
# 区別できない）。cmdline が読めない・空のときは SIG を空にする（照合不能として再起動を認定しない）。値は出力しない。
read_sig() {
  local cl
  SIG=""
  read_comm "$1"
  cl="$(head -c 4096 "/proc/$1/cmdline" 2>/dev/null | tr '\000\n' '\001\002' || true)"
  [ -n "$cl" ] && [ -n "$COMM" ] || return 0
  SIG="${COMM}|${cl}"
}

# 全プロセスの状態・親・起動時刻・子の一覧を 1 回の走査で SZ・SP・SS・CH へ入れる（同じ時点の値で判定する）。
scan() {
  local d p s rest f
  SP=() SS=() SZ=() CH=()
  for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    { IFS= read -r s <"$d/stat"; } 2>/dev/null || continue
    rest="${s##*) }"
    read -ra f <<<"$rest"
    [ -n "${f[19]:-}" ] || continue
    SZ[$p]="${f[0]}"
    SP[$p]="${f[1]}"
    SS[$p]="${f[19]}"
    CH[${f[1]}]+="$p "
  done
}

# scan の結果を使い、pid の子孫（根を除く）を "pid:起動時刻:親pid" の空白区切りで TREE へ入れる。
# 走査は 512 件で打ち切る。打ち切り時に未走査の子孫が残る場合は TREE_TRUNC=1 にする（呼び出し側は
# 判定不成立・追跡不能として扱う。上限超過の子孫を黙って無視して pass にしない）。
tree_of() { # <root pid>
  local queue=("$1") next p c n=0
  TREE=""
  TREE_TRUNC=0
  while [ "${#queue[@]}" -gt 0 ] && [ "$n" -lt 512 ]; do
    next=()
    for p in "${queue[@]}"; do
      for c in ${CH[$p]:-}; do
        case "${SZ[$c]:-}" in Z | X | x | '') continue ;; esac
        # 追加前に上限を確認する。1 つの親に多数の子がいても上限を超えて追加しない。
        if [ "$n" -ge 512 ]; then
          TREE_TRUNC=1
          break 2
        fi
        TREE+="${c}:${SS[$c]}:${p} "
        next+=("$c")
        n=$((n + 1))
      done
    done
    queue=("${next[@]}")
  done
  for p in "${queue[@]}"; do
    [ -z "${CH[$p]:-}" ] || { TREE_TRUNC=1; break; }
  done
}

# scan の結果で、記録した pid・起動時刻のプロセスが生存（ゾンビでない）しているか。
snap_alive() { # <pid> <起動時刻>
  case "${SZ[$1]:-}" in Z | X | x | '') return 1 ;; esac
  [ "${SS[$1]:-}" = "$2" ]
}

# 環境変数トークンが一致する生存プロセス（launcher の孤児化した子孫を含む）を "pid:起動時刻" で OWNED へ入れる。
owned_scan() {
  local f p
  OWNED=()
  while IFS= read -r f; do
    p="${f#/proc/}"
    p="${p%%/*}"
    [[ "$p" =~ $num_re ]] || continue
    if read_starttime "$p" && same_proc_alive "$p" "$ST"; then OWNED+=("${p}:${ST}"); fi
  done < <(grep -lzxF -- "FANDHE_BENCH_OWNER=${owner_tok}" /proc/[0-9]*/environ 2>/dev/null || true)
}

# OWNED の各プロセスへ、トークンと起動時刻を再照合してから SIGKILL を送る。
owned_kill() {
  local desc pid
  for desc in ${OWNED[@]+"${OWNED[@]}"}; do
    pid="${desc%%:*}"
    if grep -qzxF -- "FANDHE_BENCH_OWNER=${owner_tok}" "/proc/$pid/environ" 2>/dev/null; then
      sig_same_proc KILL "$pid" "${desc#*:}"
    fi
  done
}

# 期限付きの待機。<秒> <コマンド...> が成功するまで 0.1 秒間隔で再試行し、期限切れなら 1（REPAIR-5）。
# 期限は反復回数でなく bash の $SECONDS（実経過秒）で判定する。各試行の実行時間も期限に算入される。
wait_until() {
  local deadline=$((SECONDS + $1))
  shift
  while ! "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.1
  done
}

# 起動した launcher がまだ 1 つでも生存しているか。
any_launcher_alive() {
  local i
  for i in "${!pids[@]}"; do
    if same_proc_alive "${pids[$i]}" "${pstart[$i]:-}" "$$"; then return 0; fi
  done
  return 1
}

# 起動した launcher の現在の子孫（コンテナ側プロセス）と kill 前スナップショット DESC の子孫を、記録した
# pid・起動時刻の組として TRK へ追加する。環境変数を継承しないコンテナ側プロセス（実機の実装）は
# FANDHE_BENCH_OWNER のトークンでは見つからないため、起動時に記録した同一性で追跡する（SIGKILL 後の孤児を含む）。
# 起動直後から定期的に呼ぶ（待機ループ・settle 中）ことで、launcher が途中で終了しても、それまでに見えた子孫は
# 記録済みになる。子孫を 1 つも記録できないまま消滅した launcher（SEEN 未設定）と、走査上限（512 件）に達した
# 木は追跡不能（untracked=1）として記録し、後始末の成功とは判定しない（cleanup_procs が失敗を返す）。
track_descendants() {
  local i d c rest
  scan
  for i in "${!pids[@]}"; do
    if snap_alive "${pids[$i]}" "${pstart[$i]:-}"; then
      tree_of "${pids[$i]}"
      [ "$TREE_TRUNC" -eq 0 ] || untracked=1
      for d in $TREE; do
        c="${d%%:*}"
        rest="${d#*:}"
        TRK[$c]="${rest%%:*}"
        SEEN[$i]=1
      done
    elif [ -z "${SEEN[$i]:-}" ] && [ -z "${DESC[$i]:-}" ]; then
      # 既に消滅した launcher で、子孫を 1 つも観測できていない。
      untracked=1
    fi
    for d in ${DESC[$i]:-}; do
      c="${d%%:*}"
      rest="${d#*:}"
      TRK[$c]="${rest%%:*}"
    done
  done
}

# 待機中の定期追跡つき。<秒> <コマンド...> を wait_until と同じ規則で待ち、各試行の前に子孫を記録する。
wait_tracked() {
  local deadline=$((SECONDS + $1))
  shift
  while :; do
    track_descendants
    "$@" && return 0
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.1
  done
}

# settle 秒の待機。0.5 秒ごとに子孫を記録する。
settle_tracked() {
  local k=$((settle * 2))
  while [ "$k" -gt 0 ]; do
    track_descendants
    sleep 0.5
    k=$((k - 1))
  done
}

# TRK に記録した同一プロセス（pid・起動時刻の一致）のうち生存しているものへ SIGKILL を送る。
tracked_kill() {
  local c
  for c in "${!TRK[@]}"; do sig_same_proc KILL "$c" "${TRK[$c]}"; done
}

# TRK に記録した同一プロセスがまだ生存していれば 0。
tracked_alive() {
  local c
  for c in "${!TRK[@]}"; do
    if same_proc_alive "$c" "${TRK[$c]}"; then return 0; fi
  done
  return 1
}

# 後始末。子孫を記録 → launcher へ SIGTERM → 期限超過で SIGKILL → トークン一致の所有プロセスと記録済みの
# コンテナ側プロセス（孤児を含む）を回収し、残存があるか追跡不能（untracked）なら 1 を返す。EXIT trap から必ず呼ぶ。
cleanup_procs() {
  local i round
  track_descendants
  for i in "${!pids[@]}"; do sig_same_proc TERM "${pids[$i]}" "${pstart[$i]:-}" "$$"; done
  wait_until 10 _none_alive || true
  for i in "${!pids[@]}"; do sig_same_proc KILL "${pids[$i]}" "${pstart[$i]:-}" "$$"; done
  for round in 1 2 3 4 5; do
    owned_scan
    if [ "${#OWNED[@]}" -eq 0 ] && ! tracked_alive; then break; fi
    owned_kill
    tracked_kill
    sleep 0.3
  done
  owned_scan
  [ "${#OWNED[@]}" -eq 0 ] && ! tracked_alive && [ "$untracked" -eq 0 ]
}
_none_alive() { ! any_launcher_alive; }

# 結果の公開。後始末の成功を確認した後にだけ呼ぶ（後始末失敗時に pass の結果が残らないようにする）。
publish_result() {
  if [ -n "$output" ]; then
    if ! out_tmp="$(mktemp "${output}.XXXXXX" 2>/dev/null)"; then err "output-failed" "cannot create temporary file next to the output"; return 2; fi
    printf '%s\n' "$out_buf" >"$out_tmp" 2>/dev/null || { err "output-failed" "cannot write temporary file"; return 2; }
    # ln -T（link(2)）で公開する。出力先が既に存在すれば失敗し、symlink を辿らない。
    if ! ln -T -- "$out_tmp" "$output" 2>/dev/null; then
      err "output-failed" "cannot publish output (it may already exist, or hard links are unsupported)"
      return 2
    fi
  else
    printf '%s\n' "$out_buf"
  fi
}

on_exit() {
  local rc=$?
  # 後始末の最中に届く INT・TERM・HUP は無視する（2 回目のシグナルで後始末が中断され、launcher・コンテナが
  # 残るのを防ぐ）。EXIT trap だけ先に外す。
  trap - EXIT
  trap '' INT TERM HUP
  [ "$final_rc" -eq 0 ] || rc="$final_rc"
  if [ "$spawned" -eq 1 ]; then
    if ! cleanup_procs; then
      err "cleanup-failed" "owned processes remain or could not be tracked after cleanup"
      rc=4
    fi
  fi
  if [ "$rc" -eq 0 ] && [ "$publish_pending" -eq 1 ]; then
    publish_result || rc=$?
  fi
  [ -z "$out_tmp" ] || rm -f -- "$out_tmp" || true
  [ -z "$logdir" ] || rm -rf -- "$logdir" || true
  exit "$rc"
}
on_signal() { final_rc="$1"; exit "$1"; }
trap on_exit EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

logdir="$(mktemp -d)" || { err "unsupported-os" "cannot create a temporary directory"; exit 3; }

# 引数は配列で直接 exec する（eval・sh -c を使わない）。ulimit 等の制限は掛けない（コンテナ内の挙動が変わるため）。
spawn_one() { # <i>
  local i="$1" log="${logdir}/l${1}.log"
  : >"$log"
  (
    FANDHE_BENCH_OWNER="$owner_tok" exec "$launcher" run --id "${id_prefix}-${i}" --bundle "$bundle" </dev/null >"$log" 2>&1
  ) &
  pids[i]=$!
  pstart[i]=""
  if read_starttime "${pids[$i]}"; then pstart[i]="$ST"; fi
}

all_ready() {
  local i
  for i in $(seq 1 "$count"); do
    same_proc_alive "${pids[$i]}" "${pstart[$i]:-}" "$$" || return 1
    grep -qxF -- "READY" "${logdir}/l${i}.log" 2>/dev/null || return 1
  done
}

timed_out() { err "timeout" "$1"; final_rc=1; exit 1; }

spawned=1
for i in $(seq 1 "$count"); do spawn_one "$i"; done
for i in $(seq 1 "$count"); do
  [ -n "${pstart[$i]:-}" ] || { err "launch-failed" "cannot record the start time of a launcher"; final_rc=1; exit 1; }
done
wait_tracked "$timeout_s" all_ready || timed_out "not all ${count} launchers became ready within ${timeout_s}s"

# --- kill 前スナップショット: 全 launcher の生存・木の大きさ・子孫（コンテナ側プロセス）を記録 ---
settle_tracked
scan
for i in $(seq 1 "$count"); do
  if [ "${SS[${pids[$i]}]:-}" != "${pstart[$i]}" ] || [ "${SP[${pids[$i]}]:-}" != "$$" ]; then
    err "launch-failed" "a launcher exited before the kill (started ${count} but fewer remain)"
    final_rc=1
    exit 1
  fi
  tree_of "${pids[$i]}"
  if [ "$TREE_TRUNC" -eq 1 ]; then
    err "launch-failed" "a launcher tree exceeds the 512-process scan limit (cannot verify every container-side process)"
    untracked=1
    final_rc=1
    exit 1
  fi
  DESC[i]="$TREE"
  # shellcheck disable=SC2086
  set -- $TREE
  if [ $(($# + 1)) -lt "$min_procs" ]; then
    err "launch-failed" "a launcher tree has fewer than ${min_procs} processes (no container-side process to observe)"
    final_rc=1
    exit 1
  fi
done

# --- 対象の監視プロセスだけへ SIGKILL（SIGTERM は使わない: 穏当停止ではコンテナも止まり孤児化の検証にならない） ---
tpid="${pids[$target_index]}"
tstart="${pstart[$target_index]}"
sig_same_proc KILL "$tpid" "$tstart" "$$"
_target_gone() { ! same_proc_alive "$tpid" "$tstart"; }
target_dead=false
if wait_tracked "$timeout_s" _target_gone; then target_dead=true; fi
settle_tracked

# --- 判定 ---
scan
alive_supers=0
ok_containers=0
bad_detail=""
for i in $(seq 1 "$count"); do
  [ "$i" -ne "$target_index" ] || continue
  if snap_alive "${pids[$i]}" "${pstart[$i]}" && [ "${SP[${pids[$i]}]:-}" = "$$" ]; then
    alive_supers=$((alive_supers + 1))
  else
    bad_detail+="supervisor-${i} "
  fi
  all_ok=1
  for desc in ${DESC[$i]}; do
    cpid="${desc%%:*}"
    rest="${desc#*:}"
    cstart="${rest%%:*}"
    cppid="${rest#*:}"
    if ! { snap_alive "$cpid" "$cstart" && [ "${SP[$cpid]:-}" = "$cppid" ]; }; then all_ok=0; fi
  done
  if [ "$all_ok" -eq 1 ]; then ok_containers=$((ok_containers + 1)); else bad_detail+="container-${i} "; fi
done

target_container_alive=true
reparented_to=null
for desc in ${DESC[$target_index]}; do
  cpid="${desc%%:*}"
  rest="${desc#*:}"
  cstart="${rest%%:*}"
  cppid="${rest#*:}"
  if ! snap_alive "$cpid" "$cstart"; then target_container_alive=false; fi
  if [ "$cppid" = "$tpid" ] && [ "$reparented_to" = "null" ] && [ -n "${SP[$cpid]:-}" ]; then reparented_to="${SP[$cpid]}"; fi
done

# --- --check-restart（opt-in。SUP-3 の restart ポリシー実装が前提）: 残り N-1 個のコンテナ側プロセスを kill して再起動を確認 ---
# 再起動の成立条件: 各監視プロセスについて、kill 前に記録した子孫（pid・起動時刻）に含まれない「新しい」直接の子で、
# kill した子とシグネチャ（comm＋完全な cmdline）が一致するものが、シグネチャごとに kill した直接の子の数以上、生存していること。
# 同名・別コマンドの補助プロセスが増えただけでは成立しない。成立後に settle 秒待ち、
# N-1 個の監視プロセスと再起動したコンテナ側プロセスが同一のまま生存していること（稼働継続）も再照合する。
# 既知の制約: 現行の launcher 契約にはコンテナ ID・ランタイム状態を取得する手段がないため、対応関係はコマンド同一性
# （シグネチャ）と「直接の子」という位置で近似する。同一コマンドの補助プロセスは区別できず、再起動でコマンドラインが変わる
# 実装は不成立になる（安全側）。SUP-3 の実装後は、コンテナ ID・状態の取得手段で照合に置き換える（#499 で確認）。
restart_check="skipped"
restart_confirmed=null
if [ "$check_restart" -eq 1 ]; then
  declare -A OLDKIDS=() OLDSET=() OLDN=() NEWKIDS=() OLDSIGS=() OLDSIGN=()
  sig_unreadable=0
  for i in $(seq 1 "$count"); do
    for desc in ${DESC[$i]}; do
      rest="${desc#*:}"
      OLDSET["${desc%%:*}:${rest%%:*}"]=1
    done
  done
  for i in $(seq 1 "$count"); do
    [ "$i" -ne "$target_index" ] || continue
    OLDKIDS[$i]=""
    OLDN[$i]=0
    OLDSIGS[$i]=""
    for desc in ${DESC[$i]}; do
      cpid="${desc%%:*}"
      rest="${desc#*:}"
      cstart="${rest%%:*}"
      cppid="${rest#*:}"
      [ "$cppid" = "${pids[$i]}" ] || continue
      OLDKIDS[$i]+="${cpid} "
      OLDN[$i]=$((OLDN[$i] + 1))
      read_sig "$cpid"
      if [ -z "$SIG" ]; then
        sig_unreadable=1
      else
        if [ -z "${OLDSIGN["${i}|${SIG}"]:-}" ]; then
          OLDSIGN["${i}|${SIG}"]=0
          OLDSIGS[$i]+="${SIG}"$'\n'
        fi
        # 添字を算術式に渡さない（cmdline 由来の文字列を算術評価させない）。
        sigkey="${i}|${SIG}"
        sigv="${OLDSIGN["$sigkey"]}"
        OLDSIGN["$sigkey"]=$((sigv + 1))
      fi
      sig_same_proc KILL "$cpid" "$cstart" "$cppid"
    done
  done
  restarted_all() {
    local j c n=0 fresh sg sigv
    local -A freshn
    scan
    for j in $(seq 1 "$count"); do
      [ "$j" -ne "$target_index" ] || continue
      [ "${OLDN[$j]}" -ge 1 ] || return 1
      fresh=""
      freshn=()
      for c in ${CH[${pids[$j]}]:-}; do
        case "${SZ[$c]:-}" in Z | X | x | '') continue ;; esac
        [ -z "${OLDSET["${c}:${SS[$c]}"]:-}" ] || continue
        # 新しい子のうち、kill した子とシグネチャ（comm＋cmdline）が一致するものだけを再起動したコンテナ側プロセスとして数える。
        read_sig "$c"
        [ -n "$SIG" ] || continue
        [ -n "${OLDSIGN["${j}|${SIG}"]:-}" ] || continue
        sigv="${freshn["$SIG"]:-0}"
        freshn["$SIG"]=$((sigv + 1))
        fresh+="${c}:${SS[$c]} "
      done
      # シグネチャごとに、kill した数以上が再起動していること。
      while IFS= read -r sg; do
        [ -n "$sg" ] || continue
        [ "${freshn[$sg]:-0}" -ge "${OLDSIGN["${j}|${sg}"]}" ] || return 1
      done <<<"${OLDSIGS[$j]}"
      NEWKIDS[$j]="$fresh"
      n=$((n + 1))
    done
    RESTARTED="$n"
  }
  RESTARTED=0
  if [ "$sig_unreadable" -eq 1 ]; then
    # kill 前の子のコマンドを読めない場合は対応関係を照合できないため、再起動を認定しない。
    restart_check="fail"
    restart_confirmed=0
    bad_detail+="restart-unverifiable "
  elif wait_until "$timeout_s" restarted_all; then
    # 再起動後の稼働継続: settle 後に N-1 個の監視プロセスと新しいコンテナ側プロセスを同一性つきで再照合する。
    sleep "$settle"
    scan
    restart_sup_alive=0
    restart_ok=1
    for i in $(seq 1 "$count"); do
      [ "$i" -ne "$target_index" ] || continue
      if snap_alive "${pids[$i]}" "${pstart[$i]}" && [ "${SP[${pids[$i]}]:-}" = "$$" ]; then
        restart_sup_alive=$((restart_sup_alive + 1))
      else
        restart_ok=0
        bad_detail+="restart-supervisor-${i} "
      fi
      kids_alive=0
      for desc in ${NEWKIDS[$i]}; do
        if snap_alive "${desc%%:*}" "${desc#*:}" && [ "${SP[${desc%%:*}]:-}" = "${pids[$i]}" ]; then kids_alive=$((kids_alive + 1)); fi
      done
      if [ "$kids_alive" -lt "${OLDN[$i]}" ]; then
        restart_ok=0
        bad_detail+="restart-container-${i} "
      fi
    done
    if [ "$restart_ok" -eq 1 ] && [ "$restart_sup_alive" -eq $((count - 1)) ]; then
      restart_check="pass"
      restart_confirmed="$RESTARTED"
    else
      restart_check="fail"
      restart_confirmed=0
    fi
  else
    restart_check="fail"
    restart_confirmed=0
    bad_detail+="restart "
  fi
fi

expected=$((count - 1))
result="pass"
{ [ "$target_dead" = true ] && [ "$alive_supers" -eq "$expected" ] && [ "$ok_containers" -eq "$expected" ] && [ "$target_container_alive" = true ]; } || result="fail"
[ "$restart_check" != "fail" ] || result="fail"

kernel="$(uname -r 2>/dev/null | tr -cd '[:print:]')"
arch="$(uname -m 2>/dev/null | tr -cd '[:print:]')"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
out_buf="$(printf '{\n  "schema_version": 1,\n  "behavior": "SUP-5",\n  "task": "TASK-162",\n  "timestamp": "%s",\n  "kernel": "%s",\n  "arch": "%s",\n  "count": %s,\n  "target_index": %s,\n  "supervisors_expected_alive": %s,\n  "supervisors_alive_after_kill": %s,\n  "monitored_containers_alive": %s,\n  "target_supervisor_dead": %s,\n  "target_container_alive": %s,\n  "target_container_reparented_to": %s,\n  "restart_check": "%s",\n  "restart_confirmed": %s,\n  "result": "%s"\n}\n' \
  "$ts" "$kernel" "$arch" "$count" "$target_index" "$expected" "$alive_supers" "$ok_containers" "$target_dead" "$target_container_alive" "$reparented_to" "$restart_check" "$restart_confirmed" "$result")"

if [ "$result" != "pass" ]; then
  err "independence-check-failed" "mismatch: ${bad_detail}$([ "$target_dead" = true ] || printf 'target-not-dead ')$([ "$target_container_alive" = true ] || printf 'target-container-gone')"
  # 判定不成立は内訳を標準出力へ出す（結果ファイルは作らない）。
  printf '%s\n' "$out_buf"
  final_rc=1
  exit 1
fi

# 結果の公開は後始末の完了後（on_exit）に行う。後始末が失敗（終了コード 4）したときは pass の結果を残さない。
publish_pending=1
exit 0
