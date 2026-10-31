#!/usr/bin/env bash
# 監視プロセス独立性の実証スクリプト（TASK-162・SUP-5。実証は #499・TASK-162.h1 で人間が実機実行する）。
#
# 役割: N 個の監視プロセス（fandhe-container-supervisor。コンテナ 1 つにつき 1 つ）を同時に起動し、そのうち指定した 1 個
# だけを SIGKILL して、次を機械照合する。実行・判定は人間担当（#499）で、CI で動かすのはスタブの自己テスト
# scripts/verify-supervisor-independence-selftest.sh のみ。製品バイナリ（CLI・supervisor の bin）は提供済み
# （#1717・#1819。REPAIR-3: 実機での実証は未実施で、本スクリプトは準備物）。
#   (a) 対象の監視プロセスが実際に消滅している（消えていなければ検証不成立。自明な合格を防ぐ）
#   (b) 残り N-1 個の監視プロセスが、記録した起動時刻のまま生存している（SUP-5 の「継続」）
#   (c) 残り N-1 個のコンテナ側プロセス（launcher の子孫）が、記録した pid・起動時刻・親 pid のまま生存
#       している（監視継続・巻き添えなし）
#   (d) 対象のコンテナ側プロセスが、記録した pid・起動時刻のまま生存している（孤児化しても稼働継続。
#       「同名のプロセスが居る」ではなく同一プロセスの照合）。再親化後の親 pid は参考値として出力する
# 「監視継続」は既定では (b)+(c) の生存照合で定義する。残り N-1 個のコンテナを kill して再起動を確認する
# PoC-17 相当の往復は --check-restart（opt-in・既定 off）で、SUP-3（restart ポリシー）の実装が前提のため
# supervisor の再 launch は #2043 で本番 launcher でも成立する（実機での実証は #499）。
# 孤児コンテナの re-adopt・終了ポリシーは SUP-8・TASK-165 の課題で本スクリプトの範囲外。
#
# 呼び出し元: Makefile の `supervisor-independence`（操作者が明示実行。make ci には含めない）。
# 本スクリプトは sudo を呼ばない（権限が要る場合は操作者が権限付きシェルから実行する）。ただし supervisor は
# rootful 起動を拒否する（SEC-5）ため、非 root の利用者で実行する（root では起動前に終了コード 3）。
#
# 起動契約（crates/supervisor/src/start_contract.rs・start_entry.rs。差し替え点は sup_create / sup_spawn / sup_report）:
#   1. <bin-dir>/fandhe-container --root <状態ルート> create --bundle <bundle の複製> <id> を済ませる。
#   2. <systemd-run> --user --scope --quiet -p Delegate=yes -- <bin-dir>/fandhe-container-supervisor start --root <状態ルート> <id>
#      を本スクリプトの直接の子として起動する（配列で直接 exec。eval・sh -c を使わない。--scope は同じプロセスのまま
#      exec するので pid・親子関係は保たれる。supervisor は親 cgroup に自分だけがいることを要求するため、
#      supervisor ごとに新しいスコープへ入れる）。標準出力は名前付き FIFO にする（supervisor は FIFO 以外の標準出力を拒否する）。
#   3. 結果は標準出力の 1 行 `FCSUP1 OK <pid>`（pid はコンテナ側 init のホスト上の pid）か
#      `FCSUP1 ERR <CODE> <exit> <msg>`。supervisor はコンテナを監視してフォアグラウンドに留まる。
# CLI の start を経由しない理由: CLI の start は supervisor を別のプロセスグループ（process_group(0)）で起動し、
# 標準エラーを捨て、子として wait しない。直接起動すれば supervisor が本スクリプトの直接の子（親 pid の照合）になり、
# 「supervisor の子孫を数える」集計と後始末が成立する。
# bundle: --bundle は使い捨てのテンプレートとして扱う。supervisor は bundle へ flock を取るため、コンテナごとに
# 作業ディレクトリへ複製する（cp -a --reflink=auto。inode を共有しない複製にする。製品の rootfs 検査
# check_no_external_hardlinks は rootfs 外にもリンクを持つ inode を起動前に拒否するため、cp -al は使えない）。
# 複製の失敗時は 2。複製の前に config.json の root.path を検証し、絶対パス・bundle 外へ出る相対パス・外を指す symlink は
# 2 で拒否する（cp -a は root.path を書き換えず、全コンテナが元の同じ rootfs を共有してしまうため。書き換えはしない）。reflink 対応の FS では複製どうしがデータブロックを共有しうるが、page cache の共有条件は
# 実行ごとに異なりうる（メモリ比較の前提として記録する）。
# 後始末の第 1 段: 既定（--check-restart なし・restart ポリシー no）では、生存している監視プロセス（対象を除く）へ
# CLI の stop（制御チャネル経由。Linux で結線済み・#2059・#2142）を期限付きで送る。対象は SIGKILL 済みで制御チャネルの
# 相手がいないため stop を呼ばず、記録した pid での回収に任せる。--check-restart では stop の SIGTERM が restart の対象に
# なる。SUP-9 は #2162・#2440 で実装済みだが、stop 経由への切り替えは未実施のため呼ばない。stop は SIGTERM のみ（猶予後の SIGKILL は #1545 で未実装）で、init が SIGTERM を
# 捨てうるため、以降の同一性照合つき回収を fallback として必ず残す。stop の成否は後始末の成否に影響しない。
# 計測の起点（対象への SIGKILL）は変えない。CLI の delete は呼ばない（委譲スコープ外では cgroup 検出に失敗する・#2133）。
# 後始末: 環境変数 FANDHE_BENCH_OWNER に実行ごとの乱数トークンを渡し、/proc/*/environ のトークン一致で孤児化した
# 子孫も回収する。supervisor は dumpable=0 で environ を読めないため、記録した pid・起動時刻の同一性で追跡して回収する
# （回収できなければ終了コード 4）。停止は SIGTERM、期限超過で SIGKILL。状態ルート・bundle の複製・FIFO は
# 本スクリプトが mktemp で作った配下だけを削除する。
# supervisor の標準エラーは一時ファイルへ記録する（実行後に削除する）。
#
# 使い方:
#   verify-supervisor-independence.sh --bin-dir <絶対パス> --bundle <dir> [--systemd-run <絶対パス（既定 /usr/bin/systemd-run）>]
#       [--count N（既定 50。2〜200）] [--target-index K（既定 N/2 の切り上げ。1〜N）]
#       [--min-procs N（各 launcher の木の最小プロセス数。既定 2〜64）] [--settle SECS（既定 2）]
#       [--timeout SECS（各待機の上限。既定 30）] [--id-prefix STR（既定 fc-sup-indep）]
#       [--check-restart] [--output FILE（新規ファイルのみ）] [--help]
#
# 出力: JSON（標準出力。--output 指定時はそのファイル）。launcher・bundle のパス、cmdline、環境変数は出さない。
# 終了コード: 0 = 全判定成立 / 1 = 判定不成立・起動数不足・期限切れ（起動数不足では結果を公開しない）/
#   2 = 引数・入力・出力先エラー / 3 = 前提欠如（非 Linux 等。0 で合格に見せない）/
#   4 = 後始末失敗（残存プロセス、または報告された init を pid・起動時刻つきで記録できず、追跡しきれず回収を確認できない場合〔supervisor の生存・ERR・無報告・一時的な子孫の観測だけでも 4。SUP-5〕。最優先。結果ファイルは後始末の完了後に公開するため、4 のときは作られない）/ 129・130・143 = HUP・INT・TERM による中断（後始末の完了後）。
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

bin_dir=""
systemd_run="/usr/bin/systemd-run"
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
    --bin-dir) need_val $# "$1"; bin_dir="$2"; shift 2 ;;
    --systemd-run) need_val $# "$1"; systemd_run="$2"; shift 2 ;;
    --launcher) err "invalid-argument" "--launcher was replaced by --bin-dir"; exit 2 ;;
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

[ -n "$bin_dir" ] || { err "invalid-argument" "--bin-dir is required"; exit 2; }
[ -n "$bundle" ] || { err "invalid-argument" "--bundle is required"; exit 2; }
check_range "--count" "$count" 2 200
[ -n "$target_index" ] || target_index=$(((count + 1) / 2))
check_range "--target-index" "$target_index" 1 "$count"
check_range "--min-procs" "$min_procs" 2 64
check_range "--settle" "$settle" 0 600
check_range "--timeout" "$timeout_s" 1 600
[[ "$id_prefix" =~ $id_re ]] || { err "invalid-argument" "--id-prefix must match [A-Za-z0-9_-]{1,32}"; exit 2; }
case "$bin_dir" in /*) ;; *) err "invalid-argument" "--bin-dir must be an absolute path"; exit 2 ;; esac
case "$systemd_run" in /*) ;; *) err "invalid-argument" "--systemd-run must be an absolute path"; exit 2 ;; esac
case "$bin_dir$systemd_run$bundle" in *$'\n'*) err "invalid-argument" "paths must not contain newlines"; exit 2 ;; esac
[ -d "$bundle" ] || { err "invalid-argument" "--bundle is not a directory"; exit 2; }
bundle="$(cd -- "$bundle" 2>/dev/null && pwd -P)" || { err "invalid-argument" "--bundle cannot be resolved"; exit 2; }  # cp -a がリンクのまま複製して flock 競合するのを避ける

# bundle の config.json の root.path が、複製した bundle の中へ解決される相対パスであることを検証する（SEC・OCI の rootfs）。
# cp -a は config.json を書き換えないため、root.path が絶対パス（や bundle 外へ出る相対パス・外を指す symlink）だと、
# 複製した全コンテナが元の同じ rootfs を共有し、独立した複製という計測条件が崩れる（書き込みの相互干渉・page cache の共有）。
# 書き換えではなく拒否にする理由: 計測対象の設定を本スクリプトが改変しない／bundle 外の rootfs には書き換え先がなく、
# 全コンテナ分の rootfs の複製が別途要る。--bundle はテンプレートなので、複製の前に 1 度だけ検証する（複製は同一内容）。
# 違反は終了コード 2（create・起動の前）。jq・realpath が無ければ 3。
check_bundle_root_path() {
  local rp resolved
  command -v jq >/dev/null 2>&1 || { err "unsupported-os" "jq is required to validate the bundle config.json"; exit 3; }
  command -v realpath >/dev/null 2>&1 || { err "unsupported-os" "realpath is required to validate the bundle config.json"; exit 3; }
  # root.path が無ければ OCI の慣例どおり rootfs として扱う。読む量は 1 MiB に絞る（巨大ファイルを jq へ渡さない）。
  if ! rp="$(head -c 1048577 -- "$bundle/config.json" 2>/dev/null | jq -er '(.root // {}) | (.path // "rootfs") | select(type=="string")' 2>/dev/null)"; then
    err "invalid-argument" "the bundle config.json must be valid JSON with a string root.path (or none)"
    exit 2
  fi
  case "$rp" in
    '' | /* | *$'\n'*) err "invalid-argument" "the bundle root.path must be a relative path inside the bundle (an absolute path would share one rootfs across all copies)"; exit 2 ;;
  esac
  resolved="$(realpath -m -- "$bundle/$rp" 2>/dev/null)" || { err "invalid-argument" "the bundle root.path cannot be resolved"; exit 2; }
  case "$resolved" in
    "$bundle"/?*) ;;
    *) err "invalid-argument" "the bundle root.path must stay inside the bundle (no .. or symlink to the outside)"; exit 2 ;;
  esac
}

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

# 起動する 3 つの実行ファイル（CLI・supervisor の bin・systemd-run）を他ユーザーが差し替えられないこと:
# 非 symlink の通常ファイルで、実行可能、所有者が実行ユーザーか root、group / other 書き込み不可、
# 祖先ディレクトリも上記規則を満たす。bin-dir 内は固定名で解決し PATH 探索はしない。
if ! command -v find >/dev/null 2>&1 || ! command -v id >/dev/null 2>&1 || ! command -v dirname >/dev/null 2>&1; then
  err "unsupported-os" "find, id and dirname are required"
  exit 3
fi
uid_now="$(id -u)"
check_exe() { # <表示名> <パス>
  if [ -L "$2" ] || [ ! -f "$2" ] || [ ! -x "$2" ]; then
    err "invalid-argument" "$1 must be an executable regular file (not a symlink)"
    exit 2
  fi
  if [ -z "$(find -P "$2" -maxdepth 0 -type f \( -user "$uid_now" -o -user 0 \) ! -perm -0020 ! -perm -0002 -print 2>/dev/null)" ]; then
    err "invalid-argument" "$1 must be owned by you or root and not writable by group or others"
    exit 2
  fi
  if ! path_chain_is_safe "$(dirname -- "$2")"; then
    err "invalid-argument" "the directories above $1 must be symlink-free, owned by you or root, and not writable by others (unless sticky)"
    exit 2
  fi
}
cli_bin="${bin_dir}/fandhe-container"
sup_bin="${bin_dir}/fandhe-container-supervisor"
check_exe "fandhe-container in --bin-dir" "$cli_bin"
check_exe "fandhe-container-supervisor in --bin-dir" "$sup_bin"
check_exe "--systemd-run" "$systemd_run"

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
for req in mktemp mkfifo cp timeout ln grep sleep kill uname date od head tr; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
[ -r /proc/self/stat ] || { err "unsupported-os" "/proc is required"; exit 3; }
check_bundle_root_path
# supervisor は rootful 起動を拒否する（SEC-5）。0 を返して合格に見せないよう起動前に 3 で止める。
if [ "$uid_now" -eq 0 ]; then err "unsupported-os" "supervisor rejects rootful start (SEC-5); run as a non-root user"; exit 3; fi

# --- 状態 ---
pids=()
pstart=()
DESC=()
logdir=""
owner_tok=""
out_tmp=""
final_rc=0
spawned=0
declare -A SP SS SZ CH TRK BADREP
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
# 記録済みになる。コンテナの init を記録できないまま消滅した launcher と、走査上限（512 件）に達した
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
      done
    elif [ -z "${DESC[$i]:-}" ]; then
      # 既に消滅した supervisor。コンテナの init（supervisor が報告した pid）を pid・起動時刻つきで記録できていなければ、
      # 一時的な中間プロセスを観測していてもコンテナ全体を追跡できた証明にならない。ERR・書式不正の報告を受けていても、
      # 子プロセス不在の証明にならない（start_contract.rs は ERR 報告の後に terminate 等の後始末を行い、
      # start_entry.rs には未回収のハンドルを伴う失敗経路もある）ため、追跡不能（終了コード 4）にする。
      sup_report "$i" || true
      if [ -z "${REP_PID[$i]:-}" ] || [ -z "${TRK[${REP_PID[$i]}]:-}" ]; then untracked=1; fi
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

# CLI の stop を第 1 段にした後始末（CLI-1・SUP-5。#2163）。生存している監視プロセスのうち、対象（SIGKILL 済みで制御
# チャネルの相手がいない）以外へ `fandhe-container stop <id>` を送り、監視プロセスの終了を待つ。stop は SIGTERM を
# 渡すだけで猶予後の SIGKILL を持たず（#1545）、PID 1 の init が SIGTERM を捨てる場合もあるため、成否に関わらず
# 後続の同一性照合つき SIGTERM／SIGKILL を fallback として必ず残す（失敗は後始末の失敗にしない）。--check-restart
# （--restart always）では stop の SIGTERM が restart の対象になる。SUP-9 は #2162・#2440 で実装済みだが、stop 経由への切り替えは未実施のため呼ばない。
# 呼び出しごと・段全体に期限を付ける（REPAIR-5）。各 stop の上限・強制終了猶予・終了待機はすべて段全体 deadline の
# 残り時間で制限し、段全体（既定 30 秒）を超えない。引数は検証済みの id_prefix と連番から配列で組み、出力は捨てる。
cli_stop_survivors() {
  local i call_s stage_s deadline total=0 ok=0 sid rem lim
  local -a stopped=()
  [ "$check_restart" -eq 0 ] || return 0
  call_s=10
  [ "$timeout_s" -ge "$call_s" ] || call_s="$timeout_s"
  stage_s=30
  [ "$timeout_s" -ge "$stage_s" ] || stage_s="$timeout_s"
  deadline=$((SECONDS + stage_s))
  for i in "${!pids[@]}"; do
    [ "$i" != "$target_index" ] || continue
    same_proc_alive "${pids[$i]}" "${pstart[$i]:-}" "$$" || continue
    total=$((total + 1))
    # 残り時間から強制終了猶予（2 秒）と終了待機の最小枠（1 秒）を引いた分を超えない上限で送る。足りなければ送らない。
    rem=$((deadline - SECONDS - 3))
    [ "$rem" -ge 1 ] || continue
    lim="$call_s"
    [ "$rem" -ge "$lim" ] || lim="$rem"
    sid="${id_prefix}-${i}"
    if timeout --kill-after=2 "$lim" "$cli_bin" --root "$state_root" stop "$sid" </dev/null >/dev/null 2>&1; then
      stopped+=("$i")
    fi
  done
  if [ "${#stopped[@]}" -gt 0 ]; then
    rem=$((deadline - SECONDS))
    [ "$rem" -le 10 ] || rem=10
    [ "$rem" -ge 0 ] || rem=0
    wait_until "$rem" _stopped_gone "${stopped[@]}" || true
    for i in "${stopped[@]}"; do
      if ! same_proc_alive "${pids[$i]}" "${pstart[$i]:-}" "$$"; then ok=$((ok + 1)); fi
    done
  fi
  printf 'info: cli-stop: %d/%d supervisors exited after stop\n' "$ok" "$total" >&2 || true
}
# 引数に渡した index の監視プロセスがすべて消えていれば 0。
_stopped_gone() {
  local i
  for i in "$@"; do
    if same_proc_alive "${pids[$i]}" "${pstart[$i]:-}" "$$"; then return 1; fi
  done
  return 0
}

# 後始末。子孫を記録 → （CLI の stop）→ launcher へ SIGTERM → 期限超過で SIGKILL → トークン一致の所有プロセスと記録済みの
# コンテナ側プロセス（孤児を含む）を回収し、残存があるか追跡不能（untracked）なら 1 を返す。EXIT trap から必ず呼ぶ。
cleanup_procs() {
  local i round
  track_descendants
  # supervisor の生存・FCSUP1 ERR の報告・一時的な中間プロセスの観測は、init の追跡も未生成も証明しない（最後の
  # 記録の後に init が生まれ、その直後に supervisor を止める順序が成立する）。報告された init の pid を pid・
  # 起動時刻つきで記録できていなければ、追跡不能として終了コード 4・状態保持にする（SUP-5）。
  for i in "${!pids[@]}"; do
    sup_report "$i" || true
    if [ -z "${REP_PID[$i]:-}" ] || [ -z "${TRK[${REP_PID[$i]}]:-}" ]; then untracked=1; fi
  done
  cli_stop_survivors
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
  local keep_logdir=0
  if [ "$spawned" -eq 1 ]; then
    if ! cleanup_procs; then
      err "cleanup-failed" "owned processes remain or could not be tracked after cleanup"
      rc=4
      keep_logdir=1
    fi
  fi
  if [ "$rc" -eq 0 ] && [ "$publish_pending" -eq 1 ]; then
    publish_result || rc=$?
  fi
  [ -z "$out_tmp" ] || rm -f -- "$out_tmp" || true
  if [ "$keep_logdir" -eq 1 ] && [ -n "$logdir" ]; then
    # 回収失敗時は state.json・ログ・使用中の rootfs を残し、場所を通知する（SUP-5）。
    err "cleanup-failed" "kept the working directory for inspection: ${logdir}"
  elif [ -n "$logdir" ]; then
    rm -rf -- "$logdir" || true
  fi
  exit "$rc"
}
on_signal() { final_rc="$1"; exit "$1"; }
trap on_exit EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

logdir="$(mktemp -d)" || { err "unsupported-os" "cannot create a temporary directory"; exit 3; }

state_root="${logdir}/state"
work="${logdir}/work"
mkdir -m 0700 "$state_root" "$work" "${work}/bundles" "${work}/fifos" || { err "unsupported-os" "cannot create a work directory"; exit 3; }
declare -A REP_PID FDS REP_BUF

# --- 起動契約の差し替え点（契約の根拠は冒頭コメント）。起動行・報告行の解釈はこの関数群に閉じる ---

# bundle の複製（supervisor が bundle へ flock を取るため、コンテナごとに別ディレクトリを使う）。inode は共有しない複製にする（--reflink=auto）。
make_bundle_copy() { # <i>
  local dst="${work}/bundles/${id_prefix}-${1}"
  if ! cp -a --reflink=auto -- "$bundle" "$dst" 2>/dev/null; then
    err "invalid-argument" "cannot copy the bundle template"
    exit 2
  fi
  [ -f "${dst}/config.json" ] || { err "invalid-argument" "bundle must contain config.json"; exit 2; }
}

# create を期限付きで実行する（REPAIR-5）。失敗は終了コードだけを出す（出力・パスは出さない）。
sup_create() { # <i>
  local rc=0
  timeout --kill-after=5 "$timeout_s" "$cli_bin" --root "$state_root" create --bundle "${work}/bundles/${id_prefix}-${1}" "${id_prefix}-${1}" </dev/null >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || { err "launch-failed" "create failed for container ${1} (exit ${rc})"; final_rc=1; exit 1; }
}

# supervisor を直接の子として起動する。標準出力は FIFO（読み手を先に RDWR で開く）。引数は配列で直接 exec する。
# ulimit 等の制限は掛けない（コンテナ内の挙動が変わるため）。
sup_spawn() { # <i>
  local i="$1" fifo="${work}/fifos/f${1}" fd
  mkfifo -m 0600 "$fifo" || { err "launch-failed" "cannot create a fifo"; final_rc=1; exit 1; }
  exec {fd}<>"$fifo"
  FDS[$i]="$fd"
  (
    FANDHE_BENCH_OWNER="$owner_tok" exec "$systemd_run" --user --scope --quiet -p Delegate=yes -- "$sup_bin" start --root "$state_root" ${restart_args[@]+"${restart_args[@]}"} "${id_prefix}-${i}" </dev/null >"$fifo" 2>"${logdir}/l${i}.err"
  ) &
  pids[i]=$!
  pstart[i]=""
  if read_starttime "${pids[$i]}"; then pstart[i]="$ST"; fi
}

# 報告の 1 行を読み、FCSUP1 OK <pid> なら REP_PID へ記録して 0。ERR・書式不正は起動失敗として REP_FAIL・BADREP を記録して 2
# （exit しない。EXIT trap 内の cleanup_procs からも呼ばれるため、後始末を中断させない。終了コードの決定は呼び出し側が
# 後始末の前に行う）。未到着は 1。
sup_report() { # <i>
  local i="$1" chunk="" line="" rc=0
  [ -z "${REP_PID[$i]:-}" ] || return 0
  [ -z "${BADREP[$i]:-}" ] || return 2
  # read -t は期限切れのとき、それまでに読めた途中の文字列を chunk へ返して消費する（終了コード 128 超）。
  # 読み側は FIFO を 1 バイトずつ読むため、負荷で到着が 50ms を超えて分かれると途中の行を完全な行と誤認する
  # （pid の途中切れを別 pid として受理し、追跡不能の終了コード 4 になる。#2154・SUP-5・REPAIR-5）。
  # 改行が来るまで REP_BUF へ継ぎ足し、上限 640 バイトに達したら 1 行として照合する（measure-restart-latency.sh と同じ規則）。
  IFS= read -r -n 640 -t 0.05 -u "${FDS[$i]}" chunk || rc=$?
  REP_BUF[$i]="${REP_BUF[$i]:-}${chunk}"
  if [ "$rc" -gt 128 ] && [ "${#REP_BUF[$i]}" -lt 640 ]; then
    return 1
  fi
  line="${REP_BUF[$i]}"
  REP_BUF[$i]=""
  [ -n "$line" ] || return 1
  if [[ "$line" =~ ^FCSUP1\ OK\ ([1-9][0-9]{0,9})$ ]]; then
    REP_PID[$i]="${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$line" =~ ^FCSUP1\ ERR\ ([A-Z_]{1,32})\ ([0-9]{1,3})\  ]]; then
    err "launch-failed" "supervisor ${i} reported ERR ${BASH_REMATCH[1]} (exit ${BASH_REMATCH[2]})"
  else
    err "launch-failed" "supervisor ${i} printed an unrecognized report line"
  fi
  # 同じ報告を読み直さないための印。子プロセス不在の証明にはしない（不在を確認できなければ追跡不能で終了コード 4）。
  BADREP[$i]=1
  REP_FAIL=1
  return 2
}

# 全 supervisor が生存し、FCSUP1 OK を返し、報告 pid がその supervisor の子孫であること（直前の scan の結果で判定）。
all_ready() {
  local i
  # 全員の報告を先に読む（ERR を出した supervisor は、他の報告待ちに関係なく起動失敗として検出する）。
  for i in $(seq 1 "$count"); do sup_report "$i" || true; done
  # 起動失敗の報告があれば待機を打ち切る（呼び出し側が REP_FAIL を見て終了する）。
  [ "$REP_FAIL" -eq 0 ] || return 0
  for i in $(seq 1 "$count"); do
    # 報告を先に読む（ERR を出して終了した supervisor も、ここで起動失敗として検出する）。
    sup_report "$i" || return 1
    same_proc_alive "${pids[$i]}" "${pstart[$i]:-}" "$$" || return 1
    tree_of "${pids[$i]}"
    [[ " ${TREE}" == *" ${REP_PID[$i]}:"* ]] || return 1
  done
}

timed_out() { err "timeout" "$1"; final_rc=1; exit 1; }

# --check-restart のときだけ再起動ポリシーを渡す（bin の既定は RestartPolicy::No で、渡さないと再起動を観測できない。SUP-3）。
restart_args=()
if [ "$check_restart" -eq 1 ]; then restart_args=(--restart always); fi
REP_FAIL=0
spawned=1
for i in $(seq 1 "$count"); do make_bundle_copy "$i"; done
for i in $(seq 1 "$count"); do sup_create "$i"; done
for i in $(seq 1 "$count"); do sup_spawn "$i"; done
for i in $(seq 1 "$count"); do
  [ -n "${pstart[$i]:-}" ] || { err "launch-failed" "cannot record the start time of a launcher"; final_rc=1; exit 1; }
done
wait_tracked "$timeout_s" all_ready || timed_out "not all ${count} supervisors reported FCSUP1 OK within ${timeout_s}s"
if [ "$REP_FAIL" -eq 1 ]; then final_rc=1; exit 1; fi

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
  if [[ " ${TREE}" != *" ${REP_PID[$i]}:"* ]]; then
    err "launch-failed" "the container pid reported by supervisor ${i} is not in its process tree"
    final_rc=1
    exit 1
  fi
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

# --- --check-restart（opt-in。SUP-3 の restart ポリシー実装と再 launch〔#2043 で成立〕が前提）: 残り N-1 個のコンテナ側プロセスを kill して再起動を確認 ---
# 再起動の成立条件: kill した旧プロセス（pid・起動時刻）がすべて消滅していること、かつ各監視プロセスについて、kill 前に記録した子孫（pid・起動時刻）に含まれない「新しい」直接の子で、
# kill した子とシグネチャ（comm＋完全な cmdline）が一致するものが、シグネチャごとに kill した直接の子の数以上、生存していること。
# 同名・別コマンドの補助プロセスが増えただけでは成立しない。待機中と settle 中も子孫を追跡し続け（環境変数を
# 継承しない再起動後の子も後始末で回収する）、成立後に settle 秒待ち、
# N-1 個の監視プロセスと再起動したコンテナ側プロセスが同一のまま生存していること（稼働継続）も再照合する。
# 既知の制約: 現行の launcher 契約にはコンテナ ID・ランタイム状態を取得する手段がないため、対応関係はコマンド同一性
# （シグネチャ）と「直接の子」という位置で近似する。同一コマンドの補助プロセスは区別できず、再起動でコマンドラインが変わる
# 実装は不成立になる（安全側）。SUP-3 の実装後は、コンテナ ID・状態の取得手段で照合に置き換える（#499 で確認）。
restart_check="skipped"
restart_confirmed=null
if [ "$check_restart" -eq 1 ]; then
  declare -A OLDKIDS=() OLDSET=() OLDN=() NEWKIDS=() OLDSIGS=() OLDSIGN=()
  OLDPAIRS=()
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
      OLDPAIRS+=("${cpid}:${cstart}")
      sig_same_proc KILL "$cpid" "$cstart" "$cppid"
    done
  done
  restarted_all() {
    local j c n=0 fresh sg sigv
    local -A freshn
    scan
    # kill した旧プロセス（pid・起動時刻の組）がすべて消滅するまで、新しい子を再起動と認定しない。
    # SIGKILL の失敗（権限・競合）で旧プロセスが残ったまま同一コマンドの子が増えても pass にしない。
    for c in ${OLDPAIRS[@]+"${OLDPAIRS[@]}"}; do
      ! snap_alive "${c%%:*}" "${c#*:}" || return 1
    done
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
  elif wait_tracked "$timeout_s" restarted_all; then
    # 再起動後の稼働継続: settle 後に N-1 個の監視プロセスと新しいコンテナ側プロセスを同一性つきで再照合する。
    settle_tracked
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
