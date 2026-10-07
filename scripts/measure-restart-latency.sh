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
#       [--label STR] [--id-prefix STR（既定 fc-restart-lat）] [--output FILE（新規ファイルのみ）] [--help]
#   --state-root 省略時: 非 root は一時ディレクトリを XDG_RUNTIME_DIR として launcher に渡す。root は
#   /run/fandhe-container を読む（crates/core の解決規則と同じ）。
#
# 出力: JSON（標準出力。--output 指定時はそのファイル）。launcher・bundle・state-root のパス、cmdline、環境変数は出さない。
# 終了コード: 0 = 成功 / 1 = 計測失敗（READY なし・期限切れ・再起動未観測・時計変更・launcher 異常終了）/
#   2 = 引数・入力・出力先エラー / 3 = 前提欠如（非 Linux・bash 5 未満・jq・/proc。0 で合格に見せない）/
#   4 = 後始末失敗（残存プロセス。最優先）/ 129・130・143 = HUP・INT・TERM による中断（後始末の完了後）。
# 新プロセスの検証: 観測時と確定時に、新 pid が生存し（ゾンビ除外）launcher の子孫で、起動時刻が一致することを
#   確認する（SUP-3。state.json だけ残って新プロセスが終了した試行は採用しない）。
# 後始末: 試行中に観測した全コンテナ pid を起動時刻の同一性で回収し、launcher 停止後に state.json に現れた
#   別 pid は session（launcher と一致）または所有トークン（環境変数）で帰属を確認できたものだけ回収し、
#   確認できない pid は kill せず警告を出し、残存として終了コード 4 で結果を公開しない（起動時刻だけを根拠にしない）。restart ログの副系列は
#   launcher 停止後に集計する（最後の restart ログが状態更新より遅れても欠損にしない）。
# 安全策: kill の送信先は「state.json の pid」かつ「launcher の子孫」かつ「起動時刻が記録と一致」の
#   3 条件を満たすものだけ（偽造 state.json・pid 再利用で無関係プロセスを kill しない）。
set -euo pipefail

readonly num_re='^(0|[1-9][0-9]{0,8})$'
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
check_range "--trials" "$trials" 1 200
check_range "--warmup" "$warmup" 0 20
check_range "--timeout" "$timeout_s" 1 600
check_range "--poll-us" "$poll_us" 100 100000
check_range "--settle-ms" "$settle_ms" 0 5000
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
for req in mktemp ln grep sleep kill uname od tr jq setsid env rm mkfifo; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
[ -r /proc/self/stat ] && [ -r /proc/uptime ] || { err "unsupported-os" "/proc is required"; exit 3; }

# --- 状態 ---
workdir=""
owner_tok=""
launcher_pid=""
launcher_start=""
final_rc=0
reported="null"
reported_err=0
collect_log=0
# 試行中に観測したコンテナ側プロセスの「pid → 起動時刻」。後始末で全件を同一性照合のうえ回収する。
declare -A tracked=()
declare -A unrelated=()
cleaned=0
napfd=""
out_tmp=""
state_file=""
container_id=""

# 待機は組み込みの read -t（fork しない）で行う。ポーリング中に一過性の子プロセスを作らないため。
nap() { read -r -t "$1" -u "$napfd" || true; }

# マイクロ秒の現在時刻（EPOCHREALTIME の小数点は locale により , の場合がある）。
now_us() { local t="$EPOCHREALTIME"; t="${t/[.,]/}"; REPLY_US=$((10#$t)); }
up_cs() { local up; read -r up _ </proc/uptime; up="${up/[.,]/}"; REPLY_CS=$((10#$up)); }

# /proc/<pid>/stat から ppid・session・起動時刻（field 22）を得る。comm に空白・括弧を含んでもよいよう最後の ) 以降を使う。
proc_info() { # <pid> → REPLY_PPID / REPLY_SID / REPLY_START（失敗時は return 1）
  local s rest
  local -a f
  [ -r "/proc/$1/stat" ] || return 1
  s="$(<"/proc/$1/stat")" 2>/dev/null || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  [ "${#f[@]}" -ge 20 ] || return 1
  REPLY_PPID="${f[1]}"
  REPLY_SID="${f[3]}"
  REPLY_START="${f[19]}"
}

# 生存判定。kill -0 はゾンビも真になるため /proc の state が Z でないことを見る。
alive() { # <pid>
  local s
  [ -r "/proc/$1/stat" ] || return 1
  s="$(<"/proc/$1/stat")" 2>/dev/null || return 1
  [[ "$s" != *") Z "* ]]
}

# pid の起動時刻が記録と一致するか（PID 再利用で別プロセスへ signal を送らないための直前再照合）。
# 記録が空なら不一致扱い（同一性を証明できないものには送らない）。
same_proc() { # <pid> <記録した起動時刻>
  [ -n "$2" ] || return 1
  alive "$1" && proc_info "$1" && [ "$REPLY_START" = "$2" ]
}

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

# pid が launcher の子孫か（PPid 連鎖を 64 段まで辿る）。成功時の REPLY_START は対象 pid 自身の起動時刻
# （祖先の起動時刻で上書きしない。孫以降の子孫でも同一性照合が成立するように先頭で退避する）。
is_descendant() { # <pid>
  local p="$1" depth=0 target_start=""
  while [ "$depth" -lt 64 ]; do
    proc_info "$p" || return 1
    [ "$depth" -gt 0 ] || target_start="$REPLY_START"
    p="$REPLY_PPID"
    if [ "$p" = "$launcher_pid" ]; then REPLY_START="$target_start"; return 0; fi
    { [ "$p" -le 1 ] 2>/dev/null; } && return 1
    depth=$((depth + 1))
  done
  return 1
}

# state.json を純 bash で読む（計測区間内で jq を fork しない）。1 MiB 上限・symlink 拒否。
# 結果: ST_STATUS / ST_PID / ST_COUNT。読めない・途中の内容は return 1（呼び出し側が再ポーリング）。
read_state() {
  local c=""
  ST_STATUS="" ST_PID="" ST_COUNT=""
  [ -L "$state_file" ] && return 1
  [ -f "$state_file" ] || return 1
  IFS= read -r -d '' -N 1048577 c <"$state_file" 2>/dev/null || true
  [ "${#c}" -le 1048576 ] || return 1
  [[ "$c" =~ \"status\"[[:space:]]*:[[:space:]]*\"([a-z]+)\" ]] || return 1
  ST_STATUS="${BASH_REMATCH[1]}"
  [[ "$c" =~ \"restartCount\"[[:space:]]*:[[:space:]]*([0-9]{1,9})[^0-9] ]] || return 1
  ST_COUNT=$((10#${BASH_REMATCH[1]}))
  if [[ "$c" =~ \"pid\"[[:space:]]*:[[:space:]]*([0-9]{1,9})[^0-9] ]]; then ST_PID=$((10#${BASH_REMATCH[1]})); else ST_PID=""; fi
  return 0
}

# 追跡対象へ追加（同一 pid は起動時刻を更新。pid 再利用後の古い記録は死んでいるので無害）。
track_pid() { tracked["$1"]="$2"; }

# 観測が終わった後に jq で state.json を再読込して厳密検証する。id 一致・status=running・観測した新 pid・
# restartCount == 旧 + 1 のすべてを満たさなければ失敗（ポーリング後に状態が変わった試行は採用しない）。
validate_state_strict() { # <観測した新 pid> <期待 restartCount>
  [ -L "$state_file" ] && return 1
  jq -e --arg id "$container_id" --argjson pid "$1" --argjson cnt "$2" \
    '.id == $id and .status == "running" and (.pid|type=="number") and .pid == $pid and (.restartCount|type=="number") and .restartCount == $cnt' \
    "$state_file" >/dev/null 2>&1
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
  if jq -Rre 'fromjson? | select(type=="object" and .component=="supervisor.monitor" and .operation=="restart" and .result=="error") | "x"' "$workdir/err.log" 2>/dev/null | grep -q x; then
    reported_err=1
    return 0
  fi
  mapfile -t rep < <(jq -Rre 'fromjson? | select(type=="object" and .component=="supervisor.monitor" and .operation=="restart" and .result=="ok") | .elapsed_us | select(type=="number" and .>=0 and .==floor and .<=3600000000)' "$workdir/err.log" 2>/dev/null || true)
  if [ "${#rep[@]}" -eq "$total" ]; then
    reported="$(printf '%s\n' "${rep[@]:$warmup}")"
  fi
}

# 回収。終了コード 4（残存）を最優先にするため、戻り値 0 = 回収確認済み。
do_cleanup() {
  local i p rc=0 stale=()
  [ "$cleaned" -eq 0 ] || return 0
  cleaned=1
  trap '' INT TERM HUP
  # launcher へは起動時刻が記録と一致する間だけ送る（先に終了して PID が再利用された場合に無関係プロセスを止めない）。
  if [ -n "$launcher_pid" ] && same_proc "$launcher_pid" "$launcher_start"; then
    kill -TERM "$launcher_pid" 2>/dev/null || true
    for ((i = 0; i < 100; i++)); do
      same_proc "$launcher_pid" "$launcher_start" || break
      nap 0.05
    done
    if same_proc "$launcher_pid" "$launcher_start"; then kill -KILL "$launcher_pid" 2>/dev/null || true; fi
  fi
  # 環境変数を継承した孤児はトークンの完全一致で回収する。grep -F は候補の絞り込みだけに使い、
  # 所有判定は environ の NUL 区切りエントリの完全一致（env_owned）で行い、kill 直前に起動時刻を再照合する。
  if [ -n "$owner_tok" ]; then
    local -A stale_start=()
    local s1
    for ((i = 0; i < 3; i++)); do
      stale=()
      while IFS= read -r p; do
        p="${p#/proc/}"; p="${p%%/*}"
        [ "$p" = "$$" ] && continue
        proc_info "$p" || continue
        s1="$REPLY_START"
        env_owned "$p" || continue
        if same_proc "$p" "$s1"; then
          stale+=("$p")
          stale_start["$p"]="$s1"
          kill -KILL "$p" 2>/dev/null || true
        fi
      done < <(grep -l -a -F -s "FANDHE_BENCH_OWNER=$owner_tok" /proc/[0-9]*/environ 2>/dev/null || true)
      [ "${#stale[@]}" -gt 0 ] || break
      nap 0.1
    done
    if [ "${#stale[@]}" -gt 0 ]; then
      nap 0.2
      for p in "${stale[@]}"; do
        if same_proc "$p" "${stale_start[$p]}"; then rc=4; fi
      done
    fi
  fi
  # launcher 停止後に state.json の pid を再読込する。追跡済みでない生存 pid（回収中に launcher が最後に
  # 起動したコンテナ）は、本計測への帰属を証明できる場合だけ追跡へ加える。帰属の根拠は (1) session が
  # launcher（setsid の leader）と一致する、(2) 環境変数に本実行の所有トークンを持つ、のいずれか。
  # 起動時刻が launcher 以降という条件だけでは本計測の生成物と言えない（無関係な新規 pid の可能性）ため
  # 根拠にしない。帰属を確認できない pid は kill せず警告ログを出して後始末失敗（rc=4）とする（権限付きシェルでの誤殺防止）。
  if [ -n "$state_file" ] && [ -n "$launcher_pid" ] && read_state && [ -n "$ST_PID" ] \
    && [ -z "${tracked[$ST_PID]+x}" ] && [ -z "${unrelated[$ST_PID]+x}" ] && [ "$ST_PID" != "$$" ] && alive "$ST_PID"; then
    if proc_info "$ST_PID"; then
      if [ "$REPLY_SID" = "$launcher_pid" ] \
        || env_owned "$ST_PID"; then
        track_pid "$ST_PID" "$REPLY_START"
      else
        # 生存したまま残るため後始末失敗（4）として扱い、結果は公開しない（特権操作の後始末。誤殺防止で kill はしない）。
        printf 'warning: pid %s in state.json cannot be attributed to this run; not signaling it\n' "$ST_PID" >&2 || true
        rc=4
      fi
    else
      # 生存しているが帰属を判定できない pid も残存として扱う。
      rc=4
    fi
  fi
  # launcher 停止後なので restart ログは出尽くしている。副系列はここで集計する（状態更新後にログを出す契約でも欠損にしない）。
  if [ "$collect_log" -eq 1 ]; then collect_reported; fi
  # 環境変数を継承しないコンテナ側プロセスは、追跡した全 pid を起動時刻の同一性で回収する。
  local -a victims=()
  for p in "${!tracked[@]}"; do
    if proc_info "$p" && [ "$REPLY_START" = "${tracked[$p]}" ]; then
      victims+=("$p")
      # 列挙時の照合から kill までの間に PID が再利用されていないか直前に再照合する。
      if same_proc "$p" "${tracked[$p]}"; then kill -KILL "$p" 2>/dev/null || true; fi
    fi
  done
  if [ "${#victims[@]}" -gt 0 ]; then
    nap 0.1
    for p in "${victims[@]}"; do
      if alive "$p" && proc_info "$p" && [ "$REPLY_START" = "${tracked[$p]}" ]; then rc=4; fi
    done
  fi
  if [ -n "$launcher_pid" ]; then
    if same_proc "$launcher_pid" "$launcher_start"; then rc=4; else wait "$launcher_pid" 2>/dev/null || true; fi
  fi
  [ -z "$out_tmp" ] || rm -f -- "$out_tmp" 2>/dev/null || true
  [ -z "$workdir" ] || rm -rf -- "$workdir" 2>/dev/null || true
  if [ -n "$state_root" ] && [ -n "$container_id" ] && [ "$rc" -eq 0 ]; then
    : # --state-root は操作者の領域。<id>/ は削除しない（残置を通知する）。
    printf 'note: left state entry for id %s under --state-root (operator-owned)\n' "$container_id" >&2 || true
  fi
  return "$rc"
}

on_exit() {
  local rc=$?
  final_rc=$rc
  if ! do_cleanup; then
    err "cleanup-failed" "processes may remain after the run; inspect and kill them manually"
    exit 4
  fi
  exit "$final_rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

fail() { err "measurement-failed" "$1"; exit 1; }

# --- 準備 ---
umask 077
workdir="$(mktemp -d)"
mkfifo "$workdir/nap.fifo"
exec {napfd}<>"$workdir/nap.fifo"
owner_tok="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
rand8="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
container_id="${id_prefix}-${rand8}"
launcher_env=()
if [ -n "$state_root" ]; then
  state_dir="$state_root"
elif [ "$uid_now" -eq 0 ]; then
  state_dir="/run/fandhe-container"
else
  mkdir -m 0700 "$workdir/xdg"
  launcher_env=("XDG_RUNTIME_DIR=$workdir/xdg")
  state_dir="$workdir/xdg/fandhe-container"
fi
state_file="$state_dir/$container_id/state.json"
printf -v poll_s '0.%06d' "$poll_us"
poll_s="${poll_s/0.1000000/1}"
settle_s="$((settle_ms / 1000)).$(printf '%03d' $((settle_ms % 1000)))"

build_launch_cmd
(
  ulimit -f 4096 2>/dev/null || true # 標準エラーの肥大化を 4 MiB で止める（超過で launcher が止まり計測失敗）
  exec setsid env "FANDHE_BENCH_OWNER=$owner_tok" "${launcher_env[@]}" "${LAUNCH_CMD[@]}" \
    >"$workdir/out.log" 2>"$workdir/err.log" </dev/null
) &
launcher_pid=$!
if proc_info "$launcher_pid"; then launcher_start="$REPLY_START"; fi

deadline_wait() { # <説明> : 条件関数 "$@" が真になるまで --timeout まで待つ
  local what="$1" end
  shift
  now_us
  end=$((REPLY_US + timeout_s * 1000000))
  while ! "$@"; do
    alive "$launcher_pid" || fail "launcher exited while waiting for $what"
    now_us
    [ "$REPLY_US" -lt "$end" ] || fail "timed out waiting for $what"
    nap "$poll_s"
  done
}

ready_seen() { grep -qx 'READY' "$workdir/out.log" 2>/dev/null; }
running_seen() { read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ]; }

deadline_wait "READY" ready_seen
deadline_wait "the container to be running in state.json" running_seen

vals=()
total=$((trials + warmup))
for ((n = 1; n <= total; n++)); do
  read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ] || fail "state.json is not in the running state before trial $n"
  old_pid="$ST_PID"
  old_count="$ST_COUNT"
  alive "$launcher_pid" || fail "launcher exited before trial $n"
  # kill 前の 3 条件: 子孫・起動時刻の記録・直前再照合（無関係プロセスへ送信しない）。
  # 子孫でないと判定済みの pid は本計測の生成物でない（偽造・無関係）。後始末で残存扱いにしない。
  is_descendant "$old_pid" || { unrelated["$old_pid"]=1; fail "pid in state.json is not a descendant of the launcher; refusing to send a signal"; }
  start1="$REPLY_START"
  track_pid "$old_pid" "$start1"
  proc_info "$old_pid" && [ "$REPLY_START" = "$start1" ] || fail "container process changed before the signal"
  up_cs; up0="$REPLY_CS"
  now_us; t0="$REPLY_US"
  kill -KILL "$old_pid" 2>/dev/null || fail "could not signal the container process"
  end=$((t0 + timeout_s * 1000000))
  t1=""
  while :; do
    if read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ] && [ "$ST_PID" != "$old_pid" ]; then
      now_us; t1="$REPLY_US"
      [ "$ST_COUNT" -eq $((old_count + 1)) ] || fail "restartCount jumped from $old_count to $ST_COUNT in trial $n"
      break
    fi
    alive "$launcher_pid" || fail "launcher exited before the restart was observed in trial $n"
    now_us
    [ "$REPLY_US" -lt "$end" ] || fail "restart was not observed within ${timeout_s}s in trial $n"
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
  alive "$new_pid" && is_descendant "$new_pid" || fail "new container process is not alive as a launcher descendant at observation in trial $n"
  new_start="$REPLY_START"
  track_pid "$new_pid" "$new_start"
  validate_state_strict "$new_pid" "$((old_count + 1))" || fail "state.json failed strict validation in trial $n"
  # 確定時: 同じ新 pid・起動時刻のプロセスがまだ生存していること。
  alive "$new_pid" && proc_info "$new_pid" && [ "$REPLY_START" = "$new_start" ] || fail "new container process exited before the trial $n result was confirmed"
  [ "$n" -le "$warmup" ] || vals+=("$d_wall")
  nap "$settle_s"
done

# --- 副系列は launcher 停止後（do_cleanup 内の collect_reported）に集計する。ここで停止・回収を先に行う ---
collect_log=1
if ! do_cleanup; then
  err "cleanup-failed" "processes may remain after the run; inspect and kill them manually"
  exit 4
fi
[ "$reported_err" -eq 0 ] || fail "launcher reported a failed restart"

# 集計（jq）。中央値は偶数個で中央 2 値の平均、p95 は昇順の ceil(n*95/100)-1 番目。単位は ms（小数 3 桁）。
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
      observed: "SIGKILL to the container process until state.json shows running, a new pid and restartCount+1; includes signal delivery, exit detection and the polling granularity of this script (upper bound)",
      supervisor_reported: "elapsed_us of the supervisor.monitor restart log line (exit detected until the new Running state is recorded); null when the launcher log does not provide trials+warmup ok lines",
      poc17_difference: "PoC-17 measured the next start time minus the previous end time recorded by a self-exiting workload, which is a different interval; do not compare the numbers directly",
      percentile: "nearest-rank ceil(n*95/100)-1 on sorted samples; median averages the two middle values for an even count" } }')"

# 後始末は上で完了済み（残存があれば 4 で結果を出さない）。結果を公開する。
if [ -n "$output" ]; then
  out_tmp="$(mktemp "${output}.XXXXXX")"
  printf '%s\n' "$result" >"$out_tmp"
  ln -T -- "$out_tmp" "$output" 2>/dev/null || { rm -f -- "$out_tmp"; err "invalid-argument" "output path already exists or cannot be created"; exit 2; }
  rm -f -- "$out_tmp"
  out_tmp=""
else
  printf '%s\n' "$result"
fi
exit 0
