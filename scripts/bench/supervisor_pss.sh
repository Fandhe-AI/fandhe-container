#!/usr/bin/env bash
# 監視プロセス常駐メモリ（PSS）計測スクリプト（TASK-158・SUP-2）。
#
# 役割: 監視プロセス（既定 exe 名 fandhe-container-supervisor）の PSS を /proc から計測し、
# SUP-2（監視プロセス 1 つあたりの PSS 中央値が 2MB 以下。単体・N コンテナ按分後のいずれの
# 解釈でも満たす。PoC-17 追記 5 は N=50 按分後 526KB = 26,282KB / 50）の判定材料を出力する。
# 呼び出し元は Makefile の `supervisor-pss` ターゲット。idle_memory.sh（TASK-45.1・CORE-7）の
# 識別規則・終了コード契約を踏襲し、後続の実測レポート（TASK-158.h1・#485）が利用する。
# 本スクリプトは合否を出さない（目標値 2048KB は JSON の target_pss_kb に参考値として載せるのみ。
# 判定は人間が行う）。コンテナ・監視プロセスの起動もしない（起動は操作者が事前に行う。
# 50 コンテナ同時起動の起動ハーネスは concurrent_50_memory.sh が持つ）。
#
# 現状（REPAIR-3）: fandhe-container-supervisor の製品バイナリは未提供のため、現時点では実測できない。
# 実測は製品バイナリ提供後に #485 で人間が行う。--exe-name の既定値が実バイナリ名と一致するかも
# その時に確認する。「監視プロセス」に runtime 側の補助プロセスを含めるか（PoC-17 の N=1 は
# supervisor 単体 + runtime-proto 単体の合算）は判定側の解釈事項で、本スクリプトは exe 名 1 種の
# 集計に留める。必要なら --exe-name を変えて複数回計測する。
#
# 使い方:
#   supervisor_pss.sh --pid <pid> [--pid <pid>]... [共通オプション]   # PID 指定モード
#   supervisor_pss.sh --count <N> [共通オプション]                    # 按分モード（N 個検出が必須）
# 共通オプション:
#   [--samples K] [--interval SECS] [--exe-name NAME] [--expected-dir <dir>]...
#   [--format text|json] [--output <file>] [--help]
#   --samples K（1〜100・既定 1）: K 回走査する。サンプル間で対象 pid 集合が変わったら計測失敗。
#   --interval SECS（0〜600・既定 1）: サンプル間隔。
#   --exe-name: 既定 fandhe-container-supervisor。^fandhe-container(-[a-z0-9-]+)?$ のみ許可。
#   --pid（1〜1024 個・重複不可）: 各 pid の exe basename が対象名でなければ計測失敗。
#   --count N（1〜1024）: /proc を走査し exe basename が対象名に完全一致するプロセスを発見する。
#     発見数が N と一致しなければ計測失敗（起動失敗を含む無効な按分値を公開しない）。
#   --pid と --count は排他で、どちらか必須。
#
# 集計（固定）: 指標は smaps_rollup の Pss（主）と status の VmRSS（参考）。小数は 1 桁・四捨五入
#   （bash 整数演算の 10 倍固定小数点。例: 26282 / 50 = 525.64 -> 525.6）。
#   apportioned_pss_kb_median = サンプルごとの (合計 / 数) のサンプル間中央値（主指標・按分後）
#   per_process_pss_kb_median = 最終サンプルのプロセス間 PSS 中央値（単体解釈の参考）
#   偶数個の中央値は中央 2 値の平均。
#
# 識別: /proc/<pid>/exe のリンク先 basename（argv[0] は自己申告できるため使わない）。--count 走査では
#   exe が対象名でないが argv[0] または comm（15 文字切り詰め形含む）が対象名を名乗るもの、
#   exe を読めない非カーネルスレッド・非ゾンビは計測失敗（fail-closed）。--expected-dir を与えると
#   対象名 exe がそのディレクトリ直下になければ計測失敗。残余リスク: exe・argv[0]・comm をすべて偽装した
#   改名バイナリは検出できない（偽装による妨害は可能だが偽の成功にはならない）。
#   cmdline 全文・環境変数は読まず出力しない（出すのは pid・basename・数値のみ）。
#
# 終了コード:
#   0 = 計測成功
#   1 = 未使用（set -e の暗黙終了で 1 を返さないよう失敗しうる操作は明示分岐する）
#   2 = 引数・入力エラー、非 Linux（unsupported-os。0 を返して合格に見せない）、出力先エラー
#   3 = 計測失敗（発見数 != N、exe 不一致、PSS が 0・欠落・非数値・読めない、pid 消滅が収束しない、
#       サンプル間で pid 集合が変化）。0 として足さず fail-closed
#
# 前提・既知の制約:
#   - Linux 限定（smaps_rollup はカーネル 4.14 以降）。スクリプト内で sudo は呼ばない
#     （他ユーザー所有プロセスの読み取りは操作者が権限付きシェルから実行する）。
#   - /proc の読み取り自体にはタイムアウトがない（REPAIR-5）。Makefile の `supervisor-pss` が
#     `timeout` で包む。
#   - --output は mktemp + mv -fT で原子的に公開する。権限付き実行時の祖先ディレクトリ差し替えは
#     防がない（出力先は信頼できる場所に限ること）。
#   - stderr に出す外部由来の文字列は印字可能 ASCII 以外を `?` に置換する。

set -euo pipefail

readonly MAX_PIDS=65536
readonly MAX_SCAN_ATTEMPTS=10
readonly TARGET_PSS_KB=2048

err() {
  local LC_ALL=C msg
  msg="error: $1: $2"
  msg="${msg//[^[:print:]]/?}"
  printf '%s\n' "$msg" >&2 || true
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

# 先頭 0 付きを拒否し 13 桁まで（算術の 8 進解釈と 64 bit あふれの防止）。
num_re='^(0|[1-9][0-9]{0,12})$'
name_re='^fandhe-container(-[a-z0-9-]+)?$'

# 範囲検証。引数: <名前> <値> <最小> <最大>
check_range() {
  if ! [[ "$2" =~ $num_re ]] || [ "$2" -lt "$3" ] || [ "$2" -gt "$4" ]; then
    err "invalid-argument" "$1 must be an integer from $3 to $4"
    exit 2
  fi
}

format="text"
output=""
proc_root=""
proc_root_given=0
exe_name="fandhe-container-supervisor"
samples=1
interval=1
count=""
pids=()
expected_dirs=()

need_value() { [ "$1" -ge 2 ] || { err "invalid-argument" "$2 requires a value"; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --pid) need_value $# --pid; pids+=("$2"); shift 2 ;;
    --count) need_value $# --count; count="$2"; shift 2 ;;
    --samples) need_value $# --samples; samples="$2"; shift 2 ;;
    --interval) need_value $# --interval; interval="$2"; shift 2 ;;
    --exe-name) need_value $# --exe-name; exe_name="$2"; shift 2 ;;
    --format) need_value $# --format; format="$2"; shift 2 ;;
    --output) need_value $# --output; output="$2"; shift 2 ;;
    --proc-root) need_value $# --proc-root; proc_root="$2"; proc_root_given=1; shift 2 ;;
    --expected-dir) need_value $# --expected-dir; expected_dirs+=("${2%/}"); shift 2 ;;
    --help | -h)
      if ! usage 2>/dev/null; then
        err "output-failed" "cannot write usage to stdout"
        exit 2
      fi
      exit 0
      ;;
    *) err "invalid-argument" "unknown argument: $1"; exit 2 ;;
  esac
done

case "$format" in
  text | json) ;;
  *) err "invalid-argument" "--format must be text or json"; exit 2 ;;
esac
if ! [[ "$exe_name" =~ $name_re ]]; then
  err "invalid-argument" "--exe-name must match ${name_re}"
  exit 2
fi
check_range "--samples" "$samples" 1 100
check_range "--interval" "$interval" 0 600

if [ "${#pids[@]}" -gt 0 ] && [ -n "$count" ]; then
  err "invalid-argument" "--pid and --count are mutually exclusive"
  exit 2
fi
if [ "${#pids[@]}" -eq 0 ] && [ -z "$count" ]; then
  err "invalid-argument" "either --pid or --count is required"
  exit 2
fi
if [ -n "$count" ]; then
  mode="count"
  check_range "--count" "$count" 1 1024
else
  mode="pid"
  if [ "${#pids[@]}" -gt 1024 ]; then
    err "invalid-argument" "too many --pid values (limit 1024)"
    exit 2
  fi
  seen=" "
  for p in "${pids[@]}"; do
    check_range "--pid" "$p" 1 9999999999999
    case "$seen" in
      *" $p "*) err "invalid-argument" "duplicate --pid: $p"; exit 2 ;;
    esac
    seen+="$p "
  done
  count="${#pids[@]}"
fi

# --proc-root（疑似 /proc）は selftest 専用。実 /proc の迂回を通常利用で許さない。
if [ "$proc_root_given" -eq 1 ]; then
  if [ "${FANDHE_SUPERVISOR_PSS_SELFTEST:-}" != "1" ]; then
    err "invalid-argument" "--proc-root is for selftest only (set FANDHE_SUPERVISOR_PSS_SELFTEST=1)"
    exit 2
  fi
  case "$proc_root" in
    -*) err "invalid-argument" "proc root must not start with '-'"; exit 2 ;;
  esac
fi

if [ -n "${FANDHE_SUPERVISOR_PSS_UNAME_S:-}" ]; then
  os_name="$FANDHE_SUPERVISOR_PSS_UNAME_S"
elif ! os_name="$(uname -s)"; then
  err "unsupported-os" "cannot determine OS name"
  exit 2
fi
if [ "$proc_root_given" -eq 0 ]; then
  if [ "$os_name" != "Linux" ]; then
    err "unsupported-os" "only Linux is supported (got ${os_name})"
    exit 2
  fi
  proc_root="/proc"
fi
if [ ! -d "$proc_root" ]; then
  err "invalid-argument" "proc root is not a directory: ${proc_root}"
  exit 2
fi

if [ -n "$output" ]; then
  case "$output" in
    -*) err "invalid-argument" "output path must not start with '-'"; exit 2 ;;
  esac
  if [ -d "$output" ]; then
    err "invalid-argument" "output path is a directory: ${output}"
    exit 2
  fi
  output_dir="${output%/*}"
  [ "$output_dir" != "$output" ] || output_dir="."
  [ -n "$output_dir" ] || output_dir="/"
  if [ ! -d "$output_dir" ]; then
    err "invalid-argument" "output directory does not exist: ${output_dir}"
    exit 2
  fi
fi

# 1 回の走査結果。各要素は "pid name pss rss"。
records=()
scanned=0

read_kb() {
  awk -v key="$2:" '$1 == key { print $2; exit }' "$1"
}

comm_claims_name() {
  [[ "$1" =~ $name_re ]] || [ "$1" = "fandhe-containe" ]
}

# 対象 1 件の PSS / RSS を読んで records へ足す。0・欠落・非数値・読めない値は計測失敗（過小計上の防止）。
# 戻り値: 0 = 追加 / 10 = pid 消滅（走査やり直し）。
add_record() {
  local dir="$1" pid="$2" name="$3" pss rss
  if ! pss="$(read_kb "$dir/smaps_rollup" Pss 2>/dev/null)" ||
    ! rss="$(read_kb "$dir/status" VmRSS 2>/dev/null)"; then
    [ -d "$dir" ] || return 10
    err "measurement-failed" "cannot read memory counters of pid ${pid} (insufficient permission?)"
    exit 3
  fi
  if ! [[ "$pss" =~ $num_re ]] || ! [[ "$rss" =~ $num_re ]] || [ "$pss" -eq 0 ]; then
    [ -d "$dir" ] || return 10
    err "measurement-failed" "zero, non-numeric or missing Pss/VmRSS for pid ${pid}"
    exit 3
  fi
  records+=("${pid} ${name} ${pss} ${rss}")
}

check_expected_dir() {
  local d in_expected=0
  [ "${#expected_dirs[@]}" -gt 0 ] || return 0
  for d in "${expected_dirs[@]}"; do
    if [ "${2%/*}" = "$d" ]; then in_expected=1; break; fi
  done
  if [ "$in_expected" -eq 0 ]; then
    err "measurement-failed" "pid $1 exe is outside --expected-dir: $2"
    exit 3
  fi
}

# --pid モードの 1 回走査。戻り値: 0 / 10（pid 消滅）。
scan_pids() {
  local pid dir exe_target name
  records=()
  for pid in "${pids[@]}"; do
    dir="$proc_root/$pid"
    [ -d "$dir" ] || return 10
    if ! exe_target="$(readlink "$dir/exe" 2>/dev/null)" || [ -z "$exe_target" ]; then
      [ -d "$dir" ] || return 10
      err "measurement-failed" "cannot read exe of pid ${pid} (insufficient permission?)"
      exit 3
    fi
    exe_target="${exe_target% (deleted)}"
    name="${exe_target##*/}"
    if [ "$name" != "$exe_name" ]; then
      err "measurement-failed" "pid ${pid} exe basename is not ${exe_name}"
      exit 3
    fi
    check_expected_dir "$pid" "$exe_target"
    add_record "$dir" "$pid" "$name" || return 10
  done
  return 0
}

# --count モードの 1 回走査（idle_memory.sh と同じ fail-closed 識別）。戻り値: 0 / 10。
scan_all() {
  local dir pid exe_target name ppid state argv0 comm claimed opened
  records=()
  scanned=0
  for dir in "$proc_root"/[0-9]*; do
    pid="${dir##*/}"
    [[ "$pid" =~ $num_re ]] || continue
    scanned=$((scanned + 1))
    if [ "$scanned" -gt "$MAX_PIDS" ]; then
      err "invalid-input" "too many pids under ${proc_root} (limit ${MAX_PIDS})"
      exit 2
    fi
    if exe_target="$(readlink "$dir/exe" 2>/dev/null)" && [ -n "$exe_target" ]; then
      exe_target="${exe_target% (deleted)}"
      name="${exe_target##*/}"
    else
      [ -d "$dir" ] || return 10
      if ! ppid="$(read_kb "$dir/status" PPid 2>/dev/null)" ||
        ! state="$(read_kb "$dir/status" State 2>/dev/null)"; then
        [ -d "$dir" ] || return 10
        err "measurement-failed" "cannot read exe or status of pid ${pid} (insufficient permission?)"
        exit 3
      fi
      if [ "$pid" = "2" ] || [ "$ppid" = "2" ]; then continue; fi
      if [ "$state" = "Z" ] || [ "$state" = "X" ]; then
        opened=1
        comm=""
        { IFS= read -r comm || true; } 2>/dev/null <"$dir/comm" || opened=0
        if [ "$opened" -eq 0 ] || comm_claims_name "$comm"; then
          err "measurement-failed" "zombie pid ${pid} cannot be ruled out as a target"
          exit 3
        fi
        continue
      fi
      [ -d "$dir" ] || return 10
      err "measurement-failed" "cannot verify executable of pid ${pid} (insufficient permission?)"
      exit 3
    fi
    if [ "$name" != "$exe_name" ]; then
      # 別名で配置・起動された対象の疑い（argv[0]・comm が対象名を名乗る）は識別不能として失敗にする。
      argv0=""
      comm=""
      opened=1
      { IFS= read -r -d '' argv0 || true; } 2>/dev/null <"$dir/cmdline" || opened=0
      if [ "$opened" -eq 1 ]; then
        { IFS= read -r comm || true; } 2>/dev/null <"$dir/comm" || opened=0
      fi
      if [ "$opened" -eq 0 ]; then
        [ -d "$dir" ] || return 10
        err "measurement-failed" "cannot read cmdline or comm of pid ${pid}; cannot rule out a renamed target"
        exit 3
      fi
      argv0="${argv0##*/}"
      claimed=""
      if [ "$argv0" = "$exe_name" ]; then
        claimed="argv[0]"
      elif [ "$comm" = "$exe_name" ] || [ "$comm" = "${exe_name:0:15}" ]; then
        claimed="comm"
      fi
      if [ -n "$claimed" ]; then
        err "measurement-failed" "pid ${pid} claims ${exe_name} via ${claimed} but exe basename is '${name}'; cannot identify"
        exit 3
      fi
      continue
    fi
    check_expected_dir "$pid" "$exe_target"
    add_record "$dir" "$pid" "$name" || return 10
  done
  return 0
}

# 走査をやり直し付きで 1 回実行する。
scan_with_retry() {
  local attempt=0 rc
  while :; do
    rc=0
    if [ "$mode" = "pid" ]; then scan_pids || rc=$?; else scan_all || rc=$?; fi
    [ "$rc" -eq 0 ] && return 0
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$MAX_SCAN_ATTEMPTS" ]; then
      err "measurement-failed" "pids kept vanishing or missing during scan (${attempt} attempts)"
      exit 3
    fi
  done
}

# 整数列の 10 倍固定小数点の中央値を標準出力へ。偶数個は中央 2 値の平均（整数入力なので厳密）。
median10() {
  local -a v
  local n
  mapfile -t v < <(printf '%s\n' "$@" | sort -n)
  n="${#v[@]}"
  if [ $((n % 2)) -eq 1 ]; then
    echo $((v[n / 2] * 10))
  else
    echo $(((v[n / 2 - 1] + v[n / 2]) * 5))
  fi
}

# 10 倍固定小数点値を小数 1 桁の文字列へ。
fmt10() {
  printf '%s.%s' "$(($1 / 10))" "$(($1 % 10))"
}

shopt -s nullglob
sample_totals=()
sample_appor10=()
pid_set=""
for ((k = 1; k <= samples; k++)); do
  scan_with_retry
  if [ "${#records[@]}" -ne "$count" ]; then
    err "measurement-failed" "found ${#records[@]} target processes but expected ${count}"
    exit 3
  fi
  total=0
  cur_set=""
  for rec in "${records[@]}"; do
    read -r _pid _name _pss _rss <<<"$rec"
    total=$((total + _pss))
    cur_set+="${_pid} "
  done
  if [ "$k" -eq 1 ]; then
    pid_set="$cur_set"
  elif [ "$cur_set" != "$pid_set" ]; then
    err "measurement-failed" "target pid set changed between samples"
    exit 3
  fi
  sample_totals+=("$total")
  # 四捨五入した 10 倍固定小数点の按分値: round(total * 10 / count)。
  sample_appor10+=("$(((total * 100 / count + 5) / 10))")
  if [ "$k" -lt "$samples" ] && [ "$interval" -gt 0 ]; then sleep "$interval"; fi
done

# 按分値（10 倍固定小数点）の中央値。偶数個は平均を四捨五入する。
n="${#sample_appor10[@]}"
mapfile -t _sorted < <(printf '%s\n' "${sample_appor10[@]}" | sort -n)
if [ $((n % 2)) -eq 1 ]; then
  appor_med10="${_sorted[n / 2]}"
else
  appor_med10=$(((_sorted[n / 2 - 1] + _sorted[n / 2] + 1) / 2))
fi
total_med10="$(median10 "${sample_totals[@]}")"
last_pss=()
rss_total=0
for rec in "${records[@]}"; do
  read -r _pid _name _pss _rss <<<"$rec"
  last_pss+=("$_pss")
  rss_total=$((rss_total + _rss))
done
per_proc_med10="$(median10 "${last_pss[@]}")"

out_buf=""
append() { out_buf+="$1"$'\n'; }

render_text() {
  local rec pid name pss rss
  append "behavior=SUP-2"
  append "mode=${mode}"
  append "count=${count}"
  append "samples=${samples}"
  append "total_pss_kb_median=$(fmt10 "$total_med10")"
  append "apportioned_pss_kb_median=$(fmt10 "$appor_med10")"
  append "per_process_pss_kb_median=$(fmt10 "$per_proc_med10")"
  append "rss_kb_total=${rss_total}"
  for rec in "${records[@]}"; do
    read -r pid name pss rss <<<"$rec"
    append "process pid=${pid} name=${name} pss_kb=${pss} rss_kb=${rss}"
  done
}

render_json() {
  local ts kernel arch rec pid name pss rss line first=1 t list=""
  if ! ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || ! kernel="$(uname -r)" || ! arch="$(uname -m)"; then
    err "measurement-failed" "cannot determine timestamp, kernel or arch"
    exit 3
  fi
  kernel="${kernel//[^A-Za-z0-9._+-]/}"
  arch="${arch//[^A-Za-z0-9._-]/}"
  for t in "${sample_totals[@]}"; do
    list+="${list:+, }${t}"
  done
  append "{"
  append "  \"schema_version\": 1,"
  append "  \"behavior\": \"SUP-2\","
  append "  \"task\": \"TASK-158\","
  append "  \"timestamp\": \"${ts}\","
  append "  \"kernel\": \"${kernel}\","
  append "  \"arch\": \"${arch}\","
  append "  \"mode\": \"${mode}\","
  append "  \"exe_name\": \"${exe_name}\","
  append "  \"count\": ${count},"
  append "  \"samples\": ${samples},"
  append "  \"interval_s\": ${interval},"
  append "  \"target_pss_kb\": ${TARGET_PSS_KB},"
  append "  \"total_pss_kb_median\": $(fmt10 "$total_med10"),"
  append "  \"apportioned_pss_kb_median\": $(fmt10 "$appor_med10"),"
  append "  \"per_process_pss_kb_median\": $(fmt10 "$per_proc_med10"),"
  append "  \"rss_kb_total\": ${rss_total},"
  append "  \"sample_totals_pss_kb\": [${list}],"
  append "  \"processes\": ["
  for rec in "${records[@]}"; do
    read -r pid name pss rss <<<"$rec"
    printf -v line '    {"pid": %s, "name": "%s", "pss_kb": %s, "rss_kb": %s}' "$pid" "$name" "$pss" "$rss"
    if [ "$first" -eq 0 ]; then out_buf="${out_buf%$'\n'},"$'\n'; fi
    first=0
    append "$line"
  done
  append "  ]"
  append "}"
}

if [ "$format" = "json" ]; then render_json; else render_text; fi

if [ -n "$output" ]; then
  if ! tmp="$(mktemp "${output}.XXXXXX" 2>/dev/null)"; then
    err "output-failed" "cannot create temporary file next to ${output}"
    exit 2
  fi
  trap 'rm -f "$tmp"' EXIT
  if ! printf '%s' "$out_buf" 2>/dev/null >"$tmp"; then
    err "output-failed" "cannot write temporary file ${tmp}"
    exit 2
  fi
  if ! mv -fT "$tmp" "$output" 2>/dev/null; then
    err "output-failed" "cannot publish output to ${output}"
    exit 2
  fi
  trap - EXIT
else
  if ! printf '%s' "$out_buf" 2>/dev/null; then
    err "output-failed" "cannot write to stdout"
    exit 2
  fi
fi
exit 0
