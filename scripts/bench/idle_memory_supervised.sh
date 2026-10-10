#!/usr/bin/env bash
# 監視プロセス込み構成のアイドル時常駐メモリ回帰テスト（TASK-47・CORE-7・SUP-1・CORE-1・D-19）。
#
# 役割: 「コンテナ 0 個 → 1 個（監視プロセス supervisor 付き）→ 0 個」を操作者が渡す driver で
# 再現し、各時点の常駐メモリ（プロセス数・PSS・RSS）を `idle_memory.sh` で計測する。
# 判定の本体は「コンテナを 0 個へ戻すと fandhe-container 関連の常駐が 0 に戻る」こと
# （常駐デーモンを持たない設計。CORE-1・D-19・SUP-1）で、監視プロセス込みの値（supervised）は
# CORE-7 の Docker 比較（人間担当・#215）の入力データになる。/proc 走査は `idle_memory.sh` に
# 任せ、本スクリプトは再実装しない（識別規則・fail-closed は同スクリプトのヘッダを参照）。
# 呼び出し元は Makefile の `idle-memory-supervised` ターゲット。
#
# フェーズ:
#   1. before     : `idle_memory.sh --format json --expect-zero`（開始時点が 0 でなければ残留を帰属できない）
#   2. up         : `<driver> up`（1 コンテナを監視プロセス込みで起動して復帰する）
#   3. supervised : `idle_memory.sh --format json`（process_count >= 1 かつ `processes` に監視プロセス名
#                   `fandhe-container-supervisor` が含まれなければ、監視プロセス込み構成になっていない
#                   として失敗する。CLI 等の同系名プロセスだけでは合格にしない）
#   4. down       : `<driver> down`（停止・削除。up を試みたら、down の完了を確認できるまで終了時に
#                   必ず呼ぶ。中断・失敗した down は EXIT trap で再試行する）
#   5. after      : `idle_memory.sh --format json --expect-zero`（回帰判定の本体）
#
# 使い方:
#   idle_memory_supervised.sh --driver <abs-path> --expected-dir <dir> [--expected-dir <dir>]... [--timeout <秒>]
#                             [--settle <秒>] [--output <file>] [--help]
#
# driver 契約: 絶対パスの実行可能な通常ファイル。引数は固定の `up` / `down` のみを配列で直接 exec
#   する（シェル経由・文字列連結なし）。`up` は 1 コンテナを監視プロセス込みで起動して復帰し、
#   driver は symlink でなく所有者が実行ユーザーか root・group/other 書き込み不可で、親ディレクトリから / までが
#   symlink なし・所有者が実行ユーザーか root・他者書き込み不可（sticky 除く）であること（root 実行時の差し替え防止。
#   違反は `error: invalid-driver:` で終了コード 2）。
#   TERM / INT / HUP を受けても EXIT trap の `down` を必ず実行し、失敗は `cleanup-failed` で報告する。
#   `down` は停止・削除して復帰する。中断された down の後や、既に停止済みの状態でも再実行できる
#   （冪等）こと。いずれも終了コード 0 で成功を示す。driver の標準出力は破棄し、
#   標準エラーはそのまま流す。driver の絶対パス・引数は結果 JSON に出さない。
#
# 出力 JSON（契約として固定）: schema_version / behavior / task / timestamp / kernel / arch /
#   phases.{before,supervised,after}.{process_count,pss_kb,rss_kb} / driver.{up_exit,down_exit}。
#   期待違反（終了コード 1）・失敗時は標準出力にも --output にも公開しない。
#
# 終了コード（idle_memory.sh の契約を踏襲し、区別は stderr の `error: <code>: <message>` で行う）:
#   0 = 3 フェーズ成功（before・after が 0、supervised が 1 以上）
#   1 = 期待違反（before-not-zero / supervised-zero / after-not-zero）
#   2 = 引数・入力エラー、非 Linux、前提ツール（GNU timeout）欠如、出力先エラー
#   3 = 計測失敗（idle_memory.sh が 3・想定外の値、driver の up / down 失敗・タイムアウト、
#       JSON から値を取り出せない）。down に失敗した場合はコンテナ・監視プロセスが残存している
#       可能性を stderr に明示する（後始末未確定を成功扱いにしない）。EXIT trap の down が失敗した
#       場合も、元の終了コード（1 等）より優先して 3（`error: cleanup-failed:`）で返す
#
# 前提・現状の制約:
#   - Linux 限定。スクリプト内で sudo は呼ばない（実計測は操作者が権限付きシェルで明示実行する。
#     非 root では idle_memory.sh が pid 1 の exe を読めず終了コード 3 になる）。
#   - 製品の実行ファイル（supervisor の入口・本番 ProcessLauncher・CLI バイナリ〔TASK-79〕）は未提供の
#     ため、実 driver は現時点で存在しない（実装済みを装わない。REPAIR-3）。CI で動くのは
#     idle_memory_supervised_selftest.sh（スタブ）だけで、実機での確定値取得・Docker 比較は #215
#     （TASK-47.h1）の担当。実機では `--expected-dir` に配置ディレクトリを必ず渡す。
#   - 「寿命後に supervisor 役プロセスが残らない」ことの Rust 側の保証は
#     crates/supervisor/tests/run.rs（TASK-157.8）にあり、本スクリプトは実プロセスの常駐を見る別層。
#   - 各呼び出しに timeout を掛ける（REPAIR-5）。超過は終了コード 3。
#   - stderr に出す外部由来の文字列は、印字可能な ASCII 以外を `?` に置換する（端末エスケープ注入の防止）。
#   - 計測スクリプトの差し替え（FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE）と OS 名の注入
#     （FANDHE_IDLE_MEMORY_SUPERVISED_UNAME_S）は FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST=1 のときだけ
#     受け付ける（通常利用で計測を偽装できないようにする）。

set -euo pipefail

readonly DEFAULT_TIMEOUT=120
readonly MAX_SETTLE=3600

err() {
  local LC_ALL=C msg
  msg="error: $1: $2"
  msg="${msg//[^[:print:]]/?}"
  printf '%s\n' "$msg" >&2 || true
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
driver=""
output=""
timeout_s="$DEFAULT_TIMEOUT"
settle=0
expected_dirs=()

while [ $# -gt 0 ]; do
  case "$1" in
    --driver)
      [ $# -ge 2 ] || { err "invalid-argument" "--driver requires a value"; exit 2; }
      driver="$2"
      shift 2
      ;;
    --expected-dir)
      [ $# -ge 2 ] || { err "invalid-argument" "--expected-dir requires a value"; exit 2; }
      expected_dirs+=("$2")
      shift 2
      ;;
    --timeout)
      [ $# -ge 2 ] || { err "invalid-argument" "--timeout requires a value"; exit 2; }
      timeout_s="$2"
      shift 2
      ;;
    --settle)
      [ $# -ge 2 ] || { err "invalid-argument" "--settle requires a value"; exit 2; }
      settle="$2"
      shift 2
      ;;
    --output)
      [ $# -ge 2 ] || { err "invalid-argument" "--output requires a value"; exit 2; }
      output="$2"
      shift 2
      ;;
    --help | -h)
      if ! usage 2>/dev/null; then
        err "output-failed" "cannot write usage to stdout"
        exit 2
      fi
      exit 0
      ;;
    *)
      err "invalid-argument" "unknown argument: $1"
      exit 2
      ;;
  esac
done

# 差し替え口は selftest 専用。
measure="${script_dir}/idle_memory.sh"
os_name=""
if [ -n "${FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE:-}" ] || [ -n "${FANDHE_IDLE_MEMORY_SUPERVISED_UNAME_S:-}" ]; then
  if [ "${FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST:-}" != "1" ]; then
    err "invalid-argument" "FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE / _UNAME_S are for selftest only (set FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST=1)"
    exit 2
  fi
  [ -z "${FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE:-}" ] || measure="$FANDHE_IDLE_MEMORY_SUPERVISED_MEASURE"
  os_name="${FANDHE_IDLE_MEMORY_SUPERVISED_UNAME_S:-}"
fi

if [ -z "$os_name" ] && ! os_name="$(uname -s)"; then
  err "unsupported-os" "cannot determine OS name"
  exit 2
fi
if [ "$os_name" != "Linux" ]; then
  err "unsupported-os" "only Linux is supported (got ${os_name})"
  exit 2
fi

if [ -z "$driver" ]; then
  err "invalid-argument" "--driver <absolute-path> is required"
  exit 2
fi
case "$driver" in
  /*) ;;
  *) err "invalid-argument" "--driver must be an absolute path"; exit 2 ;;
esac
if [ ! -f "$driver" ] || [ ! -x "$driver" ]; then
  err "invalid-argument" "--driver is not an executable regular file: ${driver}"
  exit 2
fi
if ! [[ "$timeout_s" =~ ^[1-9][0-9]{0,5}$ ]]; then
  err "invalid-argument" "--timeout must be an integer from 1 to 999999 (seconds)"
  exit 2
fi
if ! [[ "$settle" =~ ^(0|[1-9][0-9]{0,3})$ ]] || [ "$settle" -gt "$MAX_SETTLE" ]; then
  err "invalid-argument" "--settle must be an integer from 0 to ${MAX_SETTLE} (seconds)"
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  err "unsupported-os" "timeout (coreutils) is required"
  exit 2
fi
if [ ! -f "$measure" ]; then
  err "invalid-argument" "measurement script not found"
  exit 2
fi

# 実計測では --expected-dir を必須にする。省略すると idle_memory.sh は実行ファイル名だけで対象を数え、
# 配置ディレクトリ外の同名プロセスを監視プロセスとして数えて supervised フェーズを成功扱いにできる
# （TASK-47・CORE-7）。差し替え口と同じく selftest（FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST=1）のみ省略可。
if [ "${#expected_dirs[@]}" -eq 0 ] && [ "${FANDHE_IDLE_MEMORY_SUPERVISED_SELFTEST:-}" != "1" ]; then
  err "invalid-argument" "--expected-dir is required (pass the directory the supervised binaries are installed in)"
  exit 2
fi

# 引数のディレクトリ 1 つが、他のユーザーに中のエントリを差し替えられないことを確かめる
# （startup_latency.sh の dir_is_safe と同じ規則）。symlink でない実ディレクトリで、所有者が実行
# ユーザーか root で、group / other の書き込み権がないか sticky ビット付きであること。
dir_is_safe() {
  local d="$1" uid
  uid="$(id -u)"
  [ -n "$(find -P "$d" -maxdepth 0 -type d \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) ! -perm -1000 -print 2>/dev/null)" ]
}

# --output の親ディレクトリから / までの全ディレクトリが dir_is_safe で、パスに symlink を含まない
# （論理パスと物理パスが一致する）ことを確かめる。root 実行時に、検査後に他ユーザーが親を差し替えて
# 意図しない場所へ結果を出力させる経路を塞ぐ（startup_latency.sh の output_path_is_safe と同じ規則）。
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

# root で実行される driver が、他ユーザーに差し替えられない場所・実体であることを確かめる。
# driver 自体が symlink でなく、所有者が実行ユーザーか root で、group / other の書き込み権がなく、
# 親ディレクトリから / までが output_path_is_safe の規則（symlink なし・所有者 / 権限の検査）を満たすこと。
# 検査後の差し替え競合は、経路上の全ディレクトリと driver 本体が信頼できる所有者（実行ユーザー・root）
# だけに書き込み可能であることで塞ぐ（それ以外のユーザーは差し替えられない）。
driver_is_safe() {
  local f="$1" uid dir
  uid="$(id -u)" || return 1
  [ ! -L "$f" ] || return 1
  [ -n "$(find -P "$f" -maxdepth 0 -type f \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$f" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) -print 2>/dev/null)" ] || return 1
  dir="${f%/*}"
  [ -n "$dir" ] || dir="/"
  output_path_is_safe "$dir"
}

if ! command -v find >/dev/null 2>&1 || ! command -v id >/dev/null 2>&1; then
  err "unsupported-os" "find and id are required to validate the driver"
  exit 2
fi
if ! driver_is_safe "$driver"; then
  err "invalid-driver" "--driver must not be a symlink, must be owned by you or root and not writable by group/others, and every directory above it must be owned by you or root, not a symlink, and not writable by others (unless sticky)"
  exit 2
fi

if [ -n "$output" ]; then
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
  if ! command -v find >/dev/null 2>&1 || ! command -v id >/dev/null 2>&1; then
    err "unsupported-os" "find and id are required to validate the output directory"
    exit 2
  fi
  if ! output_path_is_safe "$output_dir"; then
    err "invalid-output" "the path of --output must not contain symlinks, and every directory above it must be owned by you or root and not writable by others (unless sticky)"
    exit 2
  fi
fi

up_attempted=0
down_done=0
up_exit=0
down_exit=0
tmp=""

# 終了時の後始末。up を試みて down 未実施なら必ず down を試みる（コンテナを残さない）。
# down の失敗は元の終了コード（1・2・3 のいずれでも）より優先し、終了コード 3
# （stderr の `error: cleanup-failed:`）で返す。後始末の失敗を期待違反などの陰に埋もれさせない
# （AGENTS.md「特権操作の後始末」）。Makefile の外側 timeout はこの down が完走できる猶予を取る。
cleanup() {
  local orig=$? rc=0
  trap ':' TERM INT HUP
  if [ "$up_attempted" -eq 1 ] && [ "$down_done" -eq 0 ]; then
    # 本流の down が中断・失敗した場合もここへ来る（down_done は完了確認後にだけ立てる）。
    timeout --kill-after=10 "$timeout_s" "$driver" down >/dev/null || rc=$?
    if [ "$rc" -ne 0 ]; then
      err "cleanup-failed" "driver down failed (exit ${rc}); the container or supervisor may still be running"
      orig=3
    else
      down_done=1
    fi
  fi
  [ -z "$tmp" ] || rm -f "$tmp"
  exit "$orig"
}
trap cleanup EXIT

# 外側 timeout（Makefile）の TERM や操作者の INT / HUP でも、EXIT trap の後始末（driver down）を
# 必ず通す。実行中の driver 子プロセスを止めてから 128+signal で exit し、cleanup が down を試みる
# （down の失敗は cleanup が `error: cleanup-failed:` として報告し終了コード 3 で返す）。
child_pid=""
on_signal() {
  local code="$1"
  trap ':' TERM INT HUP
  if [ -n "$child_pid" ]; then
    kill -TERM "$child_pid" 2>/dev/null || true
    wait "$child_pid" 2>/dev/null || true
    child_pid=""
  fi
  err "interrupted" "received signal (exit ${code}); running cleanup"
  exit "$code"
}
trap 'on_signal 143' TERM
trap 'on_signal 130' INT
trap 'on_signal 129' HUP

# driver を固定サブコマンドで直接 exec する。戻り値は終了コード（timeout 超過は 124 / 137）。
# 背景起動して wait することで、実行中でも TERM 等の trap が即座に動く。
run_driver() {
  local rc=0
  timeout --kill-after=10 "$timeout_s" "$driver" "$1" >/dev/null &
  child_pid=$!
  wait "$child_pid" || rc=$?
  child_pid=""
  return "$rc"
}

num_re='^(0|[1-9][0-9]{0,12})$'
phase_out=""

# 計測を 1 回実行し、標準出力を phase_out へ入れる。$1 = フェーズ名、$2 = 1 なら --expect-zero を付ける。
# 戻り値は idle_memory.sh（または timeout）の終了コードで、呼び出し側が解釈する（ここでは exit しない）。
measure_phase() {
  local args=(--format json) d rc=0
  [ "$2" -ne 1 ] || args+=(--expect-zero)
  for d in "${expected_dirs[@]+"${expected_dirs[@]}"}"; do
    args+=(--expected-dir "$d")
  done
  phase_out="$(timeout --kill-after=10 "$timeout_s" bash "$measure" "${args[@]}")" || rc=$?
  return "$rc"
}

# 計測の終了コードを本スクリプトの契約へ変換し、失敗なら終了する。
# $1 = フェーズ名、$2 = rc、$3 = 1 のとき rc 1 を期待違反として扱う。
handle_measure_rc() {
  case "$2" in
    0) return 0 ;;
    1)
      if [ "$3" -eq 1 ]; then
        err "${1}-not-zero" "idle_memory.sh reported process_count != 0 in phase ${1}; output not published"
        exit 1
      fi
      err "measurement-failed" "idle_memory.sh exited 1 unexpectedly in phase ${1}"
      exit 3
      ;;
    2) err "invalid-input" "idle_memory.sh rejected its input in phase ${1} (exit 2)"; exit 2 ;;
    124 | 137) err "measurement-failed" "phase ${1} timed out after ${timeout_s}s"; exit 3 ;;
    *) err "measurement-failed" "idle_memory.sh failed in phase ${1} (exit ${2})"; exit 3 ;;
  esac
}

# phase_out（idle_memory.sh の JSON）からトップレベル（2 スペース字下げ）の数値を取り出す。
# jq に依存せず（bash のみで完結する既存方針）、数値正規表現で検証してから使う。
# コマンド置換内の exit は代入の失敗として set -e で伝播し、同じ終了コードで止まる。
json_num() {
  local v
  v="$(printf '%s\n' "$phase_out" | sed -n "s/^  \"$1\": \([0-9]*\),\{0,1\}\$/\1/p" | head -n 1)"
  if ! [[ "$v" =~ $num_re ]]; then
    err "measurement-failed" "cannot extract numeric field $1 from measurement output"
    exit 3
  fi
  printf '%s' "$v"
}

rc=0
measure_phase before 1 || rc=$?
handle_measure_rc before "$rc" 1
b_pc="$(json_num process_count)"
b_pss="$(json_num pss_kb)"
b_rss="$(json_num rss_kb)"
if [ "$b_pc" -ne 0 ]; then
  err "before-not-zero" "process_count=${b_pc} before up (expected 0)"
  exit 1
fi

up_attempted=1
rc=0
run_driver up || rc=$?
up_exit="$rc"
if [ "$rc" -ne 0 ]; then
  err "driver-failed" "driver up failed or timed out (exit ${rc})"
  exit 3
fi

rc=0
measure_phase supervised 0 || rc=$?
handle_measure_rc supervised "$rc" 0
s_pc="$(json_num process_count)"
s_pss="$(json_num pss_kb)"
s_rss="$(json_num rss_kb)"
if [ "$s_pc" -lt 1 ]; then
  err "supervised-zero" "process_count=0 while a container is up; not a supervised configuration"
  exit 1
fi
# process_count >= 1 だけでは CLI 等の同系名プロセスでも通るため、processes に監視プロセス名があることを確かめる。
# printf から grep -q へパイプすると、出力がパイプ容量を超えたとき grep が先に終わった後の書き込みが
# SIGPIPE（141）になり pipefail で誤って失敗するため、ヒアストリングで渡す（#1726）。
if ! grep -Eq '"name": "fandhe-container-supervisor"' <<<"$phase_out"; then
  err "supervised-zero" "no fandhe-container-supervisor process while a container is up; not a supervised configuration"
  exit 1
fi

# down_done は down の完了を確認してからだけ立てる。中断（TERM / INT / HUP）・失敗した down は
# 終了時に cleanup が再試行する（root で起動した container / supervisor を残さない）。
rc=0
run_driver down || rc=$?
down_exit="$rc"
if [ "$rc" -ne 0 ]; then
  err "driver-failed" "driver down failed or timed out (exit ${rc}); the container or supervisor may still be running"
  exit 3
fi
down_done=1

if [ "$settle" -gt 0 ]; then
  sleep "$settle"
fi

rc=0
measure_phase after 1 || rc=$?
handle_measure_rc after "$rc" 1
a_pc="$(json_num process_count)"
a_pss="$(json_num pss_kb)"
a_rss="$(json_num rss_kb)"
if [ "$a_pc" -ne 0 ]; then
  err "after-not-zero" "process_count=${a_pc} after down (expected 0; resident processes remain)"
  exit 1
fi

if ! ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || ! kernel="$(uname -r)" || ! arch="$(uname -m)"; then
  err "measurement-failed" "cannot determine timestamp, kernel or arch"
  exit 3
fi
kernel="${kernel//[^A-Za-z0-9._+-]/}"
arch="${arch//[^A-Za-z0-9._-]/}"

out_buf=""
printf -v out_buf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "behavior": "CORE-7",' \
  '  "task": "TASK-47",' \
  "  \"timestamp\": \"${ts}\"," \
  "  \"kernel\": \"${kernel}\"," \
  "  \"arch\": \"${arch}\"," \
  '  "phases": {' \
  "    \"before\": {\"process_count\": ${b_pc}, \"pss_kb\": ${b_pss}, \"rss_kb\": ${b_rss}}," \
  "    \"supervised\": {\"process_count\": ${s_pc}, \"pss_kb\": ${s_pss}, \"rss_kb\": ${s_rss}}," \
  "    \"after\": {\"process_count\": ${a_pc}, \"pss_kb\": ${a_pss}, \"rss_kb\": ${a_rss}}" \
  '  },' \
  "  \"driver\": {\"up_exit\": ${up_exit}, \"down_exit\": ${down_exit}}" \
  '}'

if [ -n "$output" ]; then
  if ! tmp="$(mktemp "${output}.XXXXXX" 2>/dev/null)"; then
    tmp=""
    err "output-failed" "cannot create temporary file next to ${output}"
    exit 2
  fi
  if ! printf '%s' "$out_buf" 2>/dev/null >"$tmp"; then
    err "output-failed" "cannot write temporary file ${tmp}"
    exit 2
  fi
  if ! mv -fT "$tmp" "$output" 2>/dev/null; then
    err "output-failed" "cannot publish output to ${output}"
    exit 2
  fi
  tmp=""
else
  if ! printf '%s' "$out_buf" 2>/dev/null; then
    err "output-failed" "cannot write to stdout"
    exit 2
  fi
fi
exit 0
