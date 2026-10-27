#!/usr/bin/env bash
# MAC-3 の小ファイル多数ワークロードの計測（TASK-70 準備・#1880。計測定義は docs/design/mac-small-files-bench.md）。
#
# 役割: macOS で「小ファイルを多数扱うワークロード」を Docker Desktop（VirtioFS）側で計測し、自前側と同じ定義で
# 比べられる JSON にする。MAC-3 の期待は、Docker Desktop を基準に壁時計時間の 15% 以上の短縮、または
# メタデータ操作の p95 の 20% 以上の低減（Should・確定。根拠 PoC-5）。実測と合否判定は人間（TASK-70・#381・#354）。
# 本スクリプトは合否も閾値判定も出さない。
#
# 呼び出し元: Makefile の `mac-small-files-docker`・`mac-small-files-report`
# （scripts/targets/mac-small-files-*.sh 経由。実機前提のため `make ci` には含めない）。自己テストは
# scripts/bench/mac_small_files_selftest.sh。cargo も sudo も呼ばない。Docker Desktop の設定は変更しない。
#
# ワークロード（spec PoC-1・PoC-11 の手順に合わせる。fork を排除するため busybox ash の組み込み echo だけで作る）:
#   mkdir → N 個の小ファイル作成（内容 "x\n"） → `ls | wc -l` で件数確認 → rm -rf。壁時計は `docker run --rm` 全体。
#   メタデータ p95 の取り方は spec に無く、バッチ境界のタイムスタンプによる暫定方式（method に provisional。
#   オーナー確認待ち。docs/design/mac-small-files-bench.md「オーナー確認待ち」）。
#
# 自前側（--mode own）は未実装。実バックエンドの配線（#2232 TASK-115 の W1〜W13）と macOS 既定方式の設計承認（#1906）の
# 後続実装が済むまで測れない（REPAIR-3: 実装済みを装わない）。差し替え点は「バックエンド差し替え点」の関数群だけ。
#
# 使い方:
#   mac_small_files.sh --mode docker --runtime <abs docker CLI> --host-dir <abs dir> [--image REF] [--count N]
#     [--trials N] [--batch N] [--label NAME] [--trial-timeout-secs N] [--timeout-secs N] [--output <abs new file>]
#   mac_small_files.sh --mode own ...                       （未実装。終了コード 5）
#   mac_small_files.sh --mode report --own-result <file> --baseline-result <file> [--output <abs new file>]
#   --count 2000〜50000（既定 2000）・--trials 5〜20（既定 5）・--batch 1〜4096（既定 20。count を割り切れること）。
#   docker モードは bash 5 以上（EPOCHREALTIME）。--host-dir は symlink を含まない実体の絶対パス（bind mount 元）。
#
# 出力 JSON: schema "fandhe-container.mac-small-files/v1"（report は ".../mac-small-files-report/v1"）。
#   絶対パス・ホスト名・ユーザー名は含めない。
#
# 終了コード:
#   0: 成功
#   1: 計測失敗（試行の失敗・期限切れ・件数の不一致・bind の未反映・有効な試行が 5 回未満・結果の検証失敗）
#   2: 入力エラー（副作用の前に検出）
#   3: 前提ツール欠如（jq・mktemp・timeout 相当・bash 5）
#   4: 後始末失敗（ラベル付きのコンテナが残る）
#   5: own 側が未実装

set -euo pipefail
umask 077
export LC_ALL=C

# shellcheck source=../lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

readonly SCHEMA="fandhe-container.mac-small-files/v1"
readonly REPORT_SCHEMA="fandhe-container.mac-small-files-report/v1"
readonly LABEL_KEY="fandhe.mac-small-files.run"
readonly MAX_RESULT_BYTES=1048576
readonly CLEANUP_TIMEOUT_SECS=60
readonly FILE_BYTES=2

usage_error() {
  echo "error: code=bad-input message=$1" >&2
  exit 2
}

mode=""
runtime=""
host_dir=""
image="alpine:3.20"
count=2000
trials=5
batch=20
label=""
trial_timeout=600
total_timeout=7200
output=""
own_result=""
baseline_result=""
seen=" "

while [ $# -gt 0 ]; do
  case "$1" in
    --mode | --runtime | --host-dir | --image | --count | --trials | --batch | --label | --trial-timeout-secs | --timeout-secs | --output | --own-result | --baseline-result)
      [ $# -ge 2 ] || usage_error "missing value for $1"
      case "$seen" in *" $1 "*) usage_error "duplicate argument: $1" ;; esac
      seen="${seen}$1 "
      case "$1" in
        --mode) mode="$2" ;;
        --runtime) runtime="$2" ;;
        --host-dir) host_dir="$2" ;;
        --image) image="$2" ;;
        --count) count="$2" ;;
        --trials) trials="$2" ;;
        --batch) batch="$2" ;;
        --label) label="$2" ;;
        --trial-timeout-secs) trial_timeout="$2" ;;
        --timeout-secs) total_timeout="$2" ;;
        --output) output="$2" ;;
        --own-result) own_result="$2" ;;
        --baseline-result) baseline_result="$2" ;;
      esac
      shift 2
      ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

case "$mode" in docker | own | report) ;; *) usage_error "--mode must be docker, own or report" ;; esac

# 指定されたオプションがモードで使えるかを検査する（使えないものは入力エラー）。
reject_opts() {
  local o
  for o in "$@"; do
    case "$seen" in *" $o "*) usage_error "$o is not valid for --mode $mode" ;; esac
  done
}

for tool in jq mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: code=missing-tool message=required tool not found: $tool" >&2
    exit 3
  }
done

check_int() { # name value min max
  int_in_range "$2" "$3" "$4" || usage_error "$1 must be an integer in $3..$4"
}

validate_output() {
  [ -n "$output" ] || return 0
  case "$output" in /*) ;; *) usage_error "--output must be an absolute path" ;; esac
  if [ -e "$output" ] || [ -L "$output" ]; then
    usage_error "--output already exists (refusing to overwrite)"
  fi
  [ -d "$(dirname "$output")" ] || usage_error "the parent of --output must be an existing directory"
}

# 結果を新規ファイルへ書く（noclobber）。省略時は stdout。
emit_result() { # file
  if [ -n "$output" ]; then
    (set -o noclobber; cat "$1" >"$output") 2>/dev/null || usage_error "cannot create --output"
  else
    cat "$1"
  fi
}

# 後始末の成功後に結果を公開する（stdout または --output の新規ファイル）。
publish_result() {
  if [ -n "$output" ]; then
    (set -o noclobber; printf '%s\n' "$1" >"$output") 2>/dev/null || usage_error "cannot create --output"
  else
    printf '%s\n' "$1"
  fi
}

work=""
RUN_LIMITED_DIR=""
run_tag=""
cleanup_needed=0
trial_dirs_file=""
cleanup_failed=0
run_image=""
# 公開待ちの結果。後始末が成功した後にだけ公開する。
pending_result=""

# ---------------------------------------------------------------------------
# バックエンド差し替え点（docker 側。own 側を実装するときはこの関数群だけを差し替える。
# ワークロードの組み立て workload_script は両側で共通。CLI の差分が出たらここだけを直す）
# ---------------------------------------------------------------------------

# コンテナ内で実行する sh スクリプトを作る（時刻は BusyBox の date が %N 非対応のため /proc/uptime 由来。fork しない read で読む）。検証済みの整数だけから組み立てる（利用者の文字列を入れない）。
# 引数: <count> <batch>。出力は `TS <ns>` 行（バッチ境界）・`FILES_CREATED=<n>`・`DONE`。
workload_script() {
  cat <<EOF
set -e
d=/data/w
mkdir -p "\$d"
cd "\$d"
now_ns() {
  read -r up _ < /proc/uptime
  fr="\${up#*.}"
  echo \$(( \${up%.*} * 100 + 1\${fr} - 100 ))0000000
}
echo "TS \$(now_ns)"
i=0
while [ "\$i" -lt $1 ]; do
  echo x > "f_\$i"
  i=\$((i + 1))
  if [ \$((i % $2)) -eq 0 ]; then echo "TS \$(now_ns)"; fi
done
echo "FILES_CREATED=\$(ls | wc -l)"
cd /data
rm -rf "\$d"
echo DONE
EOF
}

# bind が効いているかの確認用（PoC-11 の verify_bind 相当）。コンテナ内で書いたファイルをホストから読む。
probe_script() {
  echo 'echo probe > /data/probe'
}

# 引数: <log>。イメージ ID を stdout へ出す。事前取得が無ければ失敗（--pull never のため計測中に取得しない）。
backend_image_id() { run_limited "${cap_secs:-$CLEANUP_TIMEOUT_SECS}" "$runtime" image inspect --format '{{.Id}}' "$image" 2>"$1"; }
backend_version() { run_limited "${cap_secs:-$CLEANUP_TIMEOUT_SECS}" "$runtime" version --format '{{.Server.Version}}' 2>/dev/null; }

# 1 試行。引数: <limit秒> <cidfile> <host の作業ディレクトリ> <script> <stdout> <stderr>
backend_run_once() {
  run_limited "$1" "$runtime" run --rm --pull never --cidfile "$2" \
    --label "${LABEL_KEY}=${run_tag}" -v "$3:/data" "${run_image:-$image}" sh -c "$4" >"$5" 2>"$6"
}

# 完全一致のラベルで所有を証明できたコンテナ ID（停止中を含む）を stdout へ出す。--filter name= は部分一致のため使わない。
backend_list_owned() {
  run_limited "$CLEANUP_TIMEOUT_SECS" "$runtime" ps -a -q --no-trunc --filter "label=${LABEL_KEY}=${run_tag}" 2>/dev/null
}

backend_remove() { run_limited "$CLEANUP_TIMEOUT_SECS" "$runtime" rm -f "$1" >/dev/null 2>&1; }

# 所有を証明した ID（cidfile の 64 桁 16 進と、今回のラベルで一覧に出たもの）だけを消し、一覧が空になることを確かめる。
backend_cleanup() {
  local f id ids="" listed rc=0
  for f in "${work}"/cid.*; do
    [ -f "$f" ] || continue
    id=""
    IFS= read -r -n 128 id <"$f" || true
    case "$id" in
      '' | *[!0-9a-f]*) ;;
      *) [ "${#id}" -eq 64 ] && ids="${ids} ${id}" ;;
    esac
  done
  listed="$(backend_list_owned)" || rc=$?
  for id in $listed; do
    case "$id" in '' | *[!0-9a-f]*) continue ;; esac
    [ "${#id}" -eq 64 ] && ids="${ids} ${id}"
  done
  for id in $ids; do
    backend_remove "$id" || true
  done
  rc=0
  listed="$(backend_list_owned)" || rc=$?
  [ "$rc" -eq 0 ] && [ -z "$listed" ]
}

# ---------------------------------------------------------------------------

cleanup() {
  local rc=$?
  trap - EXIT
  run_limited_abort || true
  if [ "$cleanup_needed" -eq 1 ] && [ -n "$run_tag" ] && [ -d "$work" ]; then
    backend_cleanup || cleanup_failed=1
  fi
  # 自分が作った試行ディレクトリだけを消す（trial_dirs_file に記録したもの）。
  if [ -n "$trial_dirs_file" ] && [ -f "$trial_dirs_file" ]; then
    local d
    while IFS= read -r d; do
      case "$d" in
        "${host_dir}"/fandhe-mac-small-files.*) rm -rf "$d" || cleanup_failed=1 ;;
      esac
    done <"$trial_dirs_file"
  fi
  # 後始末の失敗でも set -e で打ち切らず、cleanup-failed（終了コード 4）まで到達させる。
  if [ -n "$work" ]; then rm -rf "$work" || cleanup_failed=1; fi
  if [ "$cleanup_failed" -eq 1 ]; then
    echo "error: code=cleanup-failed message=containers labeled ${LABEL_KEY}=${run_tag} may remain; inspect and remove them manually" >&2
    exit 4
  fi
  if [ "$rc" -eq 0 ] && [ -n "$pending_result" ]; then
    publish_result "$pending_result"
  fi
  exit "$rc"
}

fail_measure() {
  echo "error: code=measurement-failed message=$1" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# report モード
# ---------------------------------------------------------------------------
run_report() {
  reject_opts --runtime --host-dir --image --count --trials --batch --label --trial-timeout-secs --timeout-secs
  [ -n "$own_result" ] || usage_error "--own-result is required"
  [ -n "$baseline_result" ] || usage_error "--baseline-result is required"
  validate_output
  local f size
  [ "$own_result" != "$baseline_result" ] || usage_error "--own-result and --baseline-result must be different files"
  local role
  for role in own docker; do
    if [ "$role" = own ]; then f="$own_result"; else f="$baseline_result"; fi
    case "$f" in /*) ;; *) usage_error "result files must be absolute paths" ;; esac
    [ -f "$f" ] && [ ! -L "$f" ] || usage_error "result files must be regular files"
    size="$(wc -c <"$f" | tr -d ' ')"
    [ "$size" -le "$MAX_RESULT_BYTES" ] || usage_error "result file is too large"
    # 複数の JSON 値を含むファイルを弾くため slurp し、ちょうど 1 要素であることを要求する。
    jq -s -e --arg s "$SCHEMA" --arg want "$role" '
      length == 1 and (.[0]
      | .schema == $s
      and .target == $want
      and (.metrics.wall_clock_median_ms.value | type == "number" and . > 0)
      and (.metrics.metadata_p95_us.value | type == "number" and . > 0)
      and (.metrics.wall_clock_median_ms.method | type == "string" and length > 0)
      and (.metrics.metadata_p95_us.method | type == "string" and length > 0)
      and (.metrics.wall_clock_median_ms.unit | type == "string" and length > 0)
      and (.metrics.metadata_p95_us.unit | type == "string" and length > 0)
      and (.workload | type == "object")
      and (.workload.count | type == "number" and . > 0)
      and (.workload.batch | type == "number" and . > 0)
      and (.workload.file_bytes | type == "number" and . >= 0)
      and (.image | type == "string" and length > 0)
      and (.image_id | type == "string" and test("^sha256:[0-9a-f]{64}$"))
      and (.mount_kind | type == "string" and length > 0)
      and (.label | type == "string")
      and (.trials_ok | type == "number" and . >= 5))
    ' "$f" >/dev/null 2>&1 || usage_error "result file failed validation (single JSON object, schema, target=${role} and required fields)"
  done
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  jq -n --slurpfile o "$own_result" --slurpfile b "$baseline_result" --arg schema "$REPORT_SCHEMA" '
    ($o[0]) as $own | ($b[0]) as $base
    | (($own.workload == $base.workload) and ($own.image == $base.image) and ($own.image_id == $base.image_id) and ($own.mount_kind == $base.mount_kind)) as $same_wl
    | def rate($k): if $same_wl and ($own.metrics[$k].method == $base.metrics[$k].method) and ($own.metrics[$k].unit == $base.metrics[$k].unit)
        then ((1 - ($own.metrics[$k].value / $base.metrics[$k].value)) * 1000000 | round / 1000000) else null end;
    {
      schema: $schema,
      benchmark: "mac-small-files",
      behavior: "MAC-3",
      own: { label: $own.label, metrics: $own.metrics, trials_ok: $own.trials_ok },
      baseline: { label: $base.label, metrics: $base.metrics, trials_ok: $base.trials_ok },
      wall_clock_reduction_ratio: rate("wall_clock_median_ms"),
      metadata_p95_reduction_ratio: rate("metadata_p95_us"),
      methods_differ: ((rate("wall_clock_median_ms") == null) or (rate("metadata_p95_us") == null)),
      note: "ratios are 1 - own/baseline (positive means own is faster); null when workload, image (tag or digest), mount kind, method or unit differ. No pass/fail here: the MAC-3 thresholds (wall clock >= 15% shorter, or metadata p95 >= 20% lower than Docker Desktop VirtioFS) are judged by a human in TASK-70 (#381). The p95 method is provisional (owner confirmation pending)"
    }' >"$tmp" 2>/dev/null || fail_measure "cannot build the report"
  emit_result "$tmp"
  rm -f "$tmp"
  trap - EXIT
}

# ---------------------------------------------------------------------------
# own モード（未実装）
# ---------------------------------------------------------------------------
run_own() {
  # 副作用の前に拒否する。測れるように装わない（REPAIR-3）。
  err_code unimplemented "own backend measurement is not wired yet (see #2232 / #1906)"
  exit 5
}

# ---------------------------------------------------------------------------
# docker モード
# ---------------------------------------------------------------------------

# 1 試行の stdout を検証し、バッチ区間ごとの ns/op（1 操作あたり）を <out> に書く。失敗は理由を stdout へ出し 1 を返す。
parse_trial() { # <stdout file> <intervals out>
  local line prev="" cur n_ts=0 created="" done_seen=0 delta
  : >"$2"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "TS "*)
        cur="${line#TS }"
        case "$cur" in '' | *[!0-9]*) echo "timestamp is not numeric (workload clock output is not a number)"; return 1 ;; esac
        [ "${#cur}" -ge 1 ] && [ "${#cur}" -le 19 ] || { echo "timestamp has an unexpected width"; return 1; }
        if [ -n "$prev" ]; then
          if [ "$cur" -lt "$prev" ]; then echo "timestamps are not monotonic"; return 1; fi
          delta=$(((cur - prev) / batch))
          echo "$delta" >>"$2"
        fi
        prev="$cur"
        n_ts=$((n_ts + 1))
        ;;
      FILES_CREATED=*) created="${line#FILES_CREATED=}"; created="$(printf '%s' "$created" | tr -d ' ')" ;;
      DONE) done_seen=1 ;;
    esac
  done <"$1"
  [ "$done_seen" -eq 1 ] || { echo "workload did not finish"; return 1; }
  [ "$created" = "$count" ] || { echo "file count mismatch (expected ${count}, got ${created:-none})"; return 1; }
  [ "$n_ts" -eq $((count / batch + 1)) ] || { echo "unexpected number of batch timestamps"; return 1; }
  return 0
}

run_docker() {
  reject_opts --own-result --baseline-result
  [ -n "$runtime" ] || usage_error "--runtime is required"
  [ -n "$host_dir" ] || usage_error "--host-dir is required"
  case "$runtime" in /*) ;; *) usage_error "--runtime must be an absolute path" ;; esac
  if [ ! -f "$runtime" ] || [ ! -x "$runtime" ]; then
    usage_error "--runtime must be an executable regular file"
  fi
  case "$host_dir" in /*) ;; *) usage_error "--host-dir must be an absolute path" ;; esac
  case "$host_dir" in *[!A-Za-z0-9_./-]*) usage_error "--host-dir contains characters outside [A-Za-z0-9_./-]" ;; esac
  case "/$host_dir/" in */../* | */./*) usage_error "--host-dir must not contain . or .. components" ;; esac
  while [ "${#host_dir}" -gt 1 ] && [ "${host_dir%/}" != "$host_dir" ]; do host_dir="${host_dir%/}"; done
  [ -d "$host_dir" ] && [ ! -L "$host_dir" ] || usage_error "--host-dir must be an existing directory (not a symlink)"
  [ "$(cd "$host_dir" && pwd -P)" = "$host_dir" ] || usage_error "--host-dir must be a real path without symlink components"
  case "$image" in
    '' | -* | *[!A-Za-z0-9_./:@-]*) usage_error "--image has characters outside [A-Za-z0-9_./:@-] or starts with -" ;;
  esac
  [ "${#image}" -le 200 ] || usage_error "--image is too long"
  check_int --count "$count" 2000 50000
  check_int --trials "$trials" 5 20
  check_int --batch "$batch" 1 4096
  check_int --trial-timeout-secs "$trial_timeout" 1 7200
  check_int --timeout-secs "$total_timeout" 1 86400
  count=$((10#$count)); trials=$((10#$trials)); batch=$((10#$batch))
  trial_timeout=$((10#$trial_timeout)); total_timeout=$((10#$total_timeout))
  [ $((count % batch)) -eq 0 ] || usage_error "--count must be a multiple of --batch"
  if [ -z "$label" ]; then label="docker"; fi
  case "$label" in *[!A-Za-z0-9_.-]* | '') usage_error "--label has characters outside [A-Za-z0-9_.-]" ;; esac
  [ "${#label}" -le 64 ] || usage_error "--label is too long"
  validate_output
  if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
    echo "error: code=missing-tool message=bash 5 or later is required (EPOCHREALTIME)" >&2
    exit 3
  fi

  work="$(mktemp -d)"
  RUN_LIMITED_DIR="$work"
  trial_dirs_file="${work}/trial-dirs"
  : >"$trial_dirs_file"
  run_tag="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  case "$run_tag" in '' | *[!0-9a-f]*) fail_measure "cannot generate a run token" ;; esac
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  cleanup_needed=1
  local started=$SECONDS

  # 事前確認: イメージの事前取得・サーバー版数の記録。
  local image_id backend_ver rc=0
  # 全体期限の残り時間（秒）。呼び出しごとの上限をこれ以下にする。
  remaining_secs() { echo $((total_timeout - (SECONDS - started))); }
  # 引数: <希望の上限秒>。残りが無ければ失敗し、残りが小さければそれに切り詰めた値を $cap_secs へ入れる。
  local cap_secs=0
  cap_for() {
    local want="$1" rem
    rem="$(remaining_secs)"
    [ "$rem" -gt 0 ] || fail_measure "total deadline exceeded"
    cap_secs="$want"
    [ "$rem" -ge "$cap_secs" ] || cap_secs="$rem"
  }
  cap_for "$CLEANUP_TIMEOUT_SECS"
  image_id="$(backend_image_id "${work}/image.err")" || rc=$?
  [ "$rc" -eq 0 ] || fail_measure "image is not available locally (pull it first; --pull never is used)"
  case "$image_id" in sha256:*) ;; *) fail_measure "unexpected image id" ;; esac
  case "${image_id#sha256:}" in *[!0-9a-f]* | '') fail_measure "unexpected image id" ;; esac
  # 計測の各 run は事前確認した ID を起動する（可変タグの差し替えで別イメージを測らない）。タグは表示用に残す。
  run_image="$image_id"
  rc=0
  cap_for "$CLEANUP_TIMEOUT_SECS"
  backend_ver="$(backend_version)" || rc=$?
  [ "$rc" -eq 0 ] || fail_measure "cannot read the docker server version"
  case "$backend_ver" in '' | *[!A-Za-z0-9._+-]*) fail_measure "unexpected docker server version" ;; esac
  [ "${#backend_ver}" -le 64 ] || fail_measure "unexpected docker server version"

  # 1 試行ぶんの作業ディレクトリ（ホスト側。bind mount 元）を作る。引数: <n>。パスは $trial_dir に入れる。
  local trial_dir=""
  new_trial_dir() {
    trial_dir="${host_dir}/fandhe-mac-small-files.${run_tag}.$1"
    mkdir "$trial_dir" 2>/dev/null || fail_measure "cannot create a work directory under --host-dir"
    echo "$trial_dir" >>"$trial_dirs_file"
  }

  # bind が効いていることの確認（コンテナ内の書き込みがホストから見える）。
  new_trial_dir probe
  rc=0
  cap_for "$trial_timeout"
  backend_run_once "$cap_secs" "${work}/cid.probe" "$trial_dir" "$(probe_script)" "${work}/probe.out" "${work}/probe.err" || rc=$?
  [ "$rc" -eq 0 ] || fail_measure "the bind probe run failed (exit ${rc})"
  [ -f "${trial_dir}/probe" ] && [ "$(tr -d '\n' <"${trial_dir}/probe")" = "probe" ] \
    || fail_measure "bind mount is not effective: a file written in the container is not visible on the host"

  local script n=0 ok=0 failed=0 t0 t1 wall_us limit remaining
  script="$(workload_script "$count" "$batch")"
  : >"${work}/samples.jsonl"
  : >"${work}/walls"
  : >"${work}/pooled"
  while [ "$n" -lt "$trials" ]; do
    n=$((n + 1))
    remaining=$((total_timeout - (SECONDS - started)))
    [ "$remaining" -gt 0 ] || fail_measure "total deadline exceeded"
    limit="$trial_timeout"
    [ "$remaining" -ge "$limit" ] || limit="$remaining"
    new_trial_dir "$n"
    t0="${EPOCHREALTIME/./}"
    rc=0
    backend_run_once "$limit" "${work}/cid.${n}" "$trial_dir" "$script" "${work}/out.${n}" "${work}/err.${n}" || rc=$?
    t1="${EPOCHREALTIME/./}"
    wall_us=$((t1 - t0))
    if [ "$rc" -eq 124 ]; then
      fail_measure "trial ${n} exceeded its deadline (${limit}s)"
    fi
    if [ "$rc" -ne 0 ]; then
      echo "warning: trial ${n} failed: docker run exited with ${rc}" >&2
      failed=$((failed + 1))
      continue
    fi
    local why=""
    why="$(parse_trial "${work}/out.${n}" "${work}/int.${n}")" || {
      echo "warning: trial ${n} failed: ${why}" >&2
      rm -f "${work}/int.${n}"
      failed=$((failed + 1))
      continue
    }
    [ "$wall_us" -gt 0 ] || { echo "warning: trial ${n} failed: non-positive wall clock" >&2; rm -f "${work}/int.${n}"; failed=$((failed + 1)); continue; }
    ok=$((ok + 1))
    # p95 の母集団には検証を通った試行の区間だけを足す（失敗試行の区間を混ぜない）。
    cat "${work}/int.${n}" >>"${work}/pooled"
    echo "$wall_us" >>"${work}/walls"
    jq -Rn --argjson t "$n" --argjson w "$wall_us" '
      [inputs | tonumber] | sort
      | { trial: $t, wall_us: $w, intervals: length, interval_ns_per_op_min: .[0],
          interval_ns_per_op_median: .[(length / 2 | floor)], interval_ns_per_op_max: .[-1],
          interval_ns_per_op_p95: .[((length * 0.95 | ceil) - 1)] }' <"${work}/int.${n}" >>"${work}/samples.jsonl"
  done
  # 有効な試行が下限（5）未満なら中央値を歪めるため失敗にする。
  [ "$ok" -ge 5 ] || fail_measure "only ${ok} valid trials (at least 5 required; ${failed} failed)"

  local pooled="${work}/pooled"
  local final="${work}/final.json"
  jq -n --slurpfile samples "${work}/samples.jsonl" \
    --slurpfile pool <(jq -Rn '[inputs | tonumber] | sort | .[((length * 0.95 | ceil) - 1)]' <"$pooled") \
    --slurpfile walls <(jq -Rn '[inputs | tonumber] | sort' <"${work}/walls") \
    --arg schema "$SCHEMA" --arg label "$label" --arg image "$image" --arg image_id "$image_id" --arg ver "$backend_ver" \
    --argjson count "$count" --argjson batch "$batch" --argjson trials "$trials" --argjson ok "$ok" --argjson fb "$FILE_BYTES" '
    ($walls[0]) as $w
    | (if ($w | length) % 2 == 1 then $w[(($w | length) - 1) / 2] else (($w[($w | length) / 2 - 1] + $w[($w | length) / 2]) / 2) end) as $median_us
    | {
        schema: $schema, mode: "docker", target: "docker", label: $label,
        image: $image, image_id: $image_id, mount_kind: "bind", backend_version: $ver,
        workload: { count: $count, file_bytes: $fb, batch: $batch,
                    ops: "mkdir, create N files with shell builtin echo, ls | wc -l, rm -rf" },
        trials_requested: $trials, trials_ok: $ok,
        metrics: {
          wall_clock_median_ms: { value: ($median_us / 1000), unit: "ms", method: "docker-run-rm-total" },
          metadata_p95_us: { value: ($pool[0] / 1000), unit: "us", method: "batch-boundary-provisional" }
        },
        samples: $samples,
        note: "wall clock is the whole `docker run --rm` (VM crossing and container start included, as in PoC-1/PoC-11). metadata_p95_us is PROVISIONAL: the p95 over per-batch average ns/op (pooled across trials), not a per-operation p95; the method is pending owner confirmation. No pass/fail here (TASK-70, #381)."
      }' >"$final" 2>/dev/null || fail_measure "cannot build the result"
  jq -e '.trials_ok >= 5 and (.metrics.wall_clock_median_ms.value > 0) and (.metrics.metadata_p95_us.value >= 0)' "$final" >/dev/null 2>&1 \
    || fail_measure "result failed validation"
  [ "$(wc -c <"$final" | tr -d ' ')" -le "$MAX_RESULT_BYTES" ] || fail_measure "result is too large"
  pending_result="$(cat "$final")"
}

case "$mode" in
  docker) reject_opts --own-result --baseline-result; run_docker ;;
  own) run_own ;;
  report) run_report ;;
esac
