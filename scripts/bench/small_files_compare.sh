#!/usr/bin/env bash
# bind / named volume の 2 構成で small_files ハーネスを回し、結果を 1 つの JSON にまとめる薄い入口
# （TASK-24.1・IO-7。ハーネス本体は TASK-189 の benches/benches/small_files.rs。計測定義は
# docs/design/small-files-bench.md）。
#
# 役割: 同一引数で `--config bind` → `--config named-volume` の順にハーネスを起動し（各 5 試行以上）、
# 2 つの結果 JSON を検証して `results.bind` / `results["named-volume"]` に丸ごと残す。ハーネスの
# `method`・`note`・`wire_path`・`io2_guaranteed` は加工しない（REPAIR-3: 実装済みを装わない）。
# 2 構成の意味は「書き込み先（共有ルート）の置き場所の違い」だけで、--bind-root は利用者指定のホストの
# ディレクトリ、--volume-root はランタイム管理のディレクトリに相当する場所を操作者が与える。
# 合否も中央値の比も出さない。IO-7 の 1.5 倍判定と評価レポートは TASK-24.2（#110）の担当。
# 実機での実測は人間（#107）。
#
# 呼び出し元: Makefile の `small-files-compare`（scripts/targets/small-files-compare.sh 経由。実機前提のため
# `make ci` には含めない）。自己テストは scripts/bench/small_files_compare_selftest.sh。cargo も sudo も呼ばない。
#
# 使い方:
#   small_files_compare.sh --harness <abs> --bind-root <abs dir> --volume-root <abs dir>
#     [--count N] [--trials N] [--batch-size N] [--file-size N] [--layout auto|flat|tree]
#     [--trial-timeout-secs N] [--timeout-secs N] [--output <abs new file>]
#   範囲はハーネスの定数（MIN_COUNT=2000・MAX_COUNT=50000・MAX_BATCH_SIZE_ARG=4096・MAX_FILE_SIZE=65536・
#   MAX_TRIALS=20・MAX_TRIAL_TIMEOUT_SECS=7200・MAX_TIMEOUT_SECS=86400）に合わせる（最終判定はハーネス）。
#   --trials は 5〜20（既定 5。受け入れ条件の下限）。環境変数 SMALL_FILES_COMPARE_GRACE_SECS（1〜300・既定 60）は
#   ハーネス自身の --timeout-secs に足す外側の期限の余裕（REPAIR-5。自己テストが短くするために使う）。
#
# 出力 JSON: schema "fandhe-container.small-files-compare/v1"・order・trials_per_config・method・note・results。
#   絶対パス・ホスト名・ユーザー名は含めない。
#
# 終了コード:
#   0: 成功
#   1: 計測失敗（ハーネスの非ゼロ終了・期限切れ・結果の検証失敗・2 構成の不一致）
#   2: 入力エラー（副作用の前に検出）
#   3: 前提ツール欠如（jq・mktemp）

set -euo pipefail
umask 077

# 相対パス入力を lib.sh の cd（リポジトリルートへ移る）より前に拒否するため、絶対パスのみ受ける。
# shellcheck source=../lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

readonly SCHEMA="fandhe-container.small-files-compare/v1"
readonly MAX_RESULT_BYTES=1048576

usage_error() {
  echo "error: code=bad-input message=$1" >&2
  exit 2
}

for tool in jq mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: code=missing-tool message=required tool not found: $tool" >&2
    exit 3
  }
done

harness=""
bind_root=""
volume_root=""
count=2000
trials=5
batch_size=1
file_size=2
layout="auto"
trial_timeout=1800
total_timeout=10800
output=""
seen=" "

# 数値は桁数を制限してから範囲を比較する（int_in_range は lib.sh。先頭ゼロ・符号・非数字を拒否）。
check_int() { # name value min max
  int_in_range "$2" "$3" "$4" || usage_error "$1 must be an integer in $3..$4"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --harness | --bind-root | --volume-root | --count | --trials | --batch-size | --file-size | --layout | --trial-timeout-secs | --timeout-secs | --output)
      [ $# -ge 2 ] || usage_error "missing value for $1"
      case "$seen" in *" $1 "*) usage_error "duplicate argument: $1" ;; esac
      seen="${seen}$1 "
      case "$1" in
        --harness) harness="$2" ;;
        --bind-root) bind_root="$2" ;;
        --volume-root) volume_root="$2" ;;
        --count) count="$2" ;;
        --trials) trials="$2" ;;
        --batch-size) batch_size="$2" ;;
        --file-size) file_size="$2" ;;
        --layout) layout="$2" ;;
        --trial-timeout-secs) trial_timeout="$2" ;;
        --timeout-secs) total_timeout="$2" ;;
        --output) output="$2" ;;
      esac
      shift 2
      ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

check_int --count "$count" 2000 50000
check_int --trials "$trials" 5 20
check_int --batch-size "$batch_size" 1 4096
check_int --file-size "$file_size" 1 65536
check_int --trial-timeout-secs "$trial_timeout" 1 7200
check_int --timeout-secs "$total_timeout" 1 86400
count=$((10#$count))
trials=$((10#$trials))
batch_size=$((10#$batch_size))
file_size=$((10#$file_size))
trial_timeout=$((10#$trial_timeout))
total_timeout=$((10#$total_timeout))
[ "$batch_size" -le "$count" ] || usage_error "--batch-size must not exceed --count"
case "$layout" in auto | flat | tree) ;; *) usage_error "--layout must be auto, flat or tree" ;; esac

grace="${SMALL_FILES_COMPARE_GRACE_SECS:-60}"
check_int SMALL_FILES_COMPARE_GRACE_SECS "$grace" 1 300
grace=$((10#$grace))

[ -n "$harness" ] || usage_error "--harness is required"
case "$harness" in /*) ;; *) usage_error "--harness must be an absolute path" ;; esac
if [ ! -f "$harness" ] || [ ! -x "$harness" ]; then
  usage_error "--harness must be an executable regular file"
fi

# ルートは絶対パス・既存ディレクトリのみ。実体で比較し、同じ場所を 2 構成に使うことを拒否する。
resolve_dir() { # name value -> 実体の絶対パスを stdout へ
  case "$2" in /*) ;; *) usage_error "$1 must be an absolute path" ;; esac
  [ -d "$2" ] || usage_error "$1 must be an existing directory"
  (cd "$2" && pwd -P) || usage_error "$1 is not accessible"
}
[ -n "$bind_root" ] || usage_error "--bind-root is required"
[ -n "$volume_root" ] || usage_error "--volume-root is required"
bind_real="$(resolve_dir --bind-root "$bind_root")"
volume_real="$(resolve_dir --volume-root "$volume_root")"
[ "$bind_real" != "$volume_real" ] || usage_error "--bind-root and --volume-root must be different directories"

if [ -n "$output" ]; then
  case "$output" in /*) ;; *) usage_error "--output must be an absolute path" ;; esac
  if [ -e "$output" ] || [ -L "$output" ]; then
    usage_error "--output already exists (refusing to overwrite)"
  fi
  [ -d "$(dirname "$output")" ] || usage_error "the parent of --output must be an existing directory"
fi

work="$(mktemp -d)"
RUN_LIMITED_DIR="${work}"
cleanup() {
  run_limited_abort
  rm -rf "${work}"
}
trap cleanup EXIT

fail_measure() {
  echo "error: code=measurement-failed message=$1" >&2
  exit 1
}

# 1 構成ぶんを実行して検証する。 引数: <cfg> <root>
run_one() {
  local cfg="$1" root="$2" rc=0 res="${work}/${1}.json"
  run_limited $((total_timeout + grace)) "$harness" \
    --count "$count" --batch-size "$batch_size" --file-size "$file_size" --layout "$layout" \
    --config "$cfg" --trials "$trials" --trial-timeout-secs "$trial_timeout" \
    --timeout-secs "$total_timeout" --root "$root" --output "$res" >"${work}/${cfg}.stdout" || rc=$?
  if [ "$rc" -eq 124 ]; then fail_measure "$cfg: harness exceeded its deadline"; fi
  if [ "$rc" -ne 0 ]; then fail_measure "$cfg: harness exited with status $rc"; fi
  [ -f "$res" ] || fail_measure "$cfg: harness wrote no result file"
  local size
  size="$(wc -c <"$res" | tr -d ' ')"
  if [ "$size" -gt "$MAX_RESULT_BYTES" ]; then fail_measure "$cfg: result file is too large"; fi
  # 結果の layout は解決済みの値（auto は count 2000 以下で flat、超えると tree。ハーネスの AUTO_FLAT_MAX）。
  local want_layout="$layout"
  if [ "$layout" = auto ]; then
    if [ "$count" -le 2000 ]; then want_layout=flat; else want_layout=tree; fi
  fi
  # method と io2_guaranteed の整合・wire_path false・単位・config・引数・試行の中身を照合する（fail-closed）。
  jq -e --arg cfg "$cfg" --argjson count "$count" --argjson bs "$batch_size" \
    --argjson fs "$file_size" --argjson trials "$trials" --arg layout "$want_layout" \
    --argjson tt "$trial_timeout" --argjson total "$total_timeout" '
    def posint: type == "number" and . > 0 and . == floor;
    .schema_version == 1
    and (.metrics.small_files_files_per_sec.unit == "files/s")
    and (.metrics.small_files_files_per_sec.value | type == "number" and . > 0)
    and (if $bs == 1
      then (.method == "server-api-direct/flush-per-file" and .io2_guaranteed == true)
      else (.method == "server-api-direct/flush-every-k" and .io2_guaranteed == false) end)
    and .wire_path == false
    and .aggregate == "median"
    and .params.config == $cfg
    and .params.count == $count and .params.batch_size == $bs
    and .params.file_size_bytes == $fs and .params.trials == $trials
    and .params.layout == $layout
    and .params.trial_timeout_secs == $tt and .params.timeout_secs == $total
    and (.trials | length) == $trials
    and all(.trials[]; (.elapsed_ns | posint) and (.files_per_sec | type == "number" and . > 0))
  ' "$res" >/dev/null 2>&1 || fail_measure "$cfg: harness result failed validation"
}

run_one bind "$bind_real"
run_one named-volume "$volume_real"

final="${work}/final.json"
jq -n --slurpfile b "${work}/bind.json" --slurpfile n "${work}/named-volume.json" \
  --arg schema "$SCHEMA" --argjson trials "$trials" '
  ($b[0]) as $bind | ($n[0]) as $nv
  | if ($bind.method != $nv.method) or (($bind.params | del(.config)) != ($nv.params | del(.config)))
    then error("configs differ")
    else {
      schema: $schema,
      benchmark: "small_files_compare",
      behavior: "IO-7",
      order: ["bind", "named-volume"],
      trials_per_config: $trials,
      method: $bind.method,
      note: "no pass/fail and no ratio here; the IO-7 median ratio (bind <= 1.5x named volume) is evaluated in TASK-24.2 (#110). Each result is the small_files harness output as is (see its method/note); the two configs differ only in the --root location, and the wire path is not measured",
      results: { "bind": $bind, "named-volume": $nv }
    } end' >"$final" 2>/dev/null || fail_measure "the two configs ran different workloads"

if [ -n "$output" ]; then
  # 既存ファイルは上書きしない（noclobber）。検査後に作られた場合も失敗にする。
  (set -o noclobber; cat "$final" >"$output") 2>/dev/null || usage_error "cannot create --output"
else
  cat "$final"
fi
