#!/usr/bin/env bash
# ベンチ結果の絞り込み・照合・マージスクリプト（TASK-189 追補・#1899・REPAIR-8）。
#
# 役割: make bench-check が各ベンチから集めた結果ファイル（<ベンチ名>.json）を 1 個の results.json へまとめ、
# 比較スクリプト（scripts/check-bench-regression.sh）へ渡せる形にする。「baseline.json へ実測基準値が入るまでは
# 比較しない」段階登録ベンチ（scripts/lib.sh の BENCH_STAGED_NAMES）の扱いをここに集約し、
# bench-check.sh にベンチ名の接頭辞を直書きしない（起動 p95 等の追加が一覧への 1 語の追加で済む）。
# 呼び出し元は scripts/targets/bench-check.sh と scripts/check-bench-regression-selftest.sh（cargo なしで
# fixture 照合する）。
#
# 使い方:
#   assemble_results.sh --baseline <baseline.json> --metrics <metrics.json> --staged "<ベンチ名...>" \
#     --output <results.json> <ベンチ名>.json...
#
# 検査と処理:
#   1. baseline.json の全 metric が metrics.json に存在すること（登録済み metric が metrics.json から
#      消えたら入力エラー。すべてのベンチが対象）
#   2. 段階登録ベンチの結果は、baseline 登録済みの metric が「ない」か「全部」であること（部分登録・登録後に
#      追加された metric の未登録は入力エラー。比較対象から metric が静かに外れる経路を作らない）
#   3. 段階登録ベンチの結果は baseline 登録済みの metric だけ残す（未登録の間は比較しない）。段階登録でない
#      ベンチの結果はそのまま通し、未登録 metric は check-bench-regression.sh が入力エラーにする
#   4. 全結果を {schema_version: 1, metrics: ...} へマージして出力（metric 名の重複は入力エラー）
#
# 終了コード: 0 成功 / 2 入力エラー（引数・ファイル・照合の不一致）。
# JSON は jq の --slurpfile・--argjson でのみ渡し、シェル展開しない。

set -euo pipefail

readonly MAX_FILE_BYTES=1048576
readonly MAX_RESULTS_FILES=32

err() {
  echo "error: $1: $2" >&2
}

# 入力ファイルの検査（check-bench-regression.sh と同じ規則: symlink 拒否・通常ファイル・1 MiB 上限）。
check_input_file() {
  local path="$1"
  if [ -L "${path}" ]; then
    err "invalid-input" "${path} is a symlink, refusing to read"
    exit 2
  fi
  if [ ! -e "${path}" ]; then
    err "invalid-input" "${path} does not exist"
    exit 2
  fi
  if [ ! -f "${path}" ]; then
    err "invalid-input" "${path} is not a regular file"
    exit 2
  fi
  local size
  if ! size=$(wc -c <"${path}" 2>/dev/null | tr -d ' '); then
    err "invalid-input" "${path} could not be read"
    exit 2
  fi
  if [ "${size}" -gt "${MAX_FILE_BYTES}" ]; then
    err "invalid-input" "${path} exceeds ${MAX_FILE_BYTES} bytes"
    exit 2
  fi
}

baseline_file=""
metrics_file=""
staged=""
have_staged=0
output_file=""
results_files=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --baseline | --metrics | --staged | --output)
      if [ "$#" -lt 2 ]; then
        err "arg-count" "$1 requires a value"
        exit 2
      fi
      case "$1" in
        --baseline) baseline_file="$2" ;;
        --metrics) metrics_file="$2" ;;
        --staged)
          staged="$2"
          have_staged=1
          ;;
        --output) output_file="$2" ;;
      esac
      shift 2
      ;;
    --*)
      err "arg-unknown" "unknown option $1"
      exit 2
      ;;
    *)
      results_files+=("$1")
      shift
      ;;
  esac
done

if [ -z "${baseline_file}" ] || [ -z "${metrics_file}" ] || [ -z "${output_file}" ] || [ "${have_staged}" -ne 1 ]; then
  err "arg-count" "usage: assemble_results.sh --baseline <f> --metrics <f> --staged \"<names>\" --output <f> <results.json>..."
  exit 2
fi
if [ "${#results_files[@]}" -lt 1 ] || [ "${#results_files[@]}" -gt "${MAX_RESULTS_FILES}" ]; then
  err "arg-count" "expected 1..${MAX_RESULTS_FILES} results files"
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  err "missing-tool" "jq is required"
  exit 2
fi

check_input_file "${baseline_file}"
check_input_file "${metrics_file}"
for f in "${results_files[@]}"; do
  check_input_file "${f}"
done

# 段階登録ベンチ名を検証して JSON 配列にする（外部入力の名前をそのまま jq 本文へ入れない）。
staged_json="[]"
for n in ${staged}; do
  if ! printf '%s' "${n}" | grep -Eq '^[a-z0-9_]{1,64}$'; then
    err "invalid-input" "staged bench name is invalid: ${n}"
    exit 2
  fi
  staged_json="$(jq -c --arg n "${n}" '. + [$n]' <<<"${staged_json}")"
done

# 照合 1: baseline の全 metric が metrics.json にあること。
if ! missing="$(jq -c --slurpfile m "${metrics_file}" \
  '[.metrics | keys[] | select(. as $k | ($m[0].metrics | has($k)) | not)]' "${baseline_file}")"; then
  err "invalid-input" "baseline.json or metrics.json is not valid"
  exit 2
fi
if [ "${missing}" != "[]" ]; then
  err "invalid-input" "registered metric removed from metrics.json: ${missing}; recalibrate per TASK-88"
  exit 2
fi

# 照合 2 と絞り込み: 結果ファイルごとに処理し、一時ファイルを経由せず jq の出力を溜める。
merged="{}"
for f in "${results_files[@]}"; do
  name="$(basename "${f}" .json)"
  is_staged="$(jq -n --arg n "${name}" --argjson s "${staged_json}" '$s | index($n) != null')"
  if [ "${is_staged}" = "true" ]; then
    if ! part="$(jq -c --slurpfile b "${baseline_file}" --arg n "${name}" '
      (.metrics | keys) as $r
      | [$r[] | select(. as $k | $b[0].metrics | has($k))] as $reg
      | if ($reg | length) > 0 and ($reg | length) != ($r | length) then
          error("staged bench \($n): baseline registers \($reg) but results have \($r) (partial registration; recalibrate per TASK-88)")
        else .metrics | with_entries(select(.key as $k | $b[0].metrics | has($k)))
        end' "${f}")"; then
      err "invalid-input" "staged bench ${name} cannot be reconciled with baseline.json"
      exit 2
    fi
  else
    if ! part="$(jq -c '.metrics' "${f}")"; then
      err "invalid-input" "${f} is not valid"
      exit 2
    fi
  fi
  if ! merged="$(jq -c -n --argjson a "${merged}" --argjson p "${part}" '
    if ($p | type) != "object" then error("metrics must be an object")
    elif ([$a | keys[]] - ([$a | keys[]] - [$p | keys[]])) | length > 0 then error("duplicate metric across results files")
    else $a + $p end')"; then
    err "invalid-input" "${f} has a duplicate or malformed metrics object"
    exit 2
  fi
done

jq -n --argjson m "${merged}" '{schema_version: 1, metrics: $m}' >"${output_file}"
