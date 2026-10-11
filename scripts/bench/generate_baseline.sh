#!/usr/bin/env bash
# baseline.json 生成スクリプト（TASK-88.1・REPAIR-8）。
#
# 役割: metric 定義ファイル（benches/metrics.json。direction・unit・placeholder の SSOT）と
# ベンチ実行結果（results.json。1 個以上）をマージし、比較スクリプト
# （scripts/check-bench-regression.sh）の入力スキーマに合う baseline.json を生成する。
# 呼び出し元は Makefile の `bench-baseline` ターゲット（実測は TASK-88.2〔#229〕が行う）。
# 生成物は比較スクリプトへ通す往復検証に合格したものだけを出力先へ置き換える。
#
# 使い方:
#   generate_baseline.sh --metrics <metrics.json> --output <baseline.json> \
#     [--environment <text>] <results.json>...
#
# 終了コード:
#   0: 生成成功（往復検証に合格）
#   1: 往復検証の失敗（出力先は置き換えない）
#   2: 入力エラー（引数・ファイル・スキーマ不正、jq 未導入等）
#
# 環境変数 SOURCE_DATE_EPOCH（数値）があれば generated_at にその時刻を使う（決定的な出力用）。
# ホスト名・ユーザー名・IP は自動収集しない（public リポへの混入防止）。--environment は
# オペレータが渡す一般化した環境説明のみ（256 文字以内）。
# 閾値（15%）はデータ側に持たせず check-bench-regression.sh の定数のままとする。

set -euo pipefail

readonly MAX_FILE_BYTES=1048576
readonly MAX_METRICS=256
readonly MAX_RESULTS_FILES=32
readonly MAX_ENV_CHARS=256

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
check_script="${script_dir}/../check-bench-regression.sh"

err() {
  echo "error: $1: $2" >&2
}

metrics_file=""
output_file=""
environment=""
have_env=0
results_files=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --metrics | --output | --environment)
      if [ "$#" -lt 2 ]; then
        err "arg-count" "$1 requires a value"
        exit 2
      fi
      case "$1" in
        --metrics) metrics_file="$2" ;;
        --output) output_file="$2" ;;
        --environment)
          environment="$2"
          have_env=1
          ;;
      esac
      shift 2
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        results_files+=("$1")
        shift
      done
      ;;
    -*)
      err "arg-unknown" "unknown option: $1"
      exit 2
      ;;
    *)
      results_files+=("$1")
      shift
      ;;
  esac
done

if [ -z "$metrics_file" ] || [ -z "$output_file" ]; then
  err "arg-count" "usage: generate_baseline.sh --metrics <metrics.json> --output <baseline.json> [--environment <text>] <results.json>..."
  exit 2
fi
if [ "${#results_files[@]}" -eq 0 ]; then
  err "arg-count" "at least one results.json is required"
  exit 2
fi
if [ "${#results_files[@]}" -gt "$MAX_RESULTS_FILES" ]; then
  err "arg-count" "too many results files (max ${MAX_RESULTS_FILES})"
  exit 2
fi
if [ "${#environment}" -gt "$MAX_ENV_CHARS" ]; then
  err "invalid-input" "--environment exceeds ${MAX_ENV_CHARS} characters"
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  err "missing-tool" "jq is required but not found in PATH"
  exit 2
fi

epoch=""
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  case "$SOURCE_DATE_EPOCH" in
    *[!0-9]*)
      err "invalid-input" "SOURCE_DATE_EPOCH must be a non-negative integer"
      exit 2
      ;;
    *) epoch="$SOURCE_DATE_EPOCH" ;;
  esac
fi

check_input_file() {
  local path="$1"
  # symlink 判定は `-f` より先に行う（比較スクリプトと同じ規則）。
  if [ -L "$path" ]; then
    err "invalid-input" "$path is a symlink, refusing to read"
    exit 2
  fi
  if [ ! -e "$path" ]; then
    err "invalid-input" "$path does not exist"
    exit 2
  fi
  if [ ! -f "$path" ]; then
    err "invalid-input" "$path is not a regular file"
    exit 2
  fi
  local size
  if ! size=$(wc -c <"$path" 2>/dev/null | tr -d ' '); then
    err "invalid-input" "$path could not be read"
    exit 2
  fi
  if [ "$size" -gt "$MAX_FILE_BYTES" ]; then
    err "invalid-input" "$path exceeds ${MAX_FILE_BYTES} bytes"
    exit 2
  fi
  local docs
  if ! docs=$(jq -s 'length' "$path" 2>/dev/null) || [ "$docs" != "1" ]; then
    err "invalid-input" "$path must contain exactly one valid JSON document"
    exit 2
  fi
}

check_input_file "$metrics_file"
for f in "${results_files[@]}"; do
  check_input_file "$f"
done

# 出力先: symlink・通常ファイル以外の上書きを拒否し、親ディレクトリの存在を確かめる。
if [ -L "$output_file" ]; then
  err "invalid-output" "$output_file is a symlink, refusing to write"
  exit 2
fi
if [ -e "$output_file" ] && [ ! -f "$output_file" ]; then
  err "invalid-output" "$output_file is not a regular file"
  exit 2
fi
out_dir_raw="$(dirname -- "$output_file")"
if [ ! -d "$out_dir_raw" ]; then
  err "invalid-output" "parent directory of $output_file does not exist"
  exit 2
fi
# 親ディレクトリを物理パス（symlink 解決済み）へ固定する。以降の候補作成・置換はこの固定パスだけを
# 基に行い、検証後に親ディレクトリの symlink が差し替えられても書き込み先が変わらないようにする（TOCTOU 対策）。
if ! out_dir="$(CDPATH='' cd -- "$out_dir_raw" >/dev/null && pwd -P)"; then
  err "invalid-output" "cannot resolve parent directory of $output_file"
  exit 2
fi
out_name="$(basename -- "$output_file")"
final_path="${out_dir}/${out_name}"

# 出力先が入力（metrics / results）と同一ファイルなら拒否する。最終の mv が入力を baseline JSON で
# 上書きしてしまうため。`-ef` は同一 inode（相対・絶対パス表記の違い、`..` 経由、ハードリンクを含む）で判定する。
# 入力は check_input_file で symlink を拒否済みのため、物理パスでの同一性と等価。
if [ -e "$final_path" ]; then
  for in_path in "$metrics_file" "${results_files[@]}"; do
    if [ "$in_path" -ef "$final_path" ]; then
      err "invalid-output" "$output_file is the same file as input $in_path, refusing to overwrite"
      exit 2
    fi
  done
fi

# shellcheck disable=SC2016 # $name 等は jq 側の変数参照（シェル展開させない）。
jq_program='
def valid_name: test("^[a-z0-9_]{1,64}$");
def is_finite_positive_number:
  (type == "number") and (isnan | not) and (isinfinite | not) and (. > 0);

([inputs]) as $results
| ($defs[0]) as $d
| if ($d | type) != "object" then error("metrics definition must be a JSON object") else . end
| if $d.schema_version != 1 then error("metrics definition: schema_version must be 1") else . end
| if ($d.placeholder | type) != "boolean" then error("metrics definition: placeholder must be a boolean") else . end
| if ($d.metrics | type) != "object" then error("metrics definition: metrics must be an object") else . end
| if ($d.metrics | length) == 0 then error("metrics definition: metrics must not be empty") else . end
| if ($d.metrics | length) > $max_metrics then error("metrics definition: exceeds \($max_metrics) entries") else . end
| ($d.metrics | to_entries) as $defs_entries
| (reduce $defs_entries[] as $e (0;
    if ($e.key | valid_name | not) then error("invalid metric name: \($e.key)")
    elif ($e.value | type) != "object" then error("metric \($e.key): definition must be an object")
    elif ($e.value.unit | type) != "string" then error("metric \($e.key): unit must be a string")
    elif ($e.value.direction != "higher_is_better" and $e.value.direction != "lower_is_better")
      then error("metric \($e.key): direction must be higher_is_better or lower_is_better")
    else 0 end))
| [ $results[] | . as $r
    | if ($r | type) != "object" then error("results: document must be a JSON object") else . end
    | if $r.schema_version != 1 then error("results: schema_version must be 1") else . end
    | if ($r.metrics | type) != "object" then error("results: metrics must be an object") else . end
    | $r.metrics | to_entries[]
    | if (.key | valid_name | not) then error("invalid metric name: \(.key)")
      elif (.value | type) != "object" then error("metric \(.key): entry must be an object")
      elif (.value.value | is_finite_positive_number | not) then error("metric \(.key): value must be a finite number greater than 0")
      elif (.value.unit | type) != "string" then error("metric \(.key): unit must be a string")
      else . end
  ] as $rows
| ($rows | map(.key)) as $names
| ($names | group_by(.) | map(select(length > 1) | .[0])) as $dups
| if ($dups | length) > 0 then error("duplicate metrics across results files: \($dups | join(", "))") else . end
| ($d.metrics | keys) as $def_keys
| ($def_keys - $names) as $missing
| ($names - $def_keys) as $extra
| if ($missing | length) > 0 then error("results are missing metrics defined in metrics definition: \($missing | join(", "))") else . end
| if ($extra | length) > 0 then error("results have metrics not defined in metrics definition: \($extra | join(", "))") else . end
| ($rows | map({key: .key, value: .value}) | from_entries) as $merged
| (reduce $def_keys[] as $k (0;
    if $merged[$k].unit != $d.metrics[$k].unit then
      error("metric \($k): unit mismatch between definition (\($d.metrics[$k].unit)) and results (\($merged[$k].unit))")
    else 0 end))
| {
    baseline: (
      { schema_version: 1, placeholder: $d.placeholder }
      + (if ($d.note | type) == "string" then {note: $d.note} else {} end)
      + { generated_at: ((if $epoch == "" then now else ($epoch | tonumber) end) | todate) }
      + (if $have_env == 1 then {environment: $env} else {} end)
      + { metrics: ($def_keys | map({key: ., value: {
            value: $merged[.].value,
            unit: $d.metrics[.].unit,
            direction: $d.metrics[.].direction }}) | from_entries) }
    ),
    results: { schema_version: 1,
               metrics: ($def_keys | map({key: ., value: {value: $merged[.].value, unit: $merged[.].unit}}) | from_entries) }
  }
'

tmp_dir="$(mktemp -d)"
cand_tmp=""
cleanup() {
  rm -rf "$tmp_dir"
  if [ -n "$cand_tmp" ]; then
    rm -f "$cand_tmp"
  fi
}
trap cleanup EXIT

# JSON の値はシェルへ展開せず --slurpfile / --arg / --argjson だけで jq に渡す。
if ! merged=$(jq -n \
  --argjson max_metrics "$MAX_METRICS" \
  --arg epoch "$epoch" \
  --argjson have_env "$have_env" \
  --arg env "$environment" \
  --slurpfile defs "$metrics_file" \
  "$jq_program" "${results_files[@]}" 2>&1); then
  err "invalid-input" "$merged"
  exit 2
fi

printf '%s\n' "$merged" | jq '.baseline' >"${tmp_dir}/baseline.json"
printf '%s\n' "$merged" | jq '.results' >"${tmp_dir}/results.json"

# 往復検証: 生成物が比較スクリプトで合格（exit 0）しなければ出力先を置き換えない。
# 比較スクリプトが exit 2 を返す場合も、生成器のスキーマ食い違いの兆候として exit 1 で扱う。
rc=0
bash "$check_script" "${tmp_dir}/baseline.json" "${tmp_dir}/results.json" >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
  err "roundtrip-failed" "generated baseline did not pass check-bench-regression.sh (exit=${rc})"
  exit 1
fi

# 出力先と同じディレクトリの tmp から mv してアトミックに置き換える。
cand_tmp="$(mktemp "${final_path}.XXXXXX")"
cp "${tmp_dir}/baseline.json" "$cand_tmp"
chmod 644 "$cand_tmp"
# 置換直前に出力先の状態を再検証する（検証〜置換の間に symlink / ディレクトリへ差し替えられた場合は拒否）。
# 残る窓は再検証〜mv の数命令分のみで、書き込み先は固定済みの物理ディレクトリ配下に限られる。
if [ -L "$final_path" ] || { [ -e "$final_path" ] && [ ! -f "$final_path" ]; }; then
  err "invalid-output" "$final_path changed to a symlink or non-regular file, refusing to replace"
  exit 2
fi
mv -f -- "$cand_tmp" "$final_path"
cand_tmp=""
echo "generated: ${output_file}"
