#!/usr/bin/env bash
# ベンチ回帰チェック（TASK-86.3・REPAIR-7 第 4 段階・REPAIR-8）。
#
# 役割: ベンチ実行結果（results.json）を基準値（benches/baseline.json）と比較し、
# 15% 超の悪化を検出したら非ゼロで終了する。REPAIR-7 が定める CI 5 段階ゲートの
# 4 段階目にあたる。呼び出し元は Makefile の `bench-check` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ。
#
# 使い方: check-bench-regression.sh <baseline.json> <results.json>
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 合格（回帰なし。ちょうど 15.0% の悪化は合格として扱う）
#   1: 回帰を検出（いずれかの metric が 15% 超悪化）
#   2: 入力エラー（引数・ファイル・スキーマ不正、jq 未導入等）
#
# 入力スキーマ（fail-closed で検証する。詳細は scripts/testdata/bench-regression/ の
# fixture と scripts/check-bench-regression-selftest.sh を参照）:
#   baseline.json: { schema_version: 1, placeholder?: bool, metrics: {
#     <name>: { value: number(>0, 有限), unit: string,
#               direction: "higher_is_better" | "lower_is_better" } } }
#   results.json:  { schema_version: 1, metrics: {
#     <name>: { value: number(>0, 有限), unit: string } } }
#   baseline にある metric が results に無い、または results にしかない metric が
#   あれば入力エラー（基準値の無いベンチを素通りさせない）。
#
# 閾値は REPAIR-8 の固定値としてこのスクリプト内の定数に置く（baseline.json 側の
# フィールドでは変更できない。ゲートをデータ側から緩める経路を作らないため）。
#
# 判定式（比率 current/baseline で比較する。baseline は is_finite_positive_number
#   により有限かつ 0 超であることを検証済みなので除算は安全に行える。かつては
#   current*100 と baseline*(100±THRESHOLD_PERCENT) を乗算してから比較していたが、
#   baseline・current が極端に大きい有限値（例: 1e307 と 1e308）だと乗算結果が
#   双方とも DBL_MAX 相当へ飽和して等しくなり、実際には閾値超の悪化があっても
#   「回帰なし」と誤判定する不具合があったため、乗算を避け比率で比較する）:
#   lower_is_better:  current/baseline > (100+THRESHOLD_PERCENT)/100 なら回帰
#   higher_is_better: current/baseline < (100-THRESHOLD_PERCENT)/100 なら回帰
#   「15% 超」の悪化を回帰とするため、ちょうど 15.0% の悪化は合格（不等号は
#   `>` / `<` であり `>=` / `<=` ではない）。

set -euo pipefail

# REPAIR-8 が定める固定閾値（%）。baseline.json 側からは上書きできない。
readonly THRESHOLD_PERCENT=15
# jq に渡す前にファイルサイズを制限する（無制限確保による DoS を防ぐ。security.md）。
readonly MAX_FILE_BYTES=1048576
# 検証対象の metric 件数上限（同上の理由）。
readonly MAX_METRICS=256

err() {
  # ERR 系の構造化形式に揃える（code: message）。
  echo "error: $1: $2" >&2
}

if [ "$#" -ne 2 ]; then
  err "arg-count" "usage: check-bench-regression.sh <baseline.json> <results.json>"
  exit 2
fi

baseline_file="$1"
results_file="$2"

if ! command -v jq >/dev/null 2>&1; then
  err "missing-tool" "jq is required but not found in PATH"
  exit 2
fi

check_input_file() {
  local path="$1"
  # symlink 判定は `-f`（symlink をたどって判定する）より先に行う。
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
  # `wc -c` の失敗（読み取り権限なし等）を `set -e` に丸投げしない。丸投げすると
  # パイプライン全体の終了コード（`wc` 由来。多くは 1）がそのままスクリプトの
  # 終了コードになり、呼び出し元が「回帰検出」（exit 1）と誤認する。
  # 契約どおり入力エラーとして exit 2 で終わらせるため、ここで捕捉する。
  if ! size=$(wc -c <"$path" 2>/dev/null | tr -d ' '); then
    err "invalid-input" "$path could not be read"
    exit 2
  fi
  if [ "$size" -gt "$MAX_FILE_BYTES" ]; then
    err "invalid-input" "$path exceeds ${MAX_FILE_BYTES} bytes"
    exit 2
  fi
}

check_input_file "$baseline_file"
check_input_file "$results_file"

# jq 側の検証・比較結果（1 個の JSON オブジェクト）を一時変数へ受け取る。
# jq が非ゼロ終了した場合（スキーマ不正・error() 呼び出し・JSON パース失敗）は
# 入力エラー（exit 2）として扱う。jq のエラーメッセージはそのまま stderr へ出す。
# shellcheck disable=SC2016 # jq プログラム内の $name 等は jq 側の変数参照であり、
# シェル展開させない意図でシングルクォートにしている（--argjson/--slurpfile で渡す）。
jq_program='
def valid_name:
  test("^[a-z0-9_]{1,64}$");

def is_finite_positive_number:
  (type == "number") and (isnan | not) and (isinfinite | not) and (. > 0);

def check_metric_entry($name; require_direction):
  if (.value | type) != "object" then
      error("metric \($name): entry must be an object")
    else . end
  | if (.value.value | is_finite_positive_number | not) then
      error("metric \($name): value must be a finite number greater than 0")
    else . end
  | if (.value.unit | type) != "string" then
      error("metric \($name): unit must be a string")
    else . end
  | if require_direction and
       (.value.direction != "higher_is_better") and
       (.value.direction != "lower_is_better") then
      error("metric \($name): direction must be higher_is_better or lower_is_better")
    else . end
;

def validate_doc(require_direction):
  . as $doc
  | if (type != "object") then error("document must be a JSON object") else . end
  | if ($doc.schema_version != 1) then error("schema_version must be 1") else . end
  | if (($doc.metrics | type) != "object") then error("metrics must be an object") else . end
  | ($doc.metrics | length) as $n
  | if ($n == 0) then error("metrics must not be empty") else . end
  | if ($n > $max_metrics) then error("metrics exceeds \($max_metrics) entries") else . end
  | ($doc.metrics | to_entries) as $entries
  | (reduce $entries[] as $e (0;
      if ($e.key | valid_name | not) then
        error("invalid metric name: \($e.key)")
      else
        ($e | check_metric_entry($e.key; require_direction)) | 0
      end))
  | $doc
;

($bf[0]) as $baseline
| ($rf[0]) as $results
| if ($bf | length) != 1 then error("baseline.json must contain exactly one JSON document") else . end
| if ($rf | length) != 1 then error("results.json must contain exactly one JSON document") else . end
| ($baseline | validate_doc(true)) as $baseline
| ($results | validate_doc(false)) as $results
| ($baseline.metrics | keys) as $base_keys
| ($results.metrics | keys) as $res_keys
| (($base_keys - $res_keys)) as $missing
| (($res_keys - $base_keys)) as $extra
| if ($missing | length) > 0 then
    error("results.json is missing metrics present in baseline: \($missing | join(", "))")
  else . end
| if ($extra | length) > 0 then
    error("results.json has metrics not present in baseline: \($extra | join(", "))")
  else . end
| [ $base_keys[] as $name
    | ($baseline.metrics[$name]) as $b
    | ($results.metrics[$name]) as $r
    | if $b.unit != $r.unit then
        error("metric \($name): unit mismatch between baseline (\($b.unit)) and results (\($r.unit))")
      else . end
    | ($b.value) as $bv
    | ($r.value) as $cv
    | ($b.direction) as $dir
    | (if $dir == "lower_is_better" then
         ($cv / $bv) > ((100 + $threshold) / 100)
       else
         ($cv / $bv) < ((100 - $threshold) / 100)
       end) as $is_regression
    | {
        name: $name,
        baseline: $bv,
        current: $cv,
        unit: $b.unit,
        direction: $dir,
        change_percent: (((($cv - $bv) / $bv) * 10000 | round) / 100),
        status: (if $is_regression then "regression" else "ok" end)
      }
  ] as $rows
| {
    placeholder: ($baseline.placeholder // false),
    rows: $rows,
    regressions: ([ $rows[] | select(.status == "regression") ] | length)
  }
'

if ! output=$(jq -n \
  --argjson threshold "$THRESHOLD_PERCENT" \
  --argjson max_metrics "$MAX_METRICS" \
  --slurpfile bf "$baseline_file" \
  --slurpfile rf "$results_file" \
  "$jq_program" 2>&1); then
  err "invalid-input" "$output"
  exit 2
fi

placeholder=$(printf '%s' "$output" | jq -r '.placeholder')
if [ "$placeholder" = "true" ]; then
  echo "warning: baseline.json is a placeholder (to be replaced with measured values in TASK-88)" >&2
fi

printf '%s\n' "$output" | jq -r '.rows[] | "\(.name) / baseline=\(.baseline)\(.unit) / current=\(.current)\(.unit) / change=\(.change_percent)% / \(.status)"'

regressions=$(printf '%s' "$output" | jq -r '.regressions')
if [ "$regressions" -gt 0 ]; then
  echo "error: regression-detected: ${regressions} metric(s) regressed more than ${THRESHOLD_PERCENT}%" >&2
  exit 1
fi

exit 0
