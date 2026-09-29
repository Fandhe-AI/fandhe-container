#!/usr/bin/env bash
# fio ベースライン比算出スクリプト（TASK-25.2・IO-8・MS-1 Phase 2）。
#
# 役割: `scripts/fio-randwrite-4k.sh` が出力した results.json を 2 つ（baseline /
# candidate）受け取り、IOPS・レイテンシの倍率（candidate ÷ baseline）を機械可読な
# JSON で stdout へ出す。呼び出し元は Makefile の `fio-baseline-ratio` /
# `fio-baseline-ratio-selftest` ターゲットと `docs/design/io-fio-bench.md` の
# 「Docker ベースラインの計測手順」節（人間が実機実測の最後に実行する）。
# 本スクリプト自身は fio を実行しない（比較専用。実測は fio-randwrite-4k.sh の役目）。
#
# 前提条件: jq・grep・head・wc・tr・mktemp・sleep・cat・rm（fio-randwrite-4k.sh と同じ前提ツール確認方式。
# 欠如したまま進むと `set -e` によりそのコマンドの終了コード（多くは 127）が
# そのままスクリプトの終了コードになり、別の理由による失敗と誤分類されるため、
# 入力の検証より先に確認する）
#
# 入力の安全性（security.md・fio-randwrite-4k.sh と同方針）:
#   - symlink・通常ファイル以外は拒否する（パストラバーサル・symlink 対策）
#   - 元のパスは 1 回だけ open し、開いた fd が通常ファイルであることを確かめてから
#     `head -c <上限+1>` でコピーし、以後はその内容（変数）だけを使う（検証と変換の
#     間に元のパスを差し替えられても影響しない。TOCTOU 対策）。FIFO 等へ差し替え
#     られても fd 側で拒否し、open・read が止まる場合は 10 秒で打ち切る（REPAIR-5）
#   - サイズ上限は fio-randwrite-4k.sh の MAX_FROM_JSON_BYTES と同じ 4 MiB
#
# 検証（いずれか 1 つでも満たさなければ exit 2。fail-closed）:
#   - JSON として解析できる、かつちょうど 1 個の JSON 値だけを含む（複数の JSON
#     値が連結された入力は、後段の `jq -s` が先頭 2 個〔.[0]/.[1]〕しか使わず
#     意図しない値同士の比率を算出しうるため拒否する）
#   - schema_version == 1 かつ benchmark == "fio_randwrite_4k"
#   - label が ^[a-z0-9_-]{1,64}$（fio-randwrite-4k.sh の --label と同じ制約）
#   - metrics の 5 項目（iops・lat_mean_us・clat_p50/95/99_us）が揃い、value が
#     有限の正数、unit が期待値と一致（0 除算の防止も兼ねる）
#   - baseline と candidate の params が JSON の値として完全一致（キーの存在有無
#     も含めて比較する。片方にキーが無く、もう片方でそのキーが null で存在する
#     場合は不一致として扱う。異なる条件の結果同士を比較しない正当性ゲート。
#     不一致なら差分キーを stderr に出す）
#   - fio_version の不一致・label の一致は拒否せず stderr に警告するだけ
#     （同一条件の繰り返し計測は正当な使い方のため）
#
# 終了コード（呼び出し元はこの具体値で分岐する。fio-randwrite-4k.sh と同じ体系）:
#   0: 成功
#   2: 入力エラー（引数・スキーマ・値域・params 不一致・symlink 等）
#   3: 前提ツール（jq）が無い
#   （1 は使わない。本スクリプトは fio を実行しないため「fio 実行失敗」の区分が無い）
#
# 出力（stdout のみ。ファイルへは書かない。人が読むサマリーは stderr）:
#   {
#     "schema_version": 1,
#     "comparison": "fio_randwrite_4k_baseline_ratio",
#     "baseline":  { "label", "target_kind", "fio_version", "iops" },
#     "candidate": { "label", "target_kind", "fio_version", "iops" },
#     "params": <baseline/candidate で一致した params>,
#     "ratios": {
#       "iops":        { "value": <candidate/baseline>, "direction": "higher_is_better" },
#       "lat_mean_us": { "value": <candidate/baseline>, "direction": "lower_is_better" },
#       "clat_p50_us": { ... }, "clat_p95_us": { ... }, "clat_p99_us": { ... }
#     }
#   }
#   比は jq の浮動小数のまま出す（丸めない。jq 1.6/1.7+ の表現差を数値比較で吸収するため）。

set -euo pipefail

readonly MAX_INPUT_BYTES=4194304 # 4 MiB（fio-randwrite-4k.sh の MAX_FROM_JSON_BYTES と同じ）

err() {
  # ERR 系の構造化形式（code: message）に揃える（coding-rust.md）。
  echo "error: $1: $2" >&2
}

usage() {
  cat >&2 <<'USAGE'
usage:
  fio-baseline-ratio.sh --baseline <results.json> --candidate <results.json>

Both results.json files must be the JSON output of fio-randwrite-4k.sh
(schema_version 1, benchmark "fio_randwrite_4k") measured under identical
params. The IOPS/latency ratio (candidate / baseline) is printed to stdout.
USAGE
}

baseline_path=""
candidate_path=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --baseline)
      [ "$#" -ge 2 ] || { err "arg-error" "--baseline requires a value"; exit 2; }
      baseline_path="$2"
      shift 2
      ;;
    --candidate)
      [ "$#" -ge 2 ] || { err "arg-error" "--candidate requires a value"; exit 2; }
      candidate_path="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "arg-error" "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [ -z "$baseline_path" ] || [ -z "$candidate_path" ]; then
  err "arg-error" "--baseline and --candidate are both required"
  usage
  exit 2
fi

for tool in jq grep head wc tr mktemp sleep cat rm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing-tool" "${tool} is required but not found in PATH"
    exit 3
  fi
done

# 1 回だけ読み込んだ内容を変数に格納し、以後の判定・変換はすべてこの内容に対して
# 行う（検証と使用の間で元のパスが差し替えられても影響しない。TOCTOU 対策）。
# 元のパスは 1 回だけ open し、開いた fd が通常ファイルであることを確かめてから
# `head -c <上限+1>` で一時ファイルへコピーする（読み取り量そのものを上限で頭打ちに
# する。DoS 防止）。事前の `-f` 判定後に FIFO へ差し替えられても fd 側で拒否する。
# open や read が無期限に止まる場合に備え、INPUT_READ_TIMEOUT_SECS で打ち切る
# （sleep と kill の見張り。REPAIR-5。timeout は macOS 標準環境に無いため使わない）。
readonly INPUT_READ_TIMEOUT_SECS=10
read_input() {
  local path="$1"
  local what="$2"
  local content
  local dst
  local reader_pid
  local watchdog_pid
  local rc=0
  local bytes
  if [ -L "$path" ]; then
    err "invalid-input" "${what} is a symlink, refusing to use it: ${path}"
    exit 2
  fi
  if [ ! -e "$path" ]; then
    err "invalid-input" "${what} does not exist: ${path}"
    exit 2
  fi
  if [ ! -f "$path" ]; then
    err "invalid-input" "${what} is not a regular file: ${path}"
    exit 2
  fi
  if ! dst=$(mktemp 2>/dev/null) || [ -z "$dst" ]; then
    err "invalid-input" "could not create a temporary file to copy ${what}"
    exit 2
  fi
  (
    exec 3<"$path" || exit 10
    # /dev/fd/3 の stat は開いた fd 自体を指す（Linux・macOS 共通）
    [ -f /dev/fd/3 ] || exit 11
    exec head -c "$((MAX_INPUT_BYTES + 1))" <&3 >"$dst"
  ) 2>/dev/null &
  reader_pid=$!
  ( sleep "$INPUT_READ_TIMEOUT_SECS" && kill -KILL "$reader_pid" ) >/dev/null 2>&1 &
  watchdog_pid=$!
  wait "$reader_pid" || rc=$?
  # 既に終了した見張りへの kill・wait の失敗で set -e が止まらないよう `|| true` を付ける
  kill "$watchdog_pid" >/dev/null 2>&1 || true
  wait "$watchdog_pid" >/dev/null 2>&1 || true
  case "$rc" in
    0) ;;
    10)
      rm -f -- "$dst"
      err "invalid-input" "${what} could not be opened: ${path}"
      exit 2
      ;;
    11)
      rm -f -- "$dst"
      err "invalid-input" "${what} is not a regular file (it may have been replaced after validation): ${path}"
      exit 2
      ;;
    137)
      rm -f -- "$dst"
      err "invalid-input" "${what} could not be read within ${INPUT_READ_TIMEOUT_SECS}s: ${path}"
      exit 2
      ;;
    *)
      rm -f -- "$dst"
      err "invalid-input" "${what} could not be read (status ${rc}): ${path}"
      exit 2
      ;;
  esac
  # コマンド置換 `$( )` は末尾改行を取り除くため、サイズはコピーしたファイルに対して
  # `wc -c` で測る（改行付き JSON が上限をわずかに超えても素通りさせない）。
  if ! bytes=$(wc -c <"$dst" | tr -d ' ') || ! printf '%s' "$bytes" | grep -Eq '^[0-9]+$'; then
    rm -f -- "$dst"
    err "invalid-input" "${what} could not be read: ${path}"
    exit 2
  fi
  if [ "$bytes" -gt "$MAX_INPUT_BYTES" ]; then
    rm -f -- "$dst"
    err "invalid-input" "${what} exceeds ${MAX_INPUT_BYTES} bytes: ${path}"
    exit 2
  fi
  if ! content=$(cat -- "$dst" 2>/dev/null); then
    rm -f -- "$dst"
    err "invalid-input" "${what} could not be read: ${path}"
    exit 2
  fi
  rm -f -- "$dst"
  printf '%s' "$content"
}

# results.json のスキーマ・値域を検証する jq プログラム。失敗した最初の項目名を
# error() で jq の stderr へ出し、`jq -e` の非ゼロ終了で呼び出し元が検知する。
# shellcheck disable=SC2016 # jq プログラム内の $m 等は jq 側の変数参照であり、シェル展開ではない
readonly validate_jq_program='
def check(cond; msg): if cond then . else error(msg) end;
. as $r
| check(($r.schema_version // null) == 1; "schema_version must be 1")
| check(($r.benchmark // null) == "fio_randwrite_4k"; "benchmark must be \"fio_randwrite_4k\"")
| check((($r.label // null) | type) == "string" and (($r.label) | test("^[a-z0-9_-]{1,64}$")); "label must match ^[a-z0-9_-]{1,64}$")
| check((($r.fio_version // null) | type) == "string"; "fio_version must be a string")
| check((($r.target_kind // null) | type) == "string"; "target_kind must be a string")
| check(($r.params // null | type) == "object"; "params must be an object")
| check(($r.metrics // null | type) == "object"; "metrics must be an object")
| reduce ([
    ["fio_randwrite_4k_iops", "ops/s"],
    ["fio_randwrite_4k_lat_mean_us", "us"],
    ["fio_randwrite_4k_clat_p50_us", "us"],
    ["fio_randwrite_4k_clat_p95_us", "us"],
    ["fio_randwrite_4k_clat_p99_us", "us"]
  ][]) as $m (.;
    ($r.metrics[$m[0]]) as $mv
    | check($mv != null; "metrics.\($m[0]) is missing")
    | check(($mv.value // null | type) == "number"; "metrics.\($m[0]).value must be a number")
    | check(($mv.value | isinfinite | not) and ($mv.value | isnan | not); "metrics.\($m[0]).value must be finite")
    | check($mv.value > 0; "metrics.\($m[0]).value must be greater than 0")
    | check(($mv.unit // null) == $m[1]; "metrics.\($m[0]).unit must be \"\($m[1])\"")
  )
| true
'

validate_content() {
  local content="$1"
  local what="$2"
  local value_count
  local msg
  # `jq -e` が受け付ける入力ストリームは JSON 値が複数個（ホワイトスペース区切りで
  # 連結された JSON）でも順に処理してしまい、後段の `jq -s` は先頭 2 個
  # （.[0]/.[1]）しか使わない。そのため 1 ファイルに複数の fio 結果が連結されて
  # いても検証を通過し、意図しない値同士の比率を算出しうる。`jq -c '.'` は入力
  # ストリーム中の JSON 値ごとに 1 行を出力するため、出力行数で「ちょうど 1 個」
  # であることを確認する（invalid-input・fail-closed）。
  if ! value_count=$(printf '%s' "$content" | jq -c '.' 2>/dev/null | wc -l | tr -d ' '); then
    err "invalid-input" "${what} is not valid JSON"
    exit 2
  fi
  if [ "$value_count" -ne 1 ]; then
    err "invalid-input" "${what} must contain exactly one JSON value (found ${value_count})"
    exit 2
  fi
  if ! msg=$(printf '%s' "$content" | jq -e "$validate_jq_program" 2>&1 >/dev/null); then
    err "invalid-input" "${what} failed schema validation: ${msg}"
    exit 2
  fi
}

baseline_content=$(read_input "$baseline_path" "--baseline")
candidate_content=$(read_input "$candidate_path" "--candidate")
validate_content "$baseline_content" "--baseline (${baseline_path})"
validate_content "$candidate_content" "--candidate (${candidate_path})"

# params の完全一致（正当性ゲート）。不一致キーを stderr へ列挙してから exit 2。
# baseline/candidate の内容は `--argjson`（コマンドライン引数）ではなく stdin 経由で
# jq へ渡す。Linux の 1 引数あたりの上限（MAX_ARG_STRLEN・通常 128 KiB）を、
# 4 MiB まで許す本スクリプトの契約の入力が越えると `Argument list too long` で
# `set -e` により想定外の終了コード（126）になるのを避けるため
# （fio-randwrite-4k.sh の誤分類対策と同種の対策）。
params_diff=$(printf '%s\n%s\n' "$baseline_content" "$candidate_content" | jq -s '
  (.[0].params) as $bp
  | (.[1].params) as $cp
  | ([$bp, $cp] | add | keys_unsorted | unique) as $keys
  | [ $keys[] as $k | select(($bp | has($k)) != ($cp | has($k)) or $bp[$k] != $cp[$k]) | $k ]
')
if [ "$(printf '%s' "$params_diff" | jq 'length')" -gt 0 ]; then
  err "invalid-input" "baseline and candidate params differ: $(printf '%s' "$params_diff" | jq -c '.')"
  exit 2
fi

# fio_version の不一致・label の一致は拒否しない警告のみ（同一条件の繰り返し計測は
# 正当な使い方のため）。
baseline_fio_version=$(printf '%s' "$baseline_content" | jq -r '.fio_version')
candidate_fio_version=$(printf '%s' "$candidate_content" | jq -r '.fio_version')
if [ "$baseline_fio_version" != "$candidate_fio_version" ]; then
  echo "warning: fio_version differs between baseline (${baseline_fio_version}) and candidate (${candidate_fio_version})" >&2
fi

# 分母・分子の値はそれぞれ validate_jq_program で有限の正数と確認済みだが、
# 極端な組み合わせ（非常に大きい値÷非常に小さい値）では倍率自体が IEEE754
# 倍精度の範囲を超えて inf/NaN になり得る。「終了コード 0 で機械可読な倍率を
# 返す」契約が崩れるため、5 種すべての倍率が有限であることを検証する。
# この検証は倍率を算出した同じ jq プロセス内（出力を一旦テキスト化する前）で
# 行う必要がある。jq は出力を JSON テキストへシリアライズする際に無限大を
# 有限の DBL_MAX へ丸めるため、一度 stdout へ出してから改めて `isinfinite` を
# 調べても既に有限の値に化けており検出できない。
if ! result=$(printf '%s\n%s\n' "$baseline_content" "$candidate_content" | jq -s '
  def check_ratio(v; name): if (v | isinfinite or isnan) then error("ratio \(name) is not finite") else v end;
  .[0] as $b | .[1] as $c
  | ($c.metrics.fio_randwrite_4k_iops.value / $b.metrics.fio_randwrite_4k_iops.value) as $iops_ratio
  | ($c.metrics.fio_randwrite_4k_lat_mean_us.value / $b.metrics.fio_randwrite_4k_lat_mean_us.value) as $lat_mean_ratio
  | ($c.metrics.fio_randwrite_4k_clat_p50_us.value / $b.metrics.fio_randwrite_4k_clat_p50_us.value) as $clat_p50_ratio
  | ($c.metrics.fio_randwrite_4k_clat_p95_us.value / $b.metrics.fio_randwrite_4k_clat_p95_us.value) as $clat_p95_ratio
  | ($c.metrics.fio_randwrite_4k_clat_p99_us.value / $b.metrics.fio_randwrite_4k_clat_p99_us.value) as $clat_p99_ratio
  | check_ratio($iops_ratio; "iops")
  | check_ratio($lat_mean_ratio; "lat_mean_us")
  | check_ratio($clat_p50_ratio; "clat_p50_us")
  | check_ratio($clat_p95_ratio; "clat_p95_us")
  | check_ratio($clat_p99_ratio; "clat_p99_us")
  | {
    schema_version: 1,
    comparison: "fio_randwrite_4k_baseline_ratio",
    baseline: {
      label: $b.label, target_kind: $b.target_kind, fio_version: $b.fio_version,
      iops: $b.metrics.fio_randwrite_4k_iops.value
    },
    candidate: {
      label: $c.label, target_kind: $c.target_kind, fio_version: $c.fio_version,
      iops: $c.metrics.fio_randwrite_4k_iops.value
    },
    params: $b.params,
    ratios: {
      iops: { value: $iops_ratio, direction: "higher_is_better" },
      lat_mean_us: { value: $lat_mean_ratio, direction: "lower_is_better" },
      clat_p50_us: { value: $clat_p50_ratio, direction: "lower_is_better" },
      clat_p95_us: { value: $clat_p95_ratio, direction: "lower_is_better" },
      clat_p99_us: { value: $clat_p99_ratio, direction: "lower_is_better" }
    }
  }
' 2>&1); then
  err "invalid-input" "computed ratio is not finite (candidate/baseline values are too extreme): ${result}"
  exit 2
fi

printf '%s\n' "$result"

iops_ratio=$(printf '%s' "$result" | jq -r '.ratios.iops.value')
echo "iops ratio (candidate/baseline): ${iops_ratio}x" >&2
