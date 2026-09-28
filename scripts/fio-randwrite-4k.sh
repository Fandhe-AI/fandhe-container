#!/usr/bin/env bash
# fio 4K ランダム write ベンチスクリプト（TASK-25.1・IO-8・MS-1 Phase 2）。
#
# 役割: DB 書き込み相当の 4K ランダム write ワークロードを fio で実行（run モード）、
# または既存の fio JSON 出力を変換するだけ（--from-json モード）で、IOPS・レイテンシを
# scripts/check-bench-regression.sh が読める results.json 互換の機械可読形式へ変換する。
# 呼び出し元は Makefile の `fio-bench` / `fio-bench-selftest` ターゲットと、
# `scripts/fio-randwrite-4k-selftest.sh`（本体の自己テスト）。
#
# 現状の制約（REPAIR-3: 実装済みを装わない）: fandhe-container の I/O 共有プロトコル
# 経由の共有マウントはまだ公開されていない（TASK-13.2.2 以降）。このスクリプトは
# 書き込み先を `--target-dir` で受け取る汎用の形にし、`--label` で計測対象
# （Docker のベースラインか、将来の fandhe 経路か）を出力に記録する契約とする。
# fandhe 経路の実測は、共有マウントを公開する後続 TASK を待つ（IO-8）。
#
# 前提条件:
#   - run モード: fio 3.x 以上（`*_ns` キーを出力する版。fio の JSON 出力レイアウト
#     （top-level `"fio version"`・`jobs[].write.{iops,lat_ns,clat_ns}`・percentile を
#     `%f` 形式の文字列キーで持つこと）は fio 本体（axboe/fio）の `stat.c`（JSON 出力を
#     組み立てる `add_ddir_lat_json`/`json_object_add_value_string(root, "fio version", ...)`
#     周辺）を直接参照して確認した。fio 2.x 系は `lat`/`clat`（usec 単位、`_ns` サフィックス
#     なし）を使うため、`_ns` キーの有無で fio 3.x 以降かどうかを判定する（`_ns` への正確な
#     移行版数までは未確認。この環境には fio が無く、実際の fio 出力での照合は未実施）、
#     GNU coreutils の `timeout`（Linux ホストが対象。macOS 標準環境には無い）、`jq`
#   - --from-json モード: `jq` のみ（fio 不要）
#   - root 権限・`/dev/kvm` は不要
#   - 全モード共通で `grep`・`dirname`・`wc`・`tr`・`mktemp`、run モードでは加えて
#     `realpath`・`find`（いずれも前提ツール検証の対象。欠如は exit 3）
#
# 書き込み先の安全性（security.md の symlink・ボリューム外書き込み対策）:
#   fio のデータファイルは `--target-dir` 直下の固定パスではなく、実行ごとに
#   `mktemp -d` で `--target-dir` 内へ新規作成する専用サブディレクトリ（0700）の中に
#   作る。事前に置かれた symlink を fio（O_CREAT・O_EXCL なしで open し symlink を
#   たどる）に踏ませないための構造的対策で、後始末もそのサブディレクトリを
#   `rm -rf` で消すだけにする（symlink をたどらない）。
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: fio の実行失敗またはタイムアウト
#   2: 入力エラー（引数の検証失敗、fio JSON のスキーマ不正、値が 0 以下、
#      ファイルサイズ超過、symlink 等）
#   3: 前提ツールが無い（run モードでの fio・timeout・realpath・find。全モード共通で
#      jq・grep・dirname・wc・tr・mktemp）
#
# 出力（stdout。`--output <path>` を指定した場合はファイルにも書く。人が読む進捗・
# サマリーは stderr に出す）:
#   {
#     "schema_version": 1,
#     "benchmark": "fio_randwrite_4k",
#     "label": "<--label の値>",
#     "fio_version": "<fio が報告した version 文字列>",
#     "target_kind": "run" | "from_json",
#     "params": { rw, bs, ioengine, direct, size, runtime, iodepth, numjobs,
#                 end_fsync, group_reporting, filename },
#     "metrics": {
#       "fio_randwrite_4k_iops": { "value": <number>, "unit": "ops/s" },
#       "fio_randwrite_4k_lat_mean_us": { "value": <number>, "unit": "us" },
#       "fio_randwrite_4k_clat_p50_us": { "value": <number>, "unit": "us" },
#       "fio_randwrite_4k_clat_p95_us": { "value": <number>, "unit": "us" },
#       "fio_randwrite_4k_clat_p99_us": { "value": <number>, "unit": "us" }
#     }
#   }
# `metrics` の形は scripts/check-bench-regression.sh の results.json スキーマと
# 互換（schema_version・metrics.<name>.{value,unit}）で、そのまま回帰比較にかけられる。

set -euo pipefail

# --------------------------------------------------
# 定数（DoS 防止・REPAIR-5 のタイムアウト方針。security.md）
# --------------------------------------------------
readonly FIXED_FILENAME="fandhe-fio-randwrite-4k.dat"
readonly MAX_FROM_JSON_BYTES=4194304 # 4 MiB
readonly MAX_SIZE_BYTES=$((10 * 1024 * 1024 * 1024)) # 10 GiB（--size の上限）
readonly MIN_RUNTIME=1
readonly MAX_RUNTIME=600
readonly MIN_IODEPTH=1
readonly MAX_IODEPTH=64
readonly MIN_NUMJOBS=1
readonly MAX_NUMJOBS=16
readonly TIMEOUT_MARGIN_SECS=60 # fio の起動・終了処理のオーバーヘッド分の余裕
# timeout が SIGTERM を送っても fio が終わらない（共有 FS 上の fsync 待ち等で
# SIGTERM を無視する）場合に SIGKILL へ切り替えるまでの猶予（REPAIR-5: 確実に終わらせる）
readonly TIMEOUT_KILL_AFTER_SECS=10

err() {
  # ERR 系の構造化形式（code: message）に揃える（coding-rust.md）。
  echo "error: $1: $2" >&2
}

usage() {
  cat >&2 <<'USAGE'
usage:
  fio-randwrite-4k.sh --target-dir <dir> --label <label> [options]
  fio-randwrite-4k.sh --from-json <fio-output.json> --label <label> [options]

common options:
  --output <path>     also write the result JSON to this path (must not exist;
                       parent directory must already exist and be writable)
  -h, --help          show this help

run-mode-only options:
  --direct 0|1        O_DIRECT flag (default: 1)
  --size <NkNmNg>      fio --size (default: 256m, capped at 10 GiB)
  --runtime <1-600>    fio --runtime in seconds (default: 30)
  --iodepth <1-64>     fio --iodepth (default: 1)
  --numjobs <1-16>     fio --numjobs (default: 1)
USAGE
}

# --------------------------------------------------
# 引数解析（ファイルシステム・外部コマンドには触れない純粋なパース）
# --------------------------------------------------
mode="run"
target_dir=""
from_json=""
label=""
output_path=""
direct="1"
size="256m"
runtime="30"
iodepth="1"
numjobs="1"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target-dir)
      [ "$#" -ge 2 ] || { err "arg-error" "--target-dir requires a value"; exit 2; }
      target_dir="$2"
      shift 2
      ;;
    --from-json)
      [ "$#" -ge 2 ] || { err "arg-error" "--from-json requires a value"; exit 2; }
      from_json="$2"
      mode="from-json"
      shift 2
      ;;
    --label)
      [ "$#" -ge 2 ] || { err "arg-error" "--label requires a value"; exit 2; }
      label="$2"
      shift 2
      ;;
    --output)
      [ "$#" -ge 2 ] || { err "arg-error" "--output requires a value"; exit 2; }
      output_path="$2"
      shift 2
      ;;
    --direct)
      [ "$#" -ge 2 ] || { err "arg-error" "--direct requires a value"; exit 2; }
      direct="$2"
      shift 2
      ;;
    --size)
      [ "$#" -ge 2 ] || { err "arg-error" "--size requires a value"; exit 2; }
      size="$2"
      shift 2
      ;;
    --runtime)
      [ "$#" -ge 2 ] || { err "arg-error" "--runtime requires a value"; exit 2; }
      runtime="$2"
      shift 2
      ;;
    --iodepth)
      [ "$#" -ge 2 ] || { err "arg-error" "--iodepth requires a value"; exit 2; }
      iodepth="$2"
      shift 2
      ;;
    --numjobs)
      [ "$#" -ge 2 ] || { err "arg-error" "--numjobs requires a value"; exit 2; }
      numjobs="$2"
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

if [ -z "$label" ]; then
  err "arg-error" "--label is required"
  exit 2
fi

# --------------------------------------------------
# 前提ツールの確認（外部入力の検証より先に行う。REPAIR-5 のタイムアウト方針にも
# `timeout` コマンド自体が要る。ツール欠如とその他の入力エラーを終了コードで
# 区別できるよう、ファイルシステム検証より先に済ませる）
# --------------------------------------------------
# jq 以外の coreutils 系も確認する。欠如したまま進むと `set -e` でそのコマンドの
# 終了コード（多くは 1 か 127）がスクリプトの終了コードになり、「fio 実行失敗」
# （exit 1）と誤分類される（c2458d5 で直した誤分類と同種の穴）。
for tool in jq grep dirname wc tr mktemp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "missing-tool" "${tool} is required but not found in PATH"
    exit 3
  fi
done
if [ "$mode" = "run" ]; then
  if ! command -v fio >/dev/null 2>&1; then
    err "missing-tool" "fio is required but not found in PATH (run mode)"
    exit 3
  fi
  if ! command -v timeout >/dev/null 2>&1; then
    err "missing-tool" "GNU coreutils 'timeout' is required but not found in PATH (run mode, Linux host only)"
    exit 3
  fi
  for tool in realpath find; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      err "missing-tool" "${tool} is required but not found in PATH (run mode)"
      exit 3
    fi
  done
fi

# --------------------------------------------------
# 引数の値検証（許可リスト方式。数値はすべて正規表現と範囲で検証してから fio へ渡す）
# --------------------------------------------------
if ! printf '%s' "$label" | grep -Eq '^[a-z0-9_-]{1,64}$'; then
  err "invalid-input" "--label must match ^[a-z0-9_-]{1,64}\$: $label"
  exit 2
fi

if ! printf '%s' "$direct" | grep -Eq '^[01]$'; then
  err "invalid-input" "--direct must be 0 or 1: $direct"
  exit 2
fi

# 数値系は先頭ゼロを拒否する（`^[1-9][0-9]*$` 系の正規表現）。先頭ゼロを許すと
# 後段の bash 算術評価 `$((...))` が 8 進数として解釈し（例: `08` は
# 「value too great for base」でエラー）、`set -e` により fio 失敗（exit 1）と
# 誤認する、または `--argjson` への非数値 JSON エラーになるため、入力エラー
# （exit 2）として弾ける形の正規表現にしている。
if ! printf '%s' "$runtime" | grep -Eq '^[1-9][0-9]{0,3}$' || \
   [ "$runtime" -lt "$MIN_RUNTIME" ] || [ "$runtime" -gt "$MAX_RUNTIME" ]; then
  err "invalid-input" "--runtime must be an integer in [${MIN_RUNTIME}, ${MAX_RUNTIME}] with no leading zero: $runtime"
  exit 2
fi

if ! printf '%s' "$iodepth" | grep -Eq '^[1-9][0-9]{0,2}$' || \
   [ "$iodepth" -lt "$MIN_IODEPTH" ] || [ "$iodepth" -gt "$MAX_IODEPTH" ]; then
  err "invalid-input" "--iodepth must be an integer in [${MIN_IODEPTH}, ${MAX_IODEPTH}] with no leading zero: $iodepth"
  exit 2
fi

if ! printf '%s' "$numjobs" | grep -Eq '^[1-9][0-9]{0,2}$' || \
   [ "$numjobs" -lt "$MIN_NUMJOBS" ] || [ "$numjobs" -gt "$MAX_NUMJOBS" ]; then
  err "invalid-input" "--numjobs must be an integer in [${MIN_NUMJOBS}, ${MAX_NUMJOBS}] with no leading zero: $numjobs"
  exit 2
fi

if ! printf '%s' "$size" | grep -Eq '^[1-9][0-9]{0,5}[kmg]$'; then
  err "invalid-input" "--size must match ^[1-9][0-9]{0,5}[kmg]\$ (no leading zero): $size"
  exit 2
fi
size_num="${size%[kmg]}"
size_unit="${size: -1}"
case "$size_unit" in
  k) size_mult=1024 ;;
  m) size_mult=$((1024 * 1024)) ;;
  g) size_mult=$((1024 * 1024 * 1024)) ;;
esac
size_bytes=$((size_num * size_mult))
if [ "$size_bytes" -gt "$MAX_SIZE_BYTES" ]; then
  err "invalid-input" "--size exceeds the ${MAX_SIZE_BYTES}-byte cap: $size"
  exit 2
fi

# 結果 JSON を --output へ書く。事前の `-L`/`-e` 検証から書き込みまでの間に
# symlink・ファイルを置かれても踏まないよう、noclobber（bash は対象が無ければ
# O_CREAT|O_EXCL で開くため、dangling を含む symlink・既存ファイルでは失敗する）の
# サブシェルで書く。失敗は入力エラー（exit 2）として扱う（set -e に任せると
# exit 1「fio 実行失敗」と誤分類されるため）。
# 残る制約: bash の noclobber は、既存の「通常ファイル以外」（FIFO・デバイス等。
# それを指す symlink を含む）には O_CREAT なしで開いて書き込む仕様のため、検証後の
# 競合でそれらを指す symlink を置かれた場合は防げない（通常ファイル・dangling
# symlink・存在しないパスの上書きは防げる）。
write_output_file() {
  local content="$1"
  if ! (set -o noclobber; printf '%s\n' "$content" >"$output_path") 2>/dev/null; then
    err "invalid-input" "--output path could not be created exclusively (appeared after validation or is not writable): $output_path"
    exit 2
  fi
}

check_symlink_reject() {
  # symlink をたどって存在判定する `-e`/`-f` より先に symlink 判定する
  # （check-bench-regression.sh の check_input_file と同方針。security.md の
  # パストラバーサル・symlink 対策）。
  local path="$1"
  if [ -L "$path" ]; then
    err "invalid-input" "$path is a symlink, refusing to use it"
    exit 2
  fi
}

if [ -n "$output_path" ]; then
  check_symlink_reject "$output_path"
  if [ -e "$output_path" ]; then
    err "invalid-input" "--output path already exists, refusing to overwrite: $output_path"
    exit 2
  fi
  # 親ディレクトリの存在・書き込み可否をここで検証する。検証せずに後段の
  # `printf ... >"$output_path"` に任せると、`set -e` 下でその書き込み失敗が
  # そのままスクリプトを終了させ、fio 実行失敗（exit 1）または fio-3-legacy 等の
  # 別要因と誤分類される（呼び出し元が exit 1 を見て「fio 自体が失敗した」と
  # 誤認し、実際には計測・変換自体は成功していたケースを再計測ループに入れる、
  # または exit 2 を期待する検証コードを素通りさせる）。入力エラー（exit 2）として
  # fail-closed に倒す（docs/design/io-fio-bench.md の終了コード契約と整合）。
  output_dir=$(dirname -- "$output_path")
  if [ ! -d "$output_dir" ]; then
    err "invalid-input" "--output parent directory does not exist: $output_dir"
    exit 2
  fi
  if [ ! -w "$output_dir" ]; then
    err "invalid-input" "--output parent directory is not writable: $output_dir"
    exit 2
  fi
fi

# --------------------------------------------------
# fio JSON → metrics 変換（run / --from-json 共通）。jq プログラム 1 本にまとめ、
# シェル値は --arg / --argjson でのみ渡す（インジェクション対策。security.md）。
# --------------------------------------------------
# shellcheck disable=SC2016 # jq プログラム内の $name 等は jq 側の変数参照であり、
# シェル展開させない意図でシングルクォートにしている（--arg/--argjson で渡す）。
convert_jq_program='
def is_finite_positive_number:
  (type == "number") and (isnan | not) and (isinfinite | not) and (. > 0);

($ff[0]) as $doc
| if ($ff | length) != 1 then error("fio output must contain exactly one JSON document") else . end
| if (($doc | type) != "object") then error("fio output must be a JSON object") else . end
| ($doc["fio version"]) as $fv
| if (($fv | type) != "string") then error("missing or invalid \"fio version\" field") else . end
| if ($fv | test("^fio-[0-9]+\\.") | not) then
    error("cannot parse fio version string: \($fv)")
  else . end
| ($fv | capture("^fio-(?<major>[0-9]+)\\.").major | tonumber) as $major
| if ($major < 3) then
    error("unsupported fio version \($fv): fio 3.x or later is required (lat_ns/clat_ns output keys)")
  else . end
| if (($doc.jobs | type) != "array") or (($doc.jobs | length) < 1) then
    error("fio output must contain a non-empty \"jobs\" array")
  else . end
| ($doc.jobs[0].write) as $w
| if (($w | type) != "object") then error("jobs[0].write is missing or not an object") else . end
| if (($w.lat_ns | type) != "object") then
    error("jobs[0].write.lat_ns is missing (fio 2.x \"lat\" output is not supported)")
  else . end
| if (($w.clat_ns | type) != "object") then
    error("jobs[0].write.clat_ns is missing (fio 2.x \"clat\" output is not supported)")
  else . end
| if ($w.iops | is_finite_positive_number | not) then
    error("jobs[0].write.iops must be a finite number greater than 0")
  else . end
| if ($w.lat_ns.mean | is_finite_positive_number | not) then
    error("jobs[0].write.lat_ns.mean must be a finite number greater than 0")
  else . end
| ($w.clat_ns.percentile) as $pct
| if (($pct | type) != "object") then
    error("jobs[0].write.clat_ns.percentile is missing or not an object")
  else . end
| if (($pct["50.000000"] | is_finite_positive_number | not)) then
    error("jobs[0].write.clat_ns.percentile[\"50.000000\"] must be a finite number greater than 0")
  else . end
| if (($pct["95.000000"] | is_finite_positive_number | not)) then
    error("jobs[0].write.clat_ns.percentile[\"95.000000\"] must be a finite number greater than 0")
  else . end
| if (($pct["99.000000"] | is_finite_positive_number | not)) then
    error("jobs[0].write.clat_ns.percentile[\"99.000000\"] must be a finite number greater than 0")
  else . end
| {
    schema_version: 1,
    benchmark: "fio_randwrite_4k",
    label: $label,
    fio_version: $fv,
    target_kind: $target_kind,
    params: $params,
    metrics: {
      fio_randwrite_4k_iops: { value: $w.iops, unit: "ops/s" },
      fio_randwrite_4k_lat_mean_us: { value: ($w.lat_ns.mean / 1000), unit: "us" },
      fio_randwrite_4k_clat_p50_us: { value: ($pct["50.000000"] / 1000), unit: "us" },
      fio_randwrite_4k_clat_p95_us: { value: ($pct["95.000000"] / 1000), unit: "us" },
      fio_randwrite_4k_clat_p99_us: { value: ($pct["99.000000"] / 1000), unit: "us" }
    }
  }
'

# 引数: <fio 出力 JSON のパス> <target_kind> <params オブジェクト（JSON 文字列）>
convert_fio_json() {
  local fio_json_path="$1"
  local target_kind="$2"
  local params_json="$3"
  local out

  if ! out=$(jq -n \
    --arg label "$label" \
    --arg target_kind "$target_kind" \
    --argjson params "$params_json" \
    --slurpfile ff "$fio_json_path" \
    "$convert_jq_program" 2>&1); then
    err "invalid-input" "$out"
    exit 2
  fi
  # jq プログラムが `capture`/`match` 系フィルタで意図せず空ストリームを返すと
  # jq 自体は正常終了（exit 0）かつ標準出力が空文字列になる。検証漏れによる
  # 「空 JSON を成功として返す」事故を防ぐ最後の砦（fail-closed）。
  if [ -z "$out" ]; then
    err "invalid-input" "converter produced no output (unexpected empty jq result)"
    exit 2
  fi
  printf '%s\n' "$out"
}

params_json=$(jq -n \
  --arg rw "randwrite" \
  --arg bs "4k" \
  --arg ioengine "psync" \
  --argjson direct "$direct" \
  --arg size "$size" \
  --argjson runtime "$runtime" \
  --argjson iodepth "$iodepth" \
  --argjson numjobs "$numjobs" \
  --argjson end_fsync 1 \
  --argjson group_reporting true \
  --arg filename "$FIXED_FILENAME" \
  '{rw: $rw, bs: $bs, ioengine: $ioengine, direct: $direct, size: $size,
    runtime: $runtime, iodepth: $iodepth, numjobs: $numjobs,
    end_fsync: $end_fsync, group_reporting: $group_reporting, filename: $filename}')

if [ "$mode" = "from-json" ]; then
  check_symlink_reject "$from_json"
  if [ ! -e "$from_json" ]; then
    err "invalid-input" "$from_json does not exist"
    exit 2
  fi
  if [ ! -f "$from_json" ]; then
    err "invalid-input" "$from_json is not a regular file"
    exit 2
  fi
  # `wc -c` 自体の失敗（読み取り権限なし等）を `set -e`/`pipefail` に丸投げすると
  # `wc` 由来の終了コード（多くは 1）がそのままスクリプトの終了コードになり、
  # 「fio 実行失敗」（exit 1）と誤認する。ここで捕捉し、契約どおり入力エラー
  # （exit 2）として扱う（check-bench-regression.sh の check_input_file と同方針）。
  if ! from_json_size=$(wc -c <"$from_json" 2>/dev/null | tr -d ' '); then
    err "invalid-input" "$from_json could not be read"
    exit 2
  fi
  if [ "$from_json_size" -gt "$MAX_FROM_JSON_BYTES" ]; then
    err "invalid-input" "$from_json exceeds ${MAX_FROM_JSON_BYTES} bytes"
    exit 2
  fi

  result=$(convert_fio_json "$from_json" "from_json" "$params_json")
  printf '%s\n' "$result"
  if [ -n "$output_path" ]; then
    write_output_file "$result"
  fi
  exit 0
fi

# --------------------------------------------------
# run モード: --target-dir の検証 → fio 実行（timeout 保護）→ 変換 → 後始末
# --------------------------------------------------
check_symlink_reject "$target_dir"
if [ ! -e "$target_dir" ]; then
  err "invalid-input" "--target-dir does not exist: $target_dir"
  exit 2
fi
if [ ! -d "$target_dir" ]; then
  err "invalid-input" "--target-dir is not a directory: $target_dir"
  exit 2
fi
if [ ! -w "$target_dir" ]; then
  err "invalid-input" "--target-dir is not writable: $target_dir"
  exit 2
fi
if ! target_dir_real=$(realpath -- "$target_dir" 2>/dev/null) || [ -z "$target_dir_real" ]; then
  err "invalid-input" "--target-dir could not be resolved: $target_dir"
  exit 2
fi

# fio の `--directory`/`--filename` は ':' をリスト区切り文字として解釈し
# （fio 本体の `filename.c` の `add_file`/`get_next_filename` 周辺が
# `FIO_ARR_SEP`（':'）でディレクトリ・ファイル名リストを分割する。マニュアルの
# `directory=str`/`filename=str` の「複数指定は ':' 区切り」という記述と一致する。
# エスケープは `\:`。この環境に fio が無く実機での再現確認はしていない）、
# ':' を含む正規化後のパスを渡すと fio が意図しない複数ディレクトリへ書き込みうる。
# `cleanup()` は専用サブディレクトリ 1 つしか消さないため、他の書き込み先にデータファイルが
# 残留する（security.md の「ボリューム外へ書き込める経路を作らない」に反する）。
# realpath 後の値を検証し、シンボリックリンク解決や相対解釈で ':' が入り込む
# 余地を残さない。
if [ "$target_dir_real" != "${target_dir_real//:/}" ]; then
  err "invalid-input" "--target-dir must not contain ':' (fio treats ':' as a directory/filename list separator): $target_dir_real"
  exit 2
fi

# 他ユーザーが書き込めて sticky bit も無いディレクトリは拒否する。そのような
# ディレクトリでは、下の専用サブディレクトリを作った直後に第三者がそれを rename して
# symlink へ差し替え、fio をボリューム外へ書き込ませる競合が残るため（sticky bit が
# あれば他ユーザーは自分のエントリしか rename・削除できない。/tmp 等の 1777 は許容）。
# グループ書き込み可（775 等）は、ユーザープライベートグループ既定の環境で一般的な
# ため拒否しない（同じグループのメンバーは信頼する前提）。
if [ -n "$(find "$target_dir_real" -maxdepth 0 -perm -0002 ! -perm -1000 2>/dev/null)" ]; then
  err "invalid-input" "--target-dir is world-writable without the sticky bit, refusing to use it: $target_dir_real"
  exit 2
fi

# trap より先に空で初期化し、作成前に終了した経路で未定義・空パスを rm しないようにする。
tmp_dir=""
run_dir=""
# fio の一時出力・書き込んだデータファイルは、成否に関わらず必ず削除する（DoS 防止・
# ディスク占有を残さないための後始末。coding-rust.md「相手の応答を待つ処理には
# タイムアウトを設ける」と対で、タイムアウト／失敗経路でも後始末が漏れないようにする）。
# `rm -rf` は削除対象のパス自体が symlink に差し替えられていてもリンクそのものを
# 消すだけで、リンク先をたどって再帰削除しない。
# shellcheck disable=SC2329 # trap 経由で呼ばれるため直接の呼び出しは無い
cleanup() {
  if [ -n "$tmp_dir" ]; then
    rm -rf -- "$tmp_dir"
  fi
  if [ -n "$run_dir" ]; then
    rm -rf -- "$run_dir"
  fi
}
trap cleanup EXIT

if ! tmp_dir=$(mktemp -d 2>/dev/null) || [ -z "$tmp_dir" ]; then
  tmp_dir=""
  err "invalid-input" "could not create a temporary directory for the fio output"
  exit 2
fi
fio_out_json="${tmp_dir}/fio-output.json"

# データファイルの置き場として、--target-dir 内に実行ごとの専用サブディレクトリを
# 新規作成する（security.md の symlink・ボリューム外書き込み対策）。
# 固定パス `${target_dir_real}/${FIXED_FILENAME}` を直接 fio に渡すと、事前に置かれた
# 同名 symlink を fio がたどってリンク先（ボリューム外）を --size 分上書きする。
# 「symlink・既存ファイルなら拒否（exit 2）」という事前検査は検査から fio の open
# までの競合（TOCTOU）を原理的に塞げないため採らない。`mktemp -d` は一意な名前で
# mkdir(2)（最終要素が既存の symlink なら EEXIST で失敗し、たどらない）を 0700 で
# 行うため、作成後のサブディレクトリ内へ第三者（root 以外）がエントリを置けない。
# fio にはこのサブディレクトリ内の固定ファイル名だけを渡す。
if ! run_dir=$(mktemp -d "${target_dir_real}/fandhe-fio-randwrite-4k.XXXXXXXXXX" 2>/dev/null) || [ -z "$run_dir" ]; then
  run_dir=""
  err "invalid-input" "could not create a private working directory under --target-dir: $target_dir_real"
  exit 2
fi

fio_args=(
  --name=fandhe-fio-randwrite-4k
  --directory="$run_dir"
  --filename="$FIXED_FILENAME"
  --rw=randwrite
  --bs=4k
  --ioengine=psync
  --direct="$direct"
  --size="$size"
  --runtime="$runtime"
  --time_based
  --iodepth="$iodepth"
  --numjobs="$numjobs"
  --end_fsync=1
  --group_reporting
  --output-format=json
  --output="$fio_out_json"
)

timeout_secs=$((runtime + TIMEOUT_MARGIN_SECS))
echo "info: running fio (runtime=${runtime}s, timeout=${timeout_secs}s, target=${target_dir_real})" >&2
fio_rc=0
# `-k` で SIGTERM 後も終わらない fio を SIGKILL する（REPAIR-5）。タイムアウト時の
# 終了コードは SIGTERM で止まれば 124、SIGKILL へ切り替えた場合は 137（128+SIGKILL）に
# なりうる（uutils coreutils 0.10.0 で 137 を確認。GNU coreutils での値は未確認）ため、
# 両方をタイムアウト系として扱う。いずれも契約上は exit 1。
timeout -k "${TIMEOUT_KILL_AFTER_SECS}s" "${timeout_secs}s" fio "${fio_args[@]}" >&2 || fio_rc=$?
if [ "$fio_rc" -eq 124 ]; then
  err "fio-timeout" "fio did not finish within ${timeout_secs}s"
  exit 1
fi
if [ "$fio_rc" -eq 137 ]; then
  err "fio-timeout" "fio was killed with SIGKILL (did not stop within ${TIMEOUT_KILL_AFTER_SECS}s after the ${timeout_secs}s timeout, or was killed externally)"
  exit 1
fi
if [ "$fio_rc" -ne 0 ]; then
  err "fio-failed" "fio exited with status ${fio_rc}"
  exit 1
fi

result=$(convert_fio_json "$fio_out_json" "run" "$params_json")
printf '%s\n' "$result"
if [ -n "$output_path" ]; then
  write_output_file "$result"
fi
exit 0
