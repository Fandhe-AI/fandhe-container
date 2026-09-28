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
#   - --from-json モード: `jq`（fio 不要）
#   - root 権限・`/dev/kvm` は不要
#   - 全モード共通で `grep`・`dirname`・`basename`・`wc`・`tr`・`mktemp`・`find`・`ln`・
#     `head`・`sleep`・`id`（いずれも前提ツール検証の対象。欠如は exit 3）
#
# 書き込み先の安全性（security.md の symlink・ボリューム外書き込み対策）:
#   fio のデータファイルは `--target-dir` 直下の固定パスではなく、実行ごとに
#   `mktemp -d` で `--target-dir` 内へ新規作成する専用サブディレクトリ（0700）の中に
#   作る。事前に置かれた symlink を fio（O_CREAT・O_EXCL なしで open し symlink を
#   たどる）に踏ませないための構造的対策で、後始末もそのサブディレクトリを
#   `rm -rf` で消すだけにする（symlink をたどらない）。
#
# 総書き込み量と runtime（DoS 防止。IO-8 の計測契約）:
#   fio に --time_based を渡さない。--time_based があると fio はファイルを書き終えても
#   runtime いっぱいまで同じワークロードを繰り返すため、書き込み量が --size × --numjobs
#   の上限を超えて runtime に比例して増える。--time_based なしの fio は各ジョブが
#   --size 分（4K ブロックを重複なく 1 巡。fio の既定の random map）を書いた時点か
#   runtime に達した時点の早い方で止まるため、総書き込み量は --size × --numjobs 以下に
#   なり、--runtime は打ち切り時間として働く。IOPS はこの 1 巡（または runtime までの
#   区間）の平均になる（詳細と計測上の影響は docs/design/io-fio-bench.md）。runtime・
#   time_based の挙動は fio 本体（axboe/fio master）の HOWTO.rst の記述で確認した。
#
# --from-json と run モードの契約（IO-8 の計測条件をベンチ名と一致させる）:
#   変換対象の fio JSON は run モードと同じ条件で実行されたものだけを受け付ける。
#   `jobs` はちょうど 1 件（--group_reporting）・`jobname` は `fandhe-fio-randwrite-4k`・
#   `error` は 0 で、`global options` と `job options` を合わせた fio オプションは
#   run モードが渡すものと同じ集合（name・directory・filename・rw・bs・ioengine・direct・
#   size・runtime・iodepth・numjobs・end_fsync・group_reporting）に限る（time_based は
#   総書き込み量の上限を無効にするため含めない。下の「総書き込み量と runtime」参照）。
#   これらはすべて必須（存在する場合だけ照合する項目は置かない。`global options`
#   だけは fio が空のとき出力しないため省略可）。
#   値は name=`fandhe-fio-randwrite-4k`・rw=randwrite・bs=4k（4k/4K/4096）・
#   ioengine=psync・filename=固定名・end_fsync=1 で、directory は ':' を含まない
#   空でない絶対パス（run モードでは本スクリプトが作った専用サブディレクトリと一致）、
#   direct・size・runtime・iodepth・numjobs は本スクリプトの
#   同名オプション（既定値含む）と一致しなければならない。これにより出力の `params` は
#   元の fio 実行条件と一致することが保証される。条件不一致・欠落・未知のオプションは
#   exit 2。fio の JSON 上のオプション表現（`job options`/`global options` は
#   `add_to_dump_list` が記録した正規名→入力文字列の組、値なしフラグは空文字列）は
#   fio 本体（axboe/fio master）の `parse.c`・`stat.c`（`json_add_job_opts`）・
#   `json.h` を直接参照して確認した（実 fio の出力での照合は未実施）。
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: fio の実行失敗（exit 0 でも出力 JSON を書かなかった場合を含む）またはタイムアウト
#   2: 入力エラー（引数の検証失敗、fio JSON のスキーマ不正・実行条件の不一致、
#      値が 0 以下、ファイルサイズ・総書き込み量の上限超過、symlink 等）
#   3: 前提ツールが無い（run モードでの fio・timeout。全モード共通で
#      jq・grep・dirname・basename・wc・tr・mktemp・find・ln・head・sleep・id）
#   4: 計測データ（run モードの専用サブディレクトリ。最大 --size 分）を後始末で
#      削除できなかった（残ったパスを stderr に出す。本来の終了コードより優先する）
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
# fio の --size はジョブごとの値のため、上限は総量（--size × --numjobs）で課す
# （DoS 防止。ジョブ単体の --size もこれ以下になる）。
readonly MAX_TOTAL_SIZE_BYTES=$((10 * 1024 * 1024 * 1024)) # 10 GiB
readonly FIO_JOB_NAME="fandhe-fio-randwrite-4k"
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
# 変換対象 JSON を一時ファイルへ 1 回だけ読み込むときの上限時間。検証後に入力パスを
# FIFO 等へ差し替えられて open/read が止まっても、この秒数で打ち切る（REPAIR-5）。
# `timeout` は macOS 標準環境に無く --from-json モードでは使えないため、sleep と kill
# による見張りで実装する（snapshot_json_input 参照）。
readonly INPUT_READ_TIMEOUT_SECS=10

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

workload options (run mode: passed to fio; --from-json mode: the fio JSON's
job options must match these values, defaults included):
  --direct 0|1        O_DIRECT flag (default: 1)
  --size <NkNmNg>      fio --size per job (default: 256m; --size x --numjobs
                       is capped at 10 GiB in total, and is the upper bound
                       on the bytes written)
  --runtime <1-600>    fio --runtime in seconds, an upper bound on the run
                       (default: 30; fio stops earlier once --size is written)
  --iodepth <1-64>     fio --iodepth (default: 1)
  --numjobs <1-16>     fio --numjobs (default: 1)

--target-dir is run-mode only and must not be combined with --from-json.
USAGE
}

# --------------------------------------------------
# 引数解析（ファイルシステム・外部コマンドには触れない純粋なパース）
# --------------------------------------------------
mode="run"
target_dir=""
target_dir_given=0
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
      target_dir_given=1
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
# --from-json と --target-dir の併用は拒否する（--target-dir が黙って無視され、
# 呼び出し元が「実測した」と誤認するのを防ぐ）。run モードでは --target-dir 必須。
if [ "$mode" = "from-json" ] && [ "$target_dir_given" -eq 1 ]; then
  err "arg-error" "--target-dir cannot be combined with --from-json"
  exit 2
fi
if [ "$mode" = "run" ] && [ -z "$target_dir" ]; then
  err "arg-error" "--target-dir is required in run mode (or use --from-json)"
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
for tool in jq grep dirname basename wc tr mktemp find ln head sleep id; do
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
# 総量（ジョブごとの --size × --numjobs）で上限を課す。値域は size_num ≤ 999999・
# size_mult ≤ 1 GiB・numjobs ≤ 16 のため、積は bash の 64bit 整数に収まる。
# （実装上は全ジョブが同じ --filename を共有するためディスク上のファイルは 1 つだが、
# fio の書き込み量・将来のファイル分割に対して保守的に総量で制限する）
total_size_bytes=$((size_bytes * numjobs))
if [ "$total_size_bytes" -gt "$MAX_TOTAL_SIZE_BYTES" ]; then
  err "invalid-input" "--size x --numjobs (${size} x ${numjobs} = ${total_size_bytes} bytes) exceeds the ${MAX_TOTAL_SIZE_BYTES}-byte total cap"
  exit 2
fi

# 後始末（成否・タイムアウト・シグナルに関わらず EXIT で必ず走る）。対象は
# run モードの fio 一時出力ディレクトリ・専用サブディレクトリと、--output 用の
# 一時ファイル。trap より先に空で初期化し、作成前に終了した経路で未定義・空パスを
# rm しないようにする。`rm -rf`/`rm -f` は対象パス自体が symlink に差し替えられて
# いてもリンクそのものを消すだけで、リンク先をたどらない（DoS 防止・ディスク占有を
# 残さない。coding-rust.md のタイムアウト方針と対で、失敗経路でも後始末を漏らさない）。
tmp_dir=""
run_dir=""
output_tmp=""
# 削除失敗の扱いは対象の大きさで分ける:
#   - run モードの専用サブディレクトリ（計測データ。最大 --size 分、既定 256 MiB・
#     上限 10 GiB）: 削除できなければ残ったパスを stderr に出し、本来の終了コードより
#     優先して exit 4 で終わる（大容量のデータが黙って残るのを防ぐ。fail-closed）
#   - 一時ディレクトリ（JSON のスナップショット・fio の JSON 出力。各 4 MiB 以下）・
#     --output 用の一時ファイル名（結果 JSON と同じ inode の別名）: 小さいため警告
#     （残ったパス）を stderr に出すだけで、本来の終了コードを保つ
# 削除できたかどうかは rm の終了コードに加え、削除後にパスが残っていないこと
# （存在しない・symlink でもない）で判定する。
# `set -e` 下の EXIT trap でコマンドが失敗すると、シェルはその失敗の終了コードで
# 終わる（bash で確認）ため、入口で本来の終了コードを保存し、最後に明示的に終わる。
# shellcheck disable=SC2329 # trap 経由で呼ばれるため直接の呼び出しは無い
cleanup() {
  local rc=$?
  local data_left=0
  if [ -n "$tmp_dir" ]; then
    if ! rm -rf -- "$tmp_dir" || [ -e "$tmp_dir" ] || [ -L "$tmp_dir" ]; then
      echo "warning: cleanup-failed: could not remove temporary files: ${tmp_dir}" >&2
    fi
  fi
  if [ -n "$run_dir" ]; then
    if ! rm -rf -- "$run_dir" || [ -e "$run_dir" ] || [ -L "$run_dir" ]; then
      echo "error: cleanup-failed: could not remove benchmark data (up to --size bytes may remain): ${run_dir}" >&2
      data_left=1
    fi
  fi
  if [ -n "$output_tmp" ]; then
    if ! rm -f -- "$output_tmp" || [ -e "$output_tmp" ] || [ -L "$output_tmp" ]; then
      echo "warning: cleanup-failed: could not remove temporary file: ${output_tmp}" >&2
    fi
  fi
  if [ "$data_left" -eq 1 ]; then
    if [ "$rc" -ne 0 ]; then
      echo "error: cleanup-failed: the run had already failed with exit status ${rc}" >&2
    fi
    exit 4
  fi
  exit "$rc"
}
trap cleanup EXIT

# 本スクリプトがエントリを作るディレクトリ（--target-dir・--output の親・一時
# ディレクトリ）について、ルートから最終ディレクトリまでの全パス要素が第三者に
# 差し替えられないことを確かめる（OpenSSH の StrictModes と同じ考え方。exit 2）。
# 各要素（`cd` と `pwd -P` で symlink を解決した実体のパス）に次を要求する:
#   - symlink でないディレクトリである
#   - 所有者が実行ユーザーまたは root
#   - group・other に書き込み権限が無い。ただし sticky bit 付き（/tmp 等）は許す
# 根拠: ディレクトリのエントリを rename・削除・作成できるのは、そのディレクトリへの
# 書き込み権限を持つ者（sticky bit 付きなら、エントリの所有者・ディレクトリの
# 所有者・root のみ）に限られる。上の条件を満たす要素の直下のエントリは、実行
# ユーザーと root 以外には差し替えられないため、全要素が条件を満たせば、検証から
# 書き込みまでの間に祖先を symlink 等へ差し替えられることは起きない。sticky bit 付き
# ディレクトリ（所有者は実行ユーザーか root に限る）の直下に mktemp で作った 0700 の
# ディレクトリは実行ユーザーの所有なので、以降も同じ理由で安全になる。
# 判定は要素ごとに fail-closed: find が条件を満たすと判定して `safe` を 1 回だけ出力し、
# 終了コード 0 かつ出力（stderr を含む）が `safe` と完全一致したときだけ通す。find の
# 失敗・エラー出力・空出力・`unsafe` はすべて拒否する。
# 成功時は解決済みの絶対パスを trusted_dir に入れる。呼び出し側は以後この値だけを
# 使い、利用者が渡したパス（symlink を含みうる）を解決し直さない。
# 引数: <オプション名（メッセージ用）> <ディレクトリ>
trusted_dir=""
require_trusted_dir_chain() {
  local what="$1"
  local given="$2"
  local resolved
  local uid
  local rest
  local cur=""
  local comp
  local -a parts=()
  trusted_dir=""
  if ! resolved=$(CDPATH='' cd -- "$given" 2>/dev/null && pwd -P) || [ -z "$resolved" ]; then
    err "invalid-input" "${what} directory could not be resolved: ${given}"
    exit 2
  fi
  case "$resolved" in
    /*) ;;
    *)
      err "invalid-input" "${what} directory did not resolve to an absolute path: ${resolved}"
      exit 2
      ;;
  esac
  # 改行・制御文字を含むパスは要素分割と表示が曖昧になるため拒否する
  if [[ "$resolved" == *[[:cntrl:]]* ]]; then
    err "invalid-input" "${what} directory path contains control characters, refusing to use it"
    exit 2
  fi
  if ! uid=$(id -u 2>&1) || ! printf '%s' "$uid" | grep -Eq '^[0-9]+$'; then
    err "invalid-input" "could not determine the current user id to check ${what} directory: ${uid}"
    exit 2
  fi
  check_trusted_dir_component "$what" "/" "$uid" "$given"
  rest="${resolved#/}"
  if [ -n "$rest" ]; then
    IFS='/' read -r -a parts <<<"$rest"
  fi
  for comp in "${parts[@]}"; do
    if [ -z "$comp" ]; then
      continue
    fi
    cur="${cur}/${comp}"
    check_trusted_dir_component "$what" "$cur" "$uid" "$given"
  done
  trusted_dir="$resolved"
}

# require_trusted_dir_chain の 1 要素分の判定。引数: <what> <絶対パス> <uid> <元の指定>
check_trusted_dir_component() {
  local what="$1"
  local comp="$2"
  local uid="$3"
  local given="$4"
  local verdict
  local rc=0
  if [ -L "$comp" ]; then
    err "invalid-input" "${what} path component ${comp} is a symlink (it may have been replaced after resolution), refusing to use it: ${given}"
    exit 2
  fi
  verdict=$(find "$comp" -maxdepth 0 -type d \
    \( -user "$uid" -o -user 0 \) \
    \( \( ! -perm -0020 ! -perm -0002 \) -o -perm -1000 \) \
    -exec printf safe \; -o -exec printf unsafe \; 2>&1) || rc=$?
  if [ "$rc" -eq 0 ] && [ "$verdict" = "safe" ]; then
    return 0
  fi
  if [ "$rc" -eq 0 ] && [ "$verdict" = "unsafe" ]; then
    err "invalid-input" "${what} path component ${comp} can be modified by other users (every directory from / must be owned by you or root and must not be writable by group or others unless it has the sticky bit), refusing to use it: ${given}"
    exit 2
  fi
  err "invalid-input" "could not verify the permissions of ${what} path component ${comp} (find exited with ${rc}: ${verdict}), refusing to use it: ${given}"
  exit 2
}

# 結果 JSON を --output へ書く（security.md の symlink 対策）。
# 保証範囲: --output のパスが（検証後に置かれたものも含め）何らかの形で存在すれば
# ─ 通常ファイル・ディレクトリ・FIFO・デバイス・それらを指す symlink・dangling
# symlink のいずれでも ─ 書き込まずに exit 2 で止め、既存のエントリやリンク先を
# 開かない・変更しない。手順は次のとおり:
#   1. 出力先と同じディレクトリに `mktemp` で新しい通常ファイル（0600。O_CREAT|O_EXCL
#      で作られ、既存の symlink をたどらない）を作り、結果を書く
#   2. `ln -n` で --output のパスへハードリンクを張る。link(2) は宛先が既に存在すれば
#      （symlink を含む）EEXIST で失敗し、宛先の symlink をたどらない。`-n` は宛先が
#      ディレクトリを指す symlink のときにその中へ作らないため（GNU・BSD〔macOS〕
#      共通のオプションで、GNU 専用の `mv -T`/`ln -T` には依存しない）
#   3. 検証後に実ディレクトリを置かれた場合、`ln` はその中へリンクを作ってしまうため、
#      --output のパスが一時ファイルと同一 inode の通常ファイル（symlink でない）で
#      あることを確かめ、違えば exit 2（置かれたディレクトリの中に一時ファイル名の
#      ハードリンクが残るが、既存のエントリは変更しない）
#   4. 一時ファイル名を消す（--output 側のリンクが残る）
# 1 の書き込みはパス名で開き直すが、親ディレクトリは require_trusted_dir_chain で
# ルートからの全要素が第三者に差し替えられないことを確認済みで、以後は解決済みの
# パス（output_final）だけを使うため、他ユーザーが一時ファイルや祖先を差し替える
# ことはできない。
# 制約: ハードリンク非対応のファイルシステム（FAT 系等）では 2 が失敗し exit 2 になる。
# 出力ファイルの権限は mktemp の 0600 になる。失敗はすべて入力エラー（exit 2）として
# 扱う（set -e に任せると exit 1「fio 実行失敗」と誤分類されるため）。
write_output_file() {
  local content="$1"
  if ! output_tmp=$(mktemp "${output_dir_real}/.fandhe-fio-output.XXXXXXXXXX" 2>/dev/null) || [ -z "$output_tmp" ]; then
    output_tmp=""
    err "invalid-input" "could not create a temporary file next to --output: $output_path"
    exit 2
  fi
  if ! printf '%s\n' "$content" >"$output_tmp" 2>/dev/null; then
    err "invalid-input" "could not write the temporary file for --output: $output_tmp"
    exit 2
  fi
  if ! ln -n -- "$output_tmp" "$output_final" 2>/dev/null; then
    err "invalid-input" "--output path could not be created exclusively (it exists, possibly created after validation, or the filesystem does not support hard links): $output_path"
    exit 2
  fi
  if [ -L "$output_final" ] || [ ! -f "$output_final" ] || [ ! "$output_final" -ef "$output_tmp" ]; then
    err "invalid-input" "--output path was replaced during the write (a directory or other entry appeared after validation): $output_path"
    exit 2
  fi
  # 一時ファイル名の削除に失敗しても結果は --output に書けている。set -e で打ち切らず、
  # 後始末（cleanup）でもう一度消し、それでも残れば警告にする。
  if rm -f -- "$output_tmp"; then
    output_tmp=""
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
  require_trusted_dir_chain "--output parent" "$output_dir"
  output_dir_real="$trusted_dir"
  # 書き込み先は解決済みの親ディレクトリ＋最終要素で組み立て直す（以後、利用者が
  # 渡したパスを解決し直さない）。最終要素が `.`・`..`・空（末尾 `/`）なら拒否する。
  output_base=$(basename -- "$output_path")
  case "$output_path" in
    */)
      err "invalid-input" "--output must be a file path, not a directory: $output_path"
      exit 2
      ;;
  esac
  case "$output_base" in
    "" | . | .. | /)
      err "invalid-input" "--output must name a file: $output_path"
      exit 2
      ;;
  esac
  output_final="${output_dir_real}/${output_base}"
  check_symlink_reject "$output_final"
  if [ -e "$output_final" ]; then
    err "invalid-input" "--output path already exists, refusing to overwrite: $output_path"
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

# fio の size 文字列（`256m`・`256M`・`268435456` 等）をバイト数へ。kb_base の既定
# （1024）前提で k/m/g のみ受け付け、それ以外の書式（`256MiB`・`1t`・小数等）は null
# （＝不一致として拒否）にする。
def fio_size_bytes:
  if type != "string" then null
  else (capture("^(?<n>[1-9][0-9]{0,11})(?<u>[kKmMgG]?)$") // null) as $c
  | if $c == null then null
    else ($c.n | tonumber) * ({"": 1, "k": 1024, "m": 1048576, "g": 1073741824}[$c.u | ascii_downcase])
    end
  end;

# fio の runtime 文字列（`30`・`30s`）を秒数へ。それ以外の単位（`1m` 等）は null。
def fio_runtime_secs:
  if type != "string" then null
  else (capture("^(?<n>[1-9][0-9]{0,5})s?$") // null) as $c
  | if $c == null then null else ($c.n | tonumber) end
  end;

# 値なしフラグ（group_reporting）: fio は値なしを空文字列で記録する。
# `=1` は有効、`=0` は無効化なので拒否する。
def fio_flag_enabled:
  (type == "string") and (. == "" or . == "1");

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
| if (($doc.jobs | type) != "array") or (($doc.jobs | length) != 1) then
    error("fio output must contain exactly one entry in \"jobs\" (run with --group_reporting and a single job section)")
  else . end
| ($doc.jobs[0]) as $job
| if (($job | type) != "object") then error("jobs[0] must be an object") else . end
| if ($job.jobname != $expect.jobname) then
    error("jobs[0].jobname must be \"\($expect.jobname)\" (got \($job.jobname | tojson))")
  else . end
| if ($job.error != 0) then
    error("jobs[0].error must be present and 0 (got \($job.error | tojson))")
  else . end
# 実行条件の検証（IO-8: fio_randwrite_4k_* の名前で出してよいのは 4K ランダム write の
# 条件で実行された結果だけ）。global options に job options を上書きした実効値で判定する。
# global options は fio が空のとき出力しないため省略可。`//` は false も省略扱いに
# してしまうため has で判定し、存在するならオブジェクトであることを要求する。
| (if ($doc | has("global options")) then $doc["global options"] else {} end) as $gopts
| if (($gopts | type) != "object") then error("\"global options\" must be an object") else . end
| ($job["job options"]) as $jopts
| if (($jopts | type) != "object") then
    error("jobs[0][\"job options\"] is missing: cannot verify that the run used the 4K random write conditions")
  else . end
| ($gopts + $jopts) as $o
| (["name", "directory", "filename", "rw", "bs", "ioengine", "direct", "size", "runtime",
    "iodepth", "numjobs", "end_fsync", "group_reporting"]) as $allowed
| (($o | keys) - $allowed) as $unexpected
| if ($unexpected | length) > 0 then
    error("unexpected fio options (only the options passed in run mode are accepted): \($unexpected | join(", "))")
  else . end
| (($o | to_entries | map(select(.value | type != "string")) | map(.key))) as $nonstring
| if ($nonstring | length) > 0 then
    error("fio options must be strings: \($nonstring | join(", "))")
  else . end
# 許可リストの項目はすべて必須（「値があるときだけ照合」にしない）。欠落は null として
# 以下の各比較で不一致になる。
| if ($o.name != $expect.jobname) then
    error("fio option name must be present and equal to \"\($expect.jobname)\" (got \($o.name | tojson))")
  else . end
# directory: fio の --directory。run モードと同じくコロン（fio のディレクトリ・ファイル名
# リストの区切り文字）を含まない空でない絶対パスを要求する（Windows 版 fio の
# ドライブレター形式は受け付けない）。run モードでは $expect.directory に本スクリプトが
# 作った専用サブディレクトリが入り、完全一致を要求する（--from-json では null）。
| if ((($o.directory | type) != "string") or ($o.directory == "")) then
    error("fio option directory must be present and non-empty (got \($o.directory | tojson))")
  else . end
| if (($o.directory | startswith("/")) | not) then
    error("fio option directory must be an absolute path (got \($o.directory | tojson))")
  else . end
| if ($o.directory | contains(":")) then
    error("fio option directory must not contain a colon (got \($o.directory | tojson))")
  else . end
| if (($expect.directory != null) and ($o.directory != $expect.directory)) then
    error("fio option directory must be the private working directory of this run \($expect.directory | tojson) (got \($o.directory | tojson))")
  else . end
| if ($o.rw != "randwrite") then
    error("fio option rw must be \"randwrite\" (got \($o.rw | tojson))")
  else . end
| if (($o.bs | IN("4k", "4K", "4096")) | not) then
    error("fio option bs must be 4k (\"4k\", \"4K\" or \"4096\"; got \($o.bs | tojson))")
  else . end
| if ($o.ioengine != "psync") then
    error("fio option ioengine must be \"psync\" (got \($o.ioengine | tojson))")
  else . end
| if ($o.filename != $expect.filename) then
    error("fio option filename must be \"\($expect.filename)\" (got \($o.filename | tojson))")
  else . end
| if ($o.end_fsync != "1") then
    error("fio option end_fsync must be \"1\" (got \($o.end_fsync | tojson))")
  else . end
| if (($o.group_reporting | fio_flag_enabled) | not) then
    error("fio option group_reporting must be enabled (got \($o.group_reporting | tojson))")
  else . end
| if ($o.direct != $expect.direct) then
    error("fio option direct must match --direct \($expect.direct) (got \($o.direct | tojson))")
  else . end
| if ($o.iodepth != $expect.iodepth) then
    error("fio option iodepth must match --iodepth \($expect.iodepth) (got \($o.iodepth | tojson))")
  else . end
| if ($o.numjobs != $expect.numjobs) then
    error("fio option numjobs must match --numjobs \($expect.numjobs) (got \($o.numjobs | tojson))")
  else . end
| if (($o.size | fio_size_bytes) != $expect.size_bytes) then
    error("fio option size must match --size \($expect.size) (\($expect.size_bytes) bytes; got \($o.size | tojson))")
  else . end
| if (($o.runtime | fio_runtime_secs) != $expect.runtime) then
    error("fio option runtime must match --runtime \($expect.runtime) seconds (got \($o.runtime | tojson))")
  else . end
| ($job.write) as $w
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
    --argjson expect "$expect_json" \
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

# params・expect の組み立ては入力検証済みの値だけから作る。jq が失敗した場合は
# set -e に任せず入力エラーとして止める（終了コードの契約を保つ）。
if ! params_json=$(jq -n \
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
    end_fsync: $end_fsync, group_reporting: $group_reporting, filename: $filename}') || [ -z "$params_json" ]; then
  err "invalid-input" "could not build the params object"
  exit 2
fi

# fio JSON の実行条件の照合値（convert_jq_program の $expect）。params と同じ入力から
# 作り、run・--from-json の両モードで同じ照合をかける（出力の params が元の fio 実行
# 条件と一致することの保証）。fio は値を入力文字列のまま記録するため direct・iodepth・
# numjobs は文字列で、size・runtime は正規化後の数値で比較する。
if ! expect_json=$(jq -n \
  --arg jobname "$FIO_JOB_NAME" \
  --arg filename "$FIXED_FILENAME" \
  --arg direct "$direct" \
  --arg iodepth "$iodepth" \
  --arg numjobs "$numjobs" \
  --arg size "$size" \
  --argjson size_bytes "$size_bytes" \
  --argjson runtime "$runtime" \
  '{jobname: $jobname, filename: $filename, direct: $direct, iodepth: $iodepth,
    numjobs: $numjobs, size: $size, size_bytes: $size_bytes, runtime: $runtime,
    directory: null}') || [ -z "$expect_json" ]; then
  err "invalid-input" "could not build the expected fio options"
  exit 2
fi
# directory の期待値は run モードでのみ、専用サブディレクトリ作成後に設定する
# （--from-json では元の実行先を知り得ないため null のまま。形式の照合だけ行う）。

# 変換結果を出す。--output を先に書き、失敗したら stdout には何も出さず exit 2 に
# する（呼び出し元は exit 0 のときだけ stdout を結果として読む前提）。
emit_result() {
  local result="$1"
  if [ -n "$output_path" ]; then
    write_output_file "$result"
  fi
  printf '%s\n' "$result"
}

# 本スクリプト専用の一時ディレクトリ。変換対象 JSON のスナップショットと run モードの
# fio 出力を置く（両モード共通）。手順は「解決 → 検証 → 作成 → 返り値をそのまま使う」:
#   1. TMPDIR（未設定なら /tmp）を cd と pwd -P で実体のパスへ解決する
#   2. その全パス要素を require_trusted_dir_chain で検証する（第三者が書き換え可能な
#      場所だと、スナップショットを差し替えられてサイズ判定済みの内容と変換する内容が
#      ずれる）
#   3. 解決済みの実体パスを基点に mktemp -d する（0700 で新規作成。最終要素が既存の
#      symlink なら失敗し、たどらない）
#   4. mktemp が返したパスをそのまま使い、以後は解決し直さない（作成後に解決し直すと、
#      その間に差し替えられたパスを採用してしまうため）。後始末も同じパスを消す
require_trusted_dir_chain "temporary (TMPDIR)" "${TMPDIR:-/tmp}"
tmp_base="$trusted_dir"
if ! tmp_dir=$(mktemp -d "${tmp_base}/fandhe-fio-bench.XXXXXXXXXX" 2>/dev/null) || [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ] || [ -L "$tmp_dir" ]; then
  tmp_dir=""
  err "invalid-input" "could not create a private temporary directory under ${tmp_base}"
  exit 2
fi

# 変換対象 JSON を 1 回だけ読み、内容を固定したコピー（tmp_dir 内に mktemp で作る
# 0600 の新規ファイル。パスは snapshot_path に入れて返す）を作る。
# 以後の処理（サイズ上限の判定・jq による変換）はこのコピーだけを入力にするため、
# 検証と使用の間に元のパスを差し替えられても、判定済みの内容と変換する内容が
# ずれない（TOCTOU 対策・DoS 防止）。
#   - 元のパスは 1 回だけ open し、その fd が通常ファイルであることを確かめてから
#     `head -c (上限+1)` でコピーする（FIFO・デバイス等へ差し替えられた場合は拒否。
#     上限 +1 バイトまでしか読まないため、巨大ファイルでも読み込み量は有界）
#   - open 自体が FIFO で止まる場合に備え、INPUT_READ_TIMEOUT_SECS で打ち切る
#     （sleep と kill の見張り。timeout は --from-json の対象の macOS に無いため）
#   - コピーのサイズが上限を超えたら拒否する。サイズは数字であることを確かめてから
#     比較する（`wc` の出力が空・非数値のとき `[ -gt ]` が偽になって素通りするのを防ぐ）
# 検証後に元のパスを通常ファイルへの symlink に差し替えられた場合はリンク先を読む
# （読み取りのみで書き込みはしない。内容は untrusted として変換時にすべて検証する）。
# 引数: <元のパス> <メッセージ用の名前>
snapshot_path=""
snapshot_json_input() {
  local src="$1"
  local what="$2"
  local dst
  local reader_pid
  local watchdog_pid
  local rc=0
  local bytes
  if ! dst=$(mktemp "${tmp_dir}/json-snapshot.XXXXXXXXXX" 2>/dev/null) || [ -z "$dst" ]; then
    err "invalid-input" "could not create a temporary file to copy ${what}"
    exit 2
  fi
  (
    exec 3<"$src" || exit 10
    # /dev/fd/3 の stat は開いた fd 自体を指す（Linux・macOS 共通）
    [ -f /dev/fd/3 ] || exit 11
    exec head -c "$((MAX_FROM_JSON_BYTES + 1))" <&3 >"$dst"
  ) 2>/dev/null &
  reader_pid=$!
  ( sleep "$INPUT_READ_TIMEOUT_SECS" && kill -KILL "$reader_pid" ) >/dev/null 2>&1 &
  watchdog_pid=$!
  wait "$reader_pid" || rc=$?
  # 見張りの終了コードは判定に使わない（読み取りが先に終われば kill で止めるだけ）。
  # ここでの `|| true` は、既に終了した見張りへの kill・wait の失敗で set -e が
  # スクリプトを止めないためのもの。
  kill "$watchdog_pid" >/dev/null 2>&1 || true
  wait "$watchdog_pid" >/dev/null 2>&1 || true
  case "$rc" in
    0) ;;
    10)
      err "invalid-input" "${what} could not be opened: ${src}"
      exit 2
      ;;
    11)
      err "invalid-input" "${what} is not a regular file (it may have been replaced after validation): ${src}"
      exit 2
      ;;
    137)
      err "invalid-input" "${what} could not be read within ${INPUT_READ_TIMEOUT_SECS}s (it may have been replaced by a FIFO after validation): ${src}"
      exit 2
      ;;
    *)
      err "invalid-input" "${what} could not be read (status ${rc}): ${src}"
      exit 2
      ;;
  esac
  if ! bytes=$(wc -c <"$dst" | tr -d ' ') || ! printf '%s' "$bytes" | grep -Eq '^[0-9]+$'; then
    err "invalid-input" "could not determine the size of ${what}: ${src}"
    exit 2
  fi
  if [ "$bytes" -gt "$MAX_FROM_JSON_BYTES" ]; then
    err "invalid-input" "${what} exceeds ${MAX_FROM_JSON_BYTES} bytes: ${src}"
    exit 2
  fi
  snapshot_path="$dst"
}

if [ "$mode" = "from-json" ]; then
  # 以下の事前検査は分かりやすいエラーを早く返すためのもので、安全性（差し替えへの
  # 耐性・サイズ上限）は snapshot_json_input が担う。
  check_symlink_reject "$from_json"
  if [ ! -e "$from_json" ]; then
    err "invalid-input" "$from_json does not exist"
    exit 2
  fi
  if [ ! -f "$from_json" ]; then
    err "invalid-input" "$from_json is not a regular file"
    exit 2
  fi
  snapshot_json_input "$from_json" "--from-json input"

  result=$(convert_fio_json "$snapshot_path" "from_json" "$params_json")
  emit_result "$result"
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
# symlink を解決した実体のパスについて、ルートからの全要素が第三者に差し替えられない
# ことを確かめる（祖先を含む。判定基準と根拠は require_trusted_dir_chain のコメント）。
# 以後は解決済みの target_dir_real だけを使い、利用者が渡したパスを解決し直さない。
require_trusted_dir_chain "--target-dir" "$target_dir"
target_dir_real="$trusted_dir"

# fio の `--directory`/`--filename` は ':' をリスト区切り文字として解釈し
# （fio 本体の `filename.c` の `add_file`/`get_next_filename` 周辺が
# `FIO_ARR_SEP`（':'）でディレクトリ・ファイル名リストを分割する。マニュアルの
# `directory=str`/`filename=str` の「複数指定は ':' 区切り」という記述と一致する。
# エスケープは `\:`。この環境に fio が無く実機での再現確認はしていない）、
# ':' を含む正規化後のパスを渡すと fio が意図しない複数ディレクトリへ書き込みうる。
# `cleanup()` は専用サブディレクトリ 1 つしか消さないため、他の書き込み先にデータファイルが
# 残留する（security.md の「ボリューム外へ書き込める経路を作らない」に反する）。
# 解決後の値を検証し、シンボリックリンク解決や相対解釈で ':' が入り込む
# 余地を残さない。
if [ "$target_dir_real" != "${target_dir_real//:/}" ]; then
  err "invalid-input" "--target-dir must not contain ':' (fio treats ':' as a directory/filename list separator): $target_dir_real"
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
if ! run_dir=$(mktemp -d "${target_dir_real}/fandhe-fio-randwrite-4k.XXXXXXXXXX" 2>/dev/null) || [ -z "$run_dir" ] || [ ! -d "$run_dir" ] || [ -L "$run_dir" ]; then
  run_dir=""
  err "invalid-input" "could not create a private working directory under --target-dir: $target_dir_real"
  exit 2
fi
# mktemp が返したパス（検証済みの target_dir_real を基点に 0700 で新規作成したもの）を
# そのまま使い、解決し直さない（一時ディレクトリと同じ理由）。
# run モードの fio 出力は、fio の directory がこの専用サブディレクトリと一致することまで
# 照合する（--from-json では形式のみ。convert_jq_program の directory の照合を参照）。
if ! expect_json=$(jq -c --arg directory "$run_dir" '.directory = $directory' <<<"$expect_json") || [ -z "$expect_json" ]; then
  err "invalid-input" "could not set the expected fio directory"
  exit 2
fi

fio_args=(
  --name="$FIO_JOB_NAME"
  --directory="$run_dir"
  --filename="$FIXED_FILENAME"
  --rw=randwrite
  --bs=4k
  --ioengine=psync
  --direct="$direct"
  --size="$size"
  --runtime="$runtime"
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

# fio が exit 0 でも出力 JSON を書いていなければ fio 側の失敗（exit 1）として扱う
# （そのまま jq に渡すとスキーマ不正の exit 2 に誤分類される）。
if [ ! -f "$fio_out_json" ] || [ ! -s "$fio_out_json" ]; then
  err "fio-failed" "fio exited successfully but did not write its JSON output"
  exit 1
fi
snapshot_json_input "$fio_out_json" "fio JSON output"

result=$(convert_fio_json "$snapshot_path" "run" "$params_json")
emit_result "$result"
exit 0
