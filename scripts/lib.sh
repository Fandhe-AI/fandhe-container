#!/usr/bin/env bash
# scripts/targets/*.sh と scripts/{help,with-tools,with-workspace,run-parallel}.sh が共有するヘルパー。
# 直接実行せず source して使う:
#   DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # scripts/ または scripts/targets/
#   source "${DIR}/../lib.sh"                              # scripts/targets/ から。scripts/ からは "${DIR}/lib.sh"
#
# 呼び出し元は `set -euo pipefail` を引き継ぐため、失敗したコマンドはその場でスクリプトを止め、
# 終了コードがそのまま呼び出し元（人・`make`・CI）へ伝わる。
# source した時点で作業ディレクトリをリポジトリルートへ移す。ターゲットが使う相対パスを、
# ルートで実行される `make` 経由と同じ意味にするため。
# macOS 標準の bash 3.2 でも動く書き方に限る（.claude/rules/makefile.md）。回帰テストは scripts/lib-selftest.sh。
set -euo pipefail

_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${_lib_dir}/.." && pwd)"
# shellcheck disable=SC2034 # source した側のスクリプトで参照する
readonly ROOT_DIR
cd "${ROOT_DIR}"

# shellcheck source=./versions.sh
source "${_lib_dir}/versions.sh"

# コマンドを表示してから実行する（make が @ なしのレシピ行を表示するのと同じ見え方にする）。
run() {
  printf '%s\n' "$*"
  "$@"
}

# require_cmd <name>: <name> が PATH に無ければ明確なメッセージで exit 1 する。導入は一切試みない。
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    if [ "$1" = jq ]; then
      echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2
    else
      echo "$1 is required but not found" >&2
    fi
    exit 1
  fi
}

# has_cargo: ルートに Cargo.toml があるか。
# has_members: メンバー crate（crates/*/Cargo.toml）が 1 つ以上あるか。members = [] の仮想 workspace では
# fmt / clippy / test / doc / deny が「対象パッケージが無い」で失敗するため、これらのターゲットは skip する。
# glob が一致しないと bash はパターン文字列をそのまま返すため、展開結果を `[ -f ]` で 1 件ずつ検査する
# （nullglob・compgen の挙動差に依存しない。bash 3.2 でも同じ結果になる）。
has_cargo() { [ -f Cargo.toml ]; }
has_members() {
  local f
  for f in crates/*/Cargo.toml; do
    if [ -f "${f}" ]; then
      return 0
    fi
  done
  return 1
}

# skip_unless_workspace <target>: Cargo.toml とメンバー crate が揃っていなければ skip を表示して exit 0 する。
skip_unless_workspace() {
  if ! has_cargo || ! has_members; then
    echo "skip: Cargo.toml is missing or the workspace has no member crate, skipping $1"
    exit 0
  fi
}

# validate_timeout <NAME> <value>: 1〜999999 の整数でなければ exit 2 する（0 は `timeout` を無効にするため拒否）。
validate_timeout() {
  local name="$1" t="$2"
  case "$t" in '' | *[!0-9]* | ???????*) t=invalid ;; esac
  if [ "$t" = invalid ] || [ "$t" -eq 0 ]; then
    echo "error: invalid-argument: ${name} must be an integer from 1 to 999999 (seconds)" >&2
    exit 2
  fi
}

# require_timeout_cmd: 実機計測のターゲットが使う coreutils の `timeout` が無ければ exit 2 する。
require_timeout_cmd() {
  if ! command -v timeout >/dev/null 2>&1; then
    echo "error: unsupported-os: timeout (coreutils) is required" >&2
    exit 2
  fi
}

# ensure_cargo_deny: cargo-deny が無ければ CARGO_DENY_VERSION で導入する（CI の cargo-deny-version と同値）。
ensure_cargo_deny() {
  if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "installing cargo-deny ${CARGO_DENY_VERSION}"
    cargo install "cargo-deny@${CARGO_DENY_VERSION}" --locked
  fi
}

# 登録済みベンチ名（bench-check / bench-baseline が実行する。旧 Makefile の BENCH_NAMES）。
# 実ベンチを追加するときに足す場所（plugin 境界ベンチ〔TASK-113〕・small_files〔files/s・TASK-189 追補・#1899〕は
# 登録済み。起動 p95 は実機前提のため下の BENCH_MANUAL_NAMES に置き、ここへは入れない。#1901）。
# 各ベンチの metric は benches/metrics.json に登録済みのため、ここにも同時に載せる
# （generate_baseline.sh は metrics.json と results の metric 集合が完全一致しないと exit 2）。
BENCH_NAMES="regression_placeholder plugin_boundary plugin_boundary_list_images small_files"

# 段階登録ベンチ名: metrics.json には登録済みだが baseline.json へ実測基準値が入るまでは比較しないベンチ
# （実測基準値の確定は TASK-88.h1〔#230〕・TASK-113.h1）。scripts/bench/assemble_results.sh が、これらの結果から
# baseline 登録済みの metric だけを比較対象に残す。新しい段階登録ベンチは BENCH_NAMES と
# ここへ 1 語足すだけでよい（起動 p95 は実機前提のため対象外。下の BENCH_MANUAL_NAMES）。
# shellcheck disable=SC2034 # scripts/targets/bench-check.sh が source 後に参照する
BENCH_STAGED_NAMES="plugin_boundary plugin_boundary_list_images small_files"

# Unix 限定ベンチ名: Windows（OS=Windows_NT）では実行せず、baseline・metrics からも除く。
# plugin 境界ベンチは Unix ドメインソケット前提（PLUG-5）。small_files は基準値（#230）が ubuntu の CI 環境の値で、
# Windows の永続化は file 単位の同期（SupportedFileSync）と Linux の syncfs で計測方式が異なり、登録後に
# Windows で比べると偽の回帰が出るため除く。metric 名は「<ベンチ名>_」で始まる命名規約に従う
# （bench_metric_prefixes_jq が一覧から jq 用の接頭辞配列を作る）。
BENCH_UNIX_ONLY_NAMES="plugin_boundary plugin_boundary_list_images small_files"

# 実機前提ベンチ名（#1901・TASK-190 追補・REPAIR-8）: Linux 6.12 以上・非 root・非特権 user namespace・
# systemd-run --user を要し、GitHub ホステッド runner では動かない。bench-check / bench-baseline / CI では
# 実行せず（BENCH_NAMES・BENCH_STAGED_NAMES・BENCH_UNIX_ONLY_NAMES に入れない）、人が実機で採った結果を
# make bench-check-manual で benches/baseline-manual.json と比べる。このため CI では回帰を検出できない
# （docs/design/bench-calibration.md「CI の扱いの決定」。暫定方針で、(c)/(d) へ変わったらここから
# BENCH_NAMES と BENCH_STAGED_NAMES へ移し、基準値を共有の baseline.json へ移す）。
# shellcheck disable=SC2034 # テストとドキュメントの整合照合が参照する
BENCH_MANUAL_NAMES="startup_latency"
# 実機前提ベンチの metric 名（完全一致で扱う。名前が "<ベンチ名>_" で始まる規約に従わないため接頭辞は使わない）。
BENCH_MANUAL_METRICS="startup_create_to_supervisor_ok_p95_ms"

bench_names_for_os() {
  if [ "${OS:-}" = "Windows_NT" ]; then
    local n out=""
    for n in ${BENCH_NAMES}; do
      case " ${BENCH_UNIX_ONLY_NAMES} " in
        *" ${n} "*) ;;
        *) out="${out:+${out} }${n}" ;;
      esac
    done
    echo "${out}"
  else
    echo "${BENCH_NAMES}"
  fi
}

# bench_metric_prefixes_jq: Unix 限定ベンチの metric 名接頭辞（"<名>_"）を JSON 配列で返す
# （Windows で baseline・metrics から除く jq の入力。接頭辞をスクリプトへ直書きしない）。
bench_metric_prefixes_jq() {
  local n out=""
  for n in ${BENCH_UNIX_ONLY_NAMES}; do
    out="${out:+${out},}\"${n}_\""
  done
  echo "[${out}]"
}

# bench_manual_metrics_jq: 実機前提 metric 名を JSON 配列で返す（metrics の絞り込み・結果検査の jq の入力）。
bench_manual_metrics_jq() {
  local m out=""
  for m in ${BENCH_MANUAL_METRICS}; do
    out="${out:+${out},}\"${m}\""
  done
  echo "[${out}]"
}

# bench_filter_metrics_for_run <入力 metrics.json> <出力先>: その実行で測らない metric を .metrics から除いた
# JSON を書く。除くのは実機前提 metric（全 OS）と、Windows（OS=Windows_NT）では Unix 限定ベンチの metric。
# bench-baseline.sh が generate_baseline.sh へ渡す metrics の作成に使う（metrics と results の集合を一致させる）。
bench_filter_metrics_for_run() {
  local in="$1" out="$2" prefixes="[]"
  if [ "${OS:-}" = "Windows_NT" ]; then
    prefixes="$(bench_metric_prefixes_jq)"
  fi
  jq --argjson p "${prefixes}" --argjson m "$(bench_manual_metrics_jq)" \
    '.metrics |= with_entries(select(.key as $k | (($m | index($k)) == null) and ($p | any(. as $x | $k | startswith($x)) | not)))' \
    "${in}" >"${out}"
}

# bench_args_for <ベンチ名> <作業用ルート>: make bench-check / bench-baseline が各ベンチへ渡す引数を 1 行ずつ出す
# （両ターゲットの値の乖離を防ぐため 1 か所で決める）。
# small_files（IO-6・TASK-189 追補・#1899）は計測負荷を決める引数をすべて明示し、将来の既定値変更で
# ゲートの負荷が黙って変わらないようにする。
#   --count 2000          ハーネス CLI の下限（MIN_COUNT。IO-6 の 2,000 件）。CI の所要時間を小さく保つ
#   --batch-size 1        1 ファイルごとに永続化（IO-2 の保証内。flush-every-k は保証外かつ Linux 限定のため使わない）
#   --file-size 2         既定値を明示
#   --layout tree         3〜5 万件の実測（#107）で auto が選ぶ配置形にそろえ、平置きのディレクトリ走査が区間を支配しない
#   --config bind         ラベルのみ（挙動は変えない）
#   --trials 3            中央値が 1 回の外れ値に耐える最小数
#   --trial-timeout-secs 120 / --timeout-secs 300  ジョブ上限（15 分）より十分短く切る（REPAIR-5）
# 3〜5 万件の実測は人間がハーネスを直接実行する（#107）。他のベンチは引数なし。
bench_args_for() {
  case "$1" in
    small_files)
      printf '%s\n' --count 2000 --batch-size 1 --file-size 2 --layout tree --config bind \
        --trials 3 --trial-timeout-secs 120 --timeout-secs 300 --root "$2"
      ;;
    *) ;;
  esac
}
