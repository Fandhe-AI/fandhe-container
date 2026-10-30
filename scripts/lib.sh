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

# int_in_range <値> <最小> <最大>: 値が「数字だけ・符号なし・9 桁以下」の整数で、最小〜最大に収まれば 0、それ以外は 1 を返す。
# 何も出力せず exit もしない純関数（bash 3.2 でも動く。`[[ =~ ]]` は使わない）。数値引数の構文と範囲判定の共通部で、
# validate_timeout・run_limited と guest/kernel/build.sh・scripts/build-guest-initrd.sh・
# scripts/generate-third-party-licenses.sh の数値オプション検査が使う（REPAIR-1・REPAIR-5）。範囲はオプションごとの意味で
# 異なるため揃えない。終了コードの整理: 引数エラーは呼び出し側が exit 2、run_limited の呼び出し誤りは 125（内部の誤用）。
int_in_range() {
  case "$1" in '' | *[!0-9]* | ??????????*) return 1 ;; esac
  # 先頭ゼロは 8 進と解釈されるため、比較前に取り除いて 10 進にそろえる（08 のエラー、07 の誤受理の防止）。
  local v="$1"
  while [ "${#v}" -gt 1 ] && [ "${v#0}" != "${v}" ]; do v="${v#0}"; done
  [ "${v}" -ge "$2" ] && [ "${v}" -le "$3" ]
}

# err_code <code> <message> / info_msg <message>: `error: code=<code> message=<英語>` と `info: <英語>` を stderr に出す。
# guest/kernel/build.sh・scripts/build-guest-initrd.sh・scripts/generate-third-party-licenses.sh が共有する（以前は各本に
# 重複。REPAIR-1・REPAIR-4）。`err` という名前は足さない（scripts/targets/*.sh が別書式の `err()` を source 後に自前で定義するため）。
err_code() {
  printf 'error: code=%s message=%s\n' "$1" "$2" >&2
}
info_msg() {
  printf 'info: %s\n' "$1" >&2
}

# acquire_output_lock <出力先>: 出力先の排他ロック（<出力先>.lock ディレクトリ。mkdir は不可分）を取る。
# 親ディレクトリを作れなければ bad-output、既にロックがあれば output-busy で exit 2。成功したら OUTPUT_LOCK_DIR に入れる。
# 異常終了（KILL 等）で残ったロックは手で削除する。呼び出し元の EXIT trap で release_output_lock を呼ぶこと。
OUTPUT_LOCK_DIR=""
acquire_output_lock() {
  mkdir -p "$(dirname "$1")" 2>/dev/null || { err_code bad-output "cannot create the parent of the output directory"; exit 2; }
  if mkdir "$1.lock" 2>/dev/null; then
    OUTPUT_LOCK_DIR="$1.lock"
  else
    err_code output-busy "another run holds $1.lock (remove it if no run is active)"
    exit 2
  fi
}

# release_output_lock: 自分が取った出力先のロックを外す。冪等。
release_output_lock() {
  [ -z "${OUTPUT_LOCK_DIR}" ] || rmdir "${OUTPUT_LOCK_DIR}" 2>/dev/null || true
  OUTPUT_LOCK_DIR=""
}

# validate_timeout <NAME> <value>: 1〜999999 の整数でなければ exit 2 する（0 は `timeout` を無効にするため拒否）。
validate_timeout() {
  local name="$1" t="$2"
  if ! int_in_range "$t" 1 999999; then
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
# Windows で比べると偽の回帰が出るため除く。wire 経路（#2074）は UDS 前提で Windows では動かない。metric 名は「<ベンチ名>_」で始まる命名規約に従う
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

# 実機前提ベンチの基準値・結果の環境を機械照合するための閉じた語彙（#2095・TASK-190 追補・REPAIR-8）。
# arch は結果 JSON の .arch（ハーネスの std::env::consts::ARCH。計測は Linux の x86_64 / aarch64 のみ）から取る。
# ホストの種類は、ハーネスが結果 JSON の .host_kind に載せる（Linux の /proc・/sys から自動判定。判定できなければ
# 語彙の外の unknown）。操作者は BENCH_HOST_KIND で語彙から指定でき、結果が unknown か無いときはこれが必須になる
# （bench_manual_resolve_host_kind）。語彙そのものの見直しは #230（TASK-88.h1）の担当。
# shellcheck disable=SC2034 # bench-check-manual / bench-baseline-manual とテストが参照する
BENCH_MANUAL_ARCHES="x86_64 aarch64"
# shellcheck disable=SC2034
BENCH_MANUAL_HOST_KINDS="bare-metal vm wsl2"
# bench-baseline-manual の既定の出力先。共有の benches/baseline-manual.json を誤って上書きしないよう target/ 配下にする。
# shellcheck disable=SC2034
BENCH_MANUAL_BASELINE_OUT_DEFAULT="target/bench-baseline-manual/baseline-manual.json"

# bench_manual_in_vocab <語> <語彙（空白区切り）>: 語が語彙に完全一致すれば 0。空・部分一致・空白入りは不一致。
bench_manual_in_vocab() {
  local w="$1" v
  [ -n "${w}" ] || return 1
  for v in $2; do
    [ "${w}" = "${v}" ] && return 0
  done
  return 1
}

# bench_manual_resolve_host_kind <結果 JSON>: BENCH_HOST_KIND（操作者の指定。空可）と結果の .host_kind から、使うホストの
# 種類を決めて BENCH_HOST_KIND に入れる（呼び出し元の変数を更新する。サブシェルでは呼ばない）。
#   - 結果の host_kind が語彙の外で unknown でもない → exit 2。無い・文字列でない・unknown → 結果からは決まらない
#   - 両方あって食い違う → exit 2（偽の合格・偽の回帰を避ける）。片方だけならそれを使う
# 決まらなければ BENCH_HOST_KIND は空のまま（呼び出し元が必要かどうかを判断する）。jq が必要。
bench_manual_resolve_host_kind() {
  local rk
  rk="$(jq -r '.host_kind // "" | if type == "string" then . else "" end' "$1")"
  if [ -n "${rk}" ] && [ "${rk}" != unknown ] && ! bench_manual_in_vocab "${rk}" "${BENCH_MANUAL_HOST_KINDS}"; then
    echo "error: invalid-input: results host_kind must be one of: ${BENCH_MANUAL_HOST_KINDS} unknown" >&2
    exit 2
  fi
  [ "${rk}" != unknown ] || rk=""
  if [ -n "${BENCH_HOST_KIND:-}" ] && [ -n "${rk}" ] && [ "${BENCH_HOST_KIND}" != "${rk}" ]; then
    echo "error: invalid-input: environment mismatch: BENCH_HOST_KIND ${BENCH_HOST_KIND} != results host_kind ${rk}" >&2
    exit 2
  fi
  BENCH_HOST_KIND="${BENCH_HOST_KIND:-${rk}}"
}

# bench_manual_check_input_file <パス>: 入力ファイルの検査（symlink 拒否・通常ファイル・1 MiB 以下）。
# 不正なら error: invalid-input を stderr に出して exit 2（呼び出し元スクリプトを終了させる）。
# bench-check-manual / bench-baseline-manual の両方が使い、結果の検査規則を一箇所に保つ。
bench_manual_check_input_file() {
  local path="$1" size
  if [ -L "${path}" ]; then
    echo "error: invalid-input: ${path} is a symlink, refusing to read" >&2
    exit 2
  fi
  if [ ! -f "${path}" ]; then
    echo "error: invalid-input: ${path} is not an existing regular file" >&2
    exit 2
  fi
  if ! size=$(wc -c <"${path}" 2>/dev/null | tr -d ' '); then
    echo "error: invalid-input: ${path} could not be read" >&2
    exit 2
  fi
  if [ "${size}" -gt 1048576 ]; then
    echo "error: invalid-input: ${path} exceeds 1048576 bytes" >&2
    exit 2
  fi
}

# bench_manual_validate_results <結果> <metrics.json>: 実機前提ベンチの結果の検査。実機前提 metric だけを持ち、
# 失敗・後始末の残りが無く、値は有限の正の数、単位は metrics.json の登録値と一致すること。不正なら exit 2。
bench_manual_validate_results() {
  local results="$1" metrics="$2" manual_json
  manual_json="$(bench_manual_metrics_jq)"
  if ! jq -e --argjson m "${manual_json}" \
    '.schema_version == 1
     and ((.metrics | type) == "object")
     and ((.metrics | keys | sort) == ($m | sort))
     and (((.failures.total // 0) | . == 0))
     and (((.leftover_ids // []) | length) == 0)' "${results}" >/dev/null 2>&1; then
    echo "error: invalid-input: results must have schema_version 1, exactly the manual-bench metrics ${manual_json}, no failures and no leftover ids (a failed run emits empty metrics)" >&2
    exit 2
  fi
  if ! jq -e --slurpfile reg "${metrics}" \
    '(.metrics | to_entries | length > 0)
     and (.metrics | to_entries | all(
       (.value | type) == "object"
       and ((.value.value | type) == "number")
       and (.value.value > 0 and .value.value < 1.7976931348623157e308)
       and ((.value.unit | type) == "string")
       and (.value.unit == ($reg[0].metrics[.key].unit // null))
     ))' "${results}" >/dev/null 2>&1; then
    echo "error: invalid-input: every metric in results must have a finite positive numeric value and a unit equal to the registered one in ${metrics}" >&2
    exit 2
  fi
}

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
#   --route wire          UDS 越しのワイヤー経路の files/s を測る（#2074。既定の server-api ではない）。Linux 限定のゲートのため問題なし（Windows は BENCH_UNIX_ONLY_NAMES で除外）
#   --trials 3            中央値が 1 回の外れ値に耐える最小数
#   --trial-timeout-secs 120 / --timeout-secs 300  ジョブ上限（15 分）より十分短く切る（REPAIR-5）
# 3〜5 万件の実測は人間がハーネスを直接実行する（#107）。他のベンチは引数なし。
bench_args_for() {
  case "$1" in
    small_files)
      printf '%s\n' --count 2000 --batch-size 1 --file-size 2 --layout tree --config bind --route wire \
        --trials 3 --trial-timeout-secs 120 --timeout-secs 300 --root "$2"
      ;;
    *) ;;
  esac
}

# run_limited <上限秒> <コマンド> [引数...]: 子プロセスを上限秒で打ち切って実行する（REPAIR-5）。
# macOS 標準に timeout が無いため見張り役方式で、guest/kernel/build.sh・scripts/build-guest-initrd.sh・
# scripts/generate-third-party-licenses.sh が共有する（以前は 3 本に重複していた。REPAIR-1）。回帰テストは
# scripts/lib-selftest.sh。シェル関数も子として渡せる。
#   前提: 呼び出し元が mktemp -d で作った private なディレクトリを RUN_LIMITED_DIR に設定する
#         （期限切れの印ファイルの置き場。共有の固定パスを使わない）。呼び出し元の EXIT trap で
#         run_limited_abort を呼ぶこと（異常終了時に実行中の子孫を回収する）。
#   戻り値: 子の終了コードをそのまま返す（0 を含む）。期限切れは 124。
#           上限秒が 1〜999999 の整数でない・RUN_LIMITED_DIR がディレクトリでない場合は実行せず 125。
#   期限切れ時: 子のプロセスグループ全体へ TERM → 2 秒後に KILL を送り、最大 5 秒グループの消滅を確認する。
_run_limited_child_pid=""
_run_limited_wd_pid=""
run_limited() {
  local limit="$1"
  shift
  if ! int_in_range "${limit}" 1 999999; then
    echo "error: run-limited: limit must be an integer from 1 to 999999 (seconds)" >&2
    return 125
  fi
  # int_in_range は先頭ゼロを許すが、下の見張り役の [ -lt ] は 8 進と解釈する（08・09 は異常終了、010 は 8 秒になる）。
  # 先頭ゼロを取り除いて 10 進にそろえる。
  while [ "${#limit}" -gt 1 ] && [ "${limit#0}" != "${limit}" ]; do limit="${limit#0}"; done
  if [ -z "${RUN_LIMITED_DIR:-}" ] || [ ! -d "${RUN_LIMITED_DIR}" ]; then
    echo "error: run-limited: RUN_LIMITED_DIR must be a directory" >&2
    return 125
  fi
  local marker="${RUN_LIMITED_DIR}/timeout-marker"
  rm -f "${marker}"
  # 子は job control で独立したプロセスグループにする（グループ宛ての kill で子孫ごと止める）。
  set -m
  "$@" &
  local pid=$!
  set +m
  _run_limited_child_pid="${pid}"
  (
    # 親の EXIT / TERM trap（呼び出し元の cleanup）を引き継がない
    trap - EXIT INT TERM
    i=0
    while [ "${i}" -lt "${limit}" ]; do
      sleep 1
      kill -0 "${pid}" 2>/dev/null || exit 0
      i=$((i + 1))
    done
    : >"${marker}"
    kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
    sleep 2
    kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
  ) &
  _run_limited_wd_pid=$!
  local rc=0
  wait "${pid}" || rc=$?
  if [ -e "${marker}" ]; then
    # 見張り役が KILL まで送り終えるのを待ち、グループの消滅を確認する。
    wait "${_run_limited_wd_pid}" 2>/dev/null || true
    local n=0
    while kill -0 -- "-${pid}" 2>/dev/null && [ "${n}" -lt 5 ]; do
      sleep 1
      n=$((n + 1))
    done
    _run_limited_wd_pid=""
    _run_limited_child_pid=""
    rm -f "${marker}"
    return 124
  fi
  kill -KILL "${_run_limited_wd_pid}" 2>/dev/null || true
  wait "${_run_limited_wd_pid}" 2>/dev/null || true
  _run_limited_wd_pid=""
  _run_limited_child_pid=""
  return "${rc}"
}

# run_limited_abort: 実行中の run_limited の子（プロセスグループ）と見張り役を止める。冪等。
# 呼び出し元の EXIT trap（cleanup）から呼ぶ。送る相手は run_limited 自身が起動したものだけ。
run_limited_abort() {
  if [ -n "${_run_limited_child_pid}" ]; then
    kill -TERM -- "-${_run_limited_child_pid}" 2>/dev/null || true
    kill -KILL -- "-${_run_limited_child_pid}" 2>/dev/null || true
  fi
  if [ -n "${_run_limited_wd_pid}" ]; then
    kill -KILL "${_run_limited_wd_pid}" 2>/dev/null || true
  fi
  _run_limited_child_pid=""
  _run_limited_wd_pid=""
}
