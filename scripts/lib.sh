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
# 実ベンチを追加するときに足す場所（plugin 境界ベンチ〔TASK-113〕は登録済み。files/s・起動 p95 のベンチは
# 担当タスク未定で、docs/design/bench-calibration.md「既知の欠落」）。
# plugin 境界ベンチ（TASK-113.1〜113.3）は metric を benches/metrics.json に登録済みのため、ここにも同時に載せる
# （generate_baseline.sh は metrics.json と results の metric 集合が完全一致しないと exit 2）。
# Windows（OS=Windows_NT）は Unix ドメインソケット前提の plugin 境界ベンチを実行できないため regression_placeholder のみ。
BENCH_NAMES="regression_placeholder plugin_boundary plugin_boundary_list_images"
bench_names_for_os() {
  if [ "${OS:-}" = "Windows_NT" ]; then
    echo "regression_placeholder"
  else
    echo "${BENCH_NAMES}"
  fi
}
