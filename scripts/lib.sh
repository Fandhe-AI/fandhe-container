#!/usr/bin/env bash
# Shared helpers for scripts/targets/*.sh and scripts/{help,with-tools,with-workspace}.sh.
# Source it, do not execute it:
#   DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # scripts/ or scripts/targets/
#   source "${DIR}/../lib.sh"                              # (scripts/targets/); "${DIR}/lib.sh" in scripts/
#
# The caller inherits `set -euo pipefail`, so a failing command stops the script and its
# exit status reaches the caller (a human, `make` or CI) unchanged.
# Sourcing also moves the working directory to the repository root so that the relative
# paths used by the targets behave the same as under `make` (which runs at the root).
set -euo pipefail

_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${_lib_dir}/.." && pwd)"
# shellcheck disable=SC2034 # used by the sourcing scripts
readonly ROOT_DIR
cd "${ROOT_DIR}"

# shellcheck source=./versions.sh
source "${_lib_dir}/versions.sh"

# Print the command (like make does for a non-silent recipe line) and run it.
run() {
  printf '%s\n' "$*"
  "$@"
}

# require_cmd <name>: fail with a clear message when <name> is not on PATH. Never installs.
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

# has_cargo / has_members: Cargo.toml exists and at least one member crate exists (virtual workspaces
# with `members = []` make fmt/clippy/test/doc/deny fail with "no packages", so those targets skip).
has_cargo() { [ -f Cargo.toml ]; }
has_members() { compgen -G 'crates/*/Cargo.toml' >/dev/null; }

# skip_unless_workspace <target>: print a skip notice and exit 0 unless Cargo.toml and a member crate exist.
skip_unless_workspace() {
  if ! has_cargo || ! has_members; then
    echo "skip: Cargo.toml is missing or the workspace has no member crate, skipping $1"
    exit 0
  fi
}

# validate_timeout <NAME> <value>: integer 1..999999 or exit 2 (0 would disable `timeout`).
validate_timeout() {
  local name="$1" t="$2"
  case "$t" in '' | *[!0-9]* | ???????*) t=invalid ;; esac
  if [ "$t" = invalid ] || [ "$t" -eq 0 ]; then
    echo "error: invalid-argument: ${name} must be an integer from 1 to 999999 (seconds)" >&2
    exit 2
  fi
}

# require_timeout_cmd: coreutils `timeout` is needed by the real-machine measurement targets.
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
