#!/usr/bin/env bash
# cargo verify-project で workspace manifest の妥当性を検証する（make check-workspace-manifest）。
#
# `cargo verify-project` は member crate が 0 件の仮想 workspace でも成功する（fmt/clippy/test 等の
# 「対象パッケージが無い」失敗とは異なる）ため、member の有無ではなく Cargo.toml の有無のみで常時実行する。
# あわせて crates/supervisor が workspace members から外れていないことを検証する
# （外れると `cargo test --workspace` が crate 内の機械照合テストごと実行しなくなる。TASK-157.1・#235・SUP-1・REPAIR-12）。
# `cargo pkgid` は Cargo.lock の resolve グラフを参照し members を見ないため使わず、`cargo metadata --no-deps`
# の `manifest_path` が crates/supervisor/Cargo.toml であるパッケージの有無で照合する。Windows の cargo metadata は
# バックスラッシュ区切り（JSON 上は `\\`）を返すため、区切りは `/` と `\` の両方を受け付ける。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if ! has_cargo; then
  echo "skip: Cargo.toml is missing, skipping check-workspace-manifest"
  exit 0
fi

out="$(cargo verify-project 2>&1)" || {
  echo "${out}" >&2
  echo "NG: Cargo.toml is not a valid manifest for cargo" >&2
  exit 1
}
if ! printf '%s\n' "${out}" | grep -q '"success"'; then
  echo "${out}" >&2
  echo "NG: cargo verify-project did not report success" >&2
  exit 1
fi
[ -d crates/supervisor ] || {
  echo "NG: crates/supervisor does not exist" >&2
  exit 1
}
cargo metadata --no-deps --format-version 1 2>/dev/null |
  grep -Eq '"manifest_path"[[:space:]]*:[[:space:]]*"[^"]*[/\\]+crates[/\\]+supervisor[/\\]+Cargo\.toml"' || {
  echo "NG: crates/supervisor is not registered as a workspace member" >&2
  exit 1
}
