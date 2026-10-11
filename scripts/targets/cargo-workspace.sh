#!/usr/bin/env bash
# workspace 全体への cargo ゲート（make fmt / fmt-check / lint / test / doc）。
#
# 使い方: scripts/targets/cargo-workspace.sh <fmt|fmt-check|lint|test|doc>
# Cargo.toml 未追加、または member crate が無い間は skip して成功終了する（冪等セルフヒール）。
# すべて既定 feature のみで検証する（`--all-features` 込みの検証は CI の rust-ci ジョブが担う。
# CI の platform-ci ジョブは lint / test / doc と同一コマンドを実行する）。
# doc は rustdoc の警告（壊れた intra-doc リンク・private 項目へのリンク等）を -D warnings で fail させる
# （REPAIR-3・REPAIR-7・#1300）。cfg(target_os) 限定の項目へのリンクは他 OS で解決できず fail するため、
# doc コメントではリンクにせずコード表記にする。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ "$#" -ne 1 ]; then
  echo "usage: cargo-workspace.sh <fmt|fmt-check|lint|test|doc>" >&2
  exit 2
fi
name="$1"
skip_unless_workspace "${name}"
case "${name}" in
  fmt) run cargo fmt --all ;;
  fmt-check) run cargo fmt --all --check ;;
  lint) run cargo clippy --workspace --all-targets -- -D warnings ;;
  test) run cargo test --workspace ;;
  doc)
    echo 'RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps'
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
    ;;
  *)
    echo "usage: cargo-workspace.sh <fmt|fmt-check|lint|test|doc>" >&2
    exit 2
    ;;
esac
