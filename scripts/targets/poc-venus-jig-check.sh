#!/usr/bin/env bash
# venus 試験治具（workspace 外の独立 PoC パッケージ poc/venus-decoder/jig）の fmt-check・clippy・test
# （make poc-venus-jig-check。GPU-6・TASK-172.4・#888）。
#
# `make ci` には含めない。CI は platform-ci ジョブ（PR は ubuntu・main は 3 OS）が実行し、plugin-macos 側の変更で
# 治具が壊れたことを検出する。実機前提テストは #[ignore] で分離済み。clippy / test は --locked で治具の
# Cargo.lock を固定する（ルート側の依存変更で lock が黙って再解決され、監査していない版でビルドされるのを防ぐ）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

manifest="poc/venus-decoder/jig/Cargo.toml"
run cargo fmt --manifest-path "${manifest}" --check
run cargo clippy --manifest-path "${manifest}" --locked --all-targets -- -D warnings
run cargo test --manifest-path "${manifest}" --locked
