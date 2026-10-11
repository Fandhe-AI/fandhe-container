#!/usr/bin/env bash
# rustup（cargo）の導入を確認する（make rustup）。確認のみで自動導入はしない。
#
# 取得したインストーラを検証なしに実行する経路（curl | sh）を作らないため（security.md・
# サプライチェーン対策）。未導入時は公式手順を案内して停止する。toolchain は rust-toolchain.toml が単一真実源。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if ! command -v rustup >/dev/null 2>&1 && [ ! -x "${HOME}/.cargo/bin/rustup" ]; then
  echo "error: rustup not found. Install it from https://rustup.rs/ and re-run" >&2
  exit 1
fi
