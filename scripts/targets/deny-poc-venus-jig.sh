#!/usr/bin/env bash
# venus 試験治具（ルート workspace 外。独自の Cargo.lock を持つ。GPU-6・TASK-172.4）の依存監査
# （make deny-poc-venus-jig）。
#
# ルートの deny.toml を共有し（--config）、ルートと同じ 4 種を --locked で検査する。cargo-deny 未導入なら
# deny と同じ版を自動導入する。引数の位置: cargo-deny 0.20.2 では --manifest-path・--config・--locked は
# `cargo deny` 直下の大域オプションで、`check` の後ろに置くと「unexpected argument '--config'」で失敗する。
# --show-stats で 4 種それぞれの ok / 件数を必ずログに出す。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

export PATH="${HOME}/.cargo/bin:${PATH}"
ensure_cargo_deny
cargo deny --manifest-path poc/venus-decoder/jig/Cargo.toml --config deny.toml --locked \
  check --show-stats advisories bans licenses sources
