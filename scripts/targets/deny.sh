#!/usr/bin/env bash
# cargo deny check advisories bans licenses sources（make deny）。ルート workspace と venus 試験治具の依存監査。
#
# cargo-deny 未導入なら CARGO_DENY_VERSION（scripts/versions.sh）で自動導入する。
# 治具の検査は deny-poc-venus-jig.sh（CI は rust-ci の deny がルートのみを見るため platform-ci が別に実行する）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if ! has_cargo || [ ! -f deny.toml ] || ! has_members; then
  echo "skip: Cargo.toml / deny.toml is missing or the workspace has no member crate, skipping deny"
  exit 0
fi
export PATH="${HOME}/.cargo/bin:${PATH}"
ensure_cargo_deny
cargo deny --locked check advisories bans licenses sources
"${DIR}/deny-poc-venus-jig.sh"
