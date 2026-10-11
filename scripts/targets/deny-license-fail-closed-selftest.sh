#!/usr/bin/env bash
# deny.toml のライセンス fail-closed 自己テスト（make deny-license-fail-closed-selftest。TASK-90.2・#127・
# OSS-4・OSS-5・REPAIR-9）。
#
# 使い捨て workspace と本物の deny.toml で照合し、本番の依存・lock は変えない。`make ci` には含めない。
# CI は platform-ci（ubuntu）が実行する。cargo-deny 未導入なら deny と同じ版を導入してから
# scripts/deny-license-fail-closed-selftest.sh を実行する。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

export PATH="${HOME}/.cargo/bin:${PATH}"
ensure_cargo_deny
exec bash scripts/deny-license-fail-closed-selftest.sh
