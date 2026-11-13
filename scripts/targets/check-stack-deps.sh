#!/usr/bin/env bash
# stack crate の依存方向の機械判定（make check-stack-deps。STACK-8・REPAIR-1・#4638）。
# 実体は scripts/check-stack-deps.sh。workspace が未整備なら skip する。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace check-stack-deps
exec "${DIR}/../check-stack-deps.sh"
