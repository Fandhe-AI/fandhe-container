#!/usr/bin/env bash
# plugin 起動対象の構築口 `PluginLaunchTarget::from_verified_file` を呼ぶのが core の変換と許可した
# 試験コードだけであることの機械判定（make check-launch-target。PLUG-11・REPAIR-1・#1857）。
# 実体は scripts/check-plugin-launch-target-construction.sh。cargo を使わないソースの走査のため
# skip_unless_workspace は使わない（skip せず常に判定する）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

exec "${DIR}/../check-plugin-launch-target-construction.sh" --root "$(pwd)"
