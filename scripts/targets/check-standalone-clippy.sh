#!/usr/bin/env bash
# 試験用 feature 無効の -p 単独 lib/bin ビルドの clippy を全メンバーに回す（make check-standalone-clippy。
# #2640・REPAIR-7・REPAIR-12）。判定本体は scripts/check-standalone-clippy.sh。
# CLIPPY_TARGET=<triple> で `--target` を付ける（cross-target-check が macOS・Windows 向けに使う）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace check-standalone-clippy
require_cmd jq

exec "${DIR}/../check-standalone-clippy.sh"
