#!/usr/bin/env bash
# plugin 境界ベンチ（代表操作 A・B。TASK-113.1〜113.3）の実行（make bench-plugin-boundary）。
#
# Δp50 と CORE-10 の Linux 実機値（0.290〜0.298 秒）に対する割合を stderr へログ出力する（PLUG-5・CORE-10）。
# 基準値との比較はしない（plugin 系 metric は baseline.json 未登録。実測基準値は TASK-88.h1・TASK-113.h1 で確定）。
# 一時ディレクトリは trap で必ず削除する。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace bench-plugin-boundary
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
cargo bench -p fandhe-container-benches --bench plugin_boundary -- --output "${tmp}/a.json"
cargo bench -p fandhe-container-benches --bench plugin_boundary_list_images -- --output "${tmp}/b.json" >/dev/null
