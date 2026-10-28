#!/usr/bin/env bash
# core の既定 / plugin 除外構成の release ビルドと成果物サイズの記録（make plugin-feature-size。
# PLUG-3・TASK-111.2・#263）。
#
# CI の bench-regression ジョブ（ubuntu-latest 単独。サイズは OS 間で比較できないため）が実行し、stdout の
# markdown 表を $GITHUB_STEP_SUMMARY へ追記する。`make ci` には含めない。記録文書: docs/design/plugin-feature-size-record.md
# - 計測対象は rlib（#2170 の判断）: CLI の bin はあるが、cli が fandhe-container-plugin に直接依存し、supervisor が
#   core を既定 feature で引くため、plugin なしの実行ファイルを作れない。実行ファイルへの切り替えは cli・supervisor の
#   feature 伝播の設計の後（REPAIR-3: 実装済みを装わない）。
# - `-p fandhe-container-core` で計測する: workspace 全体の `--no-default-features` は supervisor が core を既定
#   feature つきで依存するため feature 統合で plugin が再有効化され、除外ビルドにならない。
# - ゲート配下は現状再エクスポートのみで、core rlib の差は僅少（合計差は plugin rlib 自体が占める）。軽量化効果の実測ではない。
# - サイズ差に閾値は設けない（ノイズ程度の差で誤検出するため）。ビルド失敗・rlib 不在・不正値・除外構成での
#   plugin rlib 出現は fail-closed で非ゼロ終了する。
# - target dir は mktemp -d 配下（リポ内の target/ とキャッシュに影響しない）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace plugin-feature-size
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT
CARGO_TARGET_DIR="${root}/default" cargo build --release -p fandhe-container-core >&2
CARGO_TARGET_DIR="${root}/no-plugin" cargo build --release -p fandhe-container-core --no-default-features >&2
size_of() {
  [ -f "$1" ] || {
    echo "NG: rlib not found: $1" >&2
    exit 1
  }
  local n
  n="$(wc -c <"$1" | tr -d '[:space:]')"
  [[ "${n}" =~ ^[1-9][0-9]*$ ]] || {
    echo "NG: invalid size for $1: ${n}" >&2
    exit 1
  }
  echo "${n}"
}
core_def="$(size_of "${root}/default/release/libfandhe_container_core.rlib")"
core_np="$(size_of "${root}/no-plugin/release/libfandhe_container_core.rlib")"
plugin_def=""
for f in "${root}"/default/release/deps/libfandhe_container_plugin-*.rlib; do
  [ -e "${f}" ] || continue
  [ -z "${plugin_def}" ] || {
    echo "NG: multiple plugin rlibs in default build" >&2
    exit 1
  }
  plugin_def="$(size_of "${f}")"
done
[ -n "${plugin_def}" ] || {
  echo "NG: plugin rlib not found in default build" >&2
  exit 1
}
for f in "${root}"/no-plugin/release/deps/libfandhe_container_plugin-*.rlib; do
  [ ! -e "${f}" ] || {
    echo "NG: plugin rlib exists in no-default-features build: ${f}" >&2
    exit 1
  }
done
core_diff=$((core_def - core_np))
total_def=$((core_def + plugin_def))
diff=$((total_def - core_np))
pct="$(awk -v d="${diff}" -v t="${total_def}" 'BEGIN { printf "%.2f", d * 100 / t }')"
echo "### plugin feature size record (PLUG-3, TASK-111.2)"
echo
echo "- rustc: $(rustc --version)"
echo "- platform: $(uname -sm)"
echo "- profile: release (rlib size; see #2170 for why the executable is not measured)"
echo
echo "| build | core rlib (bytes) | plugin rlib (bytes) | total (bytes) |"
echo "| ----- | ----------------- | ------------------- | ------------- |"
echo "| default | ${core_def} | ${plugin_def} | ${total_def} |"
echo "| --no-default-features | ${core_np} | - (not built) | ${core_np} |"
echo
echo "- difference (default - no-default-features): ${diff} bytes (${pct} %)"
echo "- note: measured on rlibs because the CLI executable cannot be built without the plugin crate (cli depends on it directly and supervisor enables the core plugin feature); see #2170."
echo "- note: the total difference is dominated by the plugin rlib itself (an intermediate artifact, not linked size); the core rlib difference is ${core_diff} bytes because the gated code is re-exports only. This is not a measurement of the weight-saving effect."
