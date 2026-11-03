#!/usr/bin/env bash
# CLI の実行ファイルの既定 / plugin 除外構成の release ビルドと成果物サイズの記録（make plugin-feature-size。
# PLUG-3・TASK-111.2・#263・#3204）。
#
# CI の bench-regression ジョブ（ubuntu-latest 単独。サイズは OS 間で比較できないため `.exe` の扱いは不要）が実行し、
# stdout の markdown 表を $GITHUB_STEP_SUMMARY へ追記する。`make ci` には含めない。記録文書: docs/design/plugin-feature-size-record.md
# - 計測対象は `fandhe-container-cli` の実行ファイル `fandhe-container`（#3204）: cli の `plugin` feature（既定で有効）が
#   fandhe-container-plugin と core の `plugin` を連動して有効にし、supervisor は core を default-features = false で引く
#   ため、`--no-default-features` で plugin crate をリンクしない実行ファイルを作れる（#2170 の rlib 計測から切り替え）。
# - ゲート配下は現状再エクスポートと小さな配線だけで、実行ファイルの差は僅少。軽量化効果の実測ではなく、TASK-109・TASK-110 で
#   ゲート配下に実装が入った後に再計測するための土台である（REPAIR-3: 実装済みを装わない）。
# - サイズ差に閾値は設けない（ノイズ程度の差で誤検出するため）。ビルド失敗・実行ファイル不在・不正値・除外構成での
#   plugin crate の依存木 / rlib の出現は fail-closed で非ゼロ終了する。
# - target dir は mktemp -d 配下（リポ内の target/ とキャッシュに影響しない）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace plugin-feature-size
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT
tree="$(cargo tree -p fandhe-container-cli --no-default-features -e normal --target all)" || {
  echo "NG: cargo tree failed" >&2
  exit 1
}
if printf '%s\n' "${tree}" | grep -q 'fandhe-container-plugin'; then
  echo "NG: the plugin-disabled CLI dependency tree contains fandhe-container-plugin" >&2
  exit 1
fi
t0="${SECONDS}"
CARGO_TARGET_DIR="${root}/default" cargo build --release -p fandhe-container-cli >&2
t1="${SECONDS}"
CARGO_TARGET_DIR="${root}/no-plugin" cargo build --release -p fandhe-container-cli --no-default-features >&2
t2="${SECONDS}"
size_of() {
  [ -f "$1" ] || {
    echo "NG: file not found: $1" >&2
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
exe_def="$(size_of "${root}/default/release/fandhe-container")"
exe_np="$(size_of "${root}/no-plugin/release/fandhe-container")"
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
diff=$((exe_def - exe_np))
pct="$(awk -v d="${diff}" -v t="${exe_def}" 'BEGIN { printf "%.2f", d * 100 / t }')"
echo "### plugin feature size record (PLUG-3, TASK-111.2, #3204)"
echo
echo "- rustc: $(rustc --version)"
echo "- platform: $(uname -sm)"
echo "- profile: release (CLI executable size: fandhe-container)"
echo "- build time: default $((t1 - t0)) s, no-default-features $((t2 - t1)) s"
echo
echo "| build | CLI executable (bytes) |"
echo "| ----- | ---------------------- |"
echo "| default | ${exe_def} |"
echo "| --no-default-features | ${exe_np} |"
echo
echo "- difference (default - no-default-features): ${diff} bytes (${pct} %)"
echo "- note: the plugin rlib exists only in the default build (intermediate artifact, ${plugin_def} bytes); it is absent from the no-default-features build."
echo "- note: the gated code is re-exports and small wiring only, so the difference is small. This is not a measurement of the weight-saving effect; re-measure after TASK-109 and TASK-110 put implementations behind the gate."
