#!/usr/bin/env bash
# stack crate の依存方向の機械判定（make check-stack-deps。STACK-8・PLUG-1・PLUG-4・REPAIR-1・TASK-155・#4638・#4630）。
#
# `cargo metadata --format-version 1 --locked` の依存グラフ（全 kind・全ターゲット）で次を確かめる。
# 1. `fandhe-container-cli` が `fandhe-container-stack` に依存する（up の結線の辺。#4630 の承認範囲）
# 2. `fandhe-container-stack` はどの `fandhe-container-*` にも依存しない（特に core・cli への辺を張らない。
#    状態の読み取りの本番アダプタは cli 側に置く）
# 3. `fandhe-container-plugin` は cli にも stack にも依存しない（境界機構が上位 crate へ依存しない）
# 4. ワークスペース crate 間の依存に循環が無い（自己参照の dev-dependency は除く）
# metadata の失敗・空・パッケージの欠落は fail-closed（NG）。
#
# 入力: 環境変数 STACK_DEPS_CARGO（cargo の実体。既定 cargo。自己テストがスタブを差す）。jq と tsort が必要。
# 終了コード: 0=OK、1=NG、2=必須ツールの欠落。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${DIR}/lib.sh"

for tool in jq tsort; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "error: ${tool} is required but not found" >&2
    exit 2
  fi
done

cargo_bin="${STACK_DEPS_CARGO:-cargo}"
meta="$("${cargo_bin}" metadata --format-version 1 --locked)" || {
  echo "NG: cargo metadata failed" >&2
  exit 1
}

# from<TAB>to の辺（ワークスペース crate 同士。自己参照は除く。kind は区別せず全部）。
edges="$(printf '%s' "${meta}" | jq -r '
  . as $m
  | ($m.packages | map({key: .id, value: .name}) | from_entries) as $n
  | ($m.resolve.nodes // [])[]
  | ($n[.id] // "") as $from
  | select($from | startswith("fandhe-container"))
  | .deps[]
  | ($n[.pkg] // "") as $to
  | select($to | startswith("fandhe-container"))
  | select($from != $to)
  | "\($from)\t\($to)\t\([.dep_kinds[].kind] | map(. == null or . == "build") | any)"
' | sort -u)" || {
  echo "NG: cargo metadata output is not usable" >&2
  exit 1
}

names="$(printf '%s' "${meta}" | jq -r '.packages[].name' | sort -u)" || {
  echo "NG: cargo metadata output is not usable" >&2
  exit 1
}
for required in fandhe-container-cli fandhe-container-stack fandhe-container-plugin; do
  if ! printf '%s\n' "${names}" | grep -Fxq "${required}"; then
    echo "NG: package ${required} is missing from the metadata" >&2
    exit 1
  fi
done

has_edge() { printf '%s\n' "${edges}" | awk -F'\t' -v f="$1" -v t="$2" '$1 == f && $2 == t { found = 1 } END { exit !found }'; }
from_of() { printf '%s\n' "${edges}" | awk -F'\t' -v f="$1" '$1 == f'; }

status=0
if ! has_edge fandhe-container-cli fandhe-container-stack; then
  echo "NG: fandhe-container-cli does not depend on fandhe-container-stack" >&2
  status=1
fi
if [ -n "$(from_of fandhe-container-stack)" ]; then
  echo "NG: fandhe-container-stack must not depend on any fandhe-container-* crate" >&2
  status=1
fi
for bad in fandhe-container-cli fandhe-container-stack; do
  if has_edge fandhe-container-plugin "${bad}"; then
    echo "NG: fandhe-container-plugin must not depend on ${bad}" >&2
    status=1
  fi
done
# 循環は normal / build の辺だけで見る（dev-dependency の試験用の相互参照は cargo が許す）。
if [ -n "${edges}" ] && ! printf '%s\n' "${edges}" | awk -F'\t' '$3 == "true" { print $1, $2 }' | tsort >/dev/null 2>&1; then
  echo "NG: the workspace dependency graph contains a cycle" >&2
  status=1
fi
if [ "${status}" -ne 0 ]; then
  exit 1
fi
echo "OK: cli -> stack exists; stack depends on no workspace crate; plugin does not depend on cli / stack; no cycles"
