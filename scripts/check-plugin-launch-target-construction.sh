#!/usr/bin/env bash
# plugin 起動対象 `PluginLaunchTarget::from_verified_file` の構築箇所の機械判定
# （make check-launch-target。PLUG-11・PLUG-3・REPAIR-1・REPAIR-12・TASK-122 追補・#1857・#1320）。
#
# 背景: plugin の起動 API は `PluginLaunchTarget` だけを受け取り、その構築口は
# `from_verified_file` の 1 つ。core -> plugin の依存方向のため構築口は公開 API で誰でも呼べる。
# #1320 のオーナー判断（2026-10-12）により、本番で呼んでよいのは core の
# `HashVerifiedPluginFile`（所有者・モード検証とハッシュ照合を通った fd）からの変換
# （crates/core/src/plugin.rs の `into_launch_target`）1 か所だけ。ほかで呼んでいないことを守る。
#
# 合格条件（許可リストはパスで持つ。下の判定規則を参照）:
#   definition  crates/plugin/src/lifecycle/launch_target.rs
#               試験領域の外の定義 `fn from_verified_file` が全体でちょうど 1 件。それ以外の一致は試験領域内のみ
#               （構築口の定義と plugin crate 自身の単体テスト）
#   production  crates/core/src/plugin.rs
#               試験領域の外の一致がちょうど 1 件・試験領域内は 0 件（#1320 の決定による唯一の本番の変換）
#   test-src    crates/plugin/src/ 配下（definition のファイルを除く）
#               一致はすべて試験領域内（lifecycle の単体テストは core 無しで起動対象を要る）
#   test-file   crates/plugin/tests/・crates/cli/tests/・benches/benches/・benches/tests/
#               制限しない（結合試験とベンチは製品のバイナリに入らない）
#   上記以外    一致が 1 件でもあれば NG
#
# 走査: <root>/crates・<root>/benches・<root>/poc 配下の *.rs（target・.git は除く）。識別子
# `from_verified_file` を語の境界つきで探す（`(` の有無は問わない。関数ポインタでの参照も拾う）。
# 行頭が `//` の行（`///`・`//!` を含む）は除く。行末コメントや文字列内の一致は数える（誤検出は失敗側）。
#
# 試験領域: column 0 の `#[cfg(test)]`・`#[cfg(all(test` が付いた項目（続く column 0 の他の属性・空行・
# コメントは飛ばす）。項目が 1 行で終わるもの（`;` 終わり・括弧が 1 行で閉じるもの）はその行だけ。
# それ以外は、次の column 0 の行のうち空行・`//`・`)`・`]` で始まらない最初の行まで。その行が `}` で始まれば
# 含めて閉じ、別の項目なら手前で閉じる。ファイル先頭の `#![cfg(test)]`・`#![cfg(all(test` はファイル全体。
# `cfg(any(test, ...))` は試験専用とみなさない。判定の誤りは領域を早く閉じる方向（失敗側）にしか働かない。
#
# fail-closed（非 0 で終了）: 定義が 1 件でない・definition / production のファイルが無い・件数の不一致・
# 走査対象が読めない・*.rs が通常ファイルでない・走査件数 0・crates が無い。
#
# 限界（REPAIR-3。実装済みを装わない）: `include!` と `#[path]` で走査範囲の外のファイルを取り込む場合と、
# build.rs が OUT_DIR に生成するコードは見ない。構造体リテラルでの構築は private フィールドで型が防ぐため、
# 走査するのは関数名だけ。試験領域の判定は rustfmt の整形（column 0 の規則）が前提。
#
# 使い方: check-plugin-launch-target-construction.sh [--root <dir>]（既定はこのスクリプトの 1 つ上）。
# 終了コード: 0 合格 / 1 違反または fail-closed / 2 usage。bash 3.2・BSD / Git Bash でも動く書き方にする。
# 自己テスト: scripts/check-plugin-launch-target-construction-selftest.sh
set -euo pipefail
export LC_ALL=C

DEF_FILE="crates/plugin/src/lifecycle/launch_target.rs"
PROD_FILE="crates/core/src/plugin.rs"

usage() {
  echo "usage: $0 [--root <dir>]" >&2
  exit 2
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || usage
      root="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

fail=0
ng() {
  echo "NG: $*" >&2
  fail=1
}

root="$(cd "${root}" 2>/dev/null && pwd)" || {
  echo "NG: root directory is not readable" >&2
  exit 1
}
if [ ! -d "${root}/crates" ] || [ ! -r "${root}/crates" ]; then
  echo "NG: crates directory not found or not readable" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
list="${work}/files"

# 走査対象の *.rs を NUL 区切りで集める。benches・poc は無ければ 0 件扱い。
dirs="${root}/crates"
[ -d "${root}/benches" ] && dirs="${dirs}
${root}/benches"
[ -d "${root}/poc" ] && dirs="${dirs}
${root}/poc"
: >"${list}"
while IFS= read -r d; do
  find "${d}" \( -type d \( -name target -o -name .git \) -prune \) -o -name '*.rs' -print0 >>"${list}" || {
    ng "failed to scan ${d#"${root}"/}"
  }
done <<EOF
${dirs}
EOF

# 1 ファイルを走査し「行番号 種別」を出す。種別: D=試験領域外の定義 / P=試験領域外の一致 / T=試験領域内の一致。
# shellcheck disable=SC2016  # awk プログラムは単引用符で渡す（シェル展開しない）
scan_awk='
function strip_cr() { sub(/\r$/, "", $0) }
BEGIN { all_test = 0; state = 0 }
{
  strip_cr()
  line = $0
  if (line ~ /^#!\[cfg\((test\)|all\(test[,)])/) all_test = 1
  # state: 0=通常 1=試験属性の直後（項目待ち） 2=複数行の試験項目の中
  if (state == 2) {
    if (line ~ /^[^ \t]/ && line !~ /^\/\// && line !~ /^\)/ && line !~ /^\]/) {
      if (line ~ /^\}/) { in_test_line = 1; state = 0 }
      else { state = 0; in_test_line = 0 }
    } else { in_test_line = 1 }
  } else { in_test_line = 0 }
  if (state == 0 && line ~ /^#\[cfg\((test\)\]|all\(test[,)])/ ) {
    state = 1
    in_test_line = 0
  } else if (state == 1) {
    if (line ~ /^#\[/ || line ~ /^[ \t]*$/ || line ~ /^\/\//) {
      in_test_line = 0
    } else {
      in_test_line = 1
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      if (line ~ /;[ \t]*$/ || (opens > 0 && opens == closes)) state = 0
      else state = 2
    }
  }
  tmp = line
  sub(/^[ \t]+/, "", tmp)
  if (tmp ~ /^\/\//) next
  if (line !~ /(^|[^A-Za-z0-9_])from_verified_file([^A-Za-z0-9_]|$)/) next
  region = (all_test || in_test_line)
  if (!region && line ~ /(^|[^A-Za-z0-9_])fn[ \t]+from_verified_file([^A-Za-z0-9_]|$)/) print NR, "D"
  else if (region) print NR, "T"
  else print NR, "P"
}
'

scanned=0
def_count=0
def_in_def_file=0
prod_p=0
prod_t=0
while IFS= read -r -d '' f; do
  rel="${f#"${root}"/}"
  if [ ! -f "${f}" ] || [ ! -r "${f}" ]; then
    ng "${rel}: not a readable regular file"
    continue
  fi
  scanned=$((scanned + 1))
  out="$(awk "${scan_awk}" "${f}")" || {
    ng "${rel}: scan failed"
    continue
  }
  [ -n "${out}" ] || continue
  while read -r ln kind; do
    case "${kind}" in
      D)
        def_count=$((def_count + 1))
        if [ "${rel}" = "${DEF_FILE}" ]; then def_in_def_file=$((def_in_def_file + 1)); else ng "${rel}:${ln}: from_verified_file defined outside the allowed file"; fi
        ;;
    esac
    case "${rel}" in
      "${DEF_FILE}")
        [ "${kind}" = "P" ] && ng "${rel}:${ln}: PluginLaunchTarget::from_verified_file used outside the allowed places"
        ;;
      "${PROD_FILE}")
        [ "${kind}" = "P" ] && prod_p=$((prod_p + 1))
        if [ "${kind}" = "T" ]; then
          prod_t=$((prod_t + 1))
          ng "${rel}:${ln}: PluginLaunchTarget::from_verified_file used outside the allowed places"
        fi
        ;;
      crates/plugin/src/*)
        [ "${kind}" = "P" ] && ng "${rel}:${ln}: PluginLaunchTarget::from_verified_file used outside the allowed places"
        ;;
      crates/plugin/tests/* | crates/cli/tests/* | benches/benches/* | benches/tests/*) ;;
      *)
        [ "${kind}" = "D" ] || ng "${rel}:${ln}: PluginLaunchTarget::from_verified_file used outside the allowed places"
        ;;
    esac
  done <<EOF
${out}
EOF
done <"${list}"

[ "${scanned}" -gt 0 ] || ng "no .rs files scanned"
[ -f "${root}/${DEF_FILE}" ] && [ -r "${root}/${DEF_FILE}" ] || ng "${DEF_FILE}: definition file not found or not readable"
[ -f "${root}/${PROD_FILE}" ] && [ -r "${root}/${PROD_FILE}" ] || ng "${PROD_FILE}: production conversion file not found or not readable"
if [ "${def_count}" -ne 1 ] || [ "${def_in_def_file}" -ne 1 ]; then
  ng "expected exactly one 'fn from_verified_file' definition in ${DEF_FILE}, found ${def_count}"
fi
if [ "${prod_p}" -ne 1 ]; then
  ng "${PROD_FILE}: expected exactly one production use of from_verified_file, found ${prod_p}"
fi

if [ "${fail}" -ne 0 ]; then
  exit 1
fi
echo "OK: from_verified_file is used only by the core conversion and allowed test code (scanned ${scanned} files)"
