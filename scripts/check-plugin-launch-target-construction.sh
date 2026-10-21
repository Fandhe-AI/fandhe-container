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
#               （構築口の定義と plugin crate 自身の単体テスト）。あわせて試験領域外で、戻り値に Self /
#               PluginLaunchTarget を含む fn がちょうど 1 件（from_verified_file）・構造体リテラル（`Self {` /
#               `PluginLaunchTarget {`）がちょうど 2 件（その本体の cfg(unix) / cfg(not(unix)) の 2 分岐）。
#               外部ファイルの子モジュール（`mod x;`）・`include!`・`#[path]` は禁止（private フィールドに触れられるため）
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
# コメントは飛ばす）。属性は Rust の字句（文字列・raw 文字列・ブロックコメント・文字リテラル）の外にあるものだけを認める。
# 文字列やコメントの中の属性は無視し、ファイル末で文字列・ブロックコメントが閉じない場合は判定不能として NG にする。項目が 1 行で終わるもの（`;` 終わり・括弧が 1 行で閉じるもの）はその行だけ。
# それ以外は、次の column 0 の行のうち空行・`//`・`)`・`]` で始まらない最初の行まで。その行が `}` で始まれば
# 含めて閉じ、別の項目なら手前で閉じる。ファイル先頭の `#![cfg(test)]`・`#![cfg(all(test` はファイル全体。
# `cfg(any(test, ...))` は試験専用とみなさない。column 0 の属性が同じ行で閉じ、その後ろにコードが続く行
# （`#[cfg(test)] fn a() {}` 等）は試験領域を開かず、未分類として失敗にする。この扱いと rustfmt の整形
# （column 0 の規則）を前提に、判定の誤りは領域を早く閉じる方向（失敗側）にしか働かない。
#
# fail-closed（非 0 で終了）: 定義が 1 件でない・definition / production のファイルが無い・件数の不一致・
# 走査対象が読めない・*.rs が通常ファイルでない・走査件数 0・crates が無い・構築関数 / 構造体リテラルの件数不一致・
# 未分類の属性行・symlink のディレクトリ（find が辿らず走査できないため）。
#
# 限界（REPAIR-3。実装済みを装わない）: `include!` と `#[path]` で走査範囲の外のファイルを取り込む場合と、
# build.rs が OUT_DIR に生成するコードは見ない。定義ファイル内の構築は関数の戻り値とリテラルの件数で判定し、
# 型エイリアス（`type X = PluginLaunchTarget;`）経由のリテラルと、既存値のフィールド書き換え（`&mut self`）は見ない。
# 試験領域の判定は rustfmt の整形（column 0 の規則）が前提。
#
# 使い方: check-plugin-launch-target-construction.sh [--root <dir>]（既定はこのスクリプトの 1 つ上）。
# 終了コード: 0 合格 / 1 違反または fail-closed / 2 usage。bash 3.2・BSD / Git Bash でも動く書き方にする。
# 自己テスト: scripts/check-plugin-launch-target-construction-selftest.sh
set -euo pipefail
export LC_ALL=C

DEF_FILE="crates/plugin/src/lifecycle/launch_target.rs"
PROD_FILE="crates/core/src/plugin.rs"
# 定義ファイルの試験領域外の期待件数。構築関数は from_verified_file の 1 件、構造体リテラルはその本体の
# `#[cfg(unix)]` / `#[cfg(not(unix))]` の 2 分岐の各 1 件。分岐を変えたらレビューつきで本定数を更新する。
EXPECTED_CONSTRUCTORS=1
EXPECTED_LITERALS=2

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
  # symlink のディレクトリは find が辿らず走査できないため、あれば失敗にする（*.rs の symlink は -f で実体を読む）。
  while IFS= read -r -d '' l; do
    if [ -d "${l}" ]; then ng "${l#"${root}"/}: symlinked directory is not scanned"; fi
  done < <(find "${d}" \( -type d \( -name target -o -name .git \) -prune \) -o -type l -print0)
done <<EOF
${dirs}
EOF

# 1 ファイルを走査し「行番号 種別」を出す。種別: D=試験領域外の定義 / P=試験領域外の一致 / T=試験領域内の一致。
# shellcheck disable=SC2016  # awk プログラムは単引用符で渡す（シェル展開しない）
scan_awk='
# Rust の字句（文字列・raw 文字列・ブロックコメント〔入れ子可〕・行コメント・文字リテラル）を
# 行をまたいで追跡し、コード以外の文字を空白に置き換えた行を返す。属性・括弧・column 0 の判定は
# この置換後の行で行い、文字列やコメントの中に書かれた属性で試験領域を開かせない（fail-closed）。
function lex(line,    out, n, i, c, c2, j, k, m, prev) {
  out = ""
  n = length(line)
  i = 1
  while (i <= n) {
    c = substr(line, i, 1)
    c2 = substr(line, i, 2)
    if (mode == 1) {
      if (c2 == "/*") { depth++; out = out "  "; i += 2 }
      else if (c2 == "*/") { depth--; out = out "  "; i += 2; if (depth == 0) mode = 0 }
      else { out = out " "; i++ }
    } else if (mode == 2) {
      if (c == "\\") { out = out "  "; i += 2 }
      else if (c == "\"") { out = out " "; i++; mode = 0 }
      else { out = out " "; i++ }
    } else if (mode == 3) {
      if (c == "\"" && substr(line, i + 1, rawhash) == rawpat) {
        out = out " " substr(spaces, 1, rawhash); i += 1 + rawhash; mode = 0
      } else { out = out " "; i++ }
    } else {
      if (c2 == "//") { out = out substr(spaces, 1, n - i + 1); i = n + 1 }
      else if (c2 == "/*") { mode = 1; depth = 1; out = out "  "; i += 2 }
      else if (c == "\"") { mode = 2; out = out " "; i++ }
      else if (c == "r" || (c == "b" && substr(line, i + 1, 1) == "r")) {
        prev = (i > 1) ? substr(line, i - 1, 1) : ""
        j = (c == "b") ? i + 2 : i + 1
        k = j
        while (substr(line, k, 1) == "#") k++
        if (prev !~ /[A-Za-z0-9_]/ && substr(line, k, 1) == "\"") {
          rawhash = k - j
          rawpat = substr("################################################################", 1, rawhash)
          mode = 3
          out = out substr(spaces, 1, k - i + 1)
          i = k + 1
        } else { out = out c; i++ }
      } else if (c == "\047") {
        # 文字リテラル（x・改行の escape 付き）は読み飛ばし、ライフタイムはそのまま進める
        if (substr(line, i + 1, 1) == "\\") {
          m = index(substr(line, i + 2), "\047")
          if (m > 0) { out = out substr(spaces, 1, m + 2); i += m + 2; continue }
        } else if (substr(line, i + 2, 1) == "\047" && substr(line, i + 1, 1) != "\047") {
          out = out "   "; i += 3; continue
        }
        out = out c; i++
      } else { out = out c; i++ }
    }
  }
  return out
}
function strip_cr() { sub(/\r$/, "", $0) }
# column 0 の属性が同じ行で閉じ、閉じ括弧の後ろに空白以外（コード）が残るなら 1。
# 試験属性と項目が 1 行に詰まった行を試験領域の判定に混ぜないため（未分類として失敗させる）。
function attr_trailing(s,    i, n, d, c) {
  if (s !~ /^#!?\[/) return 0
  n = length(s); d = 0
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "[") d++
    else if (c == "]") { d--; if (d == 0) return (substr(s, i + 1) !~ /^[ \t]*$/) }
  }
  return 0
}
function count_ch(s, ch,    t) { t = s; return gsub(ch, "", t) }
BEGIN { all_test = 0; is_fvf = 0; fvf = 0; fvf_d = 0; fvf_seen = 0; cur_fn = ""; state = 0; mode = 0; depth = 0; rawhash = 0; rawpat = ""; spaces = sprintf("%400s", "") }
{
  strip_cr()
  orig = $0
  line = lex(orig)
  a_trail = attr_trailing(line)
  if (a_trail) print NR, "A"
  if (!a_trail && line ~ /^#!\[cfg\((test\)|all\(test[,)])/) all_test = 1
  # state: 0=通常 1=試験属性の直後（項目待ち） 2=複数行の試験項目の中
  if (state == 2) {
    if (line ~ /^[^ \t]/ && line !~ /^\/\// && line !~ /^\)/ && line !~ /^\]/) {
      if (line ~ /^\}/) { in_test_line = 1; state = 0 }
      else { state = 0; in_test_line = 0 }
    } else { in_test_line = 1 }
  } else { in_test_line = 0 }
  if (state == 0 && !a_trail && line ~ /^#\[cfg\((test\)\]|all\(test[,)])/ ) {
    state = 1
    in_test_line = 0
  } else if (state == 1) {
    if ((line ~ /^#\[/ && !a_trail) || line ~ /^[ \t]*$/ || line ~ /^\/\//) {
      in_test_line = 0
    } else {
      in_test_line = 1
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      if (line ~ /;[ \t]*$/ || (opens > 0 && opens == closes)) state = 0
      else state = 2
    }
  }
  region = (all_test || in_test_line)
  if (is_def && !region) {
    # 定義ファイルの試験領域外: 構築関数（戻り値に Self / PluginLaunchTarget を含む fn）・構造体リテラル・
    # 外部ファイルの子モジュールを数える。private フィールドへ触れられるのはこのファイルの中だけのため、
    # from_verified_file 以外の構築は件数と名前で失敗させる。
    if (match(line, /(^|[^A-Za-z0-9_])fn[ \t]+[A-Za-z0-9_]+/)) {
      t0 = substr(line, RSTART, RLENGTH)
      sub(/^.*fn[ \t]+/, "", t0)
      cur_fn = t0
    }
    if (line ~ /(^|[^A-Za-z0-9_])fn[ \t]+from_verified_file([^A-Za-z0-9_]|$)/) { fvf = 1; fvf_d = 0; fvf_seen = 0 }
    in_fvf = 0
    if (fvf) {
      in_fvf = 1
      o = count_ch(line, "\\{"); c = count_ch(line, "\\}")
      fvf_d += o - c
      if (o > 0) fvf_seen = 1
      if (fvf_seen && fvf_d <= 0) fvf = 0
    }
    if (index(line, "->") > 0) {
      rs = line
      while ((pp = index(rs, "->")) > 0) rs = substr(rs, pp + 2)
      sub(/[{;].*/, "", rs)
      sub(/[ \t]where[ \t].*/, "", rs)
      gsub("\047[A-Za-z_]+", "", rs)
      gsub(/&[ \t]*(mut[ \t]+)?(Self|PluginLaunchTarget)/, "", rs)
      if (rs ~ /(^|[^A-Za-z0-9_])(Self|PluginLaunchTarget)([^A-Za-z0-9_]|$)/) print NR, "F", cur_fn
    }
    lt = line
    gsub(/(struct|enum|union|trait|impl|for)[ \t]+PluginLaunchTarget/, "X", lt)
    gsub(/->[ \t]*(Self|PluginLaunchTarget)/, "->X", lt)
    while (match(lt, /(^|[^A-Za-z0-9_])(Self|PluginLaunchTarget)[ \t]*\{/)) {
      print NR, "L", in_fvf
      lt = substr(lt, RSTART + RLENGTH)
    }
    if (line ~ /^[ \t]*(pub(\([^)]*\))?[ \t]+)?mod[ \t]+[A-Za-z0-9_]+[ \t]*;/ || line ~ /include!/ || line ~ /#\[[ \t]*path/) print NR, "M"
  }
  tmp = orig
  sub(/^[ \t]+/, "", tmp)
  if (tmp ~ /^\/\//) next
  if (orig !~ /(^|[^A-Za-z0-9_])from_verified_file([^A-Za-z0-9_]|$)/) next
  if (!region && orig ~ /(^|[^A-Za-z0-9_])fn[ \t]+from_verified_file([^A-Za-z0-9_]|$)/) print NR, "D"
  else if (region) print NR, "T"
  else print NR, "P"
}
END { if (mode != 0) print NR, "U" }
'

scanned=0
def_count=0
def_in_def_file=0
prod_p=0
prod_t=0
ctor_count=0
literal_count=0
while IFS= read -r -d '' f; do
  rel="${f#"${root}"/}"
  if [ ! -f "${f}" ] || [ ! -r "${f}" ]; then
    ng "${rel}: not a readable regular file"
    continue
  fi
  scanned=$((scanned + 1))
  out="$(awk -v is_def="$([ "${rel}" = "${DEF_FILE}" ] && echo 1 || echo 0)" "${scan_awk}" "${f}")" || {
    ng "${rel}: scan failed"
    continue
  }
  [ -n "${out}" ] || continue
  while read -r ln kind extra; do
    case "${kind}" in
      U) ng "${rel}: unterminated string or block comment (cannot classify test regions)" ;;
      A)
        ng "${rel}:${ln}: attribute followed by code on the same line (cannot classify test regions)"
        continue
        ;;
      F)
        ctor_count=$((ctor_count + 1))
        [ "${extra}" = "from_verified_file" ] || ng "${rel}:${ln}: function '${extra}' returns PluginLaunchTarget (only from_verified_file may construct it)"
        continue
        ;;
      L)
        literal_count=$((literal_count + 1))
        [ "${extra}" = "1" ] || ng "${rel}:${ln}: PluginLaunchTarget constructed by struct literal outside from_verified_file"
        continue
        ;;
      M)
        ng "${rel}:${ln}: out-of-file module, include! or #[path] in the definition file is not allowed"
        continue
        ;;
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
if [ "${ctor_count}" -ne "${EXPECTED_CONSTRUCTORS}" ]; then
  ng "${DEF_FILE}: expected ${EXPECTED_CONSTRUCTORS} function returning PluginLaunchTarget outside test regions, found ${ctor_count}"
fi
if [ "${literal_count}" -ne "${EXPECTED_LITERALS}" ]; then
  ng "${DEF_FILE}: expected ${EXPECTED_LITERALS} PluginLaunchTarget struct literals outside test regions, found ${literal_count}"
fi
if [ "${prod_p}" -ne 1 ]; then
  ng "${PROD_FILE}: expected exactly one production use of from_verified_file, found ${prod_p}"
fi

if [ "${fail}" -ne 0 ]; then
  exit 1
fi
echo "OK: from_verified_file is used only by the core conversion and allowed test code (scanned ${scanned} files, ${ctor_count} constructor, ${literal_count} literals)"
