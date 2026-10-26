#!/usr/bin/env bash
# 実機前提テストの成功行を、試験ソースから導出して実行ログと双方向に照合する（#2768・REPAIR-7・REPAIR-12）。
#
# 役割: ci.yml の実機前提テスト（`harness = false` の `--ignored` 試験）で、成功行の文字列やシナリオの並びを
# 手書きすると、試験側の追加・文言変更に照合が追随せず、実行されなかった成功行を見逃す。そこで試験ソースの
# 文字列リテラルから期待行を導出し、ログの成功行と集合として一致することを fail-closed で確かめる。
# 呼び出し元: ci.yml の platform-ci（ubuntu）の各実機前提テストの実行ステップ。自己テストは
# scripts/check-success-lines-selftest.sh（`make check-success-lines-selftest`）。
#
# 使い方:
#   check-success-lines.sh --name <test> --src <file.rs>... --log <file> --select <ERE>
#     [--subst key=v1,v2]... [--subst-pos <v>]... [--subst-re key=<ERE>]... [--min N]
#     [--forbid <fixed>]... [--summary]
#   --select       導出元テンプレート（プレースホルダ込みのリテラル）とログの各行の両方に適用する ERE
#   --subst        名前つきプレースホルダ {key} の置換値（複数値は直積）
#   --subst-pos    位置プレースホルダ {} の置換値（出現順。テンプレートの {} の数と一致が必要）
#   --subst-re     実行時に決まる値の ERE（このテンプレートは行全体 ^...$ の正規表現で照合する）
#   --min          期待行の下限（既定 1。0 件は常に失敗）
#   --forbid       ログに出たら失敗する固定文字列（ignored・not applicable 等）
# 照合: (a) 期待行数 >= min (b) 期待行がすべてログにある (c) ログの選別行がすべて期待行 (d) forbid が無い。
# 終了コード: 0 一致 / 1 照合・導出・入力の失敗 / 2 usage 誤り。bash 3.2 互換（mapfile・連想配列を使わない）。
set -euo pipefail

usage() {
  echo "usage: $0 --name <test> --src <file.rs>... --log <file> --select <ERE> [--subst k=v1,v2]..." \
    "[--subst-pos v]... [--subst-re k=ERE]... [--min N] [--forbid str]... [--summary]" >&2
  exit 2
}

name=""
log=""
select_re=""
min=1
summary=0
srcs=()
forbids=()
substs=""
subst_pos=""
subst_re=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) [ $# -ge 2 ] || usage; name="$2"; shift 2 ;;
    --src) [ $# -ge 2 ] || usage; srcs+=("$2"); shift 2 ;;
    --log) [ $# -ge 2 ] || usage; log="$2"; shift 2 ;;
    --select) [ $# -ge 2 ] || usage; select_re="$2"; shift 2 ;;
    --subst) [ $# -ge 2 ] || usage; substs="${substs}$2"$'\n'; shift 2 ;;
    --subst-pos) [ $# -ge 2 ] || usage; subst_pos="${subst_pos}$2"$'\n'; shift 2 ;;
    --subst-re) [ $# -ge 2 ] || usage; subst_re="${subst_re}$2"$'\n'; shift 2 ;;
    --min) [ $# -ge 2 ] || usage; min="$2"; shift 2 ;;
    --forbid) [ $# -ge 2 ] || usage; forbids+=("$2"); shift 2 ;;
    --summary) summary=1; shift ;;
    *) usage ;;
  esac
done
{ [ -n "${name}" ] && [ -n "${log}" ] && [ -n "${select_re}" ] && [ "${#srcs[@]}" -gt 0 ]; } || usage
case "${name}" in *[!A-Za-z0-9_]*) usage ;; esac
case "${min}" in '' | *[!0-9]*) usage ;; esac

fail() {
  echo "::error::${name} $*" >&2
  exit 1
}

for f in "${srcs[@]}" "${log}"; do
  if [ -L "${f}" ] || [ ! -f "${f}" ]; then
    fail "input is not a regular file: ${f}"
  fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
tr -d '\r' < "${log}" > "${tmp}/log"

# 試験ソースの文字列リテラルから、選別に掛かるテンプレートを取り出して置換・展開する。
# 出力は "L<TAB>完全一致の行" または "R<TAB>行全体の ERE"。マクロ名には依存しない
# （rustfmt で複数行に折られた println! でもリテラルを拾う）。
cat > "${tmp}/derive.awk" <<'AWK'
function die(m) { print m > "/dev/stderr"; exit 1 }
function esc(s,   i, c, o) {
  o = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (index("\\.[]{}()*+?^$|/", c) > 0) o = o "\\"
    o = o c
  }
  return o
}
function parse(t,   i, c, n, key, j, lit) {
  np = 0; lit = ""; npos = 0
  i = 1; n = length(t)
  while (i <= n) {
    c = substr(t, i, 1)
    if (c == "{") {
      if (substr(t, i + 1, 1) == "{") { lit = lit "{"; i += 2; continue }
      j = index(substr(t, i), "}")
      if (j == 0) die("unclosed placeholder in: " t)
      key = substr(t, i + 1, j - 2)
      if (lit != "") { np++; kind[np] = "L"; val[np] = lit; lit = "" }
      if (key == "") { np++; kind[np] = "P"; val[np] = ""; npos++ }
      else if (key ~ /^[A-Za-z0-9_]+$/) { np++; kind[np] = "N"; val[np] = key }
      else die("unsupported placeholder {" key "} in: " t)
      i += j
    } else if (c == "}") {
      if (substr(t, i + 1, 1) == "}") { lit = lit "}"; i += 2; continue }
      die("stray } in: " t)
    } else { lit = lit c; i++ }
  }
  if (lit != "") { np++; kind[np] = "L"; val[np] = lit }
}
function expand(from, exact, rx, hasre, pidx,   i, k, vs, nv, v) {
  for (i = from; i <= np; i++) {
    if (kind[i] == "L") { exact = exact val[i]; rx = rx esc(val[i]) }
    else if (kind[i] == "P") {
      pidx++
      exact = exact posv[pidx]; rx = rx esc(posv[pidx])
    } else {
      k = val[i]
      if (k in rev) { rx = rx "(" rev[k] ")"; hasre = 1 }
      else if (k in named) {
        nv = split(named[k], vs, ",")
        for (v = 1; v <= nv; v++) expand(i + 1, exact vs[v], rx esc(vs[v]), hasre, pidx)
        return
      } else die("no substitution for {" k "} in template")
    }
  }
  if (hasre) print "R\t^" rx "$"
  else print "L\t" exact
}
BEGIN {
  sel = ENVIRON["SEL"]
  n = split(ENVIRON["SUBST"], a, "\n")
  for (i = 1; i <= n; i++) if (a[i] != "") { p = index(a[i], "="); named[substr(a[i], 1, p - 1)] = substr(a[i], p + 1) }
  n = split(ENVIRON["SUBSTRE"], a, "\n")
  for (i = 1; i <= n; i++) if (a[i] != "") { p = index(a[i], "="); rev[substr(a[i], 1, p - 1)] = substr(a[i], p + 1) }
  nposv = 0
  n = split(ENVIRON["SUBSTPOS"], tmpv, "\n")
  for (i = 1; i <= n; i++) if (tmpv[i] != "") { nposv++; posv[nposv] = tmpv[i] }
  src = ""
  while ((getline line) > 0) src = src line "\n"
  n = length(src); i = 1
  while (i <= n) {
    c = substr(src, i, 1); c2 = substr(src, i + 1, 1)
    if (c == "/" && c2 == "/") { while (i <= n && substr(src, i, 1) != "\n") i++; continue }
    if (c == "/" && c2 == "*") {
      d = 1; i += 2
      while (i <= n && d > 0) {
        if (substr(src, i, 2) == "/*") { d++; i += 2 } else if (substr(src, i, 2) == "*/") { d--; i += 2 } else i++
      }
      continue
    }
    if (c == "'") {
      if (c2 == "\\") { j = index(substr(src, i + 2), "'"); i += (j == 0 ? 2 : j + 2); continue }
      if (substr(src, i + 2, 1) == "'") { i += 3; continue }
      i++; continue
    }
    if (c == "r" && (c2 == "\"" || c2 == "#") && (i == 1 || substr(src, i - 1, 1) !~ /[A-Za-z0-9_]/)) {
      h = 0; j = i + 1
      while (substr(src, j, 1) == "#") { h++; j++ }
      if (substr(src, j, 1) == "\"") {
        close_s = "\""; for (k = 0; k < h; k++) close_s = close_s "#"
        e = index(substr(src, j + 1), close_s)
        if (e == 0) die("unterminated raw string")
        raw = substr(src, j + 1, e - 1)
        if (raw ~ sel) die("raw string matches --select (unsupported): " raw)
        i = j + e + length(close_s); continue
      }
    }
    if (c == "\"") {
      i++; s = ""
      while (i <= n) {
        c = substr(src, i, 1)
        if (c == "\"") break
        if (c == "\\") {
          c2 = substr(src, i + 1, 1)
          if (c2 == "\n") { i += 2; while (substr(src, i, 1) ~ /[ \t\n]/) i++; continue }
          if (c2 == "n") s = s "\n"; else if (c2 == "t") s = s "\t"; else if (c2 == "r") s = s "\r"
          else s = s c2
          i += 2; continue
        }
        s = s c; i++
      }
      if (i > n) die("unterminated string literal")
      i++
      if (s ~ sel) {
        if (index(s, "\t") > 0 || index(s, "\n") > 0) die("selected literal contains tab/newline: " s)
        parse(s)
        if (npos > 0 && npos != nposv) die("template has " npos " {} but --subst-pos gave " nposv ": " s)
        expand(1, "", "", 0, 0)
      }
      continue
    }
    i++
  }
}
AWK

: > "${tmp}/derived"
for f in "${srcs[@]}"; do
  if ! SEL="${select_re}" SUBST="${substs}" SUBSTPOS="${subst_pos}" SUBSTRE="${subst_re}" \
    awk -f "${tmp}/derive.awk" "${f}" >> "${tmp}/derived" 2> "${tmp}/awk.err" < /dev/null; then
    fail "could not derive expected lines from ${f}: $(tr '\n' ' ' < "${tmp}/awk.err")"
  fi
done
LC_ALL=C sort -u "${tmp}/derived" > "${tmp}/expected"
count="$(wc -l < "${tmp}/expected" | tr -d ' ')"
if [ "${count}" -eq 0 ]; then
  fail "no expected success lines were derived from the sources (fail-closed)"
fi
if [ "${count}" -lt "${min}" ]; then
  fail "expected at least ${min} success lines, derived ${count}"
fi

# forbid が期待行と矛盾する設定ミスは usage 扱い
for bad in ${forbids[@]+"${forbids[@]}"}; do
  if cut -f2 "${tmp}/expected" | grep -Fq -- "${bad}"; then
    echo "::error::${name} --forbid '${bad}' conflicts with an expected line" >&2
    exit 2
  fi
done

: > "${tmp}/exact"
: > "${tmp}/regex"
tab="$(printf '\t')"
while IFS="${tab}" read -r kind text; do
  case "${kind}" in
    L)
      printf '%s\n' "${text}" >> "${tmp}/exact"
      grep -Fxq -- "${text}" "${tmp}/log" || fail "did not report: ${text} (possibly not executed)"
      ;;
    R)
      printf '%s\n' "${text}" >> "${tmp}/regex"
      grep -Eq -- "${text}" "${tmp}/log" || fail "did not report a line matching: ${text} (possibly not executed)"
      ;;
  esac
done < "${tmp}/expected"

# ログの選別行がすべて期待行のどれかに一致すること
grep -E -- "${select_re}" "${tmp}/log" > "${tmp}/actual" || true
while IFS= read -r actual; do
  [ -n "${actual}" ] || continue
  if grep -Fxq -- "${actual}" "${tmp}/exact"; then continue; fi
  matched=0
  while IFS= read -r rx; do
    [ -n "${rx}" ] || continue
    if printf '%s\n' "${actual}" | grep -Eq -- "${rx}"; then matched=1; break; fi
  done < "${tmp}/regex"
  [ "${matched}" -eq 1 ] || fail "reported an unexpected line: ${actual}"
done < "${tmp}/actual"

for bad in ${forbids[@]+"${forbids[@]}"}; do
  if grep -Fq -- "${bad}" "${tmp}/log"; then
    fail "log contains a forbidden string: ${bad}"
  fi
done

if [ "${summary}" -eq 1 ]; then
  out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
  cat "${tmp}/actual" >> "${out}"
fi
echo "::notice::${name} verified (${count} lines)"
