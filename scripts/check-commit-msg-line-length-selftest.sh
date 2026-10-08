#!/usr/bin/env bash
# scripts/check-commit-msg-line-length.sh の自己テスト（Issue #1295・REPAIR-12）。
#
# 役割: 境界値（100 / 101）を ASCII・全角・絵文字（UTF-16 で 2 単位）・URL・CRLF・コメント行・
# scissors・footer で具体値照合する。期待値は commitlint（body/footer-max-line-length = 100）の判定。
# 呼び出し元: Makefile の `commit-msg-line-length-selftest`。make ci には含めない。
# 一時ファイルは mktemp -d の中だけに作り trap で消す。失敗は FAIL: 行と非 0 終了。
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="$script_dir/check-commit-msg-line-length.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fails=0

rep() { # rep <文字列> <回数>
  local out="" i
  for ((i = 0; i < $2; i++)); do out+="$1"; done
  printf '%s' "$out"
}

# check <名前> <期待rc> <メッセージ本体（ヘッダー後の全体）>
check() {
  local f="$work/msg"
  printf 'chore: test\n\n%s\n' "$3" >"$f"
  sh "$target" "$f" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" -eq "$2" ]; then echo "ok: $1"; else echo "FAIL: $1 (expected rc=$2, got $rc)"; fails=$((fails + 1)); fi
}

check "ascii 100" 0 "$(rep a 100)"
check "ascii 101" 1 "$(rep a 101)"
check "fullwidth 100" 0 "$(rep あ 100)"
check "fullwidth 101" 1 "$(rep あ 101)"
check "emoji 50 (=100 units)" 0 "$(rep 😀 50)"
check "emoji 51 (=102 units)" 1 "$(rep 😀 51)"
check "mixed 98 ascii + 1 fullwidth = 99" 0 "$(rep a 98)あ"
check "mixed 99 ascii + 2 fullwidth = 101" 1 "$(rep a 99)ああ"
check "mixed 1 emoji + 98 ascii = 100" 0 "😀$(rep a 98)"
check "mixed 1 emoji + 99 ascii = 101" 1 "😀$(rep a 99)"
check "url line 150" 0 "see https://example.com/$(rep a 130)"
check "non-word-boundary url 150" 1 "x$(rep a 10)xhttps://example.com/$(rep a 130)"
check "trailing spaces after 100" 0 "$(rep a 100)   "
check "hash comment 150" 0 "# $(rep a 150)"
check "footer 101" 1 "body
BREAKING CHANGE: $(rep a 84)"
check "footer 100" 0 "body
BREAKING CHANGE: $(rep a 83)"
check "scissors drops diff" 0 "ok
# ------------------------ >8 ------------------------
$(rep a 200)"

# CRLF
printf 'chore: test\r\n\r\n%s\r\n' "$(rep a 100)" >"$work/crlf"
sh "$target" "$work/crlf" >/dev/null 2>&1 && echo "ok: crlf 100" || { echo "FAIL: crlf 100"; fails=$((fails + 1)); }

# header only
printf 'chore: test\n' >"$work/h"
sh "$target" "$work/h" >/dev/null 2>&1 && echo "ok: header only" || { echo "FAIL: header only"; fails=$((fails + 1)); }

# 引数エラー（fail-closed）
sh "$target" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] && echo "ok: no args rc=2" || { echo "FAIL: no args (rc=$rc)"; fails=$((fails + 1)); }
sh "$target" "$work/none" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] && echo "ok: missing file rc=2" || { echo "FAIL: missing file (rc=$rc)"; fails=$((fails + 1)); }

# 出力に行の中身を含めない
printf 'chore: test\n\nSECRETWORD%s\n' "$(rep a 100)" >"$work/leak"
if sh "$target" "$work/leak" 2>&1 | grep -q SECRETWORD; then
  echo "FAIL: output leaks line content"
  fails=$((fails + 1))
else
  echo "ok: no content in output"
fi

# core.commentChar=; （一時リポジトリ）
repo="$work/repo"
git init -q "$repo" && git -C "$repo" config core.commentChar ';'
printf 'chore: test\n\n;%s\n' "$(rep a 150)" >"$work/semi"
(cd "$repo" && sh "$target" "$work/semi" >/dev/null 2>&1) && echo "ok: commentChar ;" || { echo "FAIL: commentChar ;"; fails=$((fails + 1)); }
printf 'chore: test\n\n#%s\n' "$(rep a 150)" >"$work/hash"
(cd "$repo" && sh "$target" "$work/hash" >/dev/null 2>&1)
rc=$?
[ "$rc" -eq 1 ] && echo "ok: # is body when commentChar=;" || { echo "FAIL: # under commentChar=; (rc=$rc)"; fails=$((fails + 1)); }

if [ "$fails" -ne 0 ]; then
  echo "FAILED: $fails"
  exit 1
fi
echo "all passed"
