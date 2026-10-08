#!/bin/sh
# commit-msg フックの本文・フッター行長検査（Issue #1295）。
#
# 役割: コミットメッセージの 2 行目以降の各行が 100 文字以下かを検査する。lefthook.yml の
# commit-msg ジョブ（conventional-commits）が、1 行目の正規表現検査の後に呼び出す。
# 1 行目（ヘッダー）の検査は呼び出し元の正規表現が担い、本スクリプトは対象にしない。
#
# commitlint との対応（make lint-commits・CI の lint-docs。@commitlint/config-conventional）:
#   - body-max-line-length / footer-max-line-length = 100。2 行目以降をまとめて 1 規則で再現する
#   - 文字数は JS の String.length（UTF-16 コード単位）。BMP 内の全角文字は 1、BMP 外
#     （UTF-8 で 4 バイトの絵文字等）は 2 と数える。locale に依存しないようバイト単位で計算する
#   - http(s):// を含む行は長さに関係なく許可する（commitlint の /\bhttps?:\/\/\S+/ の近似。
#     全角スペース等の扱いが JS とずれる場合はフックが緩くなる方向にだけずれる）
#
# git の cleanup 差の吸収: フックが受け取るのは cleanup 前の COMMIT_EDITMSG なので、
# scissors 行以降と commentChar で始まる行を読み飛ばし、行末の CR・空白を除いて数える。
# 既知の差異: `--cleanup=verbatim` 等で残った長い # 行や不正な UTF-8 は保証外
# （最終的な防御線は CI の commitlint）。
#
# 終了コード: 0 = 適合、1 = 超過行あり、2 = 引数・入力エラー（fail-closed）。
# 出力は行番号と文字数のみで、行の中身は出さない（誤って貼った秘密情報の再表示を防ぐ）。
set -eu

MAX_LEN=100

if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ ! -r "$1" ]; then
  echo "usage: check-commit-msg-line-length.sh <commit-msg-file>" >&2
  exit 2
fi

cc="$(git config --get core.commentChar 2>/dev/null || true)"
case "$cc" in
  '' | auto) cc='#' ;;
esac

# 4 バイト文字の先頭バイト（\360-\364）。awk 実装差を避け printf で生成して渡す
lead4="$(printf '[\360-\364]')"

# 継続バイト（\200-\277）を除くとバイト数 = コードポイント数になる。commentChar も同様に正規化する
cc="$(printf '%s' "$cc" | LC_ALL=C tr -d '\200-\277')"

LC_ALL=C tr -d '\200-\277' <"$1" | LC_ALL=C awk -v max="$MAX_LEN" -v cc="$cc" -v lead4="$lead4" '
  {
    line = $0
    sub(/\r$/, "", line)
    if (index(line, cc " ------------------------ >8 ------------------------") == 1) exit
    if (index(line, cc) == 1) next
    n++
    if (n == 1) next
    sub(/[ \t]+$/, "", line)
    if (line ~ /(^|[^A-Za-z0-9_])https?:\/\/[^ \t]/) next
    len = length(line) + gsub(lead4, "&", line)
    if (len > max) {
      printf "NG: commit message line %d is %d characters (max %d)\n", NR, len, max > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad ? 1 : 0 }
'
