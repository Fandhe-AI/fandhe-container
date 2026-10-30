#!/usr/bin/env bash
# crash_safety（IO-3・TASK-18）の件数サマリーを検証し、Markdown の表にして出す（#1833・REPAIR-4・REPAIR-7）。
#
# 役割: `crates/io/tests/crash_safety.rs` が環境変数 FANDHE_CONTAINER_CRASH_SUMMARY_DIR のディレクトリへ
# 書いた `<case>.json`（crash_summary の JSON 1 行）を fail-closed で検証し、有効 / 無効の試行数・
# 損失件数を CI の実行結果（GITHUB_STEP_SUMMARY。未設定なら stdout）に出す。
# 呼び出し元: Makefile の `crash-summary-check`（CI の platform-ci「crash_safety 件数の集計」ステップ）。
# scripts/lib.sh は source しない（作業ディレクトリをルートへ移すため、相対の --dir が壊れる）。
# 検証: Linux / macOS は期待 4 ケースのファイルがすべて通常ファイル（symlink 不可）・1 行・JSON で、
# 項目の型が正しいこと。余分なファイルがあれば失敗。Windows は UDS 未対応のためケース 0 件であること。
# 使い方: check-crash-summary.sh --dir <dir> [--os Linux|macOS|Windows]
# 終了コード: 0 成功 / 1 検証失敗 / 2 usage 誤り。bash 3.2 互換。
set -euo pipefail

usage() {
  echo "usage: $0 --dir <dir> [--os Linux|macOS|Windows]" >&2
  exit 2
}

dir=""
os="${RUNNER_OS:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      [ $# -ge 2 ] || usage
      dir="$2"
      shift 2
      ;;
    --os)
      [ $# -ge 2 ] || usage
      os="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "${dir}" ] || usage
if [ -z "${os}" ]; then
  case "$(uname -s)" in
    Linux) os=Linux ;;
    Darwin) os=macOS ;;
    MINGW* | MSYS* | CYGWIN*) os=Windows ;;
    *) os="$(uname -s)" ;;
  esac
fi

fail() {
  echo "NG: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required but not found"
if [ ! -d "${dir}" ] || [ -L "${dir}" ]; then
  fail "summary dir is not a real directory: ${dir}"
fi

out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# Windows の Git Bash のネイティブ jq.exe は出力が CRLF になり、コマンド置換が末尾の CR を残して
# 件数比較（"1\r" != "1"）や TSV の表が壊れる。jq の出力から CR を除去して LF に正規化する。
# パイプの失敗は pipefail で呼び出し側の `|| fail` に伝わる。
jq_lf() { jq "$@" | tr -d '\r'; }

# ディレクトリ内の実在エントリ名（ドットファイル・壊れた symlink を含む）を改行区切りで集める
entries=""
for f in "${dir}"/* "${dir}"/.[!.]* "${dir}"/..?*; do
  if [ -e "${f}" ] || [ -L "${f}" ]; then
    entries="${entries}$(basename -- "${f}")
"
  fi
done

case "${os}" in
  Linux | macOS) expected="flushed deferred_unflushed deferred_flushed file_ops_flushed" ;;
  Windows)
    [ -z "${entries}" ] || fail "Windows must have no crash_safety cases (UDS unsupported), found: ${entries}"
    {
      echo "### crash_safety (IO-3) summary"
      echo
      echo "No cases on Windows (UDS unsupported; only the unsupported-platform check runs)."
    } >>"${out}"
    echo "OK: crash_safety summary verified (Windows, no cases)"
    exit 0
    ;;
  *) fail "unsupported os: ${os}" ;;
esac

# 期待外のエントリは失敗
while IFS= read -r name; do
  [ -n "${name}" ] || continue
  ok=0
  for c in ${expected}; do
    if [ "${name}" = "${c}.json" ]; then
      ok=1
    fi
  done
  [ "${ok}" -eq 1 ] || fail "unexpected entry in summary dir: ${name}"
done <<EOF
${entries}
EOF

# jq フィルタ: 項目の型を検査し、通れば TSV 1 行にする（$case は jq 変数。シェル展開しない）
# shellcheck disable=SC2016
filter='
  def nn: type == "number" and . >= 0 and . == floor;
  select(.event == "crash_summary" and .case == $case
    and (.persist_supported | type == "boolean") and (.aborted | type == "boolean")
    and (.attempts | nn) and (.valid | nn) and (.invalid | nn) and (.checked | nn)
    and (.total_lost | nn) and (.max_lost | nn) and (.trials_with_loss | nn) and (.unexact | nn))
  | [.case, .persist_supported, .attempts, .valid, .invalid, .aborted, .checked,
     .total_lost, .max_lost, .trials_with_loss, .unexact] | @tsv'

rows=""
unsupported=""
for c in ${expected}; do
  f="${dir}/${c}.json"
  if [ ! -f "${f}" ] || [ -L "${f}" ]; then
    fail "missing or non-regular summary file: ${c}.json"
  fi
  lines="$(wc -l <"${f}" | tr -d ' ')"
  [ "${lines}" = "1" ] || fail "${c}.json must have exactly 1 line (got ${lines})"
  # 複数のトップレベル JSON 値（連結入力）を受け付けないよう、値がちょうど 1 件であることを確認する
  count="$(jq_lf -s 'length' "${f}")" || fail "${c}.json is not valid JSON"
  [ "${count}" = "1" ] || fail "${c}.json must contain exactly 1 JSON value (got ${count})"
  tsv="$(jq_lf -r --arg case "${c}" "${filter}" "${f}")" || fail "${c}.json is not valid JSON"
  [ -n "${tsv}" ] || fail "${c}.json has missing or invalid fields"
  row="| $(printf '%s' "${tsv}" | sed 's/	/ | /g') |"
  rows="${rows}${row}
"
  case "${tsv}" in
    "${c}	false	"*) unsupported="${unsupported} ${c}" ;;
  esac
done

{
  echo "### crash_safety (IO-3) summary"
  echo
  echo "| case | persist_supported | attempts | valid | invalid | aborted | checked | total_lost | max_lost | trials_with_loss | unexact |"
  echo "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
  printf '%s' "${rows}"
  if [ -n "${unsupported}" ]; then
    echo
    echo "Note: FLUSH ACK unsupported in this environment for:${unsupported} (all trials invalid by contract; not a durability check)."
  fi
} >>"${out}"
if [ -n "${unsupported}" ]; then
  echo "::warning::crash_safety ran without FLUSH ACK support for:${unsupported}"
fi
echo "OK: crash_safety summary verified (${os})"
