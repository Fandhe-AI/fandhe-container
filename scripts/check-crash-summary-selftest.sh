#!/usr/bin/env bash
# scripts/check-crash-summary.sh の自己テスト（#1833・IO-3・REPAIR-12）。
#
# 役割: 合成 fixture（正常・ケース欠落・不正 JSON・複数行・型不正・persist_supported:false・
# Windows の空ディレクトリ・symlink・余分なファイル）だけで、終了コードと表の具体値を照合する。
# 呼び出し元: Makefile の `crash-summary-check-selftest`（CI の platform-ci が 3 OS で実行）。
# 実際のテスト実行や kill は行わない。一時ファイルは mktemp -d の中だけに作り trap で消す。
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="${script_dir}/check-crash-summary.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
fails=0

line() { # line <case> <persist_supported> <valid> <invalid> <aborted> <total_lost> <trials_with_loss>
  printf '{"event":"crash_summary","case":"%s","persist_supported":%s,"attempts":%s,"valid":%s,"invalid":%s,"aborted":%s,"checked":%s,"total_lost":%s,"max_lost":%s,"trials_with_loss":%s,"unexact":%s}\n' \
    "$1" "$2" "$(($3 + $4))" "$3" "$4" "$5" "$3" "$6" "$6" "$7" "$7"
}

# mkgood <dir>: 正常な 4 ケースを書く
mkgood() {
  mkdir -p "$1"
  line flushed true 10 0 false 0 0 >"$1/flushed.json"
  line deferred_unflushed true 10 0 false 300 10 >"$1/deferred_unflushed.json"
  line deferred_flushed true 10 0 false 0 0 >"$1/deferred_flushed.json"
  line file_ops_flushed true 10 0 false 0 0 >"$1/file_ops_flushed.json"
}

# run <名前> <期待rc> <os> <dir> [期待する出力の部分文字列]
run() {
  local name="$1" want="$2" os="$3" dir="$4" needle="${5:-}"
  local summary="${work}/summary.md"
  : >"${summary}"
  local err rc
  err="$(GITHUB_STEP_SUMMARY="${summary}" bash "${target}" --dir "${dir}" --os "${os}" 2>&1)"
  rc=$?
  if [ "${rc}" -ne "${want}" ]; then
    echo "FAIL: ${name} (expected rc=${want}, got ${rc}): ${err}"
    fails=$((fails + 1))
    return
  fi
  if [ -n "${needle}" ] && ! grep -Fq -- "${needle}" "${summary}" && ! printf '%s' "${err}" | grep -Fq -- "${needle}"; then
    echo "FAIL: ${name} (missing output: ${needle})"
    fails=$((fails + 1))
    return
  fi
  echo "ok: ${name}"
}

command -v jq >/dev/null 2>&1 || {
  echo "jq is required but not found" >&2
  exit 1
}

mkgood "${work}/good"
run "good linux" 0 Linux "${work}/good" "| deferred_unflushed | true | 10 | 10 | 0 | false | 10 | 300 | 300 | 10 | 10 |"
run "good macos" 0 macOS "${work}/good" "| flushed | true | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |"
run "good file_ops_flushed row" 0 Linux "${work}/good" "| file_ops_flushed | true | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |"

mkgood "${work}/missing"
rm "${work}/missing/deferred_flushed.json"
run "missing case" 1 Linux "${work}/missing" "missing or non-regular"

mkgood "${work}/missing_fileops"
rm "${work}/missing_fileops/file_ops_flushed.json"
run "missing file_ops case" 1 Linux "${work}/missing_fileops" "missing or non-regular"

mkgood "${work}/badjson"
echo '{not json' >"${work}/badjson/flushed.json"
run "invalid json" 1 Linux "${work}/badjson" "not valid JSON"

mkgood "${work}/multi"
line flushed true 10 0 false 0 0 >>"${work}/multi/flushed.json"
run "two lines" 1 Linux "${work}/multi" "exactly 1 line"

mkgood "${work}/concat"
printf '%s {}\n' "$(line flushed true 10 0 false 0 0 | tr -d '\n')" >"${work}/concat/flushed.json"
run "valid summary concatenated with {} on one line" 1 Linux "${work}/concat" "exactly 1 JSON value"

mkgood "${work}/concat2"
printf '%s %s\n' "$(line flushed true 10 0 false 0 0 | tr -d '\n')" "$(line flushed true 10 0 false 0 0 | tr -d '\n')" >"${work}/concat2/flushed.json"
run "two valid summaries on one line" 1 Linux "${work}/concat2" "exactly 1 JSON value"

# Windows のネイティブ jq.exe は CRLF で出力する。実 jq を包んで各行を CRLF にした偽 jq で再現する
mkgood "${work}/crlf"
mkdir -p "${work}/fakebin"
real_jq="$(command -v jq)"
cat >"${work}/fakebin/jq" <<FAKE
#!/usr/bin/env bash
"${real_jq}" "\$@" | awk '{ printf "%s\r\n", \$0 }'
exit "\${PIPESTATUS[0]}"
FAKE
chmod +x "${work}/fakebin/jq"
saved_path="${PATH}"
PATH="${work}/fakebin:${PATH}"
run "crlf jq output accepted" 0 Linux "${work}/crlf" "| deferred_unflushed | true | 10 | 10 | 0 | false | 10 | 300 | 300 | 10 | 10 |"
if grep -q "$(printf '\r')" "${work}/summary.md"; then
  echo "FAIL: crlf jq output leaked CR into summary"
  fails=$((fails + 1))
else
  echo "ok: no CR in summary"
fi
run "crlf jq output still rejects concatenated values" 1 Linux "${work}/concat" "exactly 1 JSON value"
PATH="${saved_path}"

mkgood "${work}/badtype"
sed 's/"valid":10/"valid":"10"/' "${work}/badtype/flushed.json" >"${work}/badtype/x" && mv "${work}/badtype/x" "${work}/badtype/flushed.json"
run "string count" 1 Linux "${work}/badtype" "missing or invalid fields"

mkgood "${work}/negative"
sed 's/"total_lost":0/"total_lost":-1/' "${work}/negative/flushed.json" >"${work}/negative/x" && mv "${work}/negative/x" "${work}/negative/flushed.json"
run "negative count" 1 Linux "${work}/negative" "missing or invalid fields"

mkgood "${work}/wrongcase"
line deferred_flushed true 10 0 false 0 0 >"${work}/wrongcase/flushed.json"
run "case name mismatch" 1 Linux "${work}/wrongcase" "missing or invalid fields"

mkgood "${work}/extra"
echo x >"${work}/extra/other.json"
run "extra file" 1 Linux "${work}/extra" "unexpected entry"

mkgood "${work}/unsup"
line flushed false 0 10 true 0 0 >"${work}/unsup/flushed.json"
run "persist unsupported" 0 Linux "${work}/unsup" "FLUSH ACK unsupported"

mkgood "${work}/symfile"
rm "${work}/symfile/flushed.json"
if ln -s "${work}/good/flushed.json" "${work}/symfile/flushed.json" 2>/dev/null && [ -L "${work}/symfile/flushed.json" ]; then
  run "symlinked file" 1 Linux "${work}/symfile" "missing or non-regular"
else
  echo "ok: symlinked file (skipped: symlink unsupported on this OS, not a pass criterion)"
fi

mkdir -p "${work}/empty"
run "empty dir on linux" 1 Linux "${work}/empty" "missing or non-regular"
run "empty dir on macos" 1 macOS "${work}/empty" "missing or non-regular"
run "empty dir on windows" 0 Windows "${work}/empty" "No cases on Windows"
run "cases on windows" 1 Windows "${work}/good" "must have no crash_safety cases"
run "missing dir" 1 Linux "${work}/nonexistent" "not a real directory"
run "unsupported os" 1 Plan9 "${work}/good" "unsupported os"

if bash "${target}" >/dev/null 2>&1; then
  echo "FAIL: no args must exit 2"
  fails=$((fails + 1))
else
  rc=$?
  if [ "${rc}" -eq 2 ]; then echo "ok: no args exit 2"; else echo "FAIL: no args (rc=${rc})"; fails=$((fails + 1)); fi
fi

if [ "${fails}" -ne 0 ]; then
  echo "FAIL: ${fails} case(s) failed"
  exit 1
fi
echo "all crash-summary-check selftests passed"
