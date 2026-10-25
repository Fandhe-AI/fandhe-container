#!/usr/bin/env bash
# scripts/check-standalone-clippy.sh の自己テスト（make check-standalone-clippy-selftest。
# #2640・REPAIR-7・REPAIR-12）。
#
# 一時ディレクトリにスタブの `cargo`（metadata は fixture の JSON、clippy は環境変数で指定した名前だけ失敗）を置き、
# PATH の先頭に差して判定本体を実行する。実際の cargo・ネットワーク・root は使わない（jq は必要）。
# 1 件でも期待と違えば非 0 で終わる。
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="${here}/check-standalone-clippy.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not found" >&2
  exit 1
fi

mkdir -p "${work}/bin"
cat >"${work}/bin/cargo" <<'EOT'
#!/usr/bin/env bash
# スタブ: metadata は STUB_METADATA_FILE を返す（STUB_METADATA_FAIL=1 なら失敗）。
# clippy は引数を STUB_LOG へ 1 行で記録し、-p の名前が STUB_FAIL_NAME と一致すれば失敗する。
case "$1" in
  metadata)
    if [ "${STUB_METADATA_FAIL:-}" = 1 ]; then exit 101; fi
    cat "${STUB_METADATA_FILE}"
    ;;
  clippy)
    shift
    echo "$*" >>"${STUB_LOG}"
    name=""
    prev=""
    for a in "$@"; do
      if [ "${prev}" = "-p" ]; then name="${a}"; fi
      prev="${a}"
    done
    if [ -n "${STUB_FAIL_NAME:-}" ] && [ "${name}" = "${STUB_FAIL_NAME}" ]; then exit 101; fi
    ;;
  *) exit 99 ;;
esac
EOT
chmod +x "${work}/bin/cargo"

# libonly: lib のみ / bin-only: bin のみ / both: 両方 / none: どちらも無い
cat >"${work}/meta3.json" <<'EOT'
{"packages":[
 {"name":"libonly","targets":[{"kind":["lib"]}]},
 {"name":"binonly","targets":[{"kind":["bin"]}]},
 {"name":"both","targets":[{"kind":["lib"]},{"kind":["bin"]},{"kind":["test"]}]}
]}
EOT
cat >"${work}/meta-none.json" <<'EOT'
{"packages":[{"name":"notarget","targets":[{"kind":["test"]}]},{"name":"libonly","targets":[{"kind":["lib"]}]}]}
EOT
echo '{"packages":[]}' >"${work}/meta-empty.json"

failures=0
pass() { echo "ok: $1"; }
bad() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# run_case <メタデータ fixture> [環境変数 KEY=VAL ...]: stdout+stderr を ${work}/out、cargo clippy の記録を ${work}/log へ、
# 終了コードを rc へ入れる。
run_case() {
  local meta="$1"
  shift
  : >"${work}/log"
  rc=0
  env PATH="${work}/bin:${PATH}" STUB_METADATA_FILE="${work}/${meta}" STUB_LOG="${work}/log" "$@" \
    bash "${checker}" >"${work}/out" 2>&1 || rc=$?
}

expect() { # <名前> <期待 rc> <out に含まれるべき固定文字列...>
  local name="$1" want="$2"
  shift 2
  local ok=1
  if [ "${rc}" != "${want}" ]; then
    ok=0
    echo "  rc=${rc} want=${want}" >&2
  fi
  local s
  for s in "$@"; do
    if ! grep -qF -- "${s}" "${work}/out"; then
      ok=0
      echo "  missing: ${s}" >&2
    fi
  done
  if [ "${ok}" = 1 ]; then pass "${name}"; else
    bad "${name}"
    cat "${work}/out" >&2
  fi
}

has_log() { grep -qxF -- "$1" "${work}/log"; }

# 1. 全件成功
run_case meta3.json
expect "all pass" 0 "checked=3 failed=0"

# 5. lib / bins の渡し分け
if has_log "-p libonly --lib -- -D warnings" && has_log "-p binonly --bins -- -D warnings" &&
  has_log "-p both --lib --bins -- -D warnings"; then pass "lib/bins flags per package"; else
  bad "lib/bins flags per package"
  cat "${work}/log" >&2
fi

# 2. 1 件失敗しても最後まで回し、非 0 で NG 行を出す
run_case meta3.json STUB_FAIL_NAME=libonly
expect "one failure continues" 1 "NG: libonly" "checked=3 failed=1" "OK: both"
if has_log "-p both --lib --bins -- -D warnings"; then pass "later packages still run"; else bad "later packages still run"; fi

# 3. 0 件は fail-closed
run_case meta-empty.json
expect "empty workspace fails closed" 1 "NG: no workspace member found"

# 4. metadata の失敗
run_case meta3.json STUB_METADATA_FAIL=1
expect "metadata failure" 1 "NG: cargo metadata failed"

# lib/bin の無い package は note を出して数えない
run_case meta-none.json
expect "no-target package noted" 0 "note: notarget has no lib/bin target" "checked=1 failed=0"

# 6. CLIPPY_TARGET
run_case meta3.json CLIPPY_TARGET=aarch64-apple-darwin
expect "target accepted" 0 "checked=3 failed=0"
if has_log "-p both --lib --bins --target aarch64-apple-darwin -- -D warnings"; then pass "target flag passed"; else
  bad "target flag passed"
  cat "${work}/log" >&2
fi
for t in "a b" ";x" "\$(id)"; do
  run_case meta3.json CLIPPY_TARGET="${t}"
  expect "bad target rejected: ${t}" 2 "usage:"
  if [ -s "${work}/log" ]; then bad "clippy must not run for bad target: ${t}"; fi
done

# 7. 未知の引数
rc=0
env PATH="${work}/bin:${PATH}" STUB_METADATA_FILE="${work}/meta3.json" STUB_LOG="${work}/log" \
  bash "${checker}" --nope >"${work}/out" 2>&1 || rc=$?
expect "unknown argument" 2 "usage:"

if [ "${failures}" -ne 0 ]; then
  echo "check-standalone-clippy-selftest: ${failures} case(s) failed" >&2
  exit 1
fi
echo "check-standalone-clippy-selftest: all cases passed"
