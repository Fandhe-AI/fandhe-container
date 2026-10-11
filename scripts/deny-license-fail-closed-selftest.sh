#!/usr/bin/env bash
# deny.toml の [licenses] が「許可リストに無いライセンスを拒否する」fail-closed であることを、
# 使い捨て workspace と本物の deny.toml で機械的に確認する自己テスト
# （TASK-90.2・#127。OSS-4・OSS-5・REPAIR-9・REPAIR-12）。
#
# 呼び出し元: Makefile の `deny-license-fail-closed-selftest`。CI では platform-ci（ubuntu のみ）が実行する。
# 本番の Cargo.toml / Cargo.lock / deny.toml は変更しない。probe crate は一時ディレクトリ内の
# path 依存だけで、crates.io へは接続しない（--offline）。
# 判定は終了コードと診断（rejected / licenses FAILED）の両方で行い、lock 不整合など別理由の
# 非ゼロを「拒否できた」と誤認しない。対照 case（許可されるべきもの）で常時失敗する無意味なテストも防ぐ。
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DENY_TOML="${REPO}/deny.toml"

if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "cargo-deny is required but not found: install it (cargo install cargo-deny --locked)" >&2
  exit 2
fi
[ -f "${DENY_TOML}" ] || { echo "deny.toml not found: ${DENY_TOML}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/root/src" "${WORK}/probe/src"
: > "${WORK}/root/src/lib.rs"
: > "${WORK}/probe/src/lib.rs"
cat > "${WORK}/root/Cargo.toml" <<TOML
[package]
name = "license-root"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

[dependencies]
license-probe = { path = "../probe" }

[workspace]
TOML

failures=0

# run_case <期待: reject|allow> <probe の license 式>
run_case() {
  local expect="$1" lic="$2" code=0 out ok=0
  cat > "${WORK}/probe/Cargo.toml" <<TOML
[package]
name = "license-probe"
version = "0.1.0"
edition = "2021"
license = "${lic}"
publish = false
TOML
  rm -f "${WORK}/root/Cargo.lock"
  if ! cargo generate-lockfile --offline --manifest-path "${WORK}/root/Cargo.toml" >/dev/null 2>&1; then
    echo "FAIL ${lic}: generate-lockfile failed"
    failures=$((failures + 1))
    return
  fi
  # CI は CARGO_TERM_COLOR=always のため、色なし指定と ANSI 除去の両方で判定文字列の分断を防ぐ
  out="$(NO_COLOR=1 CARGO_TERM_COLOR=never cargo deny --color never \
    --manifest-path "${WORK}/root/Cargo.toml" --config "${DENY_TOML}" --locked \
    check licenses 2>&1)" || code=$?
  out="$(printf '%s\n' "${out}" | sed $'s/\x1b\\[[0-9;]*m//g')"
  if [ "${expect}" = reject ]; then
    if [ "${code}" -ne 0 ] && grep -q 'rejected' <<<"${out}" && grep -q 'licenses FAILED' <<<"${out}"; then ok=1; fi
  else
    if [ "${code}" -eq 0 ] && ! grep -q 'rejected' <<<"${out}"; then ok=1; fi
  fi
  if [ "${ok}" -eq 1 ]; then
    echo "PASS ${lic} expect=${expect} exit=${code}"
  else
    echo "FAIL ${lic} expect=${expect} exit=${code}"
    sed 's/^/    /' <<<"${out}" >&2
    failures=$((failures + 1))
  fi
}

run_case reject "GPL-3.0-only"
run_case reject "LGPL-2.1-only"
run_case reject "AGPL-3.0-only"
run_case reject "MPL-2.0"
run_case reject "MIT AND GPL-3.0-only"
run_case allow "MIT"
# OR 式は permissive 側を選べるため cargo-deny は許可する（仕様。docs/design/license-deny-fail-closed-report.md）
run_case allow "MIT OR GPL-3.0-only"

if [ "${failures}" -ne 0 ]; then
  echo "deny-license-fail-closed-selftest: ${failures} case(s) failed" >&2
  exit 1
fi
echo "deny-license-fail-closed-selftest: all cases passed"
