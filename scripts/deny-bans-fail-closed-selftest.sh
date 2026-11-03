#!/usr/bin/env bash
# deny.toml の [bans] が rust-vmm 系の禁止クレート 10 種を拒否する fail-closed であることを、
# 使い捨て workspace と本物の deny.toml で機械的に確認する自己テスト
# （TASK-73.2・#686。MVM-4・REPAIR-9・REPAIR-12）。
#
# 呼び出し元: Makefile の `deny-bans-fail-closed-selftest`。CI では platform-ci（ubuntu のみ）が実行する。
# 禁止名の正は `scripts/check-microvm-deps.sh --list`（二重管理しない）。deny.toml が一覧と食い違えば
# 該当名の case が FAIL になるため、このテスト自体が deny.toml と --list の機械照合を兼ねる。
# 本番の Cargo.toml / Cargo.lock / deny.toml は変更しない。probe crate は一時ディレクトリ内の
# path 依存だけで、crates.io へは接続しない（--offline）。
# 判定は終了コードと診断（explicitly banned / bans FAILED）の両方で行い、lock 不整合など別理由の
# 非ゼロを「拒否できた」と誤認しない。対照 case（許可されるべきもの）で常時失敗する無意味なテストも防ぐ。
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DENY_TOML="${REPO}/deny.toml"

if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "cargo-deny is required but not found: install it (cargo install cargo-deny --locked)" >&2
  exit 2
fi
[ -f "${DENY_TOML}" ] || { echo "deny.toml not found: ${DENY_TOML}" >&2; exit 2; }

NAMES="$(bash "${REPO}/scripts/check-microvm-deps.sh" --list)"
if [ -z "${NAMES}" ]; then
  echo "FAIL: check-microvm-deps.sh --list returned no names" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

failures=0

# run_case <期待: reject|allow> <probe の package 名> <dependencies|dev-dependencies>
run_case() {
  local expect="$1" name="$2" section="$3" code=0 out ok=0
  if ! [[ "${name}" =~ ^[a-z0-9-]+$ ]]; then
    echo "FAIL ${name}: invalid probe name"
    failures=$((failures + 1))
    return
  fi
  rm -rf "${WORK}/root" "${WORK}/probe"
  mkdir -p "${WORK}/root/src" "${WORK}/probe/src"
  : > "${WORK}/root/src/lib.rs"
  : > "${WORK}/probe/src/lib.rs"
  cat > "${WORK}/probe/Cargo.toml" <<TOML
[package]
name = "${name}"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false
TOML
  cat > "${WORK}/root/Cargo.toml" <<TOML
[package]
name = "bans-root"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

[${section}]
${name} = { path = "../probe" }

[workspace]
TOML
  if ! cargo generate-lockfile --offline --manifest-path "${WORK}/root/Cargo.toml" >/dev/null 2>&1; then
    echo "FAIL ${name}: generate-lockfile failed"
    failures=$((failures + 1))
    return
  fi
  # CI は CARGO_TERM_COLOR=always のため、色なし指定と ANSI 除去の両方で判定文字列の分断を防ぐ
  out="$(NO_COLOR=1 CARGO_TERM_COLOR=never cargo deny --color never \
    --manifest-path "${WORK}/root/Cargo.toml" --config "${DENY_TOML}" --locked \
    check bans 2>&1)" || code=$?
  out="$(printf '%s\n' "${out}" | sed $'s/\x1b\\[[0-9;]*m//g')"
  if [ "${expect}" = reject ]; then
    if [ "${code}" -ne 0 ] && grep -q "crate '${name} = 0.1.0' is explicitly banned" <<<"${out}" \
      && grep -q 'bans FAILED' <<<"${out}"; then ok=1; fi
  else
    if [ "${code}" -eq 0 ] && grep -q 'bans ok' <<<"${out}" && ! grep -q 'is explicitly banned' <<<"${out}"; then ok=1; fi
  fi
  if [ "${ok}" -eq 1 ]; then
    echo "PASS ${name} (${section}) expect=${expect} exit=${code}"
  else
    echo "FAIL ${name} (${section}) expect=${expect} exit=${code}"
    # shellcheck disable=SC2001
    sed 's/^/    /' <<<"${out}" >&2
    failures=$((failures + 1))
  fi
}

while IFS= read -r n; do
  run_case reject "${n}" dependencies
done <<<"${NAMES}"
# dev-dependencies からの混入も検出すること
run_case reject "$(head -n 1 <<<"${NAMES}")" dev-dependencies
# 対照: 禁止名でなければ通ること
run_case allow bans-probe-allowed dependencies

if [ "${failures}" -ne 0 ]; then
  echo "deny-bans-fail-closed-selftest: ${failures} case(s) failed" >&2
  exit 1
fi
echo "deny-bans-fail-closed-selftest: all cases passed"
