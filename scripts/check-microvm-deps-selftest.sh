#!/usr/bin/env bash
# scripts/check-microvm-deps.sh の自己テスト（make check-microvm-deps-selftest。MVM-4・TASK-73.1・REPAIR-12）。
#
# PATH の先頭にスタブの cargo を差し、fixture の `cargo tree` 出力（{p}|{r} 形式）で判定を照合する。
# 実 cargo・ネットワーク・root には依存しない。1 件でも期待と違えば非 0 で終わる。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${DIR}/lib.sh"

SCRIPT="${DIR}/check-microvm-deps.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/bin"
: >"${tmp}/Cargo.toml"
: >"${tmp}/Cargo2.toml"

# スタブ cargo: 受け取った引数を ARGS_LOG に追記し、FIXTURE を返す（STUB_CARGO_FAIL=1 なら 101）。
cat >"${tmp}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${ARGS_LOG}"
if [ "${STUB_CARGO_FAIL:-0}" = 1 ]; then exit 101; fi
# 2 つ目の manifest だけ別 fixture を返せるようにする。
case "$*" in
  *Cargo2.toml*) [ -n "${FIXTURE2:-}" ] && { cat "${FIXTURE2}"; exit 0; } ;;
esac
cat "${FIXTURE}"
STUB
chmod +x "${tmp}/bin/cargo"

pass=0
failed=0
ok() {
  pass=$((pass + 1))
  echo "PASS: $1"
}
ng() {
  failed=$((failed + 1))
  echo "FAIL: $1" >&2
}

# run <name> <expected-rc> <expected-substring-or-empty> <args...>（環境変数は呼び出し側で設定）
run() {
  local name="$1" want_rc="$2" want_str="$3"
  shift 3
  : >"${tmp}/args.log"
  local out rc=0
  out="$(PATH="${tmp}/bin:${PATH}" ARGS_LOG="${tmp}/args.log" "${SCRIPT}" "$@" 2>&1)" || rc=$?
  LAST_OUT="${out}"
  if [ "${rc}" -ne "${want_rc}" ]; then
    ng "${name}: rc=${rc} want ${want_rc}: ${out}"
    return
  fi
  if [ -n "${want_str}" ] && ! printf '%s\n' "${out}" | grep -Fq -- "${want_str}"; then
    ng "${name}: output lacks '${want_str}': ${out}"
    return
  fi
  ok "${name}"
}

M="${tmp}/Cargo.toml"
base='serde v1.0.0|https://github.com/serde-rs/serde
tokio v1.0.0|https://github.com/tokio-rs/tokio'

printf '%s\n' "${base}" >"${tmp}/clean.txt"
export FIXTURE="${tmp}/clean.txt"
run "1 clean tree" 0 "OK: no rust-vmm crate" --manifest-path "${M}"
for want in -e\ normal,build,dev --target\ all --all-features --locked --workspace "--manifest-path ${M}"; do
  grep -Fq -- "${want}" "${tmp}/args.log" || ng "1 cargo arg missing: ${want}"
done
ok "1b cargo args"

printf '%s\nvm-memory v0.16.0|https://github.com/rust-vmm/vm-memory\n' "${base}" >"${tmp}/b.txt"
FIXTURE="${tmp}/b.txt" run "2 banned name" 1 "banned crate vm-memory" --manifest-path "${M}"

printf '%s\nvm_memory v0.1.0 (/x)|\n' "${base}" >"${tmp}/b.txt"
FIXTURE="${tmp}/b.txt" run "3 underscore name" 1 "banned crate vm_memory" --manifest-path "${M}"

printf '%s\nfoo v1.0.0|https://github.com/rust-vmm/foo\n' "${base}" >"${tmp}/b.txt"
FIXTURE="${tmp}/b.txt" run "4 rust-vmm repository" 1 "banned crate foo" --manifest-path "${M}"

printf '%s\nvhost v0.1.0|https://example.com/x\nvhost v0.1.0 (*)|https://example.com/x\n' "${base}" >"${tmp}/b.txt"
FIXTURE="${tmp}/b.txt" run "5 duplicate" 1 "banned crate vhost" --manifest-path "${M}"
n="$(printf '%s\n' "${LAST_OUT}" | grep -c 'banned crate vhost' || true)"
if [ "${n}" -eq 1 ]; then ok "5b reported once"; else ng "5b reported ${n} times"; fi

printf '%s\nvhost-xyz-other v1.0.0|https://example.com/a\nmy-vm-memory v1.0.0|https://example.com/b\n' "${base}" >"${tmp}/b.txt"
FIXTURE="${tmp}/b.txt" run "6 similar names" 0 "OK:" --manifest-path "${M}"

printf '%s\nlinux-loader v0.1.0|\n' "${base}" >"${tmp}/b2.txt"
FIXTURE2="${tmp}/b2.txt" run "7 second manifest only" 1 "banned crate linux-loader" \
  --manifest-path "${M}" --manifest-path "${tmp}/Cargo2.toml"

STUB_CARGO_FAIL=1 run "8 cargo failure" 1 "cargo tree failed" --manifest-path "${M}"

: >"${tmp}/empty.txt"
FIXTURE="${tmp}/empty.txt" run "9 empty output" 1 "printed no packages" --manifest-path "${M}"

run "10a unknown arg" 2 "usage:" --bogus
run "10b missing value" 2 "usage:" --manifest-path
run "10c missing file" 2 "manifest not found" --manifest-path "${tmp}/none.toml"

run "11 list" 0 "vm-superio" --list
lines="$(printf '%s\n' "${LAST_OUT}" | wc -l | tr -d ' ')"
if [ "${lines}" -ge 10 ]; then ok "11b list has ${lines} entries"; else ng "11b list has ${lines} entries"; fi
for c in vm-memory kvm-ioctls kvm-bindings vhost vhost-user-backend virtio-queue vmm-sys-util linux-loader event-manager vm-superio; do
  printf '%s\n' "${LAST_OUT}" | grep -Fxq -- "${c}" || ng "11c list lacks ${c}"
done
if [ ! -s "${tmp}/args.log" ]; then ok "11d list does not call cargo"; else ng "11d cargo was called"; fi

echo "check-microvm-deps-selftest: ${pass} passed, ${failed} failed"
[ "${failed}" -eq 0 ]
