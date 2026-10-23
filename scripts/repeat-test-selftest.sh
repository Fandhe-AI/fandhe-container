#!/usr/bin/env bash
# scripts/targets/repeat-test.sh の自己テスト（REPAIR-12・#2538）。
#
# 役割: スタブの cargo だけで、成功・0 件実行（false-green）・途中 1 回の失敗・入力不正の終了コードと
# 集計行を具体値で照合する。実際の試験は走らせない。呼び出し元: Makefile の `repeat-test-selftest`。
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="${script_dir}/targets/repeat-test.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
fails=0

mkdir -p "${work}/bin"
# スタブ: --no-run は成功。それ以外は STUB_MODE に従い、呼び出し回数を数える。
cat >"${work}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
case " $* " in *" --no-run "*) exit 0 ;; esac
n=0
[ ! -f "${STUB_COUNTER}" ] || n="$(cat "${STUB_COUNTER}")"
n=$((n + 1))
echo "${n}" >"${STUB_COUNTER}"
case "${STUB_MODE}" in
  ok) echo "test result: ok. 1 passed; 0 failed" ;;
  zero) echo "test result: ok. 0 passed; 0 failed" ;;
  fail2)
    if [ "${n}" -eq 2 ]; then echo "test result: FAILED. 0 passed; 1 failed"; exit 101; fi
    echo "test result: ok. 1 passed; 0 failed" ;;
esac
STUB
chmod +x "${work}/bin/cargo"

# check <名前> <期待rc> <期待する出力の部分文字列> <STUB_MODE> <環境変数...>
check() {
  local name="$1" want_rc="$2" want_out="$3" mode="$4"
  shift 4
  rm -f "${work}/counter"
  local out rc=0
  out="$(env PATH="${work}/bin:${PATH}" STUB_MODE="${mode}" STUB_COUNTER="${work}/counter" "$@" "${target}" 2>&1)" || rc=$?
  if [ "${rc}" -ne "${want_rc}" ] || ! printf '%s\n' "${out}" | grep -qF -- "${want_out}"; then
    echo "NG: ${name}: rc=${rc} (want ${want_rc}), want output containing '${want_out}'" >&2
    printf '%s\n' "${out}" >&2
    fails=$((fails + 1))
  else
    echo "OK: ${name}"
  fi
}

P="PACKAGE=fandhe-container-x"
T="TEST=a::b::c"
check all-pass 0 "passed=3 failed=0 count=3" ok "${P}" "${T}" COUNT=3
check zero-tests-is-failure 1 "passed=0 failed=2 count=2" zero "${P}" "${T}" COUNT=2
check one-failure 1 "passed=2 failed=1 count=3" fail2 "${P}" "${T}" COUNT=3
check missing-test 2 "usage:" ok "${P}"
check bad-package 2 "usage:" ok PACKAGE=other "${T}"
check flag-injection 2 "usage:" ok "${P}" "TEST=--help"
check count-zero 2 "usage:" ok "${P}" "${T}" COUNT=0
check count-over 2 "usage:" ok "${P}" "${T}" COUNT=1001

[ "${fails}" -eq 0 ] || { echo "repeat-test-selftest: ${fails} failure(s)" >&2; exit 1; }
echo "repeat-test-selftest: all passed"
