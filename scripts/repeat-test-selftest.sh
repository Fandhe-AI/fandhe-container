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
[ -z "${STUB_ARGS_LOG:-}" ] || echo "$*" >>"${STUB_ARGS_LOG}"
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
  bin-ok) echo "exec_x: all scenarios passed" ;;
  bin-na) echo "exec_x: Linux only, not applicable on this OS" ;;
  bin-prefix) echo "xx exec_x: all scenarios passed yy" ;;
  bin-early-large)
    echo "exec_x: all scenarios passed"
    head -c 4000000 /dev/zero | tr '\0' 'x'; echo ;;
  bin-crlf) printf 'exec_x: all scenarios passed\r\n' ;;
  bin-fail2)
    if [ "${n}" -eq 2 ]; then echo "boom"; exit 1; fi
    echo "exec_x: all scenarios passed" ;;
  bin-hang) sleep 30 ;;
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
B="TEST_BIN=exec_x"
S="SUCCESS_LINE=exec_x: all scenarios passed"
check bin-all-pass 0 "passed=3 failed=0 count=3 test_bin=exec_x" bin-ok "${P}" "${B}" "${S}" COUNT=3
check bin-not-applicable-is-failure 1 "reason=missing-success-line" bin-na "${P}" "${B}" "${S}" COUNT=2
check bin-not-applicable-count 1 "passed=0 failed=2 count=2 test_bin=exec_x" bin-na "${P}" "${B}" "${S}" COUNT=2
check bin-partial-match-is-failure 1 "passed=0 failed=2 count=2" bin-prefix "${P}" "${B}" "${S}" COUNT=2
check bin-one-failure 1 "passed=2 failed=1 count=3" bin-fail2 "${P}" "${B}" "${S}" COUNT=3
check bin-one-failure-reason 1 "reason=exit" bin-fail2 "${P}" "${B}" "${S}" COUNT=3
check bin-timeout 1 "reason=timeout" bin-hang "${P}" "${B}" "${S}" COUNT=1 RUN_TIMEOUT=1
check bin-crlf-accepted 0 "passed=2 failed=0 count=2" bin-crlf "${P}" "${B}" "${S}" COUNT=2
# 成功行が大きなログの先頭にあっても（grep の早期終了による SIGPIPE で）失敗に数えない。
check bin-early-success-line-large-log 0 "passed=2 failed=0 count=2" bin-early-large "${P}" "${B}" "${S}" COUNT=2
# 引数: --test が付き、--lib / --exact が付かない。TEST_IGNORED=1 で -- --ignored が付く。
rm -f "${work}/args"
env PATH="${work}/bin:${PATH}" STUB_MODE=bin-ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${B}" "${S}" COUNT=1 "${target}" >/dev/null 2>&1
if grep -qF -- "--test exec_x" "${work}/args" && ! grep -qE -- "--lib|--exact|--ignored" "${work}/args"; then
  echo "OK: bin-args"
else
  echo "NG: bin-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=bin-ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${B}" "${S}" TEST_IGNORED=1 COUNT=1 "${target}" >/dev/null 2>&1
if grep -qF -- "-- --ignored" "${work}/args"; then
  echo "OK: bin-ignored"
else
  echo "NG: bin-ignored" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi
check both-modes 2 "usage:" bin-ok "${P}" "${T}" "${B}" "${S}"
check bin-without-success-line 2 "usage:" bin-ok "${P}" "${B}"
check success-line-in-lib-mode 2 "usage:" ok "${P}" "${T}" "${S}"
check bin-flag-injection 2 "usage:" bin-ok "${P}" TEST_BIN=--help "${S}"
check bin-slash 2 "usage:" bin-ok "${P}" TEST_BIN=a/b "${S}"
check success-line-semicolon 2 "usage:" bin-ok "${P}" "${B}" "SUCCESS_LINE=a;b"
# shellcheck disable=SC2016
check success-line-dollar 2 "usage:" bin-ok "${P}" "${B}" 'SUCCESS_LINE=a$b'
check success-line-too-long 2 "usage:" bin-ok "${P}" "${B}" "SUCCESS_LINE=$(printf 'a%.0s' $(seq 1 201))"
check ignored-invalid 2 "usage:" bin-ok "${P}" "${B}" "${S}" TEST_IGNORED=yes
check missing-test 2 "usage:" ok "${P}"
check bad-package 2 "usage:" ok PACKAGE=other "${T}"
check flag-injection 2 "usage:" ok "${P}" "TEST=--help"
# FEATURES: 検証と cargo への受け渡し（#2711）。
check features-bad-flag 2 "usage:" ok "${P}" "${T}" FEATURES=-x
check features-bad-space 2 "usage:" ok "${P}" "${T}" "FEATURES=a b"
check features-bad-semicolon 2 "usage:" ok "${P}" "${T}" "FEATURES=a;b"
check features-too-long 2 "usage:" ok "${P}" "${T}" "FEATURES=$(printf 'a%.0s' $(seq 1 129))"
check features-pass 0 "passed=2 failed=0 count=2" ok "${P}" "${T}" FEATURES=grpc,x COUNT=2
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${T}" FEATURES=grpc COUNT=1 "${target}" >/dev/null 2>&1
if [ "$(grep -cF -- "--features grpc" "${work}/args")" -eq 2 ]; then
  echo "OK: features-args"
else
  echo "NG: features-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${T}" COUNT=1 "${target}" >/dev/null 2>&1
if ! grep -qF -- "--features" "${work}/args"; then
  echo "OK: no-features-args"
else
  echo "NG: no-features-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi
check count-zero 2 "usage:" ok "${P}" "${T}" COUNT=0
check count-over 2 "usage:" ok "${P}" "${T}" COUNT=1001

[ "${fails}" -eq 0 ] || { echo "repeat-test-selftest: ${fails} failure(s)" >&2; exit 1; }
echo "repeat-test-selftest: all passed"
