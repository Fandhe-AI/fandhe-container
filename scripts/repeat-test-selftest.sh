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
case " $* " in
  *" --message-format=json "*)
    # 委譲スコープモードのバイナリ特定用（#2886）。STUB_JSON_MODE: one（既定）/ none / two / null
    j() { printf '{"profile":{"test":true},"target":{"name":"exec_x"},"executable":%s}\n' "$1"; }
    case "${STUB_JSON_MODE:-one}" in
      one) j "\"${STUB_BIN}\"" ;;
      two) j "\"${STUB_BIN}\""; j "\"${STUB_BIN}.other\"" ;;
      null) j null ;;
      none) : ;;
    esac
    exit 0 ;;
esac
case " $* " in *" --no-run "*) exit 0 ;; esac
# プリフライト（--list --logfile。#3036）。カウンタは進めない。STUB_NO_LOGFILE=1 は削除後の libtest を模す。
case " $* " in
  *" --list "*)
    lf=""; prev=""
    for a in "$@"; do [ "${prev}" = --logfile ] && lf="${a}"; prev="${a}"; done
    if [ -n "${STUB_NO_LOGFILE:-}" ] && [ -n "${lf}" ]; then echo "error: Unrecognized option: 'logfile'" >&2; exit 101; fi
    [ -z "${STUB_PREFLIGHT_RC:-}" ] || exit "${STUB_PREFLIGHT_RC}"
    exit 0 ;;
esac
case " $* " in
  *" --logfile "*) [ -z "${STUB_NO_LOGFILE:-}" ] || { echo "error: Unrecognized option: 'logfile'" >&2; exit 101; } ;;
esac
[ -z "${STUB_ENV_LOG:-}" ] || echo "cargo-env: ${FANDHE_CONTAINER_TEST_ID_HELPER:-unset}" >>"${STUB_ENV_LOG}"
n=0
[ ! -f "${STUB_COUNTER}" ] || n="$(cat "${STUB_COUNTER}")"
n=$((n + 1))
echo "${n}" >"${STUB_COUNTER}"
# libtest の --logfile を模す（#2962）。引数から経路を拾う。
lf=""; prev=""
nc=""
for a in "$@"; do [ "${prev}" = --logfile ] && lf="${a}"; [ "${a}" = --no-capture ] && nc=1; prev="${a}"; done
case "${STUB_MODE}" in
  ok) echo "test result: ok. 1 passed; 0 failed"; [ -z "${lf}" ] || echo "ok a::b::c" >"${lf}" ;;
  zero) echo "test result: ok. 0 passed; 0 failed"; [ -z "${lf}" ] || : >"${lf}" ;;
  # 要約行はあるがログが空（ログ経由でないと合格にならないことの確認）
  summary-only) echo "test result: ok. 1 passed; 0 failed"; [ -z "${lf}" ] || : >"${lf}" ;;
  fail2)
    if [ "${n}" -eq 2 ]; then echo "test result: FAILED. 0 passed; 1 failed"; [ -z "${lf}" ] || echo "failed a::b::c" >"${lf}"; exit 101; fi
    echo "test result: ok. 1 passed; 0 failed"; [ -z "${lf}" ] || echo "ok a::b::c" >"${lf}" ;;
  # 汎用: STUB_STDOUT / STUB_STDERR / STUB_LOG は printf %b で出す。STUB_LOG_FIRST_ONLY=1 は 1 回目だけログを書く。
  gen)
    # 成功した試験の出力は --no-capture が無いと libtest にキャプチャされて出ない（P1）。それを模す。
    [ -z "${STUB_NC_STDOUT:-}" ] || [ -z "${nc}" ] || printf '%b' "${STUB_NC_STDOUT}"
    [ -z "${STUB_STDOUT:-}" ] || printf '%b' "${STUB_STDOUT}"
    [ -z "${STUB_STDERR:-}" ] || printf '%b' "${STUB_STDERR}" >&2
    if [ -n "${lf}" ] && { [ -z "${STUB_LOG_FIRST_ONLY:-}" ] || [ "${n}" -eq 1 ]; }; then printf '%b' "${STUB_LOG:-}" >"${lf}"; fi
    exit "${STUB_RC:-0}" ;;
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
# スタブ systemd-run: 引数を記録し、`--` 以降をそのまま実行する（委譲スコープモード。#2886）。
cat >"${work}/bin/systemd-run" <<'STUB'
#!/usr/bin/env bash
[ -z "${STUB_SD_LOG:-}" ] || echo "$*" >>"${STUB_SD_LOG}"
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
exec "$@"
STUB
chmod +x "${work}/bin/systemd-run"
# スタブ試験バイナリ: 成功行と、受け取った環境変数（false-green 検出用）を出す。
FINAL_LINE='production_launcher: pid1, default /dev nodes, landlock evidence, cgroup join verified; failed launch left no process; bind mount visible on host; post-exec capabilities and seccomp verified (root=false)'
cat >"${work}/bin/exec_x_bin" <<STUB
#!/usr/bin/env bash
echo "args: \$*"
case " \$* " in
  *" --list "*)
    lf=""; prev=""
    for a in "\$@"; do [ "\${prev}" = --logfile ] && lf="\${a}"; prev="\${a}"; done
    if [ -n "\${STUB_NO_LOGFILE:-}" ] && [ -n "\${lf}" ]; then echo "error: Unrecognized option: 'logfile'" >&2; exit 101; fi
    exit 0 ;;
esac
echo "env-seen: FANDHE_CONTAINER_TEST_ID_HELPER=\${FANDHE_CONTAINER_TEST_ID_HELPER:-unset}"
echo "user-seen: \${USER:-unset}"
case "\${STUB_MODE}" in
  scope-ok) echo '${FINAL_LINE}' ;;
  scope-prefix) echo 'xx ${FINAL_LINE} yy' ;;
  scope-fail) exit 1 ;;
  scope-hang) sleep 30 ;;
  scope-slow) sleep 3; echo '${FINAL_LINE}' ;;
  scope-gen)
    lf=""; prev=""
    nc=""
    for a in "\$@"; do [ "\${prev}" = --logfile ] && lf="\${a}"; [ "\${a}" = --no-capture ] && nc=1; prev="\${a}"; done
    [ -z "\${STUB_NC_STDOUT:-}" ] || [ -z "\${nc}" ] || printf '%b' "\${STUB_NC_STDOUT}"
    [ -z "\${STUB_STDOUT:-}" ] || printf '%b' "\${STUB_STDOUT}"
    [ -z "\${STUB_STDERR:-}" ] || printf '%b' "\${STUB_STDERR}" >&2
    [ -z "\${lf}" ] || printf '%b' "\${STUB_LOG:-}" >"\${lf}"
    exit "\${STUB_RC:-0}" ;;
esac
STUB
chmod +x "${work}/bin/exec_x_bin"

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
check success-line-semicolon-accepted 1 "passed=0 failed=1 count=1" bin-ok "${P}" "${B}" "SUCCESS_LINE=a;b" COUNT=1
check success-line-bad-char 2 "usage:" bin-ok "${P}" "${B}" "SUCCESS_LINE=a|b"
# shellcheck disable=SC2016
check success-line-dollar 2 "usage:" bin-ok "${P}" "${B}" 'SUCCESS_LINE=a$b'
check success-line-too-long 2 "usage:" bin-ok "${P}" "${B}" "SUCCESS_LINE=$(printf 'a%.0s' $(seq 1 513))"
check success-line-512-accepted 1 "passed=0 failed=1 count=1" bin-ok "${P}" "${B}" "SUCCESS_LINE=$(printf 'a%.0s' $(seq 1 512))" COUNT=1
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
if [ "$(grep -cF -- "--features grpc" "${work}/args")" -eq 3 ]; then
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

# --- libtest の --logfile 判定・禁止行（#2962）---
# lib: ログがちょうど 1 行の `ok a::b::c`。要約行だけでは通さない。
check lib-summary-without-logfile 1 "reason=missing-libtest-ok" summary-only "${P}" "${T}" COUNT=2
check lib-logfile-ok 0 "passed=2 failed=0 count=2 test=a::b::c" ok "${P}" "${T}" COUNT=2
check lib-failed-reason-exit 1 "reason=exit" fail2 "${P}" "${T}" COUNT=3
LN="LIBTEST_NAME=sec1_x"
INTERLEAVED='test sec1_x ... {"level":"info","msg":"supervisor"}\nok\n'
check libtest-interleaved-stdout-pass 0 "passed=2 failed=0 count=2 test_bin=exec_x" gen "${P}" "${B}" "${LN}" "STUB_STDOUT=${INTERLEAVED}" 'STUB_LOG=ok sec1_x\n' COUNT=2
check libtest-two-lines 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" 'STUB_LOG=ok other\nok sec1_x\n' COUNT=1
check libtest-empty-log 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" 'STUB_LOG=' COUNT=2
check libtest-ignored 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" 'STUB_LOG=ignored sec1_x\n' COUNT=1
check libtest-failed-rc0 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" 'STUB_LOG=failed sec1_x\n' COUNT=1
check libtest-suffix-name 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" 'STUB_LOG=ok sec1_x_suffix\n' COUNT=1
check libtest-prefix-name 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" 'STUB_LOG=ok prefix::sec1_x\n' COUNT=1
check lib-two-lines 1 "reason=missing-libtest-ok" gen "${P}" "${T}" 'STUB_LOG=ok a::b::c\nok other\n' COUNT=1
# 2 回目はログを書かずに exit 0 でも、1 回目のログが残っていて合格に見えてはならない。
check libtest-stale-log 1 "passed=1 failed=1 count=2" gen "${P}" "${B}" "${LN}" 'STUB_LOG=ok sec1_x\n' STUB_LOG_FIRST_ONLY=1 COUNT=2
# SUCCESS_LINE は stdout と stderr を別々に照合する。
check bin-success-line-split-streams 0 "passed=2 failed=0" gen "${P}" "${B}" "${S}" 'STUB_STDOUT=exec_x: all scenarios passed\n' 'STUB_STDERR={"level":"info"}{"level":"info"}\n' COUNT=2
check success-line-on-stderr 0 "passed=1 failed=0" gen "${P}" "${B}" "${S}" 'STUB_STDERR=exec_x: all scenarios passed\n' COUNT=1
check success-line-merged-not-accepted 1 "reason=missing-success-line" gen "${P}" "${B}" "${S}" 'STUB_STDOUT=exec_x: all scenarios ' 'STUB_STDERR=passed\n' COUNT=1
check success-line-libtest-form-warns 0 "warning: SUCCESS_LINE looks like a libtest result line" gen "${P}" "${B}" "SUCCESS_LINE=test sec1_x ... ok" 'STUB_STDOUT=test sec1_x ... ok\n' COUNT=1
# 禁止行: 成功しても当たれば失敗。どのストリーム・ログに出ても検出する。
check forbidden-absent-pass 0 "passed=1 failed=0" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=(root=true)" 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-info-count 0 "info: forbidden_count=2" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=a|b" 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-semicolon-accepted 0 "passed=1 failed=0" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=a;b" 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-in-stdout 1 "reason=forbidden-line forbidden='(root=true)'" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=(root=true)" 'STUB_STDOUT=x (root=true) y\n' 'STUB_LOG=ok sec1_x\n' COUNT=2
check forbidden-in-stdout-count 1 "passed=0 failed=2 count=2" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=(root=true)" 'STUB_STDOUT=x (root=true) y\n' 'STUB_LOG=ok sec1_x\n' COUNT=2
check forbidden-in-stderr 1 "reason=forbidden-line" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=bad thing" 'STUB_STDERR=a bad thing\n' 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-in-logfile 1 "reason=forbidden-line" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=sec1" 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-multi-second 1 "forbidden='b2'" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=b1|b2" 'STUB_STDOUT=has b2 here\n' 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-lib-mode 1 "reason=forbidden-line" gen "${P}" "${T}" "FORBIDDEN_LINE=zzz" 'STUB_STDOUT=zzz\n' 'STUB_LOG=ok a::b::c\n' COUNT=1
check forbidden-success-line-mode 1 "reason=forbidden-line" gen "${P}" "${B}" "${S}" "FORBIDDEN_LINE=zzz" 'STUB_STDOUT=exec_x: all scenarios passed\nzzz\n' COUNT=1
# 失敗の優先順位: 成功行が無ければ missing が先。
check forbidden-after-missing 1 "reason=missing-libtest-ok" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=zzz" 'STUB_STDOUT=zzz\n' 'STUB_LOG=' COUNT=1
# 入力不正。
check libtest-name-with-success-line 2 "usage:" gen "${P}" "${B}" "${LN}" "${S}"
check bin-neither-mode 2 "usage:" gen "${P}" "${B}"
check libtest-name-in-lib-mode 2 "usage:" ok "${P}" "${T}" "${LN}"
check libtest-name-flag 2 "usage:" gen "${P}" "${B}" LIBTEST_NAME=-x
check libtest-name-slash 2 "usage:" gen "${P}" "${B}" LIBTEST_NAME=a/b
check libtest-name-space 2 "usage:" gen "${P}" "${B}" "LIBTEST_NAME=a b"
check libtest-name-too-long 2 "usage:" gen "${P}" "${B}" "LIBTEST_NAME=$(printf 'a%.0s' $(seq 1 257))"
# shellcheck disable=SC2016
check forbidden-bad-dollar 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=a$b'
# shellcheck disable=SC2016
check forbidden-bad-backtick 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=a`b'
check forbidden-bad-star 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=a*b'
check forbidden-empty-middle 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=a||b'
check forbidden-empty-head 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=|a'
check forbidden-empty-tail 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=a|'
check forbidden-9-items 2 "usage:" ok "${P}" "${T}" 'FORBIDDEN_LINE=q1|q2|q3|q4|q5|q6|q7|q8|q9'
check forbidden-8-items-accepted 0 "passed=1 failed=0" ok "${P}" "${T}" 'FORBIDDEN_LINE=q1|q2|q3|q4|q5|q6|q7|q8' COUNT=1
check forbidden-item-513 2 "usage:" ok "${P}" "${T}" "FORBIDDEN_LINE=$(printf 'a%.0s' $(seq 1 513))"
check forbidden-item-512-accepted 0 "passed=1 failed=0" ok "${P}" "${T}" "FORBIDDEN_LINE=$(printf 'a%.0s' $(seq 1 512))" COUNT=1
check forbidden-total-1025 2 "usage:" ok "${P}" "${T}" "FORBIDDEN_LINE=$(printf 'a%.0s' $(seq 1 400))|$(printf 'b%.0s' $(seq 1 400))|$(printf 'c%.0s' $(seq 1 223))"
check forbidden-equals-success-line 2 "usage:" gen "${P}" "${B}" "${S}" "FORBIDDEN_LINE=exec_x: all scenarios passed"
check forbidden-equals-libtest-ok 2 "usage:" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=ok sec1_x"
check forbidden-equals-lib-ok 2 "usage:" ok "${P}" "${T}" "FORBIDDEN_LINE=ok a::b::c"
# 成功した試験の出力（--no-capture のときだけ出る）の禁止行を検出する（P1）。FORBIDDEN_LINE 無しでは --no-capture を付けない。
check forbidden-no-capture-libtest 1 "reason=forbidden-line forbidden='(root=true)'" gen "${P}" "${B}" "${LN}" "FORBIDDEN_LINE=(root=true)" 'STUB_NC_STDOUT=x (root=true)\n' 'STUB_LOG=ok sec1_x\n' COUNT=1
check forbidden-no-capture-lib 1 "reason=forbidden-line" gen "${P}" "${T}" "FORBIDDEN_LINE=zzz" 'STUB_NC_STDOUT=zzz\n' 'STUB_LOG=ok a::b::c\n' COUNT=1
check no-capture-not-without-forbidden 0 "passed=1 failed=0" gen "${P}" "${B}" "${LN}" 'STUB_NC_STDOUT=(root=true)\n' 'STUB_LOG=ok sec1_x\n' COUNT=1
# 引数: --logfile は lib と LIBTEST_NAME にだけ付き、SUCCESS_LINE には付かない。
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${T}" COUNT=1 "${target}" >/dev/null 2>&1
if grep -qE -- "-- --exact a::b::c --logfile [^ ]+libtest.log$" "${work}/args"; then
  echo "OK: lib-logfile-args"
else
  echo "NG: lib-logfile-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=gen STUB_LOG='ok sec1_x\n' STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${B}" "${LN}" COUNT=1 "${target}" >/dev/null 2>&1
if grep -qE -- "--test exec_x -- --exact sec1_x --logfile [^ ]+libtest.log$" "${work}/args"; then
  echo "OK: libtest-args"
else
  echo "NG: libtest-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=gen STUB_LOG='ok sec1_x\n' STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" \
  "${P}" "${B}" "${LN}" TEST_IGNORED=1 COUNT=1 "${target}" >/dev/null 2>&1
if grep -qE -- "--test exec_x -- --ignored --exact sec1_x --logfile [^ ]+libtest.log$" "${work}/args"; then
  echo "OK: libtest-ignored-args"
else
  echo "NG: libtest-ignored-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1))
fi

# --- logfile 非対応のプリフライト（#3036）---
check logfile-unsupported-lib 1 "FAIL: preflight rc=101 reason=logfile-unsupported" ok "${P}" "${T}" STUB_NO_LOGFILE=1 COUNT=3
check logfile-unsupported-lib-count 1 "passed=0 failed=3 count=3 test=a::b::c" ok "${P}" "${T}" STUB_NO_LOGFILE=1 COUNT=3
check logfile-unsupported-libtest 1 "reason=logfile-unsupported" gen "${P}" "${B}" "${LN}" STUB_NO_LOGFILE=1 COUNT=2
check logfile-unsupported-libtest-count 1 "passed=0 failed=2 count=2 test_bin=exec_x" gen "${P}" "${B}" "${LN}" STUB_NO_LOGFILE=1 COUNT=2
check preflight-other-failure 1 "FAIL: preflight rc=3 reason=preflight-failed" ok "${P}" "${T}" STUB_PREFLIGHT_RC=3 COUNT=2
check preflight-accepted-info 0 "info: libtest_logfile=accepted" ok "${P}" "${T}" COUNT=1
check success-line-no-preflight 0 "passed=2 failed=0 count=2 test_bin=exec_x" bin-ok "${P}" "${B}" "${S}" STUB_NO_LOGFILE=1 COUNT=2
check success-line-unrecognized-is-exit 1 "reason=exit" gen "${P}" "${B}" "${S}" "STUB_STDERR=Unrecognized option: 'logfile'\n" STUB_RC=1 COUNT=1
# プリフライトで止まったときは本番のループが 1 回も走らない（カウンタが作られない）。
rm -f "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=ok STUB_NO_LOGFILE=1 STUB_COUNTER="${work}/counter" "${P}" "${T}" COUNT=2 "${target}" >/dev/null 2>&1
if [ ! -f "${work}/counter" ]; then echo "OK: logfile-unsupported-no-runs"; else echo "NG: logfile-unsupported-no-runs" >&2; fails=$((fails + 1)); fi
rm -f "${work}/args" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" "${P}" "${T}" COUNT=1 "${target}" >/dev/null 2>&1
if grep -qE -- "-- --list --logfile [^ ]+libtest.log$" "${work}/args"; then echo "OK: lib-preflight-args"; else echo "NG: lib-preflight-args" >&2; cat "${work}/args" >&2; fails=$((fails + 1)); fi

# --- 委譲スコープモード（USER_SCOPE=1）と TEST_ENV（#2886）---
SB="STUB_BIN=${work}/bin/exec_x_bin"
FL="SUCCESS_LINE=${FINAL_LINE}"
ENVH="TEST_ENV=FANDHE_CONTAINER_TEST_ID_HELPER=1"
[ "${#FINAL_LINE}" -gt 200 ] || { echo "NG: FINAL_LINE should exceed 200 chars" >&2; fails=$((fails + 1)); }
check scope-final-line-exact 0 "passed=2 failed=0 count=2 test_bin=exec_x" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 TEST_IGNORED=1 "${ENVH}" COUNT=2
check scope-info-names-only 0 "info: user_scope=1 test_env_names=FANDHE_CONTAINER_TEST_ID_HELPER" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 TEST_IGNORED=1 "${ENVH}" COUNT=1
check scope-partial-line-is-failure 1 "passed=0 failed=2 count=2" scope-prefix "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 "${ENVH}" COUNT=2
check scope-child-failure 1 "reason=exit" scope-fail "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 COUNT=1
check scope-env-reaches-child 0 "passed=1 failed=0" scope-ok "${P}" "${B}" "SUCCESS_LINE=env-seen: FANDHE_CONTAINER_TEST_ID_HELPER=1" "${SB}" USER_SCOPE=1 "${ENVH}" COUNT=1
check scope-env-absent-without-test-env 0 "passed=1 failed=0" scope-ok "${P}" "${B}" "SUCCESS_LINE=env-seen: FANDHE_CONTAINER_TEST_ID_HELPER=unset" "${SB}" USER_SCOPE=1 COUNT=1
check scope-user-passed 0 "passed=1 failed=0" scope-ok "${P}" "${B}" "SUCCESS_LINE=user-seen: stubuser" "${SB}" USER_SCOPE=1 USER=stubuser COUNT=1
# RUN_TIMEOUT の受け渡し（#2886）: 遅い 1 回は短い上限なら timeout、十分な上限なら合格。ハングは timeout で打ち切る。
check scope-timeout 1 "reason=timeout" scope-hang "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 COUNT=1 RUN_TIMEOUT=1
check scope-slow-short-timeout 1 "reason=timeout" scope-slow "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 COUNT=1 RUN_TIMEOUT=1
check scope-slow-long-timeout 0 "passed=1 failed=0" scope-slow "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 COUNT=1 RUN_TIMEOUT=30
rm -f "${work}/args" "${work}/sd" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=scope-ok STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" STUB_SD_LOG="${work}/sd" \
  "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 TEST_IGNORED=1 COUNT=3 "${target}" >/dev/null 2>&1
if [ "$(grep -c -- "--message-format=json" "${work}/args")" -eq 1 ] && [ "$(wc -l <"${work}/args" | tr -d ' ')" -eq 1 ] \
  && [ "$(wc -l <"${work}/sd" | tr -d ' ')" -eq 3 ] \
  && grep -qE -- "^--user --scope --quiet -p Delegate=yes --unit=fandhe-repeat-[0-9]+-1 -- ${work}/bin/exec_x_bin --ignored$" "${work}/sd"; then
  echo "OK: scope-args"
else
  echo "NG: scope-args" >&2; cat "${work}/args" "${work}/sd" >&2; fails=$((fails + 1))
fi
# USER_SCOPE の直接実行にも --exact が渡る（#3037）。
for ign in 1 ""; do
  rm -f "${work}/args" "${work}/sd" "${work}/counter"
  if [ -n "${ign}" ]; then ign_arg="--ignored "; else ign_arg=""; fi
  env PATH="${work}/bin:${PATH}" STUB_MODE=scope-gen STUB_LOG='ok sec1_x\n' STUB_BIN="${work}/bin/exec_x_bin" STUB_COUNTER="${work}/counter" STUB_ARGS_LOG="${work}/args" STUB_SD_LOG="${work}/sd" \
    "${P}" "${B}" "${LN}" USER_SCOPE=1 ${ign:+TEST_IGNORED=1} COUNT=1 "${target}" >/dev/null 2>&1
  if grep -qE -- "^--user --scope --quiet -p Delegate=yes --unit=fandhe-repeat-[0-9]+-1 -- ${work}/bin/exec_x_bin ${ign_arg}--exact sec1_x --logfile [^ ]+libtest.log$" "${work}/sd"; then
    echo "OK: scope-libtest-args-ignored${ign:-0}"
  else
    echo "NG: scope-libtest-args-ignored${ign:-0}" >&2; cat "${work}/sd" >&2; fails=$((fails + 1))
  fi
done
check scope-libtest-pass 0 "passed=1 failed=0 count=1 test_bin=exec_x" scope-gen "${P}" "${B}" "${LN}" "${SB}" USER_SCOPE=1 TEST_IGNORED=1 'STUB_LOG=ok sec1_x\n' COUNT=1
check scope-libtest-missing 1 "reason=missing-libtest-ok" scope-gen "${P}" "${B}" "${LN}" "${SB}" USER_SCOPE=1 'STUB_LOG=' COUNT=1
check scope-forbidden 1 "reason=forbidden-line forbidden='(root=true)'" scope-gen "${P}" "${B}" "${LN}" "${SB}" USER_SCOPE=1 "FORBIDDEN_LINE=(root=true)" 'STUB_STDOUT=x (root=true)\n' 'STUB_LOG=ok sec1_x\n' COUNT=1
check scope-forbidden-no-capture 1 "reason=forbidden-line forbidden='(root=true)'" scope-gen "${P}" "${B}" "${LN}" "${SB}" USER_SCOPE=1 "FORBIDDEN_LINE=(root=true)" 'STUB_NC_STDOUT=x (root=true)\n' 'STUB_LOG=ok sec1_x\n' COUNT=1
check scope-success-line-forbidden 1 "passed=0 failed=1 count=1" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 "FORBIDDEN_LINE=(root=false)" COUNT=1
check scope-binary-none 1 "not uniquely identified" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 STUB_JSON_MODE=none
check scope-binary-two 1 "not uniquely identified" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 STUB_JSON_MODE=two
check scope-binary-null 1 "not uniquely identified" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=1 STUB_JSON_MODE=null
check logfile-unsupported-scope 1 "reason=logfile-unsupported" scope-gen "${P}" "${B}" "${LN}" "${SB}" USER_SCOPE=1 STUB_NO_LOGFILE=1 COUNT=1
check scope-with-lib 2 "usage:" ok "${P}" "${T}" USER_SCOPE=1
check scope-without-bin 2 "usage:" ok "${P}" USER_SCOPE=1
check scope-invalid-value 2 "usage:" scope-ok "${P}" "${B}" "${FL}" "${SB}" USER_SCOPE=yes
# systemd-run が PATH に無いときは skip せず失敗にする（require_cmd の失敗）。
# systemd-run を持たないホスト（macOS・Windows の Git Bash）では通常の PATH がすでにその状態なので、そのまま使う。
# Git Bash は `ln -sf` で symlink を作れず、`kill` 等の組み込みも解決先が無いため、PATH の組み立てを避ける（#2955）。
# systemd-run を持つホスト（Linux）では、必要なツールだけを symlink した PATH で検証する。
if command -v systemd-run >/dev/null 2>&1; then
  mkdir -p "${work}/nosd"
  for t in bash env jq cat mktemp rm dirname cut tr grep sort wc sed id uname head sleep kill ps date mkdir ls cargo; do
    src="$(command -v "${t}" 2>/dev/null || true)"
    case "${t}" in cargo) src="${work}/bin/cargo" ;; esac
    case "${src}" in /*) ln -sf "${src}" "${work}/nosd/${t}" ;; esac
  done
  nosd_path="${work}/nosd"
  nosd_bash="${work}/nosd/bash"
else
  # work/bin には systemd-run のスタブがあるため PATH に入れない。cargo のスタブだけを別ディレクトリへ写す（symlink にしない）。
  mkdir -p "${work}/nosd"
  cp "${work}/bin/cargo" "${work}/nosd/cargo"
  nosd_path="${work}/nosd:${PATH}"
  nosd_bash="$(command -v bash)"
fi
rc=0
out="$(env -i PATH="${nosd_path}" STUB_MODE=scope-ok STUB_COUNTER="${work}/counter" STUB_BIN="${work}/bin/exec_x_bin" \
  PACKAGE=fandhe-container-x TEST_BIN=exec_x "${FL}" USER_SCOPE=1 "${nosd_bash}" "${target}" 2>&1)" || rc=$?
if [ "${rc}" -ne 0 ] && ! printf '%s' "${out}" | grep -q '^skip:' && printf '%s' "${out}" | grep -q 'systemd-run'; then
  echo "OK: scope-missing-systemd-run"
else
  echo "NG: scope-missing-systemd-run rc=${rc}" >&2; printf '%s\n' "${out}" >&2; fails=$((fails + 1))
fi
check test-env-bad-key-path 2 "usage:" ok "${P}" "${T}" TEST_ENV=PATH=/x
check test-env-bad-key-ld 2 "usage:" ok "${P}" "${T}" TEST_ENV=LD_PRELOAD=x
check test-env-bad-key-user 2 "usage:" ok "${P}" "${T}" TEST_ENV=USER=x
check test-env-bad-key-lower 2 "usage:" ok "${P}" "${T}" TEST_ENV=FANDHE_CONTAINER_a=1
check test-env-no-equal 2 "usage:" ok "${P}" "${T}" TEST_ENV=FANDHE_CONTAINER_A
# shellcheck disable=SC2016
check test-env-bad-value-dollar 2 "usage:" ok "${P}" "${T}" 'TEST_ENV=FANDHE_CONTAINER_A=$x'
check test-env-bad-value-semicolon 2 "usage:" ok "${P}" "${T}" 'TEST_ENV=FANDHE_CONTAINER_A=a;b'
check test-env-value-too-long 2 "usage:" ok "${P}" "${T}" "TEST_ENV=FANDHE_CONTAINER_A=$(printf 'a%.0s' $(seq 1 129))"
check test-env-too-many 2 "usage:" ok "${P}" "${T}" "TEST_ENV=FANDHE_CONTAINER_A=1 FANDHE_CONTAINER_B=1 FANDHE_CONTAINER_C=1 FANDHE_CONTAINER_D=1 FANDHE_CONTAINER_E=1 FANDHE_CONTAINER_F=1 FANDHE_CONTAINER_G=1 FANDHE_CONTAINER_H=1 FANDHE_CONTAINER_I=1"
# 非 scope の結合試験モードでも、TEST_ENV の値は cargo の子にだけ届く。
rm -f "${work}/envlog" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=bin-ok STUB_COUNTER="${work}/counter" STUB_ENV_LOG="${work}/envlog" \
  "${P}" "${B}" "${S}" "${ENVH}" COUNT=2 "${target}" >/dev/null 2>&1
if [ "$(grep -cxF 'cargo-env: 1' "${work}/envlog")" -eq 2 ]; then
  echo "OK: test-env-non-scope"
else
  echo "NG: test-env-non-scope" >&2; cat "${work}/envlog" >&2; fails=$((fails + 1))
fi
rm -f "${work}/envlog" "${work}/counter"
env PATH="${work}/bin:${PATH}" STUB_MODE=bin-ok STUB_COUNTER="${work}/counter" STUB_ENV_LOG="${work}/envlog" \
  "${P}" "${B}" "${S}" COUNT=1 "${target}" >/dev/null 2>&1
if grep -qxF 'cargo-env: unset' "${work}/envlog"; then
  echo "OK: test-env-absent"
else
  echo "NG: test-env-absent" >&2; cat "${work}/envlog" >&2; fails=$((fails + 1))
fi
check count-zero 2 "usage:" ok "${P}" "${T}" COUNT=0
check count-over 2 "usage:" ok "${P}" "${T}" COUNT=1001

[ "${fails}" -eq 0 ] || { echo "repeat-test-selftest: ${fails} failure(s)" >&2; exit 1; }
echo "repeat-test-selftest: all passed"
