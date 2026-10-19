#!/usr/bin/env bash
# scripts/cri/crictl-smoke.sh と scripts/targets/crictl-smoke.sh の自己テスト（TASK-60・CRI-1・REPAIR-12）。
#
# 役割: bash 製のスタブ crictl と mktemp -d 配下の UNIX ソケットだけで、手順の順序・記録・失敗時のログ・後始末・
# 終了コードを具体値で照合する。実物の crictl・CRI サーバー・root は使わない（実機は #442 で人間が行う）。
# 呼び出し元は Makefile の `crictl-smoke-selftest`（CI の bench-regression ジョブでも実行）。
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。python3 が無い環境は skip せず失敗する。
#
# スタブの挙動は環境変数で切り替える（crictl-smoke.sh から継承される）:
#   STUB_LOG: 受け取ったサブコマンドと引数を 1 行ずつ追記するファイル
#   STUB_FAIL_AT: このサブコマンドを非 0 で終了させる（stderr に理由を出す）
#   STUB_HANG_AT: このサブコマンドで長時間待つ（期限切れの模擬）
#   STUB_BAD_ID_AT / STUB_BAD_ID: このサブコマンド（runp|create）が STUB_BAD_ID を ID として出力する
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${DIR}/../.." && pwd)"
SMOKE="${ROOT}/scripts/cri/crictl-smoke.sh"
PASS=0
FAILS=0

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL: $1"; }
assert_eq() { # <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
assert_has() { # <desc> <file> <fixed string>
  if grep -qF -- "$3" "$2" 2>/dev/null; then pass "$1"; else fail "$1 (missing '$3' in $2)"; fi
}
assert_lacks() { # <desc> <file> <fixed string>
  if grep -qF -- "$3" "$2" 2>/dev/null; then fail "$1 (unexpected '$3' in $2)"; else pass "$1"; fi
}

command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 is required to create a UNIX socket"; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo "FAIL: timeout (coreutils) is required"; exit 1; }
command -v pgrep >/dev/null 2>&1 || { echo "FAIL: pgrep is required"; exit 1; }

T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT

SOCK="${T}/cri.sock"
python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${SOCK}"
EP="unix://${SOCK}"
SID="$(printf 'a%.0s' $(seq 1 64))"
CID="$(printf 'b%.0s' $(seq 1 64))"

cat >"${T}/crictl" <<EOF
#!/usr/bin/env bash
# スタブ。argv は crictl --runtime-endpoint E --image-endpoint E --timeout T <sub> <args...>
shift 6
sub="\$1"
shift
printf '%s' "\${sub}" >>"\${STUB_LOG}"
for a in "\$@"; do printf ' %s' "\${a}" >>"\${STUB_LOG}"; done
printf '\n' >>"\${STUB_LOG}"
if [ "\${STUB_HANG_AT:-}" = "\${sub}" ]; then exec sleep 7311; fi
if [ "\${STUB_FAIL_AT:-}" = "\${sub}" ]; then echo "stub: \${sub} failed on purpose" >&2; exit 1; fi
if [ "\${STUB_BAD_ID_AT:-}" = "\${sub}" ]; then printf '%s\n' "\${STUB_BAD_ID}"; exit 0; fi
case "\${sub}" in
  runp) echo "${SID}" ;;
  create) echo "${CID}" ;;
esac
exit 0
EOF
chmod +x "${T}/crictl"

N=0
RC=0
LOGD=""
ERR=""
STUB=""
# 1 ケース実行する: 結果は RC・LOGD・ERR・STUB に入る。追加の環境変数は呼び出し側で export する。
run_case() { # <extra args...>
  N=$((N + 1))
  LOGD="${T}/logs/case${N}"
  ERR="${T}/case${N}.err"
  STUB="${T}/case${N}.stub"
  : >"${STUB}"
  RC=0
  STUB_LOG="${STUB}" bash "${SMOKE}" --endpoint "${EP}" --crictl "${T}/crictl" --log-dir "${LOGD}" "$@" >"${T}/case${N}.out" 2>"${ERR}" || RC=$?
}

# 1. 全手順の成功
run_case
assert_eq "success: exit code" 0 "${RC}"
assert_has "success: version summary" "${LOGD}/summary.txt" "step=version status=ok exit=0"
assert_has "success: runp summary" "${LOGD}/summary.txt" "step=runp status=ok exit=0"
assert_has "success: create summary" "${LOGD}/summary.txt" "step=create status=ok exit=0"
assert_has "success: start summary" "${LOGD}/summary.txt" "step=start status=ok exit=0"
assert_has "success: result line" "${ERR}" "result=ok log_dir=${LOGD}"
assert_eq "success: call order" "version
runp ${ROOT}/scripts/testdata/cri/pod.json
create ${SID} ${ROOT}/scripts/testdata/cri/container.json ${ROOT}/scripts/testdata/cri/pod.json
start ${CID}
stop ${CID}
rm ${CID}
stopp ${SID}
rmp ${SID}" "$(cat "${STUB}")"
assert_has "success: argv records the endpoint" "${LOGD}/02-runp.argv" "--runtime-endpoint"
assert_eq "success: sandbox ID recorded in stdout" "${SID}" "$(cat "${LOGD}/02-runp.stdout")"

# 2. 各手順の失敗
for step in runp create start; do
  STUB_FAIL_AT="${step}" run_case
  assert_eq "fail ${step}: exit code" 1 "${RC}"
  assert_has "fail ${step}: failed_step" "${ERR}" "result=failed failed_step=${step}"
  assert_has "fail ${step}: step status" "${LOGD}/summary.txt" "step=${step} status=failed exit=1"
  assert_has "fail ${step}: stderr is quoted" "${ERR}" "  | stub: ${step} failed on purpose"
done
STUB_FAIL_AT=runp run_case
assert_has "fail runp: create is skipped" "${LOGD}/summary.txt" "step=create status=skipped"
assert_has "fail runp: start is skipped" "${LOGD}/summary.txt" "step=start status=skipped"
assert_eq "fail runp: only version and runp were called" "version
runp ${ROOT}/scripts/testdata/cri/pod.json" "$(cat "${STUB}")"
STUB_FAIL_AT=create run_case
assert_has "fail create: start is skipped" "${LOGD}/summary.txt" "step=start status=skipped"
assert_eq "fail create: only the sandbox is cleaned up" "stopp ${SID}
rmp ${SID}" "$(tail -n 2 "${STUB}")"
assert_lacks "fail create: start was not called" "${STUB}" "start "
STUB_FAIL_AT=start run_case
assert_eq "fail start: container and sandbox are cleaned up" "stop ${CID}
rm ${CID}
stopp ${SID}
rmp ${SID}" "$(tail -n 4 "${STUB}")"

# 3. 手順のハング（期限切れ）
STUB_HANG_AT=runp run_case --step-timeout 1
assert_eq "hang: exit code" 1 "${RC}"
assert_has "hang: timeout status" "${LOGD}/summary.txt" "step=runp status=timeout"
assert_has "hang: failed_step" "${ERR}" "failed_step=runp"
assert_eq "hang: no leftover process" 0 "$(pgrep -fc 'sleep 7311' || true)"

# 4. 不正な ID
BAD63="$(printf 'a%.0s' $(seq 1 63))"
BADUP="$(printf 'A%.0s' $(seq 1 64))"
BADSP="$(printf 'a%.0s' $(seq 1 32)) $(printf 'a%.0s' $(seq 1 31))"
BADMETA="$(printf 'a%.0s' $(seq 1 56));rm -rf"
for bad in "" "${BAD63}" "${BADUP}" "${BADSP}" "${BADMETA}"; do
  STUB_BAD_ID_AT=runp STUB_BAD_ID="${bad}" run_case
  assert_eq "invalid ID '${bad}': exit code" 1 "${RC}"
  assert_has "invalid ID '${bad}': status" "${LOGD}/summary.txt" "step=runp status=invalid-id"
  assert_eq "invalid ID '${bad}': nothing after runp was called" "version
runp ${ROOT}/scripts/testdata/cri/pod.json" "$(cat "${STUB}")"
done
STUB_BAD_ID_AT=create STUB_BAD_ID="${BAD63}" run_case
assert_has "invalid container ID: status" "${LOGD}/summary.txt" "step=create status=invalid-id"
assert_lacks "invalid container ID: start was not called" "${STUB}" "start "

# 5. 前提欠如
run_case --crictl "${T}/missing"
assert_eq "prereq: crictl missing" 3 "${RC}"
N=$((N + 1))
RC=0
bash "${SMOKE}" --endpoint "unix://${T}/not-a-socket" --crictl "${T}/crictl" --log-dir "${T}/logs/ns" >/dev/null 2>&1 || RC=$?
assert_eq "prereq: endpoint is not a socket" 3 "${RC}"
STUB_FAIL_AT=version run_case
assert_eq "prereq: Version RPC fails" 3 "${RC}"
assert_has "prereq: version failure is reported as a prerequisite" "${ERR}" "code=prerequisite-failed message=step=version"
assert_eq "prereq: runp is not attempted" "version" "$(cat "${STUB}")"

# 6. 引数エラー
expect2() { # <desc> <args...>
  local desc="$1" rc=0
  shift
  bash "${SMOKE}" "$@" >/dev/null 2>&1 || rc=$?
  assert_eq "${desc}" 2 "${rc}"
}
expect2 "args: tcp endpoint" --endpoint tcp://127.0.0.1:1 --crictl "${T}/crictl"
expect2 "args: relative endpoint path" --endpoint unix://relative.sock --crictl "${T}/crictl"
expect2 "args: missing endpoint" --crictl "${T}/crictl"
expect2 "args: unknown option" --endpoint "${EP}" --bogus
expect2 "args: step-timeout 0" --endpoint "${EP}" --crictl "${T}/crictl" --step-timeout 0
expect2 "args: step-timeout not a number" --endpoint "${EP}" --crictl "${T}/crictl" --step-timeout abc
expect2 "args: crictl-timeout with a bad unit" --endpoint "${EP}" --crictl "${T}/crictl" --crictl-timeout 10x
mkdir "${T}/existing"
expect2 "args: log-dir exists" --endpoint "${EP}" --crictl "${T}/crictl" --log-dir "${T}/existing"
head -c 1048577 /dev/zero | tr '\0' ' ' >"${T}/big.json"
expect2 "args: config over 1 MiB" --endpoint "${EP}" --crictl "${T}/crictl" --pod-config "${T}/big.json" --log-dir "${T}/logs/big"
expect2 "args: option without a value" --endpoint

# 7. 後始末
STUB_FAIL_AT=rmp run_case
assert_eq "cleanup failure on success: exit code" 4 "${RC}"
assert_has "cleanup failure: result is still ok" "${ERR}" "result=ok"
STUB_FAIL_AT=rmp STUB_BAD_ID_AT=create STUB_BAD_ID="${BAD63}" run_case
assert_eq "cleanup failure on a failed run keeps exit 1" 1 "${RC}"
run_case --keep
assert_eq "keep: exit code" 0 "${RC}"
assert_lacks "keep: no cleanup calls" "${STUB}" "stopp "
assert_lacks "keep: no rm call" "${STUB}" "rmp "
bash "${SMOKE}" --print-budget >"${T}/budget.out" 2>&1
assert_eq "print-budget default" 550 "$(cat "${T}/budget.out")"

# 8. make の入口（scripts/targets/crictl-smoke.sh）。make 自体はレシピの失敗をすべて 2 にするため、
# 終了コードの変換はターゲットのスクリプトを直接実行して照合し、make 経由では必須変数と Error N の出力だけを見る。
TARGET="${ROOT}/scripts/targets/crictl-smoke.sh"
RC=0
(cd "${ROOT}" && env -u CRI_ENDPOINT bash "${TARGET}" >/dev/null 2>&1) || RC=$?
assert_eq "target: CRI_ENDPOINT missing" 2 "${RC}"
RC=0
(cd "${ROOT}" && env -u CRI_ENDPOINT make --no-print-directory crictl-smoke >/dev/null 2>&1) || RC=$?
assert_eq "make: CRI_ENDPOINT missing fails" 2 "${RC}"
# shellcheck disable=SC2016 # 生成するスクリプトの中で展開させる
printf '#!/usr/bin/env bash\ncase "$1" in --print-budget) echo 100 ;; *) kill -TERM $$ ;; esac\n' >"${T}/fake-term.sh"
# shellcheck disable=SC2016
printf '#!/usr/bin/env bash\ncase "$1" in --print-budget) echo 100 ;; *) exit 3 ;; esac\n' >"${T}/fake-exit3.sh"
RC=0
(cd "${ROOT}" && CRICTL_SMOKE_SCRIPT="${T}/fake-term.sh" CRI_ENDPOINT="${EP}" bash "${TARGET}" >/dev/null 2>&1) || RC=$?
assert_eq "target: a signal-terminated run is normalized to 1" 1 "${RC}"
RC=0
(cd "${ROOT}" && CRICTL_SMOKE_SCRIPT="${T}/fake-exit3.sh" CRI_ENDPOINT="${EP}" bash "${TARGET}" >/dev/null 2>&1) || RC=$?
assert_eq "target: exit code 3 is passed through" 3 "${RC}"
(cd "${ROOT}" && CRICTL_SMOKE_SCRIPT="${T}/fake-exit3.sh" make --no-print-directory crictl-smoke CRI_ENDPOINT="${EP}" >"${T}/make.out" 2>&1) || true
assert_has "make: the target's exit code is shown as Error 3" "${T}/make.out" "Error 3"

echo "crictl-smoke selftest: ${PASS} passed, ${FAILS} failed"
if [ "${FAILS}" -ne 0 ]; then exit 1; fi
