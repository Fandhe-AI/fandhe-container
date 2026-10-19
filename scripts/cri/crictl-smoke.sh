#!/usr/bin/env bash
# crictl による CRI 疎通確認の自動検証（TASK-60・CRI-1・MS-4。実機での実行と判定は #442 で人間が行う）。
#
# 役割: 指定した CRI エンドポイント（UDS）に対し、実物の crictl で `runp` -> `create` -> `start` をこの順に実行し、
# 各手順の終了コードと出力（stdout・stderr）を --log-dir に記録して成否を判定する。CRI の `RunPodSandbox` ->
# `CreateContainer` -> `StartContainer` の中核フロー（CRI-1）が 1 本通ることだけを見る。性能や挙動の細部は見ない。
# 呼び出し元: `make crictl-smoke`（scripts/targets/crictl-smoke.sh。全体期限つき）と、スタブの crictl で照合する
# scripts/cri/crictl-smoke-selftest.sh。特定のサーバー実装には依存せず、任意の `unix://` エンドポイントを受け取る。
#
# 使い方:
#   crictl-smoke.sh --endpoint unix:///abs/path.sock [--crictl <abs>] [--pod-config <file>] [--container-config <file>]
#                   [--log-dir <new dir>] [--step-timeout <secs, 1-999999, 既定 60>] [--crictl-timeout <10s 等, 既定 10s>]
#                   [--keep] | --print-budget
# 前提: イメージは事前に `crictl pull` 済み（create が pull するかは crictl の版で異なる。docs/verification/crictl-smoke.md）。
# 記録: <log-dir>/<NN>-<step>.{argv,stdout,stderr} と summary.txt（`step=<name> status=<...> exit=<n> duration_ms=<n>`）。
# 後始末: --keep が無ければ作れた ID だけ stop -> rm -> stopp -> rmp を逆順で試みる（sandbox の重複作成拒否で再実行が
# 失敗しないように。#2293）。判定の 0/1 は後始末で上書きしない。
# 終了コード: 0 = 3 手順とも成功、1 = いずれかの手順が失敗（期限切れ・ID 不正を含む）、2 = 引数・出力先の誤り、
# 3 = 前提欠如（crictl・timeout・ソケット・Version RPC）、4 = 後始末の失敗（判定が成功のときのみ）。
# 出力文字列は英語。sudo は呼ばない。bash 3.2 でも動く書き方に限る。
set -euo pipefail
ORIG_PWD="$PWD"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

usage() {
  echo "usage: crictl-smoke.sh --endpoint unix:///<abs> [--crictl <abs>] [--pod-config <file>] [--container-config <file>] [--log-dir <new dir>] [--step-timeout <secs>] [--crictl-timeout <e.g. 10s>] [--keep] | --print-budget" >&2
}
bad_arg() {
  err_code invalid-argument "$1"
  usage
  exit 2
}

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "${ORIG_PWD}" "$1" ;;
  esac
}

EP=""
CRICTL="crictl"
POD="${ROOT_DIR}/scripts/testdata/cri/pod.json"
CTR="${ROOT_DIR}/scripts/testdata/cri/container.json"
LOG_DIR=""
STEP_TIMEOUT=60
CRICTL_TIMEOUT="10s"
KEEP=0
PRINT_BUDGET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --print-budget) PRINT_BUDGET=1; shift ;;
    --endpoint | --crictl | --pod-config | --container-config | --log-dir | --step-timeout | --crictl-timeout)
      [ $# -ge 2 ] || bad_arg "$1 requires a value"
      case "$1" in
        --endpoint) EP="$2" ;;
        --crictl) CRICTL="$2" ;;
        --pod-config) POD="$(abs_path "$2")" ;;
        --container-config) CTR="$(abs_path "$2")" ;;
        --log-dir) LOG_DIR="$(abs_path "$2")" ;;
        --step-timeout) STEP_TIMEOUT="$2" ;;
        --crictl-timeout) CRICTL_TIMEOUT="$2" ;;
      esac
      shift 2
      ;;
    *) bad_arg "unknown argument: $1" ;;
  esac
done

int_in_range "${STEP_TIMEOUT}" 1 999999 || bad_arg "--step-timeout must be an integer from 1 to 999999 (seconds)"
# 先頭ゼロ（010 が 8 進の 8 と読まれる、08・09 が算術エラーになる）を除いて 10 進にそろえ、以降の予算計算と timeout に使う。
while [ "${#STEP_TIMEOUT}" -gt 1 ] && [ "${STEP_TIMEOUT#0}" != "${STEP_TIMEOUT}" ]; do STEP_TIMEOUT="${STEP_TIMEOUT#0}"; done
if [ "${PRINT_BUDGET}" = 1 ]; then
  # version 1 + 本手順 3 + 後始末 4 の最悪値に余裕 30 秒（REPAIR-5。make 側の全体期限の既定）
  echo $(((1 + 3 + 4) * (STEP_TIMEOUT + 5) + 30))
  exit 0
fi

# crictl の --timeout に渡す期間。数値 + 任意の単位（ms・s・m・h）に限り、他は拒否する。
_dur="${CRICTL_TIMEOUT%ms}"
[ "${_dur}" != "${CRICTL_TIMEOUT}" ] || _dur="${CRICTL_TIMEOUT%[smh]}"
int_in_range "${_dur}" 1 999999 || bad_arg "--crictl-timeout must look like 10s (digits with an optional ms, s, m or h unit)"

[ -n "${EP}" ] || bad_arg "--endpoint is required"
case "${EP}" in
  unix:///*) ;;
  *) bad_arg "--endpoint must be unix:///<absolute path> (TCP endpoints are refused)" ;;
esac
SOCK="${EP#unix://}"
case "${SOCK}" in *[!A-Za-z0-9_./@:+,=-]*) bad_arg "--endpoint path has unsupported characters" ;; esac

check_config() {
  [ -f "$2" ] || bad_arg "$1 is not a regular file: $2"
  local size
  size=$(($(wc -c <"$2")))
  [ "${size}" -le 1048576 ] || bad_arg "$1 exceeds 1 MiB: $2"
}
check_config --pod-config "${POD}"
check_config --container-config "${CTR}"

if [ -z "${LOG_DIR}" ]; then
  LOG_DIR="${ROOT_DIR}/target/crictl-smoke/$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
[ ! -e "${LOG_DIR}" ] || bad_arg "--log-dir already exists (refusing to overwrite): ${LOG_DIR}"

# 前提の確認（欠けていれば 3）
prereq() {
  err_code prerequisite-failed "$1"
  exit 3
}
command -v timeout >/dev/null 2>&1 || prereq "timeout (coreutils) is required"
case "${CRICTL}" in
  */*) [ -x "${CRICTL}" ] || prereq "crictl is not executable: ${CRICTL}" ;;
  *) command -v "${CRICTL}" >/dev/null 2>&1 || prereq "crictl was not found in PATH" ;;
esac
[ -S "${SOCK}" ] || prereq "endpoint path is not a UNIX socket: ${SOCK}"

mkdir -p "$(dirname "${LOG_DIR}")"
mkdir -m 0700 "${LOG_DIR}" 2>/dev/null || bad_arg "cannot create --log-dir: ${LOG_DIR}"
SUMMARY="${LOG_DIR}/summary.txt"
: >"${SUMMARY}"

now_ms() {
  local n
  n="$(date +%s%N 2>/dev/null || true)"
  case "${n}" in
    '' | *[!0-9]*) echo $(($(date +%s) * 1000)) ;;
    *) echo $((n / 1000000)) ;;
  esac
}

STEP_N=0
CHILD_PID=""
STEP_BASE=""
STEP_RC=0
STEP_STATUS=""
RAN=" "

record() { # <name> <status> <exit> <ms>
  local line
  line="step=$1 status=$2 exit=$3 duration_ms=$4"
  printf '%s\n' "${line}" >>"${SUMMARY}"
  printf '%s\n' "${line}" >&2
}

# crictl を 1 回、期限つきで実行して記録する。結果は STEP_RC・STEP_STATUS・STEP_BASE に入る。
# 引数は配列で渡し、eval やシェル文字列への連結をしない。利用者の /etc/crictl.yaml に左右されないよう
# エンドポイントは毎回明示する。
run_crictl() { # <name> <crictl subcommand and args...>
  local name="$1"
  shift
  STEP_N=$((STEP_N + 1))
  STEP_BASE="$(printf '%s/%02d-%s' "${LOG_DIR}" "${STEP_N}" "${name}")"
  local argv=("${CRICTL}" --runtime-endpoint "${EP}" --image-endpoint "${EP}" --timeout "${CRICTL_TIMEOUT}" "$@")
  printf '%s\n' "${argv[@]}" >"${STEP_BASE}.argv"
  local t0 t1 rc=0
  t0="$(now_ms)"
  # シグナルの trap をすぐ動かすため、前景ではなく背景で起動して wait する（前景だと子の終了まで trap が遅れる）。
  timeout --kill-after=5 "${STEP_TIMEOUT}" "${argv[@]}" >"${STEP_BASE}.stdout" 2>"${STEP_BASE}.stderr" </dev/null &
  CHILD_PID=$!
  wait "${CHILD_PID}" || rc=$?
  CHILD_PID=""
  t1="$(now_ms)"
  STEP_RC="${rc}"
  case "${rc}" in
    0) STEP_STATUS=ok ;;
    124 | 137) STEP_STATUS=timeout ;;
    *) STEP_STATUS=failed ;;
  esac
  RAN="${RAN}${name} "
  record "${name}" "${STEP_STATUS}" "${rc}" "$((t1 - t0))"
}

# stdout の最後の非空行から ID を取り出し、64 文字の小文字 16 進であることを確かめる（runtime_service の採番形式）。
# 信頼できない出力をそのまま次のコマンドへ渡さない。
extract_id() { # <stdout file>
  local id
  id="$(awk 'NF { l = $0 } END { gsub(/^[ \t\r]+|[ \t\r]+$/, "", l); print l }' "$1")"
  [ "${#id}" -eq 64 ] || return 1
  case "${id}" in *[!0-9a-f]*) return 1 ;; esac
  printf '%s\n' "${id}"
}

FAILED_STEP=""
fail_step() { # <name> <code> <message>
  FAILED_STEP="$1"
  err_code "$2" "step=$1 exit=${STEP_RC} $3"
  if [ -s "${STEP_BASE}.stderr" ]; then
    tail -n 20 "${STEP_BASE}.stderr" | sed 's/^/  | /' >&2
  fi
}

SID=""
CID=""

# 後始末（ベストエフォート）。作れた ID に対してだけ、逆順に実行する。
CLEAN_FAIL=0
cleanup_step() { # <name> <crictl subcommand and args...>
  run_crictl "$@"
  if [ "${STEP_STATUS}" != ok ]; then
    CLEAN_FAIL=1
    echo "warning: ${1} failed (${STEP_STATUS}); the sandbox or container may remain, inspect it manually" >&2
  fi
}
do_cleanup() {
  [ "${KEEP}" = 0 ] || return 0
  if [ -n "${CID}" ]; then
    cleanup_step cleanup-stop stop "${CID}"
    cleanup_step cleanup-rm rm "${CID}"
  fi
  if [ -n "${SID}" ]; then
    cleanup_step cleanup-stopp stopp "${SID}"
    cleanup_step cleanup-rmp rmp "${SID}"
  fi
}

# 中断（INT・TERM・HUP。make 側の全体期限の TERM を含む）: 進行中の crictl を止め、取得済みの ID だけを有限時間で回収する。
# 回収の各手順は 5 秒（kill-after 込みで最大 10 秒 x 4）に絞り、make 側の kill-after（60 秒）に収める。ID が未取得の
# 手順（runp・create の実行中の中断）で作られた資源は特定できないため、残存の可能性を明示する。
on_signal() { # <signal name>
  trap '' INT TERM HUP
  if [ -n "${CHILD_PID}" ]; then
    kill "${CHILD_PID}" 2>/dev/null || true
    wait "${CHILD_PID}" 2>/dev/null || true
    CHILD_PID=""
    echo "warning: interrupted by $1 while a crictl step was running; a resource created by that step has no known ID and may remain, inspect it manually" >&2
  fi
  STEP_TIMEOUT=5
  do_cleanup
  echo "result=failed failed_step=interrupted log_dir=${LOG_DIR}" | tee -a "${SUMMARY}" >&2
  [ "${CLEAN_FAIL}" = 0 ] || echo "warning: cleanup after $1 did not finish; remaining resources may exist, check them manually" >&2
  exit 1
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP


# 手順 0: Version RPC での到達確認。ここで失敗するのはサーバー未応答であり runp の失敗と取り違えない。
run_crictl version version
if [ "${STEP_RC}" -ne 0 ]; then
  err_code prerequisite-failed "step=version exit=${STEP_RC} the CRI endpoint did not answer the Version RPC; see ${STEP_BASE}.stderr"
  exit 3
fi

run_crictl runp runp "${POD}"
if [ "${STEP_STATUS}" != ok ]; then
  fail_step runp step-failed "crictl runp did not succeed (${STEP_STATUS})"
elif ! SID="$(extract_id "${STEP_BASE}.stdout")"; then
  SID=""
  record runp invalid-id "${STEP_RC}" 0
  fail_step runp invalid-id "runp output is not a 64-character lowercase hex sandbox ID"
fi

if [ -z "${FAILED_STEP}" ]; then
  run_crictl create create "${SID}" "${CTR}" "${POD}"
  if [ "${STEP_STATUS}" != ok ]; then
    fail_step create step-failed "crictl create did not succeed (${STEP_STATUS})"
  elif ! CID="$(extract_id "${STEP_BASE}.stdout")"; then
    CID=""
    record create invalid-id "${STEP_RC}" 0
    fail_step create invalid-id "create output is not a 64-character lowercase hex container ID"
  fi
fi

if [ -z "${FAILED_STEP}" ]; then
  run_crictl start start "${CID}"
  if [ "${STEP_STATUS}" != ok ]; then
    fail_step start step-failed "crictl start did not succeed (${STEP_STATUS})"
  fi
fi

for s in runp create start; do
  case "${RAN}" in *" ${s} "*) ;; *) record "${s}" skipped - 0 ;; esac
done

trap '' INT TERM HUP
do_cleanup

if [ -n "${FAILED_STEP}" ]; then
  echo "result=failed failed_step=${FAILED_STEP} log_dir=${LOG_DIR}" | tee -a "${SUMMARY}" >&2
  exit 1
fi
echo "result=ok log_dir=${LOG_DIR}" | tee -a "${SUMMARY}" >&2
if [ "${CLEAN_FAIL}" = 1 ]; then
  err_code cleanup-failed "the run succeeded but cleanup did not finish; remaining resources may exist, check them manually"
  exit 4
fi
exit 0
