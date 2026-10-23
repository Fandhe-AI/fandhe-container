#!/usr/bin/env bash
# 1 つの lib 試験を N 回繰り返し、毎回ちょうど 1 件 passed になることを照合する（make repeat-test。REPAIR-12・#2538）。
#
# 役割: 間欠的に失敗する試験の原因修正後に「300 回以上で失敗 0」を示す道具。CI の workflow_dispatch 入力
# （repeat-package / repeat-test / repeat-count）からも呼ばれ、macOS・Windows でも同じ手順で回せる。
# `--exact` の名前を誤ると 0 件実行でも exit 0 になるため、各回の出力に `1 passed` があることを照合する
# （false-green の防止）。`make ci` には含めない。
#
# 入力（環境変数 = make 変数）:
#   PACKAGE  必須。Cargo のパッケージ名（例: fandhe-container-supervisor）
#   TEST     必須。`--exact` に渡す lib 試験の完全名（例: start_entry::tests::sup_repair5_2008_full_queue_does_not_block）
#   COUNT    繰り返し回数（既定 300、1..=1000）
#   RUN_TIMEOUT  1 回あたりの上限秒（既定 120。REPAIR-5）
# 終了コード: 0 = 全回 passed / 1 = 失敗した回がある・想定外 / 2 = 入力不正。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

usage() {
  echo "usage: make repeat-test PACKAGE=fandhe-container-<name> TEST=<module::path::test> [COUNT=300] [RUN_TIMEOUT=120]" >&2
  exit 2
}

PACKAGE="${PACKAGE:-}"
TEST="${TEST:-}"
COUNT="${COUNT:-300}"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
{ [ -n "${PACKAGE}" ] && [ -n "${TEST}" ]; } || usage
# 入力は cargo の引数にだけ使う。許可する文字を絞り、フラグ（先頭 -）の混入も防ぐ。
case "${PACKAGE}" in fandhe-container-*) ;; *) usage ;; esac
case "${PACKAGE}" in *[!a-z0-9-]*) usage ;; esac
case "${TEST}" in '' | *[!A-Za-z0-9_:]*) usage ;; esac
int_in_range "${COUNT}" 1 1000 || usage
int_in_range "${RUN_TIMEOUT}" 1 3600 || usage

skip_unless_workspace repeat-test

if [ -r /proc/sys/kernel/core_pattern ]; then
  echo "info: core_pattern=$(cat /proc/sys/kernel/core_pattern)"
  [ ! -r /proc/sys/kernel/core_pipe_limit ] || echo "info: core_pipe_limit=$(cat /proc/sys/kernel/core_pipe_limit)"
fi

RUN_LIMITED_DIR="$(mktemp -d)"
trap 'run_limited_abort; rm -rf "${RUN_LIMITED_DIR}"' EXIT
out="${RUN_LIMITED_DIR}/out.txt"

# ビルドは 1 回だけ（以降は同じバイナリを繰り返す）。
run cargo test -p "${PACKAGE}" --lib --no-run

# 1 回分の実行。出力は照合のためファイルへ溜める（run_limited はシェル関数も子として受ける）。
one_run() {
  cargo test -p "${PACKAGE}" --lib -- --exact "${TEST}" >"${out}" 2>&1
}

passed=0
failed=0
i=1
while [ "${i}" -le "${COUNT}" ]; do
  rc=0
  run_limited "${RUN_TIMEOUT}" one_run || rc=$?
  if [ "${rc}" -eq 0 ] && grep -q 'test result: ok. 1 passed' "${out}"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: run ${i}/${COUNT} rc=${rc}" >&2
    cat "${out}" >&2
  fi
  i=$((i + 1))
done

echo "passed=${passed} failed=${failed} count=${COUNT} test=${TEST}"
[ "${failed}" -eq 0 ]
