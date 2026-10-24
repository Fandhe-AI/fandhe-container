#!/usr/bin/env bash
# 1 つの試験を N 回繰り返し、毎回の合格を照合する（make repeat-test。REPAIR-12・#2538・#2660）。
#
# 役割: 間欠的に失敗する試験の原因修正後に「300 回以上で失敗 0」を示す道具。CI の workflow_dispatch 入力
# （repeat-package / repeat-test / repeat-test-bin / repeat-success-line / repeat-count 等）からも呼ばれ、
# macOS・Windows でも同じ手順で回せる。
# 2 モードを持つ（排他）:
#   - lib モード（TEST）: `--exact` の名前を誤ると 0 件実行でも exit 0 になるため、各回の出力に
#     `1 passed` があることを照合する（false-green の防止）。
#   - 結合試験モード（TEST_BIN）: `harness = false` の試験は libtest の出力も `--exact` も持たないため、
#     終了コード 0 と、引数で渡した試験固有の成功行（行全体の完全一致）の両方を要求する。
#     非 Linux で `not applicable` を出して exit 0 する試験は成功行が無いので失敗として数える。
# `make ci` には含めない。
#
# 入力（環境変数 = make 変数）:
#   PACKAGE  必須。Cargo のパッケージ名（例: fandhe-container-supervisor）
#   TEST     lib モード。`--exact` に渡す lib 試験の完全名（例: start_entry::tests::sup_repair5_2008_full_queue_does_not_block）
#   TEST_BIN 結合試験モード。`[[test]]` の name（`cargo test --test` に渡す。`[A-Za-z0-9_-]`、先頭 - 不可）。TEST と排他
#   SUCCESS_LINE  TEST_BIN の必須。成功行（CR 除去後に行全体が一致。cargo の引数には使わず grep -F -x のオペランドのみ）
#   TEST_IGNORED  TEST_BIN のみ任意。1 で `-- --ignored` を付ける
#   COUNT    繰り返し回数（既定 300、1..=1000）
#   RUN_TIMEOUT  1 回あたりの上限秒（既定 120。REPAIR-5）
# 出力: 最終行（stdout）は lib が `passed=N failed=M count=C test=<TEST>`、結合試験が
#   `passed=N failed=M count=C test_bin=<TEST_BIN>`。結合試験の失敗行は stderr に
#   `FAIL: run i/N rc=R reason=<timeout|exit|missing-success-line>`。
# 終了コード: 0 = 全回 passed / 1 = 失敗した回がある・想定外 / 2 = 入力不正。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

usage() {
  echo "usage: make repeat-test PACKAGE=fandhe-container-<name> TEST=<module::path::test> [COUNT=300] [RUN_TIMEOUT=120]" >&2
  echo "       make repeat-test PACKAGE=fandhe-container-<name> TEST_BIN=<name> SUCCESS_LINE=<line> [TEST_IGNORED=1] [COUNT=300] [RUN_TIMEOUT=120]" >&2
  exit 2
}

PACKAGE="${PACKAGE:-}"
TEST="${TEST:-}"
TEST_BIN="${TEST_BIN:-}"
SUCCESS_LINE="${SUCCESS_LINE:-}"
TEST_IGNORED="${TEST_IGNORED:-}"
COUNT="${COUNT:-300}"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
[ -n "${PACKAGE}" ] || usage
# TEST（lib）と TEST_BIN（結合試験）はちょうど一方だけ。
if [ -n "${TEST}" ] && [ -n "${TEST_BIN}" ]; then usage; fi
if [ -z "${TEST}" ] && [ -z "${TEST_BIN}" ]; then usage; fi
# 入力は cargo の引数（SUCCESS_LINE を除く）にだけ使う。許可する文字を絞り、フラグ（先頭 -）の混入も防ぐ。
case "${PACKAGE}" in fandhe-container-*) ;; *) usage ;; esac
case "${PACKAGE}" in *[!a-z0-9-]*) usage ;; esac
if [ -n "${TEST}" ]; then
  # lib モードに結合試験用の入力があれば黙って無視せず拒否する。
  if [ -n "${SUCCESS_LINE}" ] || [ -n "${TEST_IGNORED}" ]; then usage; fi
  case "${TEST}" in *[!A-Za-z0-9_:]*) usage ;; esac
else
  case "${TEST_BIN}" in -* | *[!A-Za-z0-9_-]*) usage ;; esac
  [ "${#TEST_BIN}" -le 128 ] || usage
  [ -n "${SUCCESS_LINE}" ] || usage
  [ "${#SUCCESS_LINE}" -le 200 ] || usage
  # grep -F -x の固定文字列オペランドにだけ使う。許可文字を絞る（実例: `exec_x: all scenarios passed`）。
  case "${SUCCESS_LINE}" in *[!A-Za-z0-9\ _:.,\(\)=/+-]*) usage ;; esac
  case "${TEST_IGNORED}" in '' | 1) ;; *) usage ;; esac
fi
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

# ビルドは 1 回だけ（以降は同じバイナリを繰り返す）。結合試験の名前誤り・required-features 不足もここで落ちる。
if [ -n "${TEST}" ]; then
  run cargo test -p "${PACKAGE}" --lib --no-run
else
  run cargo test -p "${PACKAGE}" --test "${TEST_BIN}" --no-run
fi

# 1 回分の実行。出力は照合のためファイルへ溜める（run_limited はシェル関数も子として受ける）。
one_run() {
  if [ -n "${TEST}" ]; then
    cargo test -p "${PACKAGE}" --lib -- --exact "${TEST}" >"${out}" 2>&1
  elif [ "${TEST_IGNORED}" = 1 ]; then
    cargo test -p "${PACKAGE}" --test "${TEST_BIN}" -- --ignored >"${out}" 2>&1
  else
    cargo test -p "${PACKAGE}" --test "${TEST_BIN}" >"${out}" 2>&1
  fi
}

# 出力の合格判定。結合試験は CR 除去後に成功行が行全体で一致すること（部分一致・0 件実行を通さない）。
output_ok() {
  if [ -n "${TEST}" ]; then
    grep -q 'test result: ok. 1 passed' "${out}"
  else
    # grep -q は最初の一致で終了し、上流の tr が SIGPIPE で非ゼロ終了して pipefail が誤って失敗にするため、
    # -q を使わず入力を最後まで読み切る（成功行が出力の途中にあっても判定は一致の有無だけで決まる）。
    tr -d '\r' <"${out}" | grep -xF -- "${SUCCESS_LINE}" >/dev/null
  fi
}

passed=0
failed=0
i=1
while [ "${i}" -le "${COUNT}" ]; do
  rc=0
  run_limited "${RUN_TIMEOUT}" one_run || rc=$?
  if [ "${rc}" -eq 0 ] && output_ok; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    reason=""
    if [ -n "${TEST_BIN}" ]; then
      if [ "${rc}" -eq 124 ]; then
        reason=" reason=timeout"
      elif [ "${rc}" -ne 0 ]; then
        reason=" reason=exit"
      else
        reason=" reason=missing-success-line"
      fi
    fi
    echo "FAIL: run ${i}/${COUNT} rc=${rc}${reason}" >&2
    cat "${out}" >&2
  fi
  i=$((i + 1))
done

if [ -n "${TEST}" ]; then
  echo "passed=${passed} failed=${failed} count=${COUNT} test=${TEST}"
else
  echo "passed=${passed} failed=${failed} count=${COUNT} test_bin=${TEST_BIN}"
fi
[ "${failed}" -eq 0 ]
