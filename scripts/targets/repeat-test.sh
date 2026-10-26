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
# 委譲スコープモード（USER_SCOPE=1。#2886）: production_launcher のように、cargo を同じ cgroup に入れると
# prepare が失敗する試験用。ビルドは `--no-run --message-format=json` で 1 回だけ行い、jq で試験バイナリを
# 一意に特定して、毎回 `systemd-run --user --scope --quiet -p Delegate=yes` の中で直接実行する
# （引数は crates/core の `start_contract::USER_SCOPE_WRAPPER_ARGS` と ci.yml の production_launcher の実行
# ステップと同じ）。jq・systemd-run が無ければ skip せず失敗にする（false-green の防止）。
# `make ci` には含めない。
#
# 入力（環境変数 = make 変数）:
#   PACKAGE  必須。Cargo のパッケージ名（例: fandhe-container-supervisor）
#   TEST     lib モード。`--exact` に渡す lib 試験の完全名（例: start_entry::tests::sup_repair5_2008_full_queue_does_not_block）
#   TEST_BIN 結合試験モード。`[[test]]` の name（`cargo test --test` に渡す。`[A-Za-z0-9_-]`、先頭 - 不可）。TEST と排他
#   SUCCESS_LINE  TEST_BIN の必須。成功行（CR 除去後に行全体が一致。cargo の引数には使わず grep -F -x のオペランドのみ。
#            512 文字以下。`;` を許す（production_launcher の最終行が 200 文字超で `;` を含むため。#2886）。
#            `$`・バッククォート・引用符・バックスラッシュ・`*` は拒否）
#   TEST_IGNORED  TEST_BIN のみ任意。1 で `-- --ignored` を付ける
#   USER_SCOPE   TEST_BIN のみ任意。1 で委譲スコープモード（上記）。TEST との併用は不可
#   TEST_ENV     任意。試験の子プロセスにだけ渡す `NAME=VALUE` の空白区切り（8 個以下・全体 512 文字以下）。
#            NAME は `FANDHE_CONTAINER_` で始まる `[A-Z0-9_]` のみ（PATH・LD_PRELOAD・CARGO_*・USER 等の注入を拒否）。
#            VALUE は `[A-Za-z0-9_.,:/+-]` で 128 文字以下。ビルドには渡さない。出力には名前だけを出す
#   FEATURES 任意。`--features` に渡す feature 名（カンマ区切り。`[a-z0-9_,-]`、先頭 - 不可、128 文字以下）。
#            既定 feature で有効にならない試験（例: crates/plugin の `grpc` 配下）を回すのに使う（#2711）
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
  echo "usage: make repeat-test PACKAGE=fandhe-container-<name> TEST=<module::path::test> [FEATURES=<a,b>] [COUNT=300] [RUN_TIMEOUT=120]" >&2
  echo "       make repeat-test PACKAGE=fandhe-container-<name> TEST_BIN=<name> SUCCESS_LINE=<line> [TEST_IGNORED=1] [USER_SCOPE=1] [TEST_ENV='FANDHE_CONTAINER_X=1 ...'] [FEATURES=<a,b>] [COUNT=300] [RUN_TIMEOUT=120]" >&2
  exit 2
}

PACKAGE="${PACKAGE:-}"
TEST="${TEST:-}"
TEST_BIN="${TEST_BIN:-}"
SUCCESS_LINE="${SUCCESS_LINE:-}"
TEST_IGNORED="${TEST_IGNORED:-}"
USER_SCOPE="${USER_SCOPE:-}"
TEST_ENV="${TEST_ENV:-}"
FEATURES="${FEATURES:-}"
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
  if [ -n "${SUCCESS_LINE}" ] || [ -n "${TEST_IGNORED}" ] || [ -n "${USER_SCOPE}" ]; then usage; fi
  case "${TEST}" in *[!A-Za-z0-9_:]*) usage ;; esac
else
  case "${TEST_BIN}" in -* | *[!A-Za-z0-9_-]*) usage ;; esac
  [ "${#TEST_BIN}" -le 128 ] || usage
  [ -n "${SUCCESS_LINE}" ] || usage
  [ "${#SUCCESS_LINE}" -le 512 ] || usage
  # grep -F -x の固定文字列オペランドにだけ使う（シェル解釈の経路は無い）。許可文字を絞る
  # （実例: `exec_x: all scenarios passed`、`;` を含む production_launcher の最終行）。
  case "${SUCCESS_LINE}" in *[!A-Za-z0-9\ _:.,\;\(\)=/+-]*) usage ;; esac
  case "${TEST_IGNORED}" in '' | 1) ;; *) usage ;; esac
  case "${USER_SCOPE}" in '' | 1) ;; *) usage ;; esac
fi
# TEST_ENV: 子プロセスにだけ渡す環境変数。名前を FANDHE_CONTAINER_ 接頭辞に限り、値の文字も絞る（インジェクション防止）。
TEST_ENV_ARGS=()
TEST_ENV_NAMES=""
if [ -n "${TEST_ENV}" ]; then
  [ "${#TEST_ENV}" -le 512 ] || usage
  # 許可文字のみなので glob 文字（* ? [）を含まず、単語分割だけで安全に分解できる。
  case "${TEST_ENV}" in *[!A-Za-z0-9_.,:/=+\ -]*) usage ;; esac
  # shellcheck disable=SC2086
  for kv in ${TEST_ENV}; do
    case "${kv}" in *=*) ;; *) usage ;; esac
    k="${kv%%=*}"
    v="${kv#*=}"
    case "${k}" in FANDHE_CONTAINER_*) ;; *) usage ;; esac
    case "${k}" in *[!A-Z0-9_]*) usage ;; esac
    case "${v}" in *=*) usage ;; esac
    [ "${#v}" -le 128 ] || usage
    TEST_ENV_ARGS+=("${kv}")
    TEST_ENV_NAMES="${TEST_ENV_NAMES:+${TEST_ENV_NAMES},}${k}"
  done
  [ "${#TEST_ENV_ARGS[@]}" -le 8 ] || usage
fi
# FEATURES は cargo の --features の値にだけ使う。許可する文字を絞り、フラグ（先頭 -）の混入も防ぐ。
if [ -n "${FEATURES}" ]; then
  case "${FEATURES}" in -* | *[!a-z0-9_,-]*) usage ;; esac
  [ "${#FEATURES}" -le 128 ] || usage
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
SCOPE_BIN=""
SCOPE_USER=""
RUN_INDEX=0
if [ -n "${TEST}" ]; then
  run cargo test -p "${PACKAGE}" --lib ${FEATURES:+--features "${FEATURES}"} --no-run
elif [ "${USER_SCOPE}" = 1 ]; then
  # 委譲スコープモード: cargo を毎回は通さず、特定した試験バイナリを scope の中で直接実行する（#2886）。
  require_cmd jq
  require_cmd systemd-run
  build_json="${RUN_LIMITED_DIR}/build.json"
  cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} --no-run --message-format=json >"${build_json}"
  bins="$(jq -r --arg n "${TEST_BIN}" 'select(.profile.test == true and .target.name == $n) | .executable' "${build_json}" | grep -v '^null$' | sort -u || true)"
  if [ -z "${bins}" ] || [ "$(printf '%s\n' "${bins}" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "error: ${TEST_BIN} test binary not uniquely identified" >&2
    exit 1
  fi
  case "${bins}" in /*) ;; *) echo "error: ${TEST_BIN} test binary path is not absolute" >&2; exit 1 ;; esac
  [ -f "${bins}" ] && [ -x "${bins}" ] || { echo "error: ${TEST_BIN} test binary is not an executable file" >&2; exit 1; }
  SCOPE_BIN="${bins}"
  SCOPE_USER="${USER:-$(id -un)}"
  echo "info: user_scope=1 test_env_names=${TEST_ENV_NAMES}"
else
  run cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} --no-run
fi

# 1 回分の実行。出力は照合のためファイルへ溜める（run_limited はシェル関数も子として受ける）。
# TEST_ENV は env で子にだけ付ける（bash 3.2 の空配列展開に備え `${a[@]+...}` で書く）。
one_run() {
  if [ -n "${TEST}" ]; then
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} cargo test -p "${PACKAGE}" --lib ${FEATURES:+--features "${FEATURES}"} -- --exact "${TEST}" >"${out}" 2>&1
  elif [ -n "${SCOPE_BIN}" ]; then
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} USER="${SCOPE_USER}" \
      systemd-run --user --scope --quiet -p Delegate=yes --unit="fandhe-repeat-$$-${RUN_INDEX}" -- \
      "${SCOPE_BIN}" ${TEST_IGNORED:+--ignored} >"${out}" 2>&1
  elif [ "${TEST_IGNORED}" = 1 ]; then
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} -- --ignored >"${out}" 2>&1
  else
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} >"${out}" 2>&1
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
  RUN_INDEX="${i}"
  run_limited "${RUN_TIMEOUT}" one_run || rc=$?
  if [ "${rc}" -eq 0 ] && output_ok; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    reason=""
    if [ -n "${TEST_BIN}" ]; then
      if [ "${rc}" -eq 124 ]; then
        reason=" reason=timeout"
        # 残った scope を best-effort で止める（REPAIR-5。失敗しても判定は変えない）。
        [ -z "${SCOPE_BIN}" ] || systemctl --user stop "fandhe-repeat-$$-${RUN_INDEX}.scope" >/dev/null 2>&1 || true
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

if [ -n "${SCOPE_BIN}" ]; then
  # 記録用の best-effort 情報（判定には使わない）: tmpfiles の走査（boot から約 15 分）が区間に入ったかの材料（#2840）。
  echo "info: uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || true)"
  { systemctl show systemd-tmpfiles-clean.service -p ExecMainStartTimestamp 2>/dev/null | sed 's/^/info: /'; } || true
fi
if [ -n "${TEST}" ]; then
  echo "passed=${passed} failed=${failed} count=${COUNT} test=${TEST}"
else
  echo "passed=${passed} failed=${failed} count=${COUNT} test_bin=${TEST_BIN}"
fi
[ "${failed}" -eq 0 ]
