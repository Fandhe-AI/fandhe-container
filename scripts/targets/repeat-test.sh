#!/usr/bin/env bash
# 1 つの試験を N 回繰り返し、毎回の合格を照合する（make repeat-test。REPAIR-12・#2538・#2660）。
#
# 役割: 間欠的に失敗する試験の原因修正後に「300 回以上で失敗 0」を示す道具。CI の workflow_dispatch 入力
# （repeat-package / repeat-test / repeat-test-bin / repeat-success-line / repeat-count 等）からも呼ばれ、
# macOS・Windows でも同じ手順で回せる。
# 2 モードを持つ（排他）:
#   - lib モード（TEST）: `--exact` の名前を誤ると 0 件実行でも exit 0 になるため、libtest の `--logfile` に
#     書かれた結果が「ちょうど 1 行で `ok <TEST>`」であることを照合する（false-green の防止）。
#   - 結合試験モード（TEST_BIN）: 次のどちらか一方で判定する（排他・どちらか必須）。いずれも終了コード 0 を要求する。
#     - LIBTEST_NAME: libtest ハーネスの `[[test]]`。`--logfile` の `ok <LIBTEST_NAME>` 行で判定する。
#     - SUCCESS_LINE: `harness = false` の試験（libtest の出力も `--exact` も持たない）。試験固有の成功行を
#       stdout か stderr のどちらかで行全体の完全一致として要求する。非 Linux で `not applicable` を出して
#       exit 0 する試験は成功行が無いので失敗として数える。
# 判定に `--logfile` を使う理由（#2962）: 並列実行中の libtest は `test <name> ... ok` を 3 回の別々の write で出すため、
# 並列で動く別の試験が起動した supervisor の JSON ログ（stderr）がその間に入り、全件 ok・rc=0 でも行全体の完全一致が
# 外れて偽の missing-success-line になる（docs/design/container-log-removal-wait.md「繰り返し実行の記録」）。
# `--logfile` は libtest 本体だけが開くファイルで（子プロセスは書けない）、結果ごとに `ok|failed|ignored <name>` を
# 1 行ずつ書くため割り込まれない。
# `--logfile` の将来（#3036 で一次情報を確認。2026-10-28 時点）: Rust 1.86.0 で deprecated（rust-lang/rust#134283。
# 警告は stderr に改行なしで出る）。1.99.0 でも受理され、削除の PR・予定は見つからない。代替の `--format json` / `junit` は
# stable では使えず（`-Z unstable-options` が要る。rust-lang/rust#49359 は open）、結果をファイルへ書く
# `--test-results-output`（rust-lang/rust#140805）も未マージ。toolchain は stable 追従のため nightly 前提の方式は採れない。
# 切り替え方式: 当面は `--logfile` を使い続ける。受理されない toolchain ではループの前のプリフライト（`--list --logfile`）が
# 固定の `reason=logfile-unsupported` で止める（毎回 `reason=exit` が COUNT 回並ぶ汎用失敗にしない）。採らない案:
# stdout の `test <name> ... ok` 行での判定（#2962 の割り込みで偽の失敗が戻る）・`--test-threads=1`（再現条件の並列度が変わる）。
# 移行先は安定化した stable の手段（#140805 の結果ファイル、または stable の `--format json` を jq で数える。後者なら
# lib・LIBTEST_NAME モードでも `require_cmd jq` を足す）。見直しのきっかけ: (a) libtest の cli.rs から logfile を消す PR が
# マージされた・Compatibility Notes に載った (b) #140805 がマージされ stable になった (c) #49359 が stable になった
# (d) repeat-test が `reason=logfile-unsupported` で失敗した。SUCCESS_LINE モード（harness = false）は `--logfile` を
# 渡さないため削除の影響を受けない。なお `--nocapture` も 1.88.0 で deprecated（`--no-capture` が推奨。置き換えは別件）。
# stdout と stderr は別ファイルに取り、成功行・禁止行はストリームごとに照合する（試験自身の println と子の stderr が
# 互いに割り込まない）。失敗時のダンプは見出しつきで 2 本を別に出すため、時系列の並びは失われる。
# 残余: 同じストリームの別プロセスの書き込みが SUCCESS_LINE の途中に入る場合は救えない（libtest ハーネスは LIBTEST_NAME へ）。
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
#   LIBTEST_NAME  TEST_BIN の判定方式（libtest ハーネス用。SUCCESS_LINE と排他でどちらか必須）。ハーネス内の試験名
#            （`[A-Za-z0-9_:]`、256 文字以下、先頭 - 不可。cargo と試験バイナリの引数になる）
#   SUCCESS_LINE  TEST_BIN の判定方式（LIBTEST_NAME と排他でどちらか必須）。成功行（CR 除去後に行全体が一致。cargo の引数には使わず grep -F -x のオペランドのみ。
#            512 文字以下。`;` を許す（production_launcher の最終行が 200 文字超で `;` を含むため。#2886）。
#            `$`・バッククォート・引用符・バックスラッシュ・`*` は拒否）
#   FORBIDDEN_LINE  任意（全モード）。出たら失敗にする固定文字列の `|` 区切り（8 個以下、各 1〜512 文字・空要素不可、
#            全体 1024 文字以下。許可文字は SUCCESS_LINE と同じ。ただし `|` は区切り）。stdout・stderr・ログファイルの
#            いずれかに部分一致（grep -F）した回は、成功行が出ていても失敗に数える（reason=forbidden-line）。
#            SUCCESS_LINE や `ok <LIBTEST_NAME>` と同一の要素は設定の誤りとして拒否する
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
#   `FAIL: run i/N rc=R reason=<timeout|exit|missing-success-line|missing-libtest-ok|forbidden-line>`
#   （lib も reason を出す。forbidden-line は `forbidden='<要素>'` を併記）。lib・LIBTEST_NAME はループの前に
#   `--list --logfile` のプリフライトを行い、通れば `info: libtest_logfile=accepted`、失敗なら
#   `FAIL: preflight rc=R reason=<logfile-unsupported|preflight-failed>` と stdout・stderr のダンプ、集計行
#   `passed=0 failed=<COUNT> ...`（呼び出し側の「passed=count でなければ失敗」と矛盾させない）を出して exit 1。
# 終了コード: 0 = 全回 passed / 1 = 失敗した回がある・想定外 / 2 = 入力不正。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

usage() {
  echo "usage: make repeat-test PACKAGE=fandhe-container-<name> TEST=<module::path::test> [FEATURES=<a,b>] [COUNT=300] [RUN_TIMEOUT=120]" >&2
  echo "       make repeat-test PACKAGE=fandhe-container-<name> TEST_BIN=<name> (SUCCESS_LINE=<line> | LIBTEST_NAME=<name>) [TEST_IGNORED=1] [USER_SCOPE=1] [TEST_ENV='FANDHE_CONTAINER_X=1 ...'] [FEATURES=<a,b>] [COUNT=300] [RUN_TIMEOUT=120]" >&2
  echo "       (any mode) [FORBIDDEN_LINE='a|b']" >&2
  exit 2
}

PACKAGE="${PACKAGE:-}"
TEST="${TEST:-}"
TEST_BIN="${TEST_BIN:-}"
SUCCESS_LINE="${SUCCESS_LINE:-}"
LIBTEST_NAME="${LIBTEST_NAME:-}"
FORBIDDEN_LINE="${FORBIDDEN_LINE:-}"
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
  if [ -n "${SUCCESS_LINE}" ] || [ -n "${LIBTEST_NAME}" ] || [ -n "${TEST_IGNORED}" ] || [ -n "${USER_SCOPE}" ]; then usage; fi
  case "${TEST}" in *[!A-Za-z0-9_:]*) usage ;; esac
else
  case "${TEST_BIN}" in -* | *[!A-Za-z0-9_-]*) usage ;; esac
  [ "${#TEST_BIN}" -le 128 ] || usage
  # 判定方式は SUCCESS_LINE か LIBTEST_NAME のちょうど一方。
  if [ -n "${SUCCESS_LINE}" ] && [ -n "${LIBTEST_NAME}" ]; then usage; fi
  if [ -z "${SUCCESS_LINE}" ] && [ -z "${LIBTEST_NAME}" ]; then usage; fi
  [ "${#SUCCESS_LINE}" -le 512 ] || usage
  case "${LIBTEST_NAME}" in -* | *[!A-Za-z0-9_:]*) usage ;; esac
  [ "${#LIBTEST_NAME}" -le 256 ] || usage
  # grep -F -x の固定文字列オペランドにだけ使う（シェル解釈の経路は無い）。許可文字を絞る
  # （実例: `exec_x: all scenarios passed`、`;` を含む production_launcher の最終行）。
  case "${SUCCESS_LINE}" in *[!A-Za-z0-9\ _:.,\;\(\)=/+-]*) usage ;; esac
  case "${TEST_IGNORED}" in '' | 1) ;; *) usage ;; esac
  case "${USER_SCOPE}" in '' | 1) ;; *) usage ;; esac
fi
# FORBIDDEN_LINE: `|` 区切りの固定文字列。grep -F -- のオペランドにだけ使い、シェル解釈・eval・case のパターンには使わない。
# 許可文字に glob 文字（* ? [）を含まないため、read -a での分解で展開は起きない。
FORBIDDEN_ITEMS=()
if [ -n "${FORBIDDEN_LINE}" ]; then
  [ "${#FORBIDDEN_LINE}" -le 1024 ] || usage
  case "${FORBIDDEN_LINE}" in *[!A-Za-z0-9\ _:.,\;\(\)=/+\|-]*) usage ;; esac
  case "${FORBIDDEN_LINE}" in '|'* | *'|' | *'||'*) usage ;; esac
  IFS='|' read -r -a FORBIDDEN_ITEMS <<<"${FORBIDDEN_LINE}"
  [ "${#FORBIDDEN_ITEMS[@]}" -le 8 ] || usage
  for item in "${FORBIDDEN_ITEMS[@]}"; do
    [ "${#item}" -ge 1 ] && [ "${#item}" -le 512 ] || usage
    [ "${item}" != "${SUCCESS_LINE}" ] || usage
    [ -z "${LIBTEST_NAME}" ] || [ "${item}" != "ok ${LIBTEST_NAME}" ] || usage
    [ -z "${TEST}" ] || [ "${item}" != "ok ${TEST}" ] || usage
  done
fi
# 後方互換: libtest の結果行を SUCCESS_LINE に渡すと並列出力の割り込みで偽の失敗になりうる（#2962）。拒否はせず警告する。
libtest_line_re='^test [^ ]+ \.\.\. ok$'
if [ -n "${SUCCESS_LINE}" ] && [[ "${SUCCESS_LINE}" =~ ${libtest_line_re} ]]; then
  echo "warning: SUCCESS_LINE looks like a libtest result line; use LIBTEST_NAME=<name> to avoid interleaving" >&2
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
echo "info: forbidden_count=${#FORBIDDEN_ITEMS[@]}"

RUN_LIMITED_DIR="$(mktemp -d)"
trap 'run_limited_abort; rm -rf "${RUN_LIMITED_DIR}"' EXIT
out_o="${RUN_LIMITED_DIR}/stdout.txt"
out_e="${RUN_LIMITED_DIR}/stderr.txt"
logf="${RUN_LIMITED_DIR}/libtest.log"
# libtest の結果を読むモード（lib・LIBTEST_NAME）だけ --logfile を渡す。harness = false のバイナリには渡さない。
# Git Bash では cygpath で Windows 形式にする（別の引数として渡すので MSYS のパス変換も効く）。
LOGARGS=()
if [ -n "${TEST}" ] || [ -n "${LIBTEST_NAME}" ]; then
  log_arg="${logf}"
  if command -v cygpath >/dev/null 2>&1; then log_arg="$(cygpath -m "${logf}")"; fi
  LOGARGS=(--logfile "${log_arg}")
  # 成功した試験の println!/eprintln! は既定でキャプチャされ、禁止行の照合に届かない。FORBIDDEN_LINE 指定時は
  # --nocapture で出力を stdout/stderr へ流す（lib・LIBTEST_NAME・USER_SCOPE のすべてで LOGARGS が `--` 以降に渡る。P1）。
  if [ "${#FORBIDDEN_ITEMS[@]}" -gt 0 ]; then LOGARGS+=(--nocapture); fi
fi

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

# プリフライト（#3036）: libtest が `--logfile` を受理するかをループの前に 1 回だけ確かめる。`--list` は試験を走らせない
# （委譲スコープも TEST_ENV も不要）。削除後は未知のオプションで rc≠0 になるため、COUNT 回の汎用 `reason=exit` ではなく
# 原因の分かる固定行で fail-closed に止める。ラベルは文言で決めるだけで、失敗にするかは rc とログの有無で決める。
preflight_run() {
  if [ -n "${SCOPE_BIN}" ]; then
    "${SCOPE_BIN}" --list --logfile "${log_arg}" >"${pre_o}" 2>"${pre_e}"
  elif [ -n "${TEST}" ]; then
    cargo test -p "${PACKAGE}" --lib ${FEATURES:+--features "${FEATURES}"} -- --list --logfile "${log_arg}" >"${pre_o}" 2>"${pre_e}"
  else
    cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} -- --list --logfile "${log_arg}" >"${pre_o}" 2>"${pre_e}"
  fi
}
if [ "${#LOGARGS[@]}" -gt 0 ]; then
  pre_o="${RUN_LIMITED_DIR}/preflight.out"
  pre_e="${RUN_LIMITED_DIR}/preflight.err"
  pre_rc=0
  rm -f "${logf}"
  run_limited "${RUN_TIMEOUT}" preflight_run || pre_rc=$?
  if [ "${pre_rc}" -eq 0 ] && [ -f "${logf}" ]; then
    echo "info: libtest_logfile=accepted"
    rm -f "${logf}"
  else
    pre_reason="preflight-failed"
    if cat "${pre_o}" "${pre_e}" 2>/dev/null | grep -F -- "Unrecognized option: 'logfile'" >/dev/null; then
      pre_reason="logfile-unsupported"
    fi
    echo "FAIL: preflight rc=${pre_rc} reason=${pre_reason}" >&2
    echo "--- preflight stdout ---" >&2
    cat "${pre_o}" >&2 2>/dev/null || true
    echo "--- preflight stderr ---" >&2
    cat "${pre_e}" >&2 2>/dev/null || true
    if [ -n "${TEST}" ]; then
      echo "passed=0 failed=${COUNT} count=${COUNT} test=${TEST}"
    else
      echo "passed=0 failed=${COUNT} count=${COUNT} test_bin=${TEST_BIN}"
    fi
    exit 1
  fi
fi

# 1 回分の実行。stdout・stderr は別ファイルへ溜めて照合する（run_limited はシェル関数も子として受ける）。
# TEST_ENV は env で子にだけ付ける（bash 3.2 の空配列展開に備え `${a[@]+...}` で書く）。
one_run() {
  local extra=()
  if [ -n "${TEST}" ]; then
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} cargo test -p "${PACKAGE}" --lib ${FEATURES:+--features "${FEATURES}"} -- --exact "${TEST}" "${LOGARGS[@]}" >"${out_o}" 2>"${out_e}"
    return
  fi
  [ "${TEST_IGNORED}" != 1 ] || extra+=(--ignored)
  extra+=(${LOGARGS[@]+"${LOGARGS[@]}"})
  if [ -n "${SCOPE_BIN}" ]; then
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} USER="${SCOPE_USER}" \
      systemd-run --user --scope --quiet -p Delegate=yes --unit="fandhe-repeat-$$-${RUN_INDEX}" -- \
      "${SCOPE_BIN}" ${extra[@]+"${extra[@]}"} >"${out_o}" 2>"${out_e}"
  elif [ "${#extra[@]}" -gt 0 ]; then
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} -- "${extra[@]}" >"${out_o}" 2>"${out_e}"
  else
    env ${TEST_ENV_ARGS[@]+"${TEST_ENV_ARGS[@]}"} cargo test -p "${PACKAGE}" --test "${TEST_BIN}" ${FEATURES:+--features "${FEATURES}"} >"${out_o}" 2>"${out_e}"
  fi
}

# ファイルを CR 除去して流す（無ければ何も出さない）。
crless() { [ ! -f "$1" ] || tr -d '\r' <"$1"; }

# 出力の合格判定。部分一致・0 件実行・ignored・failed・別名を通さない。
# grep -q は最初の一致で上流が SIGPIPE で非ゼロ終了し pipefail が誤って失敗にするため、-q を使わず読み切る。
output_ok() {
  if [ -n "${TEST}" ]; then
    # ログがちょうど 1 行で `ok <TEST>`（0 件実行は空ファイルになる）。
    [ -f "${logf}" ] || return 1
    [ "$(crless "${logf}" | wc -l | tr -d ' ')" -eq 1 ] || return 1
    crless "${logf}" | grep -xF -- "ok ${TEST}" >/dev/null
  elif [ -n "${LIBTEST_NAME}" ]; then
    [ -f "${logf}" ] || return 1
    crless "${logf}" | grep -xF -- "ok ${LIBTEST_NAME}" >/dev/null
  else
    crless "${out_o}" | grep -xF -- "${SUCCESS_LINE}" >/dev/null || crless "${out_e}" | grep -xF -- "${SUCCESS_LINE}" >/dev/null
  fi
}

# 禁止行の判定。当たった要素を FORBID_HIT に入れて 0 を返す（無ければ 1）。
FORBID_HIT=""
forbidden_hit() {
  local item f
  for item in ${FORBIDDEN_ITEMS[@]+"${FORBIDDEN_ITEMS[@]}"}; do
    for f in "${out_o}" "${out_e}" "${logf}"; do
      if [ -f "${f}" ] && crless "${f}" | grep -F -- "${item}" >/dev/null; then
        FORBID_HIT="${item}"
        return 0
      fi
    done
  done
  return 1
}

passed=0
failed=0
i=1
while [ "${i}" -le "${COUNT}" ]; do
  rc=0
  RUN_INDEX="${i}"
  # 前回の結果が残って合格に見えるのを防ぐ（起動前に落ちた回の false-green）。
  rm -f "${out_o}" "${out_e}" "${logf}"
  run_limited "${RUN_TIMEOUT}" one_run || rc=$?
  reason=""
  FORBID_HIT=""
  if [ "${rc}" -eq 124 ]; then
    reason="timeout"
    # 残った scope を best-effort で止める（REPAIR-5。失敗しても判定は変えない）。
    [ -z "${SCOPE_BIN}" ] || systemctl --user stop "fandhe-repeat-$$-${RUN_INDEX}.scope" >/dev/null 2>&1 || true
  elif [ "${rc}" -ne 0 ]; then
    reason="exit"
  elif ! output_ok; then
    if [ -n "${SUCCESS_LINE}" ]; then reason="missing-success-line"; else reason="missing-libtest-ok"; fi
  elif forbidden_hit; then
    reason="forbidden-line forbidden='${FORBID_HIT}'"
  fi
  if [ -z "${reason}" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: run ${i}/${COUNT} rc=${rc} reason=${reason}" >&2
    echo "--- stdout ---" >&2
    cat "${out_o}" >&2 2>/dev/null || true
    echo "--- stderr ---" >&2
    cat "${out_e}" >&2 2>/dev/null || true
    if [ -f "${logf}" ]; then
      echo "--- libtest log ---" >&2
      cat "${logf}" >&2
    fi
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
