#!/usr/bin/env bash
# scripts/lib.sh の workspace 判定（has_cargo・has_members・skip_unless_workspace）と run_limited の回帰テスト。
#
# 一時ディレクトリに scripts/lib.sh・scripts/versions.sh を複製した疑似リポジトリを作り、Cargo.toml・
# crates/*/Cargo.toml の有無の組み合わせごとに判定結果と skip の出力を具体値で照合する。
# 実行する bash は PATH 上の bash に加え、/bin/bash があればそれでも回す（macOS 標準の bash 3.2 で
# glob 不一致時の判定が崩れないことを確かめる。PR #1756 の指摘）。リポジトリ内のファイルは変更しない。
# run_limited は終了コード・経過秒・子孫の回収を具体値で照合する（TASK-64 追補・#2092・REPAIR-1・REPAIR-5）。
# 呼び出し元: Makefile の `lib-selftest`（CI の platform-ci ジョブ。PR は ubuntu・main は 3 OS）。
# 終了コード: 0 = 全件一致、1 = 不一致あり。
set -euo pipefail

src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT

shells=()
path_bash="$(command -v bash)"
shells+=("${path_bash}")
if [ -x /bin/bash ] && [ "/bin/bash" != "${path_bash}" ]; then
  shells+=(/bin/bash)
fi

failures=0
pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# make_repo <dir> <cargo:0|1> <layout>: layout は none（crates/ 無し）・empty（crates/ のみ）・
# dironly（crates/a/ に Cargo.toml 無し）・member（crates/a/Cargo.toml あり）
make_repo() {
  local dir="$1" cargo="$2" layout="$3"
  mkdir -p "${dir}/scripts"
  cp "${src_dir}/lib.sh" "${src_dir}/versions.sh" "${dir}/scripts/"
  if [ "${cargo}" = 1 ]; then : >"${dir}/Cargo.toml"; fi
  case "${layout}" in
    none) ;;
    empty) mkdir -p "${dir}/crates" ;;
    dironly) mkdir -p "${dir}/crates/a" ;;
    member) mkdir -p "${dir}/crates/a" && : >"${dir}/crates/a/Cargo.toml" ;;
  esac
  cat >"${dir}/scripts/probe.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
if has_cargo; then c=1; else c=0; fi
if has_members; then m=1; else m=0; fi
echo "cargo=${c} members=${m}"
skip_unless_workspace probe
echo "ran"
EOF
}

# check <名前> <cargo> <layout> <期待する出力（改行は |）>
check() {
  local name="$1" cargo="$2" layout="$3" want="$4" sh dir got rc
  for sh in "${shells[@]}"; do
    dir="${root}/${name}-$(basename "$(dirname "${sh}")")-$$-${RANDOM}"
    make_repo "${dir}" "${cargo}" "${layout}"
    rc=0
    got="$(cd / && "${sh}" "${dir}/scripts/probe.sh" 2>&1)" || rc=$?
    got="$(printf '%s' "${got}" | tr '\n' '|')"
    if [ "${rc}" -eq 0 ] && [ "${got}" = "${want}" ]; then
      pass "${name} (${sh})"
    else
      fail "${name} (${sh}): exit=${rc} got='${got}' want='${want}'"
    fi
  done
}

skip_line="skip: Cargo.toml is missing or the workspace has no member crate, skipping probe"
check no-cargo-no-crates 0 none "cargo=0 members=0|${skip_line}"
check cargo-no-crates 1 none "cargo=1 members=0|${skip_line}"
check cargo-empty-crates 1 empty "cargo=1 members=0|${skip_line}"
check cargo-dir-without-manifest 1 dironly "cargo=1 members=0|${skip_line}"
check member-without-root-cargo 0 member "cargo=0 members=1|${skip_line}"
check cargo-and-member 1 member "cargo=1 members=1|ran"

# --- run_limited（REPAIR-5）: 終了コードと経過秒を具体値で照合する ---
# probe は lib.sh を source し、RUN_LIMITED_DIR に private な一時ディレクトリを設定して 1 ケースを実行し、
# `rc=<終了コード> secs=<経過秒> extra=<補足> left=<印ファイルの残り>` の 1 行を出す。
make_rl_probe() {
  local dir="$1"
  mkdir -p "${dir}/scripts"
  cp "${src_dir}/lib.sh" "${src_dir}/versions.sh" "${dir}/scripts/"
  cat >"${dir}/gc.sh" <<'GC'
#!/bin/sh
# TERM を無視する孫を作る（期限切れで KILL まで届くことの確認用）
sh -c 'trap "" TERM; echo $$ >"$1"; exec sleep 30' _ "$RL_DIR/gc.pid" &
wait
GC
  chmod +x "${dir}/gc.sh"
  cat >"${dir}/scripts/rl-probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
RL_DIR="$2"
export RL_DIR
mkdir -p "${RL_DIR}/work"
RUN_LIMITED_DIR="${RL_DIR}/work"
trap run_limited_abort EXIT
f5() { return 5; }
SECONDS=0
rc=0
extra=""
case "$1" in
  exit7) run_limited 10 sh -c 'exit 7' || rc=$? ;;
  true) run_limited 10 true || rc=$? ;;
  func) run_limited 10 f5 || rc=$? ;;
  timeout) run_limited 1 sleep 30 || rc=$? ;;
  grandchild)
    run_limited 1 "${RL_DIR}/gc.sh" || rc=$?
    if kill -0 "$(cat "${RL_DIR}/gc.pid")" 2>/dev/null; then extra=alive; else extra=gone; fi
    ;;
  badlimit0) run_limited 0 touch "${RL_DIR}/ran" || rc=$? ;;
  badlimitabc) run_limited abc touch "${RL_DIR}/ran" || rc=$? ;;
  nodir) unset RUN_LIMITED_DIR; run_limited 5 touch "${RL_DIR}/ran" || rc=$? ;;
esac
if [ -e "${RL_DIR}/ran" ]; then extra="${extra}ran"; fi
left="$(ls -A "${RL_DIR}/work" | tr '\n' ',')"
echo "rc=${rc} secs=${SECONDS} extra=${extra} left=${left}"
PROBE
}

# check_rl <ケース> <期待 rc> <最小秒> <最大秒> <期待 extra>
check_rl() {
  local name="$1" want_rc="$2" min="$3" max="$4" want_extra="$5" sh dir got rc rc_got secs extra left
  for sh in "${shells[@]}"; do
    dir="${root}/rl-${name}-$(basename "$(dirname "${sh}")")-$$-${RANDOM}"
    make_rl_probe "${dir}"
    rc=0
    got="$(cd / && "${sh}" "${dir}/scripts/rl-probe.sh" "${name}" "${dir}" 2>&1)" || rc=$?
    # 失敗しても孫を残さない
    if [ -f "${dir}/gc.pid" ]; then kill -KILL "$(cat "${dir}/gc.pid")" 2>/dev/null || true; fi
    rc_got="$(printf '%s' "${got}" | sed -n 's/.*rc=\([0-9]*\) secs=.*/\1/p' | tail -n 1)"
    secs="$(printf '%s' "${got}" | sed -n 's/.* secs=\([0-9]*\) extra=.*/\1/p' | tail -n 1)"
    extra="$(printf '%s' "${got}" | sed -n 's/.* extra=\([a-z]*\) left=.*/\1/p' | tail -n 1)"
    left="$(printf '%s' "${got}" | sed -n 's/.* left=\(.*\)$/\1/p' | tail -n 1)"
    if [ "${rc}" -eq 0 ] && [ "${rc_got}" = "${want_rc}" ] && [ "${extra}" = "${want_extra}" ] &&
      [ -n "${secs}" ] && [ "${secs}" -ge "${min}" ] && [ "${secs}" -le "${max}" ] && [ -z "${left}" ]; then
      pass "run_limited ${name} (${sh}): rc=${rc_got} secs=${secs}"
    else
      fail "run_limited ${name} (${sh}): exit=${rc} got='${got}' want rc=${want_rc} secs=${min}..${max} extra='${want_extra}' left=''"
    fi
  done
}

check_rl exit7 7 0 2 ""
check_rl true 0 0 2 ""
check_rl func 5 0 2 ""
check_rl timeout 124 1 8 ""
check_rl grandchild 124 1 10 "gone"
check_rl badlimit0 125 0 2 ""
check_rl badlimitabc 125 0 2 ""
check_rl nodir 125 0 2 ""

# int_in_range <値> <最小> <最大>: 戻り値 0 / 1 を具体値で照合する（数字だけ・9 桁以下・範囲内）。
check_range() {
  local name="$1" want="$2" value="$3" min="$4" max="$5" sh rc
  for sh in "${shells[@]}"; do
    rc=0
    # shellcheck disable=SC2016 # 引数は子の bash 側で展開させる
    "${sh}" -c 'source "$1"; int_in_range "$2" "$3" "$4"' _ "${src_dir}/lib.sh" "${value}" "${min}" "${max}" >/dev/null 2>&1 || rc=$?
    if [ "${rc}" = "${want}" ]; then
      pass "int_in_range ${name} (${sh})"
    else
      fail "int_in_range ${name} (${sh}): want rc=${want}, got rc=${rc}"
    fi
  done
}

check_range one 0 1 1 10
check_range max 0 10 1 10
check_range zero 1 0 1 10
check_range over 1 11 1 10
check_range leading-zero 0 08 1 10
check_range empty 1 "" 1 10
check_range negative 1 -1 1 10
check_range alpha 1 1a 1 10
check_range ten-digits 1 1234567890 1 99999999999
check_range nine-digits 0 123456789 1 999999999

for sh in "${shells[@]}"; do
  # shellcheck disable=SC2016 # BASH_VERSION は子の bash 側で展開させる
  echo "shell: ${sh} ($("${sh}" -c 'echo "${BASH_VERSION}"'))"
done
if [ "${failures}" -ne 0 ]; then
  echo "${failures} case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
