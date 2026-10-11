#!/usr/bin/env bash
# scripts/install-privileged-launcher.sh の自己テスト（TASK-171 追補・#1721・SUP-14・SEC-1・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へ setcap / getcap / chown / chmod / id のスタブと入力元・配置先を作り、
#   終了コード・stdout / stderr・スタブ呼び出し記録・最終ファイルのモードを具体値で照合する。root もホスト設定の
#   変更も使わない（実機の root 実行と検証は人間担当: #538・#539）。インストーラ本体はテスト入口
#   FANDHE_INSTALL_TEST_SANDBOX 経由で本番と同じ検査コードを通る。
# 呼び出し元: Makefile の `install-launcher-selftest` と CI の bench-regression ジョブ。
# 1 件でも期待と異なれば非ゼロで終了する（fail-closed）。Linux・非 root 限定で、前提を満たさない環境では失敗する。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/install-privileged-launcher.sh"
repo_root="$(cd "${script_dir}/.." && pwd)"

if [ "$(uname -s)" != "Linux" ]; then
  echo "FAIL: selftest requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: selftest must not run as root" >&2
  exit 1
fi

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }
eq() { # <name> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}

root_tmp="$(mktemp -d)"
trap 'chmod -R u+rwx "${root_tmp}" 2>/dev/null || true; rm -rf "${root_tmp}"' EXIT

CAPS="cap_sys_admin,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_kill,cap_setgid+ep"
SB=""

# 新しい sandbox（スタブ・入力元・配置先）を作る。
new_sandbox() {
  SB="$(mktemp -d "${root_tmp}/sb.XXXXXX")"
  mkdir "${SB}/stubs" "${SB}/src" "${SB}/dest"
  chmod 755 "${SB}/dest"
  : >"${SB}/calls.log"
  printf 'NEW-LAUNCHER\n' >"${SB}/src/launcher"
  printf 'NEW-SUPERVISOR\n' >"${SB}/src/supervisor"
  cat >"${SB}/stubs/id" <<'EOS'
#!/bin/bash
if [ "${1:-}" = "-u" ]; then echo "${STUB_UID:-0}"; exit 0; fi
exec /usr/bin/id "$@"
EOS
  cat >"${SB}/stubs/chown" <<'EOS'
#!/bin/bash
echo "chown $*" >>"${FANDHE_INSTALL_TEST_SANDBOX}/calls.log"
EOS
  cat >"${SB}/stubs/chmod" <<'EOS'
#!/bin/bash
echo "chmod $*" >>"${FANDHE_INSTALL_TEST_SANDBOX}/calls.log"
exec /usr/bin/chmod "$@"
EOS
  cat >"${SB}/stubs/setcap" <<'EOS'
#!/bin/bash
echo "setcap $*" >>"${FANDHE_INSTALL_TEST_SANDBOX}/calls.log"
file="${!#}"
case "${STUB_SETCAP_MODE:-ok}" in
  ok) case "$file" in *launcher*) : >"${FANDHE_INSTALL_TEST_SANDBOX}/capstate.launcher" ;; esac; exit 0 ;;
  enotsup) echo "Failed to set capabilities on file '$file': Operation not supported" >&2; exit 1 ;;
  enotsup-musl) echo "Failed to set capabilities on file '$file': Not supported" >&2; exit 1 ;;
  eperm) echo "Failed to set capabilities on file '$file': Operation not permitted" >&2; exit 1 ;;
  einval) echo "Failed to set capabilities on file '$file': Invalid argument" >&2; exit 1 ;;
  empty) exit 1 ;;
  notfound) exit 127 ;;
esac
EOS
  cat >"${SB}/stubs/getcap" <<'EOS'
#!/bin/bash
echo "getcap $*" >>"${FANDHE_INSTALL_TEST_SANDBOX}/calls.log"
file="$1"
[ "${STUB_GETCAP_MODE:-match}" = "fail" ] && exit 1
[ "${STUB_GETCAP_MODE:-match}" = "fail-supervisor" ] && case "$file" in *supervisor*) exit 1 ;; esac
if [ "${STUB_GETCAP_MODE:-match}" = "term-installer" ]; then
  # 置換後の最終名の supervisor を読み戻すときだけ、インストーラ本体（timeout の親）へ SIGTERM を送る。
  case "$file" in */.supervisor.*) ;; *supervisor) kill -TERM "$(ps -o ppid= -p "$PPID" | tr -d ' ')" ;; esac
fi
caps="cap_kill,cap_setgid,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_sys_admin"
emit() { # <caps>
  if [ "${STUB_GETCAP_FORMAT:-old}" = "new" ]; then echo "$file = $1+ep"; else echo "$file $1=ep"; fi
}
case "$file" in
  *launcher*)
    [ -e "${FANDHE_INSTALL_TEST_SANDBOX}/capstate.launcher" ] || exit 0
    if [ "${STUB_GETCAP_MODE:-match}" = "mismatch" ]; then emit "cap_sys_admin,cap_kill"; else emit "$caps"; fi ;;
  *supervisor*)
    if [ "${STUB_GETCAP_MODE:-match}" = "supervisor-has-caps" ]; then emit "$caps"; fi ;;
esac
exit 0
EOS
  chmod +x "${SB}/stubs/"*
}

# インストーラを sandbox 内で実行し、rc / out / err を記録する。
run_install() { # <env 代入>... -- <引数>...
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  rc=0
  env FANDHE_INSTALL_TEST_SANDBOX="${SB}" ${envs[@]+"${envs[@]}"} "${target}" "$@" >"${SB}/out" 2>"${SB}/err" || rc=$?
}
std_args() { echo "--launcher ${SB}/src/launcher --supervisor ${SB}/src/supervisor --dest-dir ${SB}/dest"; }
norm_log() {
  sed -E -e "s#${SB}#SB#g" -e 's#\.(launcher|supervisor)\.[A-Za-z0-9]{6}#.\1.TMP#g' "${SB}/calls.log"
}
count_log() { grep -c -E "$1" "${SB}/calls.log" || true; }
stderr_head() { head -n1 "${SB}/err" | sed -E 's#^((error|warning): [a-z-]+:).*#\1#'; }

# --- 1. root でない ---
new_sandbox
# shellcheck disable=SC2046
run_install STUB_UID=1000 -- $(std_args)
eq "not-root: exit code" 3 "${rc}"
eq "not-root: stderr code" "error: not-root:" "$(stderr_head)"
eq "not-root: no mutating calls" 0 "$(count_log '^(chown|chmod|setcap)')"
eq "not-root: dest untouched" 0 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"
rc=0
env -u FANDHE_INSTALL_TEST_SANDBOX "${target}" --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" \
  --dest-dir "${SB}/dest" >"${SB}/out" 2>"${SB}/err" || rc=$?
eq "not-root (real EUID): exit code" 3 "${rc}"
eq "not-root (real EUID): stderr code" "error: not-root:" "$(stderr_head)"

# --- 2. 配置先が信頼できない ---
untrusted_case() { # <name> <prep 関数>
  new_sandbox
  printf 'OLD-LAUNCHER\n' >"${SB}/dest/fandhe-container-launcher"
  "$2"
  # shellcheck disable=SC2046
  run_install -- $(std_args)
  eq "$1: exit code" 3 "${rc}"
  eq "$1: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
  eq "$1: no mutating calls" 0 "$(count_log '^(chown|chmod|setcap)')"
  eq "$1: stdout empty" "" "$(cat "${SB}/out")"
  if [ -d "${SB}/dest" ]; then
    eq "$1: old launcher unchanged" "OLD-LAUNCHER" "$(cat "${SB}/dest/fandhe-container-launcher")"
  fi
}
prep_777() { chmod 777 "${SB}/dest"; }
prep_gw_dest() { chmod 775 "${SB}/dest"; }
prep_symlink() { mv "${SB}/dest" "${SB}/real"; ln -s "${SB}/real" "${SB}/dest"; }
prep_file() { rm -rf "${SB}/dest"; : >"${SB}/dest"; }
untrusted_case "dest mode 777" prep_777
untrusted_case "dest group-writable" prep_gw_dest
untrusted_case "dest is symlink" prep_symlink
untrusted_case "dest is regular file" prep_file
# 祖先が g+w（dest は親の下）
new_sandbox
mkdir "${SB}/parent"
mkdir "${SB}/parent/dest"
chmod 755 "${SB}/parent/dest"
chmod 775 "${SB}/parent"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/parent/dest"
eq "parent group-writable: exit code" 3 "${rc}"
eq "parent group-writable: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
eq "parent group-writable: no mutating calls" 0 "$(count_log '^(chown|chmod|setcap)')"
# 配置先の既存ファイルが symlink
new_sandbox
ln -s "${SB}/src/launcher" "${SB}/dest/fandhe-container-launcher"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "dest file is symlink: exit code" 3 "${rc}"
eq "dest file is symlink: no mutating calls" 0 "$(count_log '^(chown|chmod|setcap)')"

# --- 3. setcap 成功 ---
success_case() { # <name> <getcap format>
  new_sandbox
  # shellcheck disable=SC2046
  run_install "STUB_GETCAP_FORMAT=$2" -- $(std_args)
  eq "$1: exit code" 0 "${rc}"
  eq "$1: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
  eq "$1: launcher mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container-launcher")"
  eq "$1: supervisor mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container-supervisor")"
  eq "$1: launcher content" "NEW-LAUNCHER" "$(cat "${SB}/dest/fandhe-container-launcher")"
  eq "$1: supervisor content" "NEW-SUPERVISOR" "$(cat "${SB}/dest/fandhe-container-supervisor")"
  eq "$1: chown count" 2 "$(count_log '^chown root:root ')"
  eq "$1: setcap calls" "setcap ${CAPS} SB/dest/.launcher.TMP" "$(norm_log | grep '^setcap' || true)"
  eq "$1: no setuid chmod" 0 "$(count_log '^chmod 4755')"
  eq "$1: no leftover temp files" 2 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"
}
success_case "setcap ok (old getcap format)" old
success_case "setcap ok (new getcap format)" new
# 冪等（アップグレード）: 同じ入力でもう一度
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "upgrade rerun: exit code" 0 "${rc}"
eq "upgrade rerun: file count" 2 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"

# --- 4. xattr 非対応で setuid ---
setuid_case() { # <name> <mode>
  new_sandbox
  # shellcheck disable=SC2046
  run_install "STUB_SETCAP_MODE=$2" -- $(std_args)
  eq "$1: exit code" 0 "${rc}"
  eq "$1: stdout" "installed: method=setuid dest-dir=${SB}/dest" "$(cat "${SB}/out")"
  eq "$1: stderr warning" "warning: setuid-fallback:" "$(stderr_head)"
  eq "$1: launcher mode" 4755 "$(stat -c %a "${SB}/dest/fandhe-container-launcher")"
  eq "$1: supervisor mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container-supervisor")"
  eq "$1: chmod 4755 count" 1 "$(count_log '^chmod 4755 ')"
  eq "$1: chown precedes chmod 4755" "chown root:root SB/dest/.launcher.TMP" \
    "$(norm_log | grep -B1 '^chmod 4755' | head -n1)"
  eq "$1: no leftover temp files" 2 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"
}
setuid_case "setuid fallback (glibc ENOTSUP)" enotsup
setuid_case "setuid fallback (musl wording)" enotsup-musl

# --- 5. その他の失敗では止まる ---
stop_case() { # <name> <expected code> <env 代入>...
  local name="$1" code="$2"
  shift 2
  local pre
  for pre in new old; do
    new_sandbox
    if [ "${pre}" = old ]; then
      printf 'OLD-LAUNCHER\n' >"${SB}/dest/fandhe-container-launcher"
      printf 'OLD-SUPERVISOR\n' >"${SB}/dest/fandhe-container-supervisor"
    fi
    # shellcheck disable=SC2046
    run_install "$@" -- $(std_args)
    eq "${name} (${pre}): exit code" 1 "${rc}"
    eq "${name} (${pre}): stderr code" "error: ${code}:" "$(stderr_head)"
    eq "${name} (${pre}): stdout empty" "" "$(cat "${SB}/out")"
    eq "${name} (${pre}): no setuid chmod" 0 "$(count_log '^chmod 4755')"
    if [ "${pre}" = old ]; then
      eq "${name} (${pre}): old launcher unchanged" "OLD-LAUNCHER" "$(cat "${SB}/dest/fandhe-container-launcher")"
      eq "${name} (${pre}): old supervisor unchanged" "OLD-SUPERVISOR" "$(cat "${SB}/dest/fandhe-container-supervisor")"
      eq "${name} (${pre}): no leftover temp files" 2 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"
    else
      eq "${name} (${pre}): nothing installed" 0 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"
    fi
  done
}
stop_case "setcap EPERM" setcap-failed STUB_SETCAP_MODE=eperm
stop_case "setcap EINVAL" setcap-failed STUB_SETCAP_MODE=einval
stop_case "setcap silent failure" setcap-failed STUB_SETCAP_MODE=empty
stop_case "setcap not installed (127)" setcap-failed STUB_SETCAP_MODE=notfound
stop_case "getcap mismatch" capability-mismatch STUB_GETCAP_MODE=mismatch
stop_case "getcap fails (launcher readback)" capability-mismatch STUB_GETCAP_MODE=fail
stop_case "getcap fails (no-caps readback)" capability-mismatch STUB_GETCAP_MODE=fail-supervisor
stop_case "supervisor has capabilities" capability-mismatch STUB_GETCAP_MODE=supervisor-has-caps

# --- 5b. 更新途中の中断・末尾スラッシュ・FIFO ---
new_sandbox
printf 'OLD-LAUNCHER\n' >"${SB}/dest/fandhe-container-launcher"
printf 'OLD-SUPERVISOR\n' >"${SB}/dest/fandhe-container-supervisor"
# shellcheck disable=SC2046
run_install STUB_GETCAP_MODE=term-installer -- $(std_args)
eq "SIGTERM mid-update: exit code" 143 "${rc}"
eq "SIGTERM mid-update: old launcher kept" "OLD-LAUNCHER" "$(cat "${SB}/dest/fandhe-container-launcher")"
eq "SIGTERM mid-update: old supervisor restored" "OLD-SUPERVISOR" "$(cat "${SB}/dest/fandhe-container-supervisor")"
eq "SIGTERM mid-update: no leftover files" 2 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"
new_sandbox
# shellcheck disable=SC2046
run_install STUB_GETCAP_MODE=term-installer -- $(std_args)
eq "SIGTERM mid-update (fresh): exit code" 143 "${rc}"
eq "SIGTERM mid-update (fresh): nothing installed" 0 "$(find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' ')"

new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest/"
eq "dest-dir trailing slash: exit code" 0 "${rc}"
eq "dest-dir trailing slash: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest//"
eq "dest-dir double trailing slash: exit code" 2 "${rc}"

new_sandbox
mkfifo "${SB}/src/fifo"
rc=0
env FANDHE_INSTALL_TEST_SANDBOX="${SB}" timeout 20 "${target}" --launcher "${SB}/src/fifo" \
  --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest" >"${SB}/out" 2>"${SB}/err" || rc=$?
eq "fifo source: exit code" 3 "${rc}"
eq "fifo source: stderr code" "error: invalid-source:" "$(stderr_head)"

# --- 6. 引数エラー・入力元 ---
new_sandbox
run_install --
eq "no args: exit code" 2 "${rc}"
run_install -- --bogus
eq "unknown option: exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir relative/dir
eq "relative dest-dir: exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest/../dest"
eq "dest-dir with '..': exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/de st"
eq "dest-dir with space: exit code" 2 "${rc}"
run_install -- --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest"
eq "missing --launcher: exit code" 2 "${rc}"
ln -s "${SB}/src/launcher" "${SB}/src/launcher-link"
run_install -- --launcher "${SB}/src/launcher-link" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest"
eq "symlink source: exit code" 3 "${rc}"
eq "symlink source: stderr code" "error: invalid-source:" "$(stderr_head)"
run_install -- --launcher "${SB}/src/none" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest"
eq "missing source: exit code" 3 "${rc}"
eq "invalid source: no mutating calls" 0 "$(count_log '^(chown|chmod|setcap)')"

# --- 7. privilege.rs の集合とのドリフト防止 ---
rust_caps="$(sed -n '/RUNTIME_REQUIRED_CAPABILITIES: \[Capability; [0-9]*\] = \[/,/^\];/p' \
  "${repo_root}/crates/supervisor/src/privilege.rs" | sed -n 's/.*Capability::\([A-Za-z]*\),.*/\1/p' |
  sed -E 's/([a-z])([A-Z])/\1_\2/g' | tr '[:upper:]' '[:lower:]' | sed 's/^/cap_/' | sort | paste -sd, -)"
script_caps="$(sed -n 's/^LAUNCHER_CAPS="\(.*\)+ep"$/\1/p' "${target}" | tr ',' '\n' | grep -v '^cap_setgid$' | sort | paste -sd, -)"
eq "capability set matches privilege.rs (minus cap_setgid)" "${rust_caps}" "${script_caps}"
eq "capability set is non-empty" 7 "$(printf '%s\n' "${rust_caps}" | tr ',' '\n' | grep -c .)"

if [ "${failures}" -ne 0 ]; then
  echo "FAIL: ${failures} check(s) failed" >&2
  exit 1
fi
echo "OK: all install-privileged-launcher checks passed"
