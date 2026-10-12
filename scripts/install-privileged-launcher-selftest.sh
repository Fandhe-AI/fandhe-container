#!/usr/bin/env bash
# scripts/install-privileged-launcher.sh の自己テスト（TASK-171 追補・#1721・SUP-14・SEC-1・REPAIR-5・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へスタブ（stat / mkdir / mktemp / dd / chown / chmod / setcap / getcap / ln / mv / rm / id）と
#   入力元・配置先を作り、終了コード・stdout / stderr・スタブ呼び出し記録・最終ファイルの中身とモードを具体値で照合する。
#   root もホスト設定の変更も使わない（実機の root 実行と検証は人間担当: #538・#539）。インストーラ本体はテスト入口
#   FANDHE_INSTALL_TEST_SANDBOX 経由で本番と同じ検査コードを通る。
# 期限の照合（REPAIR-5）: 期限なしの呼び出しが残っていないことを 3 通りで確かめる。
#   (1) どのスタブも親プロセスが timeout(1) であることを呼び出しごとに確かめる（全ケースが対象）。
#   (2) 成功する更新 1 回の呼び出し列を記録し、その 1 件ずつをハングさせた実行をすべて行う（期限 1 秒へ短縮）。止まった位置に
#       応じた終了コード・1 行目の code・結果の行・最終ファイルの組み合わせ・退避ファイルの有無を照合する。
#   (3) インストーラの本文に、期限なしの外部コマンド・親シェルのファイル検査・配置先へのリダイレクトが無いことを静的に確かめる。
#   経過秒はきつく照合しない（CI では他の自己テストと並列に走るため）。各実行を外側の timeout で包み、ハングしたまま
#   残らないことだけを確かめる。
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
# 配置先・属性を変えるスタブ呼び出し（「何も変更していない」の照合に使う）。
MUTATING='^(chown|chmod|setcap|mkdir|mktemp|dd|ln|mv|rm) '
# インストーラ 1 回を包む外側の期限（秒）。ハングの注入が期限で止まらなかったときに自己テスト自体を止めないため。
OUTER_TIMEOUT=60
# 期限の照合で使うインストーラ側の期限（秒）。
SHORT_TIMEOUT=1
SB=""

# 新しい sandbox（スタブ・入力元・配置先）を作る。
new_sandbox() {
  local name real
  SB="$(mktemp -d "${root_tmp}/sb.XXXXXX")"
  mkdir "${SB}/stubs" "${SB}/src" "${SB}/dest"
  chmod 755 "${SB}/dest"
  : >"${SB}/calls.log"
  printf 'NEW-LAUNCHER\n' >"${SB}/src/launcher"
  printf 'NEW-SUPERVISOR\n' >"${SB}/src/supervisor"
  # 全スタブ共通の前処理: 呼び出し記録・期限つき実行の確認・n 回目の呼び出しへのハング / 失敗の注入。
  #   STUB_HANG / STUB_FAIL / STUB_HANG_AFTER は `<command>:<n>` の空白区切り（そのコマンドの n 回目の呼び出し）。
  #   STUB_HANG_AFTER は本来の処理を済ませてからハングする（「操作は効いたが応答が返らない」の再現）。
  cat >"${SB}/stub-common.sh" <<'EOS'
sb="${FANDHE_INSTALL_TEST_SANDBOX}"
name="${0##*/}"
echo "${name} $*" >>"${sb}/calls.log"
# インストーラは外部コマンドを必ず timeout(1) 経由で起動する。親が timeout でなければ期限なしの呼び出しとして記録する。
parent=""
read -r parent <"/proc/${PPID}/comm" || true
[ "${parent}" = "timeout" ] || echo "${name} $*" >>"${sb}/unbounded.log"
n="$(grep -c "^${name} " "${sb}/calls.log")"
injected() { # <`command:n` の並び>
  local spec
  for spec in $1; do
    if [ "${spec}" = "${name}:${n}" ]; then return 0; fi
  done
  return 1
}
hang() { # <記録に残す種別>
  echo "$1 ${name}:${n}" >>"${sb}/inject.log"
  exec sleep 120
}
if injected "${STUB_HANG:-}"; then hang hang; fi
if injected "${STUB_FAIL:-}"; then
  echo "fail ${name}:${n}" >>"${sb}/inject.log"
  echo "${name}: injected failure" >&2
  exit 1
fi
# 本来の処理（実コマンド）を実行して終わる。STUB_HANG_AFTER の対象なら、処理を済ませてからハングする。
finish() { # <実コマンド> [args...]
  if injected "${STUB_HANG_AFTER:-}"; then
    "$@" || exit $?
    hang hang-after
  fi
  exec "$@"
}
EOS
  cat >"${SB}/stubs/id" <<'EOS'
#!/bin/bash
if [ "${1:-}" = "-u" ]; then echo "${STUB_UID:-0}"; exit 0; fi
exec /usr/bin/id "$@"
EOS
  # 実コマンドへそのまま渡すスタブ（記録と注入だけを足す）。
  for name in stat mkdir mktemp dd chmod ln mv rm; do
    real="$(PATH=/usr/bin:/bin command -v "${name}")"
    cat >"${SB}/stubs/${name}" <<EOS
#!/bin/bash
. "\${FANDHE_INSTALL_TEST_SANDBOX}/stub-common.sh"
finish "${real}" "\$@"
EOS
  done
  # chown は非 root では root:root にできないため、記録だけして成功を返す。
  cat >"${SB}/stubs/chown" <<'EOS'
#!/bin/bash
. "${FANDHE_INSTALL_TEST_SANDBOX}/stub-common.sh"
finish true
EOS
  cat >"${SB}/stubs/setcap" <<'EOS'
#!/bin/bash
. "${FANDHE_INSTALL_TEST_SANDBOX}/stub-common.sh"
file="${!#}"
case "${STUB_SETCAP_MODE:-ok}" in
  ok) case "$file" in *launcher*) : >"${FANDHE_INSTALL_TEST_SANDBOX}/capstate.launcher" ;; esac; exit 0 ;;
  enotsup) echo "Failed to set capabilities on file '$file': Operation not supported" >&2; exit 1 ;;
  enotsup-musl) echo "Failed to set capabilities on file '$file': Not supported" >&2; exit 1 ;;
  enotsup-stdout) echo "Failed to set capabilities on file '$file': Operation not supported"; exit 1 ;;
  eperm) echo "Failed to set capabilities on file '$file': Operation not permitted" >&2; exit 1 ;;
  einval) echo "Failed to set capabilities on file '$file': Invalid argument" >&2; exit 1 ;;
  empty) exit 1 ;;
  notfound) exit 127 ;;
esac
EOS
  # getcap のスタブ。xattr 非対応の FS は libcap の版で見え方が違うため、3 通りを模す:
  #   既定（何も出さず 0。2021-09 以降の libcap は ENOTSUP を capability なしと同じに扱う）・
  #   enotsup-stderr（それより前の libcap。stderr に診断を出して 0）・enotsup-exit1（非 0 で終わる実装）。
  cat >"${SB}/stubs/getcap" <<'EOS'
#!/bin/bash
. "${FANDHE_INSTALL_TEST_SANDBOX}/stub-common.sh"
file="$1"
mode="${STUB_GETCAP_MODE:-match}"
[ "${mode}" = "fail" ] && exit 1
[ "${mode}" = "fail-supervisor" ] && case "$file" in *supervisor*) exit 1 ;; esac
case "${mode}" in
  enotsup-stderr) echo "Failed to get capabilities of file '$file' (Operation not supported)" >&2; exit 0 ;;
  enotsup-exit1) echo "Failed to get capabilities of file '$file' (Operation not supported)" >&2; exit 1 ;;
  enotsup-stderr-supervisor)
    case "$file" in *supervisor*) echo "Failed to get capabilities of file '$file' (Operation not supported)" >&2; exit 0 ;; esac ;;
  enotsup-exit1-supervisor)
    case "$file" in *supervisor*) echo "Failed to get capabilities of file '$file' (Operation not supported)" >&2; exit 1 ;; esac ;;
  eio-stderr) echo "Failed to get capabilities of file '$file' (Input/output error)" >&2; exit 0 ;;
  eio-stderr-supervisor)
    case "$file" in *supervisor*) echo "Failed to get capabilities of file '$file' (Input/output error)" >&2; exit 0 ;; esac ;;
esac
if [ "${mode}" = "term-installer" ]; then
  # 置換後の最終名の supervisor を読み戻すときだけ、インストーラ本体へ SIGTERM を送る。本体の pid は run_install が
  # 起動時に書いたファイルから読む（プロセスの親子関係からは推測しない。bash の版で fork の有無が変わるため）。
  case "$file" in */.supervisor.*) ;; *supervisor) kill -TERM "$(cat "${FANDHE_INSTALL_TEST_SANDBOX}/installer.pid")" ;; esac
fi
caps="cap_kill,cap_setgid,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_sys_admin"
emit() { # <caps>
  if [ "${STUB_GETCAP_FORMAT:-old}" = "new" ]; then echo "$file = $1+ep"; else echo "$file $1=ep"; fi
}
case "$file" in
  *launcher*)
    [ -e "${FANDHE_INSTALL_TEST_SANDBOX}/capstate.launcher" ] || exit 0
    if [ "${mode}" = "mismatch" ]; then emit "cap_sys_admin,cap_kill"; else emit "$caps"; fi ;;
  *supervisor*)
    if [ "${mode}" = "supervisor-has-caps" ]; then emit "$caps"; fi ;;
esac
exit 0
EOS
  chmod +x "${SB}/stubs/"*
}

# インストーラを sandbox 内で実行し、rc / out / err を記録する。本体の pid を ${SB}/installer.pid へ書いてから exec する
# （bash → env → インストーラと exec でつなぐので pid は変わらない）。外側の timeout は自己テストを止めないための保険。
run_install() { # <env 代入>... -- <引数>...
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  rc=0
  # shellcheck disable=SC2016 # $$ と $@ は内側の bash で展開する
  timeout "${OUTER_TIMEOUT}" bash -c 'echo "$$" >"$0"; exec "$@"' "${SB}/installer.pid" \
    env FANDHE_INSTALL_TEST_SANDBOX="${SB}" ${envs[@]+"${envs[@]}"} "${target}" "$@" >"${SB}/out" 2>"${SB}/err" || rc=$?
}
std_args() { echo "--launcher ${SB}/src/launcher --supervisor ${SB}/src/supervisor --dest-dir ${SB}/dest"; }
norm_log() {
  sed -E -e "s#${SB}#SB#g" -e 's#\.(launcher|supervisor)\.[A-Za-z0-9]{6}#.\1.TMP#g' "${SB}/calls.log"
}
count_log() { grep -c -E "$1" "${SB}/calls.log" || true; }
count_err() { grep -c -E "$1" "${SB}/err" || true; }
stderr_head() { head -n1 "${SB}/err" | sed -E 's#^((error|warning): [a-z-]+:).*#\1#'; }
dest_count() { find "${SB}/dest" -mindepth 1 | wc -l | tr -d ' '; }
launcher_content() { cat "${SB}/dest/fandhe-container-launcher" 2>/dev/null || echo "<missing>"; }
supervisor_content() { cat "${SB}/dest/fandhe-container-supervisor" 2>/dev/null || echo "<missing>"; }
backup_content() { cat "${SB}"/dest/.supervisor.bak.* 2>/dev/null || echo "<missing>"; }
# stderr の n 行目。期限超過の終了コードは timeout(1) の実装と信号の無視の有無で 124 / 137 のどちらにもなるため、
# 1 つの語へそろえてから照合する（どちらも期限超過を表す）。
err_line() { # <n>
  sed -n "$1p" "${SB}/err" | sed -E 's/\(exit code (124|137)\)/(exit code TIMEOUT)/'
}
put_old_files() {
  printf 'OLD-LAUNCHER\n' >"${SB}/dest/fandhe-container-launcher"
  printf 'OLD-SUPERVISOR\n' >"${SB}/dest/fandhe-container-supervisor"
}

# --- 1. root でない ---
new_sandbox
# shellcheck disable=SC2046
run_install STUB_UID=1000 -- $(std_args)
eq "not-root: exit code" 3 "${rc}"
eq "not-root: stderr code" "error: not-root:" "$(stderr_head)"
eq "not-root: no mutating calls" 0 "$(count_log "${MUTATING}")"
eq "not-root: dest untouched" 0 "$(dest_count)"
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
  eq "$1: no mutating calls" 0 "$(count_log "${MUTATING}")"
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
eq "parent group-writable: no mutating calls" 0 "$(count_log "${MUTATING}")"
# 配置先の既存ファイルが symlink・ディレクトリ
new_sandbox
ln -s "${SB}/src/launcher" "${SB}/dest/fandhe-container-launcher"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "dest file is symlink: exit code" 3 "${rc}"
eq "dest file is symlink: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
eq "dest file is symlink: no mutating calls" 0 "$(count_log "${MUTATING}")"
new_sandbox
mkdir "${SB}/dest/fandhe-container-supervisor"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "dest file is directory: exit code" 3 "${rc}"
eq "dest file is directory: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
eq "dest file is directory: no mutating calls" 0 "$(count_log "${MUTATING}")"

# --- 3. setcap 成功 ---
success_case() { # <name> <getcap format>
  new_sandbox
  # shellcheck disable=SC2046
  run_install "STUB_GETCAP_FORMAT=$2" -- $(std_args)
  eq "$1: exit code" 0 "${rc}"
  eq "$1: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
  eq "$1: stderr empty" "" "$(cat "${SB}/err")"
  eq "$1: launcher mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container-launcher")"
  eq "$1: supervisor mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container-supervisor")"
  eq "$1: launcher content" "NEW-LAUNCHER" "$(launcher_content)"
  eq "$1: supervisor content" "NEW-SUPERVISOR" "$(supervisor_content)"
  eq "$1: chown count" 2 "$(count_log '^chown root:root ')"
  eq "$1: setcap calls" "setcap ${CAPS} SB/dest/.launcher.TMP" "$(norm_log | grep '^setcap' || true)"
  eq "$1: no setuid chmod" 0 "$(count_log '^chmod 4755')"
  eq "$1: no leftover temp files" 2 "$(dest_count)"
}
success_case "setcap ok (old getcap format)" old
success_case "setcap ok (new getcap format)" new
# 冪等（アップグレード）: 同じ入力でもう一度
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "upgrade rerun: exit code" 0 "${rc}"
eq "upgrade rerun: stderr empty" "" "$(cat "${SB}/err")"
eq "upgrade rerun: file count" 2 "$(dest_count)"
# 以前の実行が残した退避ファイル（復元に失敗したとき等に残す）があっても、名前が衝突せず更新できる。残っていたものは消さない
: >"${SB}/dest/.supervisor.bak.$$"
printf 'STALE\n' >"${SB}/dest/.supervisor.bak.AAAAAA"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "upgrade with stale backups: exit code" 0 "${rc}"
eq "upgrade with stale backups: stale file kept" "STALE" "$(cat "${SB}/dest/.supervisor.bak.AAAAAA")"
eq "upgrade with stale backups: file count" 4 "$(dest_count)"
# 配置先が無ければ、信頼できる祖先の下に 0755 で作る（umask に依らない）
new_sandbox
rmdir "${SB}/dest"
rc=0
(umask 077 && run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" \
  --dest-dir "${SB}/dest/a/b" && exit "${rc}") || rc=$?
eq "dest created: exit code" 0 "${rc}"
eq "dest created: mkdir calls" "mkdir -m 0755 -- SB/dest|mkdir -m 0755 -- SB/dest/a|mkdir -m 0755 -- SB/dest/a/b" \
  "$(norm_log | grep '^mkdir' | paste -sd'|' -)"
eq "dest created: directory modes" "755 755 755" \
  "$(stat -c %a "${SB}/dest" "${SB}/dest/a" "${SB}/dest/a/b" | paste -sd' ' -)"
eq "dest created: launcher content" "NEW-LAUNCHER" "$(cat "${SB}/dest/a/b/fandhe-container-launcher")"

# --- 4. xattr 非対応で setuid ---
setuid_case() { # <name> <setcap mode> [env 代入]...
  local name="$1" mode="$2"
  shift 2
  new_sandbox
  # shellcheck disable=SC2046
  run_install "STUB_SETCAP_MODE=${mode}" "$@" -- $(std_args)
  eq "${name}: exit code" 0 "${rc}"
  eq "${name}: stdout" "installed: method=setuid dest-dir=${SB}/dest" "$(cat "${SB}/out")"
  eq "${name}: stderr warning" "warning: setuid-fallback:" "$(stderr_head)"
  eq "${name}: stderr is the warning only" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
  eq "${name}: launcher mode" 4755 "$(stat -c %a "${SB}/dest/fandhe-container-launcher")"
  eq "${name}: supervisor mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container-supervisor")"
  eq "${name}: chmod 4755 count" 1 "$(count_log '^chmod 4755 ')"
  eq "${name}: chown precedes chmod 4755" "chown root:root SB/dest/.launcher.TMP" \
    "$(norm_log | grep -B1 '^chmod 4755' | head -n1)"
  eq "${name}: no leftover temp files" 2 "$(dest_count)"
}
setuid_case "setuid fallback (glibc ENOTSUP)" enotsup
setuid_case "setuid fallback (musl wording)" enotsup-musl
# xattr 非対応の FS では getcap も ENOTSUP を見る。libcap の版による 2 通りの見え方でも setuid の導入を完了する。
setuid_case "setuid fallback (getcap prints ENOTSUP, exit 0)" enotsup STUB_GETCAP_MODE=enotsup-stderr
setuid_case "setuid fallback (getcap exits 1 with ENOTSUP)" enotsup STUB_GETCAP_MODE=enotsup-exit1

# --- 5. その他の失敗では止まる ---
stop_case() { # <name> <expected code> <env 代入>...
  local name="$1" code="$2"
  shift 2
  local pre
  for pre in new old; do
    new_sandbox
    if [ "${pre}" = old ]; then
      put_old_files
    fi
    # shellcheck disable=SC2046
    run_install "$@" -- $(std_args)
    eq "${name} (${pre}): exit code" 1 "${rc}"
    eq "${name} (${pre}): stderr code" "error: ${code}:" "$(stderr_head)"
    eq "${name} (${pre}): stdout empty" "" "$(cat "${SB}/out")"
    eq "${name} (${pre}): no setuid chmod" 0 "$(count_log '^chmod 4755')"
    if [ "${pre}" = old ]; then
      eq "${name} (${pre}): old launcher unchanged" "OLD-LAUNCHER" "$(launcher_content)"
      eq "${name} (${pre}): old supervisor unchanged" "OLD-SUPERVISOR" "$(supervisor_content)"
      eq "${name} (${pre}): no leftover temp files" 2 "$(dest_count)"
    else
      eq "${name} (${pre}): nothing installed" 0 "$(dest_count)"
    fi
  done
}
stop_case "setcap EPERM" setcap-failed STUB_SETCAP_MODE=eperm
stop_case "setcap EINVAL" setcap-failed STUB_SETCAP_MODE=einval
stop_case "setcap silent failure" setcap-failed STUB_SETCAP_MODE=empty
stop_case "setcap not installed (127)" setcap-failed STUB_SETCAP_MODE=notfound
# setuid への切り替えは setcap の stderr だけで決める（stdout の文言では切り替えない）
stop_case "setcap 'not supported' on stdout only" setcap-failed STUB_SETCAP_MODE=enotsup-stdout
stop_case "getcap mismatch" capability-mismatch STUB_GETCAP_MODE=mismatch
stop_case "getcap fails (launcher readback)" capability-mismatch STUB_GETCAP_MODE=fail
stop_case "getcap fails (no-caps readback)" capability-mismatch STUB_GETCAP_MODE=fail-supervisor
stop_case "supervisor has capabilities" capability-mismatch STUB_GETCAP_MODE=supervisor-has-caps
# getcap の「非対応」を capability なしと読み替えるのは setcap が非対応で失敗した後だけ。setcap が成功した FS で
# getcap が非対応を返すのは矛盾なので止まる（setuid への切り替え条件は広がらない）。
stop_case "getcap ENOTSUP on stderr while setcap succeeded" capability-mismatch STUB_GETCAP_MODE=enotsup-stderr
stop_case "getcap ENOTSUP with exit 1 while setcap succeeded" capability-mismatch STUB_GETCAP_MODE=enotsup-exit1
stop_case "getcap ENOTSUP for the supervisor only while setcap succeeded" capability-mismatch \
  STUB_GETCAP_MODE=enotsup-stderr-supervisor
stop_case "getcap ENOTSUP with exit 1 for the supervisor only while setcap succeeded" capability-mismatch \
  STUB_GETCAP_MODE=enotsup-exit1-supervisor
# getcap が終了コード 0 のまま stderr に別の診断を出したら、capability なしとは見なさずに止まる
stop_case "getcap reports EIO with exit 0 (launcher)" capability-mismatch STUB_GETCAP_MODE=eio-stderr
stop_case "getcap reports EIO with exit 0 (supervisor)" capability-mismatch STUB_GETCAP_MODE=eio-stderr-supervisor
# setuid へ切り替えた後でも、`not supported` 以外の getcap の失敗では止まる
setuid_stop_case() { # <name> <getcap mode>
  new_sandbox
  put_old_files
  chmod 644 "${SB}/dest/fandhe-container-launcher"
  # shellcheck disable=SC2046
  run_install STUB_SETCAP_MODE=enotsup "STUB_GETCAP_MODE=$2" -- $(std_args)
  eq "$1: exit code" 1 "${rc}"
  eq "$1: stderr code" "error: capability-mismatch:" "$(stderr_head)"
  eq "$1: stdout empty" "" "$(cat "${SB}/out")"
  eq "$1: old launcher unchanged" "OLD-LAUNCHER" "$(launcher_content)"
  eq "$1: old launcher mode unchanged" 644 "$(stat -c %a "${SB}/dest/fandhe-container-launcher")"
  eq "$1: old supervisor unchanged" "OLD-SUPERVISOR" "$(supervisor_content)"
  eq "$1: no leftover temp files" 2 "$(dest_count)"
}
setuid_stop_case "setuid fallback: getcap reports EIO with exit 0" eio-stderr
setuid_stop_case "setuid fallback: getcap fails without a message" fail

# --- 5b. 更新途中の中断・末尾スラッシュ・FIFO ---
new_sandbox
put_old_files
# shellcheck disable=SC2046
run_install STUB_GETCAP_MODE=term-installer -- $(std_args)
eq "SIGTERM mid-update: exit code" 143 "${rc}"
eq "SIGTERM mid-update: outcome line" 1 "$(count_err '^warning: rolled-back: previous supervisor restored ')"
eq "SIGTERM mid-update: stderr is the outcome only" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
eq "SIGTERM mid-update: old launcher kept" "OLD-LAUNCHER" "$(launcher_content)"
eq "SIGTERM mid-update: old supervisor restored" "OLD-SUPERVISOR" "$(supervisor_content)"
eq "SIGTERM mid-update: no leftover files" 2 "$(dest_count)"
new_sandbox
# shellcheck disable=SC2046
run_install STUB_GETCAP_MODE=term-installer -- $(std_args)
eq "SIGTERM mid-update (fresh): exit code" 143 "${rc}"
eq "SIGTERM mid-update (fresh): outcome line" 1 "$(count_err '^warning: rolled-back: new supervisor removed ')"
eq "SIGTERM mid-update (fresh): nothing installed" 0 "$(dest_count)"

new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest/"
eq "dest-dir trailing slash: exit code" 0 "${rc}"
eq "dest-dir trailing slash: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest//"
eq "dest-dir double trailing slash: exit code" 2 "${rc}"

new_sandbox
mkfifo "${SB}/src/fifo"
run_install -- --launcher "${SB}/src/fifo" --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest"
eq "fifo source: exit code" 3 "${rc}"
eq "fifo source: stderr code" "error: invalid-source:" "$(stderr_head)"

# --- 6. 引数エラー・入力元・テスト入口 ---
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
eq "missing source: stderr code" "error: invalid-source:" "$(stderr_head)"
eq "invalid source: no mutating calls" 0 "$(count_log "${MUTATING}")"
# 期限の短縮はテスト入口の中で 1〜30 の整数だけを受け付ける
for bad in 0 31 abc 1.5 ""; do
  [ -n "${bad}" ] || continue
  # shellcheck disable=SC2046
  run_install "FANDHE_INSTALL_TEST_TIMEOUT_SECS=${bad}" -- $(std_args)
  eq "timeout override '${bad}': exit code" 3 "${rc}"
  eq "timeout override '${bad}': stderr code" "error: test-seam-refused:" "$(stderr_head)"
done
eq "timeout override refused: no mutating calls" 0 "$(count_log "${MUTATING}")"
rc=0
env -u FANDHE_INSTALL_TEST_SANDBOX FANDHE_INSTALL_TEST_TIMEOUT_SECS=1 "${target}" --launcher "${SB}/src/launcher" \
  --supervisor "${SB}/src/supervisor" --dest-dir "${SB}/dest" >"${SB}/out" 2>"${SB}/err" || rc=$?
eq "timeout override outside the sandbox: exit code" 3 "${rc}"
eq "timeout override outside the sandbox: stderr code" "error: test-seam-refused:" "$(stderr_head)"

# --- 7. privilege.rs の集合とのドリフト防止 ---
rust_caps="$(sed -n '/RUNTIME_REQUIRED_CAPABILITIES: \[Capability; [0-9]*\] = \[/,/^\];/p' \
  "${repo_root}/crates/supervisor/src/privilege.rs" | sed -n 's/.*Capability::\([A-Za-z]*\),.*/\1/p' |
  sed -E 's/([a-z])([A-Z])/\1_\2/g' | tr '[:upper:]' '[:lower:]' | sed 's/^/cap_/' | sort | paste -sd, -)"
script_caps="$(sed -n 's/^LAUNCHER_CAPS="\(.*\)+ep"$/\1/p' "${target}" | tr ',' '\n' | grep -v '^cap_setgid$' | sort | paste -sd, -)"
eq "capability set matches privilege.rs (minus cap_setgid)" "${rust_caps}" "${script_caps}"
eq "capability set is non-empty" 7 "$(printf '%s\n' "${rust_caps}" | tr ',' '\n' | grep -c .)"

# --- 8. 期限: 呼び出し 1 件ずつのハング（REPAIR-5） ---
# 背景で 1 ケースを実行し、終了コードと経過秒を sandbox へ書く。SB は呼び出し時点の sandbox。
bg_running=0
start_case() { # <env 代入>...
  (
    t0="${SECONDS}"
    # shellcheck disable=SC2046
    run_install "FANDHE_INSTALL_TEST_TIMEOUT_SECS=${SHORT_TIMEOUT}" "$@" -- $(std_args)
    echo "${rc}" >"${SB}/rc"
    echo "$((SECONDS - t0))" >"${SB}/elapsed"
  ) &
  bg_running=$((bg_running + 1))
  # 同時実行は 16 件まで（CI では他の自己テストと並列に走る）。
  if [ "${bg_running}" -ge 16 ]; then
    wait
    bg_running=0
  fi
}
# 背景実行した 1 ケースの共通の照合: 外側の期限に掛からず終わった・注入が効いた・期限なしの呼び出しが無い。
check_bounded_case() { # <name> <期待する inject.log>
  rc="$(cat "${SB}/rc" 2>/dev/null || echo "<none>")"
  local elapsed
  elapsed="$(cat "${SB}/elapsed" 2>/dev/null || echo 9999)"
  if [ "${elapsed}" -lt "$((OUTER_TIMEOUT / 2))" ]; then
    pass "$1: finished within the bound"
  else
    fail "$1: finished within the bound (took ${elapsed}s)"
  fi
  eq "$1: injection hit" "$2" "$(cat "${SB}/inject.log" 2>/dev/null | paste -sd' ' -)"
  eq "$1: every call ran under timeout" "" "$(cat "${SB}/unbounded.log" 2>/dev/null || true)"
}

# 成功する更新（旧ファイルあり）の呼び出し列を基準として記録する。
new_sandbox
put_old_files
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "reference upgrade: exit code" 0 "${rc}"
eq "reference upgrade: every call ran under timeout" "" "$(cat "${SB}/unbounded.log" 2>/dev/null || true)"
ref_log="${SB}/calls.log"
eq "reference upgrade: rename count" 2 "$(grep -c '^mv ' "${ref_log}")"
eq "reference upgrade: backup link count" 1 "$(grep -c '^ln ' "${ref_log}")"
eq "reference upgrade: remove count" 1 "$(grep -c '^rm ' "${ref_log}")"
eq "reference upgrade: temporary name count" 3 "$(grep -c '^mktemp ' "${ref_log}")"
eq "reference upgrade: stubbed commands seen" "chmod chown dd getcap ln mktemp mv rm setcap stat" \
  "$(cut -d' ' -f1 "${ref_log}" | sort -u | paste -sd' ' -)"
ref_specs=()
while IFS= read -r spec; do ref_specs+=("${spec}"); done < <(awk '{c[$1]++; print $1 ":" c[$1]}' "${ref_log}")
ref_mv1="$(grep -n '^mv ' "${ref_log}" | sed -n 1p | cut -d: -f1)"
ref_mv2="$(grep -n '^mv ' "${ref_log}" | sed -n 2p | cut -d: -f1)"
ref_rm="$(grep -n '^rm ' "${ref_log}" | sed -n 1p | cut -d: -f1)"
# launcher の rename の直後に走る stat（後始末での inode の読み戻し）が何回目の stat か。
ref_stat_after_mv2="$(($(head -n "${ref_mv2}" "${ref_log}" | grep -c '^stat ') + 1))"
echo "INFO: reference upgrade makes ${#ref_specs[@]} bounded calls (mv at ${ref_mv1} and ${ref_mv2}, backup rm at ${ref_rm})"

# 基準の呼び出し 1 件ずつをハングさせる（更新）。
matrix_sb=()
for spec in "${ref_specs[@]}"; do
  new_sandbox
  put_old_files
  matrix_sb+=("${SB}")
  start_case "STUB_HANG=${spec}"
done
# 個別のケース（2 重の障害・rename が効いた後のハング・新規インストール）。
extra_names=()
extra_sb=()
extra_case() { # <name> <old|fresh> <env 代入>...
  local name="$1" pre="$2"
  shift 2
  new_sandbox
  [ "${pre}" = fresh ] || put_old_files
  extra_names+=("${name}")
  extra_sb+=("${SB}")
  start_case "$@"
}
extra_case restore-timeout old "STUB_FAIL=mv:2" "STUB_HANG=mv:3"
extra_case restore-failure old "STUB_FAIL=mv:2 mv:3"
extra_case indeterminate old "STUB_HANG=mv:2 stat:${ref_stat_after_mv2}"
extra_case supervisor-renamed-then-hang old "STUB_HANG_AFTER=mv:1"
extra_case launcher-renamed-then-hang old "STUB_HANG_AFTER=mv:2"
extra_case cleanup-timeout-after-failure old STUB_SETCAP_MODE=eperm "STUB_HANG=rm:1"
extra_case fresh-launcher-rename-timeout fresh "STUB_HANG=mv:2"
extra_case fresh-restore-timeout fresh "STUB_FAIL=mv:2" "STUB_HANG=rm:1"
extra_case fresh-indeterminate fresh "STUB_HANG=mv:2 stat:${ref_stat_after_mv2}"
wait

i=0
for spec in "${ref_specs[@]}"; do
  SB="${matrix_sb[${i}]}"
  i=$((i + 1))
  name="hang ${spec} (call ${i})"
  check_bounded_case "${name}" "hang ${spec}"
  if [ "${i}" -eq "${ref_rm}" ]; then
    # 置換が済んだ後の退避ファイルの削除だけが止まった: 導入は成功で、消せなかった退避ファイルを警告する。
    eq "${name}: exit code" 0 "${rc}"
    eq "${name}: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
    eq "${name}: stderr" "warning: cleanup-incomplete:" "$(stderr_head)"
    eq "${name}: stderr is the warning only" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "NEW-LAUNCHER NEW-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
    eq "${name}: backup kept" "OLD-SUPERVISOR" "$(backup_content)"
    eq "${name}: file count" 3 "$(dest_count)"
    continue
  fi
  eq "${name}: exit code" 1 "${rc}"
  eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
  eq "${name}: stdout empty" "" "$(cat "${SB}/out")"
  eq "${name}: file count" 2 "$(dest_count)"
  if [ "${i}" -lt "${ref_mv1}" ]; then
    # 置換の前: 何も置き換わっていない。結果の行は要らない。
    eq "${name}: state in the message" 1 "$(head -n1 "${SB}/err" | grep -c 'no installed file was replaced')"
    eq "${name}: stderr is one line" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
  elif [ "${i}" -le "${ref_mv2}" ]; then
    # supervisor の rename から launcher の rename まで: 旧 supervisor へ戻り、その結果を 1 行で示す。
    eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: ')"
    eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
  else
    # 2 つとも置換した後の読み戻し: 新しい組で揃っていて、検証が終わっていないことを示す。
    eq "${name}: state in the message" 1 "$(head -n1 "${SB}/err" | grep -c 'both files are already replaced')"
    eq "${name}: outcome line" 1 "$(count_err '^warning: replaced-unverified: ')"
    eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "NEW-LAUNCHER NEW-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
  fi
done

i=0
for name in "${extra_names[@]}"; do
  SB="${extra_sb[${i}]}"
  i=$((i + 1))
  bak="$(find "${SB}/dest" -name '.supervisor.bak.*' | head -n1)"
  case "${name}" in
    restore-timeout | restore-failure)
      # launcher の rename が失敗し、旧 supervisor への復元も失敗（期限超過 / エラー）: 退避ファイルを残して場所を示す。
      if [ "${name}" = restore-timeout ]; then
        check_bounded_case "${name}" "fail mv:2 hang mv:3"
      else
        check_bounded_case "${name}" "fail mv:2 fail mv:3"
      fi
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: restore-failed line" \
        "error: restore-failed: could not restore the previous supervisor (exit code $([ "${name}" = restore-timeout ] && echo TIMEOUT || echo 1)); it is kept at ${bak} and ${SB}/dest/fandhe-container-supervisor is the new one; restore with: mv -f -- ${bak} ${SB}/dest/fandhe-container-supervisor" \
        "$(err_line 2)"
      eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: files" "OLD-LAUNCHER NEW-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
      eq "${name}: backup kept" "OLD-SUPERVISOR" "$(backup_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    indeterminate)
      # launcher の rename が期限超過し、置換の有無の読み戻しも期限超過: 何も動かさず退避ファイルを残す。
      check_bounded_case "${name}" "hang mv:2 hang stat:${ref_stat_after_mv2}"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: state-indeterminate line" 1 \
        "$(sed -n 2p "${SB}/err" | grep -c "^error: state-indeterminate: .* kept at ${bak}; .* restore with: mv -f -- ${bak} ${SB}/dest/fandhe-container-supervisor; ")"
      eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: backup kept" "OLD-SUPERVISOR" "$(backup_content)"
      eq "${name}: supervisor not moved" "NEW-SUPERVISOR" "$(supervisor_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    supervisor-renamed-then-hang)
      # supervisor の rename は効いたが応答が返らない: inode の読み戻しで置換済みと分かり、旧 supervisor へ戻す。
      check_bounded_case "${name}" "hang-after mv:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: previous supervisor restored ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
      eq "${name}: file count" 2 "$(dest_count)"
      ;;
    launcher-renamed-then-hang)
      # launcher の rename は効いたが応答が返らない: 新しい組で揃っているので戻さない。
      check_bounded_case "${name}" "hang-after mv:2"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: replaced-unverified: ')"
      eq "${name}: no rollback" 0 "$(count_err '^warning: rolled-back: ')"
      eq "${name}: files" "NEW-LAUNCHER NEW-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
      eq "${name}: file count" 2 "$(dest_count)"
      ;;
    cleanup-timeout-after-failure)
      # 置換の前に失敗し、一時ファイルの削除だけが期限超過: 原因は 1 行目、消せなかったファイルは警告で示す。
      check_bounded_case "${name}" "hang rm:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: setcap-failed:" "$(stderr_head)"
      eq "${name}: cleanup-incomplete line" 1 \
        "$(err_line 2 | grep -c "^warning: cleanup-incomplete: could not remove the temporary file ${SB}/dest/.launcher.[A-Za-z0-9]* (exit code TIMEOUT); ")"
      eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    fresh-launcher-rename-timeout)
      check_bounded_case "${name}" "hang mv:2"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: new supervisor removed ')"
      eq "${name}: nothing installed" 0 "$(dest_count)"
      ;;
    fresh-restore-timeout)
      check_bounded_case "${name}" "fail mv:2 hang rm:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: restore-failed line" \
        "error: restore-failed: could not remove the new supervisor at ${SB}/dest/fandhe-container-supervisor (exit code TIMEOUT); there was no previous one, remove it manually" \
        "$(err_line 2)"
      eq "${name}: files" "<missing> NEW-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
      eq "${name}: file count" 1 "$(dest_count)"
      ;;
    fresh-indeterminate)
      check_bounded_case "${name}" "hang mv:2 hang stat:${ref_stat_after_mv2}"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: state-indeterminate line" 1 \
        "$(sed -n 2p "${SB}/err" | grep -c "^error: state-indeterminate: .* there was no previous one; if the launcher is missing, remove ${SB}/dest/fandhe-container-supervisor; ")"
      eq "${name}: supervisor not moved" "NEW-SUPERVISOR" "$(supervisor_content)"
      eq "${name}: file count" 1 "$(dest_count)"
      ;;
    *) fail "unknown extra case ${name}" ;;
  esac
done

# 全ケースを通して、期限なしで呼ばれたスタブが 1 件も無いこと。
eq "no stub ran outside timeout in any case" 0 "$(find "${root_tmp}" -name unbounded.log | wc -l | tr -d ' ')"

# --- 9. 期限: 本文の静的検査（REPAIR-5） ---
# コメント行と行末コメントを除いた本文を対象にする。
code="$(grep -v '^[[:space:]]*#' "${target}" | sed -E 's/[[:space:]]+#[[:space:]].*$//')"
# 配置先・入力元に触る外部コマンドがコマンド位置（行頭・`;` `&` `|` `(` `{` `!` の直後・then / do / else・command / exec /
# env / eval / xargs の後）に現れないこと。期限つきの経路（run_child・bounded・step）の引数としてだけ現れる。
fs_cmds='(stat|mkdir|mktemp|dd|cp|cat|tee|install|chown|chmod|setcap|getcap|ln|mv|rm|rmdir|touch|readlink|realpath|ls|find|test)'
eq "static: no file command outside the bounded runner" "" \
  "$(printf '%s\n' "${code}" | grep -n -E "(^|[;&|({!]|then|do|else|command|exec|env|eval|xargs)[[:space:]]*${fs_cmds}([[:space:]]|\$)" || true)"
# timeout(1) の呼び出しは run_child の 2 行だけ（期限と猶予を必ず渡している）。
# shellcheck disable=SC2016 # インストーラ本文の文字列をそのまま探す
eq "static: timeout is invoked only by the bounded runner" 2 \
  "$(printf '%s\n' "${code}" | grep -c -F 'timeout -k "${KILL_GRACE}" "${CHILD_TIMEOUT}" "$@"')"
eq "static: no other timeout invocation" 2 "$(printf '%s\n' "${code}" | grep -c -E '(^|[^-_a-z])timeout[[:space:]]+-')"
# 親シェルのファイル検査（[ -e ] [ -f ] [ -d ] [ -L ] 等。-n と -z は文字列の検査なので除く）が無いこと。
eq "static: no file test in the parent shell" "" \
  "$(printf '%s\n' "${code}" | grep -n -E '(\[|&&|\|\|)[[:space:]]+(![[:space:]]+)?-[a-mo-yA-Z][[:space:]]' || true)"
# 親シェルが開くファイルは入力元の 1 か所（watchdog つきの open）だけ。/dev/null と fd の複製（<& >&）は対象外。
opens="$(printf '%s\n' "${code}" | sed 's#/dev/null##g' | grep -E '[<>][[:space:]]*"?(\$|/)' || true)"
eq "static: the parent shell opens one file" 1 "$(printf '%s\n' "${opens}" | grep -c .)"
# shellcheck disable=SC2016 # インストーラ本文の文字列をそのまま探す
eq "static: the only open is the watchdog-guarded source" 1 "$(printf '%s\n' "${opens}" | grep -c -F 'exec {fd}<"${path}"')"

if [ "${failures}" -ne 0 ]; then
  echo "FAIL: ${failures} check(s) failed" >&2
  exit 1
fi
echo "OK: all install-privileged-launcher checks passed"
