#!/usr/bin/env bash
# scripts/install-privileged-launcher.sh の自己テスト（TASK-171 追補・#1721・#2068・#2137・MS-9・SUP-14・SEC-1・PLUG-11・REPAIR-5・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へスタブ（stat / mkdir / flock / mktemp / dd / sha256sum / chown / chmod / setcap / getcap / ln / mv / rm / id）と
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
# 排他の照合: 配置先のロックを別プロセスが持っている間は何も変えずに止まること、配置先・属性を変えるスタブの呼び出しが
#   すべてロックを持ったまま行われること（スタブが呼び出しごとにロックの取得を試み、取れてしまったら記録する）を確かめる。
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
# 属性の変更と置換だけ（sha256sum の照合で止まる場合に何も起きていないことの照合に使う）。
ATTR_AND_REPLACE='^(chown|chmod|setcap|ln|mv) '
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
  printf 'NEW-CLI\n' >"${SB}/src/cli"
  # 許可済みの sha256（入力元の中身の実際の値）。HASH_ARGV は引数列として、SHA_* は個別に使う。
  SHA_L="$(sha256sum "${SB}/src/launcher" | cut -d' ' -f1)"
  SHA_S="$(sha256sum "${SB}/src/supervisor" | cut -d' ' -f1)"
  SHA_C="$(sha256sum "${SB}/src/cli" | cut -d' ' -f1)"
  HASH_ARGV=(--launcher-sha256 "${SHA_L}" --supervisor-sha256 "${SHA_S}" --cli-sha256 "${SHA_C}")
  # 全スタブ共通の前処理: 呼び出し記録・期限つき実行の確認・n 回目の呼び出しへのハング / 失敗の注入。
  #   STUB_HANG / STUB_FAIL / STUB_HANG_AFTER は `<command>:<n>` の空白区切り（そのコマンドの n 回目の呼び出し）。
  #   STUB_HANG_AFTER は本来の処理を済ませてからハングする（「操作は効いたが応答が返らない」の再現）。
  #   STUB_HOOK_AT の呼び出しでは、本来の処理の前に ${sb}/hook.sh を実行する（実行の途中で配置先を外から変える再現）。
  #   STUB_HOOK_AFTER_AT は本来の処理の後に実行する（検査と次の操作の間の差し替えの再現）。
  # ロックの確認にはスタブではない実物の flock を使う（スタブを通すと呼び出し記録に混ざる）。
  printf 'real_flock=%q\n' "$(PATH=/usr/bin:/bin command -v flock)" >"${SB}/stub-common.sh"
  cat >>"${SB}/stub-common.sh" <<'EOS'
sb="${FANDHE_INSTALL_TEST_SANDBOX}"
name="${0##*/}"
echo "${name} $*" >>"${sb}/calls.log"
# インストーラは外部コマンドを必ず timeout(1) 経由で起動する。親が timeout でなければ期限なしの呼び出しとして記録する。
parent=""
read -r parent <"/proc/${PPID}/comm" || true
[ "${parent}" = "timeout" ] || echo "${name} $*" >>"${sb}/unbounded.log"
# 配置先・属性を変えるコマンドは、配置先のロック（<dest-dir>/.install.lock）をインストーラが持ったまま呼ばれる。
# ロックファイルが無い・別の記述子から取れてしまう（＝誰も持っていない）なら、排他の外での変更として記録する。
case "${name}" in
  mktemp | dd | sha256sum | chown | chmod | setcap | ln | mv | rm)
    lock="$(find "${sb}" -name .install.lock | head -n1)"
    if [ -z "${lock}" ] || "${real_flock}" -n "${lock}" true; then echo "${name} $*" >>"${sb}/unlocked.log"; fi
    ;;
esac
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
if injected "${STUB_HOOK_AT:-}"; then
  echo "hook ${name}:${n}" >>"${sb}/inject.log"
  "${sb}/hook.sh"
fi
if injected "${STUB_HANG:-}"; then hang hang; fi
if injected "${STUB_FAIL:-}"; then
  echo "fail ${name}:${n}" >>"${sb}/inject.log"
  echo "${name}: injected failure" >&2
  exit 1
fi
# 本来の処理（実コマンド）を実行して終わる。STUB_HANG_AFTER の対象なら、処理を済ませてからハングする。
finish() { # <実コマンド> [args...]
  local finish_rc=0
  if injected "${STUB_HOOK_AFTER_AT:-}"; then
    "$@" || finish_rc=$?
    echo "hook-after ${name}:${n}" >>"${sb}/inject.log"
    "${sb}/hook.sh"
    exit "${finish_rc}"
  fi
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
  for name in stat mkdir flock mktemp dd chmod ln mv rm; do
    real="$(PATH=/usr/bin:/bin command -v "${name}")"
    cat >"${SB}/stubs/${name}" <<EOS
#!/bin/bash
. "\${FANDHE_INSTALL_TEST_SANDBOX}/stub-common.sh"
finish "${real}" "\$@"
EOS
  done
  # sha256sum は STUB_SHA256_MODE で出力を壊す（既定は実コマンド）。
  cat >"${SB}/stubs/sha256sum" <<'EOS'
#!/bin/bash
. "${FANDHE_INSTALL_TEST_SANDBOX}/stub-common.sh"
file="${!#}"
case "${STUB_SHA256_MODE:-real}" in
  garbage) echo "not-a-hash  ${file}"; exit 0 ;;
  two-lines)
    out="$(/usr/bin/sha256sum -- "${file}")"
    printf '%s\n%s\n' "${out}" "${out}"
    exit 0 ;;
  fail) exit 1 ;;
esac
finish /usr/bin/sha256sum "$@"
EOS
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
[ "${mode}" = "fail-cli" ] && case "$file" in */fandhe-container | */.cli.*) exit 1 ;; esac
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
  */fandhe-container | */.cli.*)
    if [ "${mode}" = "cli-has-caps" ]; then emit "$caps"; fi ;;
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
std_args() { echo "--launcher ${SB}/src/launcher --launcher-sha256 ${SHA_L} --supervisor ${SB}/src/supervisor --supervisor-sha256 ${SHA_S} --cli ${SB}/src/cli --cli-sha256 ${SHA_C} --dest-dir ${SB}/dest"; }
norm_log() {
  sed -E -e "s#${SB}#SB#g" -e 's#\.(launcher|supervisor|cli)\.[A-Za-z0-9]{6}#.\1.TMP#g' "${SB}/calls.log"
}
count_log() { grep -c -E "$1" "${SB}/calls.log" || true; }
count_err() { grep -c -E "$1" "${SB}/err" || true; }
stderr_head() { head -n1 "${SB}/err" | sed -E 's#^((error|warning): [a-z-]+:).*#\1#'; }
# 配置先の中のファイル数。ロックファイル（消さずに残す）は数えず、lock_state で別に照合する。
dest_count() { find "${SB}/dest" -mindepth 1 ! -name .install.lock | wc -l | tr -d ' '; }
# sandbox 内のロックファイルの状態（`<配置先からの相対パス>:<mode>`。無ければ none）。
lock_state() {
  local lock
  lock="$(find "${SB}" -name .install.lock | head -n1)"
  if [ -n "${lock}" ]; then echo "${lock#"${SB}"/}:$(stat -c %a "${lock}")"; else echo none; fi
}
launcher_content() { cat "${SB}/dest/fandhe-container-launcher" 2>/dev/null || echo "<missing>"; }
supervisor_content() { cat "${SB}/dest/fandhe-container-supervisor" 2>/dev/null || echo "<missing>"; }
cli_content() { cat "${SB}/dest/fandhe-container" 2>/dev/null || echo "<missing>"; }
backup_content() { cat "${SB}"/dest/.supervisor.bak.* 2>/dev/null || echo "<missing>"; }
cli_backup_content() { cat "${SB}"/dest/.cli.bak.* 2>/dev/null || echo "<missing>"; }
# stderr の n 行目。期限超過の終了コードは timeout(1) の実装と信号の無視の有無で 124 / 137 のどちらにもなるため、
# 1 つの語へそろえてから照合する（どちらも期限超過を表す）。
err_line() { # <n>
  sed -n "$1p" "${SB}/err" | sed -E 's/\(exit code (124|137)\)/(exit code TIMEOUT)/'
}
put_old_files() {
  printf 'OLD-LAUNCHER\n' >"${SB}/dest/fandhe-container-launcher"
  printf 'OLD-SUPERVISOR\n' >"${SB}/dest/fandhe-container-supervisor"
  printf 'OLD-CLI\n' >"${SB}/dest/fandhe-container"
}

# --- 1. root でない ---
new_sandbox
# shellcheck disable=SC2046
run_install STUB_UID=1000 -- $(std_args)
eq "not-root: exit code" 3 "${rc}"
eq "not-root: stderr code" "error: not-root:" "$(stderr_head)"
eq "not-root: no mutating calls" 0 "$(count_log "${MUTATING}")"
eq "not-root: dest untouched" 0 "$(dest_count)"
eq "not-root: no lock file" none "$(lock_state)"
rc=0
env -u FANDHE_INSTALL_TEST_SANDBOX "${target}" --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" \
  --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest" >"${SB}/out" 2>"${SB}/err" || rc=$?
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
  eq "$1: no lock file" none "$(lock_state)"
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
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/parent/dest"
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
# CLI の最終名が symlink・ディレクトリでも、何も変えずに止まる（launcher・supervisor と同じ検査）
new_sandbox
put_old_files
rm "${SB}/dest/fandhe-container"
ln -s "${SB}/src/cli" "${SB}/dest/fandhe-container"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "dest cli is symlink: exit code" 3 "${rc}"
eq "dest cli is symlink: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
eq "dest cli is symlink: no mutating calls" 0 "$(count_log "${MUTATING}")"
eq "dest cli is symlink: others unchanged" "OLD-LAUNCHER OLD-SUPERVISOR" "$(launcher_content) $(supervisor_content)"
new_sandbox
mkdir "${SB}/dest/fandhe-container"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "dest cli is directory: exit code" 3 "${rc}"
eq "dest cli is directory: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
eq "dest cli is directory: no mutating calls" 0 "$(count_log "${MUTATING}")"

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
  eq "$1: cli mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container")"
  eq "$1: launcher content" "NEW-LAUNCHER" "$(launcher_content)"
  eq "$1: supervisor content" "NEW-SUPERVISOR" "$(supervisor_content)"
  eq "$1: cli content" "NEW-CLI" "$(cli_content)"
  eq "$1: chown count" 3 "$(count_log '^chown root:root ')"
  eq "$1: setcap calls (launcher only, none for the cli or supervisor)" "setcap ${CAPS} SB/dest/.launcher.TMP" \
    "$(norm_log | grep '^setcap' || true)"
  eq "$1: no setuid chmod" 0 "$(count_log '^chmod 4755')"
  eq "$1: cli chmod is 0755 only" "chmod 0755 SB/dest/.cli.TMP" "$(norm_log | grep '^chmod .*\.cli\.TMP' || true)"
  eq "$1: no leftover temp files" 3 "$(dest_count)"
  eq "$1: lock file is private" "dest/.install.lock:600" "$(lock_state)"
  eq "$1: every change ran under the lock" "" "$(cat "${SB}/unlocked.log" 2>/dev/null || true)"
}
success_case "setcap ok (old getcap format)" old
success_case "setcap ok (new getcap format)" new
# 冪等（アップグレード）: 同じ入力でもう一度
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "upgrade rerun: exit code" 0 "${rc}"
eq "upgrade rerun: stderr empty" "" "$(cat "${SB}/err")"
eq "upgrade rerun: file count" 3 "$(dest_count)"
# 以前の実行が残した退避ファイル（復元に失敗したとき等に残す）があっても、名前が衝突せず更新できる。残っていたものは消さない
: >"${SB}/dest/.supervisor.bak.$$"
printf 'STALE\n' >"${SB}/dest/.supervisor.bak.AAAAAA"
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "upgrade with stale backups: exit code" 0 "${rc}"
eq "upgrade with stale backups: stale file kept" "STALE" "$(cat "${SB}/dest/.supervisor.bak.AAAAAA")"
eq "upgrade with stale backups: file count" 5 "$(dest_count)"
# 配置先が無ければ、信頼できる祖先の下に 0755 で作る（umask に依らない）
new_sandbox
rmdir "${SB}/dest"
rc=0
(umask 077 && run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" \
  --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest/a/b" && exit "${rc}") || rc=$?
eq "dest created: exit code" 0 "${rc}"
eq "dest created: mkdir calls" "mkdir -m 0755 -- SB/dest|mkdir -m 0755 -- SB/dest/a|mkdir -m 0755 -- SB/dest/a/b" \
  "$(norm_log | grep '^mkdir' | paste -sd'|' -)"
eq "dest created: directory modes" "755 755 755" \
  "$(stat -c %a "${SB}/dest" "${SB}/dest/a" "${SB}/dest/a/b" | paste -sd' ' -)"
eq "dest created: launcher content" "NEW-LAUNCHER" "$(cat "${SB}/dest/a/b/fandhe-container-launcher")"
eq "dest created: cli content" "NEW-CLI" "$(cat "${SB}/dest/a/b/fandhe-container")"
eq "dest created: lock file is private" "dest/a/b/.install.lock:600" "$(lock_state)"

# --- 3b. 同じ配置先への並行インストールの排他 ---
# 別のプロセスがロックを持っている間は、何も変えずに終了コード 3 で止まる。解放されれば更新できる。
new_sandbox
put_old_files
: >"${SB}/dest/.install.lock"
chmod 600 "${SB}/dest/.install.lock"
exec 9>>"${SB}/dest/.install.lock"
flock -n 9
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "lock held by another process: exit code" 3 "${rc}"
eq "lock held by another process: stderr code" "error: install-locked:" "$(stderr_head)"
eq "lock held by another process: stderr is one line" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
eq "lock held by another process: no mutating calls" 0 "$(count_log "${MUTATING}")"
eq "lock held by another process: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
eq "lock held by another process: file count" 3 "$(dest_count)"
exec 9>&-
# shellcheck disable=SC2046
run_install -- $(std_args)
eq "lock released: exit code" 0 "${rc}"
eq "lock released: files" "NEW-LAUNCHER NEW-SUPERVISOR NEW-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
# ロックファイルが他の利用者から読める（読めるだけで flock を取れる）・通常ファイルでないときは、信頼できない配置先として止まる
lock_untrusted_case() { # <name> <prep 関数>
  new_sandbox
  put_old_files
  "$2"
  # shellcheck disable=SC2046
  run_install -- $(std_args)
  eq "$1: exit code" 3 "${rc}"
  eq "$1: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
  eq "$1: no mutating calls" 0 "$(count_log "${MUTATING}")"
  eq "$1: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
}
prep_lock_644() { : >"${SB}/dest/.install.lock"; chmod 644 "${SB}/dest/.install.lock"; }
prep_lock_symlink() { : >"${SB}/lock-target"; chmod 600 "${SB}/lock-target"; ln -s "${SB}/lock-target" "${SB}/dest/.install.lock"; }
prep_lock_dir() { mkdir "${SB}/dest/.install.lock"; }
lock_untrusted_case "lock file readable by others" prep_lock_644
lock_untrusted_case "lock file is a symlink" prep_lock_symlink
lock_untrusted_case "lock file is a directory" prep_lock_dir

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
  eq "${name}: cli mode" 755 "$(stat -c %a "${SB}/dest/fandhe-container")"
  eq "${name}: no leftover temp files" 3 "$(dest_count)"
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
      eq "${name} (${pre}): old cli unchanged" "OLD-CLI" "$(cli_content)"
      eq "${name} (${pre}): no leftover temp files" 3 "$(dest_count)"
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
# CLI には capability を付けない。付いていたら（読み戻しが空でなければ）止まる。
stop_case "cli has capabilities" capability-mismatch STUB_GETCAP_MODE=cli-has-caps
stop_case "getcap fails (cli readback)" capability-mismatch STUB_GETCAP_MODE=fail-cli
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
  eq "$1: no leftover temp files" 3 "$(dest_count)"
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
eq "SIGTERM mid-update: old cli restored" "OLD-CLI" "$(cli_content)"
eq "SIGTERM mid-update: both restorations on the one outcome line" 1 "$(count_err 'previous supervisor restored at .*, previous CLI restored at ')"
eq "SIGTERM mid-update: no leftover files" 3 "$(dest_count)"
new_sandbox
# shellcheck disable=SC2046
run_install STUB_GETCAP_MODE=term-installer -- $(std_args)
eq "SIGTERM mid-update (fresh): exit code" 143 "${rc}"
eq "SIGTERM mid-update (fresh): outcome line" 1 "$(count_err '^warning: rolled-back: new supervisor removed ')"
eq "SIGTERM mid-update (fresh): the new cli is removed too" 1 "$(count_err 'new supervisor removed from .*, new CLI removed from ')"
eq "SIGTERM mid-update (fresh): nothing installed" 0 "$(dest_count)"

# 実行の途中で配置先が外から変えられた場合（ロックの外にいる root の操作）。スタブの呼び出しに合わせて hook.sh が変える。
write_hook() { # <hook.sh の本文>
  # hook.sh はスタブではなく実コマンドを使う（スタブを通すと呼び出し記録に混ざる）。
  printf '#!/bin/bash\nPATH=/usr/bin:/bin\n%s\n' "$1" >"${SB}/hook.sh"
  chmod +x "${SB}/hook.sh"
}
# 最初の確認の後に現れた supervisor も退避し、launcher の置換に失敗したら戻す（退避なしで上書きしない）
new_sandbox
# shellcheck disable=SC2016 # hook.sh の中で展開する
write_hook 'printf "APPEARED\n" >"${FANDHE_INSTALL_TEST_SANDBOX}/dest/fandhe-container-supervisor"'
# shellcheck disable=SC2046
run_install STUB_HOOK_AT=dd:1 STUB_FAIL=mv:3 -- $(std_args)
eq "supervisor appears mid-run: exit code" 1 "${rc}"
eq "supervisor appears mid-run: stderr code" "error: install-failed:" "$(stderr_head)"
eq "supervisor appears mid-run: outcome line" 1 "$(count_err '^warning: rolled-back: previous supervisor restored .*, new CLI removed from ')"
eq "supervisor appears mid-run: files" "<missing> APPEARED" "$(launcher_content) $(supervisor_content)"
eq "supervisor appears mid-run: file count" 1 "$(dest_count)"
# 最初の確認の後に最終名が symlink になったら、置換せずに止まる
new_sandbox
put_old_files
# shellcheck disable=SC2016 # hook.sh の中で展開する
write_hook 'ln -sf "${FANDHE_INSTALL_TEST_SANDBOX}/src/launcher" "${FANDHE_INSTALL_TEST_SANDBOX}/dest/fandhe-container-launcher"'
# shellcheck disable=SC2046
run_install STUB_HOOK_AT=dd:1 -- $(std_args)
eq "launcher becomes a symlink mid-run: exit code" 3 "${rc}"
eq "launcher becomes a symlink mid-run: stderr code" "error: untrusted-dest-dir:" "$(stderr_head)"
eq "launcher becomes a symlink mid-run: no rename" 0 "$(count_log '^mv ')"
eq "launcher becomes a symlink mid-run: supervisor unchanged" "OLD-SUPERVISOR" "$(supervisor_content)"
eq "launcher becomes a symlink mid-run: file count" 3 "$(dest_count)"
# rename の直前に最終名がディレクトリになっても、その中へ移動せずに失敗する（mv -T）
new_sandbox
# shellcheck disable=SC2016 # hook.sh の中で展開する
write_hook 'mkdir "${FANDHE_INSTALL_TEST_SANDBOX}/dest/fandhe-container-supervisor"'
# shellcheck disable=SC2046
run_install STUB_HOOK_AT=mv:2 -- $(std_args)
eq "supervisor becomes a directory before rename: exit code" 1 "${rc}"
eq "supervisor becomes a directory before rename: stderr code" "error: install-failed:" "$(stderr_head)"
eq "supervisor becomes a directory before rename: nothing moved into it" 0 \
  "$(find "${SB}/dest/fandhe-container-supervisor" -mindepth 1 | wc -l | tr -d ' ')"
eq "supervisor becomes a directory before rename: file count" 1 "$(dest_count)"
# 更新の途中で最終名の supervisor が消えていたら、退避ファイルを消さずにそこから戻す（唯一の写しを失わない）
new_sandbox
put_old_files
# shellcheck disable=SC2016 # hook.sh の中で展開する
write_hook 'rm -f "${FANDHE_INSTALL_TEST_SANDBOX}/dest/fandhe-container-supervisor"'
# shellcheck disable=SC2046
run_install STUB_HOOK_AT=mv:2 STUB_FAIL=mv:2 -- $(std_args)
eq "supervisor vanishes during the update: exit code" 1 "${rc}"
eq "supervisor vanishes during the update: stderr code" "error: install-failed:" "$(stderr_head)"
eq "supervisor vanishes during the update: outcome line" 1 "$(count_err '^warning: rolled-back: previous supervisor restored .*, previous CLI restored ')"
eq "supervisor vanishes during the update: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
eq "supervisor vanishes during the update: file count" 3 "$(dest_count)"

new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest/"
eq "dest-dir trailing slash: exit code" 0 "${rc}"
eq "dest-dir trailing slash: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest//"
eq "dest-dir double trailing slash: exit code" 2 "${rc}"

new_sandbox
mkfifo "${SB}/src/fifo"
run_install -- --launcher "${SB}/src/fifo" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "fifo source: exit code" 3 "${rc}"
eq "fifo source: stderr code" "error: invalid-source:" "$(stderr_head)"
# 検査（stat）の直後に入力元が書き手のいない FIFO へ差し替えられると、親シェルの open が止まる。watchdog が期限で
# 構造化エラーを出して本体を KILL する（終了コード 137）。本体が KILL されたことを知らせる bash の通知は捨てる。
new_sandbox
put_old_files
# shellcheck disable=SC2016 # hook.sh の中で展開する
write_hook 'rm -f "${FANDHE_INSTALL_TEST_SANDBOX}/src/launcher"; mkfifo "${FANDHE_INSTALL_TEST_SANDBOX}/src/launcher"'
rc=0
# shellcheck disable=SC2046
(run_install STUB_HOOK_AFTER_AT=stat:1 "FANDHE_INSTALL_TEST_TIMEOUT_SECS=${SHORT_TIMEOUT}" -- $(std_args) && exit "${rc}") 2>/dev/null || rc=$?
eq "source swapped to a fifo before open: exit code" 137 "${rc}"
eq "source swapped to a fifo before open: stderr" "error: source-open-timeout: opening source timed out" "$(cat "${SB}/err")"
eq "source swapped to a fifo before open: no mutating calls" 0 "$(count_log "${MUTATING}")"
eq "source swapped to a fifo before open: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"

# --- 6. 引数エラー・入力元・テスト入口 ---
new_sandbox
run_install --
eq "no args: exit code" 2 "${rc}"
run_install -- --bogus
eq "unknown option: exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir relative/dir
eq "relative dest-dir: exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest/../dest"
eq "dest-dir with '..': exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/de st"
eq "dest-dir with space: exit code" 2 "${rc}"
run_install -- --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "missing --launcher: exit code" 2 "${rc}"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "missing --cli: exit code" 2 "${rc}"
ln -s "${SB}/src/launcher" "${SB}/src/launcher-link"
run_install -- --launcher "${SB}/src/launcher-link" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "symlink source: exit code" 3 "${rc}"
eq "symlink source: stderr code" "error: invalid-source:" "$(stderr_head)"
ln -s "${SB}/src/cli" "${SB}/src/cli-link"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli-link" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "symlink cli source: exit code" 3 "${rc}"
eq "symlink cli source: stderr code" "error: invalid-source:" "$(stderr_head)"
mkfifo "${SB}/src/cli-fifo"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli-fifo" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "fifo cli source: exit code" 3 "${rc}"
eq "fifo cli source: stderr code" "error: invalid-source:" "$(stderr_head)"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/none" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
eq "missing cli source: exit code" 3 "${rc}"
eq "missing cli source: stderr code" "error: invalid-source:" "$(stderr_head)"
run_install -- --launcher "${SB}/src/none" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest"
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
  --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" "${HASH_ARGV[@]}" --dest-dir "${SB}/dest" >"${SB}/out" 2>"${SB}/err" || rc=$?
eq "timeout override outside the sandbox: exit code" 3 "${rc}"
eq "timeout override outside the sandbox: stderr code" "error: test-seam-refused:" "$(stderr_head)"

# --- 6b. 入力元の sha256 照合（#2137・SUP-14・PLUG-11） ---
# 不一致は属性の変更も置換もせず、終了コード 3 の source-hash-mismatch で止まる。照合は複製した一時ファイルに対して行う。
bad_hash="$(printf '0%.0s' $(seq 1 64))"
hash_mismatch_case() { # <name> <launcher|supervisor|cli> <old|fresh>
  new_sandbox
  if [ "$3" = old ]; then put_old_files; fi
  local args
  case "$2" in
    launcher) args=(--launcher-sha256 "${bad_hash}" --supervisor-sha256 "${SHA_S}" --cli-sha256 "${SHA_C}") ;;
    supervisor) args=(--launcher-sha256 "${SHA_L}" --supervisor-sha256 "${bad_hash}" --cli-sha256 "${SHA_C}") ;;
    *) args=(--launcher-sha256 "${SHA_L}" --supervisor-sha256 "${SHA_S}" --cli-sha256 "${bad_hash}") ;;
  esac
  run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" \
    "${args[@]}" --dest-dir "${SB}/dest"
  eq "hash mismatch $2 ($3): exit code" 3 "${rc}"
  eq "hash mismatch $2 ($3): stderr code" "error: source-hash-mismatch:" "$(stderr_head)"
  eq "hash mismatch $2 ($3): stderr is one line" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
  eq "hash mismatch $2 ($3): stdout empty" "" "$(cat "${SB}/out")"
  eq "hash mismatch $2 ($3): message has both values" 1 "$(count_err "expected ${bad_hash}, got [0-9a-f]{64}\)\$|expected [0-9a-f]{64}, got ${bad_hash}\)\$")"
  eq "hash mismatch $2 ($3): no attribute change or replacement" 0 "$(count_log "${ATTR_AND_REPLACE}")"
  eq "hash mismatch $2 ($3): no leftover temp files" "$([ "$3" = old ] && echo 3 || echo 0)" "$(dest_count)"
  eq "hash mismatch $2 ($3): every change ran under the lock" "" "$(cat "${SB}/unlocked.log" 2>/dev/null || true)"
  if [ "$3" = old ]; then
    eq "hash mismatch $2 (old): files unchanged" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
  fi
}
for which in launcher supervisor cli; do
  hash_mismatch_case "${which}" "${which}" old
  hash_mismatch_case "${which}" "${which}" fresh
done
# 16 進の大文字は受け付ける（正規化して照合する）。
new_sandbox
upper_l="$(printf '%s' "${SHA_L}" | tr 'a-f' 'A-F')"
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" \
  --launcher-sha256 "${upper_l}" --supervisor-sha256 "${SHA_S}" --cli-sha256 "${SHA_C}" --dest-dir "${SB}/dest"
eq "uppercase hex hash: exit code" 0 "${rc}"
eq "uppercase hex hash: files" "NEW-LAUNCHER NEW-SUPERVISOR NEW-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
# 形式の誤り（63 桁・65 桁・16 進以外・空）は終了コード 2 で、何も変えない。
for bad in "${SHA_L:0:63}" "${SHA_L}0" "${SHA_L:0:63}g" "" "sha256:${SHA_L}"; do
  run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" \
    --launcher-sha256 "${bad}" --supervisor-sha256 "${SHA_S}" --cli-sha256 "${SHA_C}" --dest-dir "${SB}/dest"
  eq "malformed hash '${bad}': exit code" 2 "${rc}"
  if [ -n "${bad}" ]; then
    eq "malformed hash '${bad}': stderr code" "error: invalid-argument:" "$(stderr_head)"
  fi
done
new_sandbox
run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" \
  --launcher-sha256 "${SHA_L:0:63}" --supervisor-sha256 "${SHA_S}" --cli-sha256 "${SHA_C}" --dest-dir "${SB}/dest"
eq "malformed hash: no mutating calls" 0 "$(count_log "${MUTATING}")"
eq "malformed hash: no lock file" none "$(lock_state)"
# どの --*-sha256 が欠けても使い方のエラー（ハッシュを省く既定は無い）。
for drop in launcher supervisor cli; do
  new_sandbox
  case "${drop}" in
    launcher) args=(--supervisor-sha256 "${SHA_S}" --cli-sha256 "${SHA_C}") ;;
    supervisor) args=(--launcher-sha256 "${SHA_L}" --cli-sha256 "${SHA_C}") ;;
    *) args=(--launcher-sha256 "${SHA_L}" --supervisor-sha256 "${SHA_S}") ;;
  esac
  run_install -- --launcher "${SB}/src/launcher" --supervisor "${SB}/src/supervisor" --cli "${SB}/src/cli" \
    "${args[@]}" --dest-dir "${SB}/dest"
  eq "missing --${drop}-sha256: exit code" 2 "${rc}"
  eq "missing --${drop}-sha256: no mutating calls" 0 "$(count_log "${MUTATING}")"
done
# 入力元を開いた後（複製の最中）に中身が書き換えられても、複製した一時ファイルを照合するので検出して旧版のまま止まる。
new_sandbox
put_old_files
# shellcheck disable=SC2016 # hook.sh の中で展開する
write_hook 'printf "EVIL\n" >"${FANDHE_INSTALL_TEST_SANDBOX}/src/launcher"'
# shellcheck disable=SC2046
run_install STUB_HOOK_AT=dd:1 -- $(std_args)
eq "source rewritten before the copy: exit code" 3 "${rc}"
eq "source rewritten before the copy: stderr code" "error: source-hash-mismatch:" "$(stderr_head)"
eq "source rewritten before the copy: no attribute change or replacement" 0 "$(count_log "${ATTR_AND_REPLACE}")"
eq "source rewritten before the copy: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
eq "source rewritten before the copy: no leftover temp files" 3 "$(dest_count)"
# sha256sum の異常（想定外の出力・失敗）は終了コード 1 の install-failed で、何も置換しない。
for mode in garbage two-lines fail; do
  new_sandbox
  put_old_files
  # shellcheck disable=SC2046
  run_install STUB_SHA256_MODE="${mode}" -- $(std_args)
  eq "sha256sum ${mode}: exit code" 1 "${rc}"
  eq "sha256sum ${mode}: stderr code" "error: install-failed:" "$(stderr_head)"
  eq "sha256sum ${mode}: no attribute change or replacement" 0 "$(count_log "${ATTR_AND_REPLACE}")"
  eq "sha256sum ${mode}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
  eq "sha256sum ${mode}: no leftover temp files" 3 "$(dest_count)"
done

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
eq "reference upgrade: rename count" 3 "$(grep -c '^mv ' "${ref_log}")"
eq "reference upgrade: backup link count" 2 "$(grep -c '^ln ' "${ref_log}")"
eq "reference upgrade: remove count" 2 "$(grep -c '^rm ' "${ref_log}")"
eq "reference upgrade: temporary name count" 5 "$(grep -c '^mktemp ' "${ref_log}")"
eq "reference upgrade: setcap count (launcher only)" 1 "$(grep -c '^setcap ' "${ref_log}")"
eq "reference upgrade: every change ran under the lock" "" "$(cat "${SB}/unlocked.log" 2>/dev/null || true)"
eq "reference upgrade: stubbed commands seen" "chmod chown dd flock getcap ln mktemp mv rm setcap sha256sum stat" \
  "$(cut -d' ' -f1 "${ref_log}" | sort -u | paste -sd' ' -)"
ref_specs=()
while IFS= read -r spec; do ref_specs+=("${spec}"); done < <(awk '{c[$1]++; print $1 ":" c[$1]}' "${ref_log}")
ref_mv1="$(grep -n '^mv ' "${ref_log}" | sed -n 1p | cut -d: -f1)"
ref_mv2="$(grep -n '^mv ' "${ref_log}" | sed -n 2p | cut -d: -f1)"
ref_mv3="$(grep -n '^mv ' "${ref_log}" | sed -n 3p | cut -d: -f1)"
ref_rm1="$(grep -n '^rm ' "${ref_log}" | sed -n 1p | cut -d: -f1)"
ref_rm2="$(grep -n '^rm ' "${ref_log}" | sed -n 2p | cut -d: -f1)"
# launcher の rename の直後に走る stat（後始末での inode の読み戻し）が何回目の stat か。
ref_stat_after_mv3="$(($(head -n "${ref_mv3}" "${ref_log}" | grep -c '^stat ') + 1))"
echo "INFO: reference upgrade makes ${#ref_specs[@]} bounded calls (mv at ${ref_mv1}, ${ref_mv2} and ${ref_mv3}, backup rm at ${ref_rm1} and ${ref_rm2})"

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
# mv の番号: 1 = CLI の rename・2 = supervisor の rename・3 = launcher の rename。launcher の失敗の後の復元は、
# supervisor（mv:4）→ CLI（mv:5）の順。
extra_case restore-timeout old "STUB_FAIL=mv:3" "STUB_HANG=mv:4"
extra_case restore-failure old "STUB_FAIL=mv:3 mv:4"
extra_case cli-restore-failure old "STUB_FAIL=mv:3 mv:5"
extra_case supervisor-rename-failure old "STUB_FAIL=mv:2"
extra_case cli-rename-failure old "STUB_FAIL=mv:1"
extra_case indeterminate old "STUB_HANG=mv:3 stat:${ref_stat_after_mv3}"
extra_case cli-renamed-then-hang old "STUB_HANG_AFTER=mv:1"
extra_case supervisor-renamed-then-hang old "STUB_HANG_AFTER=mv:2"
extra_case launcher-renamed-then-hang old "STUB_HANG_AFTER=mv:3"
extra_case cleanup-timeout-after-failure old STUB_SETCAP_MODE=eperm "STUB_HANG=rm:1"
extra_case fresh-launcher-rename-timeout fresh "STUB_HANG=mv:3"
extra_case fresh-restore-timeout fresh "STUB_FAIL=mv:3" "STUB_HANG=rm:1"
# 新規インストールでは退避ファイルの読み戻し（stat 2 回）が無いので、同じ stat は 2 つ前の番号になる。
extra_case fresh-indeterminate fresh "STUB_HANG=mv:3 stat:$((ref_stat_after_mv3 - 2))"
wait

i=0
for spec in "${ref_specs[@]}"; do
  SB="${matrix_sb[${i}]}"
  i=$((i + 1))
  name="hang ${spec} (call ${i})"
  check_bounded_case "${name}" "hang ${spec}"
  if [ "${i}" -eq "${ref_rm1}" ] || [ "${i}" -eq "${ref_rm2}" ]; then
    # 置換が済んだ後の退避ファイルの削除だけが止まった: 導入は成功で、消せなかった退避ファイルを警告する。
    # rm の 1 回目は旧 supervisor の退避・2 回目は旧 CLI の退避。
    eq "${name}: exit code" 0 "${rc}"
    eq "${name}: stdout" "installed: method=file-capability dest-dir=${SB}/dest" "$(cat "${SB}/out")"
    eq "${name}: stderr" "warning: cleanup-incomplete:" "$(stderr_head)"
    eq "${name}: stderr is the warning only" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "NEW-LAUNCHER NEW-SUPERVISOR NEW-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
    if [ "${i}" -eq "${ref_rm1}" ]; then
      eq "${name}: backups kept" "OLD-SUPERVISOR <missing>" "$(backup_content) $(cli_backup_content)"
    else
      eq "${name}: backups kept" "<missing> OLD-CLI" "$(backup_content) $(cli_backup_content)"
    fi
    eq "${name}: file count" 4 "$(dest_count)"
    continue
  fi
  eq "${name}: exit code" 1 "${rc}"
  eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
  eq "${name}: stdout empty" "" "$(cat "${SB}/out")"
  eq "${name}: file count" 3 "$(dest_count)"
  if [ "${i}" -lt "${ref_mv1}" ]; then
    # 置換の前: 何も置き換わっていない。結果の行は要らない。
    eq "${name}: state in the message" 1 "$(head -n1 "${SB}/err" | grep -c 'no installed file was replaced')"
    eq "${name}: stderr is one line" 1 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
  elif [ "${i}" -le "${ref_mv3}" ]; then
    # CLI の rename から launcher の rename まで: 旧 supervisor・旧 CLI へ戻り、その結果を 1 行で示す。
    eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: ')"
    eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
  else
    # 3 つとも置換した後の読み戻し: 新しい組で揃っていて、検証が終わっていないことを示す。
    eq "${name}: state in the message" 1 "$(head -n1 "${SB}/err" | grep -c 'all files are already replaced')"
    eq "${name}: outcome line" 1 "$(count_err '^warning: replaced-unverified: ')"
    eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
    eq "${name}: files" "NEW-LAUNCHER NEW-SUPERVISOR NEW-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
  fi
done

i=0
for name in "${extra_names[@]}"; do
  SB="${extra_sb[${i}]}"
  i=$((i + 1))
  bak="$(find "${SB}/dest" -name '.supervisor.bak.*' | head -n1)"
  clibak="$(find "${SB}/dest" -name '.cli.bak.*' | head -n1)"
  case "${name}" in
    restore-timeout | restore-failure)
      # launcher の rename が失敗し、旧 supervisor への復元も失敗（期限超過 / エラー）: supervisor の退避ファイルを残して
      # 場所を示す。CLI は復元できる（復元は supervisor → CLI の順で、片方の失敗で他方を止めない）。
      if [ "${name}" = restore-timeout ]; then
        check_bounded_case "${name}" "fail mv:3 hang mv:4"
      else
        check_bounded_case "${name}" "fail mv:3 fail mv:4"
      fi
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: restore-failed line" \
        "error: restore-failed: could not restore the previous supervisor (exit code $([ "${name}" = restore-timeout ] && echo TIMEOUT || echo 1)); it is kept at ${bak} and ${SB}/dest/fandhe-container-supervisor is the new one; restore with: mv -f -T -- ${bak} ${SB}/dest/fandhe-container-supervisor" \
        "$(err_line 2)"
      eq "${name}: cli restored line" 1 "$(count_err '^warning: rolled-back: previous CLI restored at .*; see the restore-failed error above ')"
      eq "${name}: stderr is three lines" 3 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: files" "OLD-LAUNCHER NEW-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: backup kept" "OLD-SUPERVISOR <missing>" "$(backup_content) $(cli_backup_content)"
      eq "${name}: file count" 4 "$(dest_count)"
      ;;
    cli-restore-failure)
      # supervisor は戻せたが CLI を戻せない: CLI の退避ファイルを残して場所を示す。
      check_bounded_case "${name}" "fail mv:3 fail mv:5"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: restore-failed line" \
        "error: restore-failed: could not restore the previous CLI (exit code 1); it is kept at ${clibak} and ${SB}/dest/fandhe-container is the new one; restore with: mv -f -T -- ${clibak} ${SB}/dest/fandhe-container" \
        "$(err_line 2)"
      eq "${name}: supervisor restored line" 1 "$(count_err '^warning: rolled-back: previous supervisor restored at .*; see the restore-failed error above ')"
      eq "${name}: stderr is three lines" 3 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR NEW-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: backup kept" "<missing> OLD-CLI" "$(backup_content) $(cli_backup_content)"
      eq "${name}: file count" 4 "$(dest_count)"
      ;;
    supervisor-rename-failure)
      # supervisor の rename が失敗: 置換済みの CLI だけを旧 CLI へ戻す（supervisor は旧のまま）。
      check_bounded_case "${name}" "fail mv:2"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: the previous supervisor is still in place at .*, previous CLI restored at .*; no installed file is replaced$')"
      eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    cli-rename-failure)
      # CLI の rename が失敗: 何も置換されていない（supervisor・launcher の rename には進まない）。
      check_bounded_case "${name}" "fail mv:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: the previous CLI is still in place at ')"
      eq "${name}: no further rename" 1 "$(grep -c '^mv ' "${SB}/calls.log")"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    indeterminate)
      # launcher の rename が期限超過し、置換の有無の読み戻しも期限超過: 何も動かさず 2 つの退避ファイルを残す。
      check_bounded_case "${name}" "hang mv:3 hang stat:${ref_stat_after_mv3}"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: state-indeterminate line" 1 \
        "$(sed -n 2p "${SB}/err" | grep -c -F "the previous supervisor is kept at ${bak}; the previous CLI is kept at ${clibak}; if the launcher was not replaced, restore with: mv -f -T -- ${bak} ${SB}/dest/fandhe-container-supervisor && mv -f -T -- ${clibak} ${SB}/dest/fandhe-container; otherwise remove ${bak} ${clibak}; or rerun the installer")"
      eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: backups kept" "OLD-SUPERVISOR OLD-CLI" "$(backup_content) $(cli_backup_content)"
      eq "${name}: supervisor and cli not moved" "NEW-SUPERVISOR NEW-CLI" "$(supervisor_content) $(cli_content)"
      eq "${name}: file count" 5 "$(dest_count)"
      ;;
    cli-renamed-then-hang)
      # CLI の rename は効いたが応答が返らない: inode の読み戻しで置換済みと分かり、旧 CLI へ戻す。
      check_bounded_case "${name}" "hang-after mv:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: previous CLI restored ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    supervisor-renamed-then-hang)
      # supervisor の rename は効いたが応答が返らない: 置換済みの supervisor・CLI を旧ファイルへ戻す。
      check_bounded_case "${name}" "hang-after mv:2"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: previous supervisor restored .*, previous CLI restored ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    launcher-renamed-then-hang)
      # launcher の rename は効いたが応答が返らない: 新しい組で揃っているので戻さない。
      check_bounded_case "${name}" "hang-after mv:3"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: replaced-unverified: ')"
      eq "${name}: no rollback" 0 "$(count_err '^warning: rolled-back: ')"
      eq "${name}: files" "NEW-LAUNCHER NEW-SUPERVISOR NEW-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 3 "$(dest_count)"
      ;;
    cleanup-timeout-after-failure)
      # 置換の前に失敗し、一時ファイルの削除だけが期限超過: 原因は 1 行目、消せなかったファイルは警告で示す。
      check_bounded_case "${name}" "hang rm:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: setcap-failed:" "$(stderr_head)"
      eq "${name}: cleanup-incomplete line" 1 \
        "$(err_line 2 | grep -c "^warning: cleanup-incomplete: could not remove the temporary file ${SB}/dest/.launcher.[A-Za-z0-9]* (exit code TIMEOUT); ")"
      eq "${name}: stderr is two lines" 2 "$(wc -l <"${SB}/err" | tr -d ' ')"
      eq "${name}: files" "OLD-LAUNCHER OLD-SUPERVISOR OLD-CLI" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 4 "$(dest_count)"
      ;;
    fresh-launcher-rename-timeout)
      check_bounded_case "${name}" "hang mv:3"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: outcome line" 1 "$(count_err '^warning: rolled-back: new supervisor removed from .*, new CLI removed from .*; nothing is installed$')"
      eq "${name}: nothing installed" 0 "$(dest_count)"
      ;;
    fresh-restore-timeout)
      check_bounded_case "${name}" "fail mv:3 hang rm:1"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: install-failed:" "$(stderr_head)"
      eq "${name}: restore-failed line" \
        "error: restore-failed: could not remove the new supervisor at ${SB}/dest/fandhe-container-supervisor (exit code TIMEOUT); there was no previous one, remove it manually" \
        "$(err_line 2)"
      eq "${name}: cli removed line" 1 "$(count_err '^warning: rolled-back: new CLI removed from .*; see the restore-failed error above ')"
      eq "${name}: files" "<missing> NEW-SUPERVISOR <missing>" "$(launcher_content) $(supervisor_content) $(cli_content)"
      eq "${name}: file count" 1 "$(dest_count)"
      ;;
    fresh-indeterminate)
      check_bounded_case "${name}" "hang mv:3 hang stat:$((ref_stat_after_mv3 - 2))"
      eq "${name}: exit code" 1 "${rc}"
      eq "${name}: stderr code" "error: operation-timeout:" "$(stderr_head)"
      eq "${name}: state-indeterminate line" 1 \
        "$(sed -n 2p "${SB}/err" | grep -c -F "there was no previous supervisor; there was no previous CLI; if the launcher was not replaced, restore with: rm -f -- ${SB}/dest/fandhe-container-supervisor && rm -f -- ${SB}/dest/fandhe-container; or rerun the installer")"
      eq "${name}: supervisor and cli not moved" "NEW-SUPERVISOR NEW-CLI" "$(supervisor_content) $(cli_content)"
      eq "${name}: file count" 2 "$(dest_count)"
      ;;
    *) fail "unknown extra case ${name}" ;;
  esac
done

# 全ケースを通して、期限なしで呼ばれたスタブ・ロックを持たずに行われた変更が 1 件も無いこと。
eq "no stub ran outside timeout in any case" 0 "$(find "${root_tmp}" -name unbounded.log | wc -l | tr -d ' ')"
eq "no change ran outside the lock in any case" 0 "$(find "${root_tmp}" -name unlocked.log | wc -l | tr -d ' ')"

# --- 9. 期限: 本文の静的検査（REPAIR-5） ---
# コメント行と行末コメントを除いた本文を対象にする。
code="$(grep -v '^[[:space:]]*#' "${target}" | sed -E 's/[[:space:]]+#[[:space:]].*$//')"
# 配置先・入力元に触る外部コマンドがコマンド位置（行頭・`;` `&` `|` `(` `{` `!` の直後・then / do / else・command / exec /
# env / eval / xargs の後）に現れないこと。期限つきの経路（run_child・bounded・step）の引数としてだけ現れる。
fs_cmds='(stat|mkdir|flock|mktemp|dd|sha256sum|shasum|b2sum|md5sum|cp|cat|tee|install|chown|chmod|setcap|getcap|ln|mv|rm|rmdir|touch|readlink|realpath|ls|find|test)'
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
# 親シェルが開くファイルは入力元とロックファイルの 2 か所（どちらも watchdog つきの open）だけ。/dev/null と fd の複製
# （<& >&）は対象外。
opens="$(printf '%s\n' "${code}" | sed 's#/dev/null##g' | grep -E '[<>][[:space:]]*"?(\$|/)' || true)"
eq "static: the parent shell opens two files" 2 "$(printf '%s\n' "${opens}" | grep -c .)"
# shellcheck disable=SC2016 # インストーラ本文の文字列をそのまま探す
eq "static: one open is the source" 1 "$(printf '%s\n' "${opens}" | grep -c -F 'exec {fd}<"${path}"')"
# shellcheck disable=SC2016 # インストーラ本文の文字列をそのまま探す
eq "static: one open is the installation lock" 1 "$(printf '%s\n' "${opens}" | grep -c -F 'exec {LOCK_FD}>>"${LOCK_PATH}"')"
# 親シェルの open は、どちらも watchdog の開始と停止の間にある。
eq "static: both opens are guarded by the watchdog" 2 \
  "$(printf '%s\n' "${code}" | grep -B1 -E '^[[:space:]]*\{ exec \{(fd|LOCK_FD)\}' | grep -c -E '^[[:space:]]*start_watchdog ')"

if [ "${failures}" -ne 0 ]; then
  echo "FAIL: ${failures} check(s) failed" >&2
  exit 1
fi
echo "OK: all install-privileged-launcher checks passed"
