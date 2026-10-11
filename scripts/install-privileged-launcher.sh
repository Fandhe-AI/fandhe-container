#!/usr/bin/env bash
# 特権ランチャー（fandhe-container-launcher）と supervisor を固定の配置先へ置き、ランチャーにだけ file capability
# を付与するインストールスクリプト（TASK-171 追補・#1721・SUP-14・SEC-1・PLUG-11・CORE-6）。
#
# 役割: #1454 の決定（2026-10-10）に従い、権限の付与は CLI ではなくこのスクリプト（またはパッケージの postinst）が
#   root で行う。CLI は特権を持たず、`setup` は本スクリプトの手順を表示するだけ（#1722）。ランチャー側の実行時検証
#   （crates/supervisor/src/launcher.rs の verify_install_chain 等）が前提とする「root 所有・g/o 書き込み不可の
#   配置先」を、ここで作って検証する。
# 呼び出し元: 人間が root で直接 / パッケージの postinst（`--dest-dir` で配置先を渡す） / `make install-launcher-selftest`
#   （スタブのみの自己テスト。root 不要）。root での実機実行と検証は人間担当（#538・#539）。本スクリプトの中で sudo は呼ばない。
# 使い方: install-privileged-launcher.sh --launcher <file> --supervisor <file> [--dest-dir <絶対パス>]
#   既定の配置先は /usr/local/libexec/fandhe-container。入力元は必須（root が作業ツリーの暗黙の既定パスを拾わないため）。
# 終了コード: 0 成功 / 1 インストール操作の失敗 / 2 引数エラー / 3 前提不成立（root でない・Linux でない・配置先が
#   信頼条件を満たさない・入力元が不正）。失敗は stderr に英語 1 行 `error: <code>: <message>`、成功は stdout に 1 行
#   `installed: method=file-capability|setuid dest-dir=<path>`（setuid のときは stderr に `warning: setuid-fallback`）。
# 付与する capability: crates/supervisor/src/privilege.rs の RUNTIME_REQUIRED_CAPABILITIES（7 件）に、`elevate` の契約
#   （方式 (c) は補助グループを持つ利用者向けに CAP_SETGID を effective で要る）に従って cap_setgid を足した 8 件を +ep で
#   付ける。縮退後の保持集合は最小の 7 件ちょうどに戻る（必要最小集合は広がらない）。自己テストが privilege.rs の集合との
#   ドリフトを検出する。
# fail-closed: setuid root への切り替えは「setcap が非 0 かつ stderr が `not supported`（ENOTSUP/EOPNOTSUPP。xattr 非対応）」
#   のときだけ。EPERM・EINVAL・setcap 未導入・読み戻し不一致では切り替えず止まる（権限の多い方式へ黙って降格しない）。
#   配置先は祖先を含む全要素が root 所有・g/o 書き込み不可でなければ、補修も上書きもせず止まる。置換は同一ディレクトリの
#   一時ファイルで検証を済ませてから rename する。入力元は 1 回だけ読んで複製し、以降は複製に対して操作する。
# 既知の未実装（実装済みを装わない）: 入力元のハッシュ・署名の照合は行わない（PLUG-11 との整合は設計書 12 章の未確認事項）。
#   nosuid マウント上の配置先では file capability / setuid が効かない（ランチャーが実行時に fail-closed で拒否する）。
# 注意: scripts/lib.sh は source しない（cwd がリポジトリルートへ移り、postinst からの相対パス解釈が変わるため）。
#   環境変数 FANDHE_INSTALL_TEST_SANDBOX は自己テスト専用の入口で、EUID が 0 のときは拒否する。

set -euo pipefail

DEFAULT_DEST_DIR="/usr/local/libexec/fandhe-container"
LAUNCHER_NAME="fandhe-container-launcher"
SUPERVISOR_NAME="fandhe-container-supervisor"
LAUNCHER_CAPS="cap_sys_admin,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_kill,cap_setgid+ep"

TMP_LAUNCHER=""
TMP_SUPERVISOR=""
cleanup() {
  [ -z "${TMP_LAUNCHER}" ] || rm -f -- "${TMP_LAUNCHER}"
  [ -z "${TMP_SUPERVISOR}" ] || rm -f -- "${TMP_SUPERVISOR}"
}
trap cleanup EXIT

# 構造化エラーを 1 行出して終了する。
die() { # <exit-code> <code> <message>
  printf 'error: %s: %s\n' "$2" "$3" >&2
  exit "$1"
}

usage() {
  echo "usage: $0 --launcher <file> --supervisor <file> [--dest-dir <absolute-dir>]" >&2
  exit 2
}

LAUNCHER_SRC=""
SUPERVISOR_SRC=""
DEST_DIR="${DEFAULT_DEST_DIR}"
while [ $# -gt 0 ]; do
  case "$1" in
    --launcher) [ $# -ge 2 ] || usage; LAUNCHER_SRC="$2"; shift 2 ;;
    --supervisor) [ $# -ge 2 ] || usage; SUPERVISOR_SRC="$2"; shift 2 ;;
    --dest-dir) [ $# -ge 2 ] || usage; DEST_DIR="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "${LAUNCHER_SRC}" ] && [ -n "${SUPERVISOR_SRC}" ] || usage

# --dest-dir は許可リスト方式で検証する（空白・改行・glob・.. を拒否）。
dest_ok=1
[ "${#DEST_DIR}" -le 4096 ] || dest_ok=0
[[ "${DEST_DIR}" =~ ^/[A-Za-z0-9._+/-]+$ ]] || dest_ok=0
case "${DEST_DIR}/" in
  *//*) dest_ok=0 ;;
esac
case "${DEST_DIR}/" in
  */../* | */./*) dest_ok=0 ;;
esac
if [ "${dest_ok}" -ne 1 ]; then
  echo "error: invalid-argument: --dest-dir must be a normalized absolute path" >&2
  exit 2
fi
DEST_DIR="${DEST_DIR%/}"

[ "$(uname -s)" = "Linux" ] || die 3 unsupported-os "this installer supports Linux only"

# 環境の固定。テスト入口は EUID が 0 のとき拒否する（本物の root ではスタブへ差し替えられない）。
SANDBOX="${FANDHE_INSTALL_TEST_SANDBOX:-}"
if [ -n "${SANDBOX}" ]; then
  [ "${EUID}" -ne 0 ] || die 3 test-seam-refused "test sandbox is not allowed for a real root"
  case "${SANDBOX}" in /*) ;; *) die 3 test-seam-refused "sandbox must be absolute" ;; esac
  PATH="${SANDBOX}/stubs:/usr/bin:/bin"
  TRUSTED_UID="${EUID}"
  CALLER_UID="$(id -u)"
  case "${DEST_DIR}/" in
    "${SANDBOX}"/*) ;;
    *) die 3 untrusted-dest-dir "dest-dir must be inside the test sandbox" ;;
  esac
else
  PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  TRUSTED_UID=0
  CALLER_UID="${EUID}"
fi
export PATH
export LC_ALL=C

[ "${CALLER_UID}" = "0" ] || die 3 not-root "must be run as root"

# 入力元の検査（通常ファイルで symlink でない）。
for src in "${LAUNCHER_SRC}" "${SUPERVISOR_SRC}"; do
  if [ -L "${src}" ] || [ ! -f "${src}" ] || [ ! -r "${src}" ]; then
    die 3 invalid-source "source must be a readable regular file and not a symlink"
  fi
done

# 配置先の 1 要素が信頼条件（ディレクトリ・非 symlink・信頼する所有者・g/o 書き込み不可）を満たすか確かめる。
check_dir() { # <path>
  local p="$1" info uid mode
  if [ -L "${p}" ] || [ ! -d "${p}" ]; then
    die 3 untrusted-dest-dir "not a plain directory: ${p}"
  fi
  info="$(stat -c '%u %a' -- "${p}")"
  uid="${info%% *}"
  mode="${info##* }"
  [ "${uid}" = "${TRUSTED_UID}" ] || die 3 untrusted-dest-dir "not owned by the trusted owner: ${p}"
  [ $(( 8#${mode} & 8#022 )) -eq 0 ] || die 3 untrusted-dest-dir "group/other writable: ${p}"
}

# 根（テスト時は sandbox）から配置先まで検査する。存在しない要素は、既存の祖先がすべて通った後に限り作る。
if [ -n "${SANDBOX}" ]; then
  cur="${SANDBOX%/}"
  rest="${DEST_DIR#"${cur}"/}"
  check_dir "${cur}"
else
  cur=""
  rest="${DEST_DIR#/}"
  check_dir "/"
fi
old_ifs="${IFS}"
IFS='/'
# shellcheck disable=SC2086 # 要素分割が目的（文字種は上で許可リスト検証済み）
set -f
for comp in ${rest}; do
  cur="${cur}/${comp}"
  if [ -e "${cur}" ] || [ -L "${cur}" ]; then
    check_dir "${cur}"
  else
    (umask 022 && mkdir -- "${cur}") || die 1 install-failed "cannot create ${cur}"
    check_dir "${cur}"
  fi
done
set +f
IFS="${old_ifs}"

LAUNCHER_DST="${DEST_DIR}/${LAUNCHER_NAME}"
SUPERVISOR_DST="${DEST_DIR}/${SUPERVISOR_NAME}"
for dst in "${LAUNCHER_DST}" "${SUPERVISOR_DST}"; do
  if [ -e "${dst}" ] || [ -L "${dst}" ]; then
    if [ -L "${dst}" ] || [ ! -f "${dst}" ]; then
      die 3 untrusted-dest-dir "existing destination is not a regular file: ${dst}"
    fi
  fi
done

# libcap の getcap 出力（新旧書式）から、パスより後ろの能力名リスト（ソート済み）とフラグを取り出す。
sorted_caps() { # <カンマ区切り>
  printf '%s\n' "${1//,/$'\n'}" | sort | paste -sd, -
}
# getcap の読み戻し。$1 のファイルの付与状態を `<sorted names>|<flags>` として大域変数 CAPS_READ へ入れる（無ければ空）。
# コマンド置換のサブシェルでは die が親を止めないため、結果は変数で返し getcap 失敗でも必ず親で止める。
CAPS_READ=""
read_caps() { # <file>
  local out rest names flags
  CAPS_READ=""
  out="$(getcap "$1")" || die 1 capability-mismatch "getcap failed for $1"
  [ -n "${out}" ] || return 0
  rest="${out#"$1"}"
  flags="${rest##*[=+]}"
  names="${rest%[=+]*}"
  names="${names//[ =]/}"
  CAPS_READ="$(sorted_caps "${names}")|${flags// /}"
}
expect_no_caps() { # <file>
  read_caps "$1"
  [ -z "${CAPS_READ}" ] || die 1 capability-mismatch "unexpected capabilities on $1"
}
expect_launcher_caps() { # <file>
  local want
  want="$(sorted_caps "${LAUNCHER_CAPS%+ep}")|ep"
  read_caps "$1"
  [ "${CAPS_READ}" = "${want}" ] || die 1 capability-mismatch "capabilities read back do not match on $1"
}
# 所有者と権限ビットの読み戻し。gid は信頼する所有者が root のとき（本番）のみ照合する。
expect_stat() { # <file> <mode>
  local info
  info="$(stat -c '%u %g %a' -- "$1")"
  [ "${info%% *}" = "${TRUSTED_UID}" ] || die 1 install-failed "owner mismatch on $1"
  [ "${info##* }" = "$2" ] || die 1 install-failed "mode mismatch on $1"
  if [ "${TRUSTED_UID}" = "0" ]; then
    local rest="${info#* }"
    [ "${rest%% *}" = "0" ] || die 1 install-failed "group mismatch on $1"
  fi
}

# 一時ファイルへ複製して属性を整える（chown を先、setcap / chmod を後にして属性消失を避ける）。
TMP_LAUNCHER="$(mktemp "${DEST_DIR}/.launcher.XXXXXX")" || die 1 install-failed "mktemp failed"
TMP_SUPERVISOR="$(mktemp "${DEST_DIR}/.supervisor.XXXXXX")" || die 1 install-failed "mktemp failed"
cat <"${LAUNCHER_SRC}" >"${TMP_LAUNCHER}" || die 1 install-failed "copy failed"
cat <"${SUPERVISOR_SRC}" >"${TMP_SUPERVISOR}" || die 1 install-failed "copy failed"
chown root:root "${TMP_LAUNCHER}" || die 1 install-failed "chown failed"
chmod 0755 "${TMP_LAUNCHER}" || die 1 install-failed "chmod failed"
chown root:root "${TMP_SUPERVISOR}" || die 1 install-failed "chown failed"
chmod 0755 "${TMP_SUPERVISOR}" || die 1 install-failed "chmod failed"

# setcap の失敗が xattr 非対応（ENOTSUP/EOPNOTSUPP）か判定する。
is_xattr_unsupported() { # <setcap の終了コード> <stderr>
  local lowered
  [ "$1" -ne 0 ] || return 1
  lowered="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  case "${lowered}" in
    *"not supported"*) return 0 ;;
    *) return 1 ;;
  esac
}

METHOD="file-capability"
rc=0
if command -v timeout >/dev/null 2>&1; then
  err="$(timeout 30 setcap "${LAUNCHER_CAPS}" "${TMP_LAUNCHER}" 2>&1 >/dev/null)" || rc=$?
else
  err="$(setcap "${LAUNCHER_CAPS}" "${TMP_LAUNCHER}" 2>&1 >/dev/null)" || rc=$?
fi
if [ "${rc}" -eq 0 ]; then
  expect_launcher_caps "${TMP_LAUNCHER}"
elif is_xattr_unsupported "${rc}" "${err}"; then
  METHOD="setuid"
  chown root:root "${TMP_LAUNCHER}" || die 1 install-failed "chown failed"
  chmod 4755 "${TMP_LAUNCHER}" || die 1 install-failed "chmod failed"
  expect_stat "${TMP_LAUNCHER}" 4755
  expect_no_caps "${TMP_LAUNCHER}"
  echo "warning: setuid-fallback: file capabilities are not supported here, installed setuid root instead" >&2
else
  die 1 setcap-failed "setcap failed with exit code ${rc}"
fi
expect_no_caps "${TMP_SUPERVISOR}"
expect_stat "${TMP_SUPERVISOR}" 755

# 失敗しうる処理がすべて成功してから最終名へ置換する（rename は xattr を保つ）。
mv -f -- "${TMP_SUPERVISOR}" "${SUPERVISOR_DST}" || die 1 install-failed "rename failed"
TMP_SUPERVISOR=""
mv -f -- "${TMP_LAUNCHER}" "${LAUNCHER_DST}" || die 1 install-failed "rename failed"
TMP_LAUNCHER=""

expect_no_caps "${SUPERVISOR_DST}"
expect_stat "${SUPERVISOR_DST}" 755
if [ "${METHOD}" = "setuid" ]; then
  expect_stat "${LAUNCHER_DST}" 4755
  expect_no_caps "${LAUNCHER_DST}"
else
  expect_stat "${LAUNCHER_DST}" 755
  expect_launcher_caps "${LAUNCHER_DST}"
fi
printf 'installed: method=%s dest-dir=%s\n' "${METHOD}" "${DEST_DIR}"
