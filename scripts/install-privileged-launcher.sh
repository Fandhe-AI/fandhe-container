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
# 終了コード: 0 成功 / 1 インストール操作の失敗（期限超過を含む） / 2 引数エラー / 3 前提不成立（root でない・Linux でない・
#   配置先が信頼条件を満たさない・入力元が不正） / 129・130・143 HUP・INT・TERM による中断。
# 出力: 成功は stdout に 1 行 `installed: method=file-capability|setuid dest-dir=<path>`。失敗は stderr の 1 行目に原因
#   `error: <code>: <message>`（英語）。更新の途中で止まったときと後始末が残ったときだけ、結果を示す行が続く
#   （どれも `error|warning: <code>: <message>` の 1 行）:
#     warning: rolled-back        旧 supervisor へ戻した（新規インストールなら新 supervisor を消した。rename の前なら何もしていない）。
#                                 置換済みのファイルは無い
#     error: restore-failed       旧 supervisor へ戻せなかった。退避ファイルを残し、場所と復元コマンドを示す
#     error: state-indeterminate  launcher の置換が起きたか確かめられなかった。退避ファイルを残し、確かめ方を示す
#     warning: replaced-unverified 2 つとも置換済みだが最後の読み戻しを終えていない（再実行で検証できる）
#     warning: cleanup-incomplete 一時ファイル・退避ファイルを消せなかった（置換の成否には影響しない。成功時は終了コード 0 のまま）
#   setuid へ切り替えたときは成功でも `warning: setuid-fallback` が出る。
# 付与する capability: crates/supervisor/src/privilege.rs の RUNTIME_REQUIRED_CAPABILITIES（7 件）に、`elevate` の契約
#   （方式 (c) は補助グループを持つ利用者向けに CAP_SETGID を effective で要る）に従って cap_setgid を足した 8 件を +ep で
#   付ける。縮退後の保持集合は最小の 7 件ちょうどに戻る（必要最小集合は広がらない）。自己テストが privilege.rs の集合との
#   ドリフトを検出する。
# fail-closed: setuid root への切り替えは「setcap が非 0 かつ stderr が `not supported`（ENOTSUP/EOPNOTSUPP。xattr 非対応）」
#   のときだけ。EPERM・EINVAL・setcap 未導入・読み戻し不一致では切り替えず止まる（権限の多い方式へ黙って降格しない）。
#   getcap は終了コード 0 のまま stderr に診断を出すことがあるため（libcap の do_getcap）、終了コードだけで成否を決めない。
#   出力が空なら capability なし、`<file> <caps>` の 1 行なら付与あり、それ以外は失敗として止まる。例外は setuid へ切り替えた
#   後だけで、診断の文言が `not supported` を含むとき（2021-09 より前の libcap は ENOTSUP を stderr へ出す）に限り
#   capability なしとして扱う。この例外は setuid への切り替え条件（setcap の結果）を広げない。
#   配置先は祖先を含む全要素が root 所有・g/o 書き込み不可でなければ、補修も上書きもせず止まる。置換は同一ディレクトリの
#   一時ファイルで検証を済ませてから rename する。入力元は 1 回だけ開いた fd を検査して同じ fd から複製し、以降は複製に対して操作する。
# 期限（REPAIR-5）: 配置先・入力元に触る外部コマンド（stat・mkdir・mktemp・dd・chown・chmod・setcap・getcap・ln・mv・rm）は
#   例外なく run_child（timeout(1)。期限 30 秒・超過後 5 秒で KILL）を通す。timeout が無ければ実行前に拒否する。親シェルは
#   ファイル検査（[ -e ] 等）も配置先へのリダイレクトも行わない（NFS / FUSE の停止で無期限に待つため）。唯一の例外は入力元の
#   open で、watchdog が同じ期限で打ち切る（`error: source-open-timeout` を出して本体を KILL する。終了コード 137。この時点では
#   何も作っていない）。それ以外の期限超過は `error: operation-timeout` で終了コード 1。超過した操作は「実行されたか不明」
#   として扱い、置換の成否は inode の読み戻しで確かめてから復元する（確かめられなければ state-indeterminate）。
#   後始末と復元の間は INT・HUP・TERM を無視して完遂を優先する（各操作に期限があるので有限時間で終わる。子は TERM を無視した
#   まま起動されるので、後始末中の期限超過は KILL までの猶予を含めて最大 35 秒）。期限超過 1 回のあとの後始末は最大 5 操作。
# 既知の未実装（実装済みを装わない）: 入力元のハッシュ・署名の照合は行わない（PLUG-11 との整合は設計書 12 章の未確認事項）。
#   nosuid マウント上の配置先では file capability / setuid が効かない（ランチャーが実行時に fail-closed で拒否する）。
#   SIGKILL でも終わらない子（割り込めない I/O 待ち）は timeout(1) が回収を待ち続けるため、期限では打ち切れない。
# 注意: scripts/lib.sh は source しない（cwd がリポジトリルートへ移り、postinst からの相対パス解釈が変わるため）。
#   環境変数 FANDHE_INSTALL_TEST_SANDBOX・FANDHE_INSTALL_TEST_TIMEOUT_SECS は自己テスト専用の入口で、前者は EUID が 0 の
#   とき、後者は前者なしで設定されたときに拒否する（本番の期限は環境変数で変えられない）。

set -euo pipefail

DEFAULT_DEST_DIR="/usr/local/libexec/fandhe-container"
LAUNCHER_NAME="fandhe-container-launcher"
SUPERVISOR_NAME="fandhe-container-supervisor"
LAUNCHER_CAPS="cap_sys_admin,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_kill,cap_setgid+ep"

# 子プロセス 1 つあたりの期限（秒）と、期限超過後に KILL するまでの猶予（秒）。
CHILD_TIMEOUT=30
KILL_GRACE=5

DEST_DIR=""
LAUNCHER_DST=""
SUPERVISOR_DST=""
TMP_LAUNCHER=""
TMP_SUPERVISOR=""
BAK_SUPERVISOR=""
# 置換前に読んだ一時ファイルの inode（dev:inode）。期限超過・中断のあと、最終名が新しい実体かどうかの判定に使う。
NEW_LAUNCHER_ID=""
NEW_SUPERVISOR_ID=""
# 進行段階。rename の前に「置換中」へ進めておき、rename が起きたか不明な間は起きた可能性があるものとして後始末する。
#   precheck → staged（一時ファイル作成以降。置換済みのファイルは無い） → supervisor-replacing → mid-update（supervisor
#   だけ置換済み） → launcher-replacing → committed（2 つとも置換済み）
PHASE="precheck"
# 1 のとき退避ファイル（旧 supervisor）を消さずに残す（復元に失敗した・状態を確かめられなかった）。
KEEP_BACKUP=0

# 構造化エラーを 1 行出して終了する。
die() { # <exit-code> <code> <message>
  printf 'error: %s: %s\n' "$2" "$3" >&2
  exit "$1"
}
warn() { # <code> <message>
  printf 'warning: %s: %s\n' "$1" "$2" >&2
}

usage() {
  echo "usage: $0 --launcher <file> --supervisor <file> [--dest-dir <absolute-dir>]" >&2
  exit 2
}

# 外部コマンドを期限つきで実行する唯一の経路（REPAIR-5）。期限超過後 KILL_GRACE 秒で KILL し、回収まで待つ。
# 出力は BOUNDED_OUT、終了コードは BOUNDED_RC に入れて返す（呼び出し側が構造化エラー 1 行へ変換する。子の stderr は
# そのまま流さない）。<mode> が all なら stdout と stderr を併せて、err なら stderr だけを BOUNDED_OUT へ入れる。
# コマンド置換のサブシェルでは die が親を止めないため、ここでは止めずに結果を大域変数で返す。
BOUNDED_OUT=""
BOUNDED_RC=0
run_child() { # <all|err> <command> [args...]
  local mode="$1"
  shift
  BOUNDED_OUT=""
  BOUNDED_RC=0
  if [ "${mode}" = "err" ]; then
    BOUNDED_OUT="$(timeout -k "${KILL_GRACE}" "${CHILD_TIMEOUT}" "$@" 2>&1 >/dev/null)" || BOUNDED_RC=$?
  else
    BOUNDED_OUT="$(timeout -k "${KILL_GRACE}" "${CHILD_TIMEOUT}" "$@" 2>&1)" || BOUNDED_RC=$?
  fi
  return "${BOUNDED_RC}"
}
# 標準入力を使わないコマンド用（端末や呼び出し元のパイプを読ませない）。
bounded() { # <command> [args...]
  run_child all "$@" </dev/null
}
# 直前の run_child が期限で打ち切られたか。timeout(1) は TERM で終われば 124、KILL まで要れば 137 を返す
# （後始末中は TERM を無視したまま子を起動するので、timeout(1) の実装によっては KILL まで要る）。137 は外部からの
# SIGKILL でも起きるが、区別せず同じ扱いにする。
timed_out() {
  [ "${BOUNDED_RC}" -eq 124 ] || [ "${BOUNDED_RC}" -eq 137 ]
}
# 期限超過のメッセージに添える、止まった時点の状態。
state_hint() {
  case "${PHASE}" in
    precheck | staged) printf 'no installed file was replaced' ;;
    committed) printf 'both files are already replaced' ;;
    *) printf 'the update was in progress and its outcome is reported below' ;;
  esac
}
# 直前の run_child の失敗で止まる。期限超過は operation-timeout（終了コード 1）、それ以外は渡された code と終了コード。
fail_bounded() { # <exit-code> <code> <何をしていたか> [期限超過時の補足]
  if timed_out; then
    die 1 operation-timeout "$3 did not finish within ${CHILD_TIMEOUT}s or was killed (exit code ${BOUNDED_RC}); $(state_hint)${4:+; $4}"
  fi
  die "$1" "$2" "$3 failed (exit code ${BOUNDED_RC})"
}
# 属性の変更など、失敗したら install-failed で止まる 1 操作。
step() { # <何をしていたか> <command> [args...]
  local what="$1"
  shift
  bounded "$@" || fail_bounded 1 install-failed "${what}"
}

# パスの種別・inode・所有者・権限を期限つきの stat（既定は lstat。第 2 引数に -L で fstat 相当）で読む。親シェルの
# [ -e ] / [ -L ] / [ -d ] / [ -f ] は使わない（期限を付けられない）。結果は P_KIND（stat の %F。無ければ missing）・
# P_ID（dev:inode）・P_UID・P_GID・P_MODE。判定できないとき（期限超過・下記以外の失敗・想定外の出力）は 1 を返す。
# 「存在しない」は終了コードだけでは他の失敗と区別できないため、stat の終了コード 1 に加えて LC_ALL=C の stat が出す
# `No such file or directory` の文言に依存する。どちらかが違えば判定不能として呼び出し側が止まる（fail-closed）。
P_KIND=""
P_ID=""
P_UID=""
P_GID=""
P_MODE=""
probe_path() { # <path> [-L]
  local rest
  P_KIND=""
  P_ID=""
  P_UID=""
  P_GID=""
  P_MODE=""
  if bounded stat ${2:+"$2"} -c '%F|%d:%i|%u|%g|%a' -- "$1"; then
    rest="${BOUNDED_OUT}"
    P_KIND="${rest%%|*}"
    rest="${rest#*|}"
    P_ID="${rest%%|*}"
    rest="${rest#*|}"
    P_UID="${rest%%|*}"
    rest="${rest#*|}"
    P_GID="${rest%%|*}"
    P_MODE="${rest#*|}"
    [[ "${P_ID}" =~ ^[0-9]+:[0-9]+$ ]] && [[ "${P_UID}" =~ ^[0-9]+$ ]] && [[ "${P_GID}" =~ ^[0-9]+$ ]] &&
      [[ "${P_MODE}" =~ ^[0-7]{1,4}$ ]] && [ -n "${P_KIND}" ] && return 0
    P_KIND=""
    return 1
  fi
  # stat 自身の失敗（終了コード 1）に限る。timeout(1) が stat を起動できなかったとき（126 / 127）の同じ文言を拾わない。
  if [ "${BOUNDED_RC}" -eq 1 ]; then
    case "${BOUNDED_OUT}" in
      *"No such file or directory"*)
        P_KIND="missing"
        return 0
        ;;
    esac
  fi
  return 1
}
is_regular() { # P_KIND が通常ファイルか（GNU stat は空ファイルを別の語で表す）
  [ "${P_KIND}" = "regular file" ] || [ "${P_KIND}" = "regular empty file" ]
}

# 最終名が新しい実体へ置き換わったかを inode で確かめる。結果は REPLACED（yes / no / unknown）。
REPLACED=""
replaced_state() { # <最終名> <新しい実体の dev:inode>
  if ! probe_path "$1"; then
    REPLACED="unknown"
  elif [ -n "$2" ] && [ "${P_ID}" = "$2" ]; then
    REPLACED="yes"
  else
    REPLACED="no"
  fi
}

# 退避ファイルを消す。消せなくても置換の成否は変わらないので、場所を示して続ける（再試行しない）。
remove_backup() {
  [ -n "${BAK_SUPERVISOR}" ] || return 0
  bounded rm -f -- "${BAK_SUPERVISOR}" ||
    warn cleanup-incomplete "could not remove the backup of the previous supervisor at ${BAK_SUPERVISOR} (exit code ${BOUNDED_RC}); it does not affect the installed files, remove it manually"
  BAK_SUPERVISOR=""
}

# 置換の途中（supervisor-replacing・mid-update・launcher-replacing）で止まったときに、旧 launcher と新 supervisor の
# 組み合わせを残さないよう状態を確定する。EXIT trap から呼ばれる。rename が起きたか不明な段階では inode を読み戻して
# 判定し、判定できないときは何も動かさず退避ファイルを残して確かめ方を示す。
settle_update() {
  local sup_state="yes"
  if [ "${PHASE}" = "launcher-replacing" ]; then
    replaced_state "${LAUNCHER_DST}" "${NEW_LAUNCHER_ID}"
    case "${REPLACED}" in
      yes)
        # launcher の rename は完了していた。2 つとも新しい実体で揃っているので戻さない。
        PHASE="committed"
        return 0
        ;;
      unknown)
        KEEP_BACKUP=1
        if [ -n "${BAK_SUPERVISOR}" ]; then
          printf 'error: state-indeterminate: could not confirm whether %s was replaced; %s is the new supervisor and the previous one is kept at %s; if the launcher is still the previous one, restore with: mv -f -- %s %s; otherwise remove %s; or rerun the installer\n' \
            "${LAUNCHER_DST}" "${SUPERVISOR_DST}" "${BAK_SUPERVISOR}" "${BAK_SUPERVISOR}" "${SUPERVISOR_DST}" "${BAK_SUPERVISOR}" >&2
        else
          printf 'error: state-indeterminate: could not confirm whether %s was installed; %s is the new supervisor and there was no previous one; if the launcher is missing, remove %s; or rerun the installer\n' \
            "${LAUNCHER_DST}" "${SUPERVISOR_DST}" "${SUPERVISOR_DST}" >&2
        fi
        return 0
        ;;
    esac
  elif [ "${PHASE}" = "supervisor-replacing" ]; then
    replaced_state "${SUPERVISOR_DST}" "${NEW_SUPERVISOR_ID}"
    sup_state="${REPLACED}"
  fi
  if [ "${sup_state}" = "no" ]; then
    # supervisor の rename は起きていない。戻すものは無い。
    PHASE="staged"
    warn rolled-back "the supervisor had not been replaced yet; no installed file is replaced"
    return 0
  fi
  if [ -n "${BAK_SUPERVISOR}" ]; then
    if bounded mv -f -- "${BAK_SUPERVISOR}" "${SUPERVISOR_DST}"; then
      BAK_SUPERVISOR=""
      PHASE="staged"
      warn rolled-back "previous supervisor restored at ${SUPERVISOR_DST}; no installed file is replaced"
    else
      # 復元に失敗したら状態を消さない。退避ファイル（旧 supervisor）は削除せず、場所と復元コマンドを示す。
      KEEP_BACKUP=1
      printf 'error: restore-failed: could not restore the previous supervisor (exit code %s); it is kept at %s and %s %s the new one; restore with: mv -f -- %s %s\n' \
        "${BOUNDED_RC}" "${BAK_SUPERVISOR}" "${SUPERVISOR_DST}" "$([ "${sup_state}" = "yes" ] && printf 'is' || printf 'may be')" \
        "${BAK_SUPERVISOR}" "${SUPERVISOR_DST}" >&2
    fi
  elif bounded rm -f -- "${SUPERVISOR_DST}"; then
    PHASE="staged"
    warn rolled-back "new supervisor removed from ${SUPERVISOR_DST}; nothing is installed"
  else
    printf 'error: restore-failed: could not remove the new supervisor at %s (exit code %s); there was no previous one, remove it manually\n' \
      "${SUPERVISOR_DST}" "${BOUNDED_RC}" >&2
  fi
}

# EXIT trap。置換途中なら状態を確定し、一時ファイルと（残す必要のない）退避ファイルを消す。終了コードは変えない。
cleanup() {
  local rc=$? f
  # 後始末・復元の途中で再度の中断を受けて半端な状態を残さないよう、捕捉可能な信号を無視する（完遂を優先する）。
  trap '' INT HUP TERM
  # 個々の失敗は下で明示的に扱う。想定外の失敗（メッセージの出力失敗など）で後始末を打ち切らない。
  set +e
  case "${PHASE}" in
    supervisor-replacing | mid-update | launcher-replacing) settle_update ;;
  esac
  for f in "${TMP_LAUNCHER}" "${TMP_SUPERVISOR}"; do
    [ -n "${f}" ] || continue
    bounded rm -f -- "${f}" ||
      warn cleanup-incomplete "could not remove the temporary file ${f} (exit code ${BOUNDED_RC}); remove it manually"
  done
  [ "${KEEP_BACKUP}" -eq 1 ] || remove_backup
  if [ "${rc}" -ne 0 ] && [ "${PHASE}" = "committed" ]; then
    warn replaced-unverified "both files were replaced but the final verification did not finish; rerun the installer to verify"
  fi
  exit "${rc}"
}
trap cleanup EXIT
# 捕捉可能な中断は終了コード付きで抜け、EXIT trap（cleanup）に後始末させる。SIGKILL は捕捉できない。
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

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

# --dest-dir は許可リスト方式で検証する（空白・改行・glob・.. を拒否）。単一の末尾スラッシュは検査より先に除去する
# （除去後に残る `//` は空要素として拒否する）。
DEST_DIR="${DEST_DIR%/}"
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

[ "$(uname -s)" = "Linux" ] || die 3 unsupported-os "this installer supports Linux only"

# 環境の固定。テスト入口は EUID が 0 のとき拒否する（本物の root ではスタブへ差し替えられない）。期限の短縮も
# テスト入口の中でだけ受け付ける（1〜30 秒の整数。KILL までの猶予は 1 秒にする）。
SANDBOX="${FANDHE_INSTALL_TEST_SANDBOX:-}"
TEST_TIMEOUT="${FANDHE_INSTALL_TEST_TIMEOUT_SECS:-}"
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
  if [ -n "${TEST_TIMEOUT}" ]; then
    [[ "${TEST_TIMEOUT}" =~ ^([1-9]|[12][0-9]|30)$ ]] ||
      die 3 test-seam-refused "timeout override must be an integer between 1 and 30"
    CHILD_TIMEOUT="${TEST_TIMEOUT}"
    KILL_GRACE=1
  fi
else
  [ -z "${TEST_TIMEOUT}" ] || die 3 test-seam-refused "timeout override is only allowed inside the test sandbox"
  PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  TRUSTED_UID=0
  CALLER_UID="${EUID}"
fi
export PATH
export LC_ALL=C

[ "${CALLER_UID}" = "0" ] || die 3 not-root "must be run as root"

# 子プロセスの待機には必ず期限を設ける（REPAIR-5）。期限を保護できない環境では実行前に拒否する。
command -v timeout >/dev/null 2>&1 || die 3 timeout-unavailable "timeout(1) is required to bound child processes"

# 入力元は 1 回だけ開き、開いた fd 自体を検査して同じ fd から複製する（検査後の再オープンによる TOCTOU を作らない）。
# パスが symlink でないこと（lstat）と、fd の指す実体（fstat）が通常ファイルで lstat と同一 inode であることを確かめる。
SRC_FD_LAUNCHER=""
SRC_FD_SUPERVISOR=""
# watchdog を止めて回収する。TERM ではなく KILL を使う: fork 直後の子はまだ親の trap（TERM で exit → EXIT trap の
# cleanup）を持っており、その間に届いた TERM は親の後始末を子で走らせたり、取りこぼされて watchdog が生き残ったりする
# （生き残ると期限後に親の pid へ KILL を送る）。KILL は取りこぼされない。
stop_watchdog() { # <pid>
  kill -KILL "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
open_source() { # <path> <fd 番号を入れる変数名>
  local path="$1" fd lst wd
  # open 前に symlink でない通常ファイルであることを期限つき stat（lstat）で確かめ、FIFO 等を open せずに拒否する
  # （書き手のいない FIFO の open は無期限に止まる）。
  probe_path "${path}" || fail_bounded 3 invalid-source "stat of the source"
  [ "${P_KIND}" = "regular file" ] || die 3 invalid-source "source must be a readable regular file and not a symlink"
  # 事前検査と open の間の差し替え競合に備え、open 自体にも期限を付ける（REPAIR-5）。この時点では一時ファイルも
  # 更新途中の状態も無いため、期限切れは watchdog が KILL して終了してよい。watchdog の sleep は打ち切り後も残るので、
  # 呼び出し元の stdout / stderr（パイプ）を握らせない。
  ( sleep "${CHILD_TIMEOUT}" >/dev/null 2>&1 && { printf 'error: source-open-timeout: opening source timed out\n' >&2; kill -KILL $$; } ) &
  wd=$!
  { exec {fd}<"${path}"; } 2>/dev/null || { stop_watchdog "${wd}"; die 3 invalid-source "source must be a readable regular file and not a symlink"; }
  stop_watchdog "${wd}"
  probe_path "${path}" || fail_bounded 3 invalid-source "stat of the source"
  lst="${P_KIND} ${P_ID}"
  probe_path "/proc/self/fd/${fd}" -L || fail_bounded 3 invalid-source "stat of the opened source"
  if [ "${lst}" != "${P_KIND} ${P_ID}" ] || [ "${P_KIND}" != "regular file" ]; then
    die 3 invalid-source "source must be a readable regular file and not a symlink"
  fi
  printf -v "$2" '%s' "${fd}"
}
open_source "${LAUNCHER_SRC}" SRC_FD_LAUNCHER
open_source "${SUPERVISOR_SRC}" SRC_FD_SUPERVISOR

# 配置先の 1 要素が信頼条件（ディレクトリ・非 symlink・信頼する所有者・g/o 書き込み不可）を満たすか確かめる。
# 種別・所有者・権限は 1 回の lstat で読む（symlink は種別が `symbolic link` になるので通らない）。
check_dir() { # <path>
  local p="$1"
  probe_path "${p}" || fail_bounded 3 untrusted-dest-dir "stat of ${p}"
  [ "${P_KIND}" = "directory" ] || die 3 untrusted-dest-dir "not a plain directory: ${p}"
  [ "${P_UID}" = "${TRUSTED_UID}" ] || die 3 untrusted-dest-dir "not owned by the trusted owner: ${p}"
  [ $(( 8#${P_MODE} & 8#022 )) -eq 0 ] || die 3 untrusted-dest-dir "group/other writable: ${p}"
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
set -f
# shellcheck disable=SC2206 # 要素分割が目的（文字種は上で許可リスト検証済み。glob は set -f で止めている）
comps=(${rest})
set +f
IFS="${old_ifs}"
for comp in ${comps[@]+"${comps[@]}"}; do
  cur="${cur}/${comp}"
  probe_path "${cur}" || fail_bounded 3 untrusted-dest-dir "stat of ${cur}"
  if [ "${P_KIND}" = "missing" ]; then
    # 権限は umask に依らず 0755 に固定する。
    bounded mkdir -m 0755 -- "${cur}" || fail_bounded 1 install-failed "mkdir of ${cur}"
  fi
  check_dir "${cur}"
done

LAUNCHER_DST="${DEST_DIR}/${LAUNCHER_NAME}"
SUPERVISOR_DST="${DEST_DIR}/${SUPERVISOR_NAME}"
SUPERVISOR_EXISTS=0
for dst in "${LAUNCHER_DST}" "${SUPERVISOR_DST}"; do
  probe_path "${dst}" || fail_bounded 3 untrusted-dest-dir "stat of ${dst}"
  if [ "${P_KIND}" = "missing" ]; then
    continue
  fi
  is_regular || die 3 untrusted-dest-dir "existing destination is not a regular file: ${dst}"
  if [ "${dst}" = "${SUPERVISOR_DST}" ]; then
    SUPERVISOR_EXISTS=1
  fi
done

# libcap の getcap 出力（新旧書式）から、パスより後ろの能力名リスト（ソート済み）とフラグを取り出す。
sorted_caps() { # <カンマ区切り>
  printf '%s\n' "${1//,/$'\n'}" | sort | paste -sd, -
}
# setcap / getcap の診断が xattr 非対応（ENOTSUP/EOPNOTSUPP）を示すか。errno は終了コードに現れないため文言で判定する。
mentions_not_supported() { # <診断の文言>
  local lowered
  lowered="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "${lowered}" in
    *"not supported"*) return 0 ;;
    *) return 1 ;;
  esac
}
# 1 のとき setcap が xattr 非対応で失敗している（setuid へ切り替えた）。getcap の `not supported` を capability なしと
# 読み替えるのはこのときだけ。
XATTR_UNSUPPORTED=0
# getcap の読み戻し。$1 のファイルの付与状態を `<sorted names>|<flags>` として大域変数 CAPS_READ へ入れる（無ければ空）。
# getcap は読めなかったときも終了コード 0 で stderr に診断を出すことがあるため、stdout と stderr を併せて受け取り、
# 「空」「`<file> <caps>` の 1 行」以外をすべて失敗として止める（fail-closed）。
CAPS_READ=""
read_caps() { # <file>
  local out rest names flags
  CAPS_READ=""
  if ! bounded getcap "$1"; then
    if timed_out; then
      fail_bounded 1 capability-mismatch "getcap for $1"
    fi
    if [ "${XATTR_UNSUPPORTED}" -eq 1 ] && mentions_not_supported "${BOUNDED_OUT}"; then
      return 0
    fi
    die 1 capability-mismatch "getcap failed for $1 (exit code ${BOUNDED_RC})"
  fi
  out="${BOUNDED_OUT}"
  [ -n "${out}" ] || return 0
  case "${out}" in
    "$1 "*$'\n'*) die 1 capability-mismatch "getcap printed unexpected output for $1" ;;
    "$1 "*) ;;
    *)
      if [ "${XATTR_UNSUPPORTED}" -eq 1 ] && mentions_not_supported "${out}"; then
        return 0
      fi
      die 1 capability-mismatch "getcap reported an error for $1"
      ;;
  esac
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
# 種別・所有者・権限ビットの読み戻し。gid は信頼する所有者が root のとき（本番）のみ照合する。読んだ inode は P_ID に残る。
expect_stat() { # <file> <mode>
  probe_path "$1" || fail_bounded 1 install-failed "stat of $1"
  is_regular || die 1 install-failed "not a regular file: $1"
  [ "${P_UID}" = "${TRUSTED_UID}" ] || die 1 install-failed "owner mismatch on $1"
  [ "${P_MODE}" = "$2" ] || die 1 install-failed "mode mismatch on $1"
  if [ "${TRUSTED_UID}" = "0" ]; then
    [ "${P_GID}" = "0" ] || die 1 install-failed "group mismatch on $1"
  fi
}

# 一時ファイルを配置先と同じディレクトリに作る。期限超過のときは名前を受け取れていないので、残った可能性を伝える。
make_temp() { # <接頭辞> <名前を入れる変数名>
  bounded mktemp "${DEST_DIR}/$1.XXXXXX" ||
    fail_bounded 1 install-failed "mktemp" "a stray ${DEST_DIR}/$1.* file may remain, remove it manually"
  case "${BOUNDED_OUT}" in
    "${DEST_DIR}/$1."??????) ;;
    *) die 1 install-failed "mktemp returned an unexpected name" ;;
  esac
  printf -v "$2" '%s' "${BOUNDED_OUT}"
}

# 一時ファイルへ複製して属性を整える（chown を先、setcap / chmod を後にして属性消失を避ける）。複製先は期限つきの子
# （dd）が開く。入力元は検査済みの fd をそのまま標準入力として渡す。
PHASE="staged"
make_temp ".launcher" TMP_LAUNCHER
make_temp ".supervisor" TMP_SUPERVISOR
run_child all dd bs=65536 of="${TMP_LAUNCHER}" <&"${SRC_FD_LAUNCHER}" || fail_bounded 1 install-failed "copy of the launcher"
run_child all dd bs=65536 of="${TMP_SUPERVISOR}" <&"${SRC_FD_SUPERVISOR}" || fail_bounded 1 install-failed "copy of the supervisor"
exec {SRC_FD_LAUNCHER}<&- {SRC_FD_SUPERVISOR}<&-
step "chown" chown root:root "${TMP_LAUNCHER}"
step "chmod" chmod 0755 "${TMP_LAUNCHER}"
step "chown" chown root:root "${TMP_SUPERVISOR}"
step "chmod" chmod 0755 "${TMP_SUPERVISOR}"

METHOD="file-capability"
LAUNCHER_MODE=755
if run_child err setcap "${LAUNCHER_CAPS}" "${TMP_LAUNCHER}" </dev/null; then
  expect_launcher_caps "${TMP_LAUNCHER}"
elif timed_out; then
  fail_bounded 1 setcap-failed "setcap"
elif mentions_not_supported "${BOUNDED_OUT}"; then
  METHOD="setuid"
  LAUNCHER_MODE=4755
  XATTR_UNSUPPORTED=1
  step "chown" chown root:root "${TMP_LAUNCHER}"
  step "chmod" chmod 4755 "${TMP_LAUNCHER}"
  expect_stat "${TMP_LAUNCHER}" 4755
  expect_no_caps "${TMP_LAUNCHER}"
  echo "warning: setuid-fallback: file capabilities are not supported here, installed setuid root instead" >&2
else
  die 1 setcap-failed "setcap failed with exit code ${BOUNDED_RC}"
fi
expect_stat "${TMP_LAUNCHER}" "${LAUNCHER_MODE}"
NEW_LAUNCHER_ID="${P_ID}"
expect_no_caps "${TMP_SUPERVISOR}"
expect_stat "${TMP_SUPERVISOR}" 755
NEW_SUPERVISOR_ID="${P_ID}"

# 失敗しうる処理がすべて成功してから最終名へ置換する（rename は xattr を保つ）。2 つの置換は一組として扱い、
# 途中で止まったら旧ファイル（ハードリンクで保持した退避。xattr も保つ）へ戻す（旧 launcher と新 supervisor の不整合を残さない）。
# 退避の名前は mktemp で一意に取り、その名前をハードリンクで置き換える（以前の実行が残した退避ファイルと衝突しない）。
if [ "${SUPERVISOR_EXISTS}" -eq 1 ]; then
  make_temp ".supervisor.bak" BAK_SUPERVISOR
  bounded ln -f -- "${SUPERVISOR_DST}" "${BAK_SUPERVISOR}" || fail_bounded 1 install-failed "backup of the previous supervisor"
fi
# rename の前に段階を進める。rename の完了と段階の更新の間で中断・期限超過が起きても、EXIT trap が inode を読み戻して
# 置換の有無を確かめるので、信号を無視する区間は要らない（期限つきの子を信号無視のまま待たない）。
PHASE="supervisor-replacing"
bounded mv -f -- "${TMP_SUPERVISOR}" "${SUPERVISOR_DST}" || fail_bounded 1 install-failed "rename of the supervisor"
TMP_SUPERVISOR=""
PHASE="mid-update"
# ここから launcher の rename 完了までが更新途中。置換後の supervisor を読み戻して検証する間に中断・失敗しても、
# EXIT trap が旧 supervisor へ戻す。
expect_no_caps "${SUPERVISOR_DST}"
expect_stat "${SUPERVISOR_DST}" 755
PHASE="launcher-replacing"
bounded mv -f -- "${TMP_LAUNCHER}" "${LAUNCHER_DST}" || fail_bounded 1 install-failed "rename of the launcher"
TMP_LAUNCHER=""
PHASE="committed"
remove_backup

expect_no_caps "${SUPERVISOR_DST}"
expect_stat "${SUPERVISOR_DST}" 755
expect_stat "${LAUNCHER_DST}" "${LAUNCHER_MODE}"
if [ "${METHOD}" = "setuid" ]; then
  expect_no_caps "${LAUNCHER_DST}"
else
  expect_launcher_caps "${LAUNCHER_DST}"
fi
printf 'installed: method=%s dest-dir=%s\n' "${METHOD}" "${DEST_DIR}"
