#!/usr/bin/env bash
# /dev/fd/N 経由の権限検査が macOS で効かない原因の切り分け用の観測スクリプト（#2088・TASK-64 追補・MAC-1・REPAIR-12）。
#
# 役割: scripts/build-guest-initrd.sh の copy_input が行う「fd 9 で開いた入力を /dev/fd/9 経由で
# find -L により検査する」処理について、原因の候補を 1 組のコマンドの差で判別できる観測値を出す。
#   (a) fdesc の /dev/fd/N に対する stat が返す mode・所有者が実パスと食い違うか
#   (b) stat は一致するのに BSD find の -L と -perm / -user の組み合わせだけが効かないか
#   (c) bash のコマンド置換の中と別プロセス（fd を継承した /bin/sh）で結果が違うか
# 観測のみで、値の良し悪しは判定しない（終了コード 0 は「観測完了」）。原因の判定と、その後の
# build-guest-initrd.sh の修正は人間の結果を受けた別 PR で行う（手順書は
# docs/verification/dev-fd-perm-check-macos.md）。
# 呼び出し元: Makefile の `dev-fd-perm-probe`（実機前提。make ci と CI には含めない）。自己テストは
# scripts/probe-dev-fd-perm-selftest.sh。
#
# 使い方:
#   probe-dev-fd-perm.sh [--foreign <絶対パス>]
#   --foreign   他者所有のファイル（操作者が自分で sudo 等を使って用意したもの）。環境変数
#               DEV_FD_PROBE_FOREIGN でも渡せる。絶対パス・symlink 不可・通常ファイルのみ。
#               未指定なら `skip:` を出して foreign のケースだけ飛ばす（skip は合格の根拠にしない）。
# 出力: 標準出力に 1 行 1 観測の key=value（空白区切り）。先頭 `probe=dev-fd-perm v=1`、末尾
#   `probe=dev-fd-perm done`。ホスト名・ユーザー名・パスは出さない（uid は数値のみ）。
# 終了コード: 0 観測完了 / 2 引数・入力不正、非対応 OS（Windows）/ 3 全体期限切れ（60 秒）/ その他 想定外の失敗。
# このスクリプトは sudo・root を使わず、--foreign のファイルは中身を読まない（fd を開くだけ）。
# shellcheck disable=SC2329,SC2185  # trap/run_limited 経由の間接呼び出しと find --version の判定
set -euo pipefail

caller_pwd="$PWD"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$script_dir/lib.sh"
cd -- "$caller_pwd" || { err_code bad-environment "cannot return to the working directory"; exit 2; }

usage() {
    echo "usage: probe-dev-fd-perm.sh [--foreign <absolute-path>]" >&2
}

foreign="${DEV_FD_PROBE_FOREIGN:-}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --foreign)
            if [ "$#" -lt 2 ]; then
                usage
                exit 2
            fi
            foreign="$2"
            shift 2
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
        err_code unsupported-os "this probe does not support Windows"
        exit 2
        ;;
    *) ;;
esac

if [ -n "$foreign" ]; then
    case "$foreign" in
        /*) ;;
        *)
            err_code bad-input "--foreign must be an absolute path"
            exit 2
            ;;
    esac
    if [ -L "$foreign" ]; then
        err_code bad-input "--foreign must not be a symlink"
        exit 2
    fi
    if [ ! -f "$foreign" ]; then
        err_code bad-input "--foreign is not a regular file"
        exit 2
    fi
fi

work_dir="$(mktemp -d)" || { err_code bad-environment "cannot create a temporary directory"; exit 2; }
cleanup() {
    run_limited_abort
    rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 143' INT TERM
RUN_LIMITED_DIR="$work_dir"

my_uid="$(id -u)"

# stat / find の系統は実際に呼んで判定する（uname だけで決めない）。
if stat --version >/dev/null 2>&1; then stat_kind=gnu; else stat_kind=bsd; fi
if find --version >/dev/null 2>&1; then find_kind=gnu; else find_kind=bsd; fi

emit() { printf '%s\n' "$*"; }

# st <case> <label> <path>: stat -L の mode / uid / gid / 型を出す（-L 無しの型と mode も）。
st() {
    local c="$1" label="$2" p="$3" out raw
    if [ "$stat_kind" = bsd ]; then
        out="$(stat -L -f 'mode=%Sp/%Lp uid=%u gid=%g type=%HT' "$p" 2>/dev/null | tr ' ' '.')" || out="error"
        raw="$(stat -f 'mode=%Sp/%Lp type=%HT' "$p" 2>/dev/null | tr ' ' '.')" || raw="error"
    else
        out="$(stat -L -c 'mode=%A/%a uid=%u gid=%g type=%F' "$p" 2>/dev/null | tr ' ' '.')" || out="error"
        raw="$(stat -c 'mode=%A/%a type=%F' "$p" 2>/dev/null | tr ' ' '.')" || raw="error"
    fi
    emit "case=$c obs=stat-L target=$label $out"
    emit "case=$c obs=stat-nolink target=$label $raw"
}

# fm <find の引数...>: -print の出力があれば yes（match）、なければ no。find 自体が非 0 で終わった
# （走査の失敗）ときは error を返し、「一致しなかった」と区別する。
fm() {
    local out frc=0
    out="$(find "$@" -print 2>/dev/null)" || frc=$?
    if [ "$frc" -ne 0 ]; then echo error; elif [ -n "$out" ]; then echo yes; else echo no; fi
}

find_set() {
    local c="$1" label="$2" p="$3"
    emit "case=$c obs=find target=$label w-other=$(fm -L "$p" -prune -perm -0002) w-group=$(fm -L "$p" -prune -perm -0020) own-me=$(fm -L "$p" -prune -user "$my_uid") own-root=$(fm -L "$p" -prune -user 0) is-file=$(fm -L "$p" -prune -type f)"
}

# find 自身が見ている mode 文字列（-ls の 3 列目）。
find_ls_mode() {
    local c="$1" label="$2" p="$3" line
    line="$(find -L "$p" -prune -ls 2>/dev/null | head -n 1)" || line=""
    emit "case=$c obs=find-ls-mode target=$label mode=$(printf '%s\n' "$line" | awk '{print $3}')"
}

observe_case() {
    local c="$1" p="$2"
    exec 9<"$p"
    st "$c" path "$p"
    st "$c" fd9 /dev/fd/9
    find_set "$c" path "$p"
    find_set "$c" fd9 /dev/fd/9
    find_ls_mode "$c" path "$p"
    find_ls_mode "$c" fd9 /dev/fd/9
    emit "case=$c obs=fd9-rawtype is-symlink=$(fm /dev/fd/9 -prune -type l) is-chardev=$(fm /dev/fd/9 -prune -type c)"
    # (c) プロセス経路: 親が開いた fd 9 を、bash のコマンド置換と、そのまま継承した別プロセスの
    # /bin/sh で検査して比べる（sh 側では開き直さない。fd 9 は親の exec 9<"$p" のもの）。
    local in_bash in_sh
    in_bash="$(fm -L /dev/fd/9 -prune -perm -0002)"
    in_sh="$(/bin/sh -c 'out=$(find -L /dev/fd/9 -prune -perm -0002 -print 2>/dev/null); frc=$?; if [ "$frc" -ne 0 ]; then echo error; elif [ -n "$out" ]; then echo yes; else echo no; fi')"
    emit "case=$c obs=route w-other-bash-subst=$in_bash w-other-sh-child=$in_sh"
    exec 9<&-
}

make_file() { # <名前> <mode>
    local f="$work_dir/$1"
    printf 'probe\n' >"$f"
    chmod "$2" "$f"
    printf '%s\n' "$f"
}

observe_all() {
    emit "probe=dev-fd-perm v=1"
    local osv=""
    if [ "$(uname -s)" = Darwin ]; then
        osv=" product=$(sw_vers -productVersion 2>/dev/null || echo unknown)"
    fi
    local rev
    rev="$(git rev-parse HEAD 2>/dev/null)" || rev="unknown"
    emit "env os=$(uname -s) kernel=$(uname -r) arch=$(uname -m)$osv bash=$BASH_VERSION find=$find_kind stat=$stat_kind uid=$my_uid rev=$rev"
    local m f
    for m in 0644 0664 0666; do
        f="$(make_file "f$m" "$m")"
        observe_case "$m" "$f"
    done
    if [ -n "$foreign" ]; then
        observe_case foreign "$foreign"
    else
        emit "skip: foreign owner case not provided (pass --foreign)"
    fi
    emit "probe=dev-fd-perm done"
}

rc=0
run_limited 60 observe_all || rc=$?
if [ "$rc" -eq 124 ]; then
    err_code probe-timeout "observation exceeded 60s"
    exit 3
fi
exit "$rc"
