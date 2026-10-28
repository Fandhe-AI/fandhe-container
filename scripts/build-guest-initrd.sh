#!/usr/bin/env bash
# macOS ゲスト VM の initrd を作るスクリプト（TASK-64 追補・#1878・MAC-1・#362・MS-5）。
#
# 役割: ゲスト init（crates/guest-init。#1875）を aarch64-unknown-linux-musl で静的リンクして
# ビルドし、`/init` 1 個だけを含む cpio（newc 形式）を作る。busybox 等の GPL ユーザーランドは
# 入れない（#362）。ディレクトリ・デバイスノードも入れず、/proc・/sys・/dev・mount point は
# init が自分で作る（crates/guest-init/src/init.rs）。呼び出し元は Makefile の
# `guest-initrd-build` と自己テスト（scripts/build-guest-initrd-selftest.sh）。
# CI と `make ci` では実ビルドしない（実機での起動確認は人間が行う。#1628）。
# カーネル側のビルドは guest/kernel/build.sh（#1874）。圧縮は guest/kernel/arm64-guest.config の
# RD_GZIP に合わせ既定 gzip。cpio は外部 cpio コマンドに依らず自前で書く（GNU / BSD の差を避け、
# 出力を決定的にして自己テストでバイト照合するため）。
#
# 使い方:
#   build-guest-initrd.sh [--output-dir <dir>] [--init <path>] [--compress gzip|none] [--linker <cmd>]
#                         [--build-timeout S] [--pack-timeout S]
#   各引数は同名の環境変数（GUEST_INITRD_OUTPUT_DIR・GUEST_INITRD_INIT・GUEST_INITRD_COMPRESS・
#   GUEST_INITRD_LINKER）でも渡せる。CLI の引数が優先。
#   --output-dir    既定: <repo>/target/guest-initrd/aarch64（空または未存在のディレクトリのみ）
#   --init          作成済みの静的リンク aarch64 の init を使う（ビルドしない）
#   --compress      gzip（既定。initrd.cpio.gz）または none（initrd.cpio）
#   --linker        cargo の子プロセスだけに渡すリンカ（既定 rust-lld。文字種 [A-Za-z0-9._/+-]）
#   --build-timeout cargo build の上限秒（既定 1800。1〜7200）
#   --pack-timeout  gzip の上限秒（既定 60。1〜600）
#
# 安全性: root・sudo を要求しない。入力は symlink・通常ファイル以外・空・上限（64 MiB）超・
# 他者所有・group/other 書き込み可を拒否する。検査と複製は開いた 1 本の fd に対して行い、以降は
# private な複製だけを ELF 検査と梱包に使う（検査後の差し替え対策。ただし親ディレクトリが他者に
# 書き換え可能な場合に開く対象自体を差し替えられる点は防げない）。ELF は aarch64・64-bit LE・ET_EXEC・PT_INTERP 無し（静的）のみ受ける。
# 出力は排他ロック（<出力先>.lock）の下で ln により確定し、既存を上書きしない。ビルドは専用の
# target ディレクトリと umask 077 で行う。cargo・gzip は期限つきで、超過時はグループごと停止する
# （REPAIR-5）。macOS でのリンクは未検証（Linux x86_64 で rust-lld により確認）。
# fd 経由の権限検査（/dev/fd/9 への find -L）が有効なのは Linux で確認済み。macOS では /dev/fd/N（fdesc）
# 経由で効くか未確認で（原因の切り分けは #2088。観測は scripts/probe-dev-fd-perm.sh）、パス側の重ねがけは
# 早期拒否であって差し替え対策の根拠ではない。macOS では --init に自分の管理下のパスを渡すこと（REPAIR-3）。
#
# 前提ツール: cargo と aarch64-unknown-linux-musl の target（--init 無指定時）・gzip（gzip 時）・
#   od・sha256sum または shasum・mktemp・find
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功（stdout に initrd の絶対パスを 1 行出す）
#   1: ビルド失敗（build-failed）・gzip 失敗（pack-failed）
#   2: 引数・環境・入力・出力先が不正、Windows ホスト
#   3: 期限切れ（build-timeout・pack-timeout・input-timeout）
# エラーは stderr に `error: code=<code> message=<英語>` の 1 行で出す。
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: build-guest-initrd.sh [--output-dir <dir>] [--init <path>] [--compress gzip|none] [--linker <cmd>]
                             [--build-timeout S] [--pack-timeout S]
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
# lib.sh は source 時に cwd をリポジトリルートへ移す（make 経由と同じ意味にするため）。本スクリプトは
# 利用者の相対パスを呼び出し元の cwd 基準で解釈するので、source 後に元の cwd へ戻す。
caller_pwd="$PWD"
# shellcheck source=lib.sh
source "$root/scripts/lib.sh"
cd -- "$caller_pwd" || { err_code bad-environment "cannot return to the working directory"; exit 2; }

output_dir="${GUEST_INITRD_OUTPUT_DIR:-}"
init_arg="${GUEST_INITRD_INIT:-}"
compress="${GUEST_INITRD_COMPRESS:-gzip}"
linker="${GUEST_INITRD_LINKER:-rust-lld}"
build_timeout=1800
pack_timeout=60
max_init_bytes=67108864

check_int() {
    if ! int_in_range "$2" "$3" "$4"; then
        err_code bad-argument "$1 must be an integer between $3 and $4"
        usage
        exit 2
    fi
}

need_value() {
    [ "$1" -ge 2 ] || { err_code bad-argument "$2 requires a value"; usage; exit 2; }
}

while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir) need_value $# "$1"; output_dir="$2"; shift 2 ;;
        --init) need_value $# "$1"; init_arg="$2"; shift 2 ;;
        --compress) need_value $# "$1"; compress="$2"; shift 2 ;;
        --linker) need_value $# "$1"; linker="$2"; shift 2 ;;
        --build-timeout) need_value $# "$1"; check_int "$1" "$2" 1 7200; build_timeout="$2"; shift 2 ;;
        --pack-timeout) need_value $# "$1"; check_int "$1" "$2" 1 600; pack_timeout="$2"; shift 2 ;;
        *) err_code bad-argument "unknown argument: $1"; usage; exit 2 ;;
    esac
done

case "$compress" in
    gzip | none) ;;
    *) err_code bad-argument "--compress must be gzip or none"; usage; exit 2 ;;
esac
if ! [[ "$linker" =~ ^[A-Za-z0-9._/+-]+$ ]]; then
    err_code bad-argument "--linker contains characters outside [A-Za-z0-9._/+-]"
    exit 2
fi
case "$output_dir$init_arg" in
    *[[:cntrl:]]*) err_code bad-argument "paths must not contain control characters"; exit 2 ;;
esac

# --- テスト用の差し替え口（自己テスト専用。サンドボックスの外では拒否する） ---
cargo_cmd="cargo"
host_os=""
expect_uid=""
private_group_seam=""
sandbox="${GUEST_INITRD_TEST_SANDBOX:-}"
seam_requested=0
for v in GUEST_INITRD_CARGO GUEST_INITRD_UNAME_S GUEST_INITRD_EXPECT_UID GUEST_INITRD_PRIVATE_GROUP; do
    [ -z "${!v:-}" ] || seam_requested=1
done
if [ "$seam_requested" -eq 1 ]; then
    if [ -z "$sandbox" ] || [ ! -d "$sandbox" ] || [ ! -f "$sandbox/.guest-initrd-selftest" ]; then
        err_code test-seam-refused "test seams are only allowed inside the selftest sandbox"
        exit 2
    fi
    case "${GUEST_INITRD_CARGO:-}" in
        "" | "$sandbox"/*) ;;
        *) err_code test-seam-refused "GUEST_INITRD_CARGO must be inside the selftest sandbox"; exit 2 ;;
    esac
    [ -z "${GUEST_INITRD_CARGO:-}" ] || cargo_cmd="$GUEST_INITRD_CARGO"
    host_os="${GUEST_INITRD_UNAME_S:-}"
    expect_uid="${GUEST_INITRD_EXPECT_UID:-}"
    case "${GUEST_INITRD_PRIVATE_GROUP:-}" in
        "" | yes | no) private_group_seam="${GUEST_INITRD_PRIVATE_GROUP:-}" ;;
        *) err_code test-seam-refused "GUEST_INITRD_PRIVATE_GROUP must be yes or no"; exit 2 ;;
    esac
    if [ -n "$expect_uid" ] && ! [[ "$expect_uid" =~ ^[0-9]{1,10}$ ]]; then
        err_code test-seam-refused "GUEST_INITRD_EXPECT_UID must be numeric"
        exit 2
    fi
fi
[ -n "$host_os" ] || host_os="$(uname -s)"
[ -n "$expect_uid" ] || expect_uid="$(id -u)"

case "$host_os" in
    MINGW* | MSYS* | CYGWIN*)
        err_code unsupported-os "Windows hosts are not supported for building the guest initrd"
        exit 2
        ;;
esac
if [ "$host_os" = "Darwin" ]; then
    info_msg "warning: linking on macOS is unverified (see AGENTS.md)"
fi

# --- 出力先（空または未存在のみ。上書きしない） ---
[ -n "$output_dir" ] || output_dir="$root/target/guest-initrd/aarch64"
case "$output_dir" in
    /*) ;;
    *) output_dir="$PWD/$output_dir" ;;
esac
while [ "${#output_dir}" -gt 1 ] && [ "${output_dir%/}" != "$output_dir" ]; do
    output_dir="${output_dir%/}"
done

# 出力先と祖先ディレクトリが他者に書き換えられないことの検査（fail-closed。PR #2086 の指摘）。
# 他ユーザーが書き込める場所だと、mktemp が作った名前を観測して削除し、再オープン前に被害者の
# ファイルへの symlink へ差し替えられ、write_info のリダイレクトや cp が参照先を上書きする。
# 出力先自身は other 書き込み可と、自分専用でない group の書き込み可を許さず、祖先は sticky 無しの
# 同条件を拒否する（/tmp のような sticky は他者の名前を消せないため許す）。自分専用 group
# （primary group で、他に所属ユーザーがいない。umask 002 の Debian / Ubuntu 慣行）の group 書き込みは許す。
# 所有者は実際の実行ユーザーか root に限る（テスト用の EXPECT_UID の差し替えは入力側のみ）。
# 検査した物理パスで output_dir を確定し、以降の mkdir・mktemp・write_info・cp はすべてそのパスを使う
# （検査後の symlink 差し替えで別の場所へ書かせない）。
private_group_cache=""
group_is_private() { # 自分の primary group が自分専用なら 0
    if [ -n "$private_group_seam" ]; then
        [ "$private_group_seam" = "yes" ]
        return
    fi
    if [ -z "$private_group_cache" ]; then
        private_group_cache=no
        if command -v getent >/dev/null 2>&1; then
            local gid user grp_line members pw_out others
            gid="$(id -g)"
            user="$(id -un)"
            # getent の失敗・空の出力は「自分しかいない」と区別できないため共有扱い（fail-closed）。
            if grp_line="$(getent group "$gid" 2>/dev/null)" && [ -n "$grp_line" ] &&
                pw_out="$(getent passwd 2>/dev/null)" && [ -n "$pw_out" ]; then
                members="$(printf '%s\n' "$grp_line" | awk -F: '{print $4}')"
                others="$(printf '%s\n' "$pw_out" | awk -F: -v g="$gid" -v u="$user" '$4==g && $1!=u {n++} END {print n+0}')"
                if [ "$others" = "0" ] && { [ -z "$members" ] || [ "$members" = "$user" ]; }; then
                    private_group_cache=yes
                fi
            fi
        fi
    fi
    [ "$private_group_cache" = "yes" ]
}
dir_unsafe_reason() { # $1=ディレクトリ $2=self|ancestor。危険なら理由を stdout に出す
    local d="$1" self_uid; self_uid="$(id -u)"
    local sticky_filter=()
    [ "$2" = "self" ] || sticky_filter=(! -perm -1000)
    if [ -z "$(find "$d" -prune \( -user "$self_uid" -o -user 0 \) -print 2>/dev/null)" ]; then
        printf 'is owned by another user'
    elif [ "$2" = "self" ] && [ -n "$(find "$d" -prune -perm -0002 -print 2>/dev/null)" ]; then
        printf 'is other writable'
    elif [ -n "$(find "$d" -prune -perm -0002 ${sticky_filter[@]+"${sticky_filter[@]}"} -print 2>/dev/null)" ]; then
        printf 'is other writable without the sticky bit'
    elif [ -n "$(find "$d" -prune -perm -0020 ${sticky_filter[@]+"${sticky_filter[@]}"} -print 2>/dev/null)" ]; then
        if ! { group_is_private && [ -n "$(find "$d" -prune -group "$(id -g)" -print 2>/dev/null)" ]; }; then
            printf 'is group writable and the group is shared'
        fi
    fi
}
check_output_safe() {
    local d="$output_dir" kind="self" reason rest=""
    while [ ! -d "$d" ] && [ "$d" != "/" ]; do
        rest="/${d##*/}$rest"
        d="$(dirname "$d")"
        kind="ancestor"
    done
    case "$rest" in
        */./* | */../* | */. | */..) err_code bad-output "output path must not contain . or .. components"; exit 2 ;;
    esac
    d="$(cd -P "$d" 2>/dev/null && pwd -P)" || {
        err_code bad-output "cannot resolve the output directory path"
        exit 2
    }
    # 物理パスで確定する（以後の操作はこのパスだけを使う）。
    if [ "$d" = "/" ]; then output_dir="$rest"; else output_dir="$d$rest"; fi
    # 解決後が空（"/"・"/."・"/.." 等のルート）だと not-empty 検査と mkdir が空パスで崩れる。
    if [ -z "$output_dir" ] || [ "$output_dir" = "/" ]; then
        err_code bad-output "output directory must not be the filesystem root or empty"
        exit 2
    fi
    while :; do
        reason="$(dir_unsafe_reason "$d" "$kind")"
        if [ -n "$reason" ]; then
            err_code unsafe-output "directory $d $reason; refusing to write there"
            exit 2
        fi
        [ "$d" != "/" ] || break
        d="$(dirname "$d")"
        kind="ancestor"
    done
}

# 空ディレクトリであることの検査（一覧取得の失敗は空と誤認しない。fail-closed）。
check_output_free() {
    if [ -L "$output_dir" ]; then
        err_code bad-output "output directory must not be a symlink"
        exit 2
    fi
    check_output_safe
    if [ -e "$output_dir" ] && [ ! -d "$output_dir" ]; then
        err_code output-exists "output path exists and is not a directory"
        exit 2
    fi
    if [ -d "$output_dir" ]; then
        local listing
        listing="$(ls -A "$output_dir" 2>/dev/null)" || {
            err_code bad-output "cannot list the output directory; refusing to continue"
            exit 2
        }
        if [ -n "$listing" ]; then
            err_code output-exists "output directory is not empty; refusing to overwrite"
            exit 2
        fi
    fi
}
check_output_free

# --- ツール確認 ---
sha_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
    sha_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sha_cmd="shasum -a 256"
else
    err_code tool-missing "sha256sum or shasum is required"
    exit 2
fi
command -v od >/dev/null 2>&1 || { err_code tool-missing "od is required"; exit 2; }
command -v find >/dev/null 2>&1 || { err_code tool-missing "find is required"; exit 2; }
if [ "$compress" = "gzip" ]; then
    command -v gzip >/dev/null 2>&1 || { err_code tool-missing "gzip is required"; exit 2; }
fi
if [ -z "$init_arg" ]; then
    command -v "$cargo_cmd" >/dev/null 2>&1 || { err_code tool-missing "cargo is required"; exit 2; }
fi

# --- 一時領域と期限つき実行（scripts/lib.sh の run_limited） ---
work_dir=""
out_created=0
publishing=0
published=""
tmp_info=""
tmp_initrd=""
cleanup() {
    local rc=$?
    run_limited_abort
    [ -z "$work_dir" ] || rm -rf "$work_dir"
    if [ "$rc" -ne 0 ] && [ "$publishing" -eq 0 ] && [ "$out_created" -eq 1 ]; then
        rmdir "$output_dir" 2>/dev/null || true
    fi
    if [ "$rc" -ne 0 ] && [ "$publishing" -eq 1 ]; then
        # 一時名と、自分が確定させたファイルだけを消す（他者の同名ファイルは触らない）。
        [ -z "$tmp_info" ] || rm -f -- "$tmp_info"
        [ -z "$tmp_initrd" ] || rm -f -- "$tmp_initrd"
        for f in $published; do rm -f "$output_dir/$f"; done
        if [ "$out_created" -eq 1 ]; then
            rmdir "$output_dir" 2>/dev/null || true
        fi
    fi
    release_output_lock
}
trap cleanup EXIT
trap 'exit 143' INT TERM

work_dir="$(mktemp -d)" || { work_dir=""; err_code bad-environment "cannot create a temporary directory"; exit 2; }
RUN_LIMITED_DIR="$work_dir"

# 出力先の排他ロック（mkdir は不可分）。取得後に空であることを再検査する。
# 異常終了（KILL 等）で残ったロックは手で削除する。
acquire_output_lock "$output_dir"
check_output_free

# 出力先は cargo build より前に 0700 で作り、所有者・モード・symlink でないことを確認する
# （ビルド中に他者が同じパスへ置いた物を、後続の mktemp・cp が使わないようにする。PR #2086 の指摘）。
if [ ! -d "$output_dir" ]; then
    mkdir -m 0700 "$output_dir" 2>/dev/null || { err_code bad-output "cannot create the output directory"; exit 2; }
    out_created=1
fi
output_dir_identity=""
# 作成済みのディレクトリを (dev:inode) で識別し、公開直前に同一であることを再確認する。
dir_identity() { # $1=ディレクトリ
    if stat -c '%d:%i' "$1" 2>/dev/null; then return 0; fi
    stat -f '%d:%i' "$1" 2>/dev/null
}
recheck_output_dir() {
    local ident
    if [ -L "$output_dir" ] || [ ! -d "$output_dir" ]; then
        err_code unsafe-output "output directory changed during the build; refusing to publish"
        exit 2
    fi
    if [ -n "$(dir_unsafe_reason "$output_dir" self)" ]; then
        err_code unsafe-output "output directory ownership or mode changed during the build; refusing to publish"
        exit 2
    fi
    ident="$(dir_identity "$output_dir")" || ident=""
    if [ -z "$ident" ] || [ "$ident" != "$output_dir_identity" ]; then
        err_code unsafe-output "output directory was replaced during the build; refusing to publish"
        exit 2
    fi
}
output_dir_identity="$(dir_identity "$output_dir")" || output_dir_identity=""
[ -n "$output_dir_identity" ] || { err_code bad-environment "cannot stat the output directory"; exit 2; }
recheck_output_dir

# cargo build を umask 077 と専用 target ディレクトリで走らせる（背景の子の中だけで umask を変える）。
cargo_build() {
    umask 077
    env "CARGO_TARGET_DIR=$work_dir/target" \
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$linker" \
        "$cargo_cmd" build --release --locked -p fandhe-container-guest-init \
        --target aarch64-unknown-linux-musl --manifest-path "$root/Cargo.toml" >&2
}

# --- 入力の取得 ---
if [ -z "$init_arg" ]; then
    info_msg "building fandhe-container-guest-init (aarch64-unknown-linux-musl)"
    rc=0
    run_limited "$build_timeout" cargo_build || rc=$?
    if [ "$rc" -eq 124 ]; then
        err_code build-timeout "cargo build exceeded ${build_timeout}s"
        exit 3
    elif [ "$rc" -ne 0 ]; then
        err_code build-failed "cargo build failed with exit code $rc (is the aarch64-unknown-linux-musl target installed and the linker available?)"
        exit 1
    fi
    init_src="$work_dir/target/aarch64-unknown-linux-musl/release/fandhe-container-guest-init"
else
    init_src="$init_arg"
fi

# --- 入力の検査と複製（開いた 1 本のファイル記述子だけを使う） ---
# 入力の open を含む検査と複製の全体を、期限つきの子プロセス（run_limited）で行う。書き手のいない
# FIFO 等で open が無期限にブロックしても input-timeout で打ち切る（REPAIR-5）。親側では open せず
# `[ -f ]`（stat のみ）で通常ファイル以外を先に拒否する。子は入力を fd 9 で 1 度だけ開き、
# メタデータ検査（通常ファイル・所有者・書き込み権限）と複製をすべてその fd に対して行う
# （パスの再解決による検査後の差し替えを避ける）。検査は /dev/fd/9 を `find -L` で辿り、fd の指す
# inode に対して行う。-L のパス検査は早期の分かりやすい拒否のためだけで安全性の根拠にしない。
# 親ディレクトリが他者に書き換え可能な場合に「どのファイルを開くか」自体を差し替えられる点は
# 防げないため、--init には自分の管理下のパスを渡すこと。
input_timeout=30
if [ -L "$init_src" ]; then
    err_code bad-input "init must not be a symlink"
    exit 2
fi
if [ ! -f "$init_src" ]; then
    err_code bad-input "init is not a regular file"
    exit 2
fi
init_copy="$work_dir/init"
# 上限 +1 バイトまで読んでサイズ超過を検出し、複製は private な work_dir へ書く。以降は複製だけを使う。
copy_input() {
    umask 077
    if ! exec 9<"$init_src"; then
        err_code bad-input "cannot open init"
        exit 2
    fi
    local fd_path="/dev/fd/9"
    if [ -z "$(find -L "$fd_path" -prune -type f -print 2>/dev/null)" ]; then
        err_code bad-input "init is not a regular file"
        exit 2
    fi
    if [ -z "$(find -L "$fd_path" -prune \( -user "$expect_uid" -o -user 0 \) -print 2>/dev/null)" ]; then
        err_code bad-input "init must be owned by the current user or root"
        exit 2
    fi
    if [ -n "$(find -L "$fd_path" -prune \( -perm -0020 -o -perm -0002 \) -print 2>/dev/null)" ]; then
        err_code bad-input "init must not be group or other writable"
        exit 2
    fi
    # macOS の /dev/fd/N（fdesc）では上の fd 経由の権限検査が効かないことがあるため、パス側でも同じ検査を
    # 重ねる（早期拒否。パスの検査は安全性の根拠にしない。fd 検査は Linux で有効、macOS では未確認で #2088）。
    if [ -n "$(find "$init_src" -prune \( -perm -0020 -o -perm -0002 \) -print 2>/dev/null)" ]; then
        err_code bad-input "init must not be group or other writable"
        exit 2
    fi
    if [ -z "$(find "$init_src" -prune -type f \( -user "$expect_uid" -o -user 0 \) -print 2>/dev/null)" ]; then
        err_code bad-input "init must be a regular file owned by the current user or root"
        exit 2
    fi
    if ! head -c $((max_init_bytes + 1)) <&9 >"$init_copy" 2>/dev/null; then
        err_code bad-input "cannot read init"
        exit 2
    fi
}
rc=0
run_limited "$input_timeout" copy_input || rc=$?
if [ "$rc" -eq 124 ]; then
    err_code input-timeout "reading init exceeded ${input_timeout}s (is it a FIFO or a stalled file?)"
    exit 3
elif [ "$rc" -ne 0 ]; then
    exit "$rc"
fi
init_size="$(wc -c <"$init_copy" | tr -d ' ')"
if ! [[ "$init_size" =~ ^[0-9]+$ ]] || [ "$init_size" -eq 0 ]; then
    err_code bad-input "init is empty or unreadable"
    exit 2
fi
if [ "$init_size" -gt "$max_init_bytes" ]; then
    err_code bad-input "init is larger than $max_init_bytes bytes"
    exit 2
fi
chmod 0700 "$init_copy"
copy_size="$(wc -c <"$init_copy" | tr -d ' ')"
if [ "$copy_size" != "$init_size" ]; then
    err_code bad-input "init changed while being copied"
    exit 2
fi

# --- ELF の検査（readelf・file は macOS に無いため od だけで読む） ---
# $1=ファイル $2=オフセット $3=バイト数 → little-endian の整数値を標準出力へ
rd_le() {
    local bytes arr v=0 i
    bytes="$(od -An -tu1 -v -j "$2" -N "$3" "$1" 2>/dev/null)" || return 1
    # shellcheck disable=SC2206
    arr=($bytes)
    [ "${#arr[@]}" -eq "$3" ] || return 1
    i=$(($3 - 1))
    while [ "$i" -ge 0 ]; do
        v=$((v * 256 + arr[i]))
        i=$((i - 1))
    done
    printf '%s\n' "$v"
}
elf_fail() {
    err_code "$1" "$2"
    exit 2
}
magic="$(od -An -tx1 -v -N 4 "$init_copy" | tr -d ' \n')"
[ "$magic" = "7f454c46" ] || elf_fail not-elf "init is not an ELF file"
# BSD od は列幅の空白と末尾の空白を付けるため、語分割で正規化してから比較する。
# shellcheck disable=SC2046
set -- $(od -An -tu1 -v -j 4 -N 2 "$init_copy")
ident="${1:-} ${2:-}"
[ "$ident" = "2 1" ] || elf_fail bad-elf "init must be a 64-bit little-endian ELF"
e_type="$(rd_le "$init_copy" 16 2)" || elf_fail bad-elf "cannot read the ELF header"
e_machine="$(rd_le "$init_copy" 18 2)" || elf_fail bad-elf "cannot read the ELF header"
[ "$e_machine" -eq 183 ] || elf_fail wrong-arch "init is not an aarch64 ELF (e_machine=$e_machine)"
[ "$e_type" -eq 2 ] || elf_fail bad-elf "init must be ET_EXEC (e_type=$e_type); position-independent executables are refused"
e_phoff="$(rd_le "$init_copy" 32 8)" || elf_fail bad-elf "cannot read the ELF header"
e_phentsize="$(rd_le "$init_copy" 54 2)" || elf_fail bad-elf "cannot read the ELF header"
e_phnum="$(rd_le "$init_copy" 56 2)" || elf_fail bad-elf "cannot read the ELF header"
[ "$e_phentsize" -eq 56 ] || elf_fail bad-elf "unexpected program header entry size"
{ [ "$e_phnum" -ge 1 ] && [ "$e_phnum" -le 64 ]; } || elf_fail bad-elf "unexpected program header count"
{ [ "$e_phoff" -ge 64 ] && [ "$e_phoff" -le "$copy_size" ] && [ "$((e_phoff + e_phnum * 56))" -le "$copy_size" ]; } \
    || elf_fail bad-elf "program headers are outside the file"
i=0
while [ "$i" -lt "$e_phnum" ]; do
    p_type="$(rd_le "$init_copy" $((e_phoff + i * 56)) 4)" || elf_fail bad-elf "cannot read a program header"
    [ "$p_type" -ne 3 ] || elf_fail not-static "init has PT_INTERP (dynamically linked)"
    i=$((i + 1))
done

# --- newc 形式の cpio を書く（`init` と TRAILER!!! の 2 エントリだけ） ---
pad4() {
    local n=$((($1 + 3) / 4 * 4 - $1))
    while [ "$n" -gt 0 ]; do
        printf '\0'
        n=$((n - 1))
    done
}
# $1=ino $2=mode $3=filesize $4=namesize（uid・gid・mtime・dev 等は 0、nlink は 1）
newc_header() {
    printf '070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x' \
        "$1" "$2" 0 0 1 0 "$3" 0 0 0 0 "$4" 0
}
cpio_file="$work_dir/initrd.cpio"
{
    newc_header 1 $((8#100755)) "$copy_size" 5
    printf 'init\0'
    pad4 $((110 + 5))
    cat "$init_copy"
    pad4 "$copy_size"
    newc_header 0 0 0 11
    printf 'TRAILER!!!\0'
    pad4 $((110 + 11))
} >"$cpio_file"

final_file="$cpio_file"
final_name="initrd.cpio"
if [ "$compress" = "gzip" ]; then
    rc=0
    run_limited "$pack_timeout" gzip -n -9 -c "$cpio_file" >"$work_dir/initrd.cpio.gz" || rc=$?
    if [ "$rc" -eq 124 ]; then
        err_code pack-timeout "gzip exceeded ${pack_timeout}s"
        exit 3
    elif [ "$rc" -ne 0 ]; then
        err_code pack-failed "gzip failed with exit code $rc"
        exit 1
    fi
    final_file="$work_dir/initrd.cpio.gz"
    final_name="initrd.cpio.gz"
fi

init_sha="$($sha_cmd "$init_copy" | awk '{print $1}')"
initrd_sha="$($sha_cmd "$final_file" | awk '{print $1}')"
rustc_line="unknown"
if command -v rustc >/dev/null 2>&1; then
    rustc_line="$(rustc -V 2>/dev/null | head -n 1 || true)"
    [ -n "$rustc_line" ] || rustc_line="unknown"
fi

# --- 出力（一時名へ書いてから ln で確定する。既存は上書きしない） ---
publishing=1
recheck_output_dir
write_info() {
    printf 'init_sha256=%s\n' "$init_sha"
    printf 'init_bytes=%s\n' "$copy_size"
    printf 'initrd_file=%s\n' "$final_name"
    printf 'initrd_sha256=%s\n' "$initrd_sha"
    printf 'compress=%s\n' "$compress"
    printf 'target=aarch64-unknown-linux-musl\n'
    printf 'rustc=%s\n' "$rustc_line"
    printf 'host=%s\n' "$host_os $(uname -m)"
}
# 一時ファイルは mktemp（O_EXCL・推測できない名前）で排他的に作る。固定名だと、空確認から書き込みまでに
# 他者が置いた symlink の参照先を上書きしうる。確定は ln（既存・symlink があれば失敗）。
tmp_info="$(mktemp "$output_dir/.build-info.XXXXXX" 2>/dev/null)" || tmp_info=""
tmp_initrd="$(mktemp "$output_dir/.initrd.XXXXXX" 2>/dev/null)" || tmp_initrd=""
if [ -z "$tmp_info" ] || [ -z "$tmp_initrd" ] \
    || ! write_info >"$tmp_info" 2>/dev/null \
    || ! cp "$final_file" "$tmp_initrd" 2>/dev/null; then
    err_code output-failed "cannot write the build outputs (disk full or permission?)"
    exit 2
fi
for pair in "build-info.txt:$tmp_info" "$final_name:$tmp_initrd"; do
    dest="${pair%%:*}"
    tmp="${pair#*:}"
    # 確定先がディレクトリ・ディレクトリへの symlink・ダングリング symlink なら ln はその配下に
    # リンクを作って成功しうるため、事前に -e / -L で拒否し、GNU ln の -T（確定先をディレクトリ
    # として解釈しない）が使えれば付ける。BSD / macOS には -T が無いため、リンク後に確定先が
    # 一時ファイルと同一 inode の通常ファイルであることを検証し、違えば配下に出来た名前を消して失敗にする。
    if [ -e "$output_dir/$dest" ] || [ -L "$output_dir/$dest" ]; then
        err_code output-exists "cannot publish $dest: it already exists; refusing to overwrite"
        exit 2
    fi
    if ln -T -- "$tmp" "$tmp.probe" 2>/dev/null; then
        rm -f -- "$tmp.probe"
        ln_notarget="-T"
    else
        ln_notarget=""
    fi
    # shellcheck disable=SC2086
    if ! ln $ln_notarget -- "$tmp" "$output_dir/$dest" 2>/dev/null; then
        err_code output-exists "cannot publish $dest: it already exists or the link failed; refusing to overwrite"
        exit 2
    fi
    if [ -L "$output_dir/$dest" ] || [ ! -f "$output_dir/$dest" ] || [ ! "$output_dir/$dest" -ef "$tmp" ]; then
        # 競合でディレクトリ等が確定先に現れた。配下に出来た名前だけを除いて失敗にする。
        if [ -d "$output_dir/$dest" ]; then
            rm -f -- "$output_dir/$dest/${tmp##*/}" 2>/dev/null || true
        fi
        err_code output-exists "cannot publish $dest: the destination is not a regular file; refusing"
        exit 2
    fi
    published="$published $dest"
    rm -f -- "$tmp"
done
publishing=0
out_created=0
info_msg "init sha256=$init_sha bytes=$copy_size"
info_msg "initrd sha256=$initrd_sha"
printf '%s\n' "$output_dir/$final_name"
