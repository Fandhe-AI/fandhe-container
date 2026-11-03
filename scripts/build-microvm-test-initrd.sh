#!/usr/bin/env bash
# microVM の実カーネル起動試験用の最小 initrd を作るスクリプト（#3770・MVM-1・TASK-75.5・MS-7）。
#
# 役割: `/init` 1 個だけの cpio（newc 形式）を作る。`/init` はこのスクリプトが固定のバイト列から組む
# 約 200 バイトの x86_64 静的 ELF で、固定文字列を fd 1（/dev/console）へ書いてから
# `reboot(LINUX_REBOOT_CMD_RESTART)` を呼ぶ。busybox 等の GPL ユーザーランド・C コンパイラ・
# ネットワークは使わない（#362 と同じ方針）。呼び出し元は Makefile の `microvm-test-initrd-build`、
# 自己テスト（scripts/build-microvm-test-initrd-selftest.sh）、AGENTS.md の手順、および実カーネルの
# 起動完走試験（#3771）の入力。カーネルは利用者が用意する（Kconfig の最小要件は AGENTS.md）。
#
# 既存の scripts/build-guest-initrd.sh（macOS ゲスト用・aarch64・外部 init を検査して梱包・MAC-1）とは
# 別スクリプトにした。アーキ・init の出どころ・用途が違い、汎用化すると MAC-1 側の契約と自己テストへ
# 波及するため（REPAIR-1）。newc の書き出し（pad4・newc_header）は同じ方式を写した複製で、片方を
# 直したらもう片方も確認すること。
#
# /init の機械語（x86_64。ファイル先頭から ELF ヘッダ 64 + program header 56 = 120 = 0x78 バイトの後に続く。
# 表のオフセットはコード先頭から）:
#    0: b8 01 00 00 00            mov eax, 1        ; write
#    5: bf 01 00 00 00            mov edi, 1        ; fd 1 = /dev/console
#   10: 48 8d 35 21 00 00 00      lea rsi, [rip+33] ; 次の命令は 17、メッセージは 50
#   17: ba <len> 00 00 00         mov edx, len
#   22: 0f 05                     syscall
#   24: b8 a9 00 00 00            mov eax, 169      ; reboot
#   29: bf ad de e1 fe            mov edi, 0xfee1dead (LINUX_REBOOT_MAGIC1)
#   34: be 69 19 12 28            mov esi, 0x28121969 (LINUX_REBOOT_MAGIC2)
#   39: ba 67 45 23 01            mov edx, 0x01234567 (LINUX_REBOOT_CMD_RESTART)
#   44: 0f 05                     syscall
#   46: f3 90                     pause             ; reboot が戻ったら終了せず回り続ける
#   48: eb fc                     jmp 46            ;（PID 1 の exit は kernel panic になる。止めるのは #3771 の期限つき stop）
#   50: メッセージ（改行つき 32 バイト）
# POWER_OFF ではなく RESTART を使う理由: ACPI の無い x86 では POWER_OFF が止まらず PID 1 が終わって panic する。
# cmdline の `reboot=t` と組み合わせると triple fault になり、KVM_EXIT_SHUTDOWN から
# StopReason::GuestShutdown に決定的につながる（crates/microvm/src/microvm.rs の classify_run）。
#
# 使い方:
#   build-microvm-test-initrd.sh [--output-dir <dir>] [--compress none|gzip] [--pack-timeout S]
#   各引数は同名の環境変数（MICROVM_TEST_INITRD_OUTPUT_DIR・MICROVM_TEST_INITRD_COMPRESS）でも渡せる。CLI が優先。
#   --output-dir    既定: <repo>/target/microvm-test-initrd/x86_64（存在しない新規ディレクトリのみ。既存は拒否）
#   --compress      none（既定。initrd.cpio）または gzip（initrd.cpio.gz。カーネルは CONFIG_RD_GZIP=y が要る）
#   --pack-timeout  gzip の上限秒（既定 60。1〜600。REPAIR-5）
#
# 安全性: root・sudo・ネットワークを使わない。外部入力のファイルは無い。出力先は不可分に `mkdir -m 0700` で
# 作り、既存（空・symlink を含む）は上書きせず拒否する。出力先の祖先が他者に書き換え可能なら拒否する
# （build-guest-initrd.sh の検査を簡略化して写した）。生成した ELF はホストでは実行しない。
# 範囲: x86_64 のみ（aarch64 の microVM ブートは未実装。REPAIR-3）。実カーネルでの起動は未確認で、
# 実機での確認は #3781（人間担当）。
#
# 終了コード: 0 成功（stdout に initrd の絶対パスを 1 行）/ 1 内部エラー・gzip 失敗 / 2 引数・環境・出力先不正、
#   Windows ホスト / 3 gzip の期限切れ。エラーは stderr に `error: code=<code> message=<英語>` の 1 行。
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: build-microvm-test-initrd.sh [--output-dir <dir>] [--compress none|gzip] [--pack-timeout S]
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
# lib.sh は source 時に cwd をリポジトリルートへ移すため、利用者の相対パスのために元の cwd へ戻す。
caller_pwd="$PWD"
# shellcheck source=lib.sh
source "$root/scripts/lib.sh"
cd -- "$caller_pwd" || { err_code bad-environment "cannot return to the working directory"; exit 2; }

output_dir="${MICROVM_TEST_INITRD_OUTPUT_DIR:-}"
compress="${MICROVM_TEST_INITRD_COMPRESS:-none}"
pack_timeout=60
init_message="fandhe-microvm-test: init ok v1"

need_value() {
    [ "$1" -ge 2 ] || { err_code bad-argument "$2 requires a value"; usage; exit 2; }
}
while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir) need_value $# "$1"; output_dir="$2"; shift 2 ;;
        --compress) need_value $# "$1"; compress="$2"; shift 2 ;;
        --pack-timeout)
            need_value $# "$1"
            int_in_range "$2" 1 600 || { err_code bad-argument "--pack-timeout must be an integer between 1 and 600"; usage; exit 2; }
            pack_timeout="$2"; shift 2 ;;
        *) err_code bad-argument "unknown argument: $1"; usage; exit 2 ;;
    esac
done
case "$compress" in
    none | gzip) ;;
    *) err_code bad-argument "--compress must be none or gzip"; usage; exit 2 ;;
esac
case "$output_dir" in
    *[[:cntrl:]]*) err_code bad-argument "paths must not contain control characters"; exit 2 ;;
esac

# --- テスト用の差し替え口（自己テスト専用。サンドボックスの印が無ければ拒否する） ---
host_os=""
gzip_cmd="gzip"
sandbox="${MICROVM_TEST_INITRD_TEST_SANDBOX:-}"
if [ -n "${MICROVM_TEST_INITRD_UNAME_S:-}" ] || [ -n "${MICROVM_TEST_INITRD_GZIP:-}" ]; then
    if [ -z "$sandbox" ] || [ ! -d "$sandbox" ] || [ ! -f "$sandbox/.microvm-test-initrd-selftest" ]; then
        err_code test-seam-refused "test seams are only allowed inside the selftest sandbox"
        exit 2
    fi
    case "${MICROVM_TEST_INITRD_GZIP:-}" in
        "" | "$sandbox"/*) ;;
        *) err_code test-seam-refused "MICROVM_TEST_INITRD_GZIP must be inside the selftest sandbox"; exit 2 ;;
    esac
    host_os="${MICROVM_TEST_INITRD_UNAME_S:-}"
    [ -z "${MICROVM_TEST_INITRD_GZIP:-}" ] || gzip_cmd="$MICROVM_TEST_INITRD_GZIP"
fi
[ -n "$host_os" ] || host_os="$(uname -s)"
case "$host_os" in
    MINGW* | MSYS* | CYGWIN*)
        err_code unsupported-os "Windows hosts are not supported for building the microvm test initrd"
        exit 2
        ;;
esac

# --- 出力先の検査 ---
[ -n "$output_dir" ] || output_dir="$root/target/microvm-test-initrd/x86_64"
case "$output_dir" in
    /*) ;;
    *) output_dir="$PWD/$output_dir" ;;
esac
while [ "${#output_dir}" -gt 1 ] && [ "${output_dir%/}" != "$output_dir" ]; do
    output_dir="${output_dir%/}"
done

private_group_cache=""
group_is_private() { # 自分の primary group が自分専用なら 0（判定できなければ共有扱い。fail-closed）
    if [ -z "$private_group_cache" ]; then
        private_group_cache=no
        if command -v getent >/dev/null 2>&1; then
            local gid user grp_line members pw_out others
            gid="$(id -g)"
            user="$(id -un)"
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
dir_unsafe_reason() { # $1=ディレクトリ。危険なら理由を stdout に出す（sticky ビット付きは他者の名前を消せないため許す）
    local d="$1" self_uid; self_uid="$(id -u)"
    if [ -z "$(find "$d" -prune \( -user "$self_uid" -o -user 0 \) -print 2>/dev/null)" ]; then
        printf 'is owned by another user'
    elif [ -n "$(find "$d" -prune -perm -0002 ! -perm -1000 -print 2>/dev/null)" ]; then
        printf 'is other writable without the sticky bit'
    elif [ -n "$(find "$d" -prune -perm -0020 ! -perm -1000 -print 2>/dev/null)" ]; then
        if ! { group_is_private && [ -n "$(find "$d" -prune -group "$(id -g)" -print 2>/dev/null)" ]; }; then
            printf 'is group writable and the group is shared'
        fi
    fi
}
# 既存の祖先を物理パスで確定し、各祖先を検査する。出力先自体は存在してはならない。
check_output_free() {
    local d="$output_dir" rest="" reason
    if [ -e "$output_dir" ] || [ -L "$output_dir" ]; then
        err_code output-exists "output path already exists; refusing to overwrite"
        exit 2
    fi
    while [ ! -d "$d" ] && [ "$d" != "/" ]; do
        rest="/${d##*/}$rest"
        d="$(dirname "$d")"
    done
    case "$rest" in
        */./* | */../* | */. | */..) err_code bad-output "output path must not contain . or .. components"; exit 2 ;;
    esac
    d="$(cd -P "$d" 2>/dev/null && pwd -P)" || { err_code bad-output "cannot resolve the output directory path"; exit 2; }
    if [ "$d" = "/" ]; then output_dir="$rest"; else output_dir="$d$rest"; fi
    if [ -z "$output_dir" ] || [ "$output_dir" = "/" ]; then
        err_code bad-output "output directory must not be the filesystem root or empty"
        exit 2
    fi
    while :; do
        reason="$(dir_unsafe_reason "$d")"
        if [ -n "$reason" ]; then
            err_code unsafe-output "directory $d $reason; refusing to write there"
            exit 2
        fi
        [ "$d" != "/" ] || break
        d="$(dirname "$d")"
    done
}
check_output_free

sha_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
    sha_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sha_cmd="shasum -a 256"
else
    err_code tool-missing "sha256sum or shasum is required"
    exit 2
fi
if [ "$compress" = "gzip" ]; then
    command -v "$gzip_cmd" >/dev/null 2>&1 || { err_code tool-missing "gzip is required"; exit 2; }
fi

# --- 後始末（自分が作ったディレクトリとファイルだけを消す） ---
work_dir=""
out_created=0
cleanup() {
    local rc=$?
    run_limited_abort
    [ -z "$work_dir" ] || rm -rf "$work_dir"
    if [ "$rc" -ne 0 ] && [ "$out_created" -eq 1 ]; then
        rm -rf -- "$output_dir"
    fi
    release_output_lock
}
trap cleanup EXIT
trap 'exit 143' INT TERM

work_dir="$(mktemp -d)" || { work_dir=""; err_code bad-environment "cannot create a temporary directory"; exit 2; }
RUN_LIMITED_DIR="$work_dir"

acquire_output_lock "$output_dir"
check_output_free
mkdir -m 0700 "$output_dir" 2>/dev/null || { err_code bad-output "cannot create the output directory"; exit 2; }
out_created=1

# --- /init（x86_64 静的 ELF）を組み立てる ---
export LC_ALL=C
bytes() { # 16 進 2 桁の引数を生バイトで書く
    local b
    for b in "$@"; do
        # shellcheck disable=SC2059
        printf "\\$(printf '%03o' "$((16#$b))")"
    done
}
le() { # $1=値 $2=バイト幅。リトルエンディアンで書く
    local v="$1" n="$2"
    while [ "$n" -gt 0 ]; do
        bytes "$(printf '%02x' $((v & 255)))"
        v=$((v >> 8))
        n=$((n - 1))
    done
}
msg_len=$((${#init_message} + 1)) # 末尾の改行を含む
code_off=120                      # ELF ヘッダ 64 + program header 56
load_addr=$((0x400000))
total_size=$((code_off + 50 + msg_len))
elf_file="$work_dir/init"
{
    # ELF ヘッダ: ident（64-bit・LE・version 1・SysV）
    bytes 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
    le 2 2                          # e_type = ET_EXEC
    le 62 2                         # e_machine = x86_64
    le 1 4                          # e_version
    le $((load_addr + code_off)) 8  # e_entry
    le 64 8                         # e_phoff
    le 0 8                          # e_shoff（section header 無し）
    le 0 4                          # e_flags
    le 64 2                         # e_ehsize
    le 56 2                         # e_phentsize
    le 1 2                          # e_phnum
    le 64 2                         # e_shentsize
    le 0 2                          # e_shnum
    le 0 2                          # e_shstrndx
    # program header: PT_LOAD を 1 個（R+X。PT_INTERP 無し）
    le 1 4
    le 5 4
    le 0 8                          # p_offset
    le "$load_addr" 8               # p_vaddr
    le "$load_addr" 8               # p_paddr
    le "$total_size" 8              # p_filesz
    le "$total_size" 8              # p_memsz
    le 4096 8                       # p_align
    # コード（先頭コメントの表と同じ並び）
    bytes b8 01 00 00 00
    bytes bf 01 00 00 00
    bytes 48 8d 35; le 33 4
    bytes ba; le "$msg_len" 4
    bytes 0f 05
    bytes b8; le 169 4
    bytes bf; le $((0xfee1dead)) 4
    bytes be; le $((0x28121969)) 4
    bytes ba; le $((0x01234567)) 4
    bytes 0f 05
    bytes f3 90 eb fc
    printf '%s\n' "$init_message"
} >"$elf_file"

init_size="$(wc -c <"$elf_file" | tr -d ' ')"
magic="$(od -An -tx1 -v -N 4 "$elf_file" | tr -d ' \n')"
if [ "$init_size" != "$total_size" ] || [ "$magic" != "7f454c46" ] || [ "$init_size" -ne 202 ]; then
    err_code internal-error "assembled init has an unexpected size or magic"
    exit 1
fi

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
    newc_header 1 $((8#100755)) "$init_size" 5
    printf 'init\0'
    pad4 $((110 + 5))
    cat "$elf_file"
    pad4 "$init_size"
    newc_header 0 0 0 11
    printf 'TRAILER!!!\0'
    pad4 $((110 + 11))
} >"$cpio_file"

final_file="$cpio_file"
final_name="initrd.cpio"
if [ "$compress" = "gzip" ]; then
    rc=0
    run_limited "$pack_timeout" "$gzip_cmd" -n -9 -c "$cpio_file" >"$work_dir/initrd.cpio.gz" || rc=$?
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

init_sha="$($sha_cmd "$elf_file" | awk '{print $1}')"
initrd_sha="$($sha_cmd "$final_file" | awk '{print $1}')"

# 出力先は自分が 0700 で作った新規ディレクトリなので、中へ直接書く（ロックと 0700 で他者は入れない）。
cp "$final_file" "$output_dir/$final_name" 2>/dev/null || { err_code output-failed "cannot write the initrd"; exit 2; }
{
    printf 'init_sha256=%s\n' "$init_sha"
    printf 'init_bytes=%s\n' "$init_size"
    printf 'initrd_file=%s\n' "$final_name"
    printf 'initrd_sha256=%s\n' "$initrd_sha"
    printf 'compress=%s\n' "$compress"
    printf 'arch=x86_64\n'
    printf 'format=newc\n'
    printf 'message=%s\n' "$init_message"
    printf 'host=%s\n' "$host_os $(uname -m)"
} >"$output_dir/build-info.txt" 2>/dev/null || { err_code output-failed "cannot write build-info.txt"; exit 2; }
out_created=0
info_msg "init sha256=$init_sha bytes=$init_size"
info_msg "initrd sha256=$initrd_sha"
printf '%s\n' "$output_dir/$final_name"
