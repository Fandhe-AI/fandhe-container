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
# variant `block-read`（#3889・MVM-1・REPAIR-12）: virtio-blk の読み出しをゲスト側から照合する版。
# /dev に devtmpfs をマウントして `/dev/vda` の先頭 512 バイトを読み、先頭 32 バイトが sentinel と
# 一致したときだけ一致メッセージを、それ以外（open・read の失敗、短い読み、不一致）は不一致メッセージを
# fd 1 へ書いてから reboot する。virtio-blk の major 番号は固定せず devtmpfs 経由で開く。
# 機械語（x86_64。ELF ヘッダ・program header は既定の版と同じ 120 バイト。表のオフセットはコード先頭から。
# 全体は 120 + 328 = 448 バイト。GNU as で組んだ逆アセンブルと一致することを確認済み）:
#    0: b8 53 00 00 00            mov eax, 83         ; mkdir
#    5: 48 8d 3d ab 00 00 00      lea rdi, [rip+0xab] ; "/dev"（0xb7）
#   12: be ed 01 00 00            mov esi, 0755
#   17: 0f 05                     syscall             ; 戻り値は見ない（組み込み initramfs が /dev を持てば EEXIST）
#   19: b8 a5 00 00 00            mov eax, 165        ; mount
#   24: 48 8d 3d 9d 00 00 00      lea rdi, [rip+0x9d] ; source = "devtmpfs"（0xbc）
#   31: 48 8d 35 91 00 00 00      lea rsi, [rip+0x91] ; target = "/dev"
#   38: 48 89 fa                  mov rdx, rdi        ; fstype = "devtmpfs"
#   41: 45 31 d2                  xor r10d, r10d      ; flags 0
#   44: 45 31 c0                  xor r8d, r8d        ; data NULL
#   47: 0f 05                     syscall             ; 戻り値は見ない（EBUSY 等でも次の open の成否で判定する）
#   49: b8 02 00 00 00            mov eax, 2          ; open
#   54: 48 8d 3d 88 00 00 00      lea rdi, [rip+0x88] ; "/dev/vda"（0xc5）
#   61: 31 f6                     xor esi, esi        ; O_RDONLY
#   63: 0f 05                     syscall
#   65: 48 85 c0                  test rax, rax
#   68: 78 3f                     js 133              ; open 失敗 → fail
#   70: 48 81 ec 00 02 00 00      sub rsp, 512        ; 読み込み先はスタック（PT_LOAD は R+X のため）
#   77: 89 c7                     mov edi, eax        ; fd
#   79: 31 c0                     xor eax, eax        ; read
#   81: 48 89 e6                  mov rsi, rsp
#   84: ba 00 02 00 00            mov edx, 512
#   89: 0f 05                     syscall
#   91: 48 3d 00 02 00 00         cmp rax, 512
#   97: 75 22                     jne 133             ; 短い読み・失敗 → fail
#   99: 48 8d 3d 64 00 00 00      lea rdi, [rip+0x64] ; sentinel（0xce）
#  106: 48 89 e6                  mov rsi, rsp
#  109: b9 20 00 00 00            mov ecx, 32         ; sentinel の長さ
#  114: fc                        cld
#  115: f3 a6                     repe cmpsb
#  117: 75 0e                     jne 133             ; 不一致 → fail
#  119: 48 8d 35 70 00 00 00      lea rsi, [rip+0x70] ; 一致メッセージ（0xee）
#  126: ba 2a 00 00 00            mov edx, 42
#  131: eb 0c                     jmp 145
#  133: 48 8d 35 8c 00 00 00      lea rsi, [rip+0x8c] ; fail: 不一致メッセージ（0x118）
#  140: ba 30 00 00 00            mov edx, 48
#  145: b8 01 00 00 00            mov eax, 1          ; write
#  150: bf 01 00 00 00            mov edi, 1          ; fd 1（/dev を覆う前にカーネルが開いた /dev/console）
#  155: 0f 05                     syscall
#  157: b8 a9 00 00 00            mov eax, 169        ; reboot（既定の版と同じ並び）
#  162: bf ad de e1 fe            mov edi, 0xfee1dead
#  167: be 69 19 12 28            mov esi, 0x28121969
#  172: ba 67 45 23 01            mov edx, 0x01234567
#  177: 0f 05                     syscall
#  179: f3 90                     pause
#  181: eb fc                     jmp 179
#  183: データ: "/dev\0"(5) "devtmpfs\0"(9) "/dev/vda\0"(9) sentinel(32) 一致メッセージ+改行(42) 不一致メッセージ+改行(48)
# sentinel は先頭 32 バイトだけを比べる。試験側（crates/microvm/tests/kernel_boot.rs）が backend の offset 0 に置く。
# 510〜511 に 0x55AA を置かないので MBR とは解釈されない。
#
# 使い方:
#   build-microvm-test-initrd.sh [--variant default|block-read] [--output-dir <dir>] [--compress none|gzip] [--pack-timeout S]
#   各引数は同名の環境変数（MICROVM_TEST_INITRD_VARIANT・MICROVM_TEST_INITRD_OUTPUT_DIR・MICROVM_TEST_INITRD_COMPRESS）でも渡せる。CLI が優先。
#   --variant       default（既定。固定文字列を書いて reboot するだけの版）または block-read（上記）
#   --output-dir    既定: <repo>/target/microvm-test-initrd/x86_64（block-read は x86_64-block-read）（存在しない新規ディレクトリのみ。既存は拒否）
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
usage: build-microvm-test-initrd.sh [--variant default|block-read] [--output-dir <dir>] [--compress none|gzip] [--pack-timeout S]
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
# lib.sh は source 時に cwd をリポジトリルートへ移すため、利用者の相対パスのために元の cwd へ戻す。
caller_pwd="$PWD"
# shellcheck source=lib.sh
source "$root/scripts/lib.sh"
cd -- "$caller_pwd" || { err_code bad-environment "cannot return to the working directory"; exit 2; }

variant="${MICROVM_TEST_INITRD_VARIANT:-default}"
output_dir="${MICROVM_TEST_INITRD_OUTPUT_DIR:-}"
compress="${MICROVM_TEST_INITRD_COMPRESS:-none}"
pack_timeout=60
init_message="fandhe-microvm-test: init ok v1"
# block-read の文字列定数（正本。crates/microvm/tests/kernel_boot.rs の単体テストが行頭の名前で抜き出して照合する。
# 長さ 32・41・47 は機械語へ固定されているため、変えるときはコードの長さ・変位も直す）
block_sentinel="fandhe-microvm-block-sentinel-01"
block_ok_message="fandhe-microvm-test: block sentinel ok v1"
block_mismatch_message="fandhe-microvm-test: block sentinel mismatch v1"

need_value() {
    [ "$1" -ge 2 ] || { err_code bad-argument "$2 requires a value"; usage; exit 2; }
}
while [ $# -gt 0 ]; do
    case "$1" in
        --variant) need_value $# "$1"; variant="$2"; shift 2 ;;
        --output-dir) need_value $# "$1"; output_dir="$2"; shift 2 ;;
        --compress) need_value $# "$1"; compress="$2"; shift 2 ;;
        --pack-timeout)
            need_value $# "$1"
            int_in_range "$2" 1 600 || { err_code bad-argument "--pack-timeout must be an integer between 1 and 600"; usage; exit 2; }
            pack_timeout="$2"; shift 2 ;;
        *) err_code bad-argument "unknown argument: $1"; usage; exit 2 ;;
    esac
done
case "$variant" in
    default | block-read) ;;
    *) err_code bad-argument "--variant must be default or block-read"; usage; exit 2 ;;
esac
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
if [ -z "$output_dir" ]; then
    if [ "$variant" = "block-read" ]; then
        output_dir="$root/target/microvm-test-initrd/x86_64-block-read"
    else
        output_dir="$root/target/microvm-test-initrd/x86_64"
    fi
fi
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
code_off=120                      # ELF ヘッダ 64 + program header 56
load_addr=$((0x400000))
elf_file="$work_dir/init"

# ELF ヘッダ + program header（両 variant 共通。$1=ファイル全体のバイト数）
emit_elf_headers() {
    local total_size="$1"
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
}

# reboot(RESTART) と停止ループ（両 variant 共通の末尾）
emit_reboot_tail() {
    bytes b8; le 169 4
    bytes bf; le $((0xfee1dead)) 4
    bytes be; le $((0x28121969)) 4
    bytes ba; le $((0x01234567)) 4
    bytes 0f 05
    bytes f3 90 eb fc
}

if [ "$variant" = "block-read" ]; then
    # 機械語に固定された長さ・サイズを文字列定数と突き合わせる（fail-closed）
    expected_size=448
    if [ "${#block_sentinel}" -ne 32 ] || [ "$((${#block_ok_message} + 1))" -ne 42 ] ||
        [ "$((${#block_mismatch_message} + 1))" -ne 48 ]; then
        err_code internal-error "block-read string lengths do not match the encoded instructions"
        exit 1
    fi
    total_size=$expected_size
    {
        emit_elf_headers "$total_size"
        # コード 183 バイト（先頭コメントの表と同じ並び）
        bytes b8; le 83 4                                  # mov eax, 83 (mkdir)
        bytes 48 8d 3d; le 171 4                           # lea rdi, [rip+0xab] -> "/dev"
        bytes be; le $((0755)) 4                           # mov esi, 0755
        bytes 0f 05                                        # syscall
        bytes b8; le 165 4                                 # mov eax, 165 (mount)
        bytes 48 8d 3d; le 157 4                           # lea rdi, [rip+0x9d] -> "devtmpfs"
        bytes 48 8d 35; le 145 4                           # lea rsi, [rip+0x91] -> "/dev"
        bytes 48 89 fa                                     # mov rdx, rdi
        bytes 45 31 d2                                     # xor r10d, r10d
        bytes 45 31 c0                                     # xor r8d, r8d
        bytes 0f 05                                        # syscall
        bytes b8; le 2 4                                   # mov eax, 2 (open)
        bytes 48 8d 3d; le 136 4                           # lea rdi, [rip+0x88] -> "/dev/vda"
        bytes 31 f6                                        # xor esi, esi (O_RDONLY)
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 78 3f                                        # js fail
        bytes 48 81 ec; le 512 4                           # sub rsp, 512
        bytes 89 c7                                        # mov edi, eax
        bytes 31 c0                                        # xor eax, eax (read)
        bytes 48 89 e6                                     # mov rsi, rsp
        bytes ba; le 512 4                                 # mov edx, 512
        bytes 0f 05                                        # syscall
        bytes 48 3d; le 512 4                              # cmp rax, 512
        bytes 75 22                                        # jne fail
        bytes 48 8d 3d; le 100 4                           # lea rdi, [rip+0x64] -> sentinel
        bytes 48 89 e6                                     # mov rsi, rsp
        bytes b9; le 32 4                                  # mov ecx, 32
        bytes fc                                           # cld
        bytes f3 a6                                        # repe cmpsb
        bytes 75 0e                                        # jne fail
        bytes 48 8d 35; le 112 4                           # lea rsi, [rip+0x70] -> ok message
        bytes ba; le 42 4                                  # mov edx, 42
        bytes eb 0c                                        # jmp write
        bytes 48 8d 35; le 140 4                           # fail: lea rsi, [rip+0x8c] -> mismatch message
        bytes ba; le 48 4                                  # mov edx, 48
        bytes b8; le 1 4                                   # write: mov eax, 1
        bytes bf; le 1 4                                   # mov edi, 1
        bytes 0f 05                                        # syscall
        emit_reboot_tail
        # データ
        printf '/dev\0'
        printf 'devtmpfs\0'
        printf '/dev/vda\0'
        printf '%s' "$block_sentinel"
        printf '%s\n' "$block_ok_message"
        printf '%s\n' "$block_mismatch_message"
    } >"$elf_file"
else
    expected_size=202
    msg_len=$((${#init_message} + 1)) # 末尾の改行を含む
    total_size=$((code_off + 50 + msg_len))
    {
        emit_elf_headers "$total_size"
        # コード（先頭コメントの表と同じ並び）
        bytes b8 01 00 00 00
        bytes bf 01 00 00 00
        bytes 48 8d 35; le 33 4
        bytes ba; le "$msg_len" 4
        bytes 0f 05
        emit_reboot_tail
        printf '%s\n' "$init_message"
    } >"$elf_file"
fi

init_size="$(wc -c <"$elf_file" | tr -d ' ')"
magic="$(od -An -tx1 -v -N 4 "$elf_file" | tr -d ' \n')"
if [ "$init_size" != "$total_size" ] || [ "$magic" != "7f454c46" ] || [ "$init_size" -ne "$expected_size" ]; then
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
    printf 'variant=%s\n' "$variant"
    if [ "$variant" = "block-read" ]; then
        printf 'sentinel=%s\n' "$block_sentinel"
        printf 'message_match=%s\n' "$block_ok_message"
        printf 'message_mismatch=%s\n' "$block_mismatch_message"
    else
        printf 'message=%s\n' "$init_message"
    fi
    printf 'host=%s\n' "$host_os $(uname -m)"
} >"$output_dir/build-info.txt" 2>/dev/null || { err_code output-failed "cannot write build-info.txt"; exit 2; }
out_created=0
info_msg "init sha256=$init_sha bytes=$init_size"
info_msg "initrd sha256=$initrd_sha"
printf '%s\n' "$output_dir/$final_name"
