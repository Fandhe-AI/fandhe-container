#!/usr/bin/env bash
# microVM の実カーネル起動試験用の最小 initrd を作るスクリプト（#3770・MVM-1・TASK-75.5・MS-7）。
#
# 役割: `/init` 1 個だけの cpio（newc 形式）を作る。`/init` はこのスクリプトが固定のバイト列から組む
# 約 200 バイトの静的 ELF（x86_64 が既定、`--arch aarch64` で aarch64 #3895）で、固定文字列を fd 1（/dev/console）へ書いてから
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
#
# /init の機械語（aarch64。#3895。ELF ヘッダは x86_64 と同じ並びで e_machine だけ 183。
# コードは code_off 120 から 60 バイト、メッセージが 180 から 32 バイト、計 212 バイト。
# ファイルに書くのはバイト列の順（ワードの表記ではない）。表のオフセットはコード先頭から）:
#    0: 20 00 80 d2   movz x0, #1          ; fd 1 = /dev/console
#    4: c1 01 00 10   adr  x1, +56         ; メッセージ（オフセット 60）
#    8: 02 04 80 d2   movz x2, #32         ; len
#   12: 08 08 80 d2   movz x8, #64         ; write
#   16: 01 00 00 d4   svc  #0
#   20: a0 d5 9b 52   movz w0, #0xdead
#   24: 20 dc bf 72   movk w0, #0xfee1, lsl #16   ; LINUX_REBOOT_MAGIC1 = 0xfee1dead
#   28: 21 2d 83 52   movz w1, #0x1969
#   32: 41 02 a5 72   movk w1, #0x2812, lsl #16   ; LINUX_REBOOT_MAGIC2 = 0x28121969
#   36: e2 ac 88 52   movz w2, #0x4567
#   40: 62 24 a0 72   movk w2, #0x0123, lsl #16   ; LINUX_REBOOT_CMD_RESTART = 0x01234567
#   44: c8 11 80 d2   movz x8, #142       ; reboot
#   48: 01 00 00 d4   svc  #0
#   52: 3f 20 03 d5   yield               ; reboot が戻ったら終了せず回り続ける（PID 1 の exit は panic）
#   56: ff ff ff 17   b    -4             ; オフセット 52 へ（x86_64 の pause; jmp の対応物。wfi には替えない）
#   60: メッセージ（x86_64 と同じ変数 init_message。改行つき 32 バイト。長さは movz x2 に焼き込み）
# p_vaddr 0x400000 は 64 KiB でも割り切れるので、64 KiB ページの arm64 カーネルでも
# p_vaddr ≡ p_offset (mod PAGE_SIZE) を満たす。p_align は 4096 のまま。
# aarch64 の RESTART の経路（ソース読解の予定。実カーネルでの確認は未実施で、版を固定した file:function の
# 照合は未確認）: reboot syscall（kernel/reboot.c）→ kernel_restart → machine_restart
# （arch/arm64/kernel/process.c）→ do_kernel_restart の restart handler → PSCI の psci_sys_reset
# （drivers/firmware/psci/psci.c。PSCI SYSTEM_RESET を HVC/SMC で呼ぶ）→ KVM の kvm_psci_system_reset
# （arch/arm64/kvm/psci.c）→ KVM_SYSTEM_EVENT_RESET → run->exit_reason = KVM_EXIT_SYSTEM_EVENT で VMM へ戻る。
# 前提: (a) vCPU で PSCI 0.2 以上（KVM_ARM_VCPU_PSCI_0_2）が有効なときだけ成り立つ。PSCI が無いと
# restart handler が無く machine_restart は止まる。有効化と KVM_EXIT_SYSTEM_EVENT の停止理由への分類は #3896 の担当。
# (b) reboot_mode が既定（cold）なら SYSTEM_RESET。warm で SYSTEM_RESET2 を持つ場合は RESET2 になりうる（未確認）。
# (c) arm64 には x86 の `reboot=t` に当たるものが無く、上の x86_64 の cmdline の説明は流用しない。
# aarch64 の結合試験と cmdline は crates/microvm/tests/kernel_boot.rs の arm64 モジュール（#3897）が持つ。
#
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
# 機械語（aarch64。#3947。全体は 120 + 224 + 145 = 489 バイト。llvm-mc で組んで llvm-objdump の逆アセンブルと
# 一致することを確認済み。ワードはリトルエンディアンの順でファイルへ書く。x86_64 との違い: mkdir・open が
# 無いので mkdirat(34)・openat(56) を AT_FDCWD（-100）で呼ぶ。mount 40・read 63・write 64・reboot 142。
# sp は 16 バイト境界を保つ（sub sp, sp, #512）。sentinel はデータの先頭（ファイルオフセット 344。8 バイト境界）に置き
# ldp で 16 バイトずつ 2 回比べる）。コードは 120 から 224 バイトで、データは 344 から:
#   sentinel(32) "/dev\0"(5) "devtmpfs\0"(9) "/dev/vda\0"(9) 一致メッセージ+改行(42) 不一致メッセージ+改行(48)
# 命令の並びは下の aarch64 の分岐の各 `bytes` 行のコメントを正とする（表の二重管理をしない）。
#
# variant `net-tx`（#3894・MVM-1・REPAIR-12）: virtio-net の TX（ゲストからホストへの送信）を照合する版。
# AF_PACKET の raw socket を開いて `eth0` を IFF_UP にし、固定の Ethernet フレーム（60 バイト）を 1 回 `sendto` する。
# 戻り値がフレーム長（60）なら成功メッセージ、それ以外（socket・ioctl・sendto の失敗、短い送信）は失敗メッセージを
# fd 1 へ書いてから reboot する。sendto の成功は qdisc が捨てた場合も 60 を返しうるため、届いた証跡は
# ホスト側の backend が受けたバイト列の照合（試験側）で取る。`eth0` という名前に依存する（udev が無く `eth%d` のまま）。
# 送信から marker・reboot の間に待ちを入れない: ホストの TX は QueueNotify の MMIO exit の中で同期に backend へ
# 届く経路で、ゲストでも sendto が戻る前に dev_queue_xmit が走るため。
# 構造体: ifreq は 40 バイト（ifr_name[16] の後、+16 に ifr_ifindex / ifr_flags）、sockaddr_ll は 20 バイト
# （family 2・protocol 2〔network byte order〕・ifindex 4・残り 12 は 0）。定数: socket=41・ioctl=16・sendto=44、
# SIOCGIFINDEX=0x8933・SIOCSIFFLAGS=0x8914、AF_PACKET=17・SOCK_RAW=3・IFF_UP=1。
# IFF_UP だけを渡すので IFF_MULTICAST 等は落ちるが、送信には影響しない（意図した単純化）。
# 機械語（x86_64。ELF ヘッダ・program header は既定の版と同じ 120 バイト。表のオフセットはコード先頭から。
# 全体は 120 + 239 + 132 = 491 バイト。GNU as 2.46 で組んだ逆アセンブルと一致することを確認済み）:
#    0: mov eax,41 ; mov edi,17 ; mov esi,3 ; xor edx,edx ; syscall   ; socket(AF_PACKET, SOCK_RAW, 0)
#   19: test rax,rax ; js fail（near）; mov r12d,eax                   ; fd を r12d へ
#   31: sub rsp,64 ; mov rdi,rsp ; xor eax,eax ; mov ecx,64 ; cld ; rep stosb  ; 作業域（スタック）を 0 埋め
#   48: mov dword [rsp],0x30687465                                       ; "eth0"
#   55: mov eax,16 ; mov edi,r12d ; mov esi,0x8933 ; mov rdx,rsp ; syscall ; SIOCGIFINDEX
#   73: test rax,rax ; js fail ; mov r13d,[rsp+16]                       ; ifindex を r13d へ
#   83: mov dword [rsp+16],1                                             ; ifr_flags = IFF_UP
#   91: mov eax,16 ; mov edi,r12d ; mov esi,0x8914 ; mov rdx,rsp ; syscall ; SIOCSIFFLAGS
#  109: test rax,rax ; js fail
#  114: mov word [rsp+40],17 ; mov word [rsp+42],0xb588 ; mov [rsp+44],r13d ; sockaddr_ll
#  133: mov eax,44 ; mov edi,r12d ; lea rsi,[rip+0x5b] ; mov edx,60 ; xor r10d,r10d ; lea r8,[rsp+40] ; mov r9d,20 ; syscall
#  169: cmp rax,60 ; jne fail ; lea rsi,[rip+0x75]（成功）; mov edx,34 ; jmp write
#  189: fail: lea rsi,[rip+0x89] ; mov edx,38
#  201: write: mov eax,1 ; mov edi,1 ; syscall
#  213: reboot の末尾（既定の版と同じ並び）、235: pause ; jmp 235
#  239: データ: フレーム(60) 成功メッセージ+改行(34) 失敗メッセージ+改行(38)
#
# variant `net-rx`（#3919・MVM-1・REPAIR-12）: virtio-net の RX（ホストからゲストへの受信）を照合する版。
# AF_PACKET の raw socket（protocol は htons(0x88B6)）を開き、`eth0` を IFF_UP にして、SO_RCVTIMEO（5 秒）を設定し、
# `recvfrom` で受ける。受けたフレームが固定の 60 バイトと完全一致なら成功メッセージ、期限切れ・syscall の失敗・
# 不一致が 16 回続いたときは失敗メッセージを fd 1 へ書いてから reboot する。ホスト側は backend に積んだフレームを
# 受信ポーラー（NetRxPoller）が DRIVER_OK の後に渡す（試験側 kernel_boot.rs）。`eth0` という名前に依存する。
# 待ちの上限（REPAIR-5）: 期限切れ（EAGAIN）は 1 回で失敗にする。ループ回数が数えるのは、EtherType は一致したが
# 内容が違うフレームだけ。期限切れでも続けると 16 x 5 秒で試験の期限（60 秒）を超え、陰性対照が毎回落ちるため。
# bind はしない（protocol の指定で EtherType は絞られ、SIOCGIFINDEX は不要）。宛先 MAC は eth0 の MAC（kernel_boot.rs の
# NET_MAC）なので PACKET_HOST で届く。構造体: ifreq は 40 バイト（+16 に ifr_flags）、timeval は 16 バイト。
# 定数: socket=41・ioctl=16・setsockopt=54・recvfrom=45、SIOCSIFFLAGS=0x8914、SOL_SOCKET=1・SO_RCVTIMEO=20。
# 作業域（スタック 192 バイト）: [0..40) ifreq / [48..64) timeval / [64..192) 受信バッファ 128（先頭 64 バイトを 0 埋め）。
# 機械語（x86_64。ELF ヘッダ・program header は既定の版と同じ 120 バイト。全体は 120 + 272 + 132 = 524 バイト。
# GNU as で組んだ逆アセンブルと一致することを確認済み。表のオフセットはコード先頭から）:
#    0: socket(17, 3, 0xb688) ; test ; js fail（near）; mov r12d,eax
#   34: sub rsp,192 ; rep stosb（64 バイト 0 埋め）; "eth0" ; ifr_flags = 1 ; ioctl(SIOCSIFFLAGS) ; js fail
#   92: tv_sec = 5 ; setsockopt(fd, 1, 20, rsp+48, 16) ; js fail ; r14d = 16
#  142: recv: recvfrom(fd, rsp+64, 128, 0, 0, 0) ; js fail ; cmp rax,60 ; jne next ; repe cmpsb（frame）; je ok
#  203: next: dec r14d ; jnz recv ; 208: fail（lea rsi,failmsg ; edx=38）; 222: ok（edx=34）; 234: write
#  246: reboot の末尾（既定の版と同じ並び）、268: pause ; jmp 268
#  272: データ: フレーム(60) 成功メッセージ+改行(34) 失敗メッセージ+改行(38)
#
# 使い方:
#   build-microvm-test-initrd.sh [--variant default|block-read|net-tx|net-rx] [--arch x86_64|aarch64] [--output-dir <dir>] [--compress none|gzip] [--pack-timeout S]
#   各引数は同名の環境変数（MICROVM_TEST_INITRD_VARIANT・MICROVM_TEST_INITRD_ARCH・MICROVM_TEST_INITRD_OUTPUT_DIR・MICROVM_TEST_INITRD_COMPRESS）でも渡せる。CLI が優先。
#   --variant       default（既定。固定文字列を書いて reboot するだけの版）・block-read・net-tx・net-rx（上記。net-tx・net-rx は x86_64 のみ。block-read は aarch64 も #3947）
#   --arch          x86_64（既定）または aarch64（#3895。別名は受けない。aarch64 は default と block-read の variant。出力先の既定は target/microvm-test-initrd/aarch64-block-read）
#   --output-dir    既定: <repo>/target/microvm-test-initrd/<arch>（block-read は x86_64-block-read、net-tx は x86_64-net-tx、net-rx は x86_64-net-rx）（存在しない新規ディレクトリのみ。既存は拒否）
#   --compress      none（既定。initrd.cpio）または gzip（initrd.cpio.gz。カーネルは CONFIG_RD_GZIP=y が要る）
#   --pack-timeout  gzip の上限秒（既定 60。1〜600。REPAIR-5）
#
# 安全性: root・sudo・ネットワークを使わない。外部入力のファイルは無い。出力先は不可分に `mkdir -m 0700` で
# 作り、既存（空・symlink を含む）は上書きせず拒否する。出力先の祖先が他者に書き換え可能なら拒否する
# （build-guest-initrd.sh の検査を簡略化して写した）。生成した ELF はホストでは実行しない。
# 範囲: x86_64 と aarch64 の生成。aarch64 の microVM ブートの結合試験は kernel_boot.rs の arm64 モジュール（#3897。シリアルの MMIO は #3898 で結線済み）。
# 実カーネルでの起動は未確認（Agent は実行していない）で、実機での確認は #3781（人間担当）。
#
# 終了コード: 0 成功（stdout に initrd の絶対パスを 1 行）/ 1 内部エラー・gzip 失敗 / 2 引数・環境・出力先不正、
#   Windows ホスト / 3 gzip の期限切れ。エラーは stderr に `error: code=<code> message=<英語>` の 1 行。
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: build-microvm-test-initrd.sh [--variant default|block-read|net-tx|net-rx] [--arch x86_64|aarch64] [--output-dir <dir>] [--compress none|gzip] [--pack-timeout S]
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
arch="${MICROVM_TEST_INITRD_ARCH:-x86_64}"
compress="${MICROVM_TEST_INITRD_COMPRESS:-none}"
pack_timeout=60
init_message="fandhe-microvm-test: init ok v1"
# block-read の文字列定数（正本。crates/microvm/tests/kernel_boot.rs の単体テストが行頭の名前で抜き出して照合する。
# 長さ 32・41・47 は機械語へ固定されているため、変えるときはコードの長さ・変位も直す）
block_sentinel="fandhe-microvm-block-sentinel-01"
block_ok_message="fandhe-microvm-test: block sentinel ok v1"
block_mismatch_message="fandhe-microvm-test: block sentinel mismatch v1"
# net-tx の文字列定数（正本。kernel_boot.rs の単体テストが行頭の名前で抜き出して照合する。
# フレームは宛先 02:fc:00:00:38:66・送信元 02:fc:00:00:38:65（kernel_boot.rs の NET_MAC）・EtherType 0x88B5
# （IEEE 802 Local Experimental。ゲストにハンドラが無い）・ペイロード 46 バイトで、最小長 60 バイト。
# 機械語の sockaddr_ll の即値 0xb588 は htons(0x88B5) で、ヘッダ hex の 25〜28 文字目 88b5 と結びつく）
net_tx_frame_header_hex="02fc0000386602fc0000386588b5"
net_tx_payload="fandhe-microvm-net-tx-payload-0123456789abcdef"
net_tx_ok_message="fandhe-microvm-test: net tx ok v1"
net_tx_failed_message="fandhe-microvm-test: net tx failed v1"
# net-rx の文字列定数（正本。kernel_boot.rs の単体テストが行頭の名前で抜き出して照合する。
# フレームは宛先 02:fc:00:00:38:65（ゲストの NET_MAC）・送信元 02:fc:00:00:38:66・EtherType 0x88B6
# （IEEE 802 Local Experimental 2。net-tx の 0x88B5 と分け、TX のフレームが socket に入らないようにする）・
# ペイロード 46 バイトで 60 バイト。機械語の socket の protocol の即値 0xb688 は htons(0x88B6) で、
# ヘッダ hex の 25〜28 文字目 88b6 と結びつく）
net_rx_frame_header_hex="02fc0000386502fc0000386688b6"
net_rx_payload="fandhe-microvm-net-rx-payload-0123456789abcdef"
net_rx_ok_message="fandhe-microvm-test: net rx ok v1"
net_rx_failed_message="fandhe-microvm-test: net rx failed v1"

need_value() {
    [ "$1" -ge 2 ] || { err_code bad-argument "$2 requires a value"; usage; exit 2; }
}
while [ $# -gt 0 ]; do
    case "$1" in
        --variant) need_value $# "$1"; variant="$2"; shift 2 ;;
        --output-dir) need_value $# "$1"; output_dir="$2"; shift 2 ;;
        --arch) need_value $# "$1"; arch="$2"; shift 2 ;;
        --compress) need_value $# "$1"; compress="$2"; shift 2 ;;
        --pack-timeout)
            need_value $# "$1"
            int_in_range "$2" 1 600 || { err_code bad-argument "--pack-timeout must be an integer between 1 and 600"; usage; exit 2; }
            pack_timeout="$2"; shift 2 ;;
        *) err_code bad-argument "unknown argument: $1"; usage; exit 2 ;;
    esac
done
case "$arch" in
    x86_64 | aarch64) ;;
    *) err_code bad-argument "--arch must be x86_64 or aarch64"; usage; exit 2 ;;
esac
case "$variant" in
    default | block-read | net-tx | net-rx) ;;
    *) err_code bad-argument "--variant must be default, block-read, net-tx or net-rx"; usage; exit 2 ;;
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
if { [ "$variant" = "net-tx" ] || [ "$variant" = "net-rx" ]; } && [ "$arch" != "x86_64" ]; then
    err_code bad-argument "--variant $variant is only available for --arch x86_64"; exit 2
fi
if [ -z "$output_dir" ]; then
    case "$variant" in
        block-read | net-tx | net-rx) output_dir="$root/target/microvm-test-initrd/${arch}-${variant}" ;;
        *) output_dir="$root/target/microvm-test-initrd/$arch" ;;
    esac
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

# --- /init（静的 ELF。arch ごと）を組み立てる ---
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
if [ "$arch" = "aarch64" ]; then
    e_machine=183
else
    e_machine=62
fi
elf_file="$work_dir/init"

# ELF ヘッダ + program header（両 variant 共通。$1=ファイル全体のバイト数）
emit_elf_headers() {
    local total_size="$1"
    # ELF ヘッダ: ident（64-bit・LE・version 1・SysV）
    bytes 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
    le 2 2                          # e_type = ET_EXEC
    le "$e_machine" 2               # e_machine（x86_64 = 62・aarch64 = 183）
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

if [ "$variant" = "net-rx" ]; then
    # 機械語に固定された長さ・サイズ・EtherType を文字列定数と突き合わせる（fail-closed）
    expected_size=524
    if [ "${#net_rx_frame_header_hex}" -ne 28 ] || [ "${#net_rx_payload}" -ne 46 ] ||
        [ "$((${#net_rx_ok_message} + 1))" -ne 34 ] || [ "$((${#net_rx_failed_message} + 1))" -ne 38 ] ||
        [ "${net_rx_frame_header_hex:24:4}" != "88b6" ]; then
        err_code internal-error "net-rx string lengths do not match the encoded instructions"
        exit 1
    fi
    total_size=$expected_size
    {
        emit_elf_headers "$total_size"
        # コード 272 バイト（先頭コメントの表と同じ並び）
        bytes b8; le 41 4                                  # mov eax, 41 (socket)
        bytes bf; le 17 4                                  # mov edi, 17 (AF_PACKET)
        bytes be; le 3 4                                   # mov esi, 3 (SOCK_RAW)
        bytes ba; le $((0xb688)) 4                         # mov edx, htons(0x88B6)
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 0f 88; le 177 4                              # js fail (near)
        bytes 41 89 c4                                     # mov r12d, eax
        bytes 48 81 ec; le 192 4                           # sub rsp, 192
        bytes 48 89 e7                                     # mov rdi, rsp
        bytes 31 c0                                        # xor eax, eax
        bytes b9; le 64 4                                  # mov ecx, 64
        bytes fc                                           # cld
        bytes f3 aa                                        # rep stosb
        bytes c7 04 24; le $((0x30687465)) 4               # mov dword [rsp], "eth0"
        bytes c7 44 24 10; le 1 4                          # mov dword [rsp+16], 1 (IFF_UP)
        bytes b8; le 16 4                                  # mov eax, 16 (ioctl)
        bytes 44 89 e7                                     # mov edi, r12d
        bytes be; le $((0x8914)) 4                         # mov esi, SIOCSIFFLAGS
        bytes 48 89 e2                                     # mov rdx, rsp
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 78 74                                        # js fail
        bytes c7 44 24 30; le 5 4                          # mov dword [rsp+48], 5 (tv_sec)
        bytes b8; le 54 4                                  # mov eax, 54 (setsockopt)
        bytes 44 89 e7                                     # mov edi, r12d
        bytes be; le 1 4                                   # mov esi, 1 (SOL_SOCKET)
        bytes ba; le 20 4                                  # mov edx, 20 (SO_RCVTIMEO)
        bytes 4c 8d 54 24 30                               # lea r10, [rsp+48]
        bytes 41 b8; le 16 4                               # mov r8d, 16
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 78 48                                        # js fail
        bytes 41 be; le 16 4                               # mov r14d, 16
        bytes b8; le 45 4                                  # recv: mov eax, 45 (recvfrom)
        bytes 44 89 e7                                     # mov edi, r12d
        bytes 48 8d 74 24 40                               # lea rsi, [rsp+64]
        bytes ba; le 128 4                                 # mov edx, 128
        bytes 45 31 d2                                     # xor r10d, r10d
        bytes 45 31 c0                                     # xor r8d, r8d
        bytes 45 31 c9                                     # xor r9d, r9d
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 78 20                                        # js fail (期限切れを含む負値)
        bytes 48 83 f8 3c                                  # cmp rax, 60
        bytes 75 15                                        # jne next
        bytes 48 8d 74 24 40                               # lea rsi, [rsp+64]
        bytes 48 8d 3d; le 78 4                            # lea rdi, [rip+0x4e] -> frame
        bytes b9; le 60 4                                  # mov ecx, 60
        bytes f3 a6                                        # repe cmpsb
        bytes 74 13                                        # je ok
        bytes 41 ff ce                                     # next: dec r14d
        bytes 75 be                                        # jnz recv
        bytes 48 8d 35; le 151 4                           # fail: lea rsi, [rip+0x97] -> failed message
        bytes ba; le 38 4                                  # mov edx, 38
        bytes eb 0c                                        # jmp write
        bytes 48 8d 35; le 103 4                           # ok: lea rsi, [rip+0x67] -> ok message
        bytes ba; le 34 4                                  # mov edx, 34
        bytes b8; le 1 4                                   # write: mov eax, 1
        bytes bf; le 1 4                                   # mov edi, 1
        bytes 0f 05                                        # syscall
        emit_reboot_tail
        # データ: フレーム 60 バイト（ヘッダ 14 + ペイロード 46）、成功・失敗メッセージ
        for ((i = 0; i < ${#net_rx_frame_header_hex}; i += 2)); do
            bytes "${net_rx_frame_header_hex:i:2}"
        done
        printf '%s' "$net_rx_payload"
        printf '%s\n' "$net_rx_ok_message"
        printf '%s\n' "$net_rx_failed_message"
    } >"$elf_file"
elif [ "$variant" = "net-tx" ]; then
    # 機械語に固定された長さ・サイズ・EtherType を文字列定数と突き合わせる（fail-closed）
    expected_size=491
    if [ "${#net_tx_frame_header_hex}" -ne 28 ] || [ "${#net_tx_payload}" -ne 46 ] ||
        [ "$((${#net_tx_ok_message} + 1))" -ne 34 ] || [ "$((${#net_tx_failed_message} + 1))" -ne 38 ] ||
        [ "${net_tx_frame_header_hex:24:4}" != "88b5" ]; then
        err_code internal-error "net-tx string lengths do not match the encoded instructions"
        exit 1
    fi
    total_size=$expected_size
    {
        emit_elf_headers "$total_size"
        # コード 239 バイト（先頭コメントの表と同じ並び）
        bytes b8; le 41 4                                  # mov eax, 41 (socket)
        bytes bf; le 17 4                                  # mov edi, 17 (AF_PACKET)
        bytes be; le 3 4                                   # mov esi, 3 (SOCK_RAW)
        bytes 31 d2                                        # xor edx, edx
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 0f 88; le 161 4                              # js fail (near)
        bytes 41 89 c4                                     # mov r12d, eax
        bytes 48 83 ec 40                                  # sub rsp, 64
        bytes 48 89 e7                                     # mov rdi, rsp
        bytes 31 c0                                        # xor eax, eax
        bytes b9; le 64 4                                  # mov ecx, 64
        bytes fc                                           # cld
        bytes f3 aa                                        # rep stosb
        bytes c7 04 24; le $((0x30687465)) 4               # mov dword [rsp], "eth0"
        bytes b8; le 16 4                                  # mov eax, 16 (ioctl)
        bytes 44 89 e7                                     # mov edi, r12d
        bytes be; le $((0x8933)) 4                         # mov esi, SIOCGIFINDEX
        bytes 48 89 e2                                     # mov rdx, rsp
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 78 6f                                        # js fail
        bytes 44 8b 6c 24 10                               # mov r13d, [rsp+16]
        bytes c7 44 24 10; le 1 4                          # mov dword [rsp+16], 1 (IFF_UP)
        bytes b8; le 16 4                                  # mov eax, 16 (ioctl)
        bytes 44 89 e7                                     # mov edi, r12d
        bytes be; le $((0x8914)) 4                         # mov esi, SIOCSIFFLAGS
        bytes 48 89 e2                                     # mov rdx, rsp
        bytes 0f 05                                        # syscall
        bytes 48 85 c0                                     # test rax, rax
        bytes 78 4b                                        # js fail
        bytes 66 c7 44 24 28; le 17 2                      # mov word [rsp+40], 17 (sll_family)
        bytes 66 c7 44 24 2a; le $((0xb588)) 2             # mov word [rsp+42], htons(0x88B5)
        bytes 44 89 6c 24 2c                               # mov [rsp+44], r13d (sll_ifindex)
        bytes b8; le 44 4                                  # mov eax, 44 (sendto)
        bytes 44 89 e7                                     # mov edi, r12d
        bytes 48 8d 35; le 91 4                            # lea rsi, [rip+0x5b] -> frame
        bytes ba; le 60 4                                  # mov edx, 60
        bytes 45 31 d2                                     # xor r10d, r10d
        bytes 4c 8d 44 24 28                               # lea r8, [rsp+40]
        bytes 41 b9; le 20 4                               # mov r9d, 20
        bytes 0f 05                                        # syscall
        bytes 48 83 f8 3c                                  # cmp rax, 60
        bytes 75 0e                                        # jne fail
        bytes 48 8d 35; le 117 4                           # lea rsi, [rip+0x75] -> ok message
        bytes ba; le 34 4                                  # mov edx, 34
        bytes eb 0c                                        # jmp write
        bytes 48 8d 35; le 137 4                           # fail: lea rsi, [rip+0x89] -> failed message
        bytes ba; le 38 4                                  # mov edx, 38
        bytes b8; le 1 4                                   # write: mov eax, 1
        bytes bf; le 1 4                                   # mov edi, 1
        bytes 0f 05                                        # syscall
        emit_reboot_tail
        # データ: フレーム 60 バイト（ヘッダ 14 + ペイロード 46）、成功・失敗メッセージ
        for ((i = 0; i < ${#net_tx_frame_header_hex}; i += 2)); do
            bytes "${net_tx_frame_header_hex:i:2}"
        done
        printf '%s' "$net_tx_payload"
        printf '%s\n' "$net_tx_ok_message"
        printf '%s\n' "$net_tx_failed_message"
    } >"$elf_file"
elif [ "$variant" = "block-read" ]; then
    # 機械語に固定された長さ・サイズを文字列定数と突き合わせる（fail-closed）
    if [ "$arch" = "aarch64" ]; then expected_size=489; else expected_size=448; fi
    if [ "${#block_sentinel}" -ne 32 ] || [ "$((${#block_ok_message} + 1))" -ne 42 ] ||
        [ "$((${#block_mismatch_message} + 1))" -ne 48 ]; then
        err_code internal-error "block-read string lengths do not match the encoded instructions"
        exit 1
    fi
    total_size=$expected_size
    {
        emit_elf_headers "$total_size"
        if [ "$arch" = "aarch64" ]; then
            bytes 60 0c 80 92  # movn x0, #99 (AT_FDCWD)
            bytes e1 07 00 10  # adr x1, "/dev"
            bytes a2 3d 80 d2  # mov x2, #0755
            bytes 48 04 80 d2  # mov x8, #34 (mkdirat)
            bytes 01 00 00 d4  # svc #0
            bytes 80 07 00 30  # adr x0, "devtmpfs"
            bytes 41 07 00 10  # adr x1, "/dev"
            bytes e2 03 00 aa  # mov x2, x0
            bytes e3 03 1f aa  # mov x3, xzr
            bytes e4 03 1f aa  # mov x4, xzr
            bytes 08 05 80 d2  # mov x8, #40 (mount)
            bytes 01 00 00 d4  # svc #0
            bytes 60 0c 80 92  # movn x0, #99
            bytes c1 06 00 50  # adr x1, "/dev/vda"
            bytes e2 03 1f aa  # mov x2, xzr (O_RDONLY)
            bytes 08 07 80 d2  # mov x8, #56 (openat)
            bytes 01 00 00 d4  # svc #0
            bytes 00 03 f8 b7  # tbnz x0, #63, fail
            bytes ff 03 08 d1  # sub sp, sp, #512
            bytes e1 03 00 91  # mov x1, sp
            bytes 02 40 80 d2  # mov x2, #512
            bytes e8 07 80 d2  # mov x8, #63 (read)
            bytes 01 00 00 d4  # svc #0
            bytes 1f 00 08 f1  # cmp x0, #512
            bytes 21 02 00 54  # b.ne fail
            bytes e3 03 00 10  # adr x3, sentinel
            bytes e4 17 40 a9  # ldp x4, x5, [sp]
            bytes 66 1c 40 a9  # ldp x6, x7, [x3]
            bytes 9f 00 06 eb  # cmp x4, x6
            bytes 81 01 00 54  # b.ne fail
            bytes bf 00 07 eb  # cmp x5, x7
            bytes 41 01 00 54  # b.ne fail
            bytes e4 17 41 a9  # ldp x4, x5, [sp, #16]
            bytes 66 1c 41 a9  # ldp x6, x7, [x3, #16]
            bytes 9f 00 06 eb  # cmp x4, x6
            bytes c1 00 00 54  # b.ne fail
            bytes bf 00 07 eb  # cmp x5, x7
            bytes 81 00 00 54  # b.ne fail
            bytes e1 03 00 70  # adr x1, ok message
            bytes 42 05 80 d2  # mov x2, #42
            bytes 03 00 00 14  # b write
            bytes e1 04 00 30  # fail: adr x1, mismatch message
            bytes 02 06 80 d2  # mov x2, #48
            bytes 20 00 80 d2  # write: mov x0, #1
            bytes 08 08 80 d2  # mov x8, #64 (write)
            bytes 01 00 00 d4  # svc #0
            bytes a0 d5 9b 52  # movz w0, #0xdead
            bytes 20 dc bf 72  # movk w0, #0xfee1, lsl #16
            bytes 21 2d 83 52  # movz w1, #0x1969
            bytes 41 02 a5 72  # movk w1, #0x2812, lsl #16
            bytes e2 ac 88 52  # movz w2, #0x4567
            bytes 62 24 a0 72  # movk w2, #0x0123, lsl #16
            bytes c8 11 80 d2  # mov x8, #142 (reboot)
            bytes 01 00 00 d4  # svc #0
            bytes 3f 20 03 d5  # yield
            bytes ff ff ff 17  # b -4
            printf '%s' "$block_sentinel"
            printf '/dev\0'
            printf 'devtmpfs\0'
            printf '/dev/vda\0'
            printf '%s\n' "$block_ok_message"
            printf '%s\n' "$block_mismatch_message"
        else
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
        fi
    } >"$elf_file"
else
    msg_len=$((${#init_message} + 1)) # 末尾の改行を含む
    if [ "$arch" = "aarch64" ]; then
        # movz x2, #32 に長さを焼き込んでいるため、メッセージ長が変わったら fail-closed にする
        [ "$msg_len" -eq 32 ] || { err_code internal-error "init message length must be 32 for aarch64"; exit 1; }
        expected_size=212
        total_size=$((code_off + 60 + msg_len))
    else
        expected_size=202
        total_size=$((code_off + 50 + msg_len))
    fi
    {
        emit_elf_headers "$total_size"
        # コード（先頭コメントの表と同じ並び）
        if [ "$arch" = "aarch64" ]; then
            bytes 20 00 80 d2  # movz x0, #1
            bytes c1 01 00 10  # adr x1, +56
            bytes 02 04 80 d2  # movz x2, #32
            bytes 08 08 80 d2  # movz x8, #64（write）
            bytes 01 00 00 d4  # svc #0
            bytes a0 d5 9b 52  # movz w0, #0xdead
            bytes 20 dc bf 72  # movk w0, #0xfee1, lsl #16
            bytes 21 2d 83 52  # movz w1, #0x1969
            bytes 41 02 a5 72  # movk w1, #0x2812, lsl #16
            bytes e2 ac 88 52  # movz w2, #0x4567
            bytes 62 24 a0 72  # movk w2, #0x0123, lsl #16
            bytes c8 11 80 d2  # movz x8, #142（reboot）
            bytes 01 00 00 d4  # svc #0
            bytes 3f 20 03 d5  # yield
            bytes ff ff ff 17  # b -4
        else
            bytes b8 01 00 00 00
            bytes bf 01 00 00 00
            bytes 48 8d 35; le 33 4
            bytes ba; le "$msg_len" 4
            bytes 0f 05
            emit_reboot_tail
        fi
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
    printf 'arch=%s\n' "$arch"
    printf 'format=newc\n'
    printf 'variant=%s\n' "$variant"
    case "$variant" in
        block-read)
            printf 'sentinel=%s\n' "$block_sentinel"
            printf 'message_match=%s\n' "$block_ok_message"
            printf 'message_mismatch=%s\n' "$block_mismatch_message"
            ;;
        net-tx)
            printf 'frame_hex=%s%s\n' "$net_tx_frame_header_hex" "$(printf '%s' "$net_tx_payload" | od -An -tx1 -v | tr -d ' \n')"
            printf 'message_ok=%s\n' "$net_tx_ok_message"
            printf 'message_failed=%s\n' "$net_tx_failed_message"
            ;;
        net-rx)
            printf 'frame_hex=%s%s\n' "$net_rx_frame_header_hex" "$(printf '%s' "$net_rx_payload" | od -An -tx1 -v | tr -d ' \n')"
            printf 'message_ok=%s\n' "$net_rx_ok_message"
            printf 'message_failed=%s\n' "$net_rx_failed_message"
            printf 'recv_timeout_secs=5\n'
            printf 'recv_attempts=16\n'
            ;;
        *) printf 'message=%s\n' "$init_message" ;;
    esac
    printf 'host=%s\n' "$host_os $(uname -m)"
} >"$output_dir/build-info.txt" 2>/dev/null || { err_code output-failed "cannot write build-info.txt"; exit 2; }
out_created=0
info_msg "init sha256=$init_sha bytes=$init_size"
info_msg "initrd sha256=$initrd_sha"
printf '%s\n' "$output_dir/$final_name"
