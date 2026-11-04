#!/usr/bin/env bash
# scripts/build-microvm-test-initrd.sh の自己テスト（#3770・MVM-1・REPAIR-12）。
#
# 呼び出し元: Makefile の `microvm-test-initrd-build-selftest` と CI の platform-ci（3 OS）。
# 一時ディレクトリとスタブの gzip だけを使い、ネットワーク・root・実カーネルは使わない。生成した ELF は実行しない。
# newc の解析は外部 cpio に頼らず自前で行う（GNU / BSD の差を避ける）。
# ゴールデンの sha256 は init の機械語・メッセージを意図して変えたときだけ更新し、理由をここに書く。
# 出力は `ok:` / `FAIL:` / `skip:` と最終行の `pass=N fail=M`。1 件でも FAIL なら終了コード 1。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="$script_dir/build-microvm-test-initrd.sh"
export LC_ALL=C

unset MICROVM_TEST_INITRD_OUTPUT_DIR MICROVM_TEST_INITRD_COMPRESS MICROVM_TEST_INITRD_UNAME_S \
    MICROVM_TEST_INITRD_GZIP MICROVM_TEST_INITRD_TEST_SANDBOX MICROVM_TEST_INITRD_VARIANT

# 初版（#3770）のゴールデン。
golden_init_sha="c7341f1857b739c9d1ac119fde214592ba12e2f12eaa02409b0f31f1262ccdcf"
golden_initrd_sha="324915663a384b3f2e253f78bdcfa8526a519544131f887ecfb18232ae7c12a7"
# variant block-read の初版（#3889）のゴールデン。コードは GNU as で組んだ逆アセンブルと一致を確認済み。
golden_block_init_sha="8a21ae7ca097222b72ca8b74d6ba6c21b3b2a70d4bea00aa4218fe97f81671aa"
golden_block_initrd_sha="3d700a7c4b52449c364c7422022c2b7875bf0622565b88f68f8d04abb4051de2"
# block-read のコード 183 バイト（ファイル先頭から 120 バイト目）
golden_block_code="b853000000488d3dab000000beed0100000f05b8a5000000488d3d9d000000488d35910000004889fa4531d24531c00f05b802000000488d3d8800000031f60f054885c0783f4881ec0002000089c731c04889e6ba000200000f05483d000200007522488d3d640000004889e6b920000000fcf3a6750e488d3570000000ba2a000000eb0c488d358c000000ba30000000b801000000bf010000000f05b8a9000000bfaddee1febe69191228ba674523010f05f390ebfc"

# variant net-tx の初版（#3894）のゴールデン。コードは GNU as 2.46 で組んだ逆アセンブルと一致を確認済み。
golden_net_tx_init_sha="751575eaa3b4feaf421b422e0f93ad2e9060cec964d22a7ea13ea8c3e83502de"
golden_net_tx_initrd_sha="482003aae76b19e9cb401b51372644f0db25783df1614d33df60183bbf654a48"
# net-tx のコード 239 バイト（ファイル先頭から 120 バイト目）
golden_net_tx_code="b829000000bf11000000be0300000031d20f054885c00f88a10000004189c44883ec404889e731c0b940000000fcf3aac7042465746830b8100000004489e7be338900004889e20f054885c0786f448b6c2410c744241001000000b8100000004489e7be148900004889e20f054885c0784b66c7442428110066c744242a88b544896c242cb82c0000004489e7488d355b000000ba3c0000004531d24c8d44242841b9140000000f054883f83c750e488d3575000000ba22000000eb0c488d3589000000ba26000000b801000000bf010000000f05b8a9000000bfaddee1febe69191228ba674523010f05f390ebfc"
# net-tx のフレーム 60 バイト（ヘッダ 14 + ペイロード 46）
golden_net_tx_frame="02fc0000386602fc0000386588b566616e6468652d6d6963726f766d2d6e65742d74782d7061796c6f61642d30313233343536373839616263646566"

sb="$(mktemp -d)"
trap 'rm -rf "$sb"' EXIT
touch "$sb/.microvm-test-initrd-selftest"
sb="$(cd -P "$sb" && pwd -P)"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1"; }
ng() { fail=$((fail + 1)); echo "FAIL: $1"; }
check() { # $1=名前 $2=期待 $3=実際
    if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (expected '$2' got '$3')"; fi
}
sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
hexat() { od -An -tx1 -v -j "$2" -N "$3" "$1" | tr -d ' \n'; }
# リトルエンディアンの数値を 10 進で返す。$1=ファイル $2=オフセット $3=幅
leat() {
    local h i v=0
    h="$(hexat "$1" "$2" "$3")"
    i=$(($3 - 1))
    while [ "$i" -ge 0 ]; do
        v=$((v * 256 + 16#${h:$((i * 2)):2}))
        i=$((i - 1))
    done
    echo "$v"
}
# newc を一覧する。出力: 名前 mode uid gid filesize。末尾が 4 バイト境界でなければ "unaligned" を出す。
list_newc() {
    local f="$1" off=0 total hdr namesize filesize name
    total="$(wc -c <"$f" | tr -d ' ')"
    while [ "$off" -lt "$total" ]; do
        hdr="$(tail -c +$((off + 1)) "$f" | head -c 110)"
        [ "${hdr:0:6}" = "070701" ] || { echo "bad-magic@$off"; return 1; }
        filesize=$((16#${hdr:54:8}))
        namesize=$((16#${hdr:94:8}))
        name="$(tail -c +$((off + 111)) "$f" | head -c "$namesize" | tr -d '\0')"
        printf '%s %s %s %s %s\n' "$name" "${hdr:14:8}" "${hdr:22:8}" "${hdr:30:8}" "$filesize"
        off=$(((off + 110 + namesize + 3) / 4 * 4))
        if [ "$name" = "TRAILER!!!" ]; then
            [ "$off" -eq "$total" ] || echo "unaligned"
            return 0
        fi
        off=$(((off + filesize + 3) / 4 * 4))
    done
    echo "no-trailer"
}

rc=0
run() {
    rc=0
    env MICROVM_TEST_INITRD_TEST_SANDBOX="$sb" "$@" >"$sb/o.out" 2>"$sb/o.err" || rc=$?
}
errcode() { grep -o 'code=[a-z-]*' "$sb/o.err" | head -n 1 | sed 's/^code=//' || true; }
n=0
newout() { n=$((n + 1)); out="$sb/out-$n"; }

# --- Windows（Git Bash）では拒否の契約だけを実ホストで照合して終える ---
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
        newout
        run "$target" --output-dir "$out"
        check "win exit code" 2 "$rc"
        check "win error code" unsupported-os "$(errcode)"
        newout
        run "$target" --variant block-read --output-dir "$out"
        check "win block-read refused" "2 unsupported-os" "$rc $(errcode)"
        newout
        run "$target" --variant net-tx --output-dir "$out"
        check "win net-tx refused" "2 unsupported-os" "$rc $(errcode)"
        echo "pass=$pass fail=$fail"
        [ "$fail" -eq 0 ]
        exit $?
        ;;
esac

# --- 1: 既定（無圧縮）の成功 ---
newout
run "$target" --output-dir "$out"
check "1 exit code" 0 "$rc"
check "1 stdout is the initrd path" "$out/initrd.cpio" "$(cat "$sb/o.out")"
check "1 output files" "build-info.txt initrd.cpio" "$(find "$out" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | tr '\n' ' ' | sed 's/ $//')"
if [ -n "$(find "$out" -maxdepth 0 -perm 0700 -print)" ]; then ok "1 output dir mode is 0700"; else ng "1 output dir mode is not 0700"; fi
check "1 lock released" "no" "$([ -e "$out.lock" ] && echo yes || echo no)"
cpio="$out/initrd.cpio"

# --- 2: newc の構造 ---
check "2 entries" "init 000081ed 00000000 00000000 202
TRAILER!!! 00000000 00000000 00000000 0" "$(list_newc "$cpio")"
init="$sb/init.bin"
tail -c +$((110 + 5 + 1 + 1)) "$cpio" | head -c 202 >"$init"
check "2 init size" 202 "$(wc -c <"$init" | tr -d ' ')"

# --- 3: ELF のフィールド ---
check "3 magic class data" "7f454c460201" "$(hexat "$init" 0 6)"
check "3 e_type" 2 "$(leat "$init" 16 2)"
check "3 e_machine" 62 "$(leat "$init" 18 2)"
check "3 e_entry" $((0x400078)) "$(leat "$init" 24 8)"
check "3 e_phoff" 64 "$(leat "$init" 32 8)"
check "3 e_shoff" 0 "$(leat "$init" 40 8)"
check "3 e_phentsize" 56 "$(leat "$init" 54 2)"
check "3 e_phnum" 1 "$(leat "$init" 56 2)"
check "3 p_type is PT_LOAD (no PT_INTERP)" 1 "$(leat "$init" 64 4)"
check "3 p_flags R+X" 5 "$(leat "$init" 68 4)"
check "3 p_offset" 0 "$(leat "$init" 72 8)"
check "3 p_vaddr" $((0x400000)) "$(leat "$init" 80 8)"
check "3 p_filesz" 202 "$(leat "$init" 96 8)"
check "3 p_memsz" 202 "$(leat "$init" 104 8)"
check "3 mov eax,1 / mov edi,1" "b801000000bf01000000" "$(hexat "$init" 120 10)"
check "3 lea rsi,[rip+33]" "488d3521000000" "$(hexat "$init" 130 7)"
check "3 mov edx,32 ; syscall" "ba200000000f05" "$(hexat "$init" 137 7)"
check "3 reboot args" "b8a9000000bfaddee1febe69191228ba67452301" "$(hexat "$init" 144 20)"
check "3 syscall ; pause ; jmp -4" "0f05f390ebfc" "$(hexat "$init" 164 6)"
check "3 message" "fandhe-microvm-test: init ok v1" "$(tail -c +171 "$init" | head -c 31)"
check "3 message newline" "0a" "$(hexat "$init" 201 1)"

# --- 4: ゴールデンと build-info ---
check "4 init sha256" "$golden_init_sha" "$(sha_of "$init")"
check "4 initrd sha256" "$golden_initrd_sha" "$(sha_of "$cpio")"
check "4 build-info" "init_sha256=$golden_init_sha
init_bytes=202
initrd_file=initrd.cpio
initrd_sha256=$golden_initrd_sha
compress=none
arch=x86_64
format=newc
variant=default
message=fandhe-microvm-test: init ok v1" "$(grep -v '^host=' "$out/build-info.txt")"

# --- 5: 決定性 ---
newout
run "$target" --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$cpio"; then ok "5 second run is byte-identical"; else ng "5 second run differs"; fi

# --- 6: gzip ---
if command -v gzip >/dev/null 2>&1; then
    newout
    run "$target" --output-dir "$out" --compress gzip
    check "6 exit code" 0 "$rc"
    if gzip -dc "$out/initrd.cpio.gz" | cmp -s - "$cpio"; then ok "6 gunzip equals the plain archive"; else ng "6 gunzip differs"; fi
else
    echo "skip: gzip is not available (case 6)"
fi

# --- 7: 既存の出力先は拒否 ---
newout
mkdir "$out"
chmod 700 "$out"
run "$target" --output-dir "$out"
check "7 empty existing dir exit code" 2 "$rc"
check "7 empty existing dir code" output-exists "$(errcode)"
printf 'KEEP' >"$out/keep"
run "$target" --output-dir "$out"
check "7 non-empty existing exit code" 2 "$rc"
check "7 existing file untouched" "KEEP" "$(cat "$out/keep")"
newout
mkdir "$sb/real-dir"
ln -s "$sb/real-dir" "$out"
run "$target" --output-dir "$out"
check "7 symlink exit code" 2 "$rc"
check "7 symlink target untouched" "" "$(ls -A "$sb/real-dir")"

# --- 8: 祖先が other 書き込み可で sticky 無し ---
newout
mkdir "$sb/open"
chmod 777 "$sb/open"
if [ "$(id -u)" -eq 0 ]; then
    echo "skip: running as root, chmod based case 8 is not meaningful"
elif [ -n "$(find "$sb/open" -maxdepth 0 -perm -0002 -print)" ]; then
    run "$target" --output-dir "$sb/open/sub"
    check "8 exit code" 2 "$rc"
    check "8 error code" unsafe-output "$(errcode)"
    check "8 nothing created" "" "$(ls -A "$sb/open")"
else
    echo "skip: cannot make a directory other-writable (case 8)"
fi

# --- 9: 引数の検査 ---
newout
run "$target" --bogus
check "9 unknown arg" "2 bad-argument" "$rc $(errcode)"
run "$target" --output-dir
check "9 missing value" "2 bad-argument" "$rc $(errcode)"
run "$target" --output-dir "$out" --compress xz
check "9 bad compress" "2 bad-argument" "$rc $(errcode)"
run "$target" --output-dir "$out" --pack-timeout 601
check "9 pack-timeout range" "2 bad-argument" "$rc $(errcode)"
run "$target" --output-dir "$(printf '%s/a\001b' "$sb")"
check "9 control char" "2 bad-argument" "$rc $(errcode)"
check "9 nothing created" "no" "$([ -e "$out" ] && echo yes || echo no)"

# --- 10: 差し替え口 ---
newout
rc=0
MICROVM_TEST_INITRD_UNAME_S=Linux "$target" --output-dir "$out" >"$sb/o.out" 2>"$sb/o.err" || rc=$?
check "10 seam outside sandbox" "2 test-seam-refused" "$rc $(errcode)"
run env MICROVM_TEST_INITRD_UNAME_S=MINGW64_NT-10.0 "$target" --output-dir "$out"
check "10 windows host refused" "2 unsupported-os" "$rc $(errcode)"
check "10 nothing created" "no" "$([ -e "$out" ] && echo yes || echo no)"

# --- 11: スタブ gzip の失敗 ---
newout
printf '#!/bin/sh\nexit 7\n' >"$sb/gzip-fail"
chmod +x "$sb/gzip-fail"
run env MICROVM_TEST_INITRD_GZIP="$sb/gzip-fail" "$target" --output-dir "$out" --compress gzip
check "11 gzip failure" "1 pack-failed" "$rc $(errcode)"
check "11 output removed" "no" "$([ -e "$out" ] && echo yes || echo no)"
check "11 lock removed" "no" "$([ -e "$out.lock" ] && echo yes || echo no)"

# --- 12: スタブ gzip のハング ---
newout
printf '#!/bin/sh\nsleep 30\n' >"$sb/gzip-hang"
chmod +x "$sb/gzip-hang"
run env MICROVM_TEST_INITRD_GZIP="$sb/gzip-hang" "$target" --output-dir "$out" --compress gzip --pack-timeout 1
check "12 gzip timeout" "3 pack-timeout" "$rc $(errcode)"
check "12 output removed" "no" "$([ -e "$out" ] && echo yes || echo no)"
check "12 lock removed" "no" "$([ -e "$out.lock" ] && echo yes || echo no)"
sleep 1
if pgrep -f "$sb/gzip-hang" >/dev/null 2>&1; then ng "12 stub process left behind"; else ok "12 no stub process left"; fi

# --- 13: variant block-read（#3889） ---
newout
run "$target" --variant block-read --output-dir "$out"
check "13 exit code" 0 "$rc"
check "13 stdout is the initrd path" "$out/initrd.cpio" "$(cat "$sb/o.out")"
bcpio="$out/initrd.cpio"
check "13 entries" "init 000081ed 00000000 00000000 448
TRAILER!!! 00000000 00000000 00000000 0" "$(list_newc "$bcpio")"
binit="$sb/init-block.bin"
tail -c +$((110 + 5 + 1 + 1)) "$bcpio" | head -c 448 >"$binit"
check "13 init size" 448 "$(wc -c <"$binit" | tr -d ' ')"
check "13 magic class data" "7f454c460201" "$(hexat "$binit" 0 6)"
check "13 e_type" 2 "$(leat "$binit" 16 2)"
check "13 e_machine" 62 "$(leat "$binit" 18 2)"
check "13 e_entry" $((0x400078)) "$(leat "$binit" 24 8)"
check "13 e_phoff" 64 "$(leat "$binit" 32 8)"
check "13 e_phnum" 1 "$(leat "$binit" 56 2)"
check "13 p_type is PT_LOAD" 1 "$(leat "$binit" 64 4)"
check "13 p_flags R+X" 5 "$(leat "$binit" 68 4)"
check "13 p_vaddr" $((0x400000)) "$(leat "$binit" 80 8)"
check "13 p_filesz" 448 "$(leat "$binit" 96 8)"
check "13 p_memsz" 448 "$(leat "$binit" 104 8)"
check "13 code (183 bytes)" "$golden_block_code" "$(hexat "$binit" 120 183)"
check "13 data /dev" "2f64657600" "$(hexat "$binit" 303 5)"
check "13 data devtmpfs" "646576746d70667300" "$(hexat "$binit" 308 9)"
check "13 data /dev/vda" "2f6465762f76646100" "$(hexat "$binit" 317 9)"
check "13 sentinel" "fandhe-microvm-block-sentinel-01" "$(tail -c +327 "$binit" | head -c 32)"
check "13 match message" "fandhe-microvm-test: block sentinel ok v1" "$(tail -c +359 "$binit" | head -c 41)"
check "13 match message newline" "0a" "$(hexat "$binit" 399 1)"
check "13 mismatch message" "fandhe-microvm-test: block sentinel mismatch v1" "$(tail -c +401 "$binit" | head -c 47)"
check "13 mismatch message newline" "0a" "$(hexat "$binit" 447 1)"
check "13 init sha256" "$golden_block_init_sha" "$(sha_of "$binit")"
check "13 initrd sha256" "$golden_block_initrd_sha" "$(sha_of "$bcpio")"
check "13 build-info" "init_sha256=$golden_block_init_sha
init_bytes=448
initrd_file=initrd.cpio
initrd_sha256=$golden_block_initrd_sha
compress=none
arch=x86_64
format=newc
variant=block-read
sentinel=fandhe-microvm-block-sentinel-01
message_match=fandhe-microvm-test: block sentinel ok v1
message_mismatch=fandhe-microvm-test: block sentinel mismatch v1" "$(grep -v '^host=' "$out/build-info.txt")"
newout
run "$target" --variant block-read --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$bcpio"; then ok "13 second run is byte-identical"; else ng "13 second run differs"; fi
if command -v gzip >/dev/null 2>&1; then
    newout
    run "$target" --variant block-read --output-dir "$out" --compress gzip
    check "13 gzip exit code" 0 "$rc"
    if gzip -dc "$out/initrd.cpio.gz" | cmp -s - "$bcpio"; then ok "13 gunzip equals the plain archive"; else ng "13 gunzip differs"; fi
else
    echo "skip: gzip is not available (case 13 gzip)"
fi

# --- 14: variant の選択（既定の版は不変・環境変数・CLI の優先・不正値） ---
newout
run "$target" --variant default --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$cpio"; then ok "14 explicit default is byte-identical to the implicit one"; else ng "14 explicit default differs"; fi
newout
run env MICROVM_TEST_INITRD_VARIANT=block-read "$target" --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$bcpio"; then ok "14 env variant selects block-read"; else ng "14 env variant ignored"; fi
newout
run env MICROVM_TEST_INITRD_VARIANT=block-read "$target" --variant default --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$cpio"; then ok "14 CLI variant wins over env"; else ng "14 CLI variant did not win"; fi
newout
run "$target" --variant bogus --output-dir "$out"
check "14 bad variant" "2 bad-argument" "$rc $(errcode)"
run env MICROVM_TEST_INITRD_VARIANT=bogus "$target" --output-dir "$out"
check "14 bad env variant" "2 bad-argument" "$rc $(errcode)"
check "14 nothing created" "no" "$([ -e "$out" ] && echo yes || echo no)"
newout
run env MICROVM_TEST_INITRD_UNAME_S=MINGW64_NT-10.0 "$target" --variant block-read --output-dir "$out"
check "14 windows host refused for block-read" "2 unsupported-os" "$rc $(errcode)"

# --- 19: variant net-tx（#3894） ---
newout
run "$target" --variant net-tx --output-dir "$out"
check "19 exit code" 0 "$rc"
check "19 stdout is the initrd path" "$out/initrd.cpio" "$(cat "$sb/o.out")"
ncpio="$out/initrd.cpio"
check "19 entries" "init 000081ed 00000000 00000000 491
TRAILER!!! 00000000 00000000 00000000 0" "$(list_newc "$ncpio")"
ninit="$sb/init-net-tx.bin"
tail -c +$((110 + 5 + 1 + 1)) "$ncpio" | head -c 491 >"$ninit"
check "19 init size" 491 "$(wc -c <"$ninit" | tr -d ' ')"
check "19 magic class data" "7f454c460201" "$(hexat "$ninit" 0 6)"
check "19 e_type" 2 "$(leat "$ninit" 16 2)"
check "19 e_machine" 62 "$(leat "$ninit" 18 2)"
check "19 e_entry" $((0x400078)) "$(leat "$ninit" 24 8)"
check "19 e_phoff" 64 "$(leat "$ninit" 32 8)"
check "19 e_phnum" 1 "$(leat "$ninit" 56 2)"
check "19 p_type is PT_LOAD" 1 "$(leat "$ninit" 64 4)"
check "19 p_flags R+X" 5 "$(leat "$ninit" 68 4)"
check "19 p_vaddr" $((0x400000)) "$(leat "$ninit" 80 8)"
check "19 p_filesz" 491 "$(leat "$ninit" 96 8)"
check "19 p_memsz" 491 "$(leat "$ninit" 104 8)"
check "19 code (239 bytes)" "$golden_net_tx_code" "$(hexat "$ninit" 120 239)"
check "19 sockaddr_ll protocol htons(0x88B5)" "66c7442428110066c744242a88b5" "$(hexat "$ninit" 234 14)"
check "19 frame (60 bytes)" "$golden_net_tx_frame" "$(hexat "$ninit" 359 60)"
check "19 ok message" "fandhe-microvm-test: net tx ok v1" "$(tail -c +420 "$ninit" | head -c 33)"
check "19 ok message newline" "0a" "$(hexat "$ninit" 452 1)"
check "19 failed message" "fandhe-microvm-test: net tx failed v1" "$(tail -c +454 "$ninit" | head -c 37)"
check "19 failed message newline" "0a" "$(hexat "$ninit" 490 1)"
check "19 init sha256" "$golden_net_tx_init_sha" "$(sha_of "$ninit")"
check "19 initrd sha256" "$golden_net_tx_initrd_sha" "$(sha_of "$ncpio")"
check "19 build-info" "init_sha256=$golden_net_tx_init_sha
init_bytes=491
initrd_file=initrd.cpio
initrd_sha256=$golden_net_tx_initrd_sha
compress=none
arch=x86_64
format=newc
variant=net-tx
frame_hex=$golden_net_tx_frame
message_ok=fandhe-microvm-test: net tx ok v1
message_failed=fandhe-microvm-test: net tx failed v1" "$(grep -v '^host=' "$out/build-info.txt")"
newout
run "$target" --variant net-tx --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$ncpio"; then ok "19 second run is byte-identical"; else ng "19 second run differs"; fi
if command -v gzip >/dev/null 2>&1; then
    newout
    run "$target" --variant net-tx --output-dir "$out" --compress gzip
    check "19 gzip exit code" 0 "$rc"
    if gzip -dc "$out/initrd.cpio.gz" | cmp -s - "$ncpio"; then ok "19 gunzip equals the plain archive"; else ng "19 gunzip differs"; fi
else
    echo "skip: gzip is not available (case 19 gzip)"
fi

# --- 20: net-tx の選択（環境変数・CLI の優先・Windows の拒否） ---
newout
run env MICROVM_TEST_INITRD_VARIANT=net-tx "$target" --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$ncpio"; then ok "20 env variant selects net-tx"; else ng "20 env variant ignored"; fi
newout
run env MICROVM_TEST_INITRD_VARIANT=net-tx "$target" --variant default --output-dir "$out"
if cmp -s "$out/initrd.cpio" "$cpio"; then ok "20 CLI variant wins over env"; else ng "20 CLI variant did not win"; fi
newout
run env MICROVM_TEST_INITRD_UNAME_S=MINGW64_NT-10.0 "$target" --variant net-tx --output-dir "$out"
check "20 windows host refused for net-tx" "2 unsupported-os" "$rc $(errcode)"

echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
