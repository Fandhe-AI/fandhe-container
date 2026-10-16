#!/usr/bin/env bash
# scripts/build-guest-initrd.sh の自己テスト（TASK-64 追補・#1878・MAC-1・REPAIR-12）。
#
# 呼び出し元: Makefile の `guest-initrd-build-selftest`（CI の platform-ci から 3 OS で実行）。
# 疑似 aarch64 静的 ELF の fixture とスタブ cargo だけを使い、ネットワーク・root・secrets・
# 実 cargo ビルドは使わない。cpio は外部 cpio コマンドに頼らず、本ファイル内の newc パーサで読む。
# 照合内容: 中身が `init` と `TRAILER!!!` だけであること、入力の拒否、既存出力の非上書き、期限切れ。
# 終了コード: 全件合格で 0、1 件でも失敗すれば 1。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="$script_dir/build-guest-initrd.sh"

for v in GUEST_INITRD_OUTPUT_DIR GUEST_INITRD_INIT GUEST_INITRD_COMPRESS GUEST_INITRD_LINKER \
    GUEST_INITRD_CARGO GUEST_INITRD_UNAME_S GUEST_INITRD_EXPECT_UID GUEST_INITRD_PRIVATE_GROUP \
    GUEST_INITRD_TEST_SANDBOX; do
    unset "$v"
done

sb="$(mktemp -d)"
trap 'rm -rf "$sb"' EXIT
: >"$sb/.guest-initrd-selftest"

pass=0
fail=0
ok() {
    pass=$((pass + 1))
    printf 'ok: %s\n' "$1"
}
ng() {
    fail=$((fail + 1))
    printf 'FAIL: %s\n' "$1" >&2
}
check() { # $1=名前 $2=期待 $3=実際
    if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (expected '$2', got '$3')"; fi
}
skip() {
    printf 'skip: case %s\n' "$1"
}

# --- fixture: 疑似 aarch64 静的 ELF（64 バイトのヘッダ + 56 バイトの program header 1 個 + 識別用の末尾） ---
# $1=出力 $2=e_type（16 進 2 桁。02=ET_EXEC） $3=e_machine（16 進 2 桁。b7=aarch64） $4=p_type（16 進 2 桁。01=PT_LOAD）
mk_elf() {
    {
        printf '\x7f\x45\x4c\x46\x02\x01\x01'
        head -c 9 /dev/zero
        printf '%b' "\\x$2\\x00\\x$3\\x00\\x01\\x00\\x00\\x00"
        head -c 8 /dev/zero
        printf '\x40\x00\x00\x00\x00\x00\x00\x00'
        head -c 8 /dev/zero
        head -c 4 /dev/zero
        printf '\x40\x00\x38\x00\x01\x00'
        head -c 6 /dev/zero
        printf '%b' "\\x$4\\x00\\x00\\x00"
        head -c 52 /dev/zero
        printf 'FANDHE-FIXTURE-PAYLOAD\n'
    } >"$1"
}
good="$sb/init-good"
mk_elf "$good" 02 b7 01
chmod 755 "$good"
good_size="$(wc -c <"$good" | tr -d ' ')"
good_sha=""
if command -v sha256sum >/dev/null 2>&1; then good_sha="$(sha256sum "$good" | awk '{print $1}')"; else good_sha="$(shasum -a 256 "$good" | awk '{print $1}')"; fi

# --- スタブ cargo ---
# $1=名前 $2=本体（CARGO_TARGET_DIR を受け取る）。サンドボックス内に作る。
mk_stub() {
    printf '#!/usr/bin/env bash\n%s\n' "$2" >"$sb/$1"
    chmod 755 "$sb/$1"
}
rel='aarch64-unknown-linux-musl/release'
mk_stub cargo-ok "mkdir -p \"\$CARGO_TARGET_DIR/$rel\" && cp '$good' \"\$CARGO_TARGET_DIR/$rel/fandhe-container-guest-init\""
mk_elf "$sb/elf-interp" 02 b7 03
mk_stub cargo-interp "mkdir -p \"\$CARGO_TARGET_DIR/$rel\" && cp '$sb/elf-interp' \"\$CARGO_TARGET_DIR/$rel/fandhe-container-guest-init\""
mk_stub cargo-fail 'echo stub-cargo-failed >&2; exit 7'
mk_stub cargo-hang "sleep 300 & echo \$! >'$sb/hang.pid'; wait"

# --- newc パーサ（外部 cpio に頼らない）。出力: 1 エントリ 1 行 "name mode uid gid filesize" ---
list_newc() {
    local f="$1" off=0 total hdr magic namesize filesize name mode uid gid
    total="$(wc -c <"$f" | tr -d ' ')"
    while [ "$off" -lt "$total" ]; do
        hdr="$(tail -c +$((off + 1)) "$f" | head -c 110)"
        magic="${hdr:0:6}"
        [ "$magic" = "070701" ] || { echo "bad-magic@$off"; return 1; }
        mode="${hdr:14:8}"
        uid="${hdr:22:8}"
        gid="${hdr:30:8}"
        filesize=$((16#${hdr:54:8}))
        namesize=$((16#${hdr:94:8}))
        name="$(tail -c +$((off + 111)) "$f" | head -c "$namesize" | tr -d '\0')"
        printf '%s %s %s %s %s\n' "$name" "$mode" "$uid" "$gid" "$filesize"
        off=$(((off + 110 + namesize + 3) / 4 * 4))
        if [ "$name" = "TRAILER!!!" ]; then
            check "archive ends at 4-byte aligned trailer end" "$total" "$off"
            return 0
        fi
        off=$(((off + filesize + 3) / 4 * 4))
    done
    echo "no-trailer"
    return 1
}

# スクリプトの実行。$1=ケース名 以降=引数。stdout を $sb/o.out、stderr を $sb/o.err、終了コードを rc に入れる。
run() {
    rc=0
    env GUEST_INITRD_TEST_SANDBOX="$sb" "$@" >"$sb/o.out" 2>"$sb/o.err" || rc=$?
}
errcode() {
    grep -o 'code=[a-z-]*' "$sb/o.err" | head -n 1 | sed 's/^code=//' || true
}
n=0
newout() {
    n=$((n + 1))
    out="$sb/out-$n"
}

# --- Windows（Git Bash）ホストでは梱包しない契約だけを実ホストで照合して終える ---
# 対象スクリプトは Windows を unsupported-os・終了コード 2 で拒否する（ホスト OS の差し替え口は
# 梱包の共通ケースで使わない）。以降の梱包ケースは POSIX の権限・所有者に依存するため走らせない。
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
        newout
        run "$target" --init "$good" --output-dir "$out"
        check "win exit code" 2 "$rc"
        check "win error code" unsupported-os "$(errcode)"
        printf 'pass=%s fail=%s\n' "$pass" "$fail"
        [ "$fail" -eq 0 ]
        exit $?
        ;;
esac

# --- 1: 成功（スタブ cargo・無圧縮） ---
newout
run env GUEST_INITRD_CARGO="$sb/cargo-ok" "$target" --compress none --output-dir "$out"
check "1 exit code" 0 "$rc"
check "1 stdout is the initrd path" "$out/initrd.cpio" "$(cat "$sb/o.out")"
entries="$(list_newc "$out/initrd.cpio" | grep -v '^ok' || true)"
check "1 entries are exactly init and TRAILER" "init 000081ed 00000000 00000000 $good_size
TRAILER!!! 00000000 00000000 00000000 0" "$entries"
if tail -c +$((110 + 5 + 1 + 1)) "$out/initrd.cpio" | head -c "$good_size" | cmp -s - "$good"; then ok "1 init data equals the fixture"; else ng "1 init data differs"; fi
# 独立に組み立てた期待バイト列とアーカイブ全体を比較する。
exp="$sb/expected.cpio"
z8=00000000
size_hex="$(printf '%08x' "$good_size")"
{
    # ino=1 mode=0100755 uid=0 gid=0 nlink=1 mtime=0 filesize dev*4=0 namesize=5 check=0
    printf '%s' "070701" 00000001 000081ed $z8 $z8 00000001 $z8 "$size_hex" $z8 $z8 $z8 $z8 00000005 $z8
    printf 'init\0\0'
    cat "$good"
    head -c "$(((4 - good_size % 4) % 4))" /dev/zero
    # ino=0 mode=0 uid=0 gid=0 nlink=1 mtime=0 filesize=0 dev*4=0 namesize=11 check=0
    printf '%s' "070701" $z8 $z8 $z8 $z8 00000001 $z8 $z8 $z8 $z8 $z8 $z8 0000000b $z8
    printf 'TRAILER!!!\0\0\0\0'
} >"$exp"
if cmp -s "$exp" "$out/initrd.cpio"; then ok "1 archive equals the independently built bytes"; else ng "1 archive differs from the expected bytes"; fi
check "1 only expected files in output" "build-info.txt initrd.cpio" "$(find "$out" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | tr '\n' ' ' | sed 's/ $//')"
cpio_ref="$out/initrd.cpio"

# --- 2: 成功（gzip 既定・--init） ---
newout
run "$target" --init "$good" --output-dir "$out"
check "2 exit code" 0 "$rc"
check "2 stdout is the gz path" "$out/initrd.cpio.gz" "$(cat "$sb/o.out")"
if gzip -dc "$out/initrd.cpio.gz" | cmp -s - "$cpio_ref"; then ok "2 gunzip equals the plain archive"; else ng "2 gunzip differs"; fi
if grep -qx "init_sha256=$good_sha" "$out/build-info.txt"; then ok "2 build-info has the init sha256"; else ng "2 build-info sha256 missing"; fi
if grep -qx 'compress=gzip' "$out/build-info.txt"; then ok "2 build-info has compress=gzip"; else ng "2 build-info compress missing"; fi

# --- 3: 既存の出力は上書きしない ---
newout
mkdir "$out"
chmod 700 "$out"
printf 'KEEP-ME' >"$out/initrd.cpio.gz"
run "$target" --init "$good" --output-dir "$out"
check "3 exit code" 2 "$rc"
check "3 error code" output-exists "$(errcode)"
check "3 existing content kept" KEEP-ME "$(cat "$out/initrd.cpio.gz")"

# 3b: 確定先がディレクトリ・ディレクトリへの symlink でも拒否し、出力先の外へ書かない
newout
mkdir "$out" "$out/initrd.cpio.gz"
run "$target" --init "$good" --output-dir "$out"
check "3b dir exit code" 2 "$rc"
check "3b dir entries inside" 0 "$(find "$out/initrd.cpio.gz" -mindepth 1 | wc -l | tr -d ' ')"
newout
mkdir "$out" "$sb/outside"
ln -s "$sb/outside" "$out/initrd.cpio.gz"
run "$target" --init "$good" --output-dir "$out"
check "3b dir-symlink exit code" 2 "$rc"
check "3b dir-symlink wrote nothing outside" 0 "$(find "$sb/outside" -mindepth 1 | wc -l | tr -d ' ')"
rm -rf "$sb/outside"

# --- 3b: 他者が書き換えられる出力先は拒否する（PR #2086 の指摘・fail-closed） ---
# 出力先が group/other 書き込み可なら、一時名の削除と symlink 差し替えで参照先を上書きされうる。
newout
mkdir "$out"
chmod 777 "$out"
run "$target" --init "$good" --output-dir "$out"
check "3b writable output exit code" 2 "$rc"
check "3b writable output error code" unsafe-output "$(errcode)"
check "3b writable output left empty" "" "$(ls -A "$out")"
chmod 700 "$out"
newout
mkdir "$out"
chmod 770 "$out"
run env GUEST_INITRD_PRIVATE_GROUP=no "$target" --init "$good" --output-dir "$out"
check "3b group-writable shared group error code" unsafe-output "$(errcode)"
chmod 700 "$out"
# getent の失敗・空の出力は fail-closed（共有 group 扱い）。スタブの getent を PATH の先頭へ置く。
for mode in fail empty; do
    mkdir -p "$sb/getent-$mode"
    if [ "$mode" = fail ]; then
        printf '#!/bin/sh\nexit 2\n' >"$sb/getent-$mode/getent"
    else
        printf '#!/bin/sh\nexit 0\n' >"$sb/getent-$mode/getent"
    fi
    chmod 755 "$sb/getent-$mode/getent"
    newout
    mkdir "$out"
    chmod 770 "$out"
    run env PATH="$sb/getent-$mode:$PATH" "$target" --init "$good" --output-dir "$out"
    check "3b getent $mode exit code" 2 "$rc"
    check "3b getent $mode error code" unsafe-output "$(errcode)"
    check "3b getent $mode left empty" "" "$(ls -A "$out")"
    chmod 700 "$out"
done
# ルート・空に解決される出力先は拒否し、カレントディレクトリへ何も作らない。
for p in / /. /tmp/..; do
    newout
    mkdir "$sb/cwd-$n"
    rc=0
    (cd "$sb/cwd-$n" && env GUEST_INITRD_TEST_SANDBOX="$sb" "$target" --init "$good" --output-dir "$p" >"$sb/o.out" 2>"$sb/o.err") || rc=$?
    check "3b root output '$p' exit code" 2 "$rc"
    check "3b root output '$p' error code" bad-output "$(errcode)"
    check "3b root output '$p' cwd untouched" "" "$(ls -A "$sb/cwd-$n")"
done
# 自分専用 group（umask 002 の 0775 ツリー）の group 書き込みは許す（PR #2086 の指摘）。
newout
mkdir "$out"
chmod 775 "$out"
run env GUEST_INITRD_PRIVATE_GROUP=yes "$target" --init "$good" --output-dir "$out/sub"
check "3b private-group 0775 ancestor exit code" 0 "$rc"
chmod 700 "$out"
# 出力先は ビルド前に 0700 で作られる（ビルド中に他者が先置きできない）。
newout
run env GUEST_INITRD_PRIVATE_GROUP=yes "$target" --init "$good" --output-dir "$out"
check "3b created output exit code" 0 "$rc"
check "3b created output mode" 700 "$(stat -c '%a' "$out" 2>/dev/null || stat -f '%Lp' "$out")"
# 出力先が symlink の場合は拒否する。検査後の差し替えで別の場所へ書かせない。
newout
mkdir "$sb/real-$n"
chmod 700 "$sb/real-$n"
ln -s "$sb/real-$n" "$out"
run "$target" --init "$good" --output-dir "$out"
check "3b symlink output exit code" 2 "$rc"
check "3b symlink output wrote nothing" "" "$(ls -A "$sb/real-$n")"
# 親が symlink の場合は物理パスへ確定し、その配下へ作る（symlink 経由の再解決をしない）。
newout
mkdir "$sb/realparent-$n"
chmod 700 "$sb/realparent-$n"
ln -s "$sb/realparent-$n" "$out"
run "$target" --init "$good" --output-dir "$out/sub"
check "3b symlinked parent exit code" 0 "$rc"
check "3b symlinked parent printed physical path" "$(cd -P "$sb/realparent-$n" && pwd -P)/sub/initrd.cpio.gz" "$(tail -n 1 "$sb/o.out")"
# sticky 無しで他者が書ける祖先（未作成の出力先の親）も拒否し、何も作らない。
newout
mkdir "$out"
chmod 777 "$out"
run "$target" --init "$good" --output-dir "$out/sub/dir"
check "3b writable ancestor exit code" 2 "$rc"
check "3b writable ancestor error code" unsafe-output "$(errcode)"
check "3b writable ancestor nothing created" "" "$(ls -A "$out")"
chmod 700 "$out"
# sticky 付きの祖先（/tmp 相当）は許す。出力先は 0700 で作られる。
newout
mkdir "$out"
chmod 1777 "$out"
run "$target" --init "$good" --output-dir "$out/sub"
check "3b sticky ancestor exit code" 0 "$rc"
chmod 700 "$out"

# --- 4: 他者のロック ---
newout
mkdir "$out.lock"
run "$target" --init "$good" --output-dir "$out"
check "4 exit code" 2 "$rc"
check "4 error code" output-busy "$(errcode)"
if [ ! -e "$out" ]; then ok "4 output dir not created"; else ng "4 output dir was created"; fi
if [ -d "$out.lock" ]; then ok "4 foreign lock kept"; else ng "4 foreign lock removed"; fi

# --- 5: 入力の拒否 ---
reject() { # $1=名前 $2=期待コード $3=init パス [追加引数...]
    local name="$1" code="$2" p="$3"
    shift 3
    newout
    run "$target" --init "$p" --output-dir "$out" "$@"
    check "5 $name exit code" 2 "$rc"
    check "5 $name error code" "$code" "$(errcode)"
    if [ ! -e "$out" ]; then ok "5 $name leaves no output"; else ng "5 $name left an output"; fi
}
ln -s "$good" "$sb/init-link"
reject symlink bad-input "$sb/init-link"
mkdir "$sb/init-dir"
reject directory bad-input "$sb/init-dir"
: >"$sb/init-empty"
reject empty bad-input "$sb/init-empty"
cp "$good" "$sb/init-ow"
chmod 666 "$sb/init-ow"
if [ -n "$(find "$sb/init-ow" -prune -perm -0002 -print 2>/dev/null)" ]; then
    reject other-writable bad-input "$sb/init-ow"
else
    skip "5 other-writable (chmod has no effect here)"
fi
if [ "$(id -u)" != "0" ]; then
    newout
    run env GUEST_INITRD_EXPECT_UID=99999 "$target" --init "$good" --output-dir "$out"
    check "5 owner mismatch exit code" 2 "$rc"
    check "5 owner mismatch error code" bad-input "$(errcode)"
else
    skip "5 owner mismatch (running as root)"
fi
printf 'not an elf file at all, just text\n' >"$sb/init-text"
chmod 755 "$sb/init-text"
reject not-elf not-elf "$sb/init-text"
mk_elf "$sb/init-x86" 02 3e 01
chmod 755 "$sb/init-x86"
reject x86_64 wrong-arch "$sb/init-x86"
mk_elf "$sb/init-dyn" 03 b7 01
chmod 755 "$sb/init-dyn"
reject et-dyn bad-elf "$sb/init-dyn"
chmod 755 "$sb/elf-interp"
reject pt-interp not-static "$sb/elf-interp"
# スタブ cargo 経由でも動的リンクは拒否される
newout
run env GUEST_INITRD_CARGO="$sb/cargo-interp" "$target" --output-dir "$out"
check "5 built dynamic binary exit code" 2 "$rc"
check "5 built dynamic binary error code" not-static "$(errcode)"

# FIFO は open 前に stat で拒否され、ブロックしない（REPAIR-5）。タイムアウト内に終わることも照合する。
if command -v mkfifo >/dev/null 2>&1 && mkfifo "$sb/init-fifo" 2>/dev/null; then
    newout
    t0=$SECONDS
    run "$target" --init "$sb/init-fifo" --output-dir "$out"
    check "5 fifo exit code" 2 "$rc"
    check "5 fifo error code" bad-input "$(errcode)"
    if [ $((SECONDS - t0)) -lt 10 ]; then ok "5 fifo rejected without blocking"; else ng "5 fifo rejection took too long"; fi
    if [ ! -e "$out" ]; then ok "5 fifo leaves no output"; else ng "5 fifo left an output"; fi
else
    skip "5 fifo (mkfifo unavailable)"
fi

# 出力ディレクトリへ固定名の symlink が先に置かれても、参照先を上書きしない（排他的な一時ファイル）。
victim="$sb/victim"
printf 'KEEP\n' >"$victim"
mk_stub cargo-plant "mkdir -p \"\$PLANT_OUT\" && ln -s '$victim' \"\$PLANT_OUT/.build-info.tmp\" && ln -s '$victim' \"\$PLANT_OUT/.initrd.tmp\" && mkdir -p \"\$CARGO_TARGET_DIR/$rel\" && cp '$good' \"\$CARGO_TARGET_DIR/$rel/fandhe-container-guest-init\""
newout
run env GUEST_INITRD_CARGO="$sb/cargo-plant" PLANT_OUT="$out" "$target" --output-dir "$out"
check "5 planted symlink victim untouched" "KEEP" "$(cat "$victim")"
if [ -f "$out/initrd.cpio.gz" ] && [ -f "$out/build-info.txt" ] && [ ! -L "$out/initrd.cpio.gz" ]; then
    ok "5 planted symlink outputs are regular files"
else
    ng "5 planted symlink outputs missing or symlinks (rc=$rc)"
fi

# --- 6: ビルド失敗 ---
newout
run env GUEST_INITRD_CARGO="$sb/cargo-fail" "$target" --output-dir "$out"
check "6 exit code" 1 "$rc"
check "6 error code" build-failed "$(errcode)"
if [ ! -e "$out" ]; then ok "6 leaves no output"; else ng "6 left an output"; fi

# --- 7: 期限切れ（子プロセスも回収される） ---
newout
rm -f "$sb/hang.pid"
run env GUEST_INITRD_CARGO="$sb/cargo-hang" "$target" --build-timeout 1 --output-dir "$out"
check "7 exit code" 3 "$rc"
check "7 error code" build-timeout "$(errcode)"
hp="$(cat "$sb/hang.pid" 2>/dev/null || true)"
if [ -n "$hp" ] && ! kill -0 "$hp" 2>/dev/null; then ok "7 the stub's child was reclaimed"; else ng "7 the stub's child is still alive (pid=$hp)"; fi

# --- 8: 引数の検査 ---
bad_arg() { # $1=名前 以降=引数
    local name="$1"
    shift
    newout
    run "$target" --init "$good" --output-dir "$out" "$@"
    check "8 $name exit code" 2 "$rc"
    check "8 $name error code" bad-argument "$(errcode)"
}
bad_arg unknown-flag --bogus
bad_arg missing-value --linker
bad_arg timeout-range --build-timeout 0
bad_arg pack-timeout-range --pack-timeout 601
bad_arg compress-value --compress zip
bad_arg linker-chars --linker 'a;b'
newout
run "$target" --init "$good" --output-dir "$out$(printf '\001')x"
check "8 control-char path exit code" 2 "$rc"
check "8 control-char path error code" bad-argument "$(errcode)"

# --- 9: 差し替え口はサンドボックス内に限る ---
newout
run env GUEST_INITRD_TEST_SANDBOX="$sb/none" GUEST_INITRD_CARGO="$sb/cargo-ok" "$target" --output-dir "$out"
check "9 missing sandbox exit code" 2 "$rc"
check "9 missing sandbox error code" test-seam-refused "$(errcode)"
newout
run env GUEST_INITRD_CARGO=/bin/true "$target" --output-dir "$out"
check "9 outside command exit code" 2 "$rc"
check "9 outside command error code" test-seam-refused "$(errcode)"

# --- 10: Windows ホスト ---
newout
run env GUEST_INITRD_UNAME_S=MINGW64_NT-10.0 "$target" --init "$good" --output-dir "$out"
check "10 exit code" 2 "$rc"
check "10 error code" unsupported-os "$(errcode)"

printf 'pass=%s fail=%s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
