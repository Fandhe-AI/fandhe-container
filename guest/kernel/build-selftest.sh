#!/usr/bin/env bash
# guest/kernel/build.sh の自己テスト（TASK-64 追補・#1874・MAC-1・REPAIR-12）。
#
# 役割: スタブの tar.xz・スタブのコンパイラ・スタブの curl だけで build.sh の契約を具体値で照合する
# （ハッシュ不一致の拒否・既存出力の非上書き・引数とロックの検証・アーカイブの検査・期限切れ・
# 設定の残存照合・差し替え口の拒否・Windows ホストの拒否）。実カーネルの取得も実ビルドも
# 行わず、ネットワーク・root・secrets は使わない。Makefile の `guest-kernel-build-selftest` と
# CI の platform-ci から呼ばれる。実リポの設定フラグメントとロックファイルの静的検査も含む。
#
# 前提ツール: bash・make・tar（xz 対応）・xz・sha256sum または shasum・mktemp・sleep・kill
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build="$here/build.sh"

sandbox="$(mktemp -d)" || { echo "cannot create a temporary directory" >&2; exit 2; }
cleanup() {
    rm -rf "$sandbox"
}
trap cleanup EXIT
trap 'exit 143' INT TERM
: >"$sandbox/.guest-kernel-selftest"

pass=0
fail=0
ok() { pass=$((pass + 1)); }
ng() { fail=$((fail + 1)); printf 'FAIL: %s\n' "$1" >&2; }
expect_eq() { # 名前 期待 実測
    if [ "$2" = "$3" ]; then ok; else ng "$1 (expected '$2', got '$3')"; fi
}

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

ver="9.9.9"
prefix="linux-$ver"

# --- スタブ一式 ---
stubs="$sandbox/stubs"
mkdir -p "$stubs"
# スタブのコンパイラ: -o の出力先へ既知の内容を書く。
cat >"$stubs/aarch64-stub-gcc" <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then echo "stub-gcc 1.0"; exit 0; fi
out=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then out="$2"; shift; fi
    shift
done
printf 'STUB-IMAGE-1\n' >"$out"
EOF
chmod +x "$stubs/aarch64-stub-gcc"

make_src() { # 展開元ディレクトリ（$1）へスタブの Makefile を置く
    mkdir -p "$1/$prefix"
    # recipe 行は先頭 TAB が必須だが、リポジトリは TAB インデントを禁じるため TAB> を TAB に置換して書く
    sed "s/^TAB>/$(printf '\t')/" >"$1/$prefix/Makefile" <<'EOF'
# スタブ: allnoconfig は KCONFIG_ALLCONFIG の =y 行を .config へ写す（DROP_OPTION の記号は落とす）。
allnoconfig:
TAB>grep '^CONFIG_.*=y$$' "$(KCONFIG_ALLCONFIG)" | grep -v "^CONFIG_$$DROP_OPTION=y$$" > .config || true
TAB>echo called >> "$(CALL_MARK)"
olddefconfig:
TAB>@:
Image:
TAB>mkdir -p arch/arm64/boot
TAB>$(CROSS_COMPILE)gcc -o arch/arm64/boot/Image
EOF
}

base="$sandbox/base"
make_src "$base"
good_tar="$sandbox/good.tar.xz"
tar -cJf "$good_tar" -C "$base" "$prefix"
good_sha="$(sha_of "$good_tar")"

write_lock() { # 出力先 版 URL sha
    printf 'KERNEL_VERSION=%s\nKERNEL_URL=%s\nKERNEL_SHA256=%s\n' "$2" "$3" "$4" >"$1"
}
url_ok="https://cdn.kernel.org/pub/linux/kernel/v9.x/$prefix.tar.xz"
lock_good="$sandbox/lock.good"
write_lock "$lock_good" "$ver" "$url_ok" "$good_sha"

# スタブ curl: -o の出力先へ tarball をコピーする。
cat >"$stubs/curl-ok" <<EOF
#!/bin/sh
out=""
while [ \$# -gt 0 ]; do
    if [ "\$1" = "-o" ]; then out="\$2"; shift; fi
    shift
done
cp "$good_tar" "\$out"
EOF
# 眠り続けるスタブ curl / make（子プロセスの pid を残す）。
cat >"$stubs/curl-sleep" <<EOF
#!/bin/sh
sleep 300 &
echo \$! > "$sandbox/child.pid"
sleep 300
EOF
cat >"$stubs/make-sleep" <<EOF
#!/bin/sh
sleep 300 &
echo \$! > "$sandbox/child.pid"
sleep 300
EOF
chmod +x "$stubs/curl-ok" "$stubs/curl-sleep" "$stubs/make-sleep"

case_n=0
# run_build <名前> <環境変数群...> -- <引数...>。stdout/stderr/rc を $sandbox/out.* へ。
run_build() {
    case_n=$((case_n + 1))
    local envs=() args=() seen=0
    for a in "$@"; do
        if [ "$a" = "--" ] && [ "$seen" -eq 0 ]; then seen=1; continue; fi
        if [ "$seen" -eq 0 ]; then envs+=("$a"); else args+=("$a"); fi
    done
    local rc=0
    env "GUEST_KERNEL_TEST_SANDBOX=$sandbox" "${envs[@]+"${envs[@]}"}" bash "$build" "${args[@]+"${args[@]}"}" \
        >"$sandbox/out.stdout" 2>"$sandbox/out.stderr" </dev/null || rc=$?
    echo "$rc" >"$sandbox/out.rc"
}
rc_of() { cat "$sandbox/out.rc"; }
has_err() { grep -q "^error: code=$1 " "$sandbox/out.stderr"; }
expect_err() { # 名前 終了コード コード
    expect_eq "$1: exit code" "$2" "$(rc_of)"
    if has_err "$3"; then ok; else ng "$1: expected error code $3, stderr=$(cat "$sandbox/out.stderr")"; fi
}

std_env=("GUEST_KERNEL_LOCK=$lock_good" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=x86_64" "GUEST_KERNEL_CURL=$stubs/curl-ok")
cc="$stubs/aarch64-stub-"

# 1. 成功（取得経路・スタブ curl）
out1="$sandbox/out1"
run_build "${std_env[@]}" "CALL_MARK=$sandbox/calls" -- --output-dir "$out1" --cross-compile "$cc" --jobs 2
expect_eq "success: exit code" "0" "$(rc_of)"
expect_eq "success: stdout" "$out1/Image" "$(cat "$sandbox/out.stdout")"
expect_eq "success: Image content" "STUB-IMAGE-1" "$(cat "$out1/Image" 2>/dev/null)"
[ -s "$out1/config" ] && ok || ng "success: config missing"
expect_eq "success: build-info version" "kernel_version=$ver" "$(sed -n 1p "$out1/build-info.txt" 2>/dev/null)"
expect_eq "success: build-info sha" "kernel_sha256=$good_sha" "$(sed -n 3p "$out1/build-info.txt" 2>/dev/null)"
expect_eq "success: no leftover tmp files" "" "$(find "$out1" -name '.*' -type f | head -n 1)"

# 2. --tarball 経路でも成功
out2="$sandbox/out2"
run_build "${std_env[@]}" "CALL_MARK=$sandbox/calls" -- --output-dir "$out2" --cross-compile "$cc" --tarball "$good_tar"
expect_eq "tarball path: exit code" "0" "$(rc_of)"

# 3. sha256 不一致: 4・展開もビルドもしない
lock_bad="$sandbox/lock.badsha"
write_lock "$lock_bad" "$ver" "$url_ok" "$(printf '%s' "$good_sha" | sed 's/^./0/;s/^00/01/')"
rm -f "$sandbox/calls"
out3="$sandbox/out3"
run_build "GUEST_KERNEL_LOCK=$lock_bad" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=x86_64" "CALL_MARK=$sandbox/calls" -- \
    --output-dir "$out3" --cross-compile "$cc" --tarball "$good_tar"
expect_err "checksum mismatch" 4 checksum-mismatch
[ ! -e "$sandbox/calls" ] && ok || ng "checksum mismatch: make was invoked"
[ ! -e "$out3" ] && ok || ng "checksum mismatch: output dir was created"

# 4. 既存の出力を上書きしない
out4="$sandbox/out4"
mkdir -p "$out4"
printf 'KEEP-ME' >"$out4/Image"
run_build "${std_env[@]}" -- --output-dir "$out4" --cross-compile "$cc" --tarball "$good_tar"
expect_err "output exists" 2 output-exists
expect_eq "output exists: bytes unchanged" "KEEP-ME" "$(cat "$out4/Image")"

# 4b. 同じ出力先の同時実行は排他ロックで拒否する（ロック保持中は何も作らない）
out4b="$sandbox/out4b"
mkdir -p "$out4b.lock"
run_build "${std_env[@]}" -- --output-dir "$out4b" --cross-compile "$cc" --tarball "$good_tar"
expect_err "output busy" 2 output-busy
[ ! -e "$out4b" ] && ok || ng "output busy: output dir was created"
[ -d "$out4b.lock" ] && ok || ng "output busy: foreign lock was removed"
rmdir "$out4b.lock"

# 5. 引数の検証（すべて 2）
args_cases=(
    "--bogus"
    "--jobs"
    "--jobs 0"
    "--jobs 257"
    "--jobs abc"
    "--build-timeout 0"
    "--build-timeout abc"
    "--build-timeout 21601"
    "--fetch-timeout 3601"
    "--extract-timeout 0"
)
for c in "${args_cases[@]}"; do
    # shellcheck disable=SC2086
    run_build "${std_env[@]}" -- --output-dir "$sandbox/outa" --cross-compile "$cc" $c
    expect_eq "bad args '$c': exit code" "2" "$(rc_of)"
done
run_build "${std_env[@]}" -- --output-dir "$sandbox/outa" --cross-compile 'a;b'
expect_eq "bad cross-compile: exit code" "2" "$(rc_of)"
run_build "${std_env[@]}" -- --output-dir "$sandbox/outa" --tarball "$good_tar"
expect_err "toolchain required on non-arm64" 2 toolchain-required
[ ! -e "$sandbox/outa" ] && ok || ng "bad args: output dir was created"

# 6. ロックファイルの検証（すべて 2・bad-lock）
lock_case() { # 名前 本文
    printf '%s\n' "$2" >"$sandbox/lock.case"
    run_build "GUEST_KERNEL_LOCK=$sandbox/lock.case" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" -- \
        --output-dir "$sandbox/outl" --tarball "$good_tar"
    expect_err "lock: $1" 2 bad-lock
}
v="KERNEL_VERSION=$ver"
u="KERNEL_URL=$url_ok"
s="KERNEL_SHA256=$good_sha"
lock_case "bad version" "$(printf 'KERNEL_VERSION=x.y\n%s\n%s' "$u" "$s")"
lock_case "http url" "$(printf '%s\nKERNEL_URL=http://cdn.kernel.org/pub/linux/kernel/v9.x/%s.tar.xz\n%s' "$v" "$prefix" "$s")"
lock_case "foreign host" "$(printf '%s\nKERNEL_URL=https://example.com/pub/linux/kernel/v9.x/%s.tar.xz\n%s' "$v" "$prefix" "$s")"
lock_case "url file name mismatch" "$(printf '%s\nKERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v9.x/linux-1.2.3.tar.xz\n%s' "$v" "$s")"
lock_case "short sha" "$(printf '%s\n%s\nKERNEL_SHA256=abc123' "$v" "$u")"
lock_case "unknown key" "$(printf '%s\n%s\n%s\nEXTRA=1' "$v" "$u" "$s")"
lock_case "duplicate key" "$(printf '%s\n%s\n%s\n%s' "$v" "$v" "$u" "$s")"
lock_case "missing key" "$(printf '%s\n%s' "$v" "$u")"
lock_case "dotdot url" "$(printf '%s\nKERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/../%s.tar.xz\n%s' "$v" "$prefix" "$s")"

# 7. 危険なアーカイブ（sha256 は一致させる）: 2・unsafe-archive-entry・外にファイルができない
# 相対パスの ../ を含むメンバは --transform で作る（GNU tar / bsdtar の差を避けるため、
# 実際のファイル名に ../ を持つアーカイブは cd した先から ../ 付きで追加して作る）。
evil_case_dotdot() {
    local d="$sandbox/evil.dotdot"
    mkdir -p "$d/a/b"
    printf 'x\n' >"$d/a/evil"
    ( cd "$d/a/b" && tar -cJf "$d/evil.tar.xz" ../evil ) 2>/dev/null
    local lk="$d/lock"
    write_lock "$lk" "$ver" "$url_ok" "$(sha_of "$d/evil.tar.xz")"
    run_build "GUEST_KERNEL_LOCK=$lk" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" -- \
        --output-dir "$d/out" --tarball "$d/evil.tar.xz"
    expect_err "archive dotdot member" 2 unsafe-archive-entry
    [ ! -e "$d/out" ] && ok || ng "archive dotdot: output created"
}
evil_case_dotdot
evil_case_abs() {
    local d="$sandbox/evil.abs"
    mkdir -p "$d"
    printf 'x\n' >"$d/evil"
    ( cd "$d" && tar -cJf "$d/evil.tar.xz" -P "$d/evil" ) 2>/dev/null
    local lk="$d/lock"
    write_lock "$lk" "$ver" "$url_ok" "$(sha_of "$d/evil.tar.xz")"
    run_build "GUEST_KERNEL_LOCK=$lk" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" -- \
        --output-dir "$d/out" --tarball "$d/evil.tar.xz"
    expect_err "archive absolute member" 2 unsafe-archive-entry
}
evil_case_abs
evil_case_prefix() {
    local d="$sandbox/evil.prefix"
    mkdir -p "$d/other-dir"
    printf 'x\n' >"$d/other-dir/f"
    ( cd "$d" && tar -cJf "$d/evil.tar.xz" other-dir )
    local lk="$d/lock"
    write_lock "$lk" "$ver" "$url_ok" "$(sha_of "$d/evil.tar.xz")"
    run_build "GUEST_KERNEL_LOCK=$lk" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" -- \
        --output-dir "$d/out" --tarball "$d/evil.tar.xz"
    expect_err "archive foreign prefix" 2 unsafe-archive-entry
    [ ! -e "$d/out" ] && ok || ng "archive prefix: output created"
}
evil_case_prefix

# 8. 期限切れ: 3・子プロセスもグループごと消える
timeout_case() { # 名前 期待コード env... -- 引数...
    local name="$1" code="$2"
    shift 2
    rm -f "$sandbox/child.pid"
    run_build "$@"
    expect_err "timeout $name" 3 "$code"
    local pid=""
    pid="$(cat "$sandbox/child.pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then ok; else ng "timeout $name: child process $pid still alive or pid missing"; fi
    [ -z "$pid" ] || kill -KILL "$pid" 2>/dev/null || true
}
timeout_case fetch fetch-timeout "GUEST_KERNEL_LOCK=$lock_good" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" \
    "GUEST_KERNEL_CURL=$stubs/curl-sleep" -- --output-dir "$sandbox/outt1" --fetch-timeout 1
[ ! -e "$sandbox/outt1" ] && ok || ng "fetch timeout: output created"
timeout_case build build-timeout "GUEST_KERNEL_LOCK=$lock_good" "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" \
    "GUEST_KERNEL_MAKE=$stubs/make-sleep" -- --output-dir "$sandbox/outt2" --tarball "$good_tar" --build-timeout 1
[ ! -e "$sandbox/outt2" ] && ok || ng "build timeout: output created"

# 9. 設定の残存照合: CONFIG_VIRTIO_FS が落ちたら 1・Image を出力しない
out9="$sandbox/out9"
run_build "${std_env[@]}" "CALL_MARK=$sandbox/calls" "DROP_OPTION=VIRTIO_FS" -- \
    --output-dir "$out9" --cross-compile "$cc" --tarball "$good_tar"
expect_err "config option missing" 1 config-option-missing
if grep -q "CONFIG_VIRTIO_FS" "$sandbox/out.stderr"; then ok; else ng "config option missing: symbol not named"; fi
[ ! -e "$out9/Image" ] && ok || ng "config option missing: Image was output"

# 10. 差し替え口はサンドボックスの外では拒否する
rc=0
GUEST_KERNEL_UNAME_S=Linux GUEST_KERNEL_TEST_SANDBOX="" bash "$build" --output-dir "$sandbox/outs" >/dev/null 2>"$sandbox/seam.err" </dev/null || rc=$?
expect_eq "seam outside sandbox: exit code" "2" "$rc"
grep -q '^error: code=test-seam-refused ' "$sandbox/seam.err" && ok || ng "seam outside sandbox: not refused"
rc=0
GUEST_KERNEL_LOCK="/etc/hosts" GUEST_KERNEL_TEST_SANDBOX="$sandbox" bash "$build" --output-dir "$sandbox/outs" >/dev/null 2>"$sandbox/seam.err" </dev/null || rc=$?
grep -q '^error: code=test-seam-refused ' "$sandbox/seam.err" && ok || ng "seam path outside sandbox: not refused"

# 11. Windows ホスト（uname の差し替え）: 2・unsupported-os
run_build "${std_env[@]}" "GUEST_KERNEL_UNAME_S=MINGW64_NT-10.0" -- --output-dir "$sandbox/outw" --cross-compile "$cc"
expect_err "windows host" 2 unsupported-os

# 12. 実リポのフラグメントとロックファイルの静的検査（ネットワーク不要）
frag="$here/arm64-guest.config"
lock="$here/source.lock"
for sym in VIRTIO_FS VIRTIO_VSOCKETS DRM_VIRTIO_GPU VIRTIO_CONSOLE VIRTIO_BLK BLK_DEV_INITRD DEVTMPFS; do
    grep -qx "CONFIG_$sym=y" "$frag" && ok || ng "fragment: CONFIG_$sym=y missing"
done
grep -qx '# CONFIG_MODULES is not set' "$frag" && ok || ng "fragment: CONFIG_MODULES is not disabled"
! grep -q '^CONFIG_MODULES=' "$frag" && ok || ng "fragment: CONFIG_MODULES enabled"
prev=""
bad_lines=""
while IFS= read -r line; do
    case "$line" in
        CONFIG_*=*)
            case "$prev" in
                "# 理由:"*) ;;
                *) bad_lines="$bad_lines ${line%%=*}" ;;
            esac
            ;;
    esac
    prev="$line"
done <"$frag"
expect_eq "fragment: every CONFIG_ line has a reason comment" "" "$bad_lines"
expect_eq "source.lock line count" "3" "$(wc -l <"$lock" | tr -d ' ')"
# ロックファイルは build.sh と同じ検証に通ること（実ファイルでの引数検証まで進めば bad-lock ではない）
run_build "GUEST_KERNEL_UNAME_S=Linux" "GUEST_KERNEL_UNAME_M=aarch64" -- --output-dir "$sandbox/outr" --tarball "$good_tar"
if has_err bad-lock; then ng "real source.lock rejected: $(cat "$sandbox/out.stderr")"; else ok; fi
expect_err "real source.lock sha differs from stub tarball" 4 checksum-mismatch

printf 'guest-kernel build selftest: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
