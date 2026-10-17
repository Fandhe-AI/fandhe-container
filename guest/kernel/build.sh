#!/usr/bin/env bash
# macOS ゲスト用 Linux カーネル（arm64）のビルドスクリプト（TASK-64 追補・#1874・MAC-1・#362・#1823）。
#
# 役割: guest/kernel/source.lock に固定した kernel.org の tarball を取得し、固定の sha256 で
# 照合してから展開し、arm64-guest.config（Kconfig フラグメント）で設定して Image をビルドする。
# GPL-2.0 のソース提供義務は「tarball の URL・版・sha256・設定・本スクリプトの公開」で満たす
# 方針（#362）。呼び出し元は Makefile の `guest-kernel-build` と自己テスト
# （guest/kernel/build-selftest.sh）。CI と `make ci` では実行しない（取得と実ビルドは人間が行う。#1628）。
#
# 使い方:
#   build.sh [--output-dir <dir>] [--tarball <path>] [--jobs N] [--cross-compile <prefix>] [--llvm]
#            [--fetch-timeout S] [--extract-timeout S] [--build-timeout S]
#   各引数は同名の環境変数（GUEST_KERNEL_OUTPUT_DIR・GUEST_KERNEL_TARBALL・GUEST_KERNEL_JOBS・
#   CROSS_COMPILE・LLVM=1）でも渡せる。CLI の引数が優先。
#   --output-dir      既定: <repo>/target/guest-kernel/<版>/arm64（空または未存在のディレクトリのみ）
#   --tarball         取得済みの tarball を使う（同じ sha256 で照合する）
#   --fetch-timeout   取得の上限秒（既定 900。1〜3600）
#   --extract-timeout 検査と展開の上限秒（既定 600。1〜3600）
#   --build-timeout   設定とビルドの make 1 回あたりの上限秒（既定 7200。1〜21600）
#
# 安全性: root を要求せず、sudo も make install も使わない。ロックファイルは source せず
# 行ごとに正規表現で検証する。tarball は sha256 の照合に通ってから、メンバ一覧を検査して
# （絶対パス・`..`・`linux-<版>/` 以外の接頭辞を拒否）、新しい空の一時ディレクトリへ所有者を
# 再現せずに展開する。出力は一時名で作ってから mv で確定し、既存の出力は上書きしない。
# 取得・展開・ビルドは独立したプロセスグループで起動し、期限超過時はグループごと
# TERM → 猶予後 KILL する（REPAIR-5）。
#
# 前提ツール: make・tar（xz 対応）・xz・curl（--tarball 無指定時）・sha256sum または shasum・
#   gcc（aarch64 ネイティブまたはクロス）または clang/lld（--llvm）・flex・bison・bc・perl
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功（stdout に出力先の Image のパスを 1 行出す）
#   1: ビルド失敗（build-failed）・設定の記号が残らなかった（config-option-missing）
#   2: 引数・環境・ツール未導入・出力先・ロックファイル・アーカイブが不正、Windows ホスト
#   3: 期限切れ（fetch-timeout・extract-timeout・build-timeout）
#   4: 完全性の検証失敗（checksum-mismatch。展開もビルドもしない）
# エラーは stderr に `error: code=<code> message=<英語>` の 1 行で出す。
set -euo pipefail

err() {
    printf 'error: code=%s message=%s\n' "$1" "$2" >&2
}
info() {
    printf 'info: %s\n' "$1" >&2
}
usage() {
    cat >&2 <<'USAGE'
usage: build.sh [--output-dir <dir>] [--tarball <path>] [--jobs N] [--cross-compile <prefix>] [--llvm]
                [--fetch-timeout S] [--extract-timeout S] [--build-timeout S]
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd)"
# lib.sh は source 時に cwd をリポジトリルートへ移す（make 経由と同じ意味にするため）。本スクリプトは
# 利用者の相対パスを呼び出し元の cwd 基準で解釈するので、source 後に元の cwd へ戻す。
caller_pwd="$PWD"
# shellcheck source=../../scripts/lib.sh
source "$root/scripts/lib.sh"
cd -- "$caller_pwd" || { err bad-environment "cannot return to the working directory"; exit 2; }

output_dir="${GUEST_KERNEL_OUTPUT_DIR:-}"
tarball_arg="${GUEST_KERNEL_TARBALL:-}"
jobs="${GUEST_KERNEL_JOBS:-}"
cross_compile="${CROSS_COMPILE:-}"
use_llvm=0
[ "${LLVM:-}" = "1" ] && use_llvm=1
fetch_timeout=900
extract_timeout=600
build_timeout=7200

# 数値引数の検証。$1=名前 $2=値 $3=最小 $4=最大
check_int() {
    if ! int_in_range "$2" "$3" "$4"; then
        err bad-argument "$1 must be an integer between $3 and $4"
        usage
        exit 2
    fi
}

need_value() {
    [ "$1" -ge 2 ] || { err bad-argument "$2 requires a value"; usage; exit 2; }
}

while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir) need_value $# "$1"; output_dir="$2"; shift 2 ;;
        --tarball) need_value $# "$1"; tarball_arg="$2"; shift 2 ;;
        --jobs) need_value $# "$1"; jobs="$2"; shift 2 ;;
        --cross-compile) need_value $# "$1"; cross_compile="$2"; shift 2 ;;
        --llvm) use_llvm=1; shift ;;
        --fetch-timeout) need_value $# "$1"; check_int "$1" "$2" 1 3600; fetch_timeout="$2"; shift 2 ;;
        --extract-timeout) need_value $# "$1"; check_int "$1" "$2" 1 3600; extract_timeout="$2"; shift 2 ;;
        --build-timeout) need_value $# "$1"; check_int "$1" "$2" 1 21600; build_timeout="$2"; shift 2 ;;
        *) err bad-argument "unknown argument: $1"; usage; exit 2 ;;
    esac
done

if [ -n "$jobs" ]; then
    check_int "--jobs" "$jobs" 1 256
fi
if [ -n "$cross_compile" ] && ! [[ "$cross_compile" =~ ^[A-Za-z0-9._/+-]+$ ]]; then
    err bad-argument "--cross-compile contains characters outside [A-Za-z0-9._/+-]"
    exit 2
fi
case "$output_dir$tarball_arg" in
    *[[:cntrl:]]*) err bad-argument "paths must not contain control characters"; exit 2 ;;
esac

# --- テスト用の差し替え口（自己テスト専用。サンドボックスの外では拒否する） ---
curl_cmd="curl"
make_cmd="make"
lock_file="$script_dir/source.lock"
host_os=""
host_arch=""
sandbox="${GUEST_KERNEL_TEST_SANDBOX:-}"
seam_requested=0
for v in GUEST_KERNEL_CURL GUEST_KERNEL_MAKE GUEST_KERNEL_LOCK GUEST_KERNEL_UNAME_S GUEST_KERNEL_UNAME_M; do
    [ -z "${!v:-}" ] || seam_requested=1
done
if [ "$seam_requested" -eq 1 ]; then
    # サンドボックスの印（自己テストが作る一時ディレクトリ内のマーカー）が無ければ拒否する。
    if [ -z "$sandbox" ] || [ ! -d "$sandbox" ] || [ ! -f "$sandbox/.guest-kernel-selftest" ]; then
        err test-seam-refused "test seams are only allowed inside the selftest sandbox"
        exit 2
    fi
    for v in GUEST_KERNEL_CURL GUEST_KERNEL_MAKE GUEST_KERNEL_LOCK; do
        val="${!v:-}"
        case "$val" in
            "") ;;
            "$sandbox"/*) ;;
            *) err test-seam-refused "$v must be inside the selftest sandbox"; exit 2 ;;
        esac
    done
    [ -z "${GUEST_KERNEL_CURL:-}" ] || curl_cmd="$GUEST_KERNEL_CURL"
    [ -z "${GUEST_KERNEL_MAKE:-}" ] || make_cmd="$GUEST_KERNEL_MAKE"
    if [ -n "${GUEST_KERNEL_LOCK:-}" ]; then
        lock_file="$GUEST_KERNEL_LOCK"
        info "warning: using a test lock file: $lock_file"
    fi
    host_os="${GUEST_KERNEL_UNAME_S:-}"
    host_arch="${GUEST_KERNEL_UNAME_M:-}"
fi
[ -n "$host_os" ] || host_os="$(uname -s)"
[ -n "$host_arch" ] || host_arch="$(uname -m)"

case "$host_os" in
    MINGW* | MSYS* | CYGWIN*)
        err unsupported-os "Windows hosts are not supported for building the guest kernel"
        exit 2
        ;;
esac

# --- ロックファイルの検証（source しない） ---
lock_ver=""
lock_url=""
lock_sha=""
[ -f "$lock_file" ] || { err bad-lock "lock file not found"; exit 2; }
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        KERNEL_VERSION=*)
            [ -z "$lock_ver" ] || { err bad-lock "duplicate key KERNEL_VERSION"; exit 2; }
            lock_ver="${line#KERNEL_VERSION=}"
            [[ "$lock_ver" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { err bad-lock "invalid KERNEL_VERSION"; exit 2; }
            ;;
        KERNEL_URL=*)
            [ -z "$lock_url" ] || { err bad-lock "duplicate key KERNEL_URL"; exit 2; }
            lock_url="${line#KERNEL_URL=}"
            ;;
        KERNEL_SHA256=*)
            [ -z "$lock_sha" ] || { err bad-lock "duplicate key KERNEL_SHA256"; exit 2; }
            lock_sha="${line#KERNEL_SHA256=}"
            [[ "$lock_sha" =~ ^[0-9a-f]{64}$ ]] || { err bad-lock "invalid KERNEL_SHA256"; exit 2; }
            ;;
        *) err bad-lock "unknown or malformed line in lock file"; exit 2 ;;
    esac
done <"$lock_file"
if [ -z "$lock_ver" ] || [ -z "$lock_url" ] || [ -z "$lock_sha" ]; then
    err bad-lock "lock file must define KERNEL_VERSION, KERNEL_URL and KERNEL_SHA256"
    exit 2
fi
if ! [[ "$lock_url" =~ ^https://cdn\.kernel\.org/pub/linux/kernel/[A-Za-z0-9._/+-]+$ ]]; then
    err bad-lock "KERNEL_URL must be an https://cdn.kernel.org/pub/linux/kernel/ URL"
    exit 2
fi
case "/$lock_url/" in
    */../*) err bad-lock "KERNEL_URL must not contain .. segments"; exit 2 ;;
esac
if [ "${lock_url##*/}" != "linux-${lock_ver}.tar.xz" ]; then
    err bad-lock "KERNEL_URL file name must be linux-<KERNEL_VERSION>.tar.xz"
    exit 2
fi

# --- ホストとツールチェーン ---
case "$host_arch" in
    aarch64 | arm64) native_arm64=1 ;;
    *) native_arm64=0 ;;
esac
if [ "$native_arm64" -eq 0 ] && [ -z "$cross_compile" ] && [ "$use_llvm" -eq 0 ]; then
    err toolchain-required "non-arm64 host requires --cross-compile <prefix> or --llvm"
    exit 2
fi
if [ "$host_os" = "Darwin" ]; then
    info "warning: building on macOS is unverified (see guest/kernel/README.md)"
fi

# --- 出力先（空または未存在のみ。上書きしない） ---
[ -n "$output_dir" ] || output_dir="$root/target/guest-kernel/$lock_ver/arm64"
# 末尾スラッシュを除く（ロック名 <出力先>.lock が出力先の内側にならないように。"/" だけは残す）。
while [ "${#output_dir}" -gt 1 ] && [ "${output_dir%/}" != "$output_dir" ]; do
    output_dir="${output_dir%/}"
done
if [ -L "$output_dir" ]; then
    err bad-output "output directory must not be a symlink"
    exit 2
fi
if [ -e "$output_dir" ] && [ ! -d "$output_dir" ]; then
    err output-exists "output path exists and is not a directory"
    exit 2
fi
if [ -d "$output_dir" ]; then
    # 一覧取得の失敗（読み取り不可の 0300 等）を空ディレクトリと誤認しない（fail-closed）。
    dir_listing="$(ls -A "$output_dir" 2>/dev/null)" || {
        err bad-output "cannot list the output directory; refusing to continue"
        exit 2
    }
    if [ -n "$dir_listing" ]; then
        err output-exists "output directory is not empty; refusing to overwrite"
        exit 2
    fi
fi

# --- ツール確認 ---
sha_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
    sha_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sha_cmd="shasum -a 256"
else
    err tool-missing "sha256sum or shasum is required"
    exit 2
fi
command -v tar >/dev/null 2>&1 || { err tool-missing "tar is required"; exit 2; }
command -v xz >/dev/null 2>&1 || { err tool-missing "xz is required"; exit 2; }
command -v "$make_cmd" >/dev/null 2>&1 || { err tool-missing "make is required"; exit 2; }
if [ -z "$tarball_arg" ]; then
    command -v "$curl_cmd" >/dev/null 2>&1 || { err tool-missing "curl is required"; exit 2; }
fi
if [ -n "$tarball_arg" ] && [ ! -f "$tarball_arg" ]; then
    err bad-argument "--tarball file not found"
    exit 2
fi
if [ -z "$jobs" ]; then
    jobs="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2) | head -n 1)"
    [[ "$jobs" =~ ^[0-9]+$ ]] || jobs=2
    [ "$jobs" -le 256 ] || jobs=256
    [ "$jobs" -ge 1 ] || jobs=1
fi

# --- 一時領域と期限つき実行（scripts/lib.sh の run_limited） ---
work_dir=""
out_created=0
lock_dir=""
publishing=0
published=""
cleanup() {
    local rc=$?
    run_limited_abort
    [ -z "$work_dir" ] || rm -rf "$work_dir"
    # 出力先の排他ロックを持つ間に始めた公開だけを回収する（ロックを持たない側は触らない）。
    if [ "$rc" -ne 0 ] && [ "$publishing" -eq 1 ]; then
        # 一時名と、自分が確定させたファイルだけを消す（他者が作った同名の既存ファイルは触らない）。
        rm -f "$output_dir/.build-info.tmp" "$output_dir/.Image.tmp" "$output_dir/.config.tmp"
        for f in $published; do rm -f "$output_dir/$f"; done
        if [ "$out_created" -eq 1 ]; then
            rmdir "$output_dir" 2>/dev/null || true
        fi
    fi
    [ -z "$lock_dir" ] || rmdir "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' INT TERM

work_dir="$(mktemp -d)" || { work_dir=""; err bad-environment "cannot create a temporary directory"; exit 2; }
RUN_LIMITED_DIR="$work_dir"

# 出力先の排他ロック（mkdir は不可分）。同じ出力先への同時実行は後発を拒否し、
# 「既存の出力を上書きしない」契約を守る。ロック確保後に空であることを再検査する。
# ロックは <出力先>.lock ディレクトリで、異常終了（KILL 等）で残ったら手で削除する。
mkdir -p "$(dirname "$output_dir")" 2>/dev/null || { err bad-output "cannot create the parent of the output directory"; exit 2; }
if mkdir "$output_dir.lock" 2>/dev/null; then
    lock_dir="$output_dir.lock"
else
    err output-busy "another run holds $output_dir.lock (remove it if no run is active)"
    exit 2
fi
if [ -L "$output_dir" ] || { [ -e "$output_dir" ] && [ ! -d "$output_dir" ]; }; then
    err output-exists "output directory is not empty; refusing to overwrite"
    exit 2
fi
if [ -d "$output_dir" ]; then
    dir_listing="$(ls -A "$output_dir" 2>/dev/null)" || {
        err bad-output "cannot list the output directory; refusing to continue"
        exit 2
    }
    if [ -n "$dir_listing" ]; then
        err output-exists "output directory is not empty; refusing to overwrite"
        exit 2
    fi
fi

# --- 取得 ---
tarball="$tarball_arg"
if [ -z "$tarball" ]; then
    tarball="$work_dir/linux-${lock_ver}.tar.xz"
    info "fetching $lock_url"
    rc=0
    run_limited "$fetch_timeout" "$curl_cmd" --proto '=https' --tlsv1.2 -fsSL --max-filesize 400000000 \
        -o "$tarball" "$lock_url" || rc=$?
    if [ "$rc" -eq 124 ]; then
        err fetch-timeout "fetching the kernel tarball exceeded ${fetch_timeout}s"
        exit 3
    elif [ "$rc" -ne 0 ]; then
        err fetch-failed "curl failed with exit code $rc"
        exit 2
    fi
fi

# --- 指定された tarball は private な work_dir（mktemp -d は 0700）へ複製し、以降の照合・一覧検査・展開は
# その同じ複製だけを使う（照合後に元ファイルや親ディレクトリを差し替えられても未検証の内容を展開しない） ---
if [ -n "$tarball_arg" ]; then
    pinned="$work_dir/pinned-linux-${lock_ver}.tar.xz"
    if ! cp -- "$tarball_arg" "$pinned" 2>/dev/null; then
        err bad-argument "cannot read the tarball to compute its sha256"
        exit 2
    fi
    tarball="$pinned"
fi

# --- 完全性の照合（不一致ならここで止まり、展開もビルドもしない） ---
if ! actual_sha="$($sha_cmd "$tarball" 2>/dev/null | awk '{print $1}'; exit "${PIPESTATUS[0]}")"; then
    err bad-argument "cannot read the tarball to compute its sha256"
    exit 2
fi
if [ "$actual_sha" != "$lock_sha" ]; then
    err checksum-mismatch "sha256 of the tarball does not match source.lock (expected $lock_sha, got $actual_sha)"
    exit 4
fi

# --- 展開前のメンバ検査 ---
prefix="linux-${lock_ver}"
list="$work_dir/members.txt"
rc=0
run_limited "$extract_timeout" tar -tJf "$tarball" >"$list" || rc=$?
if [ "$rc" -eq 124 ]; then
    err extract-timeout "listing the archive exceeded ${extract_timeout}s"
    exit 3
elif [ "$rc" -ne 0 ]; then
    err bad-archive "tar could not list the archive"
    exit 2
fi
while IFS= read -r member || [ -n "$member" ]; do
    bad=0
    case "$member" in
        /*) bad=1 ;;
        ".." | "../"* | *"/../"* | *"/..") bad=1 ;;
        "$prefix" | "$prefix/"*) ;;
        *) bad=1 ;;
    esac
    if [ "$bad" -eq 1 ]; then
        err unsafe-archive-entry "archive member is outside $prefix/ or uses an absolute or .. path"
        exit 2
    fi
done <"$list"

# --- 展開（新しい空のディレクトリへ。所有者は再現しない） ---
extract_dir="$work_dir/src"
mkdir "$extract_dir"
info "extracting"
rc=0
run_limited "$extract_timeout" tar -xJf "$tarball" -C "$extract_dir" --no-same-owner || rc=$?
if [ "$rc" -eq 124 ]; then
    err extract-timeout "extracting the archive exceeded ${extract_timeout}s"
    exit 3
elif [ "$rc" -ne 0 ]; then
    err bad-archive "tar failed to extract the archive"
    exit 2
fi
src="$extract_dir/$prefix"
[ -d "$src" ] || { err bad-archive "expected directory $prefix not found after extraction"; exit 2; }

# --- 設定とビルド ---
fragment="$script_dir/arm64-guest.config"
[ -f "$fragment" ] || { err bad-environment "arm64-guest.config not found"; exit 2; }
make_args=(-C "$src" ARCH=arm64)
[ -z "$cross_compile" ] || make_args+=("CROSS_COMPILE=$cross_compile")
[ "$use_llvm" -eq 0 ] || make_args+=("LLVM=1")

make_step() {
    local what="$1"
    shift
    local rc=0
    run_limited "$build_timeout" "$make_cmd" "${make_args[@]}" "$@" >&2 || rc=$?
    if [ "$rc" -eq 124 ]; then
        err build-timeout "make $what exceeded ${build_timeout}s"
        exit 3
    elif [ "$rc" -ne 0 ]; then
        err build-failed "make $what failed with exit code $rc"
        exit 1
    fi
}

info "configuring (allnoconfig + fragment)"
make_step allnoconfig "KCONFIG_ALLCONFIG=$fragment" allnoconfig
make_step olddefconfig olddefconfig

# 依存不足で黙って落ちた記号を検出する（fail-closed）。
missing=""
while IFS= read -r line; do
    case "$line" in
        CONFIG_*=y)
            if ! grep -qx -- "$line" "$src/.config" 2>/dev/null; then
                missing="$missing ${line%=y}"
            fi
            ;;
    esac
done <"$fragment"
# 割り込みコントローラ（GIC）は選択（select）で有効になる記号のため、フラグメントに書かなくても
# 必須として照合する。無いと arm64 ゲストが起動できない（MAC-1）。
for sym in CONFIG_ARM_GIC CONFIG_ARM_GIC_V3; do
    if ! grep -qx -- "$sym=y" "$src/.config" 2>/dev/null; then
        missing="$missing $sym"
    fi
done
if [ -n "$missing" ]; then
    err config-option-missing "options requested as =y are absent from the generated .config:$missing"
    exit 1
fi

info "building Image (jobs=$jobs)"
make_step Image "-j$jobs" Image
image="$src/arch/arm64/boot/Image"
[ -s "$image" ] || { err build-failed "Image was not produced"; exit 1; }

# --- 出力（一時名へコピーしてから mv で確定する。失敗は構造化して exit 2） ---
publishing=1
if [ ! -d "$output_dir" ]; then
    mkdir "$output_dir" 2>/dev/null || { err bad-output "cannot create the output directory"; exit 2; }
    out_created=1
fi
tc_cmd=(gcc)
# --llvm を優先する（CROSS_COMPILE が環境に残っていても clang の版を記録する）。
if [ "$use_llvm" -eq 1 ]; then tc_cmd=(clang); elif [ -n "$cross_compile" ]; then tc_cmd=("${cross_compile}gcc"); fi
tc_line=""
if run_limited 30 "${tc_cmd[0]}" --version >"$work_dir/tc-version" 2>/dev/null; then
    tc_line="$(head -n 1 "$work_dir/tc-version" 2>/dev/null || true)"
fi
{
    printf 'kernel_version=%s\n' "$lock_ver"
    printf 'kernel_url=%s\n' "$lock_url"
    printf 'kernel_sha256=%s\n' "$lock_sha"
    printf 'toolchain=%s\n' "${tc_line:-unknown}"
    printf 'host=%s\n' "$host_os $host_arch"
} >"$output_dir/.build-info.tmp" 2>/dev/null \
    && cp "$image" "$output_dir/.Image.tmp" 2>/dev/null \
    && cp "$src/.config" "$output_dir/.config.tmp" 2>/dev/null \
    || { err output-failed "cannot write the build outputs (disk full or permission?)"; exit 2; }
# 確定は ln（ハードリンク）で行う。宛先が既にあれば原子的に失敗し、他者が作ったファイルを上書きしない。
for pair in build-info.txt:.build-info.tmp config:.config.tmp Image:.Image.tmp; do
    dest="${pair%%:*}"
    tmp="${pair#*:}"
    if ! ln -- "$output_dir/$tmp" "$output_dir/$dest" 2>/dev/null; then
        err output-exists "cannot publish $dest: it already exists or the link failed; refusing to overwrite"
        exit 2
    fi
    published="$published $dest"
    rm -f -- "$output_dir/$tmp"
done
publishing=0
out_created=0
printf '%s\n' "$output_dir/Image"
