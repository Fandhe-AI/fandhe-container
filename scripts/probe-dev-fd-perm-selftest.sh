#!/usr/bin/env bash
# scripts/probe-dev-fd-perm.sh の自己テスト（#2088・TASK-64 追補・MAC-1・REPAIR-12）。
#
# 呼び出し元: Makefile の `dev-fd-perm-probe-selftest`（CI の platform-ci から 3 OS で実行）。
# 一時ディレクトリと実際の OS のコマンドだけを使い、root・ネットワークは使わない。
# Linux では fd 経由の検査が効くことを期待値として照合する。macOS では原因が未確定のため観測値は
# assert せず出力の形式だけを照合する（main の macOS leg のログが一次データになる。実機の結果の
# 代わりにはしない）。Windows（Git Bash）では本体が unsupported-os で終了コード 2 を返すことを照合する。
# 終了コード: 全件合格で 0、1 件でも失敗すれば 1。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="$script_dir/probe-dev-fd-perm.sh"

unset DEV_FD_PROBE_FOREIGN

sb="$(mktemp -d)"
trap 'rm -rf "$sb"' EXIT

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

# run_probe <out> <err> <引数...>: 終了コードを rc に入れる。
rc=0
run_probe() {
    local out="$1" err="$2"
    shift 2
    rc=0
    "$target" "$@" >"$out" 2>"$err" || rc=$?
}

# obs <ファイル> <case> <obs> <key>: 該当行の key の値を返す。
obs() {
    grep -F "case=$2 obs=$3 " "$1" | head -n 1 | tr ' ' '\n' | grep "^$4=" | head -n 1 | cut -d= -f2-
}

os="$(uname -s)"
case "$os" in
    MINGW* | MSYS* | CYGWIN*)
        run_probe "$sb/o" "$sb/e"
        check "windows: exit code" 2 "$rc"
        if grep -q 'code=unsupported-os' "$sb/e"; then ok "windows: unsupported-os"; else ng "windows: unsupported-os"; fi
        printf 'passed=%d failed=%d\n' "$pass" "$fail"
        [ "$fail" -eq 0 ]
        exit $?
        ;;
    *) ;;
esac

# 引数の検査
run_probe "$sb/o" "$sb/e" --unknown
check "unknown arg exits 2" 2 "$rc"
run_probe "$sb/o" "$sb/e" --foreign relative/path
check "relative --foreign exits 2" 2 "$rc"
if grep -q 'code=bad-input' "$sb/e"; then ok "relative --foreign code"; else ng "relative --foreign code"; fi
run_probe "$sb/o" "$sb/e" --foreign "$sb/missing"
check "missing --foreign exits 2" 2 "$rc"
printf 'x\n' >"$sb/real"
chmod 0644 "$sb/real"
ln -s "$sb/real" "$sb/link"
run_probe "$sb/o" "$sb/e" --foreign "$sb/link"
check "symlink --foreign exits 2" 2 "$rc"
run_probe "$sb/o" "$sb/e" --foreign
check "missing --foreign value exits 2" 2 "$rc"

# 通常実行（foreign 無し）
run_probe "$sb/o" "$sb/e"
check "default run exits 0" 0 "$rc"
check "first line" "probe=dev-fd-perm v=1" "$(head -n 1 "$sb/o")"
check "last line" "probe=dev-fd-perm done" "$(tail -n 1 "$sb/o")"
check "skip line count" 1 "$(grep -c '^skip: foreign owner case not provided' "$sb/o")"
for c in 0644 0664 0666; do
    for o in stat-L find find-ls-mode route; do
        if grep -q "^case=$c obs=$o " "$sb/o"; then ok "case $c has $o"; else ng "case $c has $o"; fi
    done
done
# ホスト名を出していないこと
hn="$(uname -n)"
if grep -qF -- "$hn" "$sb/o" "$sb/e" 2>/dev/null; then ng "no hostname in output"; else ok "no hostname in output"; fi

# foreign 経路（自分の所有するファイルで経路が通ることだけを確かめる）
run_probe "$sb/o2" "$sb/e2" --foreign "$sb/real"
check "foreign run exits 0" 0 "$rc"
if grep -q '^case=foreign obs=find ' "$sb/o2"; then ok "foreign case emitted"; else ng "foreign case emitted"; fi
check "foreign: no skip line" 0 "$(grep -c '^skip:' "$sb/o2" || true)"

if [ "$os" = Linux ]; then
    # find 行は target=path と target=fd9 の 2 行あるため fd9 の行を直接取る
    fd9() { grep -F "case=$1 obs=find target=fd9 " "$sb/o" | tr ' ' '\n' | grep "^$2=" | cut -d= -f2-; }
    check "linux 0666 fd9 w-other (fd)" yes "$(fd9 0666 w-other)"
    check "linux 0664 fd9 w-group" yes "$(fd9 0664 w-group)"
    check "linux 0644 fd9 w-other" no "$(fd9 0644 w-other)"
    check "linux 0644 fd9 w-group" no "$(fd9 0644 w-group)"
    for c in 0644 0664 0666; do
        check "linux $c fd9 is-file" yes "$(fd9 "$c" is-file)"
        p="$(grep -F "case=$c obs=stat-L target=path " "$sb/o" | cut -d' ' -f4-)"
        f="$(grep -F "case=$c obs=stat-L target=fd9 " "$sb/o" | cut -d' ' -f4-)"
        check "linux $c stat -L path == fd9" "$p" "$f"
    done
    check "linux 0666 route sh child" yes "$(obs "$sb/o" 0666 route w-other-sh-child)"
else
    printf 'info: %s: observation values are not asserted (cause under investigation, #2088)\n' "$os"
fi

printf 'passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
