#!/usr/bin/env bash
# generate-third-party-licenses.sh の自己テスト（TASK-103.1・OSS-5・REPAIR-12）。
# 実 cargo・cargo-about・ネットワークは使わず、一時ディレクトリのスタブ cargo
# （CARGO で差し替え）に対して終了コードと出力を具体値で照合する。
# 呼び出し元は Makefile の `third-party-licenses-selftest`。出力先はすべて一時
# ディレクトリ内で、リポジトリ内には書かない。FAIL が 1 件でもあれば exit 1。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
target="$script_dir/generate-third-party-licenses.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# STUB_MODE: ok | no-about | fail | hang。呼び出し記録は $STUB_LOG へ追記する。
cat >"$work/cargo" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
case "$1" in
    about)
        if [ "$2" = "--version" ]; then
            [ "$STUB_MODE" = "no-about" ] && exit 101
            exit 0
        fi
        [ "$STUB_MODE" = "fail" ] && exit 1
        [ "$STUB_MODE" = "hang" ] && exec sleep 30
        out=""
        while [ $# -gt 0 ]; do
            if [ "$1" = "-o" ]; then out="$2"; fi
            shift
        done
        printf 'DUMMY LICENSE TEXT\n' >"$out"
        ;;
    fetch) exit 0 ;;
esac
exit 0
STUB
chmod +x "$work/cargo"

fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# run <mode> <args...>: 終了コードを $rc、stderr を $work/err に残す。
run() {
    local mode="$1"
    shift
    : >"$work/log"
    rc=0
    CARGO="$work/cargo" STUB_MODE="$mode" STUB_LOG="$work/log" \
        bash "$target" "$@" >"$work/out" 2>"$work/err" || rc=$?
}

# 1 正常系
mkdir "$work/o1"
run ok --output "$work/o1/L.md"
if [ "$rc" -eq 0 ] && [ "$(cat "$work/o1/L.md")" = "DUMMY LICENSE TEXT" ] \
    && [ "$(cat "$work/out")" = "$work/o1/L.md" ] \
    && grep -q -- "^fetch --locked --manifest-path $root/Cargo.toml" "$work/log" \
    && grep -q -- "--frozen --workspace --all-features --fail" "$work/log" \
    && grep -q -- "-c $root/about.toml" "$work/log" \
    && grep -q -- "$root/about.hbs\$" "$work/log" \
    && [ "$(ls -A "$work/o1")" = "L.md" ]; then
    pass "success path"
else
    fail "success path (rc=$rc)"
fi

# 2 cargo-about 未導入
mkdir "$work/o2"
run no-about --output "$work/o2/L.md"
if [ "$rc" -eq 2 ] && grep -q "code=tool-missing" "$work/err" && [ ! -e "$work/o2/L.md" ]; then
    pass "tool missing"
else
    fail "tool missing (rc=$rc)"
fi

# 3 出力先が symlink
mkdir "$work/o3"
echo orig >"$work/o3/target.md"
ln -s "$work/o3/target.md" "$work/o3/L.md"
run ok --output "$work/o3/L.md"
if [ "$rc" -eq 2 ] && [ "$(cat "$work/o3/target.md")" = "orig" ]; then
    pass "symlink output rejected"
else
    fail "symlink output rejected (rc=$rc)"
fi

# 4 親ディレクトリ無し
run ok --output "$work/nodir/L.md"
if [ "$rc" -eq 2 ] && [ ! -e "$work/nodir" ]; then
    pass "missing parent rejected"
else
    fail "missing parent rejected (rc=$rc)"
fi

# 5 不正引数
run ok --bogus
r1=$rc
run ok --output "$work/o1/L.md" --timeout 0
r2=$rc
if [ "$r1" -eq 2 ] && [ "$r2" -eq 2 ]; then
    pass "bad arguments"
else
    fail "bad arguments (rc=$r1,$r2)"
fi

# 6 generate 失敗: 既存出力は不変で一時ファイルも残らない
mkdir "$work/o6"
echo keep >"$work/o6/L.md"
run fail --output "$work/o6/L.md"
if [ "$rc" -eq 1 ] && [ "$(cat "$work/o6/L.md")" = "keep" ] \
    && [ "$(ls -A "$work/o6")" = "L.md" ]; then
    pass "generate failure keeps output"
else
    fail "generate failure keeps output (rc=$rc)"
fi

# 7 ハング
mkdir "$work/o7"
start=$SECONDS
run hang --output "$work/o7/L.md" --timeout 2
elapsed=$((SECONDS - start))
if [ "$rc" -eq 3 ] && grep -q "code=timeout" "$work/err" && [ "$elapsed" -le 10 ] \
    && [ -z "$(ls -A "$work/o7")" ]; then
    pass "timeout (${elapsed}s)"
else
    fail "timeout (rc=$rc, ${elapsed}s)"
fi

if [ "$fails" -ne 0 ]; then
    echo "$fails check(s) failed"
    exit 1
fi
echo "all checks passed"
