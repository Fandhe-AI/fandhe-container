#!/usr/bin/env bash
# scripts/bench/idle_memory.sh の自己テスト（TASK-45.1・CORE-7・REPAIR-12）。
#
# 役割: 実行のたびに mktemp -d 配下へ疑似 /proc を生成し（cmdline は NUL 区切りのバイナリ、
# 読めない smaps は chmod 000 のため git では保持できない）、--proc-root で計測スクリプトへ
# 渡して出力と終了コードを具体値で照合する。呼び出し元は Makefile の `idle-memory-selftest`。
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。

set -euo pipefail

# --proc-root は selftest 専用（通常利用では拒否される）。
export FANDHE_IDLE_MEMORY_SELFTEST=1

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/idle_memory.sh"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

failures=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# 疑似プロセスを作る。引数: <proc-root> <pid> <argv0> <pss> <rss> [exe] [comm]
# exe 省略時は argv0 と同じ実行体を指す exe シンボリックリンクを作る。"-" なら作らない
# （権限不足・カーネルスレッドで exe を読めない状態）。識別は exe で行うため argv0 と別指定できる。
mkproc() {
  local d="$1/$2" exe="${6:-$3}"
  mkdir -p "$d"
  if [ "$exe" != "-" ]; then ln -s "/opt/bin/${exe##*/}" "$d/exe"; fi
  printf '%s\0--flag\0' "$3" >"$d/cmdline"
  printf '%s\n' "${7:-${3##*/}}" >"$d/comm"
  printf 'Rss: 1 kB\nPss: %s kB\n' "$4" >"$d/smaps_rollup"
  printf 'Name: x\nPPid:\t1000\nVmRSS: %s kB\n' "$5" >"$d/status"
}

# 期待 exit コードと stdout の部分一致を照合する。引数: <名前> <期待exit> <期待文字列(空可)> <args...>
check() {
  local name="$1" want="$2" needle="$3"
  shift 3
  local out actual=0
  out="$(bash "$target" "$@" 2>/dev/null)" || actual=$?
  if [ "$actual" -ne "$want" ]; then
    fail "${name} (expected exit=${want}, actual=${actual})"
  elif [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
    fail "${name} (missing output: ${needle})"
  else
    pass "${name}"
  fi
}

# 1. 対象外のみ → 0 件
empty="${root}/empty"
mkproc "$empty" 100 /usr/bin/bash 10 10
mkproc "$empty" 101 fandhe_container_io-abc123 10 10
mkproc "$empty" 102 fandhe-containerx 10 10
mkproc "$empty" 103 fandhe-container_x 10 10
check "non-target-process_count" 0 "process_count=0" --proc-root "$empty"
check "non-target-pss" 0 "pss_kb=0" --proc-root "$empty"
check "non-target-rss" 0 "rss_kb=0" --proc-root "$empty"
check "expect-zero-ok" 0 "" --proc-root "$empty" --expect-zero

# 2. 対象 2 件 + 対象外 1 件
two="${root}/two"
mkproc "$two" 200 /usr/local/bin/fandhe-container 100 300
mkproc "$two" 201 fandhe-container-supervisor 50 200
mkproc "$two" 202 /usr/bin/bash 999 999
check "two-process_count" 0 "process_count=2" --proc-root "$two"
check "two-pss" 0 "pss_kb=150" --proc-root "$two"
check "two-rss" 0 "rss_kb=500" --proc-root "$two"
check "json-process_count" 0 '"process_count": 2,' --proc-root "$two" --format json
check "json-pss" 0 '"pss_kb": 150,' --proc-root "$two" --format json
check "json-rss" 0 '"rss_kb": 500,' --proc-root "$two" --format json
check "json-record" 0 '{"pid": 201, "name": "fandhe-container-supervisor", "pss_kb": 50, "rss_kb": 200}' --proc-root "$two" --format json
check "expect-zero-violated" 1 "" --proc-root "$two" --expect-zero
# --expect-zero 違反時は標準出力にも結果を出さない（text・json とも 0 バイト。SUP-1）
for fmt in text json; do
  actual=0
  out="$(bash "$target" --proc-root "$two" --expect-zero --format "$fmt" 2>/dev/null)" || actual=$?
  if [ "$actual" -eq 1 ] && [ -z "$out" ]; then
    pass "expect-zero-violation-stdout-empty-${fmt}"
  else
    fail "expect-zero-violation-stdout-empty-${fmt} (actual=${actual}, bytes=${#out})"
  fi
done

# --output は一時ファイル経由で書かれ、残骸を残さない
outdir="${root}/out"
mkdir -p "$outdir"
if bash "$target" --proc-root "$two" --format json --output "${outdir}/r.json" >/dev/null 2>&1 &&
  grep -qF '"rss_kb": 500,' "${outdir}/r.json" && [ "$(find "$outdir" -type f | wc -l)" -eq 1 ]; then
  pass "output-file"
else
  fail "output-file"
fi

# --expect-zero 違反時は --output を公開せず、既存ファイルも置換しない
echo "previous" >"${outdir}/keep.txt"
actual=0
bash "$target" --proc-root "$two" --expect-zero --output "${outdir}/keep.txt" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 1 ] && [ "$(cat "${outdir}/keep.txt")" = "previous" ] &&
  [ ! -e "${outdir}/new.txt" ] && [ "$(find "$outdir" -type f | wc -l)" -eq 2 ]; then
  pass "expect-zero-violation-not-published"
else
  fail "expect-zero-violation-not-published (actual=${actual})"
fi
actual=0
bash "$target" --proc-root "$two" --expect-zero --output "${outdir}/new.txt" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 1 ] && [ ! -e "${outdir}/new.txt" ] && [ "$(find "$outdir" -type f | wc -l)" -eq 2 ]; then
  pass "expect-zero-violation-no-new-file"
else
  fail "expect-zero-violation-no-new-file (actual=${actual})"
fi

# --output が既存ディレクトリ → 2（ディレクトリ内へ移動して 0 を返さない）。中身は空のまま
outasdir="${root}/outasdir"
mkdir -p "$outasdir"
actual=0
bash "$target" --proc-root "$empty" --output "$outasdir" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 2 ] && [ "$(find "$outasdir" -mindepth 1 | wc -l)" -eq 0 ] &&
  [ "$(find "$root" -maxdepth 1 -name 'outasdir.*' | wc -l)" -eq 0 ]; then
  pass "output-is-directory"
else
  fail "output-is-directory (actual=${actual})"
fi

# 書き込めない出力先ディレクトリ → 2（mktemp 失敗を終了コード 1〔--expect-zero 違反〕にしない）。
# root は権限を無視して書けるため実行しない旨を明示する。
if [ "$(id -u)" -eq 0 ]; then
  echo "NOT RUN: output-dir-not-writable (running as root can write to mode 555 directories)"
else
  rodir="${root}/rodir"
  mkdir -p "$rodir"
  chmod 555 "$rodir"
  actual=0
  bash "$target" --proc-root "$empty" --output "${rodir}/r.txt" >/dev/null 2>&1 || actual=$?
  if [ "$actual" -eq 2 ] && [ "$(find "$rodir" -mindepth 1 | wc -l)" -eq 0 ]; then
    pass "output-dir-not-writable"
  else
    fail "output-dir-not-writable (actual=${actual})"
  fi
  chmod 755 "$rodir"
fi

# 標準出力へ書けない（閉じている）→ 2（echo 失敗を終了コード 1 にしない）
actual=0
bash "$target" --proc-root "$empty" >&- 2>/dev/null || actual=$?
if [ "$actual" -eq 2 ]; then pass "stdout-closed"; else fail "stdout-closed (actual=${actual})"; fi
# 書き込みエラー（ENOSPC）→ 2。/dev/full は Linux にのみあるため、無い環境では実行しない旨を明示する
if [ -c /dev/full ]; then
  actual=0
  bash "$target" --proc-root "$two" --format json >/dev/full 2>/dev/null || actual=$?
  if [ "$actual" -eq 2 ]; then pass "stdout-write-error"; else fail "stdout-write-error (actual=${actual})"; fi
else
  echo "NOT RUN: stdout-write-error (/dev/full is not available)"
fi

# 3. 読めない smaps_rollup → 3（root は chmod 000 でも読めるため実行しない旨を明示）
unreadable="${root}/unreadable"
mkproc "$unreadable" 300 fandhe-container 10 10
chmod 000 "${unreadable}/300/smaps_rollup"
if [ "$(id -u)" -eq 0 ]; then
  echo "NOT RUN: unreadable-smaps (running as root can read chmod 000 files)"
else
  check "unreadable-smaps" 3 "" --proc-root "$unreadable"
fi

# 3a. argv[0] の自己申告ではなく exe で識別する（CORE-7・SUP-1）
spoof="${root}/spoof"
mkproc "$spoof" 311 /usr/bin/bash 20 40 /opt/bin/fandhe-container-supervisor
check "argv0-not-used-to-count" 0 "process_count=1" --proc-root "$spoof"
# argv[0] だけが対象名で exe が別物 → 識別不能として 3（対象外扱いにして偽成功させない）
spoof2="${root}/spoof2"
mkproc "$spoof2" 310 fandhe-container 10 10 /usr/bin/bash
check "spoofed-argv0-fails-closed" 3 "" --proc-root "$spoof2" --expect-zero
check "spoofed-exe-pss" 0 "pss_kb=20" --proc-root "$spoof"
check "deleted-exe-suffix" 0 "process_count=1" --proc-root "$(
  d="${root}/deleted"
  mkproc "$d" 320 x 5 6 fandhe-container
  rm -f "$d/320/exe"
  ln -s "/opt/bin/fandhe-container (deleted)" "$d/320/exe"
  echo "$d"
)"

# 3a2. exe を読めず argv[0] が対象名 → 確認不能のため 3（過少計上しない）
unverifiable="${root}/unverifiable"
mkproc "$unverifiable" 330 fandhe-container 10 10 -
check "unverifiable-exe" 3 "" --proc-root "$unverifiable"

# 3a3. 走査中に消えた pid（壊れたリンク）は対象か確定できないため、やり直しても収束せず 3
vanish="${root}/vanish"
mkproc "$vanish" 340 /usr/bin/bash 10 10
ln -s "${root}/does-not-exist" "${vanish}/341"
check "vanishing-pid-fails-closed" 3 "" --proc-root "$vanish" --expect-zero

# 3b. cmdline を読めなくても exe が対象名なら計測できる（識別は exe。cmdline は別名疑いの補助のみ）
nocmd="${root}/nocmd"
mkproc "$nocmd" 350 fandhe-container 10 10
chmod 000 "${nocmd}/350/cmdline"
check "unreadable-cmdline-exe-still-counted" 0 "process_count=1" --proc-root "$nocmd"

# 3b1. 対象外 exe の cmdline / comm を開けない → 別名起動の疑いを確認できないため 3（CORE-7・SUP-1）。
# 未初期化の argv0 を set -u で参照して終了コード 1（--expect-zero 違反と同じ値）で落ちないこと、
# 直前の pid の argv0 を引き継いで対象外扱い（偽の 0 件）にしないことを具体値で照合する。
# root は chmod 000 でも読めるため実行しない旨を明示する。
if [ "$(id -u)" -eq 0 ]; then
  echo "NOT RUN: unreadable-cmdline-* / unreadable-comm-* (running as root can read chmod 000 files)"
else
  nocmd_other="${root}/nocmd_other"
  mkproc "$nocmd_other" 500 /usr/bin/bash 10 10
  chmod 000 "${nocmd_other}/500/cmdline"
  check "unreadable-cmdline-non-target-exe" 3 "" --proc-root "$nocmd_other" --expect-zero
  # pid 500 は正常に読める対象外、pid 501 は cmdline を開けない対象外（glob 順で 500 → 501）。
  nocmd_stale="${root}/nocmd_stale"
  mkproc "$nocmd_stale" 500 /usr/bin/bash 10 10
  mkproc "$nocmd_stale" 501 /usr/bin/other 10 10 /opt/bin/renamed-tool
  chmod 000 "${nocmd_stale}/501/cmdline"
  check "unreadable-cmdline-no-stale-argv0" 3 "" --proc-root "$nocmd_stale" --expect-zero
  nocomm="${root}/nocomm"
  mkproc "$nocomm" 510 /usr/bin/bash 10 10
  chmod 000 "${nocomm}/510/comm"
  check "unreadable-comm-non-target-exe" 3 "" --proc-root "$nocomm" --expect-zero
fi
# 空の cmdline（EOF）は開けない場合と区別し、対象外として 0 件のまま成功する
emptyargv="${root}/emptyargv"
mkproc "$emptyargv" 520 x 10 10 /usr/bin/other
: >"${emptyargv}/520/cmdline"
check "empty-cmdline-non-target-exe" 0 "process_count=0" --proc-root "$emptyargv" --expect-zero

# 3b2. 別名で配置・起動された対象バイナリ（exe は対象名でないが argv[0] / comm が対象名）→ 3
alias_root="${root}/alias"
mkproc "$alias_root" 380 fandhe-container-supervisor 10 10 /opt/bin/renamed-tool
check "renamed-exe-argv0-claim" 3 "" --proc-root "$alias_root" --expect-zero
alias2="${root}/alias2"
mkproc "$alias2" 381 /usr/bin/other 10 10 /opt/bin/renamed-tool fandhe-containe
check "renamed-exe-comm-claim" 3 "" --proc-root "$alias2" --expect-zero

# 3b3. --expected-dir: 配置先が一致すれば計測、外なら 3
exp_ok="${root}/exp"
mkproc "$exp_ok" 390 fandhe-container 10 10
check "expected-dir-match" 0 "process_count=1" --proc-root "$exp_ok" --expected-dir /opt/bin
check "expected-dir-mismatch" 3 "" --proc-root "$exp_ok" --expected-dir /usr/local/bin --expect-zero

# 3c. カーネルスレッド相当（exe 不明・PPid=2）は対象外として 0 件
emptycmd="${root}/emptycmd"
mkproc "$emptycmd" 360 x 10 10 -
: >"${emptycmd}/360/cmdline"
printf 'Name: kworker\nPPid:\t2\n' >"${emptycmd}/360/status"
check "kernel-thread-skipped" 0 "process_count=0" --proc-root "$emptycmd" --expect-zero

# 3c2. ゾンビ（exe リンクが切れ、State: Z）は comm が対象名でなければ対象外として 0 件（CORE-7・SUP-1）
zombie="${root}/zombie"
mkproc "$zombie" 365 x 10 10 - defunct-tool
: >"${zombie}/365/cmdline"
printf 'Name: defunct-tool\nState:\tZ (zombie)\nPPid:\t1000\n' >"${zombie}/365/status"
check "zombie-non-target-skipped" 0 "process_count=0" --proc-root "$zombie" --expect-zero
check "zombie-non-target-pss" 0 "pss_kb=0" --proc-root "$zombie"
# 終了処理中（State: X）も同じ扱い
zombie_x="${root}/zombie_x"
mkproc "$zombie_x" 366 x 10 10 - defunct-tool
printf 'Name: defunct-tool\nState:\tX (dead)\nPPid:\t1000\n' >"${zombie_x}/366/status"
check "dead-non-target-skipped" 0 "process_count=0" --proc-root "$zombie_x" --expect-zero
# comm が対象名（15 文字で切り詰め済み）のゾンビは識別できないため 3
zombie_claim="${root}/zombie_claim"
mkproc "$zombie_claim" 367 x 10 10 - fandhe-containe
printf 'Name: fandhe-containe\nState:\tZ (zombie)\nPPid:\t1000\n' >"${zombie_claim}/367/status"
check "zombie-claims-name-fails-closed" 3 "" --proc-root "$zombie_claim" --expect-zero
# comm を開けないゾンビも 3（root は chmod 000 でも読めるため実行しない旨を明示する）
if [ "$(id -u)" -eq 0 ]; then
  echo "NOT RUN: zombie-unreadable-comm (running as root can read chmod 000 files)"
else
  zombie_nocomm="${root}/zombie_nocomm"
  mkproc "$zombie_nocomm" 368 x 10 10 - defunct-tool
  printf 'Name: defunct-tool\nState:\tZ (zombie)\nPPid:\t1000\n' >"${zombie_nocomm}/368/status"
  chmod 000 "${zombie_nocomm}/368/comm"
  check "zombie-unreadable-comm" 3 "" --proc-root "$zombie_nocomm" --expect-zero
fi
# 実行中（State: S）で exe を読めないものは従来どおり 3（ゾンビ扱いで対象外にしない）
running_noexe="${root}/running_noexe"
mkproc "$running_noexe" 369 x 10 10 - defunct-tool
printf 'Name: defunct-tool\nState:\tS (sleeping)\nPPid:\t1000\n' >"${running_noexe}/369/status"
check "running-unreadable-exe-not-zombie" 3 "" --proc-root "$running_noexe" --expect-zero

# 3d. exe 読取不能かつ argv[0] を偽装（対象名でない）→ 対象外にせず 3（--expect-zero の偽成功を防ぐ）
fakeargv="${root}/fakeargv"
mkproc "$fakeargv" 370 /usr/bin/bash 10 10 -
check "unreadable-exe-spoofed-argv0" 3 "" --proc-root "$fakeargv" --expect-zero
# 空 cmdline を偽装しても PPid が 2 でなければ対象外にしない
mkproc "$fakeargv" 371 x 10 10 -
: >"${fakeargv}/371/cmdline"
check "unreadable-exe-empty-cmdline-not-kthread" 3 "" --proc-root "$fakeargv" --expect-zero

# 4. Pss が数値でない → 3
bad="${root}/bad"
mkproc "$bad" 400 fandhe-container abc 10
check "non-numeric-pss" 3 "" --proc-root "$bad"

# 5. 引数エラー・非 Linux → 2
check "missing-proc-root" 2 "" --proc-root "${root}/nonexistent"
check "unknown-argument" 2 "" --bogus
check "bad-format" 2 "" --format yaml
actual=0
FANDHE_IDLE_MEMORY_UNAME_S=Darwin bash "$target" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 2 ]; then pass "unsupported-os"; else fail "unsupported-os (actual=${actual})"; fi
# --proc-root は selftest 用フラグなしでは拒否（非 Linux 判定の回避を許さない）
actual=0
env -u FANDHE_IDLE_MEMORY_SELFTEST FANDHE_IDLE_MEMORY_UNAME_S=Darwin bash "$target" --proc-root "$two" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 2 ]; then pass "proc-root-requires-selftest"; else fail "proc-root-requires-selftest (actual=${actual})"; fi

if [ "$failures" -ne 0 ]; then
  echo "${failures} case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
