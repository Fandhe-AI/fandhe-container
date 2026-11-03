#!/usr/bin/env bash
# scripts/test-bin-watchdog.sh の自己テスト（#3504・REPAIR-5・REPAIR-7・REPAIR-12）。
#
# 役割: 一時ディレクトリのスタブの子だけで、正常終了・終了コードの透過・シグナルの透過と転送・期限切れ
# （124・診断・子孫の回収）・ps 不在時の代替診断・pipe を持たないこと・cwd と stdin の透過・gate・入力検査を
# 具体値で照合する。呼び出し元: Makefile の `test-bin-watchdog-selftest`（Linux のみ。/proc を使う）。
# shellcheck disable=SC2013 # pid ファイルは空白区切りの数字のみ
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="${script_dir}/test-bin-watchdog.sh"
work="$(mktemp -d)"
cleanup_pids() {
  local f p
  for f in "${work}"/*.pids; do
    [ -f "${f}" ] || continue
    for p in $(cat "${f}"); do kill -KILL "${p}" 2>/dev/null; done
  done
  return 0
}
trap 'cleanup_pids; rm -rf -- "${work}"' EXIT
fails=0
fail() {
  echo "FAIL: $*" >&2
  fails=$((fails + 1))
}
expect_eq() { [ "$2" = "$3" ] || fail "$1: expected '$2' got '$3'"; }
expect_contains() { # <名前> <ファイル> <部分文字列>
  grep -qF -- "$3" "$2" || fail "$1: '$3' not found in $2"
}

# 外部コマンドの前提は fail-closed。
for c in perl setsid; do
  command -v "${c}" >/dev/null 2>&1 || {
    echo "error: ${c} is required" >&2
    exit 1
  }
done

# run <NAME=VALUE...> -- <コマンド...> : out/err/rc を work に残す
run() {
  local envs=()
  while [ "$1" != "--" ]; do
    envs+=("$1")
    shift
  done
  shift
  env ${envs[@]+"${envs[@]}"} "$@" >"${work}/out" 2>"${work}/err"
  echo $? >"${work}/rc"
}
rc() { cat "${work}/rc"; }
D="FANDHE_CONTAINER_TEST_BIN_DEADLINE_SECS"
perl_bin="$(command -v perl)"

# 1. 正常終了と所要時間
s=$(date +%s)
run "${D}=20" -- "${target}" bash -c 'echo hello'
e=$(date +%s)
expect_eq normal-rc 0 "$(rc)"
expect_eq normal-out hello "$(cat "${work}/out")"
[ ! -s "${work}/err" ] || fail "normal: unexpected stderr"
[ $((e - s)) -lt 3 ] || fail "normal: took $((e - s))s"

# 2. 終了コードの透過
run "${D}=20" -- "${target}" bash -c 'exit 3'
expect_eq exit3 3 "$(rc)"
run "${D}=20" -- "${target}" bash -c 'exit 101'
expect_eq exit101 101 "$(rc)"
# 終了シグナルでない 128+N（SIGSTOP=147 等）は再送せず、そのままの終了コードで抜ける（止まり続けない）
for n in 147 148 149 150 145 146; do
  s0=$(date +%s)
  run "${D}=20" -- "${target}" bash -c "exit ${n}"
  e0=$(date +%s)
  expect_eq "exit${n}" "${n}" "$(rc)"
  [ $((e0 - s0)) -lt 5 ] || fail "exit${n}: took $((e0 - s0))s (wrapper stalled)"
done

# 3. シグナルの透過（perl の system は $? の下位 7 bit にシグナル番号を入れる）。core が cwd に出ないことも見る
mkdir -p "${work}/cwd"
got=$(cd "${work}/cwd" && env "${D}=20" "${perl_bin}" -e 'system(@ARGV); print $? & 127' -- "${target}" bash -c 'kill -TERM $$')
expect_eq sig-term 15 "${got}"
got=$(cd "${work}/cwd" && env "${D}=20" "${perl_bin}" -e 'system(@ARGV); print $? & 127' -- "${target}" bash -c 'kill -SEGV $$')
expect_eq sig-segv 11 "${got}"
[ -z "$(ls -A "${work}/cwd")" ] || fail "sig: files were created in cwd"

# 4. シグナルの転送
cat >"${work}/fwd.sh" <<STUB
#!/usr/bin/env bash
trap 'echo got > "${work}/fwd.mark"; exit 0' TERM
echo \$\$ > "${work}/fwd.pids"
while :; do sleep 0.2; done
STUB
chmod +x "${work}/fwd.sh"
env "${D}=30" "${target}" "${work}/fwd.sh" >/dev/null 2>&1 &
wp=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  [ -s "${work}/fwd.pids" ] && break
  sleep 0.2
done
kill -TERM "${wp}"
wait "${wp}" 2>/dev/null
expect_eq forward-mark got "$(cat "${work}/fwd.mark" 2>/dev/null)"

# 5. 期限切れ: setsid した孫・TERM を無視する孫を含めて回収する
cat >"${work}/hang.sh" <<STUB
#!/usr/bin/env bash
sleep 300 &
echo \$! >> "${work}/hang.pids"
setsid sleep 301 &
echo \$! >> "${work}/hang.pids"
( trap '' TERM; exec sleep 302 ) &
echo \$! >> "${work}/hang.pids"
sleep 300
STUB
chmod +x "${work}/hang.sh"
s=$(date +%s)
run "${D}=2" GITHUB_ACTIONS=true -- "${target}" "${work}/hang.sh" --exact some::test_name
e=$(date +%s)
expect_eq deadline-rc 124 "$(rc)"
[ $((e - s)) -lt 12 ] || fail "deadline: took $((e - s))s"
expect_contains deadline-code "${work}/err" "code=deadline_exceeded"
expect_contains deadline-bin "${work}/err" "binary=hang.sh"
expect_contains deadline-arg1 "${work}/err" "arg: --exact"
expect_contains deadline-arg2 "${work}/err" "arg: some::test_name"
expect_contains deadline-threads "${work}/err" "comm="
expect_contains deadline-ps "${work}/err" "PID"
expect_contains deadline-annotation "${work}/out" "::error::test-bin-watchdog deadline_exceeded binary=hang.sh deadline_secs=2"
sleep 0.5
for p in $(cat "${work}/hang.pids"); do
  if kill -0 "${p}" 2>/dev/null; then fail "deadline: descendant ${p} survived"; fi
done

# 6. ps が無い場合の代替診断（PATH を ps の無い最小ディレクトリに絞る）
mkdir -p "${work}/min"
for c in bash env cat tr cut grep sleep kill timeout head dirname setsid; do
  p="$(command -v "${c}" 2>/dev/null || true)"
  [ -n "${p}" ] && ln -sf "${p}" "${work}/min/${c}"
done
rm -f "${work}/hang.pids"
run "PATH=${work}/min" "${D}=2" -- "${target}" "${work}/hang.sh"
expect_eq nops-rc 124 "$(rc)"
expect_contains nops-diag "${work}/err" "ps not found"
for p in $(cat "${work}/hang.pids" 2>/dev/null); do
  if kill -0 "${p}" 2>/dev/null; then fail "nops: descendant ${p} survived"; fi
done

# 7. pipe を持たない: すぐ終わる子なら cat が即 EOF を受ける
s=$(date +%s)
env "${D}=60" "${target}" bash -c 'echo piped' 2>&1 | cat >"${work}/pipe.out"
e=$(date +%s)
expect_eq pipe-out piped "$(cat "${work}/pipe.out")"
[ $((e - s)) -lt 5 ] || fail "pipe: took $((e - s))s (a watchdog orphan holds the pipe?)"

# 8. cwd の保存と 9. stdin の透過
got=$(cd "${work}/cwd" && env "${D}=20" "${target}" bash -c 'pwd -P')
expect_eq cwd "$(cd "${work}/cwd" && pwd -P)" "${got}"
got=$(printf hi | env "${D}=20" "${target}" cat)
expect_eq stdin hi "${got}"

# 10. gate: CI 外の未設定・off・0・--bench は素通し（期限 1 秒でも 2 秒眠って 0）
run -- env -u "${D}" -u GITHUB_ACTIONS "${target}" bash -c 'sleep 2; exit 7'
expect_eq gate-ci-off 7 "$(rc)"
run "${D}=off" -- "${target}" bash -c 'exit 8'
expect_eq gate-off 8 "$(rc)"
run "${D}=0" -- "${target}" bash -c 'exit 9'
expect_eq gate-zero 9 "$(rc)"
run "${D}=1" -- "${target}" bash -c 'sleep 2; exit 0' --bench
expect_eq gate-bench 0 "$(rc)"
# 未設定の GITHUB_ACTIONS=true でも --ignored は素通し（既定 300 秒で実機前提テストを打ち切らない）。
# 変数で明示した場合は --ignored でも期限を使う（1 秒で 124）
# 素通しは「子の親が wrapper でない」ことで照合する（即終了の子では既定 300 秒を適用しても同じ結果で偽陽性になるため）
cat >"${work}/parent.sh" <<STUB
#!/usr/bin/env bash
tr '\\0' ' ' </proc/\$PPID/cmdline > "${work}/parent.cmd"
exit 6
STUB
chmod +x "${work}/parent.sh"
rm -f "${work}/parent.cmd"
run GITHUB_ACTIONS=true -- env -u "${D}" "${target}" "${work}/parent.sh" --ignored
expect_eq gate-ignored 6 "$(rc)"
if grep -qF "test-bin-watchdog.sh" "${work}/parent.cmd"; then fail "gate-ignored: wrapped by the watchdog"; fi
# 陽性対照: --ignored なしでは既定の期限を使うので、子の親が wrapper になる
rm -f "${work}/parent.cmd"
run GITHUB_ACTIONS=true -- env -u "${D}" "${target}" "${work}/parent.sh"
expect_contains gate-default-wrapped "${work}/parent.cmd" "test-bin-watchdog.sh"
run "${D}=1" -- "${target}" bash -c 'sleep 5; exit 0' --ignored
expect_eq gate-ignored-explicit 124 "$(rc)"
# 未設定で GITHUB_ACTIONS=true なら既定の期限を使う（その間に終われば子のコード）
run GITHUB_ACTIONS=true -- env -u "${D}" "${target}" bash -c 'exit 5'
expect_eq gate-default 5 "$(rc)"

# 12. SIGINT が試験バイナリと孫へ届く（bash の背景子は INT を無視で始まるため、既定動作へ戻す。#3504）
cat >"${work}/int-main.sh" <<STUB
#!/usr/bin/env bash
grep -m1 '^SigIgn:' /proc/self/status > "${work}/int.sigign"
exec sleep 30
STUB
chmod +x "${work}/int-main.sh"
# 背景起動した自分の子は INT 無視で始まり、非対話 bash は無視済みを戻せない。cargo の起動と同じ（無視なし）にするため perl で既定へ戻して起動する
# shellcheck disable=SC2016 # perl のコード
"${perl_bin}" -e '$SIG{INT} = "DEFAULT"; $SIG{QUIT} = "DEFAULT"; exec @ARGV' -- env "${D}=30" "${target}" "${work}/int-main.sh" >/dev/null 2>&1 &
wp=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  [ -s "${work}/int.sigign" ] && break
  sleep 0.2
done
# SigIgn の bit1（INT）と bit2（QUIT）が立っていない（下位 16 進桁の 6 が 0）こと
mask=$(awk '{print $2}' "${work}/int.sigign" 2>/dev/null)
expect_eq int-not-ignored 0 "$(( 0x${mask:-6} & 6 ))"
kill -INT "${wp}"
wait "${wp}" 2>/dev/null
expect_eq int-rc 130 "$?"

# 11. 入力検査
for v in abc 3601 -1 ""; do
  run "${D}=${v}" -- "${target}" true
  expect_eq "invalid-${v}" 2 "$(rc)"
  expect_contains "invalid-${v}-msg" "${work}/err" "code=invalid-argument"
done
run -- "${target}"
expect_eq noargs 2 "$(rc)"

if [ "${fails}" -ne 0 ]; then
  echo "test-bin-watchdog-selftest: ${fails} failure(s)" >&2
  exit 1
fi
echo "test-bin-watchdog-selftest: all cases passed"
