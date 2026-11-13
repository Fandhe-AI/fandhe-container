#!/usr/bin/env bash
# mac_small_files.sh の自己テスト（make mac-small-files-selftest。MAC-3・TASK-70 準備・#1880・REPAIR-12）。
#
# スタブの docker CLI（bash）と一時ディレクトリのみで、引数検証・起動引数・集計の具体値・件数不一致・期限・
# 後始末（所有の証明）・own（スタブの自前 CLI の create / start / state / logs / inspect / delete。#3106）・report の率を
# 照合する。実 Docker Desktop・実ランタイム・root は使わない。
# 呼び出し元: Makefile の `mac-small-files-selftest`（CI は bench-regression の並列グループ）。
# 失敗が 1 件でもあれば非ゼロで終わる。docker モードは bash 3.2 以上・perl（Time::HiRes）・jq が必要（#3104）。
# 全ケースを PATH の bash と、別にある場合は /bin/bash（macOS では 3.2）の両方で回す（lib-selftest と同じ方式）。
# 各回の先頭に shell=<path> version=<版> を出す。この行が無いのに緑なら、3.2 で回っていない。
# さらに perl の版の組（variant）を 2 つ回す。path は PATH の perl（macOS の CI では Homebrew 版のことがある）、
# system は macOS 標準の /usr/bin/perl へ exec する wrapper を PATH の先頭へ置いた回（#3354）。system の回は
# perl-variant=system perl=<版> hires=<版> path=<$^X> invoked=<wrapper> の観測行を出し、wrapper のログで
# probe（-MTime::HiRes）と各試行の計測（-e）が /usr/bin/perl を通ったことを具体値で照合する。Darwin では
# /usr/bin/perl に Time::HiRes が無ければ失敗させる（skip で緑にしない）。Darwin 以外では PATH の perl と
# 実体が同じか /usr/bin/perl が無ければ perl-variant=system skipped reason=... の行を出して飛ばす。
# 注意: ubuntu の /bin/bash は 5.x のため、bench-regression では 3.2 の実行は起きない。3.2 の実行は
# platform-ci の macOS のステップ（main への push と workflow_dispatch）が担う。
set -euo pipefail
export LC_ALL=C

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SELF_DIR}/mac_small_files.sh"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
TMP_ROOT="$(cd "$TMP_ROOT" && pwd -P)"

# 時刻源の観測値（設計書 docs/design/mac-small-files-bench.md「時刻源」の観測欄の根拠。ログに残す）。
perl -MTime::HiRes -e 'print "perl=$^V hires=$Time::HiRes::VERSION path=$^X\n"' || {
  echo "error: perl with Time::HiRes is required" >&2
  exit 2
}

# system variant（#3354）: /usr/bin/perl へ exec する wrapper。第 1 引数（-MTime::HiRes か -e）だけをログへ残し、
# 計測コード本体は残さない。起動は t0 の前に終わるので計測区間には入らない。
SYSPERL_DIR="${TMP_ROOT}/sysperl"
SYSPERL_LOG="${TMP_ROOT}/sysperl.log"
mkdir -p "$SYSPERL_DIR"
: >"$SYSPERL_LOG"
cat >"${SYSPERL_DIR}/perl" <<WRAP
#!/bin/sh
printf '%s\n' "\$1" >>"${SYSPERL_LOG}"
exec /usr/bin/perl "\$@"
WRAP
chmod 755 "${SYSPERL_DIR}/perl"
RUN_SYSTEM=0
if [ -x /usr/bin/perl ] && /usr/bin/perl -MTime::HiRes -e 1 >/dev/null 2>&1; then
  path_x="$(perl -e 'print $^X')"
  sys_x="$(/usr/bin/perl -e 'print $^X')"
  if [ "$(uname -s)" = Darwin ] || [ "$path_x" != "$sys_x" ]; then
    RUN_SYSTEM=1
  else
    echo "perl-variant=system skipped reason=same-as-path"
  fi
elif [ "$(uname -s)" = Darwin ]; then
  echo "error: /usr/bin/perl with Time::HiRes is required on macOS" >&2
  exit 2
else
  echo "perl-variant=system skipped reason=absent"
fi

SHELLS=("$(command -v bash)")
if [ -x /bin/bash ] && [ "$(command -v bash)" != "/bin/bash" ]; then SHELLS+=(/bin/bash); fi

PASS=0
FAIL=0
SHELL_TAG=""
pass() { PASS=$((PASS + 1)); echo "PASS: [${SHELL_TAG}] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: [${SHELL_TAG}] $1"; }
# check <name> <command...>: コマンドが成功すれば PASS。
check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

# run_cases <シェル> <通し番号> <perl variant: path|system>: 全ケースを指定のシェルで回す。作業ディレクトリは回ごとに作り直す。
run_cases() {
UNDER_SHELL="$1"
VARIANT="$3"
SHELL_TAG="$(basename "$1")#$2/${VARIANT}"
SAVED_PATH="$PATH"
if [ "$VARIANT" = system ]; then PATH="${SYSPERL_DIR}:${PATH}"; fi
echo "shell=$1 version=$("$1" -c 'echo $BASH_VERSION')"
echo "perl-variant=${VARIANT} $(perl -MTime::HiRes -e 'print "perl=$^V hires=$Time::HiRes::VERSION path=$^X"') invoked=$(command -v perl)"
TMP="${TMP_ROOT}/$2-${VARIANT}"
mkdir -p "$TMP"
HOST="${TMP}/host"
mkdir -p "$HOST"
STUB_DIR="${TMP}/stub"
mkdir -p "$STUB_DIR"
export STUB_DIR

# スタブの docker。STUB_MODE: slow / ok / noimage / shortcount / badts / hang / stuck / nobind / failrun / onebad
cat >"${STUB_DIR}/docker" <<'STUB'
#!/usr/bin/env bash
calls="${STUB_DIR}/calls"
psf="${STUB_DIR}/ps"
case "${1:-}" in
  image)
    echo "$*" >>"$calls"
    [ "${STUB_MODE:-ok}" = noimage ] && exit 1
    echo "sha256:$(printf 'a%.0s' $(seq 1 64))"
    exit 0
    ;;
  version) echo "$*" >>"$calls"; echo "27.0.0"; exit 0 ;;
  ps)
    echo "$*" >>"$calls"
    lab=""
    for a in "$@"; do case "$a" in label=*) lab="${a#label=}" ;; esac; done
    tag="${lab##*=}"
    if [ "${STUB_MODE:-ok}" = stuck ]; then printf 'f%.0s' $(seq 1 64); echo; exit 0; fi
    [ -f "$psf" ] && awk -v t="$tag" '$1 == t { print $2 }' "$psf"
    exit 0
    ;;
  rm)
    echo "$*" >>"$calls"
    if [ -f "$psf" ]; then grep -v " $3\$" "$psf" >"$psf.new" || true; mv "$psf.new" "$psf"; fi
    exit 0
    ;;
  run)
    n=$(( $(cat "${STUB_DIR}/n" 2>/dev/null || echo 0) + 1 ))
    echo "$n" >"${STUB_DIR}/n"
    cid="$(printf '%064x' "$n")"
    script="${!#}"
    echo "${*:1:$#-1}" >>"$calls"
    cidfile="" lab="" vol=""
    args=("$@")
    i=0
    while [ "$i" -lt "$#" ]; do
      case "${args[$i]}" in
        --cidfile) cidfile="${args[$((i + 1))]}" ;;
        --label) lab="${args[$((i + 1))]}" ;;
        -v) vol="${args[$((i + 1))]}" ;;
      esac
      i=$((i + 1))
    done
    [ -z "$cidfile" ] || printf '%s' "$cid" >"$cidfile"
    tag="${lab##*=}"
    echo "$tag $cid" >>"$psf"
    host="${vol%%:*}"
    finish() { grep -v " $cid\$" "$psf" >"$psf.new" || true; mv "$psf.new" "$psf"; }
    case "$script" in
      *probe*)
        [ "${STUB_MODE:-ok}" = nobind ] || echo probe >"$host/probe"
        finish
        exit 0
        ;;
    esac
    printf '%s' "$script" >"${STUB_DIR}/last_script"
    [ "${STUB_MODE:-ok}" = hang ] && exec sleep 30
    [ "${STUB_MODE:-ok}" = slow ] && sleep 0.3
    count="$(printf '%s' "$script" | sed -n 's/.*-lt \([0-9]*\) .*/\1/p' | head -1)"
    batch="$(printf '%s' "$script" | sed -n 's/.*% \([0-9]*\)).*/\1/p' | head -1)"
    ts=1700000000000000000
    # onebad: 4 回目の run（probe を含む。試行 3）だけ区間が巨大で件数も不一致の失敗試行にする。
    mul=1
    if [ "${STUB_MODE:-ok}" = onebad ] && [ "$n" -eq 4 ]; then mul=1000; fi
    if [ "${STUB_MODE:-ok}" = badts ]; then echo "TS %N"; else echo "TS $ts"; fi
    k=1
    while [ "$k" -le $((count / batch)) ]; do
      ts=$((ts + k * 100 * batch * mul))
      echo "TS $ts"
      k=$((k + 1))
    done
    if [ "${STUB_MODE:-ok}" = shortcount ] || { [ "${STUB_MODE:-ok}" = onebad ] && [ "$n" -eq 4 ]; }; then echo "FILES_CREATED=$((count - 1))"; else echo "FILES_CREATED=$count"; fi
    echo DONE
    finish
    [ "${STUB_MODE:-ok}" = failrun ] && exit 1
    exit 0
    ;;
esac
exit 0
STUB
chmod 755 "${STUB_DIR}/docker"
DOCKER="${STUB_DIR}/docker"

# スタブの自前 CLI（#3106）。STUB_MODE: ok / shortcount / badts / hang（start が戻らない）/ nobind / failcreate / stuck / nonzero / slow
cat >"${STUB_DIR}/fandhe" <<'STUB'
#!/usr/bin/env bash
calls="${STUB_DIR}/calls"
od="${STUB_DIR}/own"
mkdir -p "$od"
cmd="${1:-}"
echo "$*" >>"$calls"
nf() { echo '{"code":"NOT_FOUND","message":"container not found"}' >&2; exit 3; }
case "$cmd" in
  create)
    bundle="" lab="" id=""
    shift
    while [ $# -gt 0 ]; do
      case "$1" in
        --bundle) bundle="$2"; shift 2 ;;
        --label) lab="$2"; shift 2 ;;
        *) id="$1"; shift ;;
      esac
    done
    if [ "${STUB_MODE:-ok}" = failcreate ]; then
      echo '{"code":"UNIMPLEMENTED","message":"secret detail /private/path"}' >&2
      exit 12
    fi
    if [ "${STUB_MODE:-ok}" = exists ]; then
      echo foreign >"$od/$id.status"
      echo '{"code":"ALREADY_EXISTS","message":"container exists"}' >&2
      exit 6
    fi
    [ -f "$bundle/config.json" ] || exit 1
    [ "${STUB_MODE:-ok}" = slow ] && sleep 0.2
    jq -r '.mounts[0].source' "$bundle/config.json" >"$od/$id.src"
    jq -r '.process.args[2]' "$bundle/config.json" >"$od/$id.script"
    jq -e '.root.readonly == true and .mounts[0].destination == "/data" and .mounts[0].options == ["rbind","rw"]' "$bundle/config.json" >/dev/null || exit 1
    echo "$lab" >"$od/$id.label"
    echo created >"$od/$id.status"
    echo 0 >"$od/$id.polls"
    exit 0
    ;;
  start)
    id="$2"
    [ -f "$od/$id.status" ] || nf
    [ "${STUB_MODE:-ok}" = hang ] && exec sleep 30
    echo running >"$od/$id.status"
    if grep -q 'echo probe' "$od/$id.script" && [ "${STUB_MODE:-ok}" != nobind ]; then
      echo probe >"$(cat "$od/$id.src")/probe"
    fi
    exit 0
    ;;
  state)
    id="$2"
    [ -f "$od/$id.status" ] || nf
    st="$(cat "$od/$id.status")"
    if [ "$st" = running ]; then
      p=$(( $(cat "$od/$id.polls") + 1 ))
      echo "$p" >"$od/$id.polls"
      if [ "$p" -ge 2 ]; then st=stopped; echo stopped >"$od/$id.status"; fi
    fi
    printf '{"ociVersion":"1.3.0","id":"%s","status":"%s"}\n' "$id" "$st"
    exit 0
    ;;
  kill)
    id="$2"
    [ -f "$od/$id.status" ] || nf
    echo stopped >"$od/$id.status"
    exit 0
    ;;
  logs)
    id="${!#}"
    [ -f "$od/$id.status" ] || nf
    script="$(cat "$od/$id.script")"
    count="$(printf '%s' "$script" | sed -n 's/.*-lt \([0-9]*\) .*/\1/p' | head -1)"
    batch="$(printf '%s' "$script" | sed -n 's/.*% \([0-9]*\)).*/\1/p' | head -1)"
    ts=1700000000000000000
    if [ "${STUB_MODE:-ok}" = badts ]; then echo "stdout TS %N"; else echo "stdout TS $ts"; fi
    k=1
    while [ "$k" -le $((count / batch)) ]; do
      ts=$((ts + k * 100 * batch))
      echo "stdout TS $ts"
      k=$((k + 1))
    done
    if [ "${STUB_MODE:-ok}" = shortcount ]; then echo "stdout FILES_CREATED=$((count - 1))"; else echo "stdout FILES_CREATED=$count"; fi
    echo "stdout DONE"
    exit 0
    ;;
  inspect)
    id="$2"
    [ -f "$od/$id.status" ] || nf
    ec=0
    [ "${STUB_MODE:-ok}" = nonzero ] && ec=3
    printf '{"id":"%s","status":"%s","pid":null,"exitCode":%s}\n' "$id" "$(cat "$od/$id.status")" "$ec"
    exit 0
    ;;
  delete)
    id="$2"
    [ -f "$od/$id.status" ] || nf
    [ "${STUB_MODE:-ok}" = slow ] && sleep 0.1
    [ "${STUB_MODE:-ok}" = stuck ] || rm -f "$od/$id".*
    exit 0
    ;;
esac
exit 0
STUB
chmod 755 "${STUB_DIR}/fandhe"
FANDHE="${STUB_DIR}/fandhe"

reset_stub() {
  : >"${STUB_DIR}/calls"
  : >"${STUB_DIR}/ps"
  rm -f "${STUB_DIR}/n"
  rm -rf "${STUB_DIR}/own"
  mkdir -p "${STUB_DIR}/own"
  export STUB_MODE="${1:-ok}"
}

# runit <args...>: 出力を $TMP/out・$TMP/err に取り、終了コードを rc に入れる。
rc=0
runit() {
  rc=0
  "$UNDER_SHELL" "$SCRIPT" "$@" >"${TMP}/out" 2>"${TMP}/err" || rc=$?
}
rc_is() { [ "$rc" -eq "$1" ]; }
calls_count() { grep -c "^$1" "${STUB_DIR}/calls" || true; }
count_is() { [ "$(calls_count "$1")" -eq "$2" ]; }
jq_ok() { jq -e "$1" "$2"; }
no_verdict_key() { jq -e '[.. | objects | keys[]] | all(. != "pass" and . != "passed" and . != "verdict")' "$1"; }
empty_file() { [ ! -s "$1" ]; }
dir_empty() { [ -z "$(ls -A "$1")" ]; }
err_has() { grep -q -- "$1" "${TMP}/err"; }
calls_has() { grep -q -- "$1" "${STUB_DIR}/calls"; }

# --- 入力エラー（副作用の前。スタブ呼び出し 0 回） ---
reset_stub ok
runit --mode docker --runtime docker --host-dir "$HOST"
check "relative --runtime is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir relative/dir
check "relative --host-dir is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --trials 4
check "--trials 4 is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --trials 21
check "--trials 21 is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --count 2000 --count 2000
check "duplicate argument is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --count 2001 --batch 20
check "--count not a multiple of --batch is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "${HOST}/../host"
check "--host-dir with .. is rejected with 2" rc_is 2
ln -s "$HOST" "${TMP}/link"
runit --mode docker --runtime "$DOCKER" --host-dir "${TMP}/link"
check "symlinked --host-dir is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --image 'bad image;rm'
check "bad --image is rejected with 2" rc_is 2
: >"${TMP}/exists.json"
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --output "${TMP}/exists.json"
check "existing --output is rejected with 2" rc_is 2
check "no docker call happened on input errors" empty_file "${STUB_DIR}/calls"

# --- 正常系: 起動引数と集計の具体値 ---
reset_stub ok
: >"$SYSPERL_LOG"
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --label stub --output "${TMP}/res.json"
check "ok run exits 0" rc_is 0
if [ "$VARIANT" = system ]; then
  # 既定の試行数 5 に対し、probe（-MTime::HiRes）が 1 回、計測ラッパー（-e）が docker 起動 6 回（試行 5＋bind 確認 1）分呼ばれたこと。
  check "system perl: PATH resolves perl to the wrapper" test "$(command -v perl)" = "${SYSPERL_DIR}/perl"
  check "system perl: probe went through /usr/bin/perl once" test "$(grep -c '^-MTime::HiRes$' "$SYSPERL_LOG" || true)" -eq 1
  check "system perl: 6 timed docker runs went through /usr/bin/perl" test "$(grep -c '^-e$' "$SYSPERL_LOG" || true)" -eq 6
fi
if [ "$rc" -ne 0 ]; then cat "${TMP}/err"; fi
runl="$(grep '^run ' "${STUB_DIR}/calls" | tail -1)"
for want in '--pull never' '--rm' '--cidfile' '--label fandhe.mac-small-files.run=' ":/data sha256:$(printf 'a%.0s' $(seq 1 64)) "; do
  case "$runl" in *"$want"*) pass "run line has: $want" ;; *) fail "run line has: $want (got: $runl)" ;; esac
done
check "image inspect was called before run" calls_has '^image inspect'
check "5 workload runs plus 1 probe" count_is 'run ' 6
check "p95 is 9.5 us (pooled per-batch ns/op)" jq_ok '.metrics.metadata_p95_us.value == 9.5 and .metrics.metadata_p95_us.unit == "us" and .metrics.metadata_p95_us.method == "batch-boundary-provisional"' "${TMP}/res.json"
check "schema, target and workload fields" jq_ok '.schema == "fandhe-container.mac-small-files/v1" and .target == "docker" and .label == "stub" and .mount_kind == "bind" and .workload.count == 2000 and .workload.batch == 20 and .workload.file_bytes == 2 and .trials_ok == 5 and .backend_version == "27.0.0" and (.samples | length) == 5 and .metrics.wall_clock_median_ms.method == "docker-run-rm-total"' "${TMP}/res.json"
check "per-trial sample p95 is 9500 ns/op" jq_ok 'all(.samples[]; .interval_ns_per_op_p95 == 9500 and .intervals == 100 and .interval_ns_per_op_min == 100 and .interval_ns_per_op_max == 10000)' "${TMP}/res.json"
check "wall clock median is a positive number" jq_ok '.metrics.wall_clock_median_ms.value > 0' "${TMP}/res.json"
check "no pass/fail key in the result" no_verdict_key "${TMP}/res.json"
if ! grep -q "$TMP" "${TMP}/res.json" && ! grep -qi "$(hostname)" "${TMP}/res.json"; then
  pass "result has no absolute path or host name"
else
  fail "result has no absolute path or host name"
fi
check "work directories under host-dir are removed" dir_empty "$HOST"
check "no leftover containers listed" empty_file "${STUB_DIR}/ps"
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --output "${TMP}/res.json"
check "second run with the same --output is rejected with 2" rc_is 2

# --- イメージ未取得 ---
reset_stub noimage
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "missing image exits 1" rc_is 1
check "missing image: run was never called" count_is 'run ' 0

# --- 失敗の検出 ---
reset_stub shortcount
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "file count mismatch (1999) exits 1" rc_is 1
check "count mismatch is reported" err_has 'file count mismatch'
reset_stub badts
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "unexpanded %N timestamps exit 1" rc_is 1
# BusyBox の date は %N 非対応（#3079）。ワークロードは %N を使わず、/proc/uptime 由来の数値だけの時刻を出す。
reset_stub ok
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
no_pct_n() { ! grep -q '%N' "${STUB_DIR}/last_script"; }
check "workload script does not use date %N" no_pct_n
workload_fake_uptime() {
  local w="${TMP}/wl" up
  for up in "0.05" "12345.67" "100000.09"; do
    rm -rf "$w"
    mkdir -p "$w/data"
    echo "$up 0.00" >"$w/uptime"
    sed -e "s#/proc/uptime#$w/uptime#" -e "s#/data#$w/data#g" "${STUB_DIR}/last_script" >"$w/s.sh"
    sh "$w/s.sh" >"$w/out" 2>&1 || return 1
    # 先頭と末尾以外の TS 行が全て数字のみで、DONE がある
    [ "$(grep -c '^TS [0-9][0-9]*$' "$w/out")" -ge 2 ] || return 1
    grep -q '^DONE$' "$w/out" || return 1
  done
}
check "workload emits numeric timestamps from /proc/uptime (no date %N)" workload_fake_uptime
reset_stub failrun
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "failed docker run exits 1 (fewer than 5 valid trials)" rc_is 1
reset_stub nobind
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "bind not effective exits 1" rc_is 1
check "bind failure is reported" err_has 'bind mount is not effective'

# 失敗試行（件数不一致）の区間は p95 に混ざらない（6 試行中 1 試行が失敗でも p95 は 9.5 us のまま）
reset_stub onebad
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --trials 6 --output "${TMP}/onebad.json"
check "one failed trial of six: exits 0" rc_is 0
check "failed trial is excluded from pooled p95 and trials_ok" jq_ok '.trials_ok == 5 and .metrics.metadata_p95_us.value == 9.5' "${TMP}/onebad.json"

# --- 期限と後始末（所有の証明） ---
reset_stub hang
other_id="$(printf '%064x' 99999)"
echo "1111111111111111 ${other_id}" >"${STUB_DIR}/ps"
start=$SECONDS
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --trial-timeout-secs 1
elapsed=$((SECONDS - start))
check "hung trial exits 1" rc_is 1
if [ "$elapsed" -lt 60 ]; then pass "hung trial returns within the bound (took ${elapsed}s)"; else fail "hung trial returns within the bound (took ${elapsed}s)"; fi
mine="$(printf '%064x' 2)"
check "owned container was removed with rm -f" calls_has "^rm -f ${mine}\$"
check "ps with the exact run label filter was used" calls_has 'label=fandhe.mac-small-files.run=[0-9a-f]\{16\}'
if grep -q "$other_id" "${STUB_DIR}/ps" && ! calls_has "^rm -f ${other_id}"; then
  pass "other token's container is untouched"
else
  fail "other token's container is untouched"
fi
check "deadline failure is reported" err_has 'exceeded its deadline'

reset_stub stuck
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "containers that cannot be removed exit 4" rc_is 4
check "cleanup-failed is reported" err_has 'code=cleanup-failed'
reset_stub stuck
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --output "${TMP}/stuck.json"
check "cleanup failure: exit 4 with --output" rc_is 4
check "cleanup failure: result file is not published" test ! -e "${TMP}/stuck.json"
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "cleanup failure: nothing on stdout" empty_file "${TMP}/out"

# --- own（自前 CLI の契約で計測する。#3106）---
SHARED="${TMP}/shared"
BUNDLE="${SHARED}/bundle"
OWNHOST="${SHARED}/work"
mkdir -p "${BUNDLE}/rootfs" "$OWNHOST"
IMGID="sha256:$(printf 'a%.0s' $(seq 1 64))"
runown() {
  runit --mode own --runtime "$FANDHE" --shared-root "$SHARED" --host-dir "$OWNHOST" --bundle "$BUNDLE" --image-id "$IMGID" "$@"
}
own_left() { find "${STUB_DIR}/own" -type f | grep -c . || true; }
own_clean() { [ ! -e "${BUNDLE}/config.json" ] && dir_empty "$OWNHOST" && [ "$(own_left)" -eq 0 ]; }

# 入力エラー（副作用の前。CLI の呼び出し 0 回・終了コード 2）
reset_stub ok
mkdir -p "${TMP}/outside" "${BUNDLE}/sub" "${SHARED}/outer/b/rootfs"
runown --host-dir "${TMP}/outside"
check "own: --host-dir outside --shared-root is rejected with 2" rc_is 2
runit --mode own --runtime "$FANDHE" --shared-root "$SHARED" --host-dir "$OWNHOST" --bundle "${TMP}/outside" --image-id "$IMGID"
check "own: --bundle outside --shared-root is rejected with 2" rc_is 2
runown --host-dir "${BUNDLE}/sub"
check "own: --host-dir inside --bundle is rejected with 2" rc_is 2
runit --mode own --runtime "$FANDHE" --shared-root "$SHARED" --host-dir "${SHARED}/outer" --bundle "${SHARED}/outer/b" --image-id "$IMGID"
check "own: --bundle inside --host-dir is rejected with 2" rc_is 2
runit --mode own --runtime "$FANDHE" --shared-root "$SHARED" --host-dir "$SHARED" --bundle "$BUNDLE" --image-id "$IMGID"
check "own: --host-dir equal to --shared-root is rejected with 2" rc_is 2
: >"${BUNDLE}/config.json"
runown
check "own: an existing bundle config.json is rejected with 2" rc_is 2
check "own: the existing config.json is left untouched" test -e "${BUNDLE}/config.json"
rm -f "${BUNDLE}/config.json"
runown --image-id "sha256:abc"
check "own: a short --image-id is rejected with 2" rc_is 2
runown --image-id "abc"
check "own: an --image-id without sha256: is rejected with 2" rc_is 2
ln -s "$SHARED" "${TMP}/shared-link"
runit --mode own --runtime "$FANDHE" --shared-root "${TMP}/shared-link" --host-dir "$OWNHOST" --bundle "$BUNDLE" --image-id "$IMGID"
check "own: a symlinked --shared-root is rejected with 2" rc_is 2
runit --mode own --runtime "$FANDHE" --host-dir "$OWNHOST" --bundle "$BUNDLE" --image-id "$IMGID"
check "own: missing --shared-root is rejected with 2" rc_is 2
runown --own-result "${TMP}/x.json"
check "own: --own-result is rejected with 2" rc_is 2
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --shared-root "$SHARED"
check "docker: --shared-root is rejected with 2" rc_is 2
check "own: no CLI call happened on input errors" empty_file "${STUB_DIR}/calls"

# 正常系: 呼び出しの列・集計の具体値・後始末
reset_stub ok
runown --label ownstub --output "${TMP}/own-res.json"
if [ "$rc" -ne 0 ]; then cat "${TMP}/err"; fi
check "own: ok run exits 0" rc_is 0
check "own: create passes --bundle and the exact run label" calls_has '^create --bundle .* --label fandhe.mac-small-files.run=[0-9a-f]\{16\} fms-[0-9a-f]\{16\}-1$'
check "own: 5 trials plus 1 probe each create, start and delete once" test "$(calls_count 'create ')" -eq 6 -a "$(calls_count 'start ')" -eq 6 -a "$(calls_count 'delete ')" -eq 6
check "own: logs are read with --follow --stream stdout" calls_has '^logs --follow --stream stdout fms-'
check "own: no --root is passed" test "$(grep -c -- '--root' "${STUB_DIR}/calls" || true)" -eq 0
check "own: result schema, target, mode and declared image id" jq_ok '.schema == "fandhe-container.mac-small-files/v1" and .target == "own" and .mode == "own" and .label == "ownstub" and .mount_kind == "bind" and .trials_ok == 5 and .image_id == "'"$IMGID"'" and .image_id_source == "declared" and .shared_root_checked == true and .backend_version == "unknown" and (.samples | length) == 5' "${TMP}/own-res.json"
check "own: metric methods" jq_ok '.metrics.wall_clock_median_ms.method == "cli-create-start-wait-delete-total" and .metrics.metadata_p95_us.method == "batch-boundary-provisional" and .metrics.metadata_p95_us.value == 9.5 and .metrics.wall_clock_median_ms.value > 0' "${TMP}/own-res.json"
check "own: samples carry the stage breakdown and 2 state polls" jq_ok 'all(.samples[]; .state_polls == 2 and .create_us >= 0 and .start_us >= 0 and .wait_us >= 0 and .delete_us >= 0 and .wall_us > 0 and .interval_ns_per_op_p95 == 9500)' "${TMP}/own-res.json"
check "own: workload fields match the docker side" jq_ok '.workload.count == 2000 and .workload.batch == 20 and .workload.file_bytes == 2' "${TMP}/own-res.json"
check "own: no pass/fail key in the result" no_verdict_key "${TMP}/own-res.json"
if ! grep -q "$TMP" "${TMP}/own-res.json"; then pass "own: result has no absolute path"; else fail "own: result has no absolute path"; fi
check "own: config.json, work directories and containers are all removed" own_clean

# 失敗の検出
reset_stub failcreate
runown --output "${TMP}/own-fail.json"
check "own: a CLI failure exits 1" rc_is 1
check "own: the CLI error code is reported" err_has 'cli code=UNIMPLEMENTED'
if ! grep -q 'secret' "${TMP}/err" && ! grep -q "$TMP" "${TMP}/err"; then pass "own: the CLI message and paths are not echoed"; else fail "own: the CLI message and paths are not echoed"; fi
check "own: a failed run publishes no result" test ! -e "${TMP}/own-fail.json"
check "own: a failed run leaves no config.json behind" test ! -e "${BUNDLE}/config.json"
check "own: a failed create sends no kill, delete or state" test "$(grep -c '^kill\|^delete\|^state' "${STUB_DIR}/calls" || true)" -eq 0
reset_stub exists
runown --output "${TMP}/own-exists.json"
check "own: ALREADY_EXISTS exits 1 (not cleanup-failed)" rc_is 1
check "own: ALREADY_EXISTS sends no kill, delete or state" test "$(grep -c '^kill\|^delete\|^state' "${STUB_DIR}/calls" || true)" -eq 0
check "own: ALREADY_EXISTS leaves the existing container untouched" test "$(cat "${STUB_DIR}"/own/*.status)" = foreign
check "own: ALREADY_EXISTS does not report cleanup-failed" test "$(grep -c 'cleanup-failed' "${TMP}/err" || true)" -eq 0
reset_stub nonzero
runown
check "own: a non-zero container exit code exits 1" rc_is 1
check "own: the exit code failure is reported" err_has 'did not exit with code 0'
reset_stub shortcount
runown
check "own: file count mismatch exits 1" rc_is 1
check "own: count mismatch is reported" err_has 'file count mismatch'
reset_stub badts
runown
check "own: unexpanded timestamps exit 1" rc_is 1
reset_stub nobind
runown
check "own: bind not effective exits 1" rc_is 1
check "own: bind failure is reported" err_has 'bind mount is not effective'
check "own: bind failure leaves nothing behind" own_clean

# 期限と後始末
reset_stub hang
start=$SECONDS
runown --trial-timeout-secs 1
elapsed=$((SECONDS - start))
check "own: a hung start exits 1" rc_is 1
check "own: a hung start is reported as a deadline" err_has 'deadline'
if [ "$elapsed" -lt 60 ]; then pass "own: hung start returns within the bound (took ${elapsed}s)"; else fail "own: hung start returns within the bound (took ${elapsed}s)"; fi
check "own: a hung run is reaped (kill then delete) and nothing remains" own_clean
reset_stub stuck
runown --output "${TMP}/own-stuck.json"
check "own: containers that cannot be removed exit 4" rc_is 4
check "own: cleanup-failed is reported" err_has 'code=cleanup-failed'
check "own: cleanup failure publishes no result" test ! -e "${TMP}/own-stuck.json"
check "own: cleanup failure still removes config.json" test ! -e "${BUNDLE}/config.json"
rm -rf "${STUB_DIR}/own"
mkdir -p "${STUB_DIR}/own"

# 区間は呼び出しの前後を挟む（スタブの create が 0.2 秒・delete が 0.1 秒）
reset_stub slow
runown --output "${TMP}/own-slow.json"
check "own: slow run exits 0" rc_is 0
check "own: each wall clock spans create and delete (>= 0.3s)" jq_ok 'all(.samples[]; .wall_us >= 300000 and .wall_us < 30000000)' "${TMP}/own-slow.json"

# own の結果を report に通す（docker の結果と組む）
reset_stub ok
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --output "${TMP}/own-dres.json"
check "own report: docker baseline run exits 0" rc_is 0
reset_stub ok
runown --output "${TMP}/own-ores.json"
check "own report: own run exits 0" rc_is 0
runit --mode report --own-result "${TMP}/own-ores.json" --baseline-result "${TMP}/own-dres.json"
check "own report: provisional pair gives numeric ratios" jq_ok '.wall_clock_method_match == "provisional-pair" and (.wall_clock_reduction_ratio | type) == "number" and .metadata_p95_reduction_ratio == 0 and .methods_differ == false' "${TMP}/out"
jq '.metrics.wall_clock_median_ms.method = "something-else"' "${TMP}/own-ores.json" >"${TMP}/own-ores-bad.json"
runit --mode report --own-result "${TMP}/own-ores-bad.json" --baseline-result "${TMP}/own-dres.json"
check "own report: a method outside the pair table gives null and methods_differ" jq_ok '.wall_clock_method_match == null and .wall_clock_reduction_ratio == null and .methods_differ == true' "${TMP}/out"
jq ".image_id = \"sha256:$(printf 'b%.0s' $(seq 1 64))\"" "${TMP}/own-ores.json" >"${TMP}/own-ores-id.json"
runit --mode report --own-result "${TMP}/own-ores-id.json" --baseline-result "${TMP}/own-dres.json"
check "own report: a different declared image id gives null ratios" jq_ok '.wall_clock_reduction_ratio == null and .metadata_p95_reduction_ratio == null' "${TMP}/out"

# --- report ---
# mkres <target> <wall_ms> <p95_us> [method] [count] [image_id]
mkres() {
  jq -n --arg id "${6:-sha256:$(printf 'a%.0s' $(seq 1 64))}" --arg t "$1" --argjson w "$2" --argjson p "$3" --arg m "${4:-batch-boundary-provisional}" --argjson c "${5:-2000}" '
    { schema: "fandhe-container.mac-small-files/v1", mode: $t, target: $t, label: $t, image: "alpine:3.20", image_id: $id, mount_kind: "bind",
      workload: { count: $c, file_bytes: 2, batch: 20, ops: "x" }, trials_ok: 5,
      metrics: { wall_clock_median_ms: { value: $w, unit: "ms", method: "docker-run-rm-total" },
                 metadata_p95_us: { value: $p, unit: "us", method: $m } } }'
}
mkres docker 1000 100 >"${TMP}/b.json"
mkres own 800 75 >"${TMP}/o.json"
runit --mode report --own-result "${TMP}/o.json" --baseline-result "${TMP}/b.json"
check "report exits 0" rc_is 0
check "report ratios are 0.2 and 0.25 and methods agree" jq_ok '.wall_clock_reduction_ratio == 0.2 and .metadata_p95_reduction_ratio == 0.25 and .methods_differ == false and .schema == "fandhe-container.mac-small-files-report/v1"' "${TMP}/out"
check "report has no pass/fail key" no_verdict_key "${TMP}/out"
mkres own 800 75 "per-op-exact" >"${TMP}/o2.json"
runit --mode report --own-result "${TMP}/o2.json" --baseline-result "${TMP}/b.json"
check "method mismatch: p95 ratio null, wall ratio stays, methods_differ true" jq_ok '.metadata_p95_reduction_ratio == null and .wall_clock_reduction_ratio == 0.2 and .methods_differ == true' "${TMP}/out"
mkres own 800 75 batch-boundary-provisional 5000 >"${TMP}/o3.json"
runit --mode report --own-result "${TMP}/o3.json" --baseline-result "${TMP}/b.json"
check "workload mismatch: both ratios are null" jq_ok '.metadata_p95_reduction_ratio == null and .wall_clock_reduction_ratio == null and .methods_differ == true' "${TMP}/out"
# workload / image が欠損した入力は、欠損同士が一致しても入力エラー（2）
jq 'del(.workload.count)' "${TMP}/b.json" >"${TMP}/b-nocount.json"
jq 'del(.workload.count)' "${TMP}/o.json" >"${TMP}/o-nocount.json"
runit --mode report --own-result "${TMP}/o-nocount.json" --baseline-result "${TMP}/b-nocount.json"
check "report rejects results without workload.count with 2" rc_is 2
jq 'del(.image)' "${TMP}/b.json" >"${TMP}/b-noimg.json"
jq 'del(.image)' "${TMP}/o.json" >"${TMP}/o-noimg.json"
runit --mode report --own-result "${TMP}/o-noimg.json" --baseline-result "${TMP}/b-noimg.json"
check "report rejects results without image with 2" rc_is 2
runit --mode report --own-result "${TMP}/b.json" --baseline-result "${TMP}/b.json"
check "report rejects a docker result as --own-result with 2" rc_is 2
runit --mode report --own-result "${TMP}/o.json" --baseline-result "${TMP}/o.json"
check "report rejects the same file as own and baseline with 2" rc_is 2
runit --mode report --own-result "${TMP}/o.json" --baseline-result "${TMP}/o2.json"
check "report rejects a target=own result as --baseline-result with 2" rc_is 2
# 同じタグでも image_id が違えば比較不能（率は null）
mkres own 800 75 batch-boundary-provisional 2000 "sha256:$(printf 'b%.0s' $(seq 1 64))" >"${TMP}/o-id.json"
runit --mode report --own-result "${TMP}/o-id.json" --baseline-result "${TMP}/b.json"
check "image_id mismatch: both ratios are null" jq_ok '.metadata_p95_reduction_ratio == null and .wall_clock_reduction_ratio == null' "${TMP}/out"
# 複数 JSON 値（不正な先頭 + 正しい own）は拒否（2）
{ jq -c '.target = "docker"' "${TMP}/o.json"; cat "${TMP}/o.json"; } >"${TMP}/o-multi.json"
runit --mode report --own-result "${TMP}/o-multi.json" --baseline-result "${TMP}/b.json"
check "multi-value result file is rejected with 2" rc_is 2
# unit / mount_kind / trials_ok / image_id 欠損は両側で欠けても入力エラー（2）
for k in .mount_kind .trials_ok .image_id .metrics.wall_clock_median_ms.unit; do
  jq "del($k)" "${TMP}/b.json" >"${TMP}/b-del.json"
  jq "del($k)" "${TMP}/o.json" >"${TMP}/o-del.json"
  runit --mode report --own-result "${TMP}/o-del.json" --baseline-result "${TMP}/b-del.json"
  check "report rejects results without ${k} with 2" rc_is 2
done
# p95 が 0（/proc/uptime の 10ms 分解能で起こりうる）: own 側 0 は受理して率 1、基準側 0 は p95 の率だけ null（methods_differ は false のまま）
mkres own 800 0 >"${TMP}/o-p0.json"
runit --mode report --own-result "${TMP}/o-p0.json" --baseline-result "${TMP}/b.json"
check "own p95=0 is accepted: ratio 1 and wall ratio 0.2" jq_ok '.metadata_p95_reduction_ratio == 1 and .wall_clock_reduction_ratio == 0.2 and .methods_differ == false' "${TMP}/out"
mkres docker 1000 0 >"${TMP}/b-p0.json"
runit --mode report --own-result "${TMP}/o-p0.json" --baseline-result "${TMP}/b-p0.json"
check "baseline p95=0: exits 0" rc_is 0
check "baseline p95=0: p95 ratio null, wall ratio stays, methods_differ false" jq_ok '.metadata_p95_reduction_ratio == null and .wall_clock_reduction_ratio == 0.2 and .methods_differ == false' "${TMP}/out"

# --- 時刻源（perl Time::HiRes。#3104） ---
# (a) Time::HiRes を読み込めない perl では、docker を 1 回も呼ばずに 3 で止まる。
mkdir -p "${TMP}/noperl"
printf '#!/bin/sh\nexit 1\n' >"${TMP}/noperl/perl"
chmod 755 "${TMP}/noperl/perl"
reset_stub ok
rc=0
PATH="${TMP}/noperl:${PATH}" "$UNDER_SHELL" "$SCRIPT" --mode docker --runtime "$DOCKER" --host-dir "$HOST" >"${TMP}/out" 2>"${TMP}/err" || rc=$?
check "no Time::HiRes: exits 3" rc_is 3
check "no Time::HiRes: missing-tool is reported" err_has 'code=missing-tool'
check "no Time::HiRes: no docker call happened" empty_file "${STUB_DIR}/calls"
check "no Time::HiRes: nothing left under --host-dir" dir_empty "$HOST"

# (b) 時刻ファイルが壊れている試行は失敗に数え、有効な試行が 5 未満なら 1 で終わる。
mkdir -p "${TMP}/badclock"
cat >"${TMP}/badclock/perl" <<'PSTUB'
#!/usr/bin/env bash
# 本物の perl のうち probe（-MTime::HiRes -e 1）は通し、計測呼び出し（-e <code> <tsfile> <cmd...>）では
# コマンドを実行したうえで BAD_CLOCK の内容を時刻ファイルへ書く。
case "$1" in
  -MTime::HiRes) exit 0 ;;
esac
tsf="$3"
shift 3
rc=0
"$@" || rc=$?
printf '%s\n' "$BAD_CLOCK" >"$tsf"
exit "$rc"
PSTUB
chmod 755 "${TMP}/badclock/perl"
# 数字 2 つの後に続く余分なデータ（改行の後の不正行・空白の後の不正データ・64 バイト超）も不正とする。
long_pad="$(printf '%80s' '')"
for bad in 'abc def' '200 100' '1 2 3' '1' '-1 5' '1234567890123456789 1234567890123456790' \
  $'100 200\ninvalid' "100 200${long_pad}x" "100 200${long_pad}"; do
  reset_stub ok
  rc=0
  BAD_CLOCK="$bad" PATH="${TMP}/badclock:${PATH}" "$UNDER_SHELL" "$SCRIPT" --mode docker --runtime "$DOCKER" --host-dir "$HOST" >"${TMP}/out" 2>"${TMP}/err" || rc=$?
  check "bad timing record '${bad}': exits 1" rc_is 1
  check "bad timing record '${bad}': invalid timing record is reported" err_has 'invalid timing record'
done

# (c) 区間が docker の実行の前後を挟んでいる（スタブの run が 0.3 秒かかる）。
reset_stub slow
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --output "${TMP}/slow.json"
check "slow run exits 0" rc_is 0
check "each wall clock spans the run (>= 0.3s) and stays far below the deadline" jq_ok 'all(.samples[]; .wall_us >= 300000 and .wall_us < 30000000)' "${TMP}/slow.json"

# (d) 静的走査（ガードであって証明ではない）: bash 4 以降の構文を持ち込んでいないこと。
# 対象語は分割して組み立て、このファイル自身に当たらないようにする。
banned="EPOCH""REALTIME|EPOCH""SECONDS|BASH""PID|map""file|read""array|declare -""A|declare -""g|local -""n|co""proc|wait -""n"
banned="${banned}|"'[$]\{[A-Za-z_]*,,\}|[$]\{[A-Za-z_]*\^\^\}|[|]&|;;'"&"
scan_ok=1
for f in "$SCRIPT" "${SELF_DIR}/mac_small_files_selftest.sh" "${SELF_DIR}/../targets/mac-small-files-docker.sh" "${SELF_DIR}/../targets/mac-small-files-report.sh" "${SELF_DIR}/../targets/mac-small-files-own.sh"; do
  if grep -n -E -- "$banned" "$f" | grep -v '^[0-9]*:[[:space:]]*#' | grep -q .; then
    echo "bash 4+ construct found in $f"
    scan_ok=0
  fi
done
check "no bash 4+ construct in the script, its self-test and the make wrappers" test "$scan_ok" -eq 1
PATH="$SAVED_PATH"
}

i=0
for sh in "${SHELLS[@]}"; do
  i=$((i + 1))
  run_cases "$sh" "$i" path
done
if [ "$RUN_SYSTEM" -eq 1 ]; then
  # macOS 標準の組（/bin/bash があればそれ）で /usr/bin/perl の経路を 1 回だけ回す。
  sys_sh="$(command -v bash)"
  if [ -x /bin/bash ]; then sys_sh=/bin/bash; fi
  run_cases "$sys_sh" "$((i + 1))" system
fi

echo "passed=${PASS} failed=${FAIL}"
[ "$FAIL" -eq 0 ]
