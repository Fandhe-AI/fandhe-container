#!/usr/bin/env bash
# mac_small_files.sh の自己テスト（make mac-small-files-selftest。MAC-3・TASK-70 準備・#1880・REPAIR-12）。
#
# スタブの docker CLI（bash）と一時ディレクトリのみで、引数検証・起動引数・集計の具体値・件数不一致・期限・
# 後始末（所有の証明）・own の未実装・report の率を照合する。実 Docker Desktop・実ランタイム・root は使わない。
# 呼び出し元: Makefile の `mac-small-files-selftest`（CI は bench-regression の並列グループ）。
# 失敗が 1 件でもあれば非ゼロで終わる。docker モードは bash 5 以上が必要（EPOCHREALTIME）。
set -euo pipefail
export LC_ALL=C

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SELF_DIR}/mac_small_files.sh"
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
  echo "skip: bash 5 or later is required for the docker mode tests (EPOCHREALTIME)"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TMP="$(cd "$TMP" && pwd -P)"
HOST="${TMP}/host"
mkdir -p "$HOST"
STUB_DIR="${TMP}/stub"
mkdir -p "$STUB_DIR"
export STUB_DIR

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
# check <name> <command...>: コマンドが成功すれば PASS。
check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

# スタブの docker。STUB_MODE: ok / noimage / shortcount / badts / hang / stuck / nobind / failrun
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
    [ "${STUB_MODE:-ok}" = hang ] && exec sleep 30
    count="$(printf '%s' "$script" | sed -n 's/.*-lt \([0-9]*\) .*/\1/p' | head -1)"
    batch="$(printf '%s' "$script" | sed -n 's/.*% \([0-9]*\)).*/\1/p' | head -1)"
    ts=1700000000000000000
    if [ "${STUB_MODE:-ok}" = badts ]; then echo "TS %N"; else echo "TS $ts"; fi
    k=1
    while [ "$k" -le $((count / batch)) ]; do
      ts=$((ts + k * 100 * batch))
      echo "TS $ts"
      k=$((k + 1))
    done
    if [ "${STUB_MODE:-ok}" = shortcount ]; then echo "FILES_CREATED=$((count - 1))"; else echo "FILES_CREATED=$count"; fi
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

reset_stub() {
  : >"${STUB_DIR}/calls"
  : >"${STUB_DIR}/ps"
  rm -f "${STUB_DIR}/n"
  export STUB_MODE="${1:-ok}"
}

# runit <args...>: 出力を $TMP/out・$TMP/err に取り、終了コードを rc に入れる。
rc=0
runit() {
  rc=0
  bash "$SCRIPT" "$@" >"${TMP}/out" 2>"${TMP}/err" || rc=$?
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
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST" --label stub --output "${TMP}/res.json"
check "ok run exits 0" rc_is 0
if [ "$rc" -ne 0 ]; then cat "${TMP}/err"; fi
runl="$(grep '^run ' "${STUB_DIR}/calls" | tail -1)"
for want in '--pull never' '--rm' '--cidfile' '--label fandhe.mac-small-files.run=' ':/data alpine:3.20'; do
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
reset_stub failrun
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "failed docker run exits 1 (fewer than 5 valid trials)" rc_is 1
reset_stub nobind
runit --mode docker --runtime "$DOCKER" --host-dir "$HOST"
check "bind not effective exits 1" rc_is 1
check "bind failure is reported" err_has 'bind mount is not effective'

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

# --- own は未実装 ---
reset_stub ok
runit --mode own --runtime "$DOCKER" --host-dir "$HOST" --output "${TMP}/own-out.json"
check "own exits 5" rc_is 5
check "own reports code=unimplemented" err_has 'code=unimplemented'
if [ ! -e "${TMP}/own-out.json" ]; then pass "own creates no output file"; else fail "own creates no output file"; fi
check "own makes no docker call" empty_file "${STUB_DIR}/calls"

# --- report ---
# mkres <target> <wall_ms> <p95_us> [method] [count]
mkres() {
  jq -n --arg t "$1" --argjson w "$2" --argjson p "$3" --arg m "${4:-batch-boundary-provisional}" --argjson c "${5:-2000}" '
    { schema: "fandhe-container.mac-small-files/v1", mode: $t, target: $t, label: $t, image: "alpine:3.20", mount_kind: "bind",
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
runit --mode report --own-result "${TMP}/b.json" --baseline-result "${TMP}/b.json"
check "report rejects a docker result as --own-result with 2" rc_is 2

echo "passed=${PASS} failed=${FAIL}"
[ "$FAIL" -eq 0 ]
