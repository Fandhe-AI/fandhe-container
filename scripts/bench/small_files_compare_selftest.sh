#!/usr/bin/env bash
# scripts/bench/small_files_compare.sh の自己テスト（TASK-24.1・IO-7・REPAIR-12）。
#
# 役割: 実ハーネス・cargo・実ファイル書き込みを使わず、fixture（scripts/testdata/small-files-compare/）から
# 結果 JSON を作る bash のスタブ ハーネスで、2 構成の起動引数・統合 JSON の中身（method / note / params /
# 試行数）・入力エラー（終了コード 2）・計測失敗（1）・前提ツール欠如（3）を具体値で機械照合する。
# 実測そのものは行わない（実機での計測は #107、評価は #110）。
# 呼び出し元は Makefile の `small-files-compare-selftest` と `.github/workflows/ci.yml` の
# `bench-regression` ジョブ。期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。

set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/small_files_compare.sh"
fixture_dir="${script_dir}/../testdata/small-files-compare"
bash_bin="$(command -v bash)"

failures=0
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

last_stdout=""
last_stderr=""
last_rc=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}
pass() { echo "PASS: $1"; }

# スタブのハーネス。受けた引数を 1 行にして STUB_LOG へ追記し（--output の値は OUT に置換）、STUB_MODE に応じた
# 結果 JSON を --output へ書く。
stub="${tmp_root}/stub-harness.sh"
cat >"$stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
cfg="" trials="" out="" bs="" tt="" total=""
line=""
i=0
while [ "$i" -lt "${#args[@]}" ]; do
  a="${args[$i]}"
  v="${args[$((i + 1))]:-}"
  case "$a" in
    --config) cfg="$v" ;;
    --trials) trials="$v" ;;
    --output) out="$v"; v="OUT" ;;
    --batch-size) bs="$v" ;;
    --trial-timeout-secs) tt="$v" ;;
    --timeout-secs) total="$v" ;;
  esac
  line="${line}${line:+ }${a} ${v}"
  i=$((i + 2))
done
printf '%s\n' "$line" >>"$STUB_LOG"
fixture="${STUB_FIXTURE_DIR}/harness-per-file.json"
if [ "$bs" != "1" ]; then fixture="${STUB_FIXTURE_DIR}/harness-every-k.json"; fi
mode="${STUB_MODE:-ok}"
if [ "$cfg" = "named-volume" ]; then
  case "$mode" in
    fail-nv) exit 3 ;;
    hang-nv)
      sleep 300 &
      echo "$!" >"$STUB_PIDFILE"
      wait
      ;;
  esac
fi
mk() { # jq フィルタ
  jq --arg cfg "$cfg" --argjson t "$trials" --argjson tt "$tt" --argjson total "$total" '.params.config = $cfg | .params.trials = $t | .params.trial_timeout_secs = $tt | .params.timeout_secs = $total | .trials = [range(0; $t) as $i | .trials[$i % 5]] | '"$1" "$fixture" >"$out"
}
case "$mode" in
  bad-json) echo '{not json' >"$out" ;;
  bad-config) mk '.params.config = "bind"' ;;
  bad-trials) mk 'del(.trials[0])' ;;
  bad-unit) mk '.metrics.small_files_files_per_sec.unit = "ms"' ;;
  wire) mk '.wire_path = true' ;;
  bad-layout) mk '.params.layout = "tree"' ;;
  bad-trial-timeout) mk '.params.trial_timeout_secs = 1' ;;
  bad-total-timeout) mk '.params.timeout_secs = 1' ;;
  bad-method) mk '.method = (if .params.batch_size == 1 then "server-api-direct/flush-every-k" else "server-api-direct/flush-per-file" end)' ;;
  bad-io2) mk '.io2_guaranteed = (.io2_guaranteed | not)' ;;
  mismatch) if [ "$cfg" = "named-volume" ]; then mk '.method = "server-api-direct/flush-per-file" | .io2_guaranteed = true'; else mk '.'; fi ;;
  *) mk '.' ;;
esac
STUB
chmod +x "$stub"

log="${tmp_root}/argv.log"
bind_dir="${tmp_root}/bind-root"
vol_dir="${tmp_root}/volume-root"
mkdir -p "$bind_dir" "$vol_dir"
bind_real="$(cd "$bind_dir" && pwd -P)"
vol_real="$(cd "$vol_dir" && pwd -P)"

export STUB_LOG="$log"
export STUB_FIXTURE_DIR="$fixture_dir"
export STUB_PIDFILE="${tmp_root}/stub.pid"

# 対象スクリプトを実行し、stdout・stderr・終了コードを保持する（常に 0 を返す）。
run_target() {
  local errfile="$tmp_root/stderr.txt"
  : >"$log"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" "$@" 2>"$errfile")" || last_rc=$?
  last_stderr="$(cat "$errfile")"
}
base_args() { echo --harness "$stub" --bind-root "$bind_real" --volume-root "$vol_real"; }

expect_rc() { # name rc args...
  local name="$1" expected="$2"
  shift 2
  run_target "$@"
  if [ "$last_rc" -eq "$expected" ]; then pass "$name (rc=$last_rc)"; else fail "$name: expected rc=$expected, got rc=$last_rc (stderr: $last_stderr)"; fi
}
expect_json() { # name jq-expr
  if printf '%s' "$last_stdout" | jq -e "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1: jq '$2' failed on: $last_stdout"; fi
}
expect_no_harness_call() {
  if [ ! -s "$log" ]; then pass "$1 (harness not called)"; else fail "$1: harness was called: $(cat "$log")"; fi
}

# --- 正常（per-file・既定 5 試行） ---
STUB_MODE=ok
export STUB_MODE
# shellcheck disable=SC2046
run_target $(base_args)
if [ "$last_rc" -ne 0 ]; then fail "normal: rc=$last_rc (stderr: $last_stderr)"; else pass "normal (rc=0)"; fi
expect_json "normal: schema and order" '.schema == "fandhe-container.small-files-compare/v1" and .behavior == "IO-7" and .order == ["bind","named-volume"] and .trials_per_config == 5'
expect_json "normal: configs" '.results.bind.params.config == "bind" and .results["named-volume"].params.config == "named-volume"'
expect_json "normal: trial counts" '(.results.bind.trials | length) == 5 and (.results["named-volume"].trials | length) == 5'
expect_json "normal: method kept" '.method == "server-api-direct/flush-per-file" and .results.bind.method == "server-api-direct/flush-per-file" and .results.bind.io2_guaranteed == true and .results.bind.wire_path == false'
expect_json "normal: harness note kept" '.results.bind.note == "server API called directly, not the wire path; each file is flushed individually"'
expect_json "normal: no verdict" '(has("verdict") | not) and (has("ratio") | not) and (.note | test("TASK-24.2"))'
expected_bind="--count 2000 --batch-size 1 --file-size 2 --layout auto --config bind --trials 5 --trial-timeout-secs 1800 --timeout-secs 10800 --root ${bind_real} --output OUT"
expected_nv="--count 2000 --batch-size 1 --file-size 2 --layout auto --config named-volume --trials 5 --trial-timeout-secs 1800 --timeout-secs 10800 --root ${vol_real} --output OUT"
if [ "$(sed -n 1p "$log")" = "$expected_bind" ] && [ "$(sed -n 2p "$log")" = "$expected_nv" ] && [ "$(wc -l <"$log" | tr -d ' ')" -eq 2 ]; then
  pass "normal: harness argv (bind then named-volume)"
else
  fail "normal: harness argv mismatch: $(cat "$log")"
fi
case "$last_stdout" in
  *"$tmp_root"*) fail "normal: output leaks an absolute path" ;;
  *) pass "normal: output has no absolute path" ;;
esac

# --- every-k ---
# shellcheck disable=SC2046
run_target $(base_args) --batch-size 100 --trials 7
expect_json "every-k: method and note kept" '.method == "server-api-direct/flush-every-k" and .results.bind.io2_guaranteed == false and (.results.bind.note | startswith("outside IO-2 guarantee")) and .trials_per_config == 7 and (.results["named-volume"].trials | length) == 7'

# --- --output ---
# shellcheck disable=SC2046
run_target $(base_args)
stdout_mode="$last_stdout"
out_file="${tmp_root}/result.json"
# shellcheck disable=SC2046
run_target $(base_args) --output "$out_file"
if [ "$last_rc" -eq 0 ] && [ "$(cat "$out_file")" = "$stdout_mode" ]; then pass "output file equals stdout mode"; else fail "output file differs (rc=$last_rc)"; fi
before="$(cat "$out_file")"
# shellcheck disable=SC2046
expect_rc "existing --output is refused" 2 $(base_args) --output "$out_file"
if [ "$(cat "$out_file")" = "$before" ]; then pass "existing --output unchanged"; else fail "existing --output was modified"; fi
expect_no_harness_call "existing --output"

# --- 入力エラー（ハーネスを呼ばない） ---
for bad in "--trials 4" "--trials 21" "--count 1999" "--count 50001" "--batch-size 0" "--batch-size 4097" "--file-size 0" "--layout weird" "--trial-timeout-secs 0" "--timeout-secs 86401" "--trials 05x" "--bogus 1"; do
  # shellcheck disable=SC2046,SC2086
  expect_rc "bad input: $bad" 2 $(base_args) $bad
  expect_no_harness_call "bad input: $bad"
done
# shellcheck disable=SC2046
expect_rc "missing value" 2 $(base_args) --trials
# shellcheck disable=SC2046
expect_rc "duplicate argument" 2 $(base_args) --trials 5 --trials 6
expect_rc "missing --harness" 2 --bind-root "$bind_real" --volume-root "$vol_real"
expect_rc "missing --bind-root" 2 --harness "$stub" --volume-root "$vol_real"
expect_rc "relative bind root" 2 --harness "$stub" --bind-root relative/dir --volume-root "$vol_real"
expect_rc "nonexistent volume root" 2 --harness "$stub" --bind-root "$bind_real" --volume-root "${tmp_root}/nope"
expect_rc "relative harness" 2 --harness stub-harness.sh --bind-root "$bind_real" --volume-root "$vol_real"
printf '#!/bin/sh\n' >"${tmp_root}/not-exec"
expect_rc "non-executable harness" 2 --harness "${tmp_root}/not-exec" --bind-root "$bind_real" --volume-root "$vol_real"
expect_rc "same root" 2 --harness "$stub" --bind-root "$bind_real" --volume-root "$bind_real"
ln -s "$bind_real" "${tmp_root}/link-to-bind"
expect_rc "same root via symlink" 2 --harness "$stub" --bind-root "$bind_real" --volume-root "${tmp_root}/link-to-bind"
expect_no_harness_call "same root via symlink"

# --- 計測失敗（1） ---
for m in fail-nv bad-json bad-config bad-trials bad-unit wire bad-io2 bad-layout bad-trial-timeout bad-total-timeout bad-method mismatch; do
  STUB_MODE="$m"
  export STUB_MODE
  out_f="${tmp_root}/fail-${m}.json"
  # shellcheck disable=SC2046
  expect_rc "measurement failure: $m" 1 $(base_args) --batch-size 100 --output "$out_f"
  if [ ! -e "$out_f" ]; then pass "measurement failure: $m leaves no output"; else fail "measurement failure: $m left an output file"; fi
done

# --- 期限切れ（子孫を残さない） ---
STUB_MODE=hang-nv
export STUB_MODE
rm -f "$STUB_PIDFILE"
start=$SECONDS
# shellcheck disable=SC2046
SMALL_FILES_COMPARE_GRACE_SECS=1 run_target $(base_args) --timeout-secs 1
elapsed=$((SECONDS - start))
if [ "$last_rc" -eq 1 ] && [ "$elapsed" -le 20 ]; then pass "deadline: rc=1 within ${elapsed}s"; else fail "deadline: rc=$last_rc elapsed=${elapsed}s (stderr: $last_stderr)"; fi
case "$last_stderr" in *"exceeded its deadline"*) pass "deadline: message" ;; *) fail "deadline: message missing: $last_stderr" ;; esac
if [ -s "$STUB_PIDFILE" ]; then
  sleep 1
  if kill -0 "$(cat "$STUB_PIDFILE")" 2>/dev/null; then fail "deadline: stub descendant still alive"; else pass "deadline: no descendant left"; fi
else
  fail "deadline: stub did not record its child pid"
fi
STUB_MODE=ok
export STUB_MODE

# --- 前提ツール欠如（3）: jq を含まない PATH ---
nojq="${tmp_root}/nojq-bin"
mkdir -p "$nojq"
for t in dirname mktemp cat rm wc tr sed; do
  p="$(command -v "$t" || true)"
  if [ -n "$p" ]; then ln -s "$p" "${nojq}/${t}"; fi
done
rc=0
# shellcheck disable=SC2046
PATH="$nojq" "$bash_bin" "$target_script" $(base_args) >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 3 ]; then pass "missing jq (rc=3)"; else fail "missing jq: expected rc=3, got $rc"; fi

if [ "$failures" -gt 0 ]; then
  echo "small_files_compare_selftest: $failures failure(s)" >&2
  exit 1
fi
echo "small_files_compare_selftest: all checks passed"
