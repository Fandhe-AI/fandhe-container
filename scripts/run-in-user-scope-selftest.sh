#!/usr/bin/env bash
# scripts/run-in-user-scope.sh の自己テスト（#3486・REPAIR-5・REPAIR-12）。
#
# 役割: スタブの systemd-run / systemctl だけで、成功・子の終了コードの素通し・期限切れ（124 と固定行と scope 停止）・
# 孤児が出力を持って残る場合に待たないこと（pipe を持たない形の回帰検査）・入力不正（2）・前提コマンド不在（1）を
# 具体値で照合する。実機の systemd は使わない。呼び出し元: Makefile の `run-in-user-scope-selftest`。
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="${script_dir}/run-in-user-scope.sh"
work="$(mktemp -d)"
# 孤児ケースが起動した sleep だけを pid ファイル経由で回収する（pkill -f のパターン一致は並行実行の他プロセスを巻き込む）。
cleanup_orphan() {
  local p
  p="$(cat "${work}/orphan.pid" 2>/dev/null || true)"
  [ -n "${p}" ] && kill "${p}" 2>/dev/null
  return 0
}
trap 'cleanup_orphan; rm -rf -- "${work}"' EXIT
fails=0

mkdir -p "${work}/bin"
# スタブ systemd-run: --unit を記録し、-- 以降をそのまま exec する。
cat >"${work}/bin/systemd-run" <<'STUB'
#!/usr/bin/env bash
unit=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --unit=*) unit="${1#--unit=}"; shift ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
echo "unit=${unit}" >>"${STUB_CALLS}"
exec "$@"
STUB
# スタブ systemctl: 呼び出しを記録する。is-active は STUB_ACTIVE=1 のときだけ 0。
cat >"${work}/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
echo "systemctl $*" >>"${STUB_CALLS}"
case " $* " in
  *" is-active "*) [ "${STUB_ACTIVE:-0}" = 1 ] ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${work}/bin/systemd-run" "${work}/bin/systemctl"

fail() {
  echo "FAIL: $*" >&2
  fails=$((fails + 1))
}
expect_eq() { # <名前> <期待> <実際>
  [ "$2" = "$3" ] || fail "$1: expected '$2' got '$3'"
}

run_case() { # <ケース名> <引数...> : out/err/rc/calls を work に残す
  local c="$1"
  shift
  : >"${work}/calls"
  PATH="${work}/bin:${PATH}" STUB_CALLS="${work}/calls" "${target}" "$@" >"${work}/out" 2>"${work}/err"
  rc=$?
  echo "${c}: rc=${rc}"
}

log="${work}/t.log"

# 1. 成功: rc=0 とログ出力。
run_case ok --name ok --deadline 10 --log "${log}" -- bash -c 'echo hello-out'
expect_eq ok-rc 0 "${rc}"
grep -qx 'hello-out' "${work}/out" || fail "ok: log not emitted"
grep -q "^unit=fandhe-ci-ok-[0-9]*$" "${work}/calls" || fail "ok: unit name not passed"

# 2. 子の終了コードの素通し。
run_case rc3 --name rc3 --deadline 10 --log "${log}" -- bash -c 'exit 3'
expect_eq rc3-rc 3 "${rc}"

# 3. 期限切れ: 124・固定行・scope の kill と stop・経過時間。
start="$(date +%s)"
run_case dl --name dl --deadline 2 --log "${log}" -- sleep 60
elapsed=$(($(date +%s) - start))
expect_eq dl-rc 124 "${rc}"
grep -q 'error: code=deadline_exceeded message=name=dl deadline_secs=2 unit=fandhe-ci-dl-' "${work}/err" || fail "dl: fixed line missing"
grep -q 'systemctl --user kill --signal=SIGKILL fandhe-ci-dl-[0-9]*.scope' "${work}/calls" || fail "dl: kill not called"
grep -q 'systemctl --user stop fandhe-ci-dl-[0-9]*.scope' "${work}/calls" || fail "dl: stop not called"
[ "${elapsed}" -le 47 ] || fail "dl: took ${elapsed}s (limit 47)"

# 4. 孤児が出力を持って残る（主プロセスは exit 0）: 待たずに戻り、残存を検出して stop を呼ぶ。
start="$(date +%s)"
STUB_ACTIVE=1 run_case orphan --name orphan --deadline 30 --log "${log}" -- bash -c "setsid bash -c 'echo \$\$ >\"${work}/orphan.pid\"; exec sleep 4242' & exit 0"
elapsed=$(($(date +%s) - start))
expect_eq orphan-rc 0 "${rc}"
[ "${elapsed}" -le 10 ] || fail "orphan: took ${elapsed}s (limit 10)"
# GITHUB_ACTIONS=true のとき警告は stdout の ::warning:: 行になるため、out と err の両方を見る。
cat "${work}/out" "${work}/err" | grep -q 'leftover_processes name=orphan' || fail "orphan: leftover warning missing"
grep -q 'systemctl --user stop fandhe-ci-orphan-[0-9]*.scope' "${work}/calls" || fail "orphan: stop not called"
cleanup_orphan

# 5. 入力不正は 2。
for bad in \
  "--name BAD --deadline 5 --log /x -- true" \
  "--name a --deadline 0 --log /x -- true" \
  "--name a --deadline abc --log /x -- true" \
  "--name a --deadline 3601 --log /x -- true" \
  "--name a --deadline 5 --log rel -- true" \
  "--name a --deadline 5 --log /x true" \
  "--name a --deadline 5 --log /x --" \
  "--bogus"; do
  # shellcheck disable=SC2086 # 意図的に単語分割する
  run_case "bad($bad)" ${bad}
  expect_eq "bad($bad)" 2 "${rc}"
done

# 6. systemd-run が無ければ skip せず 1。
: >"${work}/calls"
env PATH="/usr/bin:/bin" STUB_CALLS="${work}/calls" bash -c '
  # PATH から systemd-run を隠すため、スタブ無しの最小 PATH を使う（実機に systemd-run があれば隠す）
  mkdir -p "$1/min"
  for c in bash env mktemp rm cat date sleep dirname kill timeout; do ln -sf "$(command -v $c)" "$1/min/$c"; done
  PATH="$1/min" "$2" --name nb --deadline 5 --log "$1/nb.log" -- true' _ "${work}" "${target}" >/dev/null 2>"${work}/err"
expect_eq nobin-rc 1 "$?"
grep -q 'code=missing-command' "${work}/err" || fail "nobin: error line missing"

if [ "${fails}" -ne 0 ]; then
  echo "run-in-user-scope-selftest: ${fails} failure(s)" >&2
  exit 1
fi
echo "run-in-user-scope-selftest: all cases passed"
