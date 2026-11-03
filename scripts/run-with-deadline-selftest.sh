#!/usr/bin/env bash
# scripts/run-with-deadline.sh の自己テスト（#3505・REPAIR-5・REPAIR-12）。実際の子プロセスのみで systemd は使わない。
# Linux の ci.yml ステップからのみ呼ばれる（setsid を使うため）。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="${DIR}/run-with-deadline.sh"
WORK="$(mktemp -d)"
fails=0
cleanup() {
  if [ -f "${WORK}/orphan.pid" ]; then
    kill -KILL "$(cat "${WORK}/orphan.pid")" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

expect_eq() { # 名前 期待 実際
  if [ "$2" != "$3" ]; then
    echo "FAIL: $1: expected '$2' got '$3'" >&2
    fails=$((fails + 1))
  fi
}

# 成功: stdout / stderr がログと標準出力の両方に出る
rc=0
out="$("${HELPER}" --name ok --deadline 10 --log "${WORK}/ok.log" -- bash -c 'echo hello; echo err >&2' 2>&1)" || rc=$?
expect_eq success-rc 0 "${rc}"
expect_eq success-out $'hello\nerr' "${out}"
expect_eq success-log $'hello\nerr' "$(cat "${WORK}/ok.log")"

# 終了コードの素通し
rc=0
"${HELPER}" --name rc7 --deadline 10 --log "${WORK}/rc7.log" -- bash -c 'exit 7' >/dev/null 2>&1 || rc=$?
expect_eq passthrough-rc 7 "${rc}"

# 環境変数の素通し
# shellcheck disable=SC2016
out="$(FOO=bar "${HELPER}" --name env --deadline 10 --log "${WORK}/env.log" -- bash -c 'echo "$FOO"' 2>&1)"
expect_eq env-passthrough bar "${out}"

# 期限切れ
rc=0
start=$SECONDS
err="$("${HELPER}" --name slow --deadline 2 --log "${WORK}/slow.log" -- sleep 30 2>&1 >/dev/null)" || rc=$?
elapsed=$((SECONDS - start))
expect_eq deadline-rc 124 "${rc}"
case "${err}" in
  *code=deadline_exceeded*name=slow*deadline_secs=2*) ;;
  *)
    echo "FAIL: deadline-line: ${err}" >&2
    fails=$((fails + 1))
    ;;
esac
if [ "${elapsed}" -ge 15 ]; then
  echo "FAIL: deadline-elapsed: ${elapsed}s" >&2
  fails=$((fails + 1))
fi

# 孤児が出力の書き込み端を持っていても即座に戻る
rc=0
start=$SECONDS
"${HELPER}" --name orphan --deadline 30 --log "${WORK}/orphan.log" -- \
  bash -c "setsid sleep 3600 & echo \$! > '${WORK}/orphan.pid'; exit 0" >/dev/null 2>&1 || rc=$?
elapsed=$((SECONDS - start))
expect_eq orphan-rc 0 "${rc}"
if [ "${elapsed}" -ge 10 ]; then
  echo "FAIL: orphan-elapsed: ${elapsed}s" >&2
  fails=$((fails + 1))
fi

# systemd-run を呼ばない
mkdir "${WORK}/bin"
printf '#!/bin/sh\necho called >> "%s/sd.calls"\nexit 1\n' "${WORK}" >"${WORK}/bin/systemd-run"
chmod +x "${WORK}/bin/systemd-run"
rc=0
PATH="${WORK}/bin:${PATH}" "${HELPER}" --name nosd --deadline 10 --log "${WORK}/nosd.log" -- true >/dev/null 2>&1 || rc=$?
expect_eq nosd-rc 0 "${rc}"
if [ -e "${WORK}/sd.calls" ]; then
  echo "FAIL: systemd-run was called" >&2
  fails=$((fails + 1))
fi

# 入力不正は 2
bad() { # 説明 引数...
  local d="$1"
  shift
  local r=0
  "${HELPER}" "$@" >/dev/null 2>&1 || r=$?
  expect_eq "usage-${d}" 2 "${r}"
}
L="${WORK}/bad.log"
bad name-chars --name Bad --deadline 5 --log "${L}" -- true
bad name-long --name "$(printf 'a%.0s' $(seq 49))" --deadline 5 --log "${L}" -- true
bad deadline-0 --name x --deadline 0 --log "${L}" -- true
bad deadline-3601 --name x --deadline 3601 --log "${L}" -- true
bad deadline-nan --name x --deadline abc --log "${L}" -- true
bad log-relative --name x --deadline 5 --log rel.log -- true
bad no-command --name x --deadline 5 --log "${L}" --

if [ "${fails}" -ne 0 ]; then
  echo "run-with-deadline-selftest: ${fails} failure(s)" >&2
  exit 1
fi
echo "run-with-deadline-selftest: ok"
