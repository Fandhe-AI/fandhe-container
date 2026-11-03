#!/usr/bin/env bash
# scripts/cri/docker-hub-ratelimit-probe.sh の自己テスト（CRI-3・REPAIR-12・#2818）。
#
# 役割: PATH 先頭のスタブ curl だけで、残量あり・残量 0・429・ヘッダ無し・到達不能・トークン欠落・usage 誤りの
# 終了コードと文言（最低残量 PROBE_MIN_REMAINING の未満・ちょうど・超過の境界を含む。#3312）を具体値で照合する。ネットワークは使わない。トークンが出力に現れないことも確かめる。
# 呼び出し元は Makefile の `docker-hub-ratelimit-probe-selftest`（CI の platform-ci でも実行）。1 件でも違えば非ゼロ（fail-closed）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="${DIR}/docker-hub-ratelimit-probe.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir "${work}/bin"
# スタブ curl: URL で token / manifest を見分け、STUB_TOKEN_CODE・STUB_MANIFEST_CODE・STUB_HEADERS・STUB_NO_TOKEN で応答する。
cat > "${work}/bin/curl" <<'STUB'
#!/usr/bin/env bash
out=""; hdrf=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -D) hdrf="$2"; shift ;;
    https://*) url="$1" ;;
  esac
  shift
done
case "${url}" in
  https://auth.docker.io/*)
    if [ -z "${STUB_NO_TOKEN:-}" ]; then echo '{"token":"SECRET-TOKEN-VALUE","expires_in":300}' > "${out}"; else echo '{}' > "${out}"; fi
    printf '%s' "${STUB_TOKEN_CODE:-200}" ;;
  https://registry-1.docker.io/*)
    printf 'HTTP/2 %s\r\n%b' "${STUB_MANIFEST_CODE:-200}" "${STUB_HEADERS:-}" > "${hdrf}"
    printf '%s' "${STUB_MANIFEST_CODE:-200}" ;;
  *) exit 7 ;;
esac
STUB
chmod +x "${work}/bin/curl"

FAILS=0
run() { # <desc> <expected rc> <expected output fragment> [VAR=value...]
  local desc="$1" erc="$2" frag="$3"
  shift 3
  local rc=0 out
  out="$(env PATH="${work}/bin:${PATH}" "$@" bash "${PROBE}" 2>&1)" || rc=$?
  if [ "${rc}" != "${erc}" ] || ! printf '%s' "${out}" | grep -qF -- "${frag}"; then
    echo "FAIL: ${desc} (rc=${rc} want ${erc}; out='${out}')"
    FAILS=$((FAILS + 1))
  elif printf '%s' "${out}" | grep -qF SECRET-TOKEN-VALUE; then
    echo "FAIL: ${desc} (token leaked)"
    FAILS=$((FAILS + 1))
  else
    echo "PASS: ${desc}"
  fi
}
run "remaining available" 0 "docker-hub-ratelimit: ok remaining=97 limit=100" \
  "STUB_HEADERS=ratelimit-limit: 100;w=21600\r\nratelimit-remaining: 97;w=21600\r\n"
run "no rate limit headers" 0 "ok (no rate limit headers)" STUB_X=1
run "remaining zero" 1 "anonymous pull rate limit exhausted (status=200 remaining=0)" \
  "STUB_HEADERS=ratelimit-limit: 100;w=21600\r\nratelimit-remaining: 0;w=21600\r\n"
run "status 429" 1 "anonymous pull rate limit exhausted (status=429 remaining=n/a)" STUB_MANIFEST_CODE=429
run "manifest 500" 1 "unreachable or returned an unexpected status (stage=manifest status=500)" STUB_MANIFEST_CODE=500
run "token unreachable" 1 "(stage=token status=000)" STUB_TOKEN_CODE=000
run "token missing" 1 "(stage=token status=no-token)" STUB_NO_TOKEN=1
H1='STUB_HEADERS=ratelimit-limit: 100;w=21600\r\nratelimit-remaining: 1;w=21600\r\n'
H2='STUB_HEADERS=ratelimit-limit: 100;w=21600\r\nratelimit-remaining: 2;w=21600\r\n'
H3='STUB_HEADERS=ratelimit-limit: 100;w=21600\r\nratelimit-remaining: 3;w=21600\r\n'
H0='STUB_HEADERS=ratelimit-limit: 100;w=21600\r\nratelimit-remaining: 0;w=21600\r\n'
run "min 2 remaining 1 (below)" 1 "remaining below required minimum (remaining=1 min=2)" PROBE_MIN_REMAINING=2 "${H1}"
run "min 2 remaining 2 (exact)" 0 "ok remaining=2 limit=100 min=2" PROBE_MIN_REMAINING=2 "${H2}"
run "min 2 remaining 3 (above)" 0 "ok remaining=3 limit=100 min=2" PROBE_MIN_REMAINING=2 "${H3}"
run "min 2 remaining 0 (exhausted wins)" 1 "anonymous pull rate limit exhausted (status=200 remaining=0)" PROBE_MIN_REMAINING=2 "${H0}"
run "min 2 no headers" 0 "ok (no rate limit headers)" PROBE_MIN_REMAINING=2
run "min 2 status 429" 1 "anonymous pull rate limit exhausted (status=429 remaining=n/a)" PROBE_MIN_REMAINING=2 STUB_MANIFEST_CODE=429
run "default min remaining 1" 0 "ok remaining=1 limit=100 min=1" "${H1}"
run "empty min is default" 0 "ok remaining=1 limit=100 min=1" PROBE_MIN_REMAINING= "${H1}"
run "invalid min" 2 "usage: invalid PROBE_MIN_REMAINING" PROBE_MIN_REMAINING=abc
run "min zero" 2 "usage: PROBE_MIN_REMAINING must be 1-100" PROBE_MIN_REMAINING=0
run "min 101" 2 "usage: PROBE_MIN_REMAINING must be 1-100" PROBE_MIN_REMAINING=101
rc=0
out="$(env PATH="${work}/bin:${PATH}" PROBE_MIN_REMAINING=2 "${H1}" bash "${PROBE}" 2>&1)" || rc=$?
if printf '%s' "${out}" | grep -qF exhausted; then
  echo "FAIL: below-minimum message must not contain 'exhausted'"
  FAILS=$((FAILS + 1))
else
  echo "PASS: below-minimum message distinct from exhausted"
fi
run "invalid repo" 2 "usage: invalid PROBE_REPO" "PROBE_REPO=a b;rm"
run "invalid tag" 2 "usage: invalid PROBE_TAG" "PROBE_TAG=1.36&x"
run "invalid timeout" 2 "usage: invalid PROBE_TIMEOUT_SECS" PROBE_TIMEOUT_SECS=abc
rc=0
bash "${PROBE}" extra > /dev/null 2>&1 || rc=$?
if [ "${rc}" = 2 ]; then
  echo "PASS: arguments rejected"
else
  echo "FAIL: arguments rejected (rc=${rc})"
  FAILS=$((FAILS + 1))
fi
if [ "${FAILS}" -ne 0 ]; then
  echo "docker-hub-ratelimit-probe-selftest: ${FAILS} failure(s)" >&2
  exit 1
fi
echo "docker-hub-ratelimit-probe-selftest: all passed"
