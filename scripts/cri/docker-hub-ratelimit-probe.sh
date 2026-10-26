#!/usr/bin/env bash
# Docker Hub の匿名 pull の残量の事前確認（make docker-hub-ratelimit-probe。CRI-3・CRI-2・#2818）。
#
# 役割: platform-ci の production_binary_full_lifecycle_real（plugin-cri の本番バイナリが docker.io の busybox を匿名で pull する
# 実機前提テスト）の前段で、外向き HTTPS の到達性と匿名 pull の rate limit の残量を確かめる。HEAD の manifest 取得は
# Docker Hub の pull 回数に数えられないため、残量を消費しない。試験側の CRI 境界では HTTP 429 が gRPC の UNAVAILABLE に
# 潰れて他の 5xx と区別できないため、rate limit の識別はこのスクリプトが担う（試験失敗後の事後診断にも再実行する）。
#
# 入力（環境変数）: PROBE_REPO（既定 library/busybox）・PROBE_TAG（既定 1.36）・PROBE_TIMEOUT_SECS（既定 20。1〜600）。
# 終了コード: 0 = 取得可（残量あり・またはヘッダ無し）、1 = rate limit（429・残量 0）または到達不能・想定外の応答、
# 2 = usage 誤り・必須コマンド不足。トークン・応答本文は出力しない。出力文字列は英語。
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "usage: docker-hub-ratelimit-probe.sh (no arguments; env: PROBE_REPO PROBE_TAG PROBE_TIMEOUT_SECS)" >&2
  exit 2
fi
repo="${PROBE_REPO:-library/busybox}"
tag="${PROBE_TAG:-1.36}"
tmo="${PROBE_TIMEOUT_SECS:-20}"
# URL へ組み込む前に許容文字を検証する（インジェクション対策）。
case "${repo}" in '' | *[!a-z0-9._/-]* | /* | *..*)
  echo "usage: invalid PROBE_REPO" >&2
  exit 2
  ;;
esac
case "${tag}" in '' | *[!A-Za-z0-9._-]*)
  echo "usage: invalid PROBE_TAG" >&2
  exit 2
  ;;
esac
case "${tmo}" in '' | *[!0-9]* | ????*)
  echo "usage: invalid PROBE_TIMEOUT_SECS" >&2
  exit 2
  ;;
esac
if [ "${tmo}" -lt 1 ] || [ "${tmo}" -gt 600 ]; then
  echo "usage: PROBE_TIMEOUT_SECS must be 1-600" >&2
  exit 2
fi
command -v curl >/dev/null 2>&1 || {
  echo "usage: curl is required" >&2
  exit 2
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

unreachable() { # <stage> <status>
  echo "::error::docker hub registry is unreachable or returned an unexpected status (stage=$1 status=$2)" >&2
  exit 1
}

# 1. 匿名トークン（pull スコープのみ）。トークンは変数に留めて出力しない。
code="$(curl --proto '=https' --max-time "${tmo}" -sS -o "${work}/token.json" -w '%{http_code}' \
  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" 2>/dev/null)" || code="000"
[ "${code}" = "200" ] || unreachable token "${code}"
token="$(sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${work}/token.json" | head -n 1)"
[ -n "${token}" ] || unreachable token "no-token"

# 2. HEAD の manifest（pull 回数に数えられない）。応答ヘッダの ratelimit-* を読む。
code="$(curl --proto '=https' --max-time "${tmo}" -sS -I -o /dev/null -D "${work}/hdr.txt" -w '%{http_code}' \
  -H "Authorization: Bearer ${token}" \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
  "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" 2>/dev/null)" || code="000"

# ヘッダ値の先頭の数値（`<n>;w=<秒>` の n）。無ければ空。
hdr() { # <name>
  [ -f "${work}/hdr.txt" ] || return 0
  tr -d '\r' < "${work}/hdr.txt" | sed -n "s/^$1:[[:space:]]*\([0-9][0-9]*\).*/\1/Ip" | head -n 1
}
remaining="$(hdr ratelimit-remaining)"
limit="$(hdr ratelimit-limit)"

if [ "${code}" = "429" ] || { [ "${code}" = "200" ] && [ "${remaining}" = "0" ]; }; then
  echo "::error::docker hub anonymous pull rate limit exhausted (status=${code} remaining=${remaining:-n/a})" >&2
  exit 1
fi
[ "${code}" = "200" ] || unreachable manifest "${code}"
if [ -n "${remaining}" ]; then
  echo "docker-hub-ratelimit: ok remaining=${remaining} limit=${limit:-n/a}"
else
  echo "docker-hub-ratelimit: ok (no rate limit headers)"
fi
