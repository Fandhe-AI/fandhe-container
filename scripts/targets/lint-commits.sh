#!/usr/bin/env bash
# commitlint（origin/main からの分岐点以降のコミットを検証。make lint-commits）。
#
# CI（lint-docs の commitlint ジョブ）と同じ extends 構成で検証する。origin/main が未取得の環境では
# 範囲を決められないためスキップする。
# `git rev-parse --verify --quiet refs/remotes/origin/main` は「参照が存在しない」場合に終了コード 1 を返す。
# これだけを skip 条件にし、1 以外の失敗（`fatal: detected dubious ownership` 等。典型的には 128）は
# エラーを表示して非 0 終了する（fail-closed）。単に非 0 かどうかだけで判定すると実エラーも無音 skip になる。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

st=0
out="$(git rev-parse --verify --quiet refs/remotes/origin/main 2>&1 >/dev/null)" || st=$?
if [ "${st}" -eq 1 ]; then
  echo "skip: origin/main is not fetched, skipping commitlint"
  exit 0
elif [ "${st}" -ne 0 ]; then
  printf '%s\n' "${out}" >&2
  echo "NG: failed to resolve origin/main (git rev-parse exit=${st})" >&2
  exit 1
fi
base="$(git merge-base origin/main HEAD)" || {
  echo "NG: git merge-base failed" >&2
  exit 1
}
run npx --yes -p "@commitlint/cli@${COMMITLINT_VERSION}" -p "@commitlint/config-conventional@${COMMITLINT_CONFIG_VERSION}" \
  commitlint --extends @commitlint/config-conventional --from "${base}" --to HEAD
