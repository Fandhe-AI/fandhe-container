#!/usr/bin/env bash
# 独立した make ターゲットを最大 N 並列で実行し、ターゲットごとのログをまとめて出力する。
#
# 使い方: scripts/run-parallel.sh <jobs> <make-target>...
# 例:     scripts/run-parallel.sh 3 concurrent-memory-selftest supervisor-independence-selftest
#
# CI の bench-regression ジョブが、互いに独立な自己テスト（スタブ・疑似 /proc・一時ディレクトリのみを使う）を
# 直列に並べると約 250 秒かかるため、同時実行数を絞って並列化するために使う。同時実行数 N を超えて起動しない
# （計測値や経過秒を照合する自己テストがあるため、全並列にして CPU を奪い合わせない）。
# 各ターゲットの出力は一時ファイルに溜め、完了順ではなく引数の順に GitHub Actions のグループ
# （`::group::`）として出力する。1 つでも失敗したら全ターゲットの完了を待ってから、失敗したターゲット名を
# 列挙して終了コード 1 で終わる（fail-closed。先に失敗しても残りを打ち切らず、全ログを残す）。
# 引数の順は「長いものを先に」並べると全体の所要時間が短くなる。
# `wait -n` を使うため bash 4.3 以上（CI の ubuntu）が前提で、macOS 標準の bash 3.2 では並列度が制限されない。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${DIR}/lib.sh"

if [ "$#" -lt 2 ]; then
  echo "usage: run-parallel.sh <jobs> <make-target>..." >&2
  exit 2
fi
jobs="$1"
shift
case "${jobs}" in '' | *[!0-9]* | 0) echo "error: <jobs> must be a positive integer" >&2; exit 2 ;; esac

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

targets=("$@")
pids=()
running=0
for i in "${!targets[@]}"; do
  while [ "${running}" -ge "${jobs}" ]; do
    wait -n || true
    running=$((running - 1))
  done
  (
    start=$SECONDS
    rc=0
    make --no-print-directory "${targets[$i]}" >"${tmp}/${i}.log" 2>&1 || rc=$?
    echo "${rc} $((SECONDS - start))" >"${tmp}/${i}.rc"
  ) &
  pids+=("$!")
  running=$((running + 1))
done
wait

failed=()
for i in "${!targets[@]}"; do
  read -r rc secs <"${tmp}/${i}.rc"
  echo "::group::make ${targets[$i]} (exit ${rc}, ${secs}s)"
  cat "${tmp}/${i}.log"
  echo "::endgroup::"
  if [ "${rc}" -ne 0 ]; then
    failed+=("${targets[$i]}")
  fi
done
if [ "${#failed[@]}" -ne 0 ]; then
  echo "error: failed targets: ${failed[*]}" >&2
  exit 1
fi
echo "all ${#targets[@]} targets passed"
