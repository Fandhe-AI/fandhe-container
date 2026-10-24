#!/usr/bin/env bash
# 試験用 feature 無効の「-p 単独」ビルドの clippy を全メンバー crate に回す判定本体
# （make check-standalone-clippy。#2640・REPAIR-7・REPAIR-12。経緯は #2550）。
#
# ワークスペース単位の clippy は feature 統一で、dev-dependency の自己参照や依存元が有効にした試験用 feature
# （exec-test-support・escape-probe 等）が lib にも効く。そのため「試験用 feature 無効の単独ビルドでだけ出る
# dead_code・unused_imports・cfg 漏れ」を検出できない。ここでは各メンバーを `cargo clippy -p <名前> --lib --bins`
# （dev-dependency を含めない最小の構成）で個別に見る。対象は `cargo metadata` で全メンバーを列挙し、表で固定しない。
#
# 呼び出し元: scripts/targets/check-standalone-clippy.sh（skip・jq 確認の後に exec）と自己テスト
# scripts/check-standalone-clippy-selftest.sh（スタブの cargo を PATH に差して直接実行する）。
# カレントディレクトリが対象 workspace のルートであること。リポジトリのファイルは書き換えない。
#
# 入力（環境変数）: CLIPPY_TARGET（任意。空なら host。`--target <triple>` として渡す。許可文字は英数字と _ . -）。
# 終了コード: 0=全件成功 / 1=失敗あり・列挙失敗・0 件（fail-closed）/ 2=引数・入力の誤り。
# bash 3.2 でも動く書き方に限る（連想配列・wait -n は使わない）。
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: [CLIPPY_TARGET=<triple>] check-standalone-clippy.sh" >&2
  exit 2
}

if [ "$#" -ne 0 ]; then
  usage
fi

target="${CLIPPY_TARGET:-}"
if [ -n "${target}" ]; then
  case "${target}" in
    *[!A-Za-z0-9_.-]*) usage ;;
  esac
fi

if ! metadata="$(cargo metadata --no-deps --format-version 1 --locked)"; then
  echo "NG: cargo metadata failed" >&2
  exit 1
fi

# name<TAB>lib の有無<TAB>bin の有無（kind は配列なので index で判定する）。
if ! rows="$(printf '%s' "${metadata}" | jq -r '.packages[] | [.name, (any(.targets[]; .kind | index("lib") != null)), (any(.targets[]; .kind | index("bin") != null))] | @tsv')"; then
  echo "NG: failed to parse cargo metadata" >&2
  exit 1
fi
rows="$(printf '%s' "${rows}" | tr -d '\r')"
if [ -z "${rows}" ]; then
  echo "NG: no workspace member found" >&2
  exit 1
fi

checked=0
failed=0
failed_names=""
start="$(date +%s)"
while IFS="$(printf '\t')" read -r name has_lib has_bin; do
  [ -n "${name}" ] || continue
  args=()
  if [ "${has_lib}" = true ]; then
    args+=(--lib)
  fi
  if [ "${has_bin}" = true ]; then
    args+=(--bins)
  fi
  if [ "${#args[@]}" -eq 0 ]; then
    echo "note: ${name} has no lib/bin target"
    continue
  fi
  if [ -n "${target}" ]; then
    args+=(--target "${target}")
  fi
  checked=$((checked + 1))
  t0="$(date +%s)"
  if cargo clippy -p "${name}" "${args[@]}" -- -D warnings; then
    echo "OK: ${name} ($(($(date +%s) - t0))s)"
  else
    echo "NG: ${name} ($(($(date +%s) - t0))s)" >&2
    failed=$((failed + 1))
    failed_names="${failed_names} ${name}"
  fi
done <<EOF
${rows}
EOF

echo "checked=${checked} failed=${failed} elapsed=$(($(date +%s) - start))s"
if [ "${checked}" -eq 0 ]; then
  echo "NG: no package was checked" >&2
  exit 1
fi
if [ "${failed}" -ne 0 ]; then
  echo "NG: standalone clippy failed for:${failed_names}" >&2
  exit 1
fi
