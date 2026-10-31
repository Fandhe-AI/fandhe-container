#!/usr/bin/env bash
# rust-vmm 系の禁止クレートが依存ツリーに含まれないことの機械判定（make check-microvm-deps。
# MVM-4・MS-7・TASK-73.1・dependency-policy.md）。
#
# 使い方: check-microvm-deps.sh [--manifest-path <Cargo.toml>]... | --list
#   引数なし: ルートの Cargo.toml（workspace 全体。今後追加される crates/microvm も自動で対象）と
#             poc/venus-decoder/jig/Cargo.toml（ルート workspace の外の PoC。vhost-user を自作しており
#             混入の危険が最も高い）を検査する。既定の対象が無ければ NG（fail-closed）。
#             治具を移動・削除するときは、ここの既定の対象もレビューつきで更新すること。
#   --manifest-path: 指定した Cargo.toml だけを検査する（複数可）。
#   --list: 禁止クレート名を 1 行 1 件で出す（cargo は呼ばない。deny.toml [bans] との機械照合用で、
#           リストの二重管理を防ぐ。照合は `make deny-bans-fail-closed-selftest`。TASK-73.2・#686）。
# 終了コード: 0 = 混入なし、1 = 混入または fail-closed、2 = usage。
#
# 判定:
# - `cargo tree --workspace -e normal,build,dev --target all --all-features --locked` の全 package を見る。
#   spec は normal,build だが dev を足した上位集合で検査する（dev からの混入も「依存ツリーに含めない」に当たる）。
#   `--target all` で cfg(target_os = "linux") 配下の辺を実行ランナーの OS に依らず見る。
# - 照合 A: package 名を `_` → `-` に正規化し、禁止リストと完全一致で比べる（部分一致はしない）。
# - 照合 B: repository URL が github.com/rust-vmm/ を含む package は名前に関係なく NG。リストに無い
#   rust-vmm 配下のクレートや改名 fork を拾う補助の信号（crate 側の自己申告のため偽装には効かない）。
# - cargo tree の失敗・出力 0 行は NG（fail-closed）。
#
# 限界（REPAIR-3。実装済みを装わない）:
# - 照合できるのは package 名と repository URL まで。コードの写し（vendoring）や repository を書き換えた
#   改名 fork は検出できない。
# - youki・Firecracker・Cloud Hypervisor 由来のクレートは本スクリプトの範囲外（AGENTS.md の P0 観点が担う）。
#   範囲を広げるときは deny.toml [bans]（TASK-73.2）と同時に行う。
# - ライセンスの確認は `make deny`（licenses）が担い、ここでは重複して検査しない。
# - 禁止リストは spec TASK-73 の 10 種。それ以外の rust-vmm クレート（vm-fdt 等）は crates.io での実在と
#   所属を一次情報で確認できたものだけを足す方針で、確認までは照合 B が補う。
set -euo pipefail

# lib.sh を source するとリポジトリルートへ cd するため、相対パスは先に絶対化する。
ORIG_PWD="${PWD}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${DIR}/lib.sh"

BANNED="vm-memory
kvm-ioctls
kvm-bindings
vhost
vhost-user-backend
virtio-queue
vmm-sys-util
linux-loader
event-manager
vm-superio"

usage() {
  echo "usage: check-microvm-deps.sh [--manifest-path <Cargo.toml>]... | --list" >&2
  exit 2
}

manifests=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --list)
      [ "$#" -eq 1 ] && [ "${#manifests[@]}" -eq 0 ] || usage
      printf '%s\n' "${BANNED}"
      exit 0
      ;;
    --manifest-path)
      [ "$#" -ge 2 ] || usage
      p="$2"
      case "${p}" in /*) ;; *) p="${ORIG_PWD}/${p}" ;; esac
      [ -f "${p}" ] || {
        echo "error: manifest not found: $2" >&2
        exit 2
      }
      manifests+=("${p}")
      shift 2
      ;;
    *) usage ;;
  esac
done

if [ "${#manifests[@]}" -eq 0 ]; then
  for m in "${ROOT_DIR}/Cargo.toml" "${ROOT_DIR}/poc/venus-decoder/jig/Cargo.toml"; do
    [ -f "${m}" ] || {
      echo "NG: default manifest not found: ${m}" >&2
      exit 1
    }
    manifests+=("${m}")
  done
fi

export LC_ALL=C
fail=0
for m in "${manifests[@]}"; do
  if ! tree="$(cargo tree --manifest-path "${m}" --workspace -e normal,build,dev --target all \
    --all-features --prefix none --format '{p}|{r}' --locked)"; then
    echo "NG: cargo tree failed for ${m}" >&2
    fail=1
    continue
  fi
  count="$(printf '%s\n' "${tree}" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "${count}" -eq 0 ]; then
    echo "NG: cargo tree printed no packages for ${m}" >&2
    fail=1
    continue
  fi
  # 1 行 = `name vX.Y.Z[ (path)][ (proc-macro)][ (*)]|repository`。名前・版・repository を取り出して判定する。
  hits="$(printf '%s\n' "${tree}" | awk -F'|' -v banned="${BANNED}" '
    BEGIN {
      n = split(banned, b, "\n")
      for (i = 1; i <= n; i++) { k = b[i]; gsub(/_/, "-", k); ban[k] = 1 }
    }
    NF >= 1 && $1 != "" {
      split($1, f, " ")
      name = f[1]; ver = f[2]
      norm = name; gsub(/_/, "-", norm)
      repo = tolower($2)
      reason = ""
      if (norm in ban) reason = "name is on the banned list"
      else if (index(repo, "github.com/rust-vmm/") > 0) reason = "repository is under github.com/rust-vmm"
      if (reason != "") {
        key = name " " ver
        if (!(key in seen)) { seen[key] = 1; print "banned crate " name " " ver " (" reason ")" }
      }
    }')"
  if [ -n "${hits}" ]; then
    printf '%s\n' "${hits}" | while IFS= read -r line; do
      echo "NG: ${m}: ${line}" >&2
    done
    fail=1
  else
    echo "OK: no rust-vmm crate in the dependency tree of ${m} (${count} packages)"
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo "NG: banned (rust-vmm) crates found or the check could not run (MVM-4)" >&2
  exit 1
fi
