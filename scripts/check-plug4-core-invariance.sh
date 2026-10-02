#!/usr/bin/env bash
# PLUG-4（TASK-109.4・REPAIR-12）: plugin crate を workspace へ追加する前後で、core が無変更であることを
# 「別ビルド」で比較する判定スクリプト（docs/design/crate-naming.md 決定 3 の 3 点）。
#   (1) core crate のソース（Cargo.toml と src/ 配下）の sha256 一覧
#   (2) `cargo tree -p fandhe-container-core --locked -e normal` の依存木
#   (3) `cargo build -p fandhe-container-core --locked` の成果物（rlib）の sha256
#       ※ core は lib のみで bin が無いため rlib を代理にする。CLI bin（TASK-79）導入後に実行ファイルへ切り替える（REPAIR-3）。
# 手順: 追跡ファイルを一時ディレクトリへ複製 → 追加前の指紋 → 一時 workspace へ probe plugin crate を追加
# （root Cargo.toml / Cargo.lock は決定 3 により比較対象外）→ target を作り直して追加後の指紋 → 比較。
# 同一パス・同一 rustc で 2 回ビルドするため、パス埋め込み差で偽陽性にならない。
# 加えて環境変数 PLUG4_BASE_REF（例: origin/main）指定時は、plugin crate を新規追加する PR が core を変更していないかも検査する。
# 失敗（ビルド失敗・指紋不一致・空の指紋）は非ゼロ終了（fail-closed）。リポ内のファイルは変更しない。
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ws="$work/ws"
mkdir -p "$ws"

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# 作業ツリーの追跡ファイル（未コミットの変更を含む）を複製する。docs/spec（submodule）は含めない。
list="$work/files.lst"
(cd "$repo" && git ls-files -z --cached | grep -zv '^docs/spec' >"$list")
(cd "$repo" && tar --null -T "$list" -cf - 2>/dev/null) | tar -xf - -C "$ws"

# $1: 指紋の出力名（before / after）
fingerprint() {
  # target dir のパスも成果物へ埋め込まれ得るため、追加前後で同一パスを使い、毎回作り直す（偽陽性防止）。
  local out="$work/$1" tgt="$work/target"
  rm -rf "$tgt"
  mkdir -p "$out"
  (cd "$ws/crates/core" && find Cargo.toml src -type f | LC_ALL=C sort | while IFS= read -r f; do sha "$f"; done) >"$out/src.txt"
  (cd "$ws" && cargo tree -p fandhe-container-core --locked -e normal) >"$out/tree.txt"
  (cd "$ws" && CARGO_TARGET_DIR="$tgt" cargo build -p fandhe-container-core --locked >&2)
  local rlib="$tgt/debug/libfandhe_container_core.rlib"
  [ -f "$rlib" ] || { echo "NG: core rlib not found: $rlib" >&2; exit 1; }
  sha "$rlib" | cut -d' ' -f1 >"$out/rlib.txt"
  local f
  for f in src tree rlib; do
    [ -s "$out/$f.txt" ] || { echo "NG: empty fingerprint: $f" >&2; exit 1; }
  done
}

fingerprint before

# plugin 追加（独立した新規 crate を workspace メンバーへ。core には依存させず core のファイルは触らない）
mkdir -p "$ws/crates/plugin-plug4probe/src"
cat >"$ws/crates/plugin-plug4probe/Cargo.toml" <<'TOML'
[package]
name = "fandhe-container-plugin-plug4probe"
version = "0.0.0"
edition.workspace = true
license.workspace = true
publish = false
TOML
echo '//! PLUG-4 判定用の probe plugin（一時 workspace 内のみ）。' >"$ws/crates/plugin-plug4probe/src/lib.rs"
sed -i.bak 's|^members = \[|members = [\n    "crates/plugin-plug4probe",|' "$ws/Cargo.toml"
rm -f "$ws/Cargo.toml.bak"
grep -q 'plugin-plug4probe' "$ws/Cargo.toml" || { echo "NG: failed to add probe member" >&2; exit 1; }
(cd "$ws" && cargo update --workspace --offline >&2)
(cd "$ws" && CARGO_TARGET_DIR="$work/target-probe" cargo build -p fandhe-container-plugin-plug4probe --locked >&2)

fingerprint after

status=0

# PR 差分の検査（PLUG4_BASE_REF 指定時のみ。CI の pull_request で base を fetch して指定する）。
# PR が plugin crate（crates/plugin*/Cargo.toml）を新規追加するとき、base から HEAD までに core の
# ソース（Cargo.toml と src/ 配下）が変わっていれば失敗する。一時 workspace 比較では、PR 自体が
# plugin 追加と同時に core を変えるケースを検出できないための補完（PLUG-4）。
# fail-closed: 指定された ref が解決できなければ失敗する。
if [ -n "${PLUG4_BASE_REF:-}" ]; then
  git -C "$repo" rev-parse --verify --quiet "${PLUG4_BASE_REF}^{commit}" >/dev/null ||
    { echo "NG: PLUG4_BASE_REF not resolvable: ${PLUG4_BASE_REF}" >&2; exit 1; }
  added=$(git -C "$repo" diff --name-only --diff-filter=A "$PLUG4_BASE_REF" HEAD -- 'crates/plugin*/Cargo.toml')
  if [ -n "$added" ]; then
    changed=$(git -C "$repo" diff --name-only "$PLUG4_BASE_REF" HEAD -- crates/core/Cargo.toml crates/core/src)
    if [ -n "$changed" ]; then
      echo "NG: PR adds a plugin crate ($added) but also changes core (PLUG-4):" >&2
      echo "$changed" >&2
      status=1
    fi
  fi
fi

for f in src tree rlib; do
  if ! diff -u "$work/before/$f.txt" "$work/after/$f.txt"; then
    echo "NG: core $f fingerprint changed after plugin add (PLUG-4)" >&2
    status=1
  fi
done
[ "$status" -eq 0 ] || exit 1
echo "OK: core source list / dependency tree / rlib sha256 unchanged after plugin add (PLUG-4)"
echo "rlib sha256: $(cat "$work/after/rlib.txt")"
