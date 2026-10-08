#!/usr/bin/env bash
# PLUG-4（TASK-109.4・REPAIR-12）: plugin crate を workspace へ追加する前後で、core が無変更であることを
# 「別ビルド」で比較する判定スクリプト（docs/design/crate-naming.md 決定 3 の 3 点）。
#   (1) core crate 配下の全ファイル（Cargo.toml・src/・tests/ 等。crates/core 全体）の sha256 一覧
#       ※ Issue #256 の受け入れ条件「core crate 配下の全ソースファイル」と、AGENTS.md の「plugin を通すために
#         core 側のソースやテストを書き換えない」に合わせ、成果物に入らない tests/ も対象に含める。
#   (2) `cargo tree -p fandhe-container-core --locked -e normal` の依存木
#   (3) `cargo build -p fandhe-container-core --locked` の成果物（rlib）の sha256
#       ※ core は lib のみで bin が無いため rlib を代理にする。CLI bin（TASK-79）導入後に実行ファイルへ切り替える（REPAIR-3）。
# 手順: 「追加前」の tree を一時ディレクトリへ展開 → 追加前の指紋 → 「追加後」の tree（PR head の作業ツリー）へ
# 入れ替えて probe plugin crate を追加（root Cargo.toml / Cargo.lock は決定 3 により比較対象外）→ target を作り直して
# 追加後の指紋 → 比較。同一パス・同一 rustc で 2 回ビルドするため、パス埋め込み差で偽陽性にならない。
# 「追加前」の tree: 環境変数 PLUG4_BASE_REF（例: origin/main）指定時で、PR が plugin crate を新規追加しているなら
# merge-base(HEAD, PLUG4_BASE_REF) の tree（実際の plugin 追加前の基準。PR 自体が core を変えても検出できる。
# PR が追加する plugin の依存による feature 統合の変化も、core の依存木・rlib の差として現れる）。
# それ以外は「追加後」と同じ tree（probe 追加前）。base の現在の先端ではなく merge-base を使うため、分岐後に
# base だけで進んだ core の変更を PR の変更と誤検出しない。
# 「追加後」の tree: PLUG4_BASE_REF 指定時（PR 判定）は HEAD のコミット tree（作業ツリーに残った未コミットの
# 変更を判定へ混ぜない。差分検査と同じ merge-base..HEAD を見る）。未指定時（ローカル実行）は作業ツリーの
# 追跡ファイル（未コミットの変更を含む）。
# 加えて PLUG4_BASE_REF 指定時は、plugin crate を新規追加する PR が core（crates/core 配下全体）を変更して
# いないかを git diff でも検査する。plugin crate を追加しない PR の core 変更は対象外（通常の開発）。
# 移植性: Linux（GNU）と macOS（BSD）の両方で動かすため、GNU 専用の機能（tar --null・sed 置換内の \n・
# grep -z 等）を使わない。自己テストは scripts/check-plug4-core-invariance-selftest.sh（CI は ubuntu・macos・
# windows〔Git Bash〕の 3 OS で実行）。
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

# PLUG4_BASE_REF 指定時は merge-base を求める（fail-closed: 解決不能・merge-base 無しは失敗。shallow clone では不可）。
mb=""
added=""
if [ -n "${PLUG4_BASE_REF:-}" ]; then
  git -C "$repo" rev-parse --verify --quiet "${PLUG4_BASE_REF}^{commit}" >/dev/null ||
    { echo "NG: PLUG4_BASE_REF not resolvable: ${PLUG4_BASE_REF}" >&2; exit 1; }
  mb=$(git -C "$repo" merge-base HEAD "$PLUG4_BASE_REF") ||
    { echo "NG: no merge-base between HEAD and ${PLUG4_BASE_REF} (shallow clone?)" >&2; exit 1; }
  # --no-renames: 既存 crate の改名・複製として検出され「新規追加」から漏れるのを防ぐ（git の既定は改名検出あり）。
  added=$(git -C "$repo" diff --no-renames --name-only --diff-filter=A "$mb" HEAD -- 'crates/plugin*/Cargo.toml')
fi

# 作業ツリーの追跡ファイル（未コミットの変更を含む）を ws へ複製する。docs/spec（submodule）は含めない。
# PLUG4_BASE_REF 未指定（ローカル実行）のときだけ使う。
# 移植性のため grep -z・tar --null は使わず、git の pathspec 除外で作った NUL 区切り一覧を bash の read で
# 1 件ずつ複製する（cp -RPp は symlink を辿らずそのまま複製する。GNU・BSD 共通）。
# 追跡ファイルが作業ツリーから消えている場合は cp が失敗し、非ゼロ終了する（fail-closed）。
populate_worktree() {
  local f
  (cd "$repo" && git ls-files -z --cached -- . ':(exclude)docs/spec') |
    while IFS= read -r -d '' f; do
      case "$f" in
        */*) mkdir -p "$ws/${f%/*}" ;;
      esac
      cp -RPp "$repo/$f" "$ws/$f"
    done
}
# $1: コミット。そのコミットの tree を ws へ展開する（submodule は gitlink のため中身は含まれない）。
populate_commit() {
  git -C "$repo" archive "$1" | tar -xf - -C "$ws"
}
# 「追加後」の tree を ws へ展開する（PLUG4_BASE_REF 指定時は HEAD のコミット、未指定時は作業ツリー）。
populate_head() {
  if [ -n "$mb" ]; then
    populate_commit HEAD
  else
    populate_worktree
  fi
}

# $1: 指紋の出力名（before / after）
fingerprint() {
  # target dir のパスも成果物へ埋め込まれ得るため、追加前後で同一パスを使い、毎回作り直す（偽陽性防止）。
  local out="$work/$1" tgt="$work/target"
  rm -rf "$tgt"
  mkdir -p "$out"
  # crates/core 配下の全ファイル（tests/ 等を含む）。target は CARGO_TARGET_DIR で ws の外へ出すため混ざらない。
  (cd "$ws/crates/core" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do sha "$f"; done) >"$out/src.txt"
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

if [ -n "$added" ]; then
  populate_commit "$mb"
else
  populate_head
fi
fingerprint before
if [ -n "$added" ]; then
  # 追加後は PR head。同一パスで再ビルドするため ws を作り直す。
  rm -rf "$ws"
  mkdir -p "$ws"
  populate_head
fi

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
# sed の置換文字列内の \n は GNU 拡張（BSD sed では文字 n になる）ため、awk で members の直後へ 1 行挿入する。
awk '{ print } /^members = \[$/ && !done { print "    \"crates/plugin-plug4probe\","; done = 1 }' \
  "$ws/Cargo.toml" >"$ws/Cargo.toml.new"
mv "$ws/Cargo.toml.new" "$ws/Cargo.toml"
grep -q '^    "crates/plugin-plug4probe",$' "$ws/Cargo.toml" || { echo "NG: failed to add probe member" >&2; exit 1; }
(cd "$ws" && cargo update --workspace --offline >&2)
(cd "$ws" && CARGO_TARGET_DIR="$work/target-probe" cargo build -p fandhe-container-plugin-plug4probe --locked >&2)

fingerprint after

status=0

# PR 差分の検査（PLUG4_BASE_REF 指定時のみ）。PR が plugin crate（crates/plugin*/Cargo.toml）を新規追加するとき、
# merge-base から HEAD までに core（crates/core 配下全体。src/ に加え tests/ 等も含む）が変わっていれば失敗する
# （指紋比較と同じ基準点。分かりやすい差分一覧を出すための補完。PLUG-4）。
if [ -n "$added" ]; then
  changed=$(git -C "$repo" diff --no-renames --name-only "$mb" HEAD -- crates/core)
  if [ -n "$changed" ]; then
    echo "NG: PR adds a plugin crate ($added) but also changes core (PLUG-4):" >&2
    echo "$changed" >&2
    status=1
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
