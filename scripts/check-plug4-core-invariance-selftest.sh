#!/usr/bin/env bash
# scripts/check-plug4-core-invariance.sh の自己テスト（PLUG-4・TASK-109.4・REPAIR-12）。
#
# 役割: 依存 0 件の最小 workspace（fandhe-container-core だけを持つ fixture）を一時 git リポジトリとして
# 作り、判定スクリプトを実際に走らせて終了コードと出力を具体値で照合する。実リポのファイルは使わない。
# 判定スクリプトは自身の位置からリポジトリを決めるため、fixture の scripts/ へ複製して実行する。
# 呼び出し元は Makefile の `plug4-core-invariance-selftest` と `.github/workflows/ci.yml` の
# `integration-test` ジョブ（ubuntu・macos・windows の 3 OS。GNU / BSD 双方のツールと Windows の Git Bash で
# 動くことを実行で確かめる）。
#
# 照合する内容:
#   - plugin crate を追加しない場合・plugin crate だけを追加する PR は成功する
#   - plugin crate を追加する PR が core の src/ または tests/ を変更すると失敗し、変更ファイルを出力する
#   - plugin crate を追加しない PR の core 変更は対象外（成功）
#   - 基準は merge-base（分岐後に base だけで進んだ core 変更を PR の変更と誤検出しない）
#   - PLUG4_BASE_REF 指定時（PR 判定）は HEAD のコミット tree を見る（作業ツリーの未コミット変更を混ぜない）。
#     未指定時（ローカル実行）は作業ツリーの未コミット変更を含めて複製する
#   - PLUG4_BASE_REF が解決できなければ失敗する（fail-closed）
#   - 空白を含むパス・symlink を含む作業ツリーを複製できる
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。cargo と git が必要（ネットワークは不要）。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${PLUG4_SCRIPT:-${script_dir}/check-plug4-core-invariance.sh}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fx="${work}/fx"

failures=0
pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# 利用者の git 設定（署名・hooks）に影響されないよう、fixture 用の設定を毎回明示する。
g() {
  git -C "$fx" -c user.name=selftest -c user.email=selftest@example.invalid \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"
}

# fixture の初期コミット（ブランチ base）を作る。
init_fixture() {
  mkdir -p "$fx/scripts" "$fx/crates/core/src" "$fx/crates/core/tests" "$fx/docs/with space"
  cat >"$fx/Cargo.toml" <<'TOML'
[workspace]
resolver = "3"
members = [
    "crates/core",
]

[workspace.package]
edition = "2024"
license = "Apache-2.0"
TOML
  cat >"$fx/crates/core/Cargo.toml" <<'TOML'
[package]
name = "fandhe-container-core"
version = "0.0.0"
edition.workspace = true
license.workspace = true
publish = false
TOML
  echo 'pub fn answer() -> u32 { 42 }' >"$fx/crates/core/src/lib.rs"
  cat >"$fx/crates/core/tests/t.rs" <<'RS'
#[test]
fn answer_is_42() {
    assert_eq!(fandhe_container_core::answer(), 42);
}
RS
  echo 'note' >"$fx/docs/with space/a b.txt"
  ln -s "with space" "$fx/docs/link"
  printf 'target/\n' >"$fx/.gitignore"
  cp "$target" "$fx/scripts/check-plug4-core-invariance.sh"
  (cd "$fx" && cargo generate-lockfile --offline >/dev/null 2>&1)
  git -C "$fx" init -q
  g checkout -q -b base
  g add -A
  g commit -q -m base
}

# plugin crate を workspace メンバーとして追加してコミットする。引数: <crate の短縮名>
add_plugin() {
  local name="$1"
  mkdir -p "$fx/crates/${name}/src"
  cat >"$fx/crates/${name}/Cargo.toml" <<TOML
[package]
name = "fandhe-container-${name}"
version = "0.0.0"
edition.workspace = true
license.workspace = true
publish = false
TOML
  echo '//! fixture plugin' >"$fx/crates/${name}/src/lib.rs"
  awk -v m="    \"crates/${name}\"," '{ print } /^members = \[$/ { print m }' "$fx/Cargo.toml" >"$fx/Cargo.toml.new"
  mv "$fx/Cargo.toml.new" "$fx/Cargo.toml"
  (cd "$fx" && cargo update --workspace --offline >/dev/null 2>&1)
  g add -A
  g commit -q -m "add ${name}"
}

# fixture のブランチ base から <ブランチ名> を作って切り替える。
branch_from_base() {
  g checkout -q base
  g checkout -q -b "$1"
}

# 引数: <ケース名> <期待終了コード> <PLUG4_BASE_REF（空なら未指定）> [出力に含まれるべき文字列...]
run_case() {
  local name="$1" expected="$2" base_ref="$3"
  shift 3
  local actual=0 want status_before
  status_before="$(g status --porcelain)"
  if [ -n "$base_ref" ]; then
    PLUG4_BASE_REF="$base_ref" bash "$fx/scripts/check-plug4-core-invariance.sh" >"$work/out.txt" 2>&1 || actual=$?
  else
    env -u PLUG4_BASE_REF bash "$fx/scripts/check-plug4-core-invariance.sh" >"$work/out.txt" 2>&1 || actual=$?
  fi
  if [ "$actual" -ne "$expected" ]; then
    fail "${name} (expected exit=${expected}, actual exit=${actual})"
    sed 's/^/    | /' "$work/out.txt" >&2
    return
  fi
  for want in "$@"; do
    if ! grep -qF -- "$want" "$work/out.txt"; then
      fail "${name} (output lacks: ${want})"
      sed 's/^/    | /' "$work/out.txt" >&2
      return
    fi
  done
  # 判定スクリプトはリポ内のファイルを変更しない
  if [ "$(g status --porcelain)" != "$status_before" ]; then
    fail "${name} (repository was modified)"
    return
  fi
  pass "${name} (exit=${actual})"
}

ok_msg="OK: core source list / dependency tree / rlib sha256 unchanged after plugin add (PLUG-4)"
ng_msg="but also changes core (PLUG-4):"

init_fixture

# 1. PLUG4_BASE_REF 未指定（probe 追加前後の比較のみ）。空白を含むパス・symlink の複製も通る
run_case "no-base-ref" 0 "" "$ok_msg"

# 2. PLUG4_BASE_REF が解決できない → 失敗（fail-closed）
run_case "unresolvable-base-ref" 1 "no-such-ref" "NG: PLUG4_BASE_REF not resolvable: no-such-ref"

# 3. plugin crate だけを追加する PR → 成功
branch_from_base pr-plugin-only
add_plugin plugin-alpha
run_case "plugin-only" 0 base "$ok_msg"

# 4. plugin crate を追加し core の tests/ を変更する PR → 失敗（tests も core。Issue #256・AGENTS.md）
branch_from_base pr-plugin-and-core-tests
add_plugin plugin-beta
echo '// changed' >>"$fx/crates/core/tests/t.rs"
g commit -q -am "change core tests"
run_case "plugin-and-core-tests" 1 base "$ng_msg" "crates/core/tests/t.rs" \
  "NG: core src fingerprint changed after plugin add (PLUG-4)"

# 5. plugin crate を追加し core の src/ を変更する PR → 失敗（rlib の指紋も変わる）
branch_from_base pr-plugin-and-core-src
add_plugin plugin-gamma
echo 'pub fn extra() -> u32 { 7 }' >>"$fx/crates/core/src/lib.rs"
g commit -q -am "change core src"
run_case "plugin-and-core-src" 1 base "$ng_msg" "crates/core/src/lib.rs" \
  "NG: core rlib fingerprint changed after plugin add (PLUG-4)"

# 6. plugin crate を追加しない PR の core 変更は対象外 → 成功
branch_from_base pr-core-only
echo '// changed' >>"$fx/crates/core/tests/t.rs"
echo 'pub fn extra() -> u32 { 7 }' >>"$fx/crates/core/src/lib.rs"
g commit -q -am "change core only"
run_case "core-only-without-plugin" 0 base "$ok_msg"

# 7. 分岐後に base だけで core が進んでも、plugin だけを追加する PR は成功（基準は merge-base）
g checkout -q base
g checkout -q -b base-moved
echo 'pub fn later() -> u32 { 1 }' >>"$fx/crates/core/src/lib.rs"
g commit -q -am "base moves core"
g checkout -q pr-plugin-only
run_case "base-moved-after-fork" 0 base-moved "$ok_msg"

# 8. PR 判定は HEAD のコミット tree を見る: 作業ツリーに未コミットの core 変更が残っていても、
#    plugin だけを追加する PR は成功する（merge-base と PR head の比較に固定）
echo 'pub fn dirty() -> u32 { 9 }' >>"$fx/crates/core/src/lib.rs"
run_case "pr-mode-ignores-dirty-worktree" 0 base "$ok_msg"

# 9. ローカル実行（PLUG4_BASE_REF 未指定）は作業ツリーを複製する: 未コミットの変更で core がビルド
#    できなくなっていれば失敗する（コミット tree を見ていれば成功してしまう）
echo 'compile_error!("dirty worktree is copied");' >>"$fx/crates/core/src/lib.rs"
run_case "local-mode-uses-worktree" 101 "" "dirty worktree is copied"
g checkout -q -- crates/core/src/lib.rs

if [ "$failures" -ne 0 ]; then
  echo "plug4-core-invariance selftest: ${failures} failure(s)" >&2
  exit 1
fi
echo "plug4-core-invariance selftest: all cases passed"
