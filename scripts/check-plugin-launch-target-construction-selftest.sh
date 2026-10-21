#!/usr/bin/env bash
# scripts/check-plugin-launch-target-construction.sh の自己テスト（make check-launch-target-selftest。
# PLUG-11・REPAIR-12・#1857）。
#
# 一時ディレクトリに実際の許可リストと同じ相対パスの最小 fixture ツリーを作り、基準形から 1 か所だけ
# 変えたケースごとに終了コードと stderr の `NG:` 行を照合する。実リポジトリ・ネットワーク・root は使わない。
# 1 件でも失敗すれば非 0 で終わる。読めないファイルのケースは chmod が効かない環境（root・Windows）では
# 実行できないため note を出して先へ進む（他のケースは skip しない）。
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="${here}/check-plugin-launch-target-construction.sh"
work="$(mktemp -d)"
trap 'chmod -R u+rwx "${work}" 2>/dev/null || true; rm -rf "${work}"' EXIT

failures=0
pass() { echo "ok: $1"; }
bad() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

DEF=crates/plugin/src/lifecycle/launch_target.rs
MODE=crates/plugin/src/lifecycle/mode.rs
PROD=crates/core/src/plugin.rs

# 基準形を ${1} に作る。
make_base() {
  local r="$1"
  mkdir -p "${r}/crates/plugin/src/lifecycle" "${r}/crates/core/src" "${r}/crates/plugin/tests" \
    "${r}/crates/cli/tests" "${r}/benches/benches"
  cat >"${r}/${DEF}" <<'EOT'
//! `PluginLaunchTarget::from_verified_file` に触れる doc コメント。
pub struct PluginLaunchTarget {
    file: Arc<File>,
}

impl PluginLaunchTarget {
    /// `from_verified_file` の doc。
    pub fn from_verified_file(
        file: File,
        display_path: PathBuf,
    ) -> Result<Self, PluginError> {
        #[cfg(unix)]
        {
            Ok(Self {
                file: Arc::new(file),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                file: Arc::new(file),
            })
        }
    }

    pub fn display_path(&self) -> &Path {
        &self.display_path
    }

    pub fn identity(&self) -> PluginFileIdentity {
        self.identity
    }
}

pub(crate) fn linux_fd_exec_path(
    target: &PluginLaunchTarget,
) -> Result<PathBuf, PluginError> {
    todo!()
}

#[cfg(test)]
fn current_exe_target() -> PluginLaunchTarget {
    PluginLaunchTarget::from_verified_file(f).unwrap()
}

#[cfg(test)]
fn test_literal() -> PluginLaunchTarget {
    PluginLaunchTarget { file: x }
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let _ = PluginLaunchTarget::from_verified_file(f);
    }
}
EOT
  cat >"${r}/${MODE}" <<'EOT'
pub fn run() {}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let _ = PluginLaunchTarget::from_verified_file(f);
    }
}
EOT
  cat >"${r}/${PROD}" <<'EOT'
//! core の変換。
impl HashVerifiedPluginFile {
    pub fn into_launch_target(self) -> Result<PluginLaunchTarget, PluginError> {
        PluginLaunchTarget::from_verified_file(file, display, exec)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}
EOT
  echo 'fn t() { PluginLaunchTarget::from_verified_file(f); }' >"${r}/crates/plugin/tests/a.rs"
  echo 'fn t() { PluginLaunchTarget::from_verified_file(f); }' >"${r}/crates/cli/tests/b.rs"
  echo 'fn t() { PluginLaunchTarget::from_verified_file(f); }' >"${r}/benches/benches/c.rs"
}

# run_case <名前> <期待終了コード> <stderr に含まれるべき文字列（空なら照合しない）> <fixture 変更関数> [引数...]
run_case() {
  local name="$1" want="$2" needle="$3" mutate="$4"
  shift 4
  local r="${work}/${name}"
  make_base "${r}"
  "${mutate}" "${r}"
  local out err rc
  out="${work}/${name}.out"
  err="${work}/${name}.err"
  set +e
  "${checker}" --root "${r}" "$@" >"${out}" 2>"${err}"
  rc=$?
  set -e
  if [ "${rc}" -ne "${want}" ]; then
    bad "${name}: exit ${rc}, want ${want} ($(tr '\n' ' ' <"${err}"))"
    return
  fi
  if [ -n "${needle}" ] && ! grep -qF -- "${needle}" "${err}" "${out}"; then
    bad "${name}: output does not contain '${needle}'"
    return
  fi
  pass "${name}"
}

m_none() { :; }
m_cli_prod() {
  mkdir -p "$1/crates/cli/src"
  printf 'fn main() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/crates/cli/src/main.rs"
}
m_mode_before_tests() {
  printf 'pub fn run() { let _ = PluginLaunchTarget::from_verified_file(f); }\n' >"$1/${MODE}"
}
m_mode_after_tests() {
  printf '\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >>"$1/${MODE}"
}
m_any_test() {
  printf '#[cfg(any(test, feature = "x"))]\nfn helper() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >>"$1/${MODE}"
}
m_core_other_test() {
  printf '#[cfg(test)]\nmod tests {\n    fn t() { PluginLaunchTarget::from_verified_file(f); }\n}\n' >"$1/crates/core/src/other.rs"
}
m_poc() {
  mkdir -p "$1/poc/pkg/src"
  echo 'fn t() { PluginLaunchTarget::from_verified_file(f); }' >"$1/poc/pkg/src/lib.rs"
}
m_rename() {
  find "$1" -name '*.rs' -exec sed -i.bak 's/from_verified_file/from_checked_file/g' {} +
  find "$1" -name '*.bak' -delete
}
m_prod_zero() {
  printf '//! core の変換。\nimpl X {}\n' >"$1/${PROD}"
}
m_prod_two() {
  printf '\nfn another() {\n    PluginLaunchTarget::from_verified_file(f);\n}\n' >>"$1/${PROD}"
}
m_fnptr() {
  mkdir -p "$1/crates/net/src"
  echo 'fn t() { x.map(PluginLaunchTarget::from_verified_file); }' >"$1/crates/net/src/lib.rs"
}
m_comment_only() {
  mkdir -p "$1/crates/net/src"
  printf '// PluginLaunchTarget::from_verified_file は呼ばない\n/// from_verified_file の説明\nfn t() {}\n' >"$1/crates/net/src/lib.rs"
}
m_dir_rs() {
  mkdir -p "$1/crates/x/src/d.rs"
}
m_no_crates() {
  rm -rf "$1/crates"
}
m_unreadable() {
  mkdir -p "$1/crates/net/src"
  echo 'fn t() {}' >"$1/crates/net/src/secret.rs"
  chmod 000 "$1/crates/net/src/secret.rs"
}
m_prod_in_test() {
  printf '\n#[cfg(test)]\nfn t() {\n    PluginLaunchTarget::from_verified_file(f);\n}\n' >>"$1/${PROD}"
}
# 文字列・コメントの中の試験属性は領域を開かない（後続の本番呼び出しは違反として検出する）
m_str_inner_attr() {
  printf 'const FIXTURE: &str = r#"\n#![cfg(test)]\n"#;\n\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_str_outer_attr() {
  printf 'const F: &str = "\\n#[cfg(test)]";\nconst G: &str = r##"\n#[cfg(test)]\n"##;\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_block_comment_attr() {
  printf '/*\n#![cfg(test)]\n#[cfg(test)]\n*/\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_multiline_str_attr() {
  printf 'const F: &str = "a\n#[cfg(test)]\nb";\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_unterminated() {
  printf 'const F: &str = "abc\n#![cfg(test)]\n' >"$1/${MODE}"
}
m_real_inner_attr() {
  printf '#![cfg(test)]\nfn t() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_char_quote() {
  printf '%s\n' "fn a() { let _ = '\"'; }" '#[cfg(test)]' 'fn t() {' '    let _ = PluginLaunchTarget::from_verified_file(f);' '}' >"$1/${MODE}"
}
def_append() { printf '%s\n' "$2" >>"$1/${DEF}"; }
m_alias_ctor_literal() {
  def_append "$1" 'impl PluginLaunchTarget {
    pub fn from_path(file: File) -> Result<Self, PluginError> {
        Ok(Self { file: Arc::new(file) })
    }
}'
}
m_alias_ctor_multiline() {
  def_append "$1" 'impl PluginLaunchTarget {
    pub fn from_path(
        file: File,
    ) -> Self {
        make(file)
    }
}'
}
m_alias_ctor_clone() {
  def_append "$1" 'impl PluginLaunchTarget {
    pub fn dup(&self) -> Self { self.clone() }
}'
}
m_literal_outside_fvf() {
  def_append "$1" 'impl Default for PluginLaunchTarget {
    fn default() -> Self {
        PluginLaunchTarget { file: x }
    }
}'
}
m_literal_count_decreased() {
  # 片方の cfg 分岐のリテラル（2 件目）を消す
  awk 'BEGIN{n=0} /Ok\(Self \{/ {n++; if (n==2) {print "            Err(todo())"; skip=2; next}} skip>0 {skip--; next} {print}' "$1/${DEF}" >"$1/${DEF}.new"
  mv "$1/${DEF}.new" "$1/${DEF}"
}
m_literal_in_test_ok() {
  def_append "$1" '#[cfg(test)]
mod more {
    fn t() -> u8 { let _ = PluginLaunchTarget { file: x }; 0 }
}'
}
m_oneline_cfg_test() {
  printf '#[cfg(test)] fn a() {}\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_oneline_attr_after_cfg_test() {
  printf '#[cfg(test)]\n#[allow(dead_code)] fn a() {}\nfn prod() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_cfg_test_trailing_comment_ok() {
  printf '#[cfg(test)] // note\nfn a() {\n    let _ = PluginLaunchTarget::from_verified_file(f);\n}\n' >"$1/${MODE}"
}
m_multiline_attr_ok() {
  printf '#[cfg(all(\n    unix,\n))]\nfn a() {}\n' >"$1/${MODE}"
}
m_def_external_mod() {
  def_append "$1" 'mod evil;'
}
m_symlink_dir() {
  mkdir -p "$1/crates/real/src"
  ln -s real "$1/crates/linked"
}
m_second_def() {
  mkdir -p "$1/crates/net/src"
  echo 'pub fn from_verified_file() {}' >"$1/crates/net/src/lib.rs"
}

run_case base 0 "OK:" m_none
run_case cli_prod 1 "NG: crates/cli/src/main.rs:2:" m_cli_prod
run_case mode_before_tests 1 "NG: ${MODE}:1:" m_mode_before_tests
run_case mode_after_tests 1 "NG: ${MODE}:" m_mode_after_tests
run_case any_test 1 "NG: ${MODE}:" m_any_test
run_case core_other_test 1 "NG: crates/core/src/other.rs:3:" m_core_other_test
run_case poc 1 "NG: poc/pkg/src/lib.rs:1:" m_poc
run_case rename 1 "NG: " m_rename
run_case prod_zero 1 "expected exactly one production use" m_prod_zero
run_case prod_two 1 "expected exactly one production use" m_prod_two
run_case prod_in_test 1 "NG: ${PROD}:" m_prod_in_test
run_case fn_pointer 1 "NG: crates/net/src/lib.rs:1:" m_fnptr
run_case comment_only 0 "OK:" m_comment_only
run_case dir_rs 1 "not a readable regular file" m_dir_rs
run_case no_crates 1 "crates directory not found" m_no_crates
run_case second_def 1 "NG: " m_second_def
run_case str_inner_attr 1 "NG: ${MODE}:6:" m_str_inner_attr
run_case str_outer_attr 1 "NG: ${MODE}:6:" m_str_outer_attr
run_case block_comment_attr 1 "NG: ${MODE}:6:" m_block_comment_attr
run_case multiline_str_attr 1 "NG: ${MODE}:5:" m_multiline_str_attr
run_case unterminated 1 "unterminated string" m_unterminated
run_case real_inner_attr 0 "OK:" m_real_inner_attr
run_case char_quote 0 "OK:" m_char_quote
run_case alias_ctor_literal 1 "function 'from_path' returns PluginLaunchTarget" m_alias_ctor_literal
run_case alias_ctor_literal_lit 1 "struct literal outside from_verified_file" m_alias_ctor_literal
run_case alias_ctor_multiline 1 "function 'from_path' returns PluginLaunchTarget" m_alias_ctor_multiline
run_case alias_ctor_clone 1 "function 'dup' returns PluginLaunchTarget" m_alias_ctor_clone
run_case literal_outside_fvf 1 "struct literal outside from_verified_file" m_literal_outside_fvf
run_case literal_count_decreased 1 "expected 2 PluginLaunchTarget struct literals" m_literal_count_decreased
run_case literal_in_test_ok 0 "OK:" m_literal_in_test_ok
run_case oneline_cfg_test 1 "NG: ${MODE}:1: attribute followed by code" m_oneline_cfg_test
run_case oneline_cfg_test_prod 1 "NG: ${MODE}:3:" m_oneline_cfg_test
run_case oneline_attr_after_cfg_test 1 "NG: ${MODE}:2: attribute followed by code" m_oneline_attr_after_cfg_test
run_case cfg_test_trailing_comment_ok 0 "OK:" m_cfg_test_trailing_comment_ok
run_case multiline_attr_ok 0 "OK:" m_multiline_attr_ok
run_case def_external_mod 1 "out-of-file module" m_def_external_mod

# ディレクトリの symlink。作れない環境（Git Bash で複製になる等）では note を出して先へ進む。
symprobe="${work}/symprobe"
mkdir -p "${symprobe}/d"
if ln -s d "${symprobe}/l" 2>/dev/null && [ -L "${symprobe}/l" ]; then
  run_case symlink_dir 1 "symlinked directory is not scanned" m_symlink_dir
else
  echo "note: symlink-dir case not applicable on this host"
fi
run_case bad_arg 2 "usage:" m_none --bogus

# 読めないファイル。chmod 000 でも読めてしまう環境では実行できない。
probe="${work}/probe"
echo x >"${probe}"
chmod 000 "${probe}"
if [ -r "${probe}" ]; then
  echo "note: unreadable-file case not applicable on this host"
else
  run_case unreadable 1 "not a readable regular file" m_unreadable
fi

if [ "${failures}" -ne 0 ]; then
  echo "FAIL: ${failures} case(s) failed" >&2
  exit 1
fi
echo "ok: all check-launch-target selftest cases passed"
