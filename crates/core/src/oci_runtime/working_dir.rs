//! `process.cwd` を start が適用できる検証済みの型へ変換する（OCI-1・TASK-29）。
//!
//! # 役割と呼び出し文脈
//!
//! `start` の `build_spec` が `config.json` の `process.cwd` を [`ContainerWorkingDir::parse`] で字句検証し、
//! [`LaunchSpec`](super::LaunchSpec) 経由で本番 launcher へ渡す。子は pivot_root の直後に
//! `exec::enter_working_dir` で、この型の要素を fd 起点・symlink 非追従で 1 要素ずつ辿って `fchdir` する。
//! 「`..`・`\`・NUL を含む値」「上限超過」を表現できない型にして、字句の検証を 1 か所に保つ（REPAIR-2）。
//!
//! 規則は `mounts[].destination` と共有する `crate::path_masks::normalize_container_path` に従う。
//! `/`（rootfs の根）だけは要素が 0 個になるため [`ContainerWorkingDir::Root`] として別に表す。

use std::path::Path;

use super::config::CONFIG_MAX_PATH_BYTES;
use crate::path_masks::normalize_container_path;

/// 検証済みのコンテナ内の作業ディレクトリ（正規化済みの絶対パス）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerWorkingDir {
    /// rootfs の根（`/`）。chdir は不要（pivot_root が cwd を根にする）。
    Root,
    /// 根より下のパス（要素列。空要素・`.`・`..`・`/`・NUL を含まない）。
    Path(Vec<String>),
}

impl ContainerWorkingDir {
    /// `process.cwd` を検証・正規化する。`/` 始まりでない・`..` を含む・`\` や NUL を含む・上限超過・
    /// UTF-8 でない値は `None`（呼び出し側が `InvalidArgument` にする）。
    pub fn parse(cwd: &Path) -> Option<Self> {
        let s = cwd.to_str()?;
        if !s.starts_with('/') {
            return None;
        }
        if s.contains('\0') || s.contains('\\') {
            return None;
        }
        if s.split('/').all(|p| p.is_empty() || p == ".") {
            return Some(Self::Root);
        }
        let normalized = normalize_container_path(s, CONFIG_MAX_PATH_BYTES)?;
        let parts = normalized
            .split('/')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        Some(Self::Path(parts))
    }

    /// 根か（chdir を省略できるか）。
    pub fn is_root(&self) -> bool {
        matches!(self, Self::Root)
    }

    /// 根からの要素列（`Root` は空）。
    pub fn components(&self) -> &[String] {
        match self {
            Self::Root => &[],
            Self::Path(p) => p,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Option<ContainerWorkingDir> {
        ContainerWorkingDir::parse(Path::new(s))
    }

    /// OCI-1: `/` は `Root`、`/app` は 1 要素、重複区切り・`.`・末尾 `/` は正規化される。
    #[test]
    fn accepts_and_normalizes() {
        assert_eq!(parse("/"), Some(ContainerWorkingDir::Root));
        assert_eq!(parse("//"), Some(ContainerWorkingDir::Root));
        assert_eq!(
            parse("/app"),
            Some(ContainerWorkingDir::Path(vec!["app".to_owned()]))
        );
        assert_eq!(
            parse("//a/./b/"),
            Some(ContainerWorkingDir::Path(vec![
                "a".to_owned(),
                "b".to_owned()
            ]))
        );
        assert_eq!(parse("/a/b").unwrap().components(), ["a", "b"]);
        assert!(parse("/").unwrap().is_root());
        assert!(!parse("/a").unwrap().is_root());
    }

    /// OCI-1・SEC-1: `..`・`\`・NUL・相対・空・上限超過は表現できない。
    #[test]
    fn rejects_traversal_and_oversize() {
        for bad in ["/a/../b", "/..", "/a\\b", "/a\0b", "rel", "", "./a"] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        let long = format!("/{}", "d".repeat(CONFIG_MAX_PATH_BYTES));
        assert_eq!(parse(&long), None);
    }
}
