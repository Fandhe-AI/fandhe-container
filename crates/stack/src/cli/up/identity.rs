//! `up` が作るコンテナ ID の規則（STACK-8・SEC-1・TASK-155・#3639）。
//!
//! プロジェクト名とサービス名（どちらも TOML / 引数由来の外部入力）から `<project>.<service>` の
//! コンテナ ID を作る唯一の関数を置く。後続の本番アダプタ（`up` の launcher・`down`・`ps`・`logs`）が
//! 同じ関数を使い、ID の食い違いで別のコンテナを操作しないようにする。
//!
//! プロジェクト名は `.` を含めないため、ID は最初の `.` で一意に分解でき、写像は単射になる
//! （別の組が同じ ID に衝突しない）。結果は core の `ContainerId::new`
//! （`crates/core/src/traits/types.rs`。1〜255 バイト・`[A-Za-z0-9._-]`・`.` / `..` 以外）の規則を
//! 常に満たす。stack は core に依存しないため規則を複製しており、SSOT は core 側。乖離は単体試験で検出する。

use std::fmt;

use crate::cli::logs::is_valid_service_name;

/// プロジェクト名の最大バイト数。
const MAX_PROJECT_NAME_LEN: usize = 63;
/// コンテナ ID の最大バイト数（core の `ContainerId` と同じ）。
const MAX_CONTAINER_ID_LEN: usize = 255;
/// ID に使えるサービス名の最大バイト数（ID 全体の上限からプロジェクト名と区切りを引いた値）。
const MAX_SERVICE_PART_LEN: usize = MAX_CONTAINER_ID_LEN - MAX_PROJECT_NAME_LEN - 1;

/// 識別子の検証失敗。入力の値は運ばない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// プロジェクト名が規則（`[a-z0-9][a-z0-9_-]{0,62}`）に反する。
    InvalidProject,
    /// サービス名が規則に反する、または ID に使うには長すぎる。
    InvalidService,
}

impl IdentityError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        "INVALID_ARGUMENT"
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidProject => "project name is invalid",
            Self::InvalidService => "service name is invalid",
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for IdentityError {}

/// 検証済みのプロジェクト名（`[a-z0-9][a-z0-9_-]{0,62}`。`.` を含まない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectName(String);

impl ProjectName {
    /// 規則を検証して作る。
    pub fn new(name: &str) -> Result<Self, IdentityError> {
        let mut bytes = name.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let rest_ok =
            bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
        if first_ok && rest_ok && name.len() <= MAX_PROJECT_NAME_LEN {
            Ok(Self(name.to_owned()))
        } else {
            Err(IdentityError::InvalidProject)
        }
    }

    /// 名前の文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// プロジェクト名を 3 段で決める（STACK-8・TASK-155・#4638。判断の出典は #4630）。
///
/// 優先順は `--project-name`（`flag`）＞ TOML の `[project].name`（`toml_name`）＞ TOML のあるディレクトリ名
/// （`toml_dir` の最後の要素）。どの段の値も [`ProjectName::new`] の既存規則で検証し、正規化（小文字化・
/// 記号の置換）はしない。上位の段に値があれば、それが不正でも下位の段へ落とさずに失敗する（fail-closed）。
/// 呼び出し元は CLI の `up`（down・ps・logs の結線も同じ関数を使い、ID の食い違いを防ぐ）。
pub fn resolve_project_name(
    flag: Option<&str>,
    toml_name: Option<&str>,
    toml_dir: &std::path::Path,
) -> Result<ProjectName, IdentityError> {
    if let Some(name) = flag {
        return ProjectName::new(name);
    }
    if let Some(name) = toml_name {
        return ProjectName::new(name);
    }
    let dir_name = toml_dir
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(IdentityError::InvalidProject)?;
    ProjectName::new(dir_name)
}

/// `<project>.<service>` 形式の検証済みコンテナ ID。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContainerId(String);

impl ServiceContainerId {
    /// プロジェクト名とサービス名から ID を作る。サービス名は検証する。
    pub fn derive(project: &ProjectName, service: &str) -> Result<Self, IdentityError> {
        if !is_valid_service_name(service) || service.len() > MAX_SERVICE_PART_LEN {
            return Err(IdentityError::InvalidService);
        }
        Ok(Self(format!("{}.{service}", project.as_str())))
    }

    /// ID の文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// core の `ContainerId::new` の規則の複製（SSOT は core）。
    fn core_rule(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 255
            && id != "."
            && id != ".."
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }

    #[test]
    fn stack8_project_name_boundaries() {
        assert!(ProjectName::new(&"a".repeat(63)).is_ok());
        assert_eq!(
            ProjectName::new(&"a".repeat(64)),
            Err(IdentityError::InvalidProject)
        );
        for bad in ["", "_a", "-a", "Ab", "a.b", "a b", "a/b", "é", "a\0"] {
            assert_eq!(
                ProjectName::new(bad),
                Err(IdentityError::InvalidProject),
                "{bad:?}"
            );
        }
        assert!(ProjectName::new("0a_b-c").is_ok());
    }

    #[test]
    fn stack8_service_part_boundaries() {
        let p = ProjectName::new("app").unwrap();
        assert!(ServiceContainerId::derive(&p, &"s".repeat(191)).is_ok());
        for bad in [
            "".to_owned(),
            "s".repeat(192),
            "a/b".to_owned(),
            "a b".to_owned(),
            "a\0b".to_owned(),
            "é".to_owned(),
        ] {
            assert_eq!(
                ServiceContainerId::derive(&p, &bad),
                Err(IdentityError::InvalidService),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn stack8_derive_is_concrete_and_injective() {
        let p = ProjectName::new("app").unwrap();
        let id = ServiceContainerId::derive(&p, "web.v2").unwrap();
        assert_eq!(id.as_str(), "app.web.v2");
        assert_eq!(id.to_string(), "app.web.v2");
        // `(a, b.c)` と `(a.b, c)` は後者のプロジェクト名が作れないため衝突しない。
        assert_eq!(ProjectName::new("a.b"), Err(IdentityError::InvalidProject));
        let id = ServiceContainerId::derive(&ProjectName::new("a").unwrap(), "b.c").unwrap();
        assert_eq!(id.as_str(), "a.b.c");
    }

    #[test]
    fn sec1_derived_ids_satisfy_core_container_id_rule() {
        let p = ProjectName::new(&"p".repeat(63)).unwrap();
        for svc in ["a", "web_1-x.y", "..", &"s".repeat(191)] {
            let id = ServiceContainerId::derive(&p, svc).unwrap();
            assert!(core_rule(id.as_str()), "{id}");
        }
    }

    /// STACK-8・#4630: flag ＞ TOML ＞ ディレクトリ名の優先順を具体値で照合する。
    #[test]
    fn stack8_4630_project_name_priority() {
        let dir = std::path::Path::new("/work/dir-x");
        let n = resolve_project_name(Some("cli-x"), Some("toml-x"), dir).expect("flag");
        assert_eq!(n.as_str(), "cli-x");
        let n = resolve_project_name(None, Some("toml-x"), dir).expect("toml");
        assert_eq!(n.as_str(), "toml-x");
        let n = resolve_project_name(None, None, dir).expect("dir");
        assert_eq!(n.as_str(), "dir-x");
    }

    /// STACK-8・#4630: 不正な値は正規化せず拒否し、上位の段が不正でも下位へ落とさない。
    #[test]
    fn stack8_4630_project_name_invalid_is_rejected_without_fallback() {
        let dir = std::path::Path::new("/work/My App");
        assert_eq!(
            resolve_project_name(None, None, dir),
            Err(IdentityError::InvalidProject)
        );
        let ok_dir = std::path::Path::new("/work/dir-x");
        assert_eq!(
            resolve_project_name(Some("Bad Name"), Some("toml-x"), ok_dir),
            Err(IdentityError::InvalidProject)
        );
        assert_eq!(
            resolve_project_name(None, Some("a.b"), ok_dir),
            Err(IdentityError::InvalidProject)
        );
        assert_eq!(
            resolve_project_name(None, None, std::path::Path::new("/")),
            Err(IdentityError::InvalidProject)
        );
    }
}
