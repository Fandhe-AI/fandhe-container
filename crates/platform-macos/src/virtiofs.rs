//! virtiofs 共有（`VZVirtioFileSystemDeviceConfiguration` 相当）の検証型（MAC-1・TASK-65.1）。
//!
//! ホストのディレクトリ・共有タグ・アクセス権を「壊れた値を表現できない」型にし、[`VirtiofsSharesSpec`] として
//! `config::VmConfigSpec` へ載せる。OS 非依存層（全 OS でビルドし 3 OS CI でテストする）で、
//! Virtualization.framework 呼び出し（`VZSingleDirectoryShare` への変換）は
//! `config::build_vz_configuration` が `sys` 経由で行う。不正値は panic ではなく [`ConfigError`] で返す。
//!
//! 呼び出し文脈: `config::build_vz_configuration` が共有ごとにデバイス構成を組み立てる。ゲスト内の mount
//! （TASK-65.3。タグが mount 引数になるため文字種を絞っている）と I/O 共有プロトコルへの接続（TASK-65.2）は
//! 別タスクで、本モジュールでは未実装（REPAIR-3）。キャッシュポリシーは VZ に設定項目がなく扱わない。
//!
//! 信頼前提: 共有ディレクトリの検証（symlink 非経由・実在ディレクトリ）から VM 起動までの間にパスが差し
//! 替えられる TOCTOU は検査できない。呼び出し側が実体パスを渡し、共有ディレクトリの祖先を他者が書き換えられ
//! ないことを前提とする（`config` のコンソールログと同じ流儀）。

use std::path::{Path, PathBuf};

use crate::config::{ConfigError, ConfigField, check_absolute_utf8};

/// virtiofs 共有の最大件数（無制限確保の防止。`MAX_BLOCK_DEVICES` に合わせる）。
pub const MAX_VIRTIOFS_SHARES: usize = 8;

/// 共有タグの最大バイト数（VZ は 36 バイト未満を要求する）。
pub const MAX_VIRTIOFS_TAG_BYTES: usize = 35;

/// 共有タグ。ゲストの mount 引数になるため ASCII 英数字と `.` `_` `-` に限る（fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtiofsTag(String);

impl VirtiofsTag {
    /// 空・35 バイト超・許可外文字を拒否して生成する。
    pub fn try_new(tag: &str) -> Result<Self, ConfigError> {
        if tag.is_empty() {
            return Err(ConfigError::VirtiofsTagEmpty);
        }
        if tag.len() > MAX_VIRTIOFS_TAG_BYTES {
            return Err(ConfigError::VirtiofsTagTooLong {
                len: tag.len(),
                max: MAX_VIRTIOFS_TAG_BYTES,
            });
        }
        if let Some(index) = tag
            .bytes()
            .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
        {
            return Err(ConfigError::VirtiofsTagInvalidChar { index });
        }
        Ok(Self(tag.to_string()))
    }

    /// タグ文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 共有するホストディレクトリ。実在し、パス要素に symlink を含まない正規化済みの絶対パスのみ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedDirectoryPath(PathBuf);

impl SharedDirectoryPath {
    /// 絶対・UTF-8・NUL なし・`.`/`..` なし・`/` 以外・実在ディレクトリ・symlink 非経由を検証する。
    ///
    /// ゲストへ公開されるホスト範囲を、呼び出し側が明示した実ディレクトリに限定するための検証（パス
    /// トラバーサル対策）。macOS の `/tmp`・`/var` のような祖先の symlink も拒否するため、呼び出し側が
    /// 実体パスへ正規化して渡す。
    ///
    /// 共有ディレクトリが VM 自身の起動入力（kernel・initrd・ディスクイメージ・コンソールログ）を含むか
    /// どうかは本型では検査しない。ReadWrite 共有にそれらを含めるとゲストが書き換え得るため、
    /// 除外は呼び出し側（構成の組み立て側）の責務とする（MAC-1・TASK-65.1。保護入力との照合は後続で追跡）。
    pub fn try_new(path: &Path) -> Result<Self, ConfigError> {
        const FIELD: ConfigField = ConfigField::SharedDirectory;
        check_absolute_utf8(FIELD, path)?;
        // check_absolute_utf8 で UTF-8 検証済みのため、`to_str` は常に Some。
        let has_dot_segment = path
            .to_str()
            .is_some_and(|s| s.split(['/', '\\']).any(|seg| seg == "." || seg == ".."));
        if has_dot_segment {
            return Err(ConfigError::SharedDirNotNormalized {
                path: path.to_path_buf(),
            });
        }
        if path.parent().is_none() {
            return Err(ConfigError::SharedDirIsRoot);
        }
        let meta = std::fs::metadata(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::PathNotFound {
                    field: FIELD,
                    path: path.to_path_buf(),
                }
            } else {
                ConfigError::PathIo {
                    field: FIELD,
                    kind: e.kind(),
                }
            }
        })?;
        if !meta.is_dir() {
            return Err(ConfigError::SharedDirNotDirectory {
                path: path.to_path_buf(),
            });
        }
        // 各接頭辞（ルートを除く）が symlink でないことを確認する。
        for prefix in path.ancestors() {
            if prefix.file_name().is_none() {
                continue;
            }
            let m = std::fs::symlink_metadata(prefix).map_err(|e| ConfigError::PathIo {
                field: FIELD,
                kind: e.kind(),
            })?;
            if m.file_type().is_symlink() {
                return Err(ConfigError::SharedDirSymlink {
                    path: prefix.to_path_buf(),
                });
            }
        }
        // 補強: 実体パスとの一致（Windows の `\\?\` 接頭辞は一致しないため unix のみ）。
        #[cfg(unix)]
        {
            match std::fs::canonicalize(path) {
                Ok(real) if real == path => {}
                // 大文字小文字非区別 FS（macOS 既定の APFS 等。IO-5）では綴りの大小だけが実体と異なり得る。
                // 各接頭辞の symlink 検査は通過済みのため、大小のみの差は symlink 経由ではないとして許容する。
                Ok(real)
                    if real.to_string_lossy().to_lowercase()
                        == path.to_string_lossy().to_lowercase() => {}
                Ok(_) => {
                    return Err(ConfigError::SharedDirSymlink {
                        path: path.to_path_buf(),
                    });
                }
                Err(e) => {
                    return Err(ConfigError::PathIo {
                        field: FIELD,
                        kind: e.kind(),
                    });
                }
            }
        }
        Ok(Self(path.to_path_buf()))
    }

    /// 検証済みのパス。
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// 共有のアクセス権。bool にせず、読み書きは明示指定のみ（最小権限）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShareAccess {
    /// 読み取り専用（既定）。
    #[default]
    ReadOnly,
    /// 読み書き。
    ReadWrite,
}

impl ShareAccess {
    /// VZ の `readOnly` 引数へ写す。
    pub fn is_read_only(self) -> bool {
        matches!(self, ShareAccess::ReadOnly)
    }
}

/// 1 つの virtiofs 共有（タグ・ホストディレクトリ・アクセス権）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtiofsShareSpec {
    /// 共有タグ。
    pub tag: VirtiofsTag,
    /// ホストのディレクトリ。
    pub host_dir: SharedDirectoryPath,
    /// アクセス権。
    pub access: ShareAccess,
}

impl VirtiofsShareSpec {
    /// 検証済みの 3 要素から生成する。
    pub fn new(tag: VirtiofsTag, host_dir: SharedDirectoryPath, access: ShareAccess) -> Self {
        Self {
            tag,
            host_dir,
            access,
        }
    }
}

/// virtiofs 共有の集合（既定は空）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VirtiofsSharesSpec {
    shares: Vec<VirtiofsShareSpec>,
}

impl VirtiofsSharesSpec {
    /// 件数上限とタグ重複（大文字小文字非区別）を検証して生成する。同一ディレクトリを別タグで共有するのは許可。
    pub fn try_new(shares: Vec<VirtiofsShareSpec>) -> Result<Self, ConfigError> {
        if shares.len() > MAX_VIRTIOFS_SHARES {
            return Err(ConfigError::TooManyVirtiofsShares {
                count: shares.len(),
                max: MAX_VIRTIOFS_SHARES,
            });
        }
        for (i, share) in shares.iter().enumerate() {
            if shares
                .iter()
                .skip(i + 1)
                .any(|o| o.tag.as_str().eq_ignore_ascii_case(share.tag.as_str()))
            {
                return Err(ConfigError::DuplicateVirtiofsTag {
                    tag: share.tag.as_str().to_string(),
                });
            }
        }
        Ok(Self { shares })
    }

    /// 共有群。
    pub fn shares(&self) -> &[VirtiofsShareSpec] {
        &self.shares
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト専用の一時ディレクトリ。macOS の `/var` は `/private/var` への symlink のため、作成直後に実体化する。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let raw = std::env::temp_dir().join(format!(
                "fandhe-macos-virtiofs-{tag}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&raw).expect("create temp dir");
            Self(std::fs::canonicalize(&raw).expect("canonicalize temp dir"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn code<T: std::fmt::Debug>(r: Result<T, ConfigError>) -> &'static str {
        r.expect_err("expected an error").code()
    }

    /// MAC-1・TASK-65.1: タグの境界値と文字種。
    #[test]
    fn tag_validation() {
        assert_eq!(code(VirtiofsTag::try_new("")), "config.virtiofs_tag_empty");
        let ok = "a".repeat(35);
        assert_eq!(VirtiofsTag::try_new(&ok).unwrap().as_str(), ok);
        let long = "a".repeat(36);
        assert_eq!(
            VirtiofsTag::try_new(&long),
            Err(ConfigError::VirtiofsTagTooLong { len: 36, max: 35 })
        );
        assert_eq!(
            VirtiofsTag::try_new("a b"),
            Err(ConfigError::VirtiofsTagInvalidChar { index: 1 })
        );
        assert_eq!(
            VirtiofsTag::try_new("ab;"),
            Err(ConfigError::VirtiofsTagInvalidChar { index: 2 })
        );
        assert_eq!(
            VirtiofsTag::try_new("é"),
            Err(ConfigError::VirtiofsTagInvalidChar { index: 0 })
        );
        assert_eq!(
            VirtiofsTag::try_new("a\nb"),
            Err(ConfigError::VirtiofsTagInvalidChar { index: 1 })
        );
        assert_eq!(
            VirtiofsTag::try_new("data-1.v_2").unwrap().as_str(),
            "data-1.v_2"
        );
    }

    /// MAC-1・TASK-65.1: 正常な実ディレクトリは受理される。
    #[test]
    fn accepts_real_directory() {
        let t = TempDir::new("ok");
        let p = SharedDirectoryPath::try_new(&t.0).unwrap();
        assert_eq!(p.as_path(), t.0.as_path());
    }

    /// MAC-1・TASK-65.1: 存在しない・ファイル・相対・`..`・ルートを拒否する。
    #[test]
    fn rejects_invalid_paths() {
        let t = TempDir::new("bad");
        let missing = t.0.join("missing");
        assert_eq!(
            SharedDirectoryPath::try_new(&missing),
            Err(ConfigError::PathNotFound {
                field: ConfigField::SharedDirectory,
                path: missing.clone()
            })
        );
        let file = t.0.join("f");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            code(SharedDirectoryPath::try_new(&file)),
            "config.shared_dir_not_directory"
        );
        assert_eq!(
            code(SharedDirectoryPath::try_new(Path::new("rel/dir"))),
            "config.path_not_absolute"
        );
        let dotdot = t.0.join("..").join(t.0.file_name().unwrap());
        assert_eq!(
            code(SharedDirectoryPath::try_new(&dotdot)),
            "config.shared_dir_not_normalized"
        );
        let root = t.0.ancestors().last().unwrap().to_path_buf();
        assert_eq!(
            code(SharedDirectoryPath::try_new(&root)),
            "config.shared_dir_is_root"
        );
    }

    /// MAC-1・TASK-65.1: 最終要素・途中要素の symlink を拒否する。
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_components() {
        let t = TempDir::new("link");
        let real = t.0.join("real");
        std::fs::create_dir_all(real.join("sub")).unwrap();
        let link = t.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            SharedDirectoryPath::try_new(&link),
            Err(ConfigError::SharedDirSymlink { path: link.clone() })
        );
        assert_eq!(
            SharedDirectoryPath::try_new(&link.join("sub")),
            Err(ConfigError::SharedDirSymlink { path: link })
        );
    }

    /// MAC-1・TASK-65.1: アクセス権の既定は読み取り専用。
    #[test]
    fn access_defaults_to_read_only() {
        assert_eq!(ShareAccess::default(), ShareAccess::ReadOnly);
        assert!(ShareAccess::ReadOnly.is_read_only());
        assert!(!ShareAccess::ReadWrite.is_read_only());
    }

    fn share(tag: &str, dir: &Path, access: ShareAccess) -> VirtiofsShareSpec {
        VirtiofsShareSpec::new(
            VirtiofsTag::try_new(tag).unwrap(),
            SharedDirectoryPath::try_new(dir).unwrap(),
            access,
        )
    }

    /// MAC-1・TASK-65.1: 集合の検証（重複タグ・件数上限・同一ディレクトリ別タグ・空）。
    #[test]
    fn shares_set_validation() {
        let t = TempDir::new("set");
        assert!(
            VirtiofsSharesSpec::try_new(vec![])
                .unwrap()
                .shares()
                .is_empty()
        );
        assert_eq!(
            VirtiofsSharesSpec::try_new(vec![
                share("Data", &t.0, ShareAccess::ReadOnly),
                share("data", &t.0, ShareAccess::ReadOnly),
            ]),
            Err(ConfigError::DuplicateVirtiofsTag {
                tag: "Data".to_string()
            })
        );
        let nine: Vec<_> = (0..9)
            .map(|i| share(&format!("t{i}"), &t.0, ShareAccess::ReadOnly))
            .collect();
        assert_eq!(
            VirtiofsSharesSpec::try_new(nine),
            Err(ConfigError::TooManyVirtiofsShares { count: 9, max: 8 })
        );
        let ok = VirtiofsSharesSpec::try_new(vec![
            share("a", &t.0, ShareAccess::ReadOnly),
            share("b", &t.0, ShareAccess::ReadWrite),
        ])
        .unwrap();
        assert_eq!(ok.shares().len(), 2);
    }
}
