//! UDS 配置ディレクトリ（runtime directory）の解決・作成・検証（PLUG-12・TASK-123.1・#286）。
//!
//! PLUG-12 は plugin との UDS を `$XDG_RUNTIME_DIR/fandhe-container/` 相当の、0700 かつ core 実行 UID
//! 所有のディレクトリ配下にのみ作ることを求める。本モジュールはその「解決・作成・検証」を担い、
//! 上位（TASK-109 の plugin 発見・TASK-114 の core 側 proxy）が socket の置き場所を得て
//! [`crate::UdsListener::bind`] へ渡す入口になる。
//!
//! # 契約
//! - 既存ディレクトリが自 UID 所有でない・symlink・ディレクトリでない・group / other にアクセス可能
//!   （`mode & 0o077 != 0`。`UdsListener::bind` の親ディレクトリ検証と同じ閾値）、または所有者の
//!   rwx が揃っていない（`mode & 0o700 != 0o700`。0500・000 等）場合は、使用せず
//!   `PermissionDenied` を返す。chmod・chown・削除での自動修復はしない（fail-closed）。
//! - 判定は `symlink_metadata`（symlink を辿らない）の結果で行う。
//! - 作成は非再帰で、基底ディレクトリ（`XDG_RUNTIME_DIR` 自体）は作らない。
//! - エラーメッセージは固定の英語文字列で、パス・環境変数値を含めない。
//!
//! # 未実装（REPAIR-3）
//! - `XDG_RUNTIME_DIR` 未設定時のフォールバック・root 時の既定配置先は未実装で、未設定は
//!   `FailedPrecondition`（TASK-123.4・#289）。
//! - 既存 socket パスの lstat 検証・stale socket 削除（TASK-123.2・#287）、socket 0600 化と
//!   `sun_path` 長検証（TASK-123.3・#288）、peer credential（TASK-124）は別 sub。
//! - 非 unix は `Unimplemented`（Windows は WIN-1 により WSL2 内の Linux 側機構に乗る）。

use std::path::{Component, Path, PathBuf};

use crate::error::{PluginError, PluginErrorCode};

/// runtime directory 名（`$XDG_RUNTIME_DIR` 直下。PLUG-12）。
pub const RUNTIME_DIR_NAME: &str = "fandhe-container";

/// 検証済みの UDS 配置ディレクトリ（PLUG-12）。生の `PathBuf` ではなく newtype で返し、
/// 検証を経ていないパスと型で区別する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDir {
    path: PathBuf,
}

impl RuntimeDir {
    /// 環境変数 `XDG_RUNTIME_DIR` と自プロセスの実効 uid から解決・作成する。
    ///
    /// 未設定・空・相対パスは `FailedPrecondition`（フォールバックは TASK-123.4・#289）。
    pub fn from_env() -> Result<Self, PluginError> {
        imp::from_env()
    }

    /// 指定の基底ディレクトリ直下の `fandhe-container` を解決・作成する。
    ///
    /// テストおよび #289 のフォールバックが基底を注入する入口。基底は絶対パス・`..` なしで、
    /// 既に存在していなければならない（`NotFound`。基底は作成しない）。
    pub fn ensure_under(base: &Path) -> Result<Self, PluginError> {
        imp::ensure_under(base)
    }

    /// 検証済みディレクトリのパス。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 基底パスの共通検証。絶対パスで `..` を含まないこと（外部入力の untrusted 検証）。
#[cfg_attr(not(unix), allow(dead_code))] // 非 unix では imp が Unimplemented を返し呼ばれない
fn validate_base(base: &Path) -> Result<(), PluginError> {
    if !base.is_absolute() {
        return Err(PluginError::new(
            PluginErrorCode::FailedPrecondition,
            "runtime directory base must be an absolute path",
        ));
    }
    if base.components().any(|c| c == Component::ParentDir) {
        return Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            "runtime directory base must not contain parent directory components",
        ));
    }
    Ok(())
}

/// `XDG_RUNTIME_DIR` の値から基底パスを得る純粋関数。未設定・空は `FailedPrecondition`。
#[cfg_attr(not(unix), allow(dead_code))] // 非 unix では imp が Unimplemented を返し呼ばれない
fn runtime_dir_base(xdg: Option<std::ffi::OsString>) -> Result<PathBuf, PluginError> {
    let value = match xdg {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                "XDG_RUNTIME_DIR is not set",
            ));
        }
    };
    let base = PathBuf::from(value);
    validate_base(&base)?;
    Ok(base)
}

#[cfg(unix)]
mod imp {
    use super::{RUNTIME_DIR_NAME, RuntimeDir, runtime_dir_base, validate_base};
    use crate::error::{PluginError, PluginErrorCode};
    use std::fs::{DirBuilder, Metadata};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::Path;

    pub(super) fn from_env() -> Result<RuntimeDir, PluginError> {
        let base = runtime_dir_base(std::env::var_os("XDG_RUNTIME_DIR"))?;
        ensure_dir(&base, crate::sys::effective_uid())
    }

    pub(super) fn ensure_under(base: &Path) -> Result<RuntimeDir, PluginError> {
        ensure_dir(base, crate::sys::effective_uid())
    }

    fn map_io(e: &io::Error) -> PluginError {
        match e.kind() {
            io::ErrorKind::NotFound => PluginError::new(
                PluginErrorCode::NotFound,
                "runtime directory base does not exist",
            ),
            io::ErrorKind::PermissionDenied => PluginError::new(
                PluginErrorCode::PermissionDenied,
                "permission denied while preparing runtime directory",
            ),
            _ => PluginError::new(
                PluginErrorCode::Internal,
                "failed to prepare runtime directory",
            ),
        }
    }

    /// `symlink_metadata` 由来の Metadata を検証する（symlink 非追従。PLUG-12）。
    fn verify(meta: &Metadata, euid: u32) -> Result<(), PluginError> {
        let deny = |m: &str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(deny("runtime directory is not a plain directory"));
        }
        if meta.uid() != euid {
            return Err(deny("runtime directory is not owned by the current user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(deny(
                "runtime directory must not be accessible by group or other",
            ));
        }
        // 所有者の rwx が揃っていない（0500・000・umask で 0700 より狭まった等）と後続の
        // UDS bind が失敗するため、0700 の契約どおり所有者 rwx も要求する。
        if meta.mode() & 0o700 != 0o700 {
            return Err(deny("runtime directory must be accessible by its owner"));
        }
        Ok(())
    }

    /// `base/fandhe-container` を解決し、無ければ 0700 で作成して検証する。
    pub(super) fn ensure_dir(base: &Path, euid: u32) -> Result<RuntimeDir, PluginError> {
        validate_base(base)?;
        let dir = base.join(RUNTIME_DIR_NAME);
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) => verify(&meta, euid)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // 非再帰。基底が無ければ NotFound。競合作成（AlreadyExists）は再 lstat で検証する。
                match DirBuilder::new().mode(0o700).create(&dir) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(map_io(&e)),
                }
                // 作成直後に再取得して検証する（差し替え・競合作成を検出）。
                let meta = std::fs::symlink_metadata(&dir).map_err(|e| map_io(&e))?;
                verify(&meta, euid)?;
            }
            Err(e) => return Err(map_io(&e)),
        }
        Ok(RuntimeDir { path: dir })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        struct Tmp(std::path::PathBuf);
        impl Tmp {
            fn new() -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "fcus-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                DirBuilder::new().mode(0o700).create(&p).unwrap();
                Self(p)
            }
        }
        impl Drop for Tmp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// PLUG-12: 所有者不一致は 0700 でも拒否する（別 UID を用意せず分岐を照合する）。
        #[test]
        fn plug12_rejects_owner_mismatch() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            ensure_dir(&t.0, euid).unwrap();
            let err = ensure_dir(&t.0, euid.wrapping_add(1)).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            let mode = std::fs::metadata(t.0.join(RUNTIME_DIR_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        /// PLUG-12: 所有者 rwx が欠けた既存ディレクトリ（0500・000）は拒否し、修復しない。
        #[test]
        fn plug12_rejects_existing_dir_without_owner_rwx() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = t.0.join(RUNTIME_DIR_NAME);
            for mode in [0o500u32, 0o000] {
                DirBuilder::new().mode(0o700).create(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
                let err = ensure_dir(&t.0, euid).unwrap_err();
                assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
                let got = std::fs::metadata(&dir).unwrap().permissions().mode();
                assert_eq!(got & 0o777, mode);
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::fs::remove_dir(&dir).unwrap();
            }
        }

        #[test]
        fn plug12_runtime_dir_base_accepts_absolute() {
            let p = runtime_dir_base(Some("/run/user/1000".into())).unwrap();
            assert_eq!(p, std::path::PathBuf::from("/run/user/1000"));
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::RuntimeDir;
    use crate::error::{PluginError, PluginErrorCode};
    use std::path::Path;

    fn unimplemented() -> PluginError {
        PluginError::new(
            PluginErrorCode::Unimplemented,
            "runtime directory is not implemented on this platform",
        )
    }

    pub(super) fn from_env() -> Result<RuntimeDir, PluginError> {
        Err(unimplemented())
    }

    pub(super) fn ensure_under(_base: &Path) -> Result<RuntimeDir, PluginError> {
        Err(unimplemented())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-12: 未設定・空・相対は FailedPrecondition（`/tmp` 等へ落とさない）。
    #[test]
    fn plug12_runtime_dir_base_rejects_unset_empty_relative() {
        for v in [None, Some("".into()), Some("relative/dir".into())] {
            let err = runtime_dir_base(v).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
        }
    }

    /// PLUG-12: `..` 要素は InvalidArgument。
    #[test]
    fn plug12_runtime_dir_base_rejects_parent_dir_component() {
        let abs = std::env::temp_dir().join("a").join("..").join("b");
        let err = runtime_dir_base(Some(abs.into_os_string())).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
    }
}
