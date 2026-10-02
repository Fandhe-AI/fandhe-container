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
//! - 基底ディレクトリも同様に検証する。自 UID 所有の非 symlink ディレクトリで group / other に
//!   書き込み権が無い（`mode & 0o022 == 0`）ことを要求し、満たさなければ `PermissionDenied`。
//!   基底は末尾 `/` を除いた正規化パスで lstat し（末尾 `/` による symlink 追従を防ぐ）、
//!   symlink なら拒否する。さらに基底を `canonicalize` した実パスの全祖先を検証する。祖先は
//!   実ディレクトリで、所有者が root または自 UID、group / other 書き込み不可（または sticky）で
//!   なければならず、満たさなければ `PermissionDenied`。
//! - 祖先・基底・runtime directory の判定は、実パスをルートから 1 要素ずつ
//!   `openat(O_NOFOLLOW | O_DIRECTORY)` で辿って開いた fd（`crate::sys::open_dir_nofollow`。
//!   `UdsListener::bind` の配置ディレクトリ検証と同じ仕組み）の `fstat` 結果で行う。経路上の要素が
//!   symlink（`canonicalize` 後の差し替えを含む）なら open が失敗し、パスの再解決で検証対象と
//!   別の場所を見ることはない（fail-closed）。基底は lstat した実体と fd の dev / ino の一致も確認する。
//! - 残余: 作成（`mkdir`）だけはパス指定で行う。検証済みの祖先を書き換えられるのは root と自 UID
//!   のみで、その場合も作成後に fd で開き直して検証するため、未検証の場所を返すことはない。
//!   返した後の保護は `UdsListener::bind` が bind 時に配置ディレクトリを fd で再検証して担う。
//! - 作成は非再帰で、基底ディレクトリ（`XDG_RUNTIME_DIR` 自体）は作らない。
//! - エラーメッセージは固定の英語文字列で、パス・環境変数値を含めない。
//! - socket の 0600 化は [`crate::UdsListener::bind`] が検証済みディレクトリ fd 基準の
//!   `fchmodat(AT_SYMLINK_NOFOLLOW)` で行う（TASK-123.3・#288）。パス指定の chmod は、bind 後の
//!   パス・祖先の差し替えで別ファイルの mode を変えうるため使わない（`docs/design/io-protocol.md`）。
//!   親が 0700 かつ自 UID 所有のため、bind から 0600 化までの mode 差は他 UID から到達できない。
//! - [`RuntimeDir::socket_path`] が socket 名の検証と `sun_path` 長検証を bind 前に行う（#288）。
//!
//! # `XDG_RUNTIME_DIR` 未設定時のフォールバック（TASK-123.4・#289）
//! 未設定または空のときだけ、OS・euid ごとに単一の基底を選び、通常経路と同じ検証
//! （[`RuntimeDir::ensure_under`] 相当）を省略なく適用する。
//!
//! | 条件 | 基底 |
//! | ---- | ---- |
//! | Linux・euid 0 | `/run`（OCI-5 の root 配置と同じツリー） |
//! | Linux・euid != 0 | `/run/user/<euid>` |
//! | macOS | 環境変数 `TMPDIR`（ユーザー固有の 0700 ディレクトリ） |
//! | 上記以外の unix | なし（`FailedPrecondition`） |
//!
//! - 共有書き込み可能な `/tmp` へは落とさない。基底は作らず、無ければ `FailedPrecondition`。
//! - 候補は単一で、検証失敗（`PermissionDenied` 等）時に別候補へ連鎖しない（改ざんを隠さない）。
//! - 設定済みだが不正な値（相対パス・`..`）はフォールバックせずエラーにする。
//! - OCI-5 の state store は別仕様で、未設定時にフォールバックしない（`crates/core`）。
//!
//! # 未実装（REPAIR-3）
//! - 既存 socket パスの lstat 検証・stale socket 削除（TASK-123.2・#287）、
//!   peer credential（TASK-124）は別 sub。
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
    /// 未設定・空のときは OS・euid ごとのフォールバック基底を使う（モジュール doc 参照。TASK-123.4・#289）。
    /// 設定済みの相対パスは `FailedPrecondition`、`..` 含みは `InvalidArgument`。
    pub fn from_env() -> Result<Self, PluginError> {
        imp::from_env()
    }

    /// 指定の基底ディレクトリ直下の `fandhe-container` を解決・作成する。
    ///
    /// テストおよびフォールバック（#289）が基底を注入する入口。基底は絶対パス・`..` なしで自 UID 所有・
    /// group/other 書き込み不可の非 symlink ディレクトリ（違反は `PermissionDenied`）で、
    /// 既に存在していなければならない（`NotFound`。基底は作成しない）。
    pub fn ensure_under(base: &Path) -> Result<Self, PluginError> {
        imp::ensure_under(base)
    }

    /// 検証済み runtime directory 直下の socket パスを、bind 前に検証して返す（PLUG-12・TASK-123.3・#288）。
    ///
    /// TASK-109（plugin 発見）・TASK-114（core 側 proxy）が [`crate::UdsListener::bind`] へ渡す前に使い、
    /// 不正な名前と `sun_path` 超過を socket を作る前に検出する。`name` は単一の通常コンポーネント
    /// （空・`.`・`..`・区切り・NUL を含まない）でなければ `InvalidArgument`。結合後のパスが
    /// `sun_path` に収まらなければ `InvalidArgument`（"socket path is too long"）。
    ///
    /// 本メソッドは早期検出であり、`UdsListener::bind` は同じ長さ検証（Linux では bind に使う
    /// `/proc/self/fd/<fd>/<名前>` 側の長さも）を再度行う。0600 化も bind 側が fd 基準で担う。
    pub fn socket_path(&self, name: &str) -> Result<PathBuf, PluginError> {
        imp::socket_path(self, name)
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
    use std::fs::{DirBuilder, File, Metadata};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::{Path, PathBuf};

    /// Linux のフォールバック基底の根（root は直下、非 root は `user/<euid>`）。
    const RUN_ROOT: &str = "/run";

    const NO_FALLBACK: &str =
        "XDG_RUNTIME_DIR is not set and no fallback runtime directory is available";

    pub(super) fn from_env() -> Result<RuntimeDir, PluginError> {
        resolve(
            std::env::var_os("XDG_RUNTIME_DIR"),
            std::env::var_os("TMPDIR"),
            crate::sys::effective_uid(),
            Path::new(RUN_ROOT),
        )
    }

    /// `XDG_RUNTIME_DIR` 未設定・空のときの単一フォールバック基底（PLUG-12・TASK-123.4）。
    /// 基底の存在・所有者・権限の検証は呼び出し元の `ensure_dir` が行う。
    #[allow(unused_variables)] // OS ごとに使う引数が異なる
    fn fallback_base(
        euid: u32,
        run_root: &Path,
        tmpdir: Option<std::ffi::OsString>,
    ) -> Result<PathBuf, PluginError> {
        #[cfg(target_os = "linux")]
        {
            if euid == 0 {
                Ok(run_root.to_path_buf())
            } else {
                Ok(run_root.join("user").join(euid.to_string()))
            }
        }
        #[cfg(target_os = "macos")]
        {
            match tmpdir {
                Some(v) if !v.is_empty() => {
                    let base = PathBuf::from(v);
                    validate_base(&base)?;
                    Ok(base)
                }
                _ => Err(PluginError::new(
                    PluginErrorCode::FailedPrecondition,
                    NO_FALLBACK,
                )),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                NO_FALLBACK,
            ))
        }
    }

    /// 環境値を注入できる解決本体。`from_env` とテストが呼ぶ。
    pub(super) fn resolve(
        xdg: Option<std::ffi::OsString>,
        tmpdir: Option<std::ffi::OsString>,
        euid: u32,
        run_root: &Path,
    ) -> Result<RuntimeDir, PluginError> {
        if matches!(&xdg, Some(v) if !v.is_empty()) {
            let base = runtime_dir_base(xdg)?;
            return ensure_dir(&base, euid);
        }
        let base = fallback_base(euid, run_root, tmpdir)?;
        // フォールバック基底が無い場合のみ前提条件違反へ写像する。検証失敗は格下げしない。
        ensure_dir(&base, euid).map_err(|e| {
            if e.code() == PluginErrorCode::NotFound {
                PluginError::new(PluginErrorCode::FailedPrecondition, NO_FALLBACK)
            } else {
                e
            }
        })
    }

    pub(super) fn ensure_under(base: &Path) -> Result<RuntimeDir, PluginError> {
        ensure_dir(base, crate::sys::effective_uid())
    }

    pub(super) fn socket_path(dir: &RuntimeDir, name: &str) -> Result<PathBuf, PluginError> {
        validate_socket_name(name)?;
        let path = dir.path().join(name);
        crate::transport::check_sun_path_len(&path)?;
        Ok(path)
    }

    /// socket 名が単一の通常コンポーネントであることを確認する純粋関数（トラバーサル防止）。
    /// `Path::components()` は末尾 `/` や中間の `.` を正規化するため、元の文字列との一致で拒否する。
    pub(super) fn validate_socket_name(name: &str) -> Result<(), PluginError> {
        let mut comps = Path::new(name).components();
        let ok = !name.contains('\0')
            && matches!(
                (comps.next(), comps.next()),
                (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(name)
            );
        if ok {
            Ok(())
        } else {
            Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "socket name must be a single path component",
            ))
        }
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

    /// runtime directory を `O_NOFOLLOW` で開いた fd の Metadata を検証する（PLUG-12）。
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

    /// 基底ディレクトリの検証（lstat または `O_NOFOLLOW` で開いた fd の Metadata）。自 UID 所有の実ディレクトリで、group / other に
    /// 書き込み権が無いこと（`mode & 0o022 == 0`）を要求する。`/run/user/<uid>`（0700）は通り、
    /// 共有書き込み可能な `/tmp` 等（sticky でも）は拒否する。祖先は [`verify_ancestor`] で別途検証する。
    fn verify_base(meta: &Metadata, euid: u32) -> Result<(), PluginError> {
        let deny = |m: &str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(deny("runtime directory base is not a plain directory"));
        }
        if meta.uid() != euid {
            return Err(deny(
                "runtime directory base is not owned by the current user",
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(deny(
                "runtime directory base must not be writable by group or other",
            ));
        }
        Ok(())
    }

    /// 基底の祖先ディレクトリの検証（実パス上の各要素を `O_NOFOLLOW` で開いた fd の Metadata。
    /// PLUG-12）。実ディレクトリで、所有者が
    /// root または自 UID、かつ group / other に書き込み権が無い（sticky bit 付きは許容。`/tmp` 等）こと。
    fn verify_ancestor(meta: &Metadata, euid: u32) -> Result<(), PluginError> {
        let deny = |m: &str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(deny("runtime directory ancestor is not a plain directory"));
        }
        if meta.uid() != 0 && meta.uid() != euid {
            return Err(deny("runtime directory ancestor has an untrusted owner"));
        }
        if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return Err(deny(
                "runtime directory ancestor must not be writable by group or other",
            ));
        }
        Ok(())
    }

    /// 実パス `abs` をルートから 1 要素ずつ symlink 非追従で開く（[`crate::sys::open_dir_nofollow`]）。
    /// 経路上の要素が symlink・非ディレクトリ・読み取り不可なら `PermissionDenied`、
    /// 未対応の OS・アーキテクチャは `Unimplemented`（いずれも fail-closed）。
    fn open_nofollow(abs: &Path) -> Result<File, PluginError> {
        crate::sys::open_dir_nofollow(abs).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => map_io(&e),
            io::ErrorKind::Unsupported => PluginError::new(
                PluginErrorCode::Unimplemented,
                "runtime directory is not implemented on this platform",
            ),
            _ => PluginError::new(
                PluginErrorCode::PermissionDenied,
                "runtime directory path could not be opened without following symlinks",
            ),
        })
    }

    fn fstat(dir: &File) -> Result<Metadata, PluginError> {
        dir.metadata().map_err(|e| map_io(&e))
    }

    /// 基底と全祖先を検証し、基底の実パス（canonical）を返す（PLUG-12）。
    ///
    /// 検証は実パスの各要素を symlink 非追従で開いた fd に対して行う。`canonicalize` 後に経路上の
    /// 要素が symlink へ差し替えられた場合は open が失敗する。
    fn resolve_base(base: &Path, euid: u32) -> Result<PathBuf, PluginError> {
        // 末尾 `/` は lstat が最終要素の symlink を辿る原因になるため、components で正規化して除く。
        let normalized: PathBuf = base.components().collect();
        let link_meta = std::fs::symlink_metadata(&normalized).map_err(|e| map_io(&e))?;
        verify_base(&link_meta, euid)?;
        // 基底が実ディレクトリと確定した後の canonicalize は祖先 symlink のみを解決する。
        let real = std::fs::canonicalize(&normalized).map_err(|e| map_io(&e))?;
        // ancestors() は自身を最初に、ルートを最後に返す。自身を除いた各祖先を fd で検証する。
        for ancestor in real.ancestors().skip(1) {
            verify_ancestor(&fstat(&open_nofollow(ancestor)?)?, euid)?;
        }
        let meta = fstat(&open_nofollow(&real)?)?;
        // 開いた fd が lstat した実体と同一であること（検査と open の間の差し替え検出）。
        if meta.dev() != link_meta.dev() || meta.ino() != link_meta.ino() {
            return Err(PluginError::new(
                PluginErrorCode::PermissionDenied,
                "runtime directory base changed during verification",
            ));
        }
        verify_base(&meta, euid)?;
        Ok(real)
    }

    /// `base/fandhe-container` を解決し、無ければ 0700 で作成して検証する。
    pub(super) fn ensure_dir(base: &Path, euid: u32) -> Result<RuntimeDir, PluginError> {
        validate_base(base)?;
        // 基底自体と全祖先を先に検証する。他ユーザーが書ける・symlink の基底や祖先では、
        // 検証済みの子を後から rename・差し替えられ配置パスの安全性が失われるため（PLUG-12）。
        let real_base = resolve_base(base, euid)?;
        let dir = real_base.join(RUNTIME_DIR_NAME);
        match std::fs::symlink_metadata(&dir) {
            // 既存の symlink・非ディレクトリは open を試みる前に拒否する（修復・削除はしない）。
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(PluginError::new(
                    PluginErrorCode::PermissionDenied,
                    "runtime directory is not a plain directory",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // 非再帰。競合作成（AlreadyExists）は下の fd 検証で判定する。
                match DirBuilder::new().mode(0o700).create(&dir) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(map_io(&e)),
                }
            }
            Err(e) => return Err(map_io(&e)),
        }
        // ルートから symlink 非追従で開き直し、開いた fd 自体を検証する。lstat・作成との間に
        // 経路上の要素や runtime directory が symlink へ差し替えられていれば open が失敗する。
        verify(&fstat(&open_nofollow(&dir)?)?, euid)?;
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

        /// PLUG-12: 基底が他ユーザー書き込み可・他 UID 所有・symlink なら拒否する。
        #[test]
        fn plug12_rejects_untrusted_base() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            for mode in [0o770u32, 0o707, 0o777] {
                std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(mode)).unwrap();
                let err = ensure_dir(&t.0, euid).unwrap_err();
                assert_eq!(
                    err.code(),
                    PluginErrorCode::PermissionDenied,
                    "mode {mode:o}"
                );
                assert!(!t.0.join(RUNTIME_DIR_NAME).exists());
            }
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();
            let err = ensure_dir(&t.0, euid.wrapping_add(1)).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&t.0, &link).unwrap();
            let err = ensure_dir(&link, euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        }

        /// PLUG-12: 末尾 `/` 付きの symlink 基底も拒否する（lstat が symlink を辿らない）。
        #[test]
        fn plug12_rejects_symlink_base_with_trailing_slash() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let target = t.0.join("real");
            DirBuilder::new().mode(0o700).create(&target).unwrap();
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let mut with_slash = link.into_os_string();
            with_slash.push("/");
            let err = ensure_dir(Path::new(&with_slash), euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!target.join(RUNTIME_DIR_NAME).exists());
        }

        /// PLUG-12: 祖先が group / other 書き込み可（非 sticky）なら、基底が安全でも拒否する。
        #[test]
        fn plug12_rejects_writable_ancestor() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let mid = t.0.join("mid");
            let base = mid.join("base");
            DirBuilder::new().mode(0o700).create(&mid).unwrap();
            DirBuilder::new().mode(0o700).create(&base).unwrap();
            std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o777)).unwrap();
            let err = ensure_dir(&base, euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!base.join(RUNTIME_DIR_NAME).exists());
            std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(ensure_dir(&base, euid).is_ok());
        }

        /// PLUG-12: 基底の祖先（最終要素以外）の symlink は実パスへ解決し、返すパスは実パス側になる
        /// （以降の検証・open は実パスを symlink 非追従で辿る）。
        #[test]
        fn plug12_resolves_ancestor_symlink_to_real_path() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let real_mid = t.0.join("mid");
            let real_base = real_mid.join("base");
            DirBuilder::new().mode(0o700).create(&real_mid).unwrap();
            DirBuilder::new().mode(0o700).create(&real_base).unwrap();
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&real_mid, &link).unwrap();
            let got = ensure_dir(&link.join("base"), euid).unwrap();
            let expected = std::fs::canonicalize(&real_base)
                .unwrap()
                .join(RUNTIME_DIR_NAME);
            assert_eq!(got.path(), expected.as_path());
            let mode = std::fs::symlink_metadata(&expected).unwrap().mode();
            assert_eq!(mode & 0o7777, 0o700);
        }

        /// PLUG-12: 祖先の所有者が root・自 UID 以外なら拒否する（別 UID を用意せず分岐を照合する）。
        #[test]
        fn plug12_verify_ancestor_rejects_untrusted_owner_and_accepts_sticky() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let meta = std::fs::symlink_metadata(&t.0).unwrap();
            assert!(verify_ancestor(&meta, euid).is_ok());
            if euid != 0 {
                let err = verify_ancestor(&meta, euid.wrapping_add(1)).unwrap_err();
                assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
                assert_eq!(
                    err.message(),
                    "runtime directory ancestor has an untrusted owner"
                );
            }
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o1777)).unwrap();
            let sticky = std::fs::symlink_metadata(&t.0).unwrap();
            assert!(verify_ancestor(&sticky, euid).is_ok());
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn osv(s: &str) -> Option<std::ffi::OsString> {
            Some(s.into())
        }

        /// 試験用の「フォールバック基底」を Tmp 内に用意する。Linux は euid に応じ
        /// `run_root`（root）または `run_root/user/<euid>` を返し、macOS は TMPDIR 値として Tmp を使う。
        fn fallback_fixture(t: &Tmp, euid: u32) -> (PathBuf, Option<std::ffi::OsString>) {
            if cfg!(target_os = "linux") {
                if euid == 0 {
                    (t.0.clone(), None)
                } else {
                    let b = t.0.join("user").join(euid.to_string());
                    DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(&b)
                        .unwrap();
                    (b, None)
                }
            } else {
                (t.0.clone(), Some(t.0.clone().into_os_string()))
            }
        }

        /// PLUG-12・TASK-123.4: Linux のフォールバック基底は euid で決まる（具体値）。
        #[cfg(target_os = "linux")]
        #[test]
        fn plug12_fallback_base_linux() {
            let root = Path::new("/run");
            assert_eq!(fallback_base(0, root, None).unwrap(), PathBuf::from("/run"));
            assert_eq!(
                fallback_base(1000, root, None).unwrap(),
                PathBuf::from("/run/user/1000")
            );
        }

        /// PLUG-12・TASK-123.4: macOS は TMPDIR のみ。未設定・空・相対は FailedPrecondition。
        #[cfg(target_os = "macos")]
        #[test]
        fn plug12_fallback_base_macos() {
            let root = Path::new("/run");
            assert_eq!(
                fallback_base(501, root, osv("/var/folders/x/T")).unwrap(),
                PathBuf::from("/var/folders/x/T")
            );
            for v in [None, osv(""), osv("relative")] {
                let err = fallback_base(501, root, v).unwrap_err();
                assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
            }
            let err = fallback_base(501, root, osv("/a/../b")).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        }

        /// PLUG-12・TASK-123.4: XDG 未設定・空でフォールバック基底直下に 0700・自 UID で作成する。
        #[test]
        fn plug12_resolve_falls_back_when_xdg_unset_or_empty() {
            let euid = crate::sys::effective_uid();
            for xdg in [None, osv("")] {
                let t = Tmp::new();
                let (base, tmpdir) = fallback_fixture(&t, euid);
                let got = resolve(xdg, tmpdir, euid, &t.0).unwrap();
                let expected = std::fs::canonicalize(&base).unwrap().join(RUNTIME_DIR_NAME);
                assert_eq!(got.path(), expected.as_path());
                let meta = std::fs::symlink_metadata(&expected).unwrap();
                assert_eq!(meta.mode() & 0o7777, 0o700);
                assert_eq!(meta.uid(), euid);
            }
        }

        /// PLUG-12・TASK-123.4: フォールバック基底が無ければ FailedPrecondition で、基底は作らない。
        #[test]
        fn plug12_resolve_fallback_missing_base_is_failed_precondition() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let missing = t.0.join("missing");
            let tmpdir = Some(missing.clone().into_os_string());
            // root の Linux は run_root 自体、非 root は run_root/user/<euid>、macOS は TMPDIR が無い状況。
            let err = resolve(None, tmpdir, euid, &missing).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
            assert!(!missing.exists());
        }

        /// PLUG-12・TASK-123.4: フォールバック先にも通常経路と同じ検証が適用され、修復されない。
        #[test]
        fn plug12_resolve_fallback_applies_verification() {
            let euid = crate::sys::effective_uid();
            let t = Tmp::new();
            let (base, tmpdir) = fallback_fixture(&t, euid);
            // 基底が group/other 書き込み可。
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
            let err = resolve(None, tmpdir.clone(), euid, &t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!base.join(RUNTIME_DIR_NAME).exists());
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
            // 既存 runtime directory が 0755。
            let dir = base.join(RUNTIME_DIR_NAME);
            DirBuilder::new().mode(0o755).create(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let err = resolve(None, tmpdir, euid, &t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }

        /// PLUG-12・TASK-123.4: 設定済みで不正な XDG はフォールバックで隠さない。
        #[test]
        fn plug12_resolve_does_not_fall_back_for_invalid_xdg() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let (base, tmpdir) = fallback_fixture(&t, euid);
            let err = resolve(osv("relative"), tmpdir, euid, &t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
            assert!(!base.join(RUNTIME_DIR_NAME).exists());
        }

        /// PLUG-12・TASK-123.4: XDG が有効ならフォールバック候補を使わない。
        #[test]
        fn plug12_resolve_prefers_xdg_when_set() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let (fb, tmpdir) = fallback_fixture(&t, euid);
            let xdg = t.0.join("xdg");
            DirBuilder::new().mode(0o700).create(&xdg).unwrap();
            let got = resolve(Some(xdg.clone().into_os_string()), tmpdir, euid, &t.0).unwrap();
            let expected = std::fs::canonicalize(&xdg).unwrap().join(RUNTIME_DIR_NAME);
            assert_eq!(got.path(), expected.as_path());
            assert!(!fb.join(RUNTIME_DIR_NAME).exists());
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

    pub(super) fn socket_path(
        _dir: &RuntimeDir,
        _name: &str,
    ) -> Result<std::path::PathBuf, PluginError> {
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
