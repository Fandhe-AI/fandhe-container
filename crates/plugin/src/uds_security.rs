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
//! - 既存 socket パス（TASK-123.2・#287）: `UdsListener::bind` が bind 前に検証済みディレクトリ fd 基準で
//!   lstat（symlink 非追従）する。symlink と他 UID 所有のエントリは削除せず `PermissionDenied`。
//!   自 UID 所有でも socket 以外、または接続が成功／判定不能（期限超過等）の socket は削除せず
//!   `AlreadyExists`。自 UID 所有で接続が拒否される stale socket だけを、再 lstat で同一性
//!   （dev / ino / uid / 種別）を確認したうえで `unlinkat` し、再 bind を可能にする。
//!   生存確認の probe は接続して即切断するだけでデータを送らない（相手の accept には一瞬届く。同一 UID）。
//!   残余: 再確認から unlink までの窓で差し替えられるのは 0700 ディレクトリ内の同一 UID のみ
//!   （脅威モデル外）。macOS は lstat がパス縮退のため窓がやや広い。
//!
//! # 未実装（REPAIR-3）
//! - `XDG_RUNTIME_DIR` 未設定時のフォールバック・root 時の既定配置先は未実装で、未設定は
//!   `FailedPrecondition`（TASK-123.4・#289）。
//! - socket 0600 化と `sun_path` 長検証（TASK-123.3・#288）、peer credential（TASK-124）は別 sub。
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
    /// テストおよび #289 のフォールバックが基底を注入する入口。基底は絶対パス・`..` なしで自 UID 所有・
    /// group/other 書き込み不可の非 symlink ディレクトリ（違反は `PermissionDenied`）で、
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
pub(crate) use imp::clear_stale_socket;

#[cfg(unix)]
mod imp {
    use super::{RUNTIME_DIR_NAME, RuntimeDir, runtime_dir_base, validate_base};
    use crate::error::{PluginError, PluginErrorCode};
    use std::fs::{DirBuilder, File, Metadata};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::{Path, PathBuf};

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

    /// stale 判定の probe（接続試行）の期限（REPAIR-5）。
    const STALE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

    /// 既存エントリの分類結果（PLUG-12・TASK-123.2）。
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum ExistingEntry {
        Absent,
        Symlink,
        ForeignOwner,
        NotSocket,
        OwnSocket(crate::sys::FileIdent),
    }

    /// lstat 結果と自 UID から分類する純粋関数（判定順: symlink → 所有者 → 種別）。
    pub(super) fn classify_existing(
        ident: Option<&crate::sys::FileIdent>,
        euid: u32,
    ) -> ExistingEntry {
        match ident {
            None => ExistingEntry::Absent,
            Some(i) if i.is_symlink => ExistingEntry::Symlink,
            Some(i) if i.uid != euid => ExistingEntry::ForeignOwner,
            Some(i) if !i.is_socket => ExistingEntry::NotSocket,
            Some(i) => ExistingEntry::OwnSocket(*i),
        }
    }

    fn err(code: PluginErrorCode, msg: &'static str) -> PluginError {
        PluginError::new(code, msg)
    }

    fn lstat_opt(
        dir: &File,
        name: &std::ffi::CStr,
        public: &Path,
    ) -> Result<Option<crate::sys::FileIdent>, PluginError> {
        match crate::sys::lstat_at(dir, name, public) {
            Ok(i) => Ok(Some(i)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(err(
                PluginErrorCode::PermissionDenied,
                "permission denied while inspecting existing socket path",
            )),
            Err(_) => Err(err(
                PluginErrorCode::Internal,
                "failed to inspect existing socket path",
            )),
        }
    }

    /// bind 前に既存エントリを検証し、自 UID 所有の stale socket のみ削除する（PLUG-12・TASK-123.2）。
    ///
    /// `UdsListener::bind` から、配置ディレクトリ検証後・`UnixListener::bind` の前に呼ばれる。
    /// `public` は公開パス（macOS の lstat 縮退用）、`probe` は生存確認の接続先。削除は
    /// 検証済み `dir` fd 基準の `unlinkat` のみ。判定不能は削除しない（fail-closed）。
    pub(crate) fn clear_stale_socket(
        dir: &File,
        name: &std::ffi::CStr,
        public: &Path,
        probe: &Path,
        euid: u32,
    ) -> Result<(), PluginError> {
        let first = match classify_existing(lstat_opt(dir, name, public)?.as_ref(), euid) {
            ExistingEntry::Absent => return Ok(()),
            ExistingEntry::Symlink => {
                return Err(err(
                    PluginErrorCode::PermissionDenied,
                    "socket path is a symlink",
                ));
            }
            ExistingEntry::ForeignOwner => {
                return Err(err(
                    PluginErrorCode::PermissionDenied,
                    "socket path is owned by another user",
                ));
            }
            ExistingEntry::NotSocket => {
                return Err(err(
                    PluginErrorCode::AlreadyExists,
                    "socket path already exists",
                ));
            }
            ExistingEntry::OwnSocket(i) => i,
        };
        let busy = || err(PluginErrorCode::AlreadyExists, "socket path already exists");
        match crate::sys::connect_unix(probe, std::time::Instant::now() + STALE_PROBE_TIMEOUT) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
            // 接続成功（生存中。即 drop）・期限超過・未対応・その他は削除しない。
            _ => return Err(busy()),
        }
        // 削除直前に同一性を再確認する（probe 中の差し替えを検出）。
        match lstat_opt(dir, name, public)? {
            None => return Ok(()),
            Some(now) if now == first => {}
            Some(_) => return Err(busy()),
        }
        match crate::sys::unlinkat(dir, name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(err(
                PluginErrorCode::Internal,
                "failed to remove stale socket",
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn ident(uid: u32, is_socket: bool, is_symlink: bool) -> crate::sys::FileIdent {
            crate::sys::FileIdent {
                dev: 1,
                ino: 2,
                uid,
                is_socket,
                is_symlink,
            }
        }

        #[test]
        fn plug12_classify_existing_symlink_wins_over_owner() {
            let i = ident(7, false, true);
            assert_eq!(classify_existing(Some(&i), 7), ExistingEntry::Symlink);
            assert_eq!(classify_existing(Some(&i), 8), ExistingEntry::Symlink);
        }

        #[test]
        fn plug12_classify_existing_foreign_owner_for_file_and_socket() {
            for sock in [false, true] {
                let i = ident(7, sock, false);
                assert_eq!(
                    classify_existing(Some(&i), 7u32.wrapping_add(1)),
                    ExistingEntry::ForeignOwner
                );
            }
        }

        #[test]
        fn plug12_classify_existing_own_entries() {
            assert_eq!(classify_existing(None, 7), ExistingEntry::Absent);
            let f = ident(7, false, false);
            assert_eq!(classify_existing(Some(&f), 7), ExistingEntry::NotSocket);
            let s = ident(7, true, false);
            assert_eq!(classify_existing(Some(&s), 7), ExistingEntry::OwnSocket(s));
        }

        #[test]
        fn plug12_clear_stale_socket_rejects_foreign_uid_and_keeps_file() {
            let d = std::env::temp_dir().join(format!("fcst-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            let sock = d.join("s");
            let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let dir = File::open(&d).unwrap();
            let name = std::ffi::CString::new("s").unwrap();
            let euid = crate::sys::effective_uid();
            let e =
                clear_stale_socket(&dir, &name, &sock, &sock, euid.wrapping_add(1)).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert!(sock.exists());
            // 存在しない名前は Ok。
            let none = std::ffi::CString::new("nope").unwrap();
            assert_eq!(
                clear_stale_socket(&dir, &none, &d.join("nope"), &d.join("nope"), euid),
                Ok(())
            );
            drop(_l);
            std::fs::remove_dir_all(&d).ok();
        }

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
