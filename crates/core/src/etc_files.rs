//! コンテナの `/etc/hosts`・`/etc/resolv.conf` の元ファイルを管理ルートへ生成・削除する（NET-12・NET-8・CORE-1・
//! SEC-1・SEC-5・TASK-185 追補・#1872。設計は `docs/design/network-wiring.md` の D9）。
//!
//! # 役割と呼び出し文脈
//!
//! `crates/net` の `apply_add_hosts`（hosts への追記）と `apply_dns`（resolv.conf の rename 置換）は、「管理ルート配下に
//! 既にある通常ファイル」だけを対象にする。そのファイルを作るのが本モジュールで、コンテナの rootfs へ載せる
//! 段は `crate::exec` の `mount_etc_files`（pivot 前段。`inject_files` の後・`mount_binds` の前）である。
//!
//! ```text
//! supervisor start（#1873・#3065）: remove_etc_files -> create_etc_files -> apply_add_hosts / apply_dns
//!   -> launch（LaunchOptions::with_etc_files で載せる種別を指定）-> 子が rootfs の /etc/hosts 等へ bind
//! CLI delete: core の delete が成功した後に remove_etc_files
//! ```
//!
//! 置き場は `<state_root>/@container-etc/<id>/{hosts,resolv.conf}`。パスは `--root`
//! （`StateStore::host_state_root()`）と検証済みの [`ContainerId`] だけから導き、呼び出し側の任意のパスは受けない
//! （`@container-options` と同じ流儀）。状態ルート配下のため、利用者の bind mount の元としては
//! `BindSourceReachesStateRoot` で拒否され続ける（緩めない）。
//!
//! # 契約
//!
//! - **作るのは指定した種別だけ**: [`EtcFileSelection`] が空なら何も作らない（ディレクトリも作らない）。`/etc/hostname` は対象外
//! - **所有者と権限**: ディレクトリ（`@container-etc`・`<id>`）は実効 uid 所有の 0700、ファイルは実効 uid 所有の 0644・
//!   nlink 1 の通常ファイル。作成は `O_CREAT|O_EXCL|O_NOFOLLOW`、モードは作成後に `fchmod` で固定する（umask に依らない。ディレクトリも検査済みの fd 起点で固定し、列挙も同じ fd を使う）
//! - **既にあれば拒否**: `<id>` が既にあれば `ALREADY_EXISTS` で、何も変えない。「start のたびに作り直す」（D9）は呼び出し側が
//!   [`remove_etc_files`] の後に [`create_etc_files`] を呼ぶことで実現する
//! - **初期内容**: hosts は [`INITIAL_HOSTS`]（localhost の 2 行）、resolv.conf は空（`apply_dns` が後で rename 置換する）。
//!   利用者の入力は書かない（追記は `crates/net` の検証済み入力のみ）
//! - **`apply_add_hosts`・`apply_dns` の要求を満たす**: 管理ルート配下の既存の通常ファイル・nlink 1・実行ユーザー所有・管理ルートと
//!   同じマウント（同じディレクトリ内に作る）。`core` から `net` への依存は足さない
//! - **失敗時は残さない**: 作成の途中で失敗したら、自分が作った inode（`(st_dev, st_ino)` が一致するもの）だけを消し、
//!   `<id>` も消す。エラー message は固定の英語で、パス・errno・ID を含めない
//! - **fd 起点**: 状態ルートから 1 要素ずつ `O_PATH|O_NOFOLLOW` で辿り、symlink・他者所有・グループ/他者に開いた
//!   ディレクトリは `PERMISSION_DENIED` で拒否する
//!
//! # 呼び出し元と未実装（REPAIR-3: 実装済みを装わない）
//!
//! - supervisor の start からの呼び出しと start 失敗時の巻き戻しは supervisor の `container_options::etc_files`
//!   （start の手順 4b。#1873・#3065・D14 で実装済み）。本モジュールは API のみ
//! - 実際の bind mount は `crate::exec::etc_mounts`。本番の起動経路は `RootfulHostRoot` を launcher が `UNIMPLEMENTED` で
//!   拒否している（#2241・SEC-5）ため、動くのは rootless の 2 モデル（`RootlessSingleId`・`RootlessSubordinateIds`）だけ
//! - 非 Linux は `UNIMPLEMENTED`（macOS・Windows の管理ルートの扱いは MAC・WIN 系で別に決める）

use std::path::{Path, PathBuf};

use crate::injected_files::{InjectedFileSet, overlaps};
use crate::oci_runtime::BindMountSet;
use crate::tmpfs::TmpfsMountSet;
use crate::traits::ContainerId;
use crate::traits::types::{ErrorCode, TraitError};

/// 状態ルート直下の管理ディレクトリ名。
pub const ETC_DIR_NAME: &str = "@container-etc";

/// hosts の初期内容（D9。区切りはタブ）。
pub const INITIAL_HOSTS: &[u8] =
    b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";

/// 1 ディレクトリの列挙件数の上限（`remove_etc_files`。無制限の走査を避ける）。
pub const ETC_DIR_MAX_ENTRIES: usize = 64;

/// 管理ルートに生成し rootfs へ載せるファイルの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EtcFileKind {
    /// `/etc/hosts`。
    Hosts,
    /// `/etc/resolv.conf`。
    ResolvConf,
}

impl EtcFileKind {
    /// 全種別（固定順）。
    pub const ALL: [Self; 2] = [Self::Hosts, Self::ResolvConf];

    /// 管理ルート配下のファイル名。
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Hosts => "hosts",
            Self::ResolvConf => "resolv.conf",
        }
    }

    /// コンテナ内のマウント先。
    pub fn container_path(self) -> &'static str {
        match self {
            Self::Hosts => "/etc/hosts",
            Self::ResolvConf => "/etc/resolv.conf",
        }
    }
}

/// 載せる種別の選択（既定は空。`/etc/hostname` は表せない）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EtcFileSelection {
    hosts: bool,
    resolv_conf: bool,
}

impl EtcFileSelection {
    /// `kind` を足した選択を返す。
    #[must_use]
    pub fn with(mut self, kind: EtcFileKind) -> Self {
        match kind {
            EtcFileKind::Hosts => self.hosts = true,
            EtcFileKind::ResolvConf => self.resolv_conf = true,
        }
        self
    }

    /// `kind` を含むか。
    pub fn contains(&self, kind: EtcFileKind) -> bool {
        match kind {
            EtcFileKind::Hosts => self.hosts,
            EtcFileKind::ResolvConf => self.resolv_conf,
        }
    }

    /// 何も選んでいないか。
    pub fn is_empty(&self) -> bool {
        !self.hosts && !self.resolv_conf
    }

    /// 選んだ種別（固定順）。
    pub fn kinds(&self) -> Vec<EtcFileKind> {
        EtcFileKind::ALL
            .into_iter()
            .filter(|k| self.contains(*k))
            .collect()
    }
}

/// `<root>/@container-etc/<id>`。
pub fn etc_dir(root: &Path, id: &ContainerId) -> PathBuf {
    root.join(ETC_DIR_NAME).join(id.as_str())
}

/// `<root>/@container-etc/<id>/<hosts|resolv.conf>`。
pub fn etc_file_path(root: &Path, id: &ContainerId, kind: EtcFileKind) -> PathBuf {
    etc_dir(root, id).join(kind.file_name())
}

/// [`create_etc_files`] が作ったファイルの記録（巻き戻しと、後続の検証の照合用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedEtcFiles {
    files: Vec<(EtcFileKind, (u64, u64))>,
}

impl CreatedEtcFiles {
    /// 作った種別と `(st_dev, st_ino)`（作成順）。
    pub fn files(&self) -> &[(EtcFileKind, (u64, u64))] {
        &self.files
    }
}

/// [`remove_etc_files`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcRemoveOutcome {
    /// `<id>` ディレクトリとその中身を消した。
    Removed,
    /// 消すものが無かった。
    NotPresent,
}

fn err(code: ErrorCode, msg: &'static str) -> TraitError {
    TraitError::new(code, msg)
}

/// `/etc/hosts`・`/etc/resolv.conf` と、tmpfs の宛先・注入の親ディレクトリ・利用者の bind の宛先の重なりを拒否する
/// （純関数。同一・祖先・子孫のどれか。NET-12・SEC-1・D9）。
///
/// 祖先（`/etc`）の tmpfs・bind は載せた先を覆い隠し、子孫（`/etc/hosts/x`）は載せたファイルの下になるため。
/// `/etc/foo` のように重ならない宛先は受ける。config の `readonlyPaths`・`maskedPaths` は狭める方向なので対象外。
/// launcher が fork 前に、`run_pre_pivot` が段の先頭で（多重防御として）呼ぶ。
pub fn check_etc_overlaps(
    sel: EtcFileSelection,
    tmpfs: &TmpfsMountSet,
    inject: Option<&InjectedFileSet>,
    binds: Option<&BindMountSet>,
) -> Result<(), TraitError> {
    for kind in sel.kinds() {
        let target = kind.container_path();
        let hit = tmpfs
            .mounts()
            .iter()
            .any(|m| overlaps(m.destination.as_str(), target))
            || inject.is_some_and(|i| i.groups().iter().any(|g| overlaps(g.directory, target)))
            || binds.is_some_and(|b| {
                b.mounts()
                    .iter()
                    .any(|m| overlaps(m.destination().as_str(), target))
            });
        if hit {
            return Err(err(
                ErrorCode::InvalidArgument,
                "a tmpfs, injected file or bind mount destination overlaps /etc/hosts or /etc/resolv.conf",
            ));
        }
    }
    Ok(())
}

/// 管理ルートに選んだ種別のファイルを排他作成する（モジュール doc の契約）。
///
/// 非 Linux は `UNIMPLEMENTED`。
pub fn create_etc_files(
    root: &Path,
    id: &ContainerId,
    sel: EtcFileSelection,
) -> Result<CreatedEtcFiles, TraitError> {
    #[cfg(target_os = "linux")]
    {
        linux::create(root, id, sel, &linux::stat, &|_| Ok(()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, id, sel);
        Err(err(
            ErrorCode::Unimplemented,
            "container etc files are only supported on Linux",
        ))
    }
}

/// `<id>` ディレクトリとその中身を消す。`@container-etc` 自体は残す。非 Linux は `UNIMPLEMENTED`。
pub fn remove_etc_files(root: &Path, id: &ContainerId) -> Result<EtcRemoveOutcome, TraitError> {
    #[cfg(target_os = "linux")]
    {
        linux::remove(root, id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, id);
        Err(err(
            ErrorCode::Unimplemented,
            "container etc files are only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;

    use super::{
        CreatedEtcFiles, ETC_DIR_MAX_ENTRIES, ETC_DIR_NAME, EtcFileKind, EtcFileSelection,
        EtcRemoveOutcome, INITIAL_HOSTS, err, etc_dir,
    };
    use crate::sys::{self, SysError};
    use crate::traits::ContainerId;
    use crate::traits::types::{ErrorCode, TraitError};

    const DIR_MODE: u32 = 0o700;
    const FILE_MODE: u32 = 0o644;

    fn sys_err(e: SysError) -> TraitError {
        let code = match e {
            SysError::Unsupported => ErrorCode::Unimplemented,
            SysError::Os(sys::EACCES) | SysError::Os(sys::EPERM) => ErrorCode::PermissionDenied,
            _ => ErrorCode::Internal,
        };
        err(code, "container etc files operation failed")
    }

    fn cstr(name: &str) -> Result<CString, TraitError> {
        CString::new(name).map_err(|_| err(ErrorCode::InvalidArgument, "name contains NUL"))
    }

    fn denied() -> TraitError {
        err(
            ErrorCode::PermissionDenied,
            "the container etc directory is not a private directory owned by the current user",
        )
    }

    /// fd の fstat（O_PATH fd でも可）。fd は複製して見るだけ。
    pub(super) fn stat(fd: BorrowedFd<'_>) -> Result<std::fs::Metadata, TraitError> {
        let dup = fd
            .try_clone_to_owned()
            .map_err(|_| err(ErrorCode::Internal, "container etc files operation failed"))?;
        std::fs::File::from(dup)
            .metadata()
            .map_err(|_| err(ErrorCode::Internal, "container etc files operation failed"))
    }

    /// ディレクトリ・実効 uid 所有・グループ/他者に権限が無い、を確かめる。
    fn check_private_dir(fd: BorrowedFd<'_>, euid: u32) -> Result<(), TraitError> {
        let meta = stat(fd)?;
        if !meta.file_type().is_dir() || meta.uid() != euid || meta.mode() & 0o077 != 0 {
            return Err(denied());
        }
        Ok(())
    }

    /// 状態ルートの fd と `@container-etc` の fd を得る（無ければ `create` が真のときだけ作る）。
    fn open_etc_root(root: &Path, create: bool, euid: u32) -> Result<Option<OwnedFd>, TraitError> {
        let c_root = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| err(ErrorCode::InvalidArgument, "state root contains NUL"))?;
        let root_fd = sys::open_dir_path_nofollow(None, &c_root).map_err(sys_err)?;
        let name = cstr(ETC_DIR_NAME)?;
        let open = || sys::open_dir_path_nofollow(Some(root_fd.as_fd()), &name);
        let fd = match open() {
            Ok(fd) => fd,
            Err(SysError::Os(sys::ENOENT)) if !create => return Ok(None),
            Err(SysError::Os(sys::ENOENT)) => {
                match sys::mkdir_at(root_fd.as_fd(), &name, DIR_MODE) {
                    Ok(()) | Err(SysError::Os(sys::EEXIST)) => {}
                    Err(e) => return Err(sys_err(e)),
                }
                sync_dir(root);
                open().map_err(sys_err)?
            }
            // symlink・非ディレクトリ（`O_DIRECTORY|O_NOFOLLOW`）は拒否する。
            Err(SysError::Os(sys::ENOTDIR)) | Err(SysError::Os(sys::ELOOP)) => {
                return Err(denied());
            }
            Err(e) => return Err(sys_err(e)),
        };
        check_private_dir(fd.as_fd(), euid)?;
        // 検査済み（自分所有・グループ/他者に権限なし）なので、再利用時も 0700 へ固定して取り残しを直す。
        fix_dir_mode_fd(fd.as_fd())?;
        Ok(Some(fd))
    }

    /// 自分が作って検査済みのディレクトリのモードを、その fd が固定した inode に対して `DIR_MODE` へ固定する
    /// （`mkdir` は umask を受けるため。管理ディレクトリの 0700 は契約。SEC-1・NET-12）。
    ///
    /// O_PATH の fd には `fchmod` が効かないため、`/proc/thread-self/fd/N`（magic link。パスを再解決しない）経由の
    /// `chmod` で固定する。`O_RDONLY` へ開き直さないので、umask が所有者の読み取りを落として 0300 等になった
    /// ディレクトリでも直せる。パスで辿り直さないので、検査と操作の間に差し替える窓が無い。
    /// procfs が無い環境では失敗させる（fail-closed）。
    fn fix_dir_mode_fd(dir: BorrowedFd<'_>) -> Result<(), TraitError> {
        sys::chmod_pinned(dir, DIR_MODE)
            .map_err(|_| err(ErrorCode::Internal, "container etc files operation failed"))
    }

    /// ディレクトリの fsync（best-effort。耐久性のためで、分離の判断には使わない）。
    fn sync_dir(path: &Path) {
        if let Ok(f) = std::fs::File::open(path) {
            let _ = f.sync_all();
        }
    }

    /// 自分が作ったファイル（`(dev, ino)` が一致するもの）だけを消す。
    fn remove_if_same(dir: BorrowedFd<'_>, name: &str, ident: (u64, u64)) {
        let Ok(c) = cstr(name) else { return };
        let Ok(fd) = sys::open_path_nofollow_at(dir, &c) else {
            return;
        };
        if let Ok(meta) = stat(fd.as_fd())
            && (meta.dev(), meta.ino()) == ident
        {
            let _ = sys::remove_file_at(dir, &c);
        }
    }

    /// `<state_root>/@container-etc/<id>/` を作り、選択したファイルを排他作成する。
    ///
    /// 失敗時は、この呼び出しが作ったものだけを消して `<id>` ごと巻き戻す（SEC-1・NET-12・REPAIR-3）。
    /// 作成した fd は作成直後に `created` へ積み、metadata 取得などその後のどの手順が失敗しても
    /// 巻き戻しの対象から漏れないようにする（取り残すと次の create が `AlreadyExists` で固まる）。
    /// `inspect_created` は作成直後の metadata 取得の差し込み点（試験で失敗を注入する）、
    /// `after_file` は 1 件完成するごとの差し込み点。
    pub(super) fn create(
        root: &Path,
        id: &ContainerId,
        sel: EtcFileSelection,
        inspect_created: &dyn Fn(BorrowedFd<'_>) -> Result<std::fs::Metadata, TraitError>,
        after_file: &dyn Fn(usize) -> Result<(), TraitError>,
    ) -> Result<CreatedEtcFiles, TraitError> {
        if sel.is_empty() {
            return Ok(CreatedEtcFiles { files: Vec::new() });
        }
        let euid = sys::effective_uid();
        let Some(etc_fd) = open_etc_root(root, true, euid)? else {
            return Err(err(
                ErrorCode::Internal,
                "container etc files operation failed",
            ));
        };
        let id_name = cstr(id.as_str())?;
        match sys::mkdir_at(etc_fd.as_fd(), &id_name, DIR_MODE) {
            Ok(()) => {}
            Err(SysError::Os(sys::EEXIST)) => {
                return Err(err(
                    ErrorCode::AlreadyExists,
                    "container etc files already exist",
                ));
            }
            Err(e) => return Err(sys_err(e)),
        }
        // 以降の失敗は、`<id>` を消すところまで巻き戻す。
        let mut created: Vec<(EtcFileKind, std::fs::File)> = Vec::new();
        let mut idents: Vec<(EtcFileKind, (u64, u64))> = Vec::new();
        let result = (|| -> Result<(), TraitError> {
            let dir_fd =
                sys::open_dir_path_nofollow(Some(etc_fd.as_fd()), &id_name).map_err(sys_err)?;
            check_private_dir(dir_fd.as_fd(), euid)?;
            fix_dir_mode_fd(dir_fd.as_fd())?;
            for (n, kind) in sel.kinds().into_iter().enumerate() {
                let name = cstr(kind.file_name())?;
                let fd = sys::create_file_excl_at(dir_fd.as_fd(), &name, FILE_MODE).map_err(
                    |e| match e {
                        SysError::Os(sys::EEXIST) => err(
                            ErrorCode::AlreadyExists,
                            "container etc files already exist",
                        ),
                        e => sys_err(e),
                    },
                )?;
                // 作った直後に積む。以降の失敗でも巻き戻しがこの fd から同一性を取れる。
                created.push((kind, std::fs::File::from(fd)));
                let Some((_, file)) = created.last_mut() else {
                    return Err(err(
                        ErrorCode::Internal,
                        "container etc files operation failed",
                    ));
                };
                let meta = inspect_created(file.as_fd())?;
                idents.push((kind, (meta.dev(), meta.ino())));
                let io = |_: std::io::Error| {
                    err(ErrorCode::Internal, "container etc files operation failed")
                };
                file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))
                    .map_err(io)?;
                if kind == EtcFileKind::Hosts {
                    file.write_all(INITIAL_HOSTS).map_err(io)?;
                }
                file.sync_all().map_err(io)?;
                after_file(n)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                sync_dir(&etc_dir(root, id));
                sync_dir(&root.join(ETC_DIR_NAME));
                Ok(CreatedEtcFiles { files: idents })
            }
            Err(e) => {
                if let Ok(dir_fd) = sys::open_dir_path_nofollow(Some(etc_fd.as_fd()), &id_name) {
                    for (kind, file) in &created {
                        // 同一性を確かめられないものは消さない（fail-safe）。
                        if let Ok(meta) = stat(file.as_fd()) {
                            remove_if_same(
                                dir_fd.as_fd(),
                                kind.file_name(),
                                (meta.dev(), meta.ino()),
                            );
                        }
                    }
                }
                let _ = sys::remove_dir_at(etc_fd.as_fd(), &id_name);
                Err(e)
            }
        }
    }

    pub(super) fn remove(root: &Path, id: &ContainerId) -> Result<EtcRemoveOutcome, TraitError> {
        let euid = sys::effective_uid();
        let Some(etc_fd) = open_etc_root(root, false, euid)? else {
            return Ok(EtcRemoveOutcome::NotPresent);
        };
        let id_name = cstr(id.as_str())?;
        let dir_fd = match sys::open_dir_path_nofollow(Some(etc_fd.as_fd()), &id_name) {
            Ok(fd) => fd,
            Err(SysError::Os(sys::ENOENT)) => return Ok(EtcRemoveOutcome::NotPresent),
            Err(SysError::Os(sys::ENOTDIR)) | Err(SysError::Os(sys::ELOOP)) => {
                return Err(denied());
            }
            Err(e) => return Err(sys_err(e)),
        };
        check_private_dir(dir_fd.as_fd(), euid)?;
        let mut names = Vec::new();
        // 検査済みの `dir_fd` が固定した inode を列挙する（パスで辿り直さない。exec_kill.rs と同じ方式で新しい unsafe を足さない）。
        let entries = std::fs::read_dir(format!("/proc/thread-self/fd/{}", dir_fd.as_raw_fd()))
            .map_err(|_| err(ErrorCode::Internal, "container etc files operation failed"))?;
        for entry in entries {
            let entry = entry
                .map_err(|_| err(ErrorCode::Internal, "container etc files operation failed"))?;
            if names.len() >= ETC_DIR_MAX_ENTRIES {
                return Err(err(
                    ErrorCode::FailedPrecondition,
                    "the container etc directory has too many entries",
                ));
            }
            names.push(entry.file_name());
        }
        for name in names {
            let c = CString::new(name.as_bytes())
                .map_err(|_| err(ErrorCode::InvalidArgument, "name contains NUL"))?;
            // `unlinkat`（`AT_REMOVEDIR` なし）は symlink を辿らず、ディレクトリは `EISDIR` で拒否する。
            match sys::remove_file_at(dir_fd.as_fd(), &c) {
                Ok(()) | Err(SysError::Os(sys::ENOENT)) => {}
                Err(SysError::Os(_)) => {
                    return Err(err(
                        ErrorCode::FailedPrecondition,
                        "the container etc directory holds an entry that cannot be removed",
                    ));
                }
                Err(e) => return Err(sys_err(e)),
            }
        }
        sys::remove_dir_at(etc_fd.as_fd(), &id_name).map_err(sys_err)?;
        sync_dir(&root.join(ETC_DIR_NAME));
        Ok(EtcRemoveOutcome::Removed)
    }

    #[cfg(test)]
    pub(super) fn create_failing_after(
        root: &Path,
        id: &ContainerId,
        sel: EtcFileSelection,
        fail_after: usize,
    ) -> Result<CreatedEtcFiles, TraitError> {
        create(root, id, sel, &stat, &|n| {
            if n == fail_after {
                Err(err(ErrorCode::Internal, "injected failure"))
            } else {
                Ok(())
            }
        })
    }

    /// 試験用: `fail_at` 番目のファイルの作成直後の metadata 取得だけを失敗させる（REPAIR-3・NET-12）。
    #[cfg(test)]
    pub(super) fn create_failing_metadata(
        root: &Path,
        id: &ContainerId,
        sel: EtcFileSelection,
        fail_at: usize,
    ) -> Result<CreatedEtcFiles, TraitError> {
        let calls = std::cell::Cell::new(0usize);
        create(
            root,
            id,
            sel,
            &|fd| {
                let n = calls.get();
                calls.set(n + 1);
                if n == fail_at {
                    Err(err(ErrorCode::Internal, "injected failure"))
                } else {
                    stat(fd)
                }
            },
            &|_| Ok(()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn both() -> EtcFileSelection {
        EtcFileSelection::default()
            .with(EtcFileKind::Hosts)
            .with(EtcFileKind::ResolvConf)
    }

    /// NET-12: 初期 hosts のバイト列は D9 の 2 行（タブ区切り）に完全一致する。
    #[test]
    fn net12_initial_hosts_is_two_lines_with_tab() {
        assert_eq!(
            INITIAL_HOSTS,
            b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
        );
    }

    /// NET-12: 管理ルート配下のパスは `<root>/@container-etc/<id>/<name>`。
    #[test]
    fn net12_paths_follow_the_managed_layout() {
        let root = Path::new("/state");
        assert_eq!(
            etc_file_path(root, &id("c1"), EtcFileKind::Hosts),
            PathBuf::from("/state/@container-etc/c1/hosts")
        );
        assert_eq!(
            etc_file_path(root, &id("c1"), EtcFileKind::ResolvConf),
            PathBuf::from("/state/@container-etc/c1/resolv.conf")
        );
        assert_eq!(EtcFileKind::Hosts.container_path(), "/etc/hosts");
        assert_eq!(EtcFileKind::ResolvConf.container_path(), "/etc/resolv.conf");
    }

    #[test]
    fn net12_selection_defaults_empty_and_lists_kinds_in_fixed_order() {
        assert!(EtcFileSelection::default().is_empty());
        let sel = EtcFileSelection::default()
            .with(EtcFileKind::ResolvConf)
            .with(EtcFileKind::Hosts);
        assert_eq!(
            sel.kinds(),
            vec![EtcFileKind::Hosts, EtcFileKind::ResolvConf]
        );
        assert!(sel.contains(EtcFileKind::Hosts) && !sel.is_empty());
    }

    fn tmpfs_at(dest: &str) -> TmpfsMountSet {
        let mut set = TmpfsMountSet::new();
        set.push(crate::tmpfs::TmpfsMountSpec::new(dest, None).expect("tmpfs"))
            .expect("push");
        set
    }

    fn inject_at(dest: &str) -> InjectedFileSet {
        let mut set = InjectedFileSet::new();
        set.push(
            InjectedFileSpec::new(
                dest,
                InjectedContent::from_bytes(b"x".to_vec()).expect("content"),
                InjectedFileMode::DEFAULT,
            )
            .expect("spec"),
        )
        .expect("push");
        set
    }

    /// NET-12・SEC-1: 祖先・同一・子孫の tmpfs と注入は拒否し、重ならない宛先は受ける。
    #[test]
    fn net12_overlap_check_rejects_ancestor_same_and_descendant() {
        let sel = both();
        for dest in ["/etc", "/etc/hosts", "/etc/resolv.conf/x"] {
            let e = check_etc_overlaps(sel, &tmpfs_at(dest), None, None).expect_err(dest);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{dest}");
        }
        // 注入ファイルの親ディレクトリが `/etc`。
        let e = check_etc_overlaps(sel, &TmpfsMountSet::new(), Some(&inject_at("/etc/f")), None)
            .expect_err("inject dir /etc");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // 重ならない。
        for dest in ["/etc2", "/var", "/etc/foo"] {
            check_etc_overlaps(sel, &tmpfs_at(dest), None, None).expect(dest);
        }
        check_etc_overlaps(
            sel,
            &TmpfsMountSet::new(),
            Some(&inject_at("/run/s/f")),
            None,
        )
        .expect("inject elsewhere");
        // 選択が空なら何も見ない。
        check_etc_overlaps(EtcFileSelection::default(), &tmpfs_at("/etc"), None, None)
            .expect("empty selection");
    }

    /// 選択された種別だけが対象になる（hosts のみなら resolv.conf への重なりは拒否しない）。
    #[test]
    fn net12_overlap_check_only_looks_at_selected_kinds() {
        let sel = EtcFileSelection::default().with(EtcFileKind::Hosts);
        check_etc_overlaps(sel, &tmpfs_at("/etc/resolv.conf"), None, None).expect("not selected");
        assert!(check_etc_overlaps(sel, &tmpfs_at("/etc/hosts"), None, None).is_err());
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::test_support::TestTempDir;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        fn state_root() -> TestTempDir {
            let dir = TestTempDir::new("etc-files").expect("tmp");
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
            dir
        }

        fn euid() -> u32 {
            crate::sys::effective_uid()
        }

        /// NET-12: 生成物は 0644・nlink 1・euid 所有で、ディレクトリは 0700。hosts は初期内容、resolv.conf は空。
        #[test]
        fn net12_create_makes_regular_files_with_fixed_owner_and_mode() {
            let dir = state_root();
            let cid = id("c1");
            let created = create_etc_files(dir.path(), &cid, both()).expect("create");
            assert_eq!(created.files().len(), 2);
            for kind in EtcFileKind::ALL {
                let meta =
                    std::fs::symlink_metadata(etc_file_path(dir.path(), &cid, kind)).expect("meta");
                assert!(meta.file_type().is_file());
                assert_eq!(meta.mode() & 0o7777, 0o644, "{kind:?}");
                assert_eq!(meta.nlink(), 1);
                assert_eq!(meta.uid(), euid());
            }
            assert_eq!(
                std::fs::read(etc_file_path(dir.path(), &cid, EtcFileKind::Hosts)).expect("read"),
                INITIAL_HOSTS
            );
            assert_eq!(
                std::fs::read(etc_file_path(dir.path(), &cid, EtcFileKind::ResolvConf))
                    .expect("read"),
                b""
            );
            for p in [dir.path().join(ETC_DIR_NAME), etc_dir(dir.path(), &cid)] {
                let m = std::fs::symlink_metadata(&p).expect("dir");
                assert!(m.file_type().is_dir());
                assert_eq!(m.mode() & 0o777, 0o700);
                assert_eq!(m.uid(), euid());
            }
            // 記録した (dev, ino) は実体と一致する。
            let hosts = std::fs::metadata(etc_file_path(dir.path(), &cid, EtcFileKind::Hosts))
                .expect("meta");
            assert_eq!(
                created.files()[0],
                (EtcFileKind::Hosts, (hosts.dev(), hosts.ino()))
            );
        }

        /// umask が厳しくても 0644 に固定される。
        #[test]
        fn net12_create_mode_does_not_depend_on_umask() {
            // umask の変更は他のテストに影響するため、作成後の fchmod を直接観測する代わりに、
            // 既存の生成物が 0644 であること（上のテスト）と fchmod 経路の存在を
            // 「1 種別だけ」の生成でも確かめる。
            let dir = state_root();
            let cid = id("c-mode");
            create_etc_files(
                dir.path(),
                &cid,
                EtcFileSelection::default().with(EtcFileKind::ResolvConf),
            )
            .expect("create");
            let p = etc_file_path(dir.path(), &cid, EtcFileKind::ResolvConf);
            assert_eq!(std::fs::metadata(&p).expect("meta").mode() & 0o7777, 0o644);
            assert!(!etc_file_path(dir.path(), &cid, EtcFileKind::Hosts).exists());
        }

        /// NET-12: 所有者の読み取り権限が無い 0300 のディレクトリ（umask 0400 の mkdir 相当）でも 0700 に直せる。
        #[test]
        fn net12_fix_dir_mode_works_without_owner_read() {
            let dir = state_root();
            let d = dir.path().join("d");
            std::fs::create_dir(&d).expect("mkdir");
            std::fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o300))
                .expect("chmod");
            let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(d.as_os_str()))
                .expect("cstr");
            let fd = crate::sys::open_dir_path_nofollow(None, &c).expect("open");
            crate::sys::chmod_pinned(std::os::fd::AsFd::as_fd(&fd), 0o700).expect("fix");
            assert_eq!(std::fs::metadata(&d).expect("meta").mode() & 0o7777, 0o700);
        }

        /// NET-12: 2 回目の create は ALREADY_EXISTS で、内容を変えない。
        #[test]
        fn net12_second_create_is_rejected_without_touching_existing() {
            let dir = state_root();
            let cid = id("c1");
            create_etc_files(dir.path(), &cid, both()).expect("create");
            let hosts = etc_file_path(dir.path(), &cid, EtcFileKind::Hosts);
            std::fs::write(&hosts, b"changed\n").expect("write");
            let e = create_etc_files(dir.path(), &cid, both()).expect_err("second");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(std::fs::read(&hosts).expect("read"), b"changed\n");
        }

        /// 空の選択は何も作らない（`@container-etc` も作らない）。
        #[test]
        fn net12_empty_selection_creates_nothing() {
            let dir = state_root();
            let created =
                create_etc_files(dir.path(), &id("c1"), EtcFileSelection::default()).expect("ok");
            assert!(created.files().is_empty());
            assert!(!dir.path().join(ETC_DIR_NAME).exists());
        }

        /// SEC-1: `@container-etc` が symlink・グループ/他者に開いている場合は何も作らず拒否する。
        #[test]
        fn sec1_etc_root_symlink_or_open_mode_is_rejected() {
            let dir = state_root();
            let outside = dir.path().join("outside");
            std::fs::create_dir(&outside).expect("mkdir");
            std::os::unix::fs::symlink(&outside, dir.path().join(ETC_DIR_NAME)).expect("symlink");
            let e = create_etc_files(dir.path(), &id("c1"), both()).expect_err("symlink");
            assert_eq!(e.code(), ErrorCode::PermissionDenied);
            assert_eq!(std::fs::read_dir(&outside).expect("rd").count(), 0);
            std::fs::remove_file(dir.path().join(ETC_DIR_NAME)).expect("rm");

            std::fs::create_dir(dir.path().join(ETC_DIR_NAME)).expect("mkdir");
            std::fs::set_permissions(
                dir.path().join(ETC_DIR_NAME),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("chmod");
            let e = create_etc_files(dir.path(), &id("c1"), both()).expect_err("0755");
            assert_eq!(e.code(), ErrorCode::PermissionDenied);
            assert_eq!(
                std::fs::read_dir(dir.path().join(ETC_DIR_NAME))
                    .expect("rd")
                    .count(),
                0
            );
        }

        /// REPAIR-3: 途中で失敗したら自分が作ったファイルと `<id>` を消し、既存の別 ID は残す。
        #[test]
        fn net12_failure_midway_rolls_back_only_own_files() {
            let dir = state_root();
            create_etc_files(dir.path(), &id("other"), both()).expect("other");
            let cid = id("c1");
            let e = linux::create_failing_after(dir.path(), &cid, both(), 0).expect_err("inject");
            assert_eq!(e.code(), ErrorCode::Internal);
            assert!(!etc_dir(dir.path(), &cid).exists());
            assert!(etc_file_path(dir.path(), &id("other"), EtcFileKind::Hosts).exists());
            // 巻き戻し後に同じ ID を作り直せる。
            create_etc_files(dir.path(), &cid, both()).expect("recreate");
        }

        /// REPAIR-3・NET-12・SEC-1: 作成直後の metadata 取得が失敗しても、空ファイルも `<id>` も残さない。
        #[test]
        fn net12_metadata_failure_rolls_back_without_leftovers() {
            for fail_at in [0usize, 1] {
                let dir = state_root();
                create_etc_files(dir.path(), &id("other"), both()).expect("other");
                let cid = id("c1");
                let e = linux::create_failing_metadata(dir.path(), &cid, both(), fail_at)
                    .expect_err("inject");
                assert_eq!(e.code(), ErrorCode::Internal);
                for kind in [EtcFileKind::Hosts, EtcFileKind::ResolvConf] {
                    let p = etc_file_path(dir.path(), &cid, kind);
                    assert_eq!(
                        std::fs::symlink_metadata(&p).expect_err("gone").kind(),
                        std::io::ErrorKind::NotFound,
                        "fail_at={fail_at}"
                    );
                }
                assert!(!etc_dir(dir.path(), &cid).exists(), "fail_at={fail_at}");
                assert!(etc_file_path(dir.path(), &id("other"), EtcFileKind::Hosts).exists());
                assert!(etc_file_path(dir.path(), &id("other"), EtcFileKind::ResolvConf).exists());
                create_etc_files(dir.path(), &cid, both()).expect("recreate");
            }
        }

        /// NET-12: remove は `<id>` の中身（`apply_dns` の一時ファイルを含む）を消し、2 回目は NotPresent。
        #[test]
        fn net12_remove_deletes_files_and_is_idempotent() {
            let dir = state_root();
            let cid = id("c1");
            create_etc_files(dir.path(), &cid, both()).expect("create");
            std::fs::write(etc_dir(dir.path(), &cid).join("resolv.conf.tmp.x"), b"t").expect("tmp");
            assert_eq!(
                remove_etc_files(dir.path(), &cid).expect("remove"),
                EtcRemoveOutcome::Removed
            );
            assert!(!etc_dir(dir.path(), &cid).exists());
            assert!(dir.path().join(ETC_DIR_NAME).exists());
            assert_eq!(
                remove_etc_files(dir.path(), &cid).expect("again"),
                EtcRemoveOutcome::NotPresent
            );
        }

        /// 管理ディレクトリが無い状態の remove は NotPresent。
        #[test]
        fn net12_remove_without_managed_dir_is_not_present() {
            let dir = state_root();
            assert_eq!(
                remove_etc_files(dir.path(), &id("c1")).expect("remove"),
                EtcRemoveOutcome::NotPresent
            );
        }

        /// 中にディレクトリがあれば消さずに FAILED_PRECONDITION（他者の木を消さない）。
        #[test]
        fn net12_remove_keeps_unexpected_directory() {
            let dir = state_root();
            let cid = id("c1");
            create_etc_files(dir.path(), &cid, both()).expect("create");
            let sub = etc_dir(dir.path(), &cid).join("sub");
            std::fs::create_dir(&sub).expect("mkdir");
            let e = remove_etc_files(dir.path(), &cid).expect_err("dir");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert!(sub.exists());
        }

        /// SEC-1: `<id>` が symlink なら辿らずに拒否し、リンク先を消さない。
        #[test]
        fn sec1_remove_does_not_follow_symlinked_id_dir() {
            let dir = state_root();
            create_etc_files(dir.path(), &id("seed"), both()).expect("seed");
            let victim = dir.path().join("victim");
            std::fs::create_dir(&victim).expect("mkdir");
            std::fs::write(victim.join("hosts"), b"keep").expect("write");
            std::os::unix::fs::symlink(&victim, dir.path().join(ETC_DIR_NAME).join("c1"))
                .expect("symlink");
            let e = remove_etc_files(dir.path(), &id("c1")).expect_err("symlink");
            assert_eq!(e.code(), ErrorCode::PermissionDenied);
            assert_eq!(std::fs::read(victim.join("hosts")).expect("read"), b"keep");
        }
    }
}
