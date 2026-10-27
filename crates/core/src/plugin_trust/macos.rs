//! `plugin_trust` の macOS 実装（PLUG-11・TASK-122 追補・#1865・MAC-1。#1539 のオーナー判断）。
//!
//! # 役割と呼び出し元
//!
//! 親モジュール `plugin_trust` の `verify_plugin_dir`・`VerifiedPluginDir::verify_file` の macOS 版。
//! 呼び出し元は `verify_candidate`（CLI の plugin 候補検証。`plugin_discovery` の列挙結果が入口）で、
//! 判定基準（所有者が root か実効 UID・`mode & 0o022 == 0`・sticky も例外にしない・symlink は実体で判定）は
//! Linux の実装と同一。syscall は `crate::sys::plugin_fs`（#1864）のラッパーだけを使い、
//! 本ファイルは `unsafe` を持たない。
//!
//! # Linux との差分
//!
//! - macOS には `O_PATH` が無い。ディレクトリは `O_RDONLY|O_DIRECTORY|O_NOFOLLOW` で開くため、
//!   読み取り権限の無い祖先は `Io` で拒否される（Linux は検索権限だけで通る）
//! - 種別の事前プローブが無いため、ファイルは `O_NONBLOCK|O_NOCTTY` で 1 回だけ開き、その fd を
//!   そのまま保持 fd にする（開き直さない）。FIFO で止まらないが、デバイスノードは拒否する前に開く
//! - 実体の正規パスは `/proc` ではなく保持 fd への `F_GETPATH` で得る
//! - symlink のホップ上限は `MAXSYMLINKS`（32）。超過は `ELOOP` を `SymlinkLoop` に写す
//! - 拡張 ACL（`acl_get_fd_np`）が付いたディレクトリ・ファイルは、中身を解釈せず
//!   [`PluginTrustErrorKind::ExtendedAcl`] で拒否する。判定できなければ `Io`（fail-closed）。
//!   判定順は所有者・モード、その後に ACL
//!
//! # 契約
//!
//! - 判定の起点は `/` から symlink を辿らずに fd 相対で開いた fd 連鎖で、パスを stat し直さない
//! - 最終要素が symlink のときは、カーネルに 1 回だけ辿らせた fd を保持 fd とし、`F_GETPATH` で得た
//!   実体の親を `/` から同一基準で検証して、検証済み親の下の dev/ino が保持 fd と一致することを確かめる

use super::*;
use crate::sys::plugin_fs::{self, ELOOP, ENOTDIR};
use crate::sys::{self, SysError};
use std::ffi::CString;
use std::fs::Metadata;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Component;

/// 検証済みの探索先ディレクトリ fd。ファイルはここからの相対 open で開く。
#[derive(Debug)]
pub struct VerifiedPluginDir {
    fd: OwnedFd,
    path: PathBuf,
    /// 試験用変種の信頼起点。symlink 実体の祖先検証へ引き継ぐ（本番ビルドには存在しない）。
    #[cfg(test)]
    anchor: Option<PathBuf>,
}

/// 非追従 open の errno 写像。ファイルの open では `ELOOP` が O_NOFOLLOW の対象が symlink のとき。
/// ディレクトリの open（`O_DIRECTORY` 付き）では XNU が symlink に `ENOTDIR` を返す（#3126）ため、
/// どちらも祖先・探索先の symlink 等として `NotDirectory` に写す（fail-closed）。
pub(super) fn map_sys(e: SysError, dir_open: bool) -> PluginTrustErrorKind {
    match e {
        SysError::Unsupported => PluginTrustErrorKind::Unsupported,
        SysError::InvalidInput => PluginTrustErrorKind::InvalidPath,
        SysError::Os(n) if n == ENOTDIR => {
            if dir_open {
                PluginTrustErrorKind::NotDirectory
            } else {
                PluginTrustErrorKind::NotRegularFile
            }
        }
        SysError::Os(n) if n == ELOOP => {
            if dir_open {
                PluginTrustErrorKind::NotDirectory
            } else {
                PluginTrustErrorKind::NotRegularFile
            }
        }
        SysError::Os(_) => PluginTrustErrorKind::Io,
    }
}

/// 追従 open（symlink を辿る経路）専用の errno 写像。`ELOOP` はループ・ホップ上限超過。
pub(super) fn map_sys_follow(e: SysError) -> PluginTrustErrorKind {
    match e {
        SysError::Unsupported => PluginTrustErrorKind::Unsupported,
        SysError::InvalidInput => PluginTrustErrorKind::InvalidPath,
        SysError::Os(n) if n == ELOOP => PluginTrustErrorKind::SymlinkLoop,
        SysError::Os(n) if n == ENOTDIR => PluginTrustErrorKind::NotRegularFile,
        SysError::Os(_) => PluginTrustErrorKind::Io,
    }
}

/// ACL 判定結果の写像（純関数）。付いていれば `ExtendedAcl`、判定不能は `Io`（fail-closed）。
pub(super) fn acl_verdict(r: Result<bool, SysError>) -> Result<(), PluginTrustErrorKind> {
    match r {
        Ok(false) => Ok(()),
        Ok(true) => Err(PluginTrustErrorKind::ExtendedAcl),
        Err(_) => Err(PluginTrustErrorKind::Io),
    }
}

/// fd への fstat（std の `File::metadata`）。fd は複製して見るだけで元の fd は閉じない。
fn fstat(fd: &OwnedFd) -> std::io::Result<Metadata> {
    File::from(fd.as_fd().try_clone_to_owned()?).metadata()
}

/// 開いた fd の拡張 ACL を判定する。
fn check_acl(fd: &OwnedFd) -> Result<(), PluginTrustErrorKind> {
    acl_verdict(plugin_fs::has_extended_acl_fd(fd.as_fd()))
}

/// 開いた dir fd を検証する（ディレクトリであること・所有者・モード・拡張 ACL）。
fn check_dir_fd(fd: &OwnedFd, shown: &Path, runner_uid: u32) -> Result<(), PluginTrustError> {
    let err = |k| PluginTrustError::new(k, TrustTarget::Directory, shown);
    let md = fstat(fd).map_err(|_| err(PluginTrustErrorKind::Io))?;
    if !md.is_dir() {
        return Err(err(PluginTrustErrorKind::NotDirectory));
    }
    check_owner_and_mode(md.uid(), md.mode(), runner_uid).map_err(err)?;
    check_acl(fd).map_err(err)
}

/// 探索先ディレクトリを `/` から 1 要素ずつ fd 相対（`O_DIRECTORY|O_NOFOLLOW`）で辿り、
/// ルート・全祖先・探索先のすべてを fstat と ACL 検査で検証して最終 fd を固定して返す。
///
/// 祖先の symlink（`/tmp`・`/var` 等）は `NotDirectory` で拒否され、祖先の所有者・モード・ACL が
/// 不正なら拒否する（PLUG-11）。`.`・`..` を含むパスは `InvalidPath`。
pub fn verify_plugin_dir(dir: &Path) -> Result<VerifiedPluginDir, PluginTrustError> {
    walk_verify(dir, None)
}

/// [`verify_plugin_dir`] の試験用変種。`anchor` までの要素は symlink 拒否つきで辿るが所有者・
/// モード・ACL を検証せず、`anchor` より下だけを検証する。迂回経路のため `cfg(test)` 限定の非公開。
#[cfg(test)]
pub(super) fn verify_plugin_dir_below(
    anchor: &Path,
    dir: &Path,
) -> Result<VerifiedPluginDir, PluginTrustError> {
    if !dir.starts_with(anchor) {
        return Err(PluginTrustError::new(
            PluginTrustErrorKind::InvalidPath,
            TrustTarget::Directory,
            dir,
        ));
    }
    walk_verify(dir, Some(anchor))
}

fn walk_verify(dir: &Path, anchor: Option<&Path>) -> Result<VerifiedPluginDir, PluginTrustError> {
    let err = |k| PluginTrustError::new(k, TrustTarget::Directory, dir);
    if !dir.is_absolute() {
        return Err(err(PluginTrustErrorKind::InvalidPath));
    }
    // `Path::components()` は途中・末尾の `.` を黙って正規化するため、生バイト列で `.` 要素を拒否する。
    if dir
        .as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .any(|e| e == b".")
    {
        return Err(err(PluginTrustErrorKind::InvalidPath));
    }
    let runner_uid = sys::effective_uid();
    let mut shown = PathBuf::new();
    let mut cur: Option<OwnedFd> = None;
    for comp in dir.components() {
        let name: &OsStr = match comp {
            Component::RootDir => OsStr::new("/"),
            Component::Normal(n) => n,
            _ => return Err(err(PluginTrustErrorKind::InvalidPath)),
        };
        shown.push(name);
        let c =
            CString::new(name.as_bytes()).map_err(|_| err(PluginTrustErrorKind::InvalidPath))?;
        let parent = cur.as_ref().map(|f| f.as_fd());
        let fd = plugin_fs::open_dir_nofollow_at(parent, &c)
            .map_err(|e| PluginTrustError::new(map_sys(e, true), TrustTarget::Directory, &shown))?;
        // anchor 以上（試験用変種のみ）は所有者・モード・ACL を検証せず、種別だけ確認する。
        if anchor.is_some_and(|a| a.starts_with(&shown)) {
            let md = fstat(&fd).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if !md.is_dir() {
                return Err(PluginTrustError::new(
                    PluginTrustErrorKind::NotDirectory,
                    TrustTarget::Directory,
                    &shown,
                ));
            }
        } else {
            check_dir_fd(&fd, &shown, runner_uid)?;
        }
        cur = Some(fd);
    }
    let fd = cur.ok_or_else(|| err(PluginTrustErrorKind::InvalidPath))?;
    Ok(VerifiedPluginDir {
        fd,
        path: dir.to_path_buf(),
        #[cfg(test)]
        anchor: anchor.map(Path::to_path_buf),
    })
}

impl VerifiedPluginDir {
    /// 検証済みディレクトリ fd からの相対 open で 1 要素のファイルを開き、同じ fd への
    /// fstat・ACL 検査で検証する。
    pub fn verify_file(&self, file_name: &OsStr) -> Result<VerifiedPluginFile, PluginTrustError> {
        let path = self.path.join(file_name);
        let err = |k| PluginTrustError::new(k, TrustTarget::File, &path);
        if !is_single_component(file_name) {
            return Err(err(PluginTrustErrorKind::InvalidPath));
        }
        let c = CString::new(file_name.as_bytes())
            .map_err(|_| err(PluginTrustErrorKind::InvalidPath))?;
        // 1 回の非追従 open。最終要素が symlink なら ELOOP で、実体の検証へ進む。
        let rfd = match plugin_fs::open_read_nonblock_nofollow_at(self.fd.as_fd(), &c) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == ELOOP => return self.verify_symlink(&c, path),
            Err(e) => return Err(err(map_sys(e, false))),
        };
        let md = fstat(&rfd).map_err(|_| err(PluginTrustErrorKind::Io))?;
        if !md.is_file() {
            return Err(err(PluginTrustErrorKind::NotRegularFile));
        }
        check_owner_and_mode(md.uid(), md.mode(), sys::effective_uid()).map_err(err)?;
        check_acl(&rfd).map_err(err)?;
        Ok(VerifiedPluginFile {
            file: File::from(rfd),
            hash_lock: Mutex::new(()),
            owner_uid: md.uid(),
            mode: md.mode(),
            resolved_path: path.clone(),
            path,
        })
    }

    /// `name` が symlink のときの検証（PLUG-11・TASK-122 追補）。カーネルに最終要素のチェーンを
    /// 辿らせて保持 fd を一度だけ得て、実体 inode と実体の全祖先を検証する。
    fn verify_symlink(
        &self,
        name: &CString,
        path: PathBuf,
    ) -> Result<VerifiedPluginFile, PluginTrustError> {
        let err = |k| PluginTrustError::new(k, TrustTarget::File, &path);
        // (1) 追従 open で実体を一度だけ解決する。得た fd がそのまま保持 fd になる。
        let rfd = plugin_fs::open_read_nonblock_follow_at(self.fd.as_fd(), name)
            .map_err(|e| err(map_sys_follow(e)))?;
        let md = fstat(&rfd).map_err(|_| err(PluginTrustErrorKind::Io))?;
        if !md.is_file() {
            return Err(err(PluginTrustErrorKind::NotRegularFile));
        }
        // (2) 判定は実体 inode に対して行う（symlink 自体の属性は使わない）。
        check_owner_and_mode(md.uid(), md.mode(), sys::effective_uid()).map_err(err)?;
        check_acl(&rfd).map_err(err)?;
        // (3) 実体の正規パスを保持 fd の `F_GETPATH` で得る。
        let resolved =
            plugin_fs::fd_real_path(rfd.as_fd()).map_err(|_| err(PluginTrustErrorKind::Io))?;
        let (Some(real_parent), Some(real_name)) = (resolved.parent(), resolved.file_name()) else {
            return Err(err(PluginTrustErrorKind::Io));
        };
        if !is_single_component(real_name) {
            return Err(err(PluginTrustErrorKind::Io));
        }
        // (4) 実体の親と全祖先を探索先と同一基準で検証する。
        #[cfg(test)]
        let anchor = self.anchor.as_deref();
        #[cfg(not(test))]
        let anchor: Option<&Path> = None;
        let real_dir = walk_verify(real_parent, anchor)?;
        // (5) 検証済み親の下の実体が保持 fd と同一 inode であることを確かめる（保持 fd が検証済みの
        // 祖先連鎖の下にある証明）。この fd は fstat のみに使い、引き渡さない。
        let real_c = CString::new(real_name.as_bytes())
            .map_err(|_| err(PluginTrustErrorKind::InvalidPath))?;
        let bound = plugin_fs::open_read_nonblock_nofollow_at(real_dir.fd.as_fd(), &real_c)
            .map_err(|_| err(PluginTrustErrorKind::Io))?;
        let bound_md = fstat(&bound).map_err(|_| err(PluginTrustErrorKind::Io))?;
        if bound_md.dev() != md.dev() || bound_md.ino() != md.ino() {
            return Err(err(PluginTrustErrorKind::Io));
        }
        Ok(VerifiedPluginFile {
            file: File::from(rfd),
            hash_lock: Mutex::new(()),
            owner_uid: md.uid(),
            mode: md.mode(),
            path,
            resolved_path: resolved,
        })
    }
}
