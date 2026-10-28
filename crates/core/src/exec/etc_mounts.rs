//! 管理ルートに生成した `/etc/hosts`・`/etc/resolv.conf` を、pivot 前の rootfs へ fd 起点で bind mount する段
//! （NET-12・NET-8・CORE-1・SEC-1・SEC-4・SEC-5・TASK-185 追補・#1872。設計は `docs/design/network-wiring.md` の D9）。
//!
//! # 役割と呼び出し文脈
//!
//! 元のファイルは [`crate::etc_files::create_etc_files`]（supervisor の start。#1873）が
//! `<state_root>/@container-etc/<id>/` に作る。本段は `run_pre_pivot` の `inject_files` の後・`mount_binds` の前で、
//! その元を rootfs の `/etc/hosts`・`/etc/resolv.conf` に載せる。`crate::oci_runtime` の launcher だけが
//! [`EtcFileMounts::verify`] を呼んで組み立て、子（PID 1）が [`mount_etc_files`] を呼ぶ。
//!
//! ```text
//! launcher（fork 前）: EtcFileMounts::verify(state_root, id, 選択, root_readonly)   // 元を辿って所有者・権限・nlink を検査
//! 子（新しい mount namespace）: mount_etc_files(&isolation, &prepared, &mounts)    // 元を辿り直して (dev, ino) を照合し bind
//! ```
//!
//! # 元の検証が 2 段である理由
//!
//! user namespace の中では `fstat` の uid が写像後の値になり、所有者が実効 uid であることを確かめられない。そこで
//! 所有者・権限・nlink は fork 前に（ホストの uid のまま）検査して `(st_dev, st_ino)` を記録し、子は同じ正規化済みパスを
//! `/` から 1 要素ずつ `O_NOFOLLOW` で辿り直して `(st_dev, st_ino)` と nlink 1 の一致だけを要求する。状態ルートは 0700・
//! 実効 uid 所有のため、他者は検査後に差し替えられない。`open_tree` は同じ mount namespace の fd を要求するので、
//! fork 前に開いた fd は使えない。
//!
//! # 契約（1 件ごとの順序）
//!
//! 1. **先の固定**: rootfs の fd から `etc` を `O_PATH|O_NOFOLLOW|O_DIRECTORY` で開く。無い・symlink・非ディレクトリは
//!    `InvalidArgument`。続けて `etc` の fd の下の `hosts` / `resolv.conf` を `O_PATH|O_NOFOLLOW` で開く。symlink や
//!    通常ファイル以外は `InvalidArgument`（symlink は解決せず拒否を続ける。D9 の決定・#3210）。親ディレクトリは作らない
//! 2. **先が無いとき**: 書き込み可能な rootfs なら空の通常ファイル（0644）を `O_EXCL|O_NOFOLLOW` で作る。実効の
//!    `root.readonly=true`（`read_only`）や `EROFS` では rootfs へ書かず `FailedPrecondition` で拒否する
//! 3. **shared の上には載せない**: 先の属するマウントが shared なら `FailedPrecondition`
//! 4. **属性**: 元を `open_tree(OPEN_TREE_CLONE)` で切り離して複製し、`nosuid,nodev,noexec`（`read_only` なら `ro` も）を
//!    切り離した状態で付ける（`attr_clr` は 0）。付け替え前にフラグを照合し、先が動いていないことを fd で確かめてから
//!    `move_mount(2)`（fd 指定）で載せる
//! 5. **事後検証**: 先を開き直し、マウントが新しいものである・自分のものである・`(st_dev, st_ino)` が元と一致する・
//!    フラグが要求どおりであることを確かめる
//! 6. **失敗時の後始末**: この呼び出しで載せたマウントを新しい順に `MNT_DETACH` で外し、自分が作った空ファイルを
//!    `(st_dev, st_ino)` が一致するときだけ消す。後始末の失敗は元のエラーの message に `; cleanup failed: ...` として併記する
//!
//! `read_only` の既定は rw（Docker と同等。書き換えても自分の生成ファイルにしか及ばない）。実効の `root.readonly=true` では
//! ro で載せる（containerd の `containerMounts` が `readonly_rootfs` を hosts / resolv.conf の `Readonly` に写す挙動に
//! 揃えた、閉じた側の選択。一次情報の確認は #2859）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - 本番の起動経路は `RootfulHostRoot` を launcher が `UNIMPLEMENTED` で拒否している（#2241・SEC-5）ため、動くのは rootless の
//!   2 モデルだけ。rootful 固有の分岐は持たない
//! - 範囲写像でコンテナの uid 0 が実効 uid に写らない構成では、元の辿り直しが `EACCES` になり `FailedPrecondition` で拒否する
//! - 先が symlink の場合は解決せず拒否する（D9 の決定・#3210。再検討の条件は D9 の「残余・見直し条件」）。違反記録は付けて
//!   親へ渡すが、本番の sink への配線は `violation.rs` の記述どおり未実装
//! - `/etc/hostname` は対象外（D9）

use std::ffi::CString;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use crate::etc_files::{EtcFileKind, EtcFileSelection, etc_file_path};
use crate::sys::{
    self, BindMountAttrs, BindSourceKind, MountFlags, SysError, VerifiedBindSourceFd,
};
use crate::traits::ContainerId;
use crate::traits::types::ErrorCode;

use super::violation::ViolationReason;
use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, fd_mount_id, fd_still_at,
    mount_is_shared,
};

const STAGE: IsolationStage = IsolationStage::MountEtcFiles;
const FILE_MODE: u32 = 0o644;
/// 正規化済みの元のパスの要素数の上限（無制限の走査を避ける。`PATH_MAX` 4096 に対して十分大きい値）。
const MAX_SOURCE_COMPONENTS: usize = 256;

fn fail(code: ErrorCode, msg: &'static str) -> ExecError {
    ExecError::new(code, STAGE, msg)
}

/// 境界違反の失敗。違反記録（`ViolationReason`）を持たせ、子の状態チャネル経由で親の監査経路へ渡す
/// （SEC-4。bind mount の段と同じ。`code` は理由が決める）。メッセージは固有のものを使う。
fn violation(reason: ViolationReason, msg: &'static str) -> ExecError {
    let mut err = ExecError::from_violation_at(reason, None, STAGE);
    err.message = msg.into();
    err
}

fn precondition(msg: &'static str) -> ExecError {
    fail(ErrorCode::FailedPrecondition, msg)
}

/// 元 1 件の記録（fork 前の検証の結果）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct EtcSource {
    kind: EtcFileKind,
    /// 正規化済みの状態ルートから導いた元のパス（子が辿り直す）。
    path: PathBuf,
    /// 検証時の `(st_dev, st_ino)`。
    dev_ino: (u64, u64),
}

/// fork 前に検証済みの元の一覧と、載せ方（モジュール doc）。構築子は [`EtcFileMounts::verify`] だけで、
/// 任意のパスを渡す入口は無い。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtcFileMounts {
    sources: Vec<EtcSource>,
    read_only: bool,
}

/// ディレクトリの検査（純関数。不適合なら固定の理由）。実効 uid 所有の 0700 相当（グループ/他者の権限なし）。
pub(super) fn judge_etc_dir(is_dir: bool, uid: u32, mode: u32, euid: u32) -> Option<&'static str> {
    if !is_dir {
        return Some("the container etc directory is not a directory");
    }
    if uid != euid {
        return Some("the container etc directory is not owned by the current user");
    }
    if mode & 0o077 != 0 {
        return Some("the container etc directory is accessible by other users");
    }
    None
}

/// 元のファイルの検査（純関数）。実効 uid 所有の通常ファイル・nlink 1・グループ/他者に書き込み権限なし。
pub(super) fn judge_etc_source(
    is_file: bool,
    uid: u32,
    mode: u32,
    nlink: u64,
    euid: u32,
) -> Option<&'static str> {
    if !is_file {
        return Some("the container etc file is not a regular file");
    }
    if uid != euid {
        return Some("the container etc file is not owned by the current user");
    }
    if nlink != 1 {
        return Some("the container etc file has more than one hard link");
    }
    if mode & 0o022 != 0 {
        return Some("the container etc file is writable by other users");
    }
    None
}

/// `/` から 1 要素ずつ `O_NOFOLLOW` で辿った結果。
struct Walked {
    /// 辿ったディレクトリの metadata（先頭が `/`、末尾が葉の親）。
    dirs: Vec<std::fs::Metadata>,
    leaf: VerifiedBindSourceFd,
    leaf_meta: std::fs::Metadata,
}

fn meta_of(fd: BorrowedFd<'_>) -> Result<std::fs::Metadata, ExecError> {
    let dup = fd
        .try_clone_to_owned()
        .map_err(|_| fail(ErrorCode::Internal, "cannot inspect the container etc file"))?;
    std::fs::File::from(dup)
        .metadata()
        .map_err(|_| fail(ErrorCode::Internal, "cannot inspect the container etc file"))
}

/// 絶対・正規化済みの `path` を `/` から 1 要素ずつ `O_PATH|O_NOFOLLOW` で辿る。
fn walk(path: &Path) -> Result<Walked, ExecError> {
    let mut names: Vec<CString> = Vec::new();
    let mut comps = path.components();
    if comps.next() != Some(Component::RootDir) {
        return Err(precondition("the container etc file path is not absolute"));
    }
    for c in comps {
        match c {
            Component::Normal(n) => {
                let c = CString::new(n.as_bytes()).map_err(|_| {
                    fail(
                        ErrorCode::InvalidArgument,
                        "the container etc file path contains NUL",
                    )
                })?;
                names.push(c);
            }
            _ => {
                return Err(precondition(
                    "the container etc file path is not normalized",
                ));
            }
        }
        if names.len() > MAX_SOURCE_COMPONENTS {
            return Err(precondition("the container etc file path is too deep"));
        }
    }
    let Some((leaf_name, parents)) = names.split_last() else {
        return Err(precondition("the container etc file path is empty"));
    };
    let open_err = |e: SysError| match e {
        SysError::Os(sys::ENOENT) => precondition("the container etc file does not exist"),
        SysError::Os(sys::ENOTDIR) | SysError::Os(sys::ELOOP) => {
            precondition("a component of the container etc file path is a symbolic link")
        }
        SysError::Os(sys::EACCES) | SysError::Os(sys::EPERM) => fail(
            ErrorCode::PermissionDenied,
            "the container etc file is not accessible",
        ),
        e => ExecError::from_sys(e, STAGE, "openat(container etc file)"),
    };
    let mut cur = sys::open_dir_path_nofollow(None, c"/").map_err(open_err)?;
    let mut dirs = vec![meta_of(cur.as_fd())?];
    for name in parents {
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), name).map_err(open_err)?;
        dirs.push(meta_of(cur.as_fd())?);
    }
    let fd = sys::open_path_nofollow(cur.as_fd(), leaf_name).map_err(open_err)?;
    let leaf = sys::verify_bind_source_fd(fd).map_err(|e| match e {
        sys::BindSourceError::NotDirOrRegular { .. } => {
            precondition("the container etc file is not a regular file")
        }
        sys::BindSourceError::Sys(e) => ExecError::from_sys(e, STAGE, "fstat(container etc file)"),
    })?;
    let leaf_meta = meta_of(leaf.as_fd())?;
    Ok(Walked {
        dirs,
        leaf,
        leaf_meta,
    })
}

impl EtcFileMounts {
    /// fork 前の検証（モジュール doc）。`state_root` を正規化し、`@container-etc` と `<id>` が実効 uid 所有の 0700、
    /// 各ファイルが実効 uid 所有の通常ファイル・nlink 1・他者書き込み不可であることを確かめて記録する。
    /// `sel` が空なら空の集合を返す。不適合は `FailedPrecondition`（fork・予約より前に返す）。
    pub fn verify(
        state_root: &Path,
        id: &ContainerId,
        sel: EtcFileSelection,
        read_only: bool,
    ) -> Result<Self, ExecError> {
        if sel.is_empty() {
            return Ok(Self {
                sources: Vec::new(),
                read_only,
            });
        }
        let euid = sys::effective_uid();
        let root = std::fs::canonicalize(state_root)
            .map_err(|_| precondition("the state root cannot be resolved"))?;
        let mut sources = Vec::new();
        for kind in sel.kinds() {
            let path = etc_file_path(&root, id, kind);
            let walked = walk(&path)?;
            // 葉の親(<id>)とその親(@container-etc)を検査する。
            for dir in walked.dirs.iter().rev().take(2) {
                if let Some(why) =
                    judge_etc_dir(dir.file_type().is_dir(), dir.uid(), dir.mode(), euid)
                {
                    return Err(precondition(why));
                }
            }
            let m = &walked.leaf_meta;
            if let Some(why) =
                judge_etc_source(m.file_type().is_file(), m.uid(), m.mode(), m.nlink(), euid)
            {
                return Err(precondition(why));
            }
            sources.push(EtcSource {
                kind,
                path,
                dev_ino: walked.leaf.dev_ino(),
            });
        }
        Ok(Self { sources, read_only })
    }

    /// 載せる種別の選択(重なりの再検査用)。
    pub(crate) fn selection(&self) -> EtcFileSelection {
        self.sources
            .iter()
            .fold(EtcFileSelection::default(), |sel, s| sel.with(s.kind))
    }

    /// 試験用: 検査を通さずに組み立てる(`run_pre_pivot` の段の順序の試験が使う。実在しないパスを指す)。
    #[cfg(test)]
    pub(crate) fn for_test(kinds: &[EtcFileKind], read_only: bool) -> Self {
        Self {
            sources: kinds
                .iter()
                .map(|k| EtcSource {
                    kind: *k,
                    path: PathBuf::from("/nonexistent"),
                    dev_ino: (0, 0),
                })
                .collect(),
            read_only,
        }
    }

    /// 載せるものが無いか。
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// 載せる種別（固定順）。
    pub fn kinds(&self) -> Vec<EtcFileKind> {
        self.sources.iter().map(|s| s.kind).collect()
    }

    /// ro で載せるか（実効の `root.readonly`）。
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// 子（新しい mount namespace）で元を辿り直す。`(st_dev, st_ino)` と nlink 1 の一致を要求する。
    fn open_sources(&self) -> Result<Vec<(EtcFileKind, VerifiedBindSourceFd)>, ExecError> {
        let mut out = Vec::with_capacity(self.sources.len());
        for s in &self.sources {
            let walked = walk(&s.path)?;
            if walked.leaf.kind() != BindSourceKind::RegularFile
                || walked.leaf.dev_ino() != s.dev_ino
                || walked.leaf.nlink() != 1
            {
                return Err(precondition(
                    "the container etc file changed after validation",
                ));
            }
            out.push((s.kind, walked.leaf));
        }
        Ok(out)
    }
}

/// 載せた 1 件の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EtcFileOutcome {
    /// 種別。
    pub kind: EtcFileKind,
    /// コンテナ内のマウント先。
    pub destination: &'static str,
    /// ro で載せたか。
    pub read_only: bool,
    /// 先の空ファイルをこの呼び出しで作ったか。
    pub created_target: bool,
}

/// [`mount_etc_files`] の結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct EtcFilesReport {
    /// 載せた順。
    pub mounts: Vec<EtcFileOutcome>,
}

/// 先の `etc` の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EtcDirState {
    Directory,
    Missing,
    /// symlink・非ディレクトリ。
    Other,
}

/// 先の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetState {
    Regular,
    Missing,
    Symlink,
    /// ディレクトリ・デバイス等。
    Other,
}

/// 先に対する動作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetAction {
    /// 既存の通常ファイルへ載せる。
    Mount,
    /// 空の通常ファイルを作ってから載せる。
    CreateThenMount,
}

/// 先が symlink のときの利用者向けの固定文言（NET-12・SEC-1・D9）。rootfs から読んだ値は入れない。
fn symlink_message(kind: EtcFileKind) -> &'static str {
    match kind {
        EtcFileKind::Hosts => {
            "/etc/hosts in the rootfs is a symbolic link; the container etc mount does not follow symbolic links (replace it with a regular file in the image)"
        }
        EtcFileKind::ResolvConf => {
            "/etc/resolv.conf in the rootfs is a symbolic link; the container etc mount does not follow symbolic links (replace it with a regular file in the image, or remove it when the rootfs is writable)"
        }
    }
}

/// 先の規則の判定（純関数。モジュール doc の契約 1・2）。
pub(super) fn judge_target(
    kind: EtcFileKind,
    etc: EtcDirState,
    target: TargetState,
    read_only: bool,
) -> Result<TargetAction, ExecError> {
    match etc {
        EtcDirState::Directory => {}
        EtcDirState::Missing => {
            return Err(violation(
                ViolationReason::PathMissing,
                "the rootfs has no /etc directory for /etc/hosts or /etc/resolv.conf",
            ));
        }
        EtcDirState::Other => {
            return Err(violation(
                ViolationReason::PathSymlinkOrNotDirectory,
                "/etc in the rootfs is a symbolic link or not a directory",
            ));
        }
    }
    match target {
        TargetState::Regular => Ok(TargetAction::Mount),
        TargetState::Missing if read_only => Err(precondition(
            "the rootfs is read-only and has no file for the container etc mount",
        )),
        TargetState::Missing => Ok(TargetAction::CreateThenMount),
        TargetState::Symlink => Err(violation(
            ViolationReason::PathSymlinkOrNotDirectory,
            symlink_message(kind),
        )),
        TargetState::Other => Err(violation(
            ViolationReason::BindTargetKindMismatch,
            "the container etc mount destination is not a regular file",
        )),
    }
}

/// 付け替え前後のフラグの判定（純関数）。`nosuid,nodev,noexec` は必須で、`ro` は要求と一致しなければならない。
pub(super) fn judge_flags(flags: MountFlags, read_only: bool) -> Result<(), &'static str> {
    if !flags.is_valid() {
        return Err("the mount flags are not available");
    }
    if !flags.is_nosuid() || !flags.is_nodev() || !flags.is_noexec() {
        return Err("nosuid, nodev and noexec are not set on the container etc mount");
    }
    match (flags.is_read_only(), read_only) {
        (true, false) => Err("the container etc mount is read-only but read-write was requested"),
        (false, true) => Err("ro was not applied to the container etc mount"),
        _ => Ok(()),
    }
}

/// 副作用・観測の差し込み点（本番は実 syscall、単体テストは記録つきの偽。`BindDeps` と同形）。
struct Deps<'a> {
    is_shared: &'a dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    still_at: &'a dyn Fn(&OwnedFd, &Path) -> bool,
    open_tree: &'a dyn Fn(&VerifiedBindSourceFd) -> Result<OwnedFd, SysError>,
    set_attrs: &'a dyn Fn(BorrowedFd<'_>, BindMountAttrs) -> Result<(), SysError>,
    flags_of: &'a dyn Fn(BorrowedFd<'_>) -> Result<MountFlags, SysError>,
    attach: &'a dyn Fn(BorrowedFd<'_>, BorrowedFd<'_>) -> Result<(), SysError>,
    mnt_id: &'a dyn Fn(&OwnedFd) -> Result<u64, ExecError>,
    umount: &'a dyn Fn(BorrowedFd<'_>) -> Result<(), SysError>,
}

/// 載せた 1 件の後始末情報。
struct Applied {
    clone: Option<OwnedFd>,
    /// 自分が作った空ファイル `(名前, (dev, ino))`。
    created: Option<(CString, (u64, u64))>,
    /// この件の `etc` ディレクトリ（作ったファイルを消すため）。
    etc: OwnedFd,
}

fn rollback(applied: &mut Vec<Applied>, deps: &Deps<'_>) -> Vec<String> {
    let mut failures = Vec::new();
    while let Some(a) = applied.pop() {
        if let Some(clone) = &a.clone
            && let Err(e) = (deps.umount)(clone.as_fd())
        {
            failures.push(format!("umount: {e:?}"));
        }
        drop(a.clone);
        if let Some((name, ident)) = &a.created {
            match sys::open_path_nofollow(a.etc.as_fd(), name) {
                Ok(fd) => match meta_of(fd.as_fd()) {
                    Ok(m) if (m.dev(), m.ino()) == *ident => {
                        if let Err(e) = sys::remove_file_at(a.etc.as_fd(), name) {
                            failures.push(format!("unlink: {e:?}"));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => failures.push(format!("fstat: {}", e.message)),
                },
                Err(SysError::Os(sys::ENOENT)) => {}
                Err(e) => failures.push(format!("open: {e:?}")),
            }
        }
    }
    failures
}

fn with_cleanup(mut err: ExecError, failures: &[String]) -> ExecError {
    if !failures.is_empty() {
        err.message = format!("{}; cleanup failed: {}", err.message, failures.join(", "));
    }
    err
}

fn classify_target(fd: &OwnedFd) -> Result<TargetState, ExecError> {
    let m = meta_of(fd.as_fd())?;
    let t = m.file_type();
    Ok(if t.is_symlink() {
        TargetState::Symlink
    } else if t.is_file() {
        TargetState::Regular
    } else {
        TargetState::Other
    })
}

fn open_etc(root: BorrowedFd<'_>) -> Result<(EtcDirState, Option<OwnedFd>), ExecError> {
    match sys::open_dir_path_nofollow(Some(root), c"etc") {
        Ok(fd) => Ok((EtcDirState::Directory, Some(fd))),
        Err(SysError::Os(sys::ENOENT)) => Ok((EtcDirState::Missing, None)),
        Err(SysError::Os(sys::ENOTDIR)) | Err(SysError::Os(sys::ELOOP)) => {
            Ok((EtcDirState::Other, None))
        }
        Err(e) => Err(ExecError::from_sys(e, STAGE, "openat(/etc)")),
    }
}

fn apply_one(
    root: BorrowedFd<'_>,
    host_root: &Path,
    kind: EtcFileKind,
    src: &VerifiedBindSourceFd,
    read_only: bool,
    deps: &Deps<'_>,
    applied: &mut Vec<Applied>,
) -> Result<bool, ExecError> {
    let (etc_state, etc_fd) = open_etc(root)?;
    let name = CString::new(kind.file_name())
        .map_err(|_| fail(ErrorCode::Internal, "invalid container etc file name"))?;
    let target_state = match &etc_fd {
        Some(etc) => match sys::open_path_nofollow(etc.as_fd(), &name) {
            Ok(fd) => classify_target(&fd)?,
            Err(SysError::Os(sys::ENOENT)) => TargetState::Missing,
            Err(e) => {
                return Err(ExecError::from_sys(
                    e,
                    STAGE,
                    "openat(container etc target)",
                ));
            }
        },
        None => TargetState::Missing,
    };
    let action = judge_target(kind, etc_state, target_state, read_only)?;
    let Some(etc) = etc_fd else {
        return Err(fail(
            ErrorCode::Internal,
            "the /etc directory handle was lost",
        ));
    };
    let mut entry = Applied {
        clone: None,
        created: None,
        etc,
    };
    let mut created_target = false;
    if action == TargetAction::CreateThenMount {
        match sys::create_file_excl_at(entry.etc.as_fd(), &name, FILE_MODE) {
            Ok(fd) => {
                let file = std::fs::File::from(fd);
                let m = file.metadata().map_err(|_| {
                    fail(
                        ErrorCode::Internal,
                        "cannot inspect the created container etc target",
                    )
                })?;
                entry.created = Some((name.clone(), (m.dev(), m.ino())));
                created_target = true;
                let r = file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE));
                // 後始末のため、失敗しても先に記録してから返す。
                if r.is_err() {
                    applied.push(entry);
                    return Err(fail(
                        ErrorCode::Internal,
                        "cannot set the mode of the created container etc target",
                    ));
                }
            }
            Err(SysError::Os(errno))
                if std::io::Error::from_raw_os_error(errno).kind()
                    == std::io::ErrorKind::ReadOnlyFilesystem =>
            {
                return Err(precondition(
                    "the rootfs is read-only and has no file for the container etc mount",
                ));
            }
            Err(e) => {
                return Err(ExecError::from_sys(
                    e,
                    STAGE,
                    "create(container etc target)",
                ));
            }
        }
    }
    // 作ったあとの失敗でも自分が作った空ファイルを消せるよう、先に記録する。
    applied.push(entry);
    let idx = applied.len() - 1;
    let etc_ref = applied.get(idx).map(|a| a.etc.as_fd());
    let Some(etc_ref) = etc_ref else {
        return Err(fail(
            ErrorCode::Internal,
            "the /etc directory handle was lost",
        ));
    };
    let dest = sys::open_path_nofollow(etc_ref, &name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(container etc target)"))?;
    if classify_target(&dest)? != TargetState::Regular {
        return Err(violation(
            ViolationReason::BindTargetKindMismatch,
            "the container etc mount destination is not a regular file",
        ));
    }
    if (deps.is_shared)(&dest)? {
        return Err(violation(
            ViolationReason::TargetOnSharedMount,
            "the container etc mount destination is on a shared mount",
        ));
    }
    let before = (deps.mnt_id)(&dest)?;
    let clone = (deps.open_tree)(src)
        .map_err(|e| ExecError::from_sys(e, STAGE, "open_tree(container etc source)"))?;
    (deps.set_attrs)(
        clone.as_fd(),
        BindMountAttrs {
            read_only,
            noexec: true,
        },
    )
    .map_err(|e| ExecError::from_sys(e, STAGE, "mount_setattr(container etc mount)"))?;
    let flags = (deps.flags_of)(clone.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(detached container etc mount)"))?;
    judge_flags(flags, read_only).map_err(precondition)?;
    let expected = host_root.join("etc").join(kind.file_name());
    if !(deps.still_at)(&dest, &expected) {
        return Err(violation(
            ViolationReason::TargetMoved,
            "the container etc mount destination moved before the mount",
        ));
    }
    (deps.attach)(clone.as_fd(), dest.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "move_mount(container etc mount)"))?;
    if let Some(a) = applied.get_mut(idx) {
        a.clone = Some(clone);
    }
    // 事後検証: 名前で開き直した先が新しい・自分のマウントで、元と同じ inode で、フラグが要求どおりであること。
    let Some(a) = applied.get(idx) else {
        return Err(fail(
            ErrorCode::Internal,
            "the container etc mount handle was lost",
        ));
    };
    let after = sys::open_path_nofollow(a.etc.as_fd(), &name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(container etc target)"))?;
    let after_id = (deps.mnt_id)(&after)?;
    let own_id = match &a.clone {
        Some(c) => (deps.mnt_id)(c)?,
        None => {
            return Err(fail(
                ErrorCode::Internal,
                "the container etc mount handle was lost",
            ));
        }
    };
    if after_id == before {
        return Err(precondition(
            "no new mount is present at the container etc mount destination after mount",
        ));
    }
    if after_id != own_id {
        return Err(precondition(
            "the mount at the container etc destination is not the mount created by this call",
        ));
    }
    let m = meta_of(after.as_fd())?;
    if (m.dev(), m.ino()) != src.dev_ino() {
        return Err(precondition(
            "the container etc destination is not the same inode as the validated source",
        ));
    }
    let flags = (deps.flags_of)(after.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(container etc target)"))?;
    judge_flags(flags, read_only).map_err(precondition)?;
    Ok(created_target)
}

fn mount_etc_files_at(
    root: BorrowedFd<'_>,
    host_root: &Path,
    sources: Vec<(EtcFileKind, VerifiedBindSourceFd)>,
    read_only: bool,
    deps: &Deps<'_>,
) -> Result<EtcFilesReport, ExecError> {
    let mut applied: Vec<Applied> = Vec::with_capacity(sources.len());
    let mut mounts = Vec::with_capacity(sources.len());
    for (kind, src) in &sources {
        match apply_one(root, host_root, *kind, src, read_only, deps, &mut applied) {
            Ok(created_target) => mounts.push(EtcFileOutcome {
                kind: *kind,
                destination: kind.container_path(),
                read_only,
                created_target,
            }),
            Err(e) => {
                let failures = rollback(&mut applied, deps);
                return Err(with_cleanup(e, &failures));
            }
        }
    }
    // 載せたマウントは pivot 後も残す（後始末の fd だけ閉じる。マウント自体は名前空間に残る）。
    Ok(EtcFilesReport { mounts })
}

/// 子（PID 1）が rootfs の `/etc/hosts`・`/etc/resolv.conf` へ管理ルートの元を載せる（モジュール doc）。
///
/// `mounts` が空なら何もしない。呼び出し文脈は `run_pre_pivot` の `inject_files` の後・`mount_binds` の前
/// （`MountIsolation::establish` と同じスレッド）。失敗時はこの呼び出しで載せたものを戻す。
pub fn mount_etc_files(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    mounts: &EtcFileMounts,
) -> Result<EtcFilesReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    if mounts.is_empty() {
        return Ok(EtcFilesReport::default());
    }
    // 元は子の mount namespace の中で辿り直す（`open_tree` は同じ namespace の fd を要求する）。
    let sources = mounts.open_sources().map_err(|e| {
        // user namespace の写像で実効 uid に届かない構成の `EACCES` は、構造化エラーに写して fail-closed にする。
        if e.code == ErrorCode::PermissionDenied {
            precondition("the container etc file cannot be read in the container user namespace")
        } else {
            e
        }
    })?;
    let root = prepared.new_root();
    let host_root = super::tmpfs::root_display(root);
    let deps = Deps {
        is_shared: &|dir| mount_is_shared(dir, STAGE),
        still_at: &fd_still_at,
        open_tree: &|src| sys::open_tree_clone_bind(src, sys::MountTreeScope::MountOnly),
        set_attrs: &|fd, attrs| {
            sys::set_bind_mount_attrs(fd, attrs, sys::MountTreeScope::MountOnly)
        },
        flags_of: &sys::mount_flags,
        attach: &sys::move_mount_empty_path,
        mnt_id: &|fd| fd_mount_id(fd, STAGE),
        umount: &umount_fd,
    };
    mount_etc_files_at(root, &host_root, sources, mounts.read_only(), &deps)
}

/// 自分のマウントを fd 指定で `umount2(MNT_DETACH)` する（fd を直接指す syscall が無いため `/proc/thread-self/fd/N` 経由）。
fn umount_fd(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    use std::os::fd::AsRawFd as _;
    let target = CString::new(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| SysError::Os(sys::EINVAL))?;
    sys::umount_detach_at(&target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestTempDir;
    use std::cell::{Cell, RefCell};

    const VALID: i64 = 0x20;
    const RDONLY: i64 = 0x1;
    const NOSUID: i64 = 0x2;
    const NODEV: i64 = 0x4;
    const NOEXEC: i64 = 0x8;

    fn flags(read_only: bool, noexec: bool) -> MountFlags {
        let mut b = VALID | NOSUID | NODEV;
        if noexec {
            b |= NOEXEC;
        }
        if read_only {
            b |= RDONLY;
        }
        MountFlags::from_bits(b)
    }

    /// NET-12: ディレクトリ・ファイルの検査は所有者・権限・nlink・種別の具体値で判定する。
    #[test]
    fn net12_judge_dir_and_source_by_owner_mode_and_nlink() {
        assert_eq!(judge_etc_dir(true, 1000, 0o700, 1000), None);
        assert!(judge_etc_dir(false, 1000, 0o700, 1000).is_some());
        assert!(judge_etc_dir(true, 0, 0o700, 1000).is_some());
        assert!(judge_etc_dir(true, 1000, 0o750, 1000).is_some());
        assert!(judge_etc_dir(true, 1000, 0o705, 1000).is_some());
        assert_eq!(judge_etc_source(true, 1000, 0o644, 1, 1000), None);
        assert_eq!(judge_etc_source(true, 1000, 0o600, 1, 1000), None);
        assert!(judge_etc_source(false, 1000, 0o644, 1, 1000).is_some());
        assert!(judge_etc_source(true, 0, 0o644, 1, 1000).is_some());
        assert!(judge_etc_source(true, 1000, 0o644, 2, 1000).is_some());
        assert!(judge_etc_source(true, 1000, 0o664, 1, 1000).is_some());
        assert!(judge_etc_source(true, 1000, 0o646, 1, 1000).is_some());
    }

    /// NET-12・SEC-1: 先の規則(D9)。symlink・ディレクトリ・`/etc` の欠落は InvalidArgument、
    /// 無い先は rw なら作成、ro なら FailedPrecondition。
    #[test]
    fn net12_judge_target_follows_the_d9_rules() {
        use EtcDirState as E;
        use EtcFileKind as K;
        use TargetState as T;
        assert_eq!(
            judge_target(K::Hosts, E::Directory, T::Regular, false).expect("mount"),
            TargetAction::Mount
        );
        assert_eq!(
            judge_target(K::Hosts, E::Directory, T::Regular, true).expect("mount ro"),
            TargetAction::Mount
        );
        assert_eq!(
            judge_target(K::Hosts, E::Directory, T::Missing, false).expect("create"),
            TargetAction::CreateThenMount
        );
        assert_eq!(
            judge_target(K::Hosts, E::Directory, T::Missing, true)
                .expect_err("ro missing")
                .code,
            ErrorCode::FailedPrecondition
        );
        for t in [T::Symlink, T::Other] {
            assert_eq!(
                judge_target(K::Hosts, E::Directory, t, false)
                    .expect_err("bad")
                    .code,
                ErrorCode::InvalidArgument,
                "{t:?}"
            );
        }
        // #3210: symlink の文言は種別ごとの固定文字列（rootfs の値を含めない）。
        let hosts = judge_target(K::Hosts, E::Directory, T::Symlink, false).expect_err("symlink");
        assert_eq!(
            hosts.message,
            "/etc/hosts in the rootfs is a symbolic link; the container etc mount does not follow symbolic links (replace it with a regular file in the image)"
        );
        let resolv =
            judge_target(K::ResolvConf, E::Directory, T::Symlink, false).expect_err("symlink");
        assert_eq!(
            resolv.message,
            "/etc/resolv.conf in the rootfs is a symbolic link; the container etc mount does not follow symbolic links (replace it with a regular file in the image, or remove it when the rootfs is writable)"
        );
        // SEC-4: 境界違反は違反記録を持ち、親の監査経路へ渡る。
        for (t, want) in [
            (T::Symlink, ViolationReason::PathSymlinkOrNotDirectory),
            (T::Other, ViolationReason::BindTargetKindMismatch),
        ] {
            let v = judge_target(K::Hosts, E::Directory, t, false)
                .expect_err("bad")
                .violation
                .expect("violation record");
            assert_eq!(v.reason, want, "{t:?}");
        }
        let v = judge_target(K::Hosts, E::Other, T::Regular, false)
            .expect_err("bad etc")
            .violation
            .expect("violation record");
        assert_eq!(v.reason, ViolationReason::PathSymlinkOrNotDirectory);
        for e in [E::Missing, E::Other] {
            assert_eq!(
                judge_target(K::Hosts, e, T::Regular, false)
                    .expect_err("bad etc")
                    .code,
                ErrorCode::InvalidArgument,
                "{e:?}"
            );
        }
    }

    #[test]
    fn net12_judge_flags_requires_nosuid_nodev_noexec_and_matching_ro() {
        assert!(judge_flags(flags(false, true), false).is_ok());
        assert!(judge_flags(flags(true, true), true).is_ok());
        assert!(judge_flags(flags(false, false), false).is_err());
        assert!(judge_flags(flags(true, true), false).is_err());
        assert!(judge_flags(flags(false, true), true).is_err());
        assert!(judge_flags(MountFlags::from_bits(0), false).is_err());
    }

    /// 偽の差し込み点を持つ試験用の rootfs。`etc/` と、元になる通常ファイルを持つ。
    struct Fx {
        tmp: TestTempDir,
        attached: Cell<bool>,
        calls: RefCell<Vec<String>>,
        /// 付け替えで失敗させる呼び出し番号(0 始まり)。
        fail_attach_at: Cell<Option<usize>>,
        attach_count: Cell<usize>,
        shared: Cell<bool>,
    }

    impl Fx {
        fn new() -> Self {
            let tmp = TestTempDir::new("etc-mounts").expect("tmp");
            std::fs::create_dir_all(tmp.path().join("root/etc")).expect("mkdir");
            std::fs::create_dir_all(tmp.path().join("src")).expect("mkdir");
            Self {
                tmp,
                attached: Cell::new(false),
                calls: RefCell::new(Vec::new()),
                fail_attach_at: Cell::new(None),
                attach_count: Cell::new(0),
                shared: Cell::new(false),
            }
        }

        fn root(&self) -> PathBuf {
            self.tmp.path().join("root")
        }

        fn source(&self, name: &str) -> VerifiedBindSourceFd {
            let p = self.tmp.path().join("src").join(name);
            std::fs::write(&p, b"x").expect("write");
            let parent = sys::open_dir_path_nofollow(
                None,
                &CString::new(p.parent().expect("parent").as_os_str().as_bytes()).expect("c"),
            )
            .expect("open parent");
            let leaf = CString::new(name).expect("c");
            let fd = sys::open_path_nofollow(parent.as_fd(), &leaf).expect("open");
            sys::verify_bind_source_fd(fd).expect("verified")
        }

        fn run(
            &self,
            kinds: &[(EtcFileKind, VerifiedBindSourceFd)],
            read_only: bool,
        ) -> Result<EtcFilesReport, ExecError> {
            let root = sys::open_dir_path_nofollow(
                None,
                &CString::new(self.root().as_os_str().as_bytes()).expect("c"),
            )
            .expect("root");
            let sources: Vec<(EtcFileKind, VerifiedBindSourceFd)> = kinds
                .iter()
                .map(|(k, s)| {
                    let dup = s.as_fd().try_clone_to_owned().expect("dup");
                    (*k, sys::verify_bind_source_fd(dup).expect("verified"))
                })
                .collect();
            let deps = Deps {
                is_shared: &|_| Ok(self.shared.get()),
                still_at: &|_, _| true,
                open_tree: &|src| {
                    self.calls.borrow_mut().push("open_tree".into());
                    src.as_fd()
                        .try_clone_to_owned()
                        .map_err(|_| SysError::Os(sys::EINVAL))
                },
                set_attrs: &|_, a| {
                    self.calls
                        .borrow_mut()
                        .push(format!("attrs ro={} noexec={}", a.read_only, a.noexec));
                    Ok(())
                },
                flags_of: &|_| Ok(flags(read_only, true)),
                attach: &|_, _| {
                    let n = self.attach_count.get();
                    self.attach_count.set(n + 1);
                    if self.fail_attach_at.get() == Some(n) {
                        return Err(SysError::Os(sys::EINVAL));
                    }
                    self.calls.borrow_mut().push("attach".into());
                    self.attached.set(true);
                    Ok(())
                },
                // 付け替え前は 1、付け替え後は 100(自分のマウントと名前で開き直した先が一致する)。
                mnt_id: &|_| Ok(if self.attached.get() { 100 } else { 1 }),
                umount: &|_| {
                    self.calls.borrow_mut().push("umount".into());
                    Ok(())
                },
            };
            let host_root = self.root();
            // 偽の attach は何も載せないため、事後検証の `(dev, ino)` 照合は「先が元と同じ inode(ハードリンク)」の
            // 構成だけが通る。先を作る経路は照合で失敗し、後始末で作ったファイルが消えることを確かめる。
            mount_etc_files_at(root.as_fd(), &host_root, sources, read_only, &deps)
        }
    }

    /// 先に元と同じ inode のファイルを置く(ハードリンク)。偽の attach 後の事後検証の `(dev, ino)` 照合を通すため。
    fn link_target(fx: &Fx, name: &str) {
        std::fs::hard_link(
            fx.tmp.path().join("src").join(name),
            fx.root().join("etc").join(name),
        )
        .expect("link");
    }

    /// NET-12: 既存の通常ファイルへ載せる順序と属性(rw では `ro=false noexec=true`)を具体値で照合する。
    #[test]
    fn net12_mounts_in_order_with_nosuid_nodev_noexec_attrs() {
        let fx = Fx::new();
        let src = fx.source("hosts");
        link_target(&fx, "hosts");
        let report = fx.run(&[(EtcFileKind::Hosts, src)], false).expect("mount");
        assert_eq!(
            report.mounts,
            vec![EtcFileOutcome {
                kind: EtcFileKind::Hosts,
                destination: "/etc/hosts",
                read_only: false,
                created_target: false,
            }]
        );
        assert_eq!(
            *fx.calls.borrow(),
            vec!["open_tree", "attrs ro=false noexec=true", "attach"]
        );
    }

    /// 実効 root.readonly では ro で載せる。
    #[test]
    fn net12_read_only_rootfs_mounts_ro() {
        let fx = Fx::new();
        let src = fx.source("resolv.conf");
        link_target(&fx, "resolv.conf");
        let report = fx
            .run(&[(EtcFileKind::ResolvConf, src)], true)
            .expect("mount ro");
        assert!(report.mounts.iter().all(|m| m.read_only));
        assert!(
            fx.calls
                .borrow()
                .contains(&"attrs ro=true noexec=true".to_string())
        );
    }

    /// 先が symlink なら InvalidArgument で、symlink の先(rootfs の外)に何も作られず、何も載せない。
    #[test]
    fn sec1_symlink_destination_is_rejected_without_touching_the_link_target() {
        let fx = Fx::new();
        let outside = fx.tmp.path().join("outside");
        std::os::unix::fs::symlink(&outside, fx.root().join("etc/hosts")).expect("symlink");
        let src = fx.source("hosts");
        let err = fx
            .run(&[(EtcFileKind::Hosts, src)], false)
            .expect_err("symlink");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(!outside.exists());
        assert!(fx.calls.borrow().is_empty());
    }

    /// `/etc` が symlink なら InvalidArgument で、リンク先に何も作られない。
    #[test]
    fn sec1_symlinked_etc_is_rejected_without_creating_anything() {
        let fx = Fx::new();
        std::fs::remove_dir(fx.root().join("etc")).expect("rmdir");
        let outside = fx.tmp.path().join("outside-etc");
        std::fs::create_dir(&outside).expect("mkdir");
        std::os::unix::fs::symlink(&outside, fx.root().join("etc")).expect("symlink");
        let src = fx.source("hosts");
        let err = fx
            .run(&[(EtcFileKind::Hosts, src)], false)
            .expect_err("symlink etc");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_dir(&outside).expect("rd").count(), 0);
    }

    /// rw で先が無ければ空ファイル(0644)を作る。ro で先が無ければ FailedPrecondition で何も作らない。
    #[test]
    fn net12_missing_destination_is_created_only_on_writable_rootfs() {
        let fx = Fx::new();
        let src = fx.source("hosts");
        // 偽の attach の後の inode 照合は、作った空ファイルが元と別 inode のため失敗し、作ったファイルは消える。
        let err = fx
            .run(&[(EtcFileKind::Hosts, src)], false)
            .expect_err("inode differs under the fake attach");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(
            !fx.root().join("etc/hosts").exists(),
            "created file removed on rollback"
        );
        assert!(fx.calls.borrow().contains(&"umount".to_string()));

        let fx = Fx::new();
        let src = fx.source("hosts");
        let err = fx.run(&[(EtcFileKind::Hosts, src)], true).expect_err("ro");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(!fx.root().join("etc/hosts").exists());
        assert!(fx.calls.borrow().is_empty());
    }

    /// 2 件目の付け替えが失敗したら、1 件目のマウントを外す(umount)。
    #[test]
    fn net12_second_failure_rolls_back_the_first_mount() {
        let fx = Fx::new();
        let a = fx.source("hosts");
        let b = fx.source("resolv.conf");
        link_target(&fx, "hosts");
        link_target(&fx, "resolv.conf");
        fx.fail_attach_at.set(Some(1));
        let err = fx
            .run(
                &[(EtcFileKind::Hosts, a), (EtcFileKind::ResolvConf, b)],
                false,
            )
            .expect_err("second attach fails");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        let calls = fx.calls.borrow();
        assert_eq!(calls.iter().filter(|c| *c == "attach").count(), 1);
        assert_eq!(calls.iter().filter(|c| *c == "umount").count(), 1);
    }

    /// shared の上には載せない。
    #[test]
    fn sec1_shared_destination_is_rejected_before_clone() {
        let fx = Fx::new();
        let src = fx.source("hosts");
        link_target(&fx, "hosts");
        fx.shared.set(true);
        let err = fx
            .run(&[(EtcFileKind::Hosts, src)], false)
            .expect_err("shared");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(fx.calls.borrow().is_empty());
    }

    /// 空の選択の verify は空の集合を返し、何も検査しない。
    #[test]
    fn net12_verify_with_empty_selection_is_empty() {
        let m = EtcFileMounts::verify(
            Path::new("/nonexistent-state-root"),
            &ContainerId::new("c1").expect("id"),
            EtcFileSelection::default(),
            false,
        )
        .expect("empty");
        assert!(m.is_empty());
    }

    /// verify は生成物を検査して記録し、子の辿り直しが `(dev, ino)` の食い違いを拒否する。
    #[test]
    fn net12_verify_records_files_and_open_sources_detects_replacement() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TestTempDir::new("etc-verify").expect("tmp");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let cid = ContainerId::new("c1").expect("id");
        let sel = EtcFileSelection::default()
            .with(EtcFileKind::Hosts)
            .with(EtcFileKind::ResolvConf);
        crate::etc_files::create_etc_files(dir.path(), &cid, sel).expect("create");
        let m = EtcFileMounts::verify(dir.path(), &cid, sel, false).expect("verify");
        assert_eq!(m.kinds(), vec![EtcFileKind::Hosts, EtcFileKind::ResolvConf]);
        assert_eq!(m.open_sources().expect("reopen").len(), 2);
        // 差し替え(別 inode)は拒否する。
        let p = etc_file_path(
            &std::fs::canonicalize(dir.path()).expect("canon"),
            &cid,
            EtcFileKind::Hosts,
        );
        // 旧ファイルが残っている間に新 inode を確保する(remove 直後の再作成だと inode 番号が再利用されうる)。
        let tmp = p.with_extension("new");
        std::fs::write(&tmp, b"other").expect("write");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        std::fs::rename(&tmp, &p).expect("rename");
        let err = m.open_sources().expect_err("replaced");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    /// verify は他者に開いたファイル(0666)・ハードリンク付き・symlink を拒否する。
    #[test]
    fn sec1_verify_rejects_writable_hardlinked_and_symlinked_sources() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TestTempDir::new("etc-verify-bad").expect("tmp");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let cid = ContainerId::new("c1").expect("id");
        let sel = EtcFileSelection::default().with(EtcFileKind::Hosts);
        crate::etc_files::create_etc_files(dir.path(), &cid, sel).expect("create");
        let canon = std::fs::canonicalize(dir.path()).expect("canon");
        let p = etc_file_path(&canon, &cid, EtcFileKind::Hosts);
        // 0666
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        assert_eq!(
            EtcFileMounts::verify(dir.path(), &cid, sel, false)
                .expect_err("0666")
                .code,
            ErrorCode::FailedPrecondition
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        // ハードリンク(nlink 2)
        std::fs::hard_link(&p, canon.join("alias")).expect("link");
        assert_eq!(
            EtcFileMounts::verify(dir.path(), &cid, sel, false)
                .expect_err("nlink")
                .code,
            ErrorCode::FailedPrecondition
        );
        std::fs::remove_file(canon.join("alias")).expect("rm");
        // symlink
        std::fs::remove_file(&p).expect("rm");
        std::os::unix::fs::symlink(canon.join("elsewhere"), &p).expect("symlink");
        assert_eq!(
            EtcFileMounts::verify(dir.path(), &cid, sel, false)
                .expect_err("symlink")
                .code,
            ErrorCode::FailedPrecondition
        );
    }
}
