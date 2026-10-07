//! rootfs 配下への tmpfs マウント（SUP-12・TASK-169.2・MS-9。`--shm-size` / `--tmpfs`）。
//!
//! # 役割と呼び出し文脈
//!
//! supervisor の `container_options` が解析した [`TmpfsMountSet`] を、`crate::exec` の最小実行フローの
//! 「[`prepare_rootfs`](super::prepare_rootfs) の後・[`pivot_root`](super::pivot_root) の前」で実マウントする。
//! `/dev/shm` を含む場合は [`create_default_devices`](super::create_default_devices) の後に呼ぶ。
//!
//! ```text
//! prepare_rootfs -> create_default_devices -> mount_tmpfs(&isolation, &prepared, &set) -> pivot_root
//! ```
//!
//! # 契約
//!
//! - **fd 起点**: [`PreparedRootfs`] の新しい mount top の fd から、正規化済みのマウント先を 1 要素ずつ
//!   `O_PATH|O_DIRECTORY|O_NOFOLLOW` で辿る。存在しない要素は 0755 で作り、同じ方法で開き直す。
//!   symlink・非ディレクトリは `path_symlink_or_not_directory` の違反記録付きで拒否する（rootfs の外へ
//!   マウントしない）。マウント先は検証済みの fd のまま新マウント API へ渡し（`move_mount(2)` の空パス +
//!   fd 指定）、`mount(2)`・パス文字列（`/proc/thread-self/fd/N` を含む）・`data` 文字列を使わない
//! - **ホストへ伝播させない**: マウント直前に対象マウントが shared propagation でないことを確認する
//! - **移動検査**: fd 固定後にマウント先（または祖先）が改名・移動・削除されていないことを、マウント
//!   直前に fd の現在の位置で確かめる（`mount_proc` と同じ `fd_still_at`。`target_moved` の違反記録付きで
//!   拒否）。移動後の実体へマウントして rootfs 内の別の場所を覆わないようにする
//! - **フラグ・オプション**: `nosuid`・`nodev` は常に付与し外せない。`mode`・`size`・`ro` は型付きフィールド
//!   から `fsconfig(2)` へキー単位で渡し（値は整数から生成）、利用者文字列は渡さない。`fsmount(2)` が返す
//!   fd が自分のマウントを一意に指す
//! - **対応カーネル**: Linux 5.2 以降（`fsopen`・`fsconfig`・`fsmount`・`move_mount`）。未対応（`ENOSYS`）は
//!   `mount(2)` へ縮退せず、`unimplemented` で拒否する（fail-closed）
//! - **事後条件**: マウント後に同じ要素を開き直し（作成はしない）、`statfs` が tmpfs であること、マウント前
//!   に固定した fd とは別のマウントであること、さらに **自分のマウント（`fsmount` の fd）と同じマウント ID**
//!   であることを確かめる（fail-closed。固定後に名前の位置が差し替えられていれば検出する）
//! - **エラー message**: マウント先を message に入れるときは、違反記録（`ViolationSubject`）と同じ
//!   エスケープ（制御文字・`\\`）と切り詰め（256 文字）を通す（ログ注入の防止）
//! - **失敗時の後始末**: rootfs はホスト上のディレクトリの bind mount のため、自動作成したマウント先
//!   ディレクトリはプロセスを破棄しても残る。失敗時は、この呼び出しでマウントした tmpfs を逆順に
//!   `umount2(MNT_DETACH)` で外し、この呼び出しの `mkdirat` が成功した要素だけを逆順に `unlinkat(AT_REMOVEDIR)`
//!   で削除する（空ディレクトリしか消えないため、既存の内容は消さない）。後始末は最善努力で、失敗しても
//!   元のエラーを返す。fd 固定後に第三者が改名した要素は追跡しない。呼び出し後もプロセスは破棄する
//!   （`crate::exec` のモジュール doc の契約）。自分のマウントは付け替え直後に fd を保持するため、事後検証に
//!   通らなかった件も外せる
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! 本番 launcher・CLI・stack（TOML）からの配線（TASK-79・TASK-169 の後続）、`--shm-size` 未指定時の
//! `/dev/shm` 既定 64 MiB の常時マウント、OCI `mounts[]` 全般（TASK-127・TASK-29 系）。
//!
//! # 単体テストの安全策
//!
//! 新マウント API は `cfg(test)` では dry-run に差し替わる（`mount_tmpfs_syscall`）。実機での挙動は結合試験
//! `tests/tmpfs_mount.rs`（`-- --ignored`）で確認する。

use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::PathBuf;

use crate::sys::{self, SysError};
use crate::tmpfs::{TmpfsMountSet, TmpfsMountSpec};
use crate::traits::types::ErrorCode;

use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, ViolationSubject,
    fd_still_at, mount_is_shared, open_error,
};

/// 結合試験専用の入口 [`mount_tmpfs_with_attach_hook`] が、検査後・付け替え前に呼ぶ処理の型。
type AttachHook<'a> = &'a dyn Fn();

const STAGE: IsolationStage = IsolationStage::MountTmpfs;

/// 作成するマウント先ディレクトリのモード。
pub(super) const DIR_MODE: u32 = 0o755;

/// 適用した tmpfs 1 件の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TmpfsMountOutcome {
    /// コンテナ内のマウント先（正規化済み）。
    pub destination: String,
    /// 指定したサイズ（バイト）。`None` はカーネル既定。
    pub size: Option<u64>,
    /// 読み取り専用でマウントしたか。
    pub read_only: bool,
    /// 実行を許したか（偽なら `noexec`）。
    pub exec: bool,
}

/// [`mount_tmpfs`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TmpfsReport {
    /// 指定順に適用した結果。
    pub mounts: Vec<TmpfsMountOutcome>,
}

/// `set` の tmpfs を rootfs（`prepared` の新しい mount top）配下へ指定順にマウントする。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。
/// 詳細な契約はモジュール doc を参照。
pub fn mount_tmpfs(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &TmpfsMountSet,
) -> Result<TmpfsReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    mount_tmpfs_at(
        prepared.new_root(),
        set,
        &|dir| mount_is_shared(dir, STAGE),
        &|| {},
    )
}

/// 結合試験専用: [`mount_tmpfs`] と同じ検査・マウントを行い、各件の「移動検査の後・付け替えの直前」で `hook`
/// を呼ぶ（SUP-12・TASK-169 追補・#1472。検査後にマウント先を差し替えられても別の場所へ載らないことを、
/// 実マウントで決定的に照合するため）。検証は緩めず、検査後に任意処理を挟むだけ。`exec-test-support`
/// feature を付けたビルドにだけ存在し、通常の利用者は呼ばない。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn mount_tmpfs_with_attach_hook(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &TmpfsMountSet,
    hook: &dyn Fn(),
) -> Result<TmpfsReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    mount_tmpfs_at(
        prepared.new_root(),
        set,
        &|dir| mount_is_shared(dir, STAGE),
        hook,
    )
}

/// [`mount_tmpfs`] の証跡検証後の本体。`root` は rootfs（新しい mount top）の fd、`is_shared` は
/// マウント先が shared propagation かの判定（単体テストは host の mountinfo に依存しないよう差し替える）。
/// `before_attach` は移動検査の後・付け替えの直前に呼ぶ（本番は空。結合試験専用の入口だけが差し込む）。
fn mount_tmpfs_at(
    root: BorrowedFd<'_>,
    set: &TmpfsMountSet,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    before_attach: AttachHook<'_>,
) -> Result<TmpfsReport, ExecError> {
    let rootfs = root_display(root);
    // 件数は `TmpfsMountSet`（`TMPFS_MAX_MOUNTS` 以下）で上限が決まっている。
    let mut mounts = Vec::with_capacity(set.mounts().len());
    let mut applied: Vec<Applied<'_>> = Vec::with_capacity(set.mounts().len());
    for spec in set.mounts() {
        let mut state = Applied {
            names: spec
                .destination
                .as_str()
                .split('/')
                .filter(|e| !e.is_empty())
                .map(OsStr::new)
                .collect(),
            created: Vec::new(),
            mounted: None,
        };
        let result = apply_one(root, &rootfs, spec, &mut state, is_shared, before_attach);
        applied.push(state);
        if let Err(e) = result {
            roll_back(root, &rootfs, &applied);
            return Err(e);
        }
        mounts.push(TmpfsMountOutcome {
            destination: spec.destination.as_str().to_owned(),
            size: spec.size.map(|s| s.bytes()),
            read_only: spec.read_only,
            exec: spec.exec,
        });
    }
    Ok(TmpfsReport { mounts })
}

/// 1 件の適用で rootfs・mount namespace に加えた変更の記録（失敗時の [`roll_back`] が使う）。
pub(super) struct Applied<'a> {
    /// マウント先の要素列（正規化済み）。
    pub(super) names: Vec<&'a OsStr>,
    /// この呼び出しの `mkdirat` が成功した要素の添字（昇順。既存・競合で先に作られた要素は含めない）。
    pub(super) created: Vec<usize>,
    /// 付け替えた「自分のマウントのルート」を指す fd（`fsmount` の戻り値。付け替え直後に保持し、事後検証に
    /// 通らなくても失敗時の後始末が外せる。付け替え前は `None`）。
    pub(super) mounted: Option<OwnedFd>,
}

/// 失敗時の後始末（最善努力）。新しい順に、マウントした tmpfs を外してから、作成した要素を深い順に消す。
///
/// 解除するのは、付け替え時に得た自分のマウントの fd が指すマウントだけで、名前から開き直した先は
/// 解除しない（適用後に名前の位置が差し替わっていても、別のマウントを外さない）。作成した要素は `root` から名前で辿り
/// （symlink は辿らない）、`unlinkat(AT_REMOVEDIR)` は空ディレクトリしか消さないため既存の内容は壊さない。
/// 途中で失敗した件はそこで打ち切り、残りの件は続ける。
pub(super) fn roll_back(root: BorrowedFd<'_>, rootfs: &std::path::Path, applied: &[Applied<'_>]) {
    use std::os::unix::ffi::OsStrExt as _;
    for state in applied.iter().rev() {
        if let Some(dir) = &state.mounted
            && let Ok(target) = CString::new(format!("/proc/thread-self/fd/{}", dir.as_raw_fd()))
        {
            let _ = umount_tmpfs_syscall(&target);
        }
        for &index in state.created.iter().rev() {
            let (Some(name), Some(prefix)) = (state.names.get(index), state.names.get(..index))
            else {
                break;
            };
            let Ok(c_name) = CString::new(name.as_bytes()) else {
                break;
            };
            let parent_fd = if prefix.is_empty() {
                None
            } else {
                match open_chain(root, rootfs, prefix, None) {
                    Ok(fd) => Some(fd),
                    Err(_) => break,
                }
            };
            let parent = parent_fd.as_ref().map_or(root, |f| f.as_fd());
            if sys::remove_dir_at(parent, &c_name).is_err() {
                break;
            }
        }
    }
}

fn apply_one(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    spec: &TmpfsMountSpec,
    state: &mut Applied<'_>,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    before_attach: AttachHook<'_>,
) -> Result<(), ExecError> {
    let names = state.names.clone();
    let dir = open_chain(root, rootfs, &names, Some(&mut state.created))?;
    let subject = names.iter().fold(rootfs.to_path_buf(), |p, n| p.join(n));
    if is_shared(&dir)? {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetOnSharedMount,
            Some(&subject),
            STAGE,
        ));
    }
    // fd 固定後に別プロセスがマウント先（または祖先）を改名・移動・削除していれば拒否する
    // （`mount_proc_at_dir` と同じ検査）。この確認から付け替えまでに移動された場合も、付け替えは固定した fd
    // （検証済みの実体）にしか載らず rootfs の別の場所を覆わない。マウントは呼び出しスレッド専用の
    // mount namespace に閉じ、事後条件（`verify_mounted`）が名前の位置に自分のマウントが無いことを検出して
    // 失敗させ、後始末が自分のマウントを fd で外す。
    if !fd_still_at(&dir, &subject) {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetMoved,
            Some(&subject),
            STAGE,
        ));
    }
    before_attach();
    let create = sys::TmpfsCreate {
        mode: spec.mode.bits(),
        size: spec.size.map(|s| s.bytes()),
        flags: sys::TmpfsMountFlags {
            read_only: spec.read_only,
            exec: spec.exec,
        },
    };
    // 付け替え直後に自分のマウントの fd を保持する（事後検証に通らなくても後始末が外せる）。
    let mount_fd = mount_tmpfs_syscall(dir.as_fd(), create)
        .map_err(|e| tmpfs_mount_error(e, spec.destination.as_str()))?;
    let mount_fd = &*state.mounted.insert(mount_fd);
    verify_mounted(
        root,
        rootfs,
        &names,
        spec.destination.as_str(),
        &dir,
        mount_fd,
    )
}

/// 新マウント API の失敗をエラーにする。`Unsupported`（`ENOSYS`・対応外アーキテクチャ）は縮退せず
/// `unimplemented` で拒否する（Linux 5.2 以降が必要。SUP-12・TASK-169 追補・#1472）。
pub(super) fn tmpfs_mount_error(e: SysError, destination: &str) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        return ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "tmpfs mount requires the new mount API (fsopen, fsconfig, fsmount, move_mount; Linux 5.2 or later)",
        );
    }
    ExecError::from_sys(
        e,
        STAGE,
        &format!("mount(tmpfs on {})", display_destination(destination)),
    )
}

/// `root` から `names` を 1 要素ずつ `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開く。
///
/// `created` が `Some` なら、無い要素を 0755 で作ってから同じ方法で開き直し、`mkdirat` が成功した要素の
/// 添字を追記する（途中で失敗しても、それまでに作った分は残る。マウント先の準備）。`None` なら作らずに
/// `path_missing` の違反記録付きで拒否する（事後検証・後始末。副作用を持たせない）。
pub(super) fn open_chain(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    names: &[&OsStr],
    mut created: Option<&mut Vec<usize>>,
) -> Result<OwnedFd, ExecError> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut cur: Option<OwnedFd> = None;
    for (index, name) in names.iter().enumerate() {
        let c = CString::new(name.as_bytes()).map_err(|_| {
            ExecError::from_violation_at(ViolationReason::PathContainsNul, Some(rootfs), STAGE)
        })?;
        let parent = cur.as_ref().map_or(root, |f| f.as_fd());
        let next = match sys::open_dir_path_nofollow(Some(parent), &c) {
            Ok(fd) => fd,
            Err(SysError::Os(sys::ENOENT)) if created.is_some() => {
                match sys::mkdir_at(parent, &c, DIR_MODE) {
                    Ok(()) => {
                        if let Some(list) = created.as_deref_mut() {
                            list.push(index);
                        }
                    }
                    Err(SysError::Os(sys::EEXIST)) => {}
                    Err(e) => return Err(ExecError::from_sys(e, STAGE, "mkdirat(mount target)")),
                }
                // 競合で先に作られた場合も、開き直しで種別（symlink・非ディレクトリ）を検証する。
                sys::open_dir_path_nofollow(Some(parent), &c)
                    .map_err(|e| open_error(e, true, rootfs, names).at_stage(STAGE))?
            }
            Err(e) => return Err(open_error(e, true, rootfs, names).at_stage(STAGE)),
        };
        cur = Some(next);
    }
    cur.ok_or_else(|| {
        ExecError::new(
            ErrorCode::InvalidArgument,
            STAGE,
            "tmpfs mount destination is empty",
        )
    })
}

/// マウント後に同じ要素を名前で開き直し、それが「マウント前に固定した `before` とは別のマウントに属する
/// tmpfs」で、かつ「自分のマウント（`mount_fd`）」そのものであることを確かめる。
///
/// 観測は cfg で差し替わる [`observe_mount`] を介すだけで、`cfg(test)` の分岐は持たない（判定本体
/// [`check_new_tmpfs`] は単体で試験する）。`mount_fd` は呼び出し側が先に `Applied::mounted` へ保持して
/// おり、検証に失敗しても [`roll_back`] が外せる。
pub(super) fn verify_mounted(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    names: &[&OsStr],
    destination: &str,
    before: &OwnedFd,
    mount_fd: &OwnedFd,
) -> Result<(), ExecError> {
    let after = open_chain(root, rootfs, names, None)?;
    let observed = observe_mount(before, &after, mount_fd)?;
    check_new_tmpfs(observed, destination)
}

/// マウント前後の fd の観測値（[`check_new_tmpfs`] の入力）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountObservation {
    /// 開き直した fd の `statfs.f_type`。
    magic: i64,
    /// マウント前に固定した fd が属するマウントの ID。
    before_mnt_id: u64,
    /// 開き直した fd が属するマウントの ID。
    after_mnt_id: u64,
    /// 自分のマウント（`fsmount` の fd）の ID。
    own_mnt_id: u64,
}

#[cfg(not(test))]
fn observe_mount(
    before: &OwnedFd,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::fs_type(after.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(tmpfs mount target)"))?,
        before_mnt_id: super::fd_mount_id(before, STAGE)?,
        after_mnt_id: super::fd_mount_id(after, STAGE)?,
        own_mnt_id: super::fd_mount_id(own, STAGE)?,
    })
}

/// dry-run: 実マウントが無いため「別マウントの tmpfs で自分のマウント」を観測したことにする（実機の検証は結合試験で行う）。
#[cfg(test)]
fn observe_mount(
    _before: &OwnedFd,
    _after: &OwnedFd,
    _own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::TMPFS_MAGIC,
        before_mnt_id: 1,
        after_mnt_id: 2,
        own_mnt_id: 2,
    })
}

/// エラー message に入れるマウント先の表示形。違反記録と同じ `ViolationSubject` のエスケープ（制御文字・
/// `\\` を `char::escape_default` 形式へ）と切り詰め（`VIOLATION_SUBJECT_MAX_CHARS` 文字）を通す。
/// マウント先は NUL と `\\` 以外の制御文字（改行・ESC 等）を含み得るため、そのまま入れるとログ注入になる。
pub(super) fn display_destination(destination: &str) -> String {
    ViolationSubject::from_path(std::path::Path::new(destination))
        .as_str()
        .to_owned()
}

/// 事後条件の判定（純関数）。開き直した先が tmpfs で、マウント前とは別のマウントで、かつ自分のマウントで
/// なければ拒否する（rootfs 自体が tmpfs の場合に、マウントが名前の位置に無いのを tmpfs と誤認しないため。
/// 別の tmpfs が名前の位置に差し込まれていても、自分のマウントでなければ通さない）。
fn check_new_tmpfs(observed: MountObservation, destination: &str) -> Result<(), ExecError> {
    let destination = display_destination(destination);
    if observed.magic != sys::TMPFS_MAGIC {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the mount at {destination} is not tmpfs after mount"),
        ));
    }
    if observed.after_mnt_id == observed.before_mnt_id {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("no new mount is present at {destination} after mount"),
        ));
    }
    if observed.after_mnt_id != observed.own_mnt_id {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the mount at {destination} is not the mount created by this call"),
        ));
    }
    Ok(())
}

/// 違反記録の対象表示用に rootfs の実パスを得る（取れなければ固定文字列）。
pub(super) fn root_display(root: BorrowedFd<'_>) -> PathBuf {
    std::fs::read_link(format!("/proc/thread-self/fd/{}", root.as_raw_fd()))
        .unwrap_or_else(|_| PathBuf::from("<rootfs>"))
}

#[cfg(not(test))]
pub(super) fn mount_tmpfs_syscall(
    target_dir: BorrowedFd<'_>,
    create: sys::TmpfsCreate,
) -> Result<OwnedFd, SysError> {
    sys::mount_tmpfs_on(target_dir, create)
}

/// dry-run: 新マウント API を呼ばず、(付け替え先の fd が指す実体・attr フラグ・`mode`/`size` の表記) を記録し、
/// 付け替え先の fd の複製を「自分のマウント」として返す（実機の挙動は結合試験で確かめる）。
#[cfg(test)]
pub(super) fn mount_tmpfs_syscall(
    target_dir: BorrowedFd<'_>,
    create: sys::TmpfsCreate,
) -> Result<OwnedFd, SysError> {
    let resolved = std::fs::read_link(format!("/proc/thread-self/fd/{}", target_dir.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut options = format!("mode={:04o}", create.mode);
    if let Some(size) = create.size {
        options.push_str(&format!(",size={size}"));
    }
    tests::CALLS.with(|c| {
        c.borrow_mut()
            .push((resolved, u64::from(create.flags.attr_bits()), options))
    });
    target_dir
        .try_clone_to_owned()
        .map_err(|_| SysError::Os(sys::EBADF))
}

#[cfg(not(test))]
fn umount_tmpfs_syscall(target: &std::ffi::CStr) -> Result<(), SysError> {
    sys::umount_detach_at(target)
}

/// dry-run: `umount2(2)` を呼ばず、解決した対象を記録する。
#[cfg(test)]
fn umount_tmpfs_syscall(target: &std::ffi::CStr) -> Result<(), SysError> {
    let resolved = std::fs::read_link(target.to_string_lossy().as_ref())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::UMOUNTS.with(|c| c.borrow_mut().push(resolved));
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::symlink;

    thread_local! {
        pub(in crate::exec) static CALLS: std::cell::RefCell<Vec<(String, u64, String)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    thread_local! {
        pub(in crate::exec) static UMOUNTS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    pub(in crate::exec) fn take_umounts() -> Vec<String> {
        UMOUNTS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    pub(in crate::exec) fn take_calls() -> Vec<(String, u64, String)> {
        CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    pub(in crate::exec) struct Tmp(pub(in crate::exec) PathBuf);
    impl Tmp {
        pub(in crate::exec) fn new(tag: &str) -> Self {
            let p = std::fs::canonicalize(std::env::temp_dir())
                .expect("tmp")
                .join(format!("fandhe-tmpfs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }
        pub(in crate::exec) fn fd(&self) -> OwnedFd {
            sys::open_dir_path_nofollow(
                None,
                &CString::new(self.0.to_str().expect("utf8")).expect("c"),
            )
            .expect("open")
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set(specs: &[(&str, Option<u64>)]) -> TmpfsMountSet {
        let mut s = TmpfsMountSet::new();
        for (d, size) in specs {
            let size = size.map(|b| crate::tmpfs::TmpfsSize::from_bytes(b).expect("size"));
            s.push(TmpfsMountSpec::new(d, size).expect("spec"))
                .expect("push");
        }
        s
    }

    fn not_shared(_: &OwnedFd) -> Result<bool, ExecError> {
        Ok(false)
    }

    /// SUP-12・TASK-169.2: 指定順に適用し、フラグ・data が具体値で一致し、先を自動作成する。
    #[test]
    fn sup12_task169_2_applies_in_order_and_creates_targets() {
        let tmp = Tmp::new("order");
        let _ = take_calls();
        let fd = tmp.fd();
        let s = set(&[("/dev/shm", Some(65536)), ("/scratch/a", None)]);
        let report = mount_tmpfs_at(fd.as_fd(), &s, &not_shared, &|| {}).expect("mount");
        let calls = take_calls();
        let nosuid_nodev_noexec = 2 | 4 | 8;
        assert_eq!(
            calls,
            vec![
                (
                    tmp.0.join("dev/shm").to_string_lossy().into_owned(),
                    nosuid_nodev_noexec,
                    "mode=1777,size=65536".to_owned()
                ),
                (
                    tmp.0.join("scratch/a").to_string_lossy().into_owned(),
                    nosuid_nodev_noexec,
                    "mode=1777".to_owned()
                ),
            ]
        );
        assert!(tmp.0.join("dev/shm").is_dir());
        assert!(tmp.0.join("scratch/a").is_dir());
        assert_eq!(report.mounts.len(), 2);
        assert_eq!(report.mounts[0].destination, "/dev/shm");
        assert_eq!(report.mounts[0].size, Some(65536));
        assert_eq!(report.mounts[1].size, None);
    }

    /// SUP-12・TASK-169.2: 途中要素が symlink なら rootfs の外へ出さず違反記録付きで拒否する。
    #[test]
    fn sup12_task169_2_rejects_symlink_component() {
        let tmp = Tmp::new("symlink");
        let _ = take_calls();
        std::fs::create_dir_all(tmp.0.join("outside")).expect("outside");
        symlink(tmp.0.join("outside"), tmp.0.join("link")).expect("symlink");
        let fd = tmp.fd();
        let err = mount_tmpfs_at(fd.as_fd(), &set(&[("/link/x", None)]), &not_shared, &|| {})
            .expect_err("symlink");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert!(take_calls().is_empty());
        assert!(!tmp.0.join("outside/x").exists());
    }

    /// SUP-12・TASK-169.2: shared propagation 上では mount せずに拒否する。
    #[test]
    fn sup12_task169_2_rejects_shared_mount() {
        let tmp = Tmp::new("shared");
        let _ = take_calls();
        let fd = tmp.fd();
        let err = mount_tmpfs_at(fd.as_fd(), &set(&[("/run", None)]), &|_| Ok(true), &|| {})
            .expect_err("shared");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert!(take_calls().is_empty());
        // マウント前に拒否した件も、自動作成したマウント先を残さない（外す対象は無い）。
        assert!(!tmp.0.join("run").exists());
        assert_eq!(take_umounts(), Vec::<String>::new());
    }

    /// SUP-12・TASK-169.2: fd 固定後にマウント先が改名されたら、移動後の実体へ mount せず
    /// `target_moved` の違反記録付きで拒否する（propagation 判定の差し込み点で改名して窓を再現する）。
    #[test]
    fn sup12_task169_2_rejects_target_moved_after_pin() {
        let tmp = Tmp::new("moved");
        let _ = take_calls();
        let fd = tmp.fd();
        let (from, to) = (tmp.0.join("run"), tmp.0.join("elsewhere"));
        let err = mount_tmpfs_at(
            fd.as_fd(),
            &set(&[("/run", None)]),
            &|_| {
                std::fs::rename(&from, &to).expect("rename");
                Ok(false)
            },
            &|| {},
        )
        .expect_err("moved");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetMoved)
        );
        assert_eq!(take_calls(), Vec::new());
    }

    /// SUP-12・TASK-169.2: 事後検証の開き直しは無い要素を作らず `path_missing` で拒否する。
    #[test]
    fn sup12_task169_2_reject_mode_does_not_create_missing() {
        let tmp = Tmp::new("nocreate");
        let fd = tmp.fd();
        let names = [OsStr::new("a"), OsStr::new("b")];
        let err = open_chain(fd.as_fd(), &tmp.0, &names, None).expect_err("missing");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathMissing)
        );
        assert!(!tmp.0.join("a").exists());
        std::fs::create_dir(tmp.0.join("a")).expect("pre-existing a");
        let mut created = Vec::new();
        open_chain(fd.as_fd(), &tmp.0, &names, Some(&mut created)).expect("create");
        assert!(tmp.0.join("a/b").is_dir());
        // 既存の `a` は含めず、自分で作った `b`（添字 1）だけを記録する。
        assert_eq!(created, vec![1]);
    }

    /// SUP-12・TASK-169.2: 後続の件が失敗したら、先にマウントした tmpfs を外し、自動作成した
    /// ディレクトリだけを消す（既存ディレクトリと中身は残す）。
    #[test]
    fn sup12_task169_2_failure_rolls_back_mounts_and_created_dirs() {
        let tmp = Tmp::new("rollback");
        let _ = (take_calls(), take_umounts());
        std::fs::create_dir_all(tmp.0.join("pre")).expect("pre");
        std::fs::write(tmp.0.join("pre/keep"), b"x").expect("keep");
        std::fs::create_dir_all(tmp.0.join("outside")).expect("outside");
        symlink(tmp.0.join("outside"), tmp.0.join("link")).expect("symlink");
        let fd = tmp.fd();
        let s = set(&[("/scratch/a", None), ("/pre/new", None), ("/link/x", None)]);
        let err = mount_tmpfs_at(fd.as_fd(), &s, &not_shared, &|| {}).expect_err("third fails");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert_eq!(take_calls().len(), 2);
        // 新しい順に外す。
        assert_eq!(
            take_umounts(),
            vec![
                tmp.0.join("pre/new").to_string_lossy().into_owned(),
                tmp.0.join("scratch/a").to_string_lossy().into_owned(),
            ]
        );
        assert!(!tmp.0.join("scratch").exists());
        assert!(!tmp.0.join("pre/new").exists());
        assert_eq!(std::fs::read(tmp.0.join("pre/keep")).expect("keep"), b"x");
        assert!(tmp.0.join("outside").is_dir());
    }

    /// SUP-12・TASK-169.2: 読み取り専用・exec 許可のフラグが反映される。
    #[test]
    fn sup12_task169_2_flags_reflect_spec() {
        let tmp = Tmp::new("flags");
        let _ = take_calls();
        let fd = tmp.fd();
        let mut s = TmpfsMountSet::new();
        let mut spec = TmpfsMountSpec::new("/ro", None).expect("spec");
        spec.read_only = true;
        spec.exec = true;
        s.push(spec).expect("push");
        mount_tmpfs_at(fd.as_fd(), &s, &not_shared, &|| {}).expect("mount");
        // MOUNT_ATTR_RDONLY(1)|NOSUID(2)|NODEV(4)、noexec なし。
        assert_eq!(take_calls().first().map(|c| c.1), Some(1 | 2 | 4));
    }

    /// SUP-12・TASK-169 追補（#1472）: 検査の後・付け替えの直前に名前の位置が差し替えられても、付け替えは
    /// 固定した実体（改名後の `elsewhere`）に対して行われ、新しく作られた同名の `run` へは行われない。
    #[test]
    fn sup12_task169_attaches_to_the_pinned_entry_not_the_name() {
        let tmp = Tmp::new("pinned");
        let _ = (take_calls(), take_umounts());
        let fd = tmp.fd();
        let (from, to) = (tmp.0.join("run"), tmp.0.join("elsewhere"));
        mount_tmpfs_at(fd.as_fd(), &set(&[("/run", None)]), &not_shared, &|| {
            std::fs::rename(&from, &to).expect("rename");
            std::fs::create_dir(&from).expect("replacement");
        })
        .expect("mount");
        let calls = take_calls();
        assert_eq!(
            calls.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
            vec![to.to_string_lossy().into_owned()]
        );
        assert_ne!(calls[0].0, from.to_string_lossy());
    }

    /// SUP-12・TASK-169 追補（#1472）: 付け替え後に名前の位置が自分のマウントでなければ拒否する。
    #[test]
    fn sup12_task169_post_condition_requires_own_mount() {
        let obs = MountObservation {
            magic: 0x0102_1994,
            before_mnt_id: 30,
            after_mnt_id: 31,
            own_mnt_id: 32,
        };
        let err = check_new_tmpfs(obs, "/run").expect_err("other tmpfs");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.message,
            "the mount at /run is not the mount created by this call"
        );
    }

    /// SUP-12・TASK-169 追補（#1472）: 未対応カーネル（`ENOSYS` 由来の `Unsupported`）は縮退せず
    /// `unimplemented` で拒否する。
    #[test]
    fn sup12_task169_unsupported_kernel_is_rejected_as_unimplemented() {
        let err = tmpfs_mount_error(SysError::Unsupported, "/run");
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert!(err.message.contains("Linux 5.2 or later"));
    }

    /// SUP-12・TASK-169.2: 事後条件は「マウント前とは別のマウントに属する tmpfs」だけを通す。
    #[test]
    fn sup12_task169_2_post_condition_requires_new_tmpfs_mount() {
        let obs = |magic, before_mnt_id, after_mnt_id| MountObservation {
            magic,
            before_mnt_id,
            after_mnt_id,
            own_mnt_id: after_mnt_id,
        };
        assert_eq!(check_new_tmpfs(obs(0x0102_1994, 30, 31), "/run"), Ok(()));
        let err = check_new_tmpfs(obs(0xEF53, 30, 31), "/run").expect_err("ext4");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(err.message, "the mount at /run is not tmpfs after mount");
        // rootfs 自体が tmpfs でも、同じマウントのままなら新しいマウントは無い。
        let err = check_new_tmpfs(obs(0x0102_1994, 30, 30), "/run").expect_err("same mount");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.message, "no new mount is present at /run after mount");
    }

    /// SUP-12・TASK-169.2・SEC-4: message に入れるマウント先は制御文字をエスケープし 256 文字で切り詰める。
    #[test]
    fn sup12_task169_2_destination_in_messages_is_escaped_and_bounded() {
        assert_eq!(
            display_destination("/a\nINJECTED\u{1b}[31m\r/b"),
            "/a\\nINJECTED\\u{1b}[31m\\r/b"
        );
        let long = format!("/{}", "x".repeat(400));
        assert_eq!(display_destination(&long), format!("/{}", "x".repeat(255)));
        let err = check_new_tmpfs(
            MountObservation {
                magic: 0xEF53,
                before_mnt_id: 1,
                after_mnt_id: 2,
                own_mnt_id: 2,
            },
            "/run\nlevel=error msg=forged",
        )
        .expect_err("not tmpfs");
        assert_eq!(
            err.message,
            "the mount at /run\\nlevel=error msg=forged is not tmpfs after mount"
        );
    }

    /// SUP-12・TASK-169.2: 後始末は検証済みの fd が指すマウントだけを外し、適用後に名前の位置が
    /// 差し替わっていても、名前から開き直した先は外さない。
    #[test]
    fn sup12_task169_2_roll_back_unmounts_only_the_verified_fd() {
        let tmp = Tmp::new("rbfd");
        let _ = take_umounts();
        std::fs::create_dir_all(tmp.0.join("ours")).expect("ours");
        let fd = tmp.fd();
        let ours = open_chain(fd.as_fd(), &tmp.0, &[OsStr::new("ours")], None).expect("open");
        // 適用後に名前 `ours` が別の実体へ差し替わった状況。
        std::fs::rename(tmp.0.join("ours"), tmp.0.join("moved")).expect("rename");
        std::fs::create_dir_all(tmp.0.join("ours")).expect("replacement");
        let applied = [
            Applied {
                names: vec![OsStr::new("ours")],
                created: Vec::new(),
                mounted: Some(ours),
            },
            // 事後検証に通っていない件は外さない。
            Applied {
                names: vec![OsStr::new("unverified")],
                created: Vec::new(),
                mounted: None,
            },
        ];
        roll_back(fd.as_fd(), &tmp.0, &applied);
        assert_eq!(
            take_umounts(),
            vec![tmp.0.join("moved").to_string_lossy().into_owned()]
        );
        assert!(tmp.0.join("ours").is_dir());
    }
}
