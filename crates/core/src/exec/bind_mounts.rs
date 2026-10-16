//! 検証済みの bind mount を pivot 前の rootfs へ fd 起点で適用する段（CORE-1・CORE-2・OCI-4・SEC-1・SEC-4・
//! SEC-5・TASK-29 追補・#1913。方針は #1910 のオーナー決定 2026-10-12・#1907 案 (a)）。
//!
//! # 役割と呼び出し文脈
//!
//! `config.json` の `mounts[]` のうち bind の指定は、[`BindMountSet::from_mounts`](crate::oci_runtime::BindMountSet)
//! （#1911）が字句検証済みの型へ変換する。本段はその型を、ホストのディレクトリ／ファイルをコンテナへ見せる
//! 分離の境界として、rootfs へ実際に載せる。tmpfs の段（`exec/tmpfs.rs`）・注入の段（`exec/inject.rs`）と同じ流儀で、
//! fd で固定し、shared の上には載せず、移動を検査し、`move_mount(2)` を fd で指定し、マウント ID で事後照合し、
//! 失敗時は自分が作ったものだけを戻す。`MountDestination::resolve_in` の文字列結合や `mount(2)` へのパス渡しは使わない。
//!
//! ```text
//! prepare_rootfs（と create_default_devices -> mount_tmpfs -> inject_files）-> mount_binds(&isolation, &prepared, &set)
//!   -> readonly_paths -> masked_paths -> pivot_root
//!                                                  ^ 同じスレッド・seccomp の適用前
//! ```
//!
//! 入口は検証済みの型（[`MountIsolation`]・[`PreparedRootfs`]・`BindMountSet`）だけを受け、生の `OciMount` や
//! パス文字列を受ける入口は持たない。`run_pre_pivot` へは組み込み済み（#1914。`inject_files` の後・`readonly_paths` の前に固定）。
//! `start` と本番 launcher への結線・`check_against_*` の呼び出しは #1915 で済み（`start` が host_paths・保護パス、launcher が tmpfs を検査する）。`/dev` の tmpfs を覆い隠す宛先は
//! `BindMountSet` が `/proc`・`/sys`・`/dev` とその配下を拒否するため型の上で作れず、`DeviceReport` の証跡は受けない。
//!
//! # マウント元をどのプロセスがどの権限で開くか
//!
//! 起動の連鎖は次のとおり。supervisor（C）は init user namespace で特権ランチャー由来の ambient capability を持つ。
//! 中間プロセス（I）が `isolate` で `unshare(CLONE_NEWUSER)` する。以後 I が持つ capability は子の user namespace の中
//! だけで、親（init）の namespace には効かない。I が fork した PID 1 は、その user namespace を引き継ぎ、
//! `establish` → `prepare_rootfs` → …… → 本段 → `pivot_root` と進む。
//!
//! **マウント元は PID 1 が本段の中で開く**。C と I は元を開かず、fd も渡さない（unshare 前に開いた fd は、`open_tree` が
//! 同じ mount namespace の fd を要求する〔`check_mnt`〕ため `EINVAL` になり、そもそも使えない）。user namespace の中の
//! `CAP_DAC_OVERRIDE`・`CAP_DAC_READ_SEARCH` は、所有者と group がその namespace へ写像されている inode にしか効かない
//! （`user_namespaces(7)` の "Effect of capabilities within a user namespace"）。写像されていない所有者の inode は、
//! ホスト側の fsuid（コンテナ root は起動した利用者の UID に写る）で通常の DAC 判定を受ける。したがって、
//! 特権ランチャー由来の capability で利用者の権限外の場所へは届かない。上書きが効くのは、利用者本人の UID が所有する
//! inode（本人は chmod できる）と、subordinate 写像のときの subuid／subgid が所有する inode（利用者に委譲済みの ID）に限る。
//!
//! `O_PATH` の open は祖先の search 権限しか見ず、末端の read 権限を確かめない（`open_tree` も見ない）。そのため種別の確認の後、
//! 固定した fd を `/proc/thread-self/fd/N` 経由で `O_RDONLY|O_NONBLOCK` に開き直し（パスを再 walk しない）、同じ inode に
//! 読み取り権限の判定を掛ける。`EACCES`・`EPERM` は `bind_source_not_accessible`。user namespace なしの経路
//! （init user namespace、またはホストの ID 0 を写像した経路）では適用せず `user_namespace_required`・
//! `host_root_identity_mapping` で拒否する。
//!
//! # 契約（1 件ごとの順序）
//!
//! 1. **元の固定**: 新しい mount namespace の中で `/` から全要素を `O_NOFOLLOW` で辿って fd に固定する。symlink は
//!    `bind_source_symlink`、種別がディレクトリ・通常ファイル以外は `bind_source_unsupported_type`、存在しなければ
//!    `NOT_FOUND`（違反ではない。何も作らない）。固定した fd から複製し、パス文字列で再解決しない
//! 2. **rootfs との同一性**: rootfs の `(st_dev, st_ino)` とその祖先（`..` を `O_NOFOLLOW` で辿る。4096 段が上限）に元が
//!    含まれれば `bind_source_contains_rootfs` で拒否する
//! 3. **先の固定**: [`PreparedRootfs`] の fd から 1 要素ずつ辿る（symlink・非ディレクトリは `path_symlink_or_not_directory`）。
//!    無い要素は 0755 で作り、元が通常ファイルなら末尾は空の通常ファイル（0644。umask の影響を受ける）にする。既存の
//!    マウント先の種別が元と違えば `bind_target_kind_mismatch`
//! 4. **検査**: マウント先が shared の上なら `target_on_shared_mount`
//! 5. **複製と属性**: 固定した元から `open_tree(OPEN_TREE_CLONE)` で複製し（`rbind` のときだけ `AT_RECURSIVE`）、切り離したまま
//!    `mount_setattr` で `nosuid`・`nodev`（常時）と `ro`・`noexec`（指定どおり）を足す。属性を付け終えてから付け替える
//! 6. **付け替え前の属性確認**: 切り離したマウントの `mount_flags` が要求どおりか確かめる。`attr_clr` を持たないため、ロックされた
//!    属性や読み取り専用の FS の元は要求より強い制限が残る。黙って別の属性で載せず、`FAILED_PRECONDITION`（`specify ro` 等）にする
//! 7. **移動検査**: 付け替えの直前にマウント先が改名・移動・削除されていないことを fd の現在位置で確かめる（`target_moved`）
//! 8. **付け替え**: `move_mount(2)` の空パス + fd 指定。直後に自分のマウントの fd を保持する
//! 9. **事後検証**: マウント前と別のマウントであること・自分のマウントの ID であること・`mount_flags` が要求どおりであること・
//!    元と同じ `(st_dev, st_ino)` であること・mountinfo で自分のマウント（`rbind` は配下全体）に `shared:`・`master:` が無く
//!    per-mount options が要求を満たすこと。満たさなければ fail-closed で失敗にする
//!
//! **伝播**: 明示の private 化はしない。`MountIsolation::establish` が `/` を `MS_REC|MS_PRIVATE` にしており、この
//! namespace のマウントは shared でも slave でもない。shared でも slave でもないマウントの複製はやはりそうなる。付け替え先は
//! 手順 4 で非 shared と確認済みで、手順 9 が `shared:`・`master:` の不在を確かめる。切り離した状態の伝播変更が許されるかは一次情報で
//! 未確認のため、`mount_setattr` の伝播変更は使わない。
//!
//! **属性の一次情報と未確認の点**: user namespace の中では、元の namespace からコピーしたマウントはロックされる
//! （`mount_namespaces(7)` の locked mounts）。ロックされた `ro`・`nosuid`・`nodev`・`noexec` は外せないが、本段は足すだけなので
//! `mount_setattr` は成功し、要求との差は手順 6・9 の構造化エラーになる。配下にロックされた子を持つ元を非再帰で複製すると
//! `EINVAL` になり（`__do_loopback` の `has_locked_children`）、`rbind` を促す `FAILED_PRECONDITION` にする。
//! 以上は #1659・#1912 で確認した知見に基づき、本 issue での一次情報の再照合は未実施（未確認）。`rbind` の配下の付け替え前の属性確認は
//! 行わず（mount top だけを見る）、配下は手順 9 の mountinfo で確かめる。実機（user namespace・実マウント）での確認は #1916。
//!
//! # エラーと監査
//!
//! 失敗は段 `MountBinds` の [`ExecError`]。分離違反（symlink・配下でない・種別違い・移動・読めない元・shared）は
//! [`ViolationReason`] を持ち、[`audit_mount_violation`](super::audit_mount_violation) で `Mount` 監査レコードにできる。違反記録の対象と
//! message のパスは**コンテナ内の宛先**で、ホスト側のマウント元・rootfs の実パスは載せない。宛先は [`display_destination`]
//! のエスケープと切り詰めを通す。新マウント API の無いカーネルでは `mount(2)` へ縮退せず `UNIMPLEMENTED` で拒否する。
//!
//! 失敗時は、載せたマウントを新しい順に `umount2(MNT_DETACH)` で外し、自分が作った空ファイル・ディレクトリを、作成時に記録した
//! `(dev, ino)` と一致するときだけ消す（自分専用の隔離ディレクトリへ `renameat2(RENAME_NOREPLACE)` してから照合して消し、照合と削除の間の
//! 差し替えを防ぐ）。後始末の失敗（umount・開き直し・照合不一致・削除）は元のエラーの message に `; cleanup failed: ...` として併記する
//! （REPAIR-4）。呼び出し後もプロセスは破棄する（`pivot_root`・exec へ進まない）。
//!
//! # 未対応・残余（REPAIR-3: 実装済みを装わない）
//!
//! - 状態ルートとの重なりの検査（`StateStore` からルートを取れないため `start` は検査しない。#1915 の残余）。実機前提の結合試験の
//!   段ごとの観測（#1916。通しの確認は `tests/production_launcher.rs` のシナリオ D〔#1915〕）。`ro` と Landlock の衝突解消（#1917）
//! - bundle・状態ルートの実体照合（#1911 の字句検証だけ）と、ホスト側の別の bind mount による別名の検出。全要素で symlink を拒否するため、
//!   字句パスと実パスは別名を除いて一致する
//! - procfs・sysfs など特殊な FS を元にすることは方針（#1910）上拒否していない
//!
//! # 単体テストの安全策
//!
//! 新マウント API・属性の観測・mountinfo は [`BindDeps`] の差し込み点で差し替える（本番は `mount_binds`、単体テストは
//! 記録つきの dry-run）。元の固定・種別・読めるかは実ファイルで照合する。実機の挙動は #1916 の結合試験で確認する。

use std::ffi::{CString, OsStr};
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use crate::oci_runtime::{BindMountSet, BindMountSpec};
use crate::rootless::parse_id_map;
use crate::sys::{
    self, BindMountAttrs, BindSourceError, BindSourceKind, MountFlags, MountTreeScope, SysError,
    VerifiedBindSourceFd,
};
use crate::traits::types::ErrorCode;

use super::tmpfs::{DIR_MODE, display_destination, open_chain, root_display};
use super::{
    ExecError, IdMapping, IsolationStage, MountIsolation, PreparedRootfs, USER_NS_INIT_INO,
    ViolationReason, fd_mount_id, fd_still_at, mount_is_shared, read_thread_mountinfo,
    thread_ns_link,
};

/// 結合試験専用の入口 [`mount_binds_with_attach_hook`] が、検査後・付け替え前に呼ぶ処理の型。
#[cfg(feature = "exec-test-support")]
type AttachHook<'a> = &'a dyn Fn();

const STAGE: IsolationStage = IsolationStage::MountBinds;

/// 通常ファイルの元に対して作る空ファイルのモード（umask の影響を受ける。bind で覆われるため見えるのは元の inode）。
const FILE_MODE: u32 = 0o644;

/// rootfs の祖先を辿る段数の上限（超えたら fail-closed。無制限の走査を防ぐ）。
const MAX_ANCESTORS: usize = 4096;

/// `/proc/thread-self/{uid,gid}_map` の読み取り上限（バイト）。
const MAX_ID_MAP_BYTES: u64 = 64 * 1024;

/// 適用した bind mount の元の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindSourceType {
    /// ディレクトリ。
    Directory,
    /// 通常ファイル。
    RegularFile,
}

impl From<BindSourceKind> for BindSourceType {
    fn from(kind: BindSourceKind) -> Self {
        match kind {
            BindSourceKind::Directory => Self::Directory,
            BindSourceKind::RegularFile => Self::RegularFile,
        }
    }
}

/// 適用した bind mount 1 件の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BindMountOutcome {
    /// `mounts[]` 内の位置。
    pub index: usize,
    /// コンテナ内のマウント先（正規化済み）。ホスト側のマウント元は載せない。
    pub destination: String,
    /// 元の種別。
    pub source_kind: BindSourceType,
    /// 読み取り専用で載せたか。
    pub read_only: bool,
    /// `noexec` で載せたか。
    pub noexec: bool,
    /// 再帰 bind（`rbind`）か。
    pub recursive: bool,
    /// マウント先（末尾の要素）をこの呼び出しが作ったか。
    pub created_target: bool,
}

/// [`mount_binds`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BindMountReport {
    /// 指定順に適用した結果。
    pub mounts: Vec<BindMountOutcome>,
}

/// `set` の bind mount を rootfs（`prepared` の新しい mount top）配下へ指定順に載せる。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。空の集合は何もしない。
/// user namespace なしの経路では適用しない。詳細な契約はモジュール doc を参照。
pub fn mount_binds(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &BindMountSet,
) -> Result<BindMountReport, ExecError> {
    mount_binds_checked(isolation, prepared, set, &|| {})
}

/// 結合試験専用: [`mount_binds`] と同じ検査・マウントを行い、各件の「移動検査の後・付け替えの直前」で `hook` を呼ぶ
/// （#1916 用。検査後にマウント先を差し替えられても別の場所へ載らないことを、実マウントで決定的に照合するため）。
/// 検証は緩めず、検査後に任意処理を挟むだけ。`exec-test-support` feature を付けたビルドにだけ存在し、通常の利用者は呼ばない。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn mount_binds_with_attach_hook(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &BindMountSet,
    hook: AttachHook<'_>,
) -> Result<BindMountReport, ExecError> {
    mount_binds_checked(isolation, prepared, set, hook)
}

/// [`mount_binds`] の証跡検証・user namespace の確認と、本番の差し込み点の組み立て。
fn mount_binds_checked(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &BindMountSet,
    before_attach: &dyn Fn(),
) -> Result<BindMountReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    if set.is_empty() {
        return Ok(BindMountReport { mounts: Vec::new() });
    }
    check_user_namespace()?;
    let deps = BindDeps {
        is_shared: &|dir| mount_is_shared(dir, STAGE),
        still_at: &fd_still_at,
        open_tree: &sys::open_tree_clone_bind,
        set_attrs: &sys::set_bind_mount_attrs,
        flags_of: &sys::mount_flags,
        attach: &sys::move_mount_empty_path,
        observe: &observe_real,
        mountinfo: &|| read_thread_mountinfo(STAGE),
        umount: &umount_fd,
        before_attach,
    };
    mount_binds_at(prepared.new_root(), set, &deps)
}

/// 副作用・観測の差し込み点（本番は実 syscall、単体テストは記録つきの dry-run。tmpfs の `mount_tmpfs_at` と同形）。
struct BindDeps<'a> {
    /// マウント先が shared propagation か。
    is_shared: &'a dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    /// 固定した fd が今も期待するホスト側パスにあるか。
    still_at: &'a dyn Fn(&OwnedFd, &Path) -> bool,
    /// 検証済みの元を切り離して複製する。
    open_tree: &'a dyn Fn(&VerifiedBindSourceFd, MountTreeScope) -> Result<OwnedFd, SysError>,
    /// 切り離したマウントへ属性を足す。
    set_attrs: &'a dyn Fn(BorrowedFd<'_>, BindMountAttrs, MountTreeScope) -> Result<(), SysError>,
    /// fd が属するマウントのフラグ。
    flags_of: &'a dyn Fn(BorrowedFd<'_>) -> Result<MountFlags, SysError>,
    /// 切り離したマウントを固定済みのマウント先へ付け替える（from, to）。
    attach: &'a dyn Fn(BorrowedFd<'_>, BorrowedFd<'_>) -> Result<(), SysError>,
    /// 付け替え後の観測（マウント前の先・開き直した先・自分のマウント）。
    observe: &'a dyn Fn(&OwnedFd, &OwnedFd, &OwnedFd) -> Result<BindObservation, ExecError>,
    /// 呼び出しスレッドの mountinfo。
    mountinfo: &'a dyn Fn() -> Result<String, ExecError>,
    /// 自分のマウントを fd 指定で外す（`MNT_DETACH`）。
    umount: &'a dyn Fn(BorrowedFd<'_>) -> Result<(), SysError>,
    /// 移動検査の後・付け替えの直前に呼ぶ（本番は空。結合試験専用の入口だけが差し込む）。
    before_attach: &'a dyn Fn(),
}

/// 付け替え前後の観測値（[`check_new_bind`] の入力）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BindObservation {
    /// マウント前に固定した先が属するマウントの ID。
    before_mnt_id: u64,
    /// 開き直した先が属するマウントの ID。
    after_mnt_id: u64,
    /// 自分のマウント（複製の fd）の ID。
    own_mnt_id: u64,
    /// 開き直した先が属するマウントのフラグ。
    flags: MountFlags,
    /// 開き直した先の `(st_dev, st_ino)`。
    dev_ino: (u64, u64),
}

/// 要求した属性（`nosuid`・`nodev` は常に付くため持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expected {
    read_only: bool,
    noexec: bool,
}

/// 1 件の適用で rootfs・mount namespace に加えた変更の記録（失敗時の [`roll_back_binds`] が使う）。
struct Applied<'a> {
    /// マウント先の要素列（正規化済み）。
    names: Vec<&'a OsStr>,
    /// この呼び出しの `mkdirat` が成功した要素の添字（昇順）。
    created_dirs: Vec<usize>,
    /// 作った各ディレクトリの `(要素の添字, (st_dev, st_ino))`（作成直後に記録。後始末は一致したものだけ消す）。
    created_dir_ids: Vec<(usize, (u64, u64))>,
    /// この呼び出しが作った空ファイル（末尾の要素）の `(st_dev, st_ino)`。
    created_file: Option<(u64, u64)>,
    /// 付け替えた「自分のマウントのルート」を指す fd（付け替え直後に保持し、事後検証に通らなくても外せる）。
    mounted: Option<OwnedFd>,
}

impl<'a> Applied<'a> {
    fn new(spec: &'a BindMountSpec) -> Self {
        Self {
            names: spec
                .destination()
                .as_str()
                .split('/')
                .filter(|e| !e.is_empty())
                .map(OsStr::new)
                .collect(),
            created_dirs: Vec::new(),
            created_dir_ids: Vec::new(),
            created_file: None,
            mounted: None,
        }
    }
}

/// 適用中に共通の値。
struct Ctx<'a> {
    /// rootfs（新しい mount top）の fd。
    root: BorrowedFd<'a>,
    /// rootfs のホスト側実パス（移動検査用。メッセージ・監査には載せない）。
    host_root: PathBuf,
    /// rootfs とその祖先の `(st_dev, st_ino)`。
    rootfs_ids: Vec<(u64, u64)>,
    deps: &'a BindDeps<'a>,
}

/// [`mount_binds`] の本体。`root` は rootfs（新しい mount top）の fd。
fn mount_binds_at(
    root: BorrowedFd<'_>,
    set: &BindMountSet,
    deps: &BindDeps<'_>,
) -> Result<BindMountReport, ExecError> {
    if set.is_empty() {
        return Ok(BindMountReport { mounts: Vec::new() });
    }
    let ctx = Ctx {
        root,
        host_root: root_display(root),
        rootfs_ids: rootfs_identity_chain(root)?,
        deps,
    };
    // 件数は `BindMountSet`（`CONFIG_MAX_MOUNTS` 以下）で上限が決まっている。
    let mut mounts = Vec::with_capacity(set.mounts().len());
    let mut applied: Vec<Applied<'_>> = Vec::with_capacity(set.mounts().len());
    for spec in set.mounts() {
        let mut state = Applied::new(spec);
        let result = apply_one(&ctx, spec, &mut state);
        let created_target =
            state.created_file.is_some() || state.created_dirs.contains(&last_index(&state));
        applied.push(state);
        match result {
            Ok(kind) => mounts.push(BindMountOutcome {
                index: spec.index(),
                destination: spec.destination().as_str().to_owned(),
                source_kind: kind.into(),
                read_only: spec.read_only(),
                noexec: spec.noexec(),
                recursive: spec.recursive(),
                created_target,
            }),
            Err(e) => {
                let failures = roll_back_binds(&ctx, &applied);
                return Err(with_cleanup_failures(e, &failures));
            }
        }
    }
    Ok(BindMountReport { mounts })
}

/// 末尾の要素の添字（空なら 0。`Applied::new` は空を作り得るが、`apply_one` が先に拒否する）。
fn last_index(state: &Applied<'_>) -> usize {
    state.names.len().saturating_sub(1)
}

/// 1 件の適用。成功時は元の種別を返す。
fn apply_one(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    state: &mut Applied<'_>,
) -> Result<BindSourceKind, ExecError> {
    let deps = ctx.deps;
    let src = pin_source(spec)?;
    if ctx.rootfs_ids.contains(&src.dev_ino()) {
        return Err(violation(spec, ViolationReason::BindSourceContainsRootfs));
    }
    let kind = src.kind();
    let dest = pin_target(ctx, spec, kind, state)?;
    if (deps.is_shared)(&dest)? {
        return Err(violation(spec, ViolationReason::TargetOnSharedMount));
    }
    let scope = if spec.recursive() {
        MountTreeScope::Recursive
    } else {
        MountTreeScope::MountOnly
    };
    let expected = Expected {
        read_only: spec.read_only(),
        noexec: spec.noexec(),
    };
    let clone = (deps.open_tree)(&src, scope).map_err(|e| open_tree_error(spec, e, scope))?;
    (deps.set_attrs)(
        clone.as_fd(),
        BindMountAttrs {
            read_only: expected.read_only,
            noexec: expected.noexec,
        },
        scope,
    )
    .map_err(|e| mount_api_error(spec, e, "mount_setattr(bind mount)"))?;
    let flags = (deps.flags_of)(clone.as_fd())
        .map_err(|e| mount_api_error(spec, e, "fstatfs(detached bind mount)"))?;
    check_flags(flags, expected).map_err(|why| failed(spec, &format!("before attach: {why}")))?;
    // fd 固定後に別プロセスがマウント先（または祖先）を改名・移動・削除していれば拒否する。この確認から
    // 付け替えまでに移動された場合も、付け替えは固定した fd（検証済みの実体）にしか載らず rootfs の別の場所を
    // 覆わない。事後検証が名前の位置に自分のマウントが無いことを検出して失敗させ、後始末が自分のマウントを外す。
    let expected_path = state
        .names
        .iter()
        .fold(ctx.host_root.clone(), |p, n| p.join(n));
    if !(deps.still_at)(&dest, &expected_path) {
        return Err(violation(spec, ViolationReason::TargetMoved));
    }
    (deps.before_attach)();
    (deps.attach)(clone.as_fd(), dest.as_fd())
        .map_err(|e| mount_api_error(spec, e, "move_mount(bind mount)"))?;
    // 付け替え直後に自分のマウントの fd を保持する（事後検証に通らなくても後始末が外せる）。
    state.mounted = Some(clone);
    let after = reopen_target(ctx, spec, state)?;
    let Some(own) = state.mounted.as_ref() else {
        return Err(failed(spec, "the bind mount handle was lost"));
    };
    let observed = (deps.observe)(&dest, &after, own)?;
    check_new_bind(&observed, expected, src.dev_ino()).map_err(|why| failed(spec, &why))?;
    let info = (deps.mountinfo)()?;
    check_bind_subtree(&info, observed.own_mnt_id, expected, spec.recursive())
        .map_err(|why| failed(spec, &why))?;
    Ok(kind)
}

/// 元をルートから 1 要素ずつ `O_NOFOLLOW` で固定し、種別と読み取り権限を確かめる（モジュール doc の手順 1）。
fn pin_source(spec: &BindMountSpec) -> Result<VerifiedBindSourceFd, ExecError> {
    let names: Vec<&str> = spec.source().split('/').filter(|e| !e.is_empty()).collect();
    let Some((leaf, parents)) = names.split_last() else {
        return Err(failed(spec, "bind mount source is empty"));
    };
    let c_name = |n: &str| {
        CString::new(n.as_bytes()).map_err(|_| failed(spec, "bind mount source contains NUL"))
    };
    let mut cur = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| source_open_error(spec, e, "openat(/)"))?;
    for name in parents {
        let c = c_name(name)?;
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c)
            .map_err(|e| source_open_error(spec, e, "openat(bind mount source)"))?;
    }
    let c = c_name(leaf)?;
    let fd = sys::open_path_nofollow(cur.as_fd(), &c)
        .map_err(|e| source_open_error(spec, e, "openat(bind mount source)"))?;
    let verified = sys::verify_bind_source_fd(fd).map_err(|e| match e {
        BindSourceError::NotDirOrRegular { mode } if mode & S_IFMT == S_IFLNK => {
            violation(spec, ViolationReason::BindSourceSymlink)
        }
        BindSourceError::NotDirOrRegular { .. } => {
            violation(spec, ViolationReason::BindSourceUnsupportedType)
        }
        BindSourceError::Sys(e) => mount_api_error(spec, e, "fstat(bind mount source)"),
    })?;
    // 読み取り権限の確認: 固定した inode を開き直す（パスを再 walk しない）。開いた fd は直ちに閉じる。
    match sys::reopen_pinned_read_nonblock(verified.as_fd()) {
        Ok(_checked) => {}
        Err(SysError::Os(e)) if e == sys::EACCES || e == sys::EPERM => {
            return Err(violation(spec, ViolationReason::BindSourceNotAccessible));
        }
        Err(e) => return Err(mount_api_error(spec, e, "open(bind mount source)")),
    }
    Ok(verified)
}

/// `st_mode` の種別ビットとシンボリックリンクの値（`sys/stat.h`）。
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

/// 元の経路の open の失敗を写す。
fn source_open_error(spec: &BindMountSpec, e: SysError, what: &str) -> ExecError {
    match e {
        // `O_DIRECTORY|O_NOFOLLOW` では中間の symlink も `ENOTDIR` になる。`ELOOP` は念のため残す。
        SysError::Os(sys::ENOTDIR) | SysError::Os(sys::ELOOP) => {
            violation(spec, ViolationReason::BindSourceSymlink)
        }
        SysError::Os(sys::ENOENT) => {
            let mut err = failed(spec, "bind mount source does not exist");
            err.code = ErrorCode::NotFound;
            err
        }
        SysError::Os(sys::EACCES) => violation(spec, ViolationReason::BindSourceNotAccessible),
        other => mount_api_error(spec, other, what),
    }
}

/// マウント先を rootfs の fd から固定する（無い要素は作る。モジュール doc の手順 3）。
fn pin_target(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    kind: BindSourceKind,
    state: &mut Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let names = state.names.clone();
    let Some((leaf, parents)) = names.split_last() else {
        return Err(failed(spec, "bind mount destination is empty"));
    };
    let parent_fd = if parents.is_empty() {
        None
    } else {
        Some(open_parents_recording(ctx, spec, parents, state)?)
    };
    let parent = parent_fd.as_ref().map_or(ctx.root, |f| f.as_fd());
    let c_leaf = CString::new(leaf.as_bytes())
        .map_err(|_| violation(spec, ViolationReason::PathContainsNul))?;
    let fd = match sys::open_path_nofollow(parent, &c_leaf) {
        Ok(fd) => fd,
        Err(SysError::Os(sys::ENOENT)) => {
            if kind == BindSourceKind::Directory {
                // 自分が作った実体であることを証明してから配置する（作成と開き直しの間の差し替えを許さない）。
                match create_dir_proven(parent, &c_leaf) {
                    Ok(Some((fd, id, leftover))) => {
                        // 配置済みの実体は、ステージング掃除の失敗より先に記録する（失敗しても後始末が回収できる）。
                        state.created_dirs.push(last_index(state));
                        state.created_dir_ids.push((last_index(state), id));
                        if let Some(detail) = leftover {
                            return Err(failed(
                                spec,
                                &format!("mkdirat(bind mount target) rmdir: {detail}"),
                            ));
                        }
                        fd
                    }
                    Ok(None) => reopen_created(spec, kind, parent, &c_leaf, state)?,
                    Err((what, detail)) => {
                        return Err(failed(
                            spec,
                            &format!("mkdirat(bind mount target) {what}: {detail}"),
                        ));
                    }
                }
            } else {
                create_target(spec, kind, parent, &c_leaf, state)?;
                reopen_created(spec, kind, parent, &c_leaf, state)?
            }
        }
        Err(e) => return Err(mount_api_error(spec, e, "openat(bind mount target)")),
    };
    check_target_kind(spec, &fd, kind)?;
    Ok(fd)
}

/// マウント先の親を rootfs の fd から 1 要素ずつ固定する（無い要素は作る）。
///
/// 作った要素は、作成直後に開き直して固定した fd の `(st_dev, st_ino)` をその場で `created_dir_ids` へ記録する
/// （名前を辿り直さない）。途中で失敗しても、それまでに作った分は記録済みのため後始末が照合して消せる。
/// 失敗は宛先の接頭辞つきの `IsolationStage::MountBinds` のエラーにする。
fn open_parents_recording(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    parents: &[&OsStr],
    state: &mut Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let mut cur: Option<OwnedFd> = None;
    for (index, name) in parents.iter().enumerate() {
        let c = CString::new(name.as_bytes())
            .map_err(|_| violation(spec, ViolationReason::PathContainsNul))?;
        let dir = cur.as_ref().map_or(ctx.root, |f| f.as_fd());
        let next = match sys::open_dir_path_nofollow(Some(dir), &c) {
            Ok(fd) => fd,
            Err(SysError::Os(sys::ENOENT)) => {
                // 自分が作った実体であることを証明してから配置する（作成と開き直しの間の差し替えを許さない）。
                match create_dir_proven(dir, &c) {
                    Ok(Some((fd, id, leftover))) => {
                        // 配置済みの実体は、ステージング掃除の失敗より先に記録する（失敗しても後始末が回収できる）。
                        state.created_dirs.push(index);
                        state.created_dir_ids.push((index, id));
                        if let Some(detail) = leftover {
                            return Err(failed(
                                spec,
                                &format!("mkdirat(bind mount target) rmdir: {detail}"),
                            ));
                        }
                        fd
                    }
                    Ok(None) => sys::open_dir_path_nofollow(Some(dir), &c).map_err(|e| {
                        annotate(
                            spec,
                            super::open_error(e, true, Path::new("/"), parents).at_stage(STAGE),
                        )
                    })?,
                    Err((what, detail)) => {
                        return Err(failed(
                            spec,
                            &format!("mkdirat(bind mount target) {what}: {detail}"),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(annotate(
                    spec,
                    super::open_error(e, true, Path::new("/"), parents).at_stage(STAGE),
                ));
            }
        };
        cur = Some(next);
    }
    cur.ok_or_else(|| failed(spec, "bind mount destination is empty"))
}

/// 無いマウント先の末尾の通常ファイルを空の 0644 で作る（ディレクトリは `create_dir_proven`）。競合で先に作られた場合は何もしない。
fn create_target(
    spec: &BindMountSpec,
    kind: BindSourceKind,
    parent: BorrowedFd<'_>,
    c_leaf: &CString,
    state: &mut Applied<'_>,
) -> Result<(), ExecError> {
    match kind {
        // ディレクトリは `create_dir_proven` が作る（作成と所有証明の間に差し替えを許さないため）。
        BindSourceKind::Directory => {
            return Err(failed(
                spec,
                "directory targets are created by create_dir_proven",
            ));
        }
        BindSourceKind::RegularFile => match sys::create_file_excl_at(parent, c_leaf, FILE_MODE) {
            Ok(created) => {
                let st = fstat_fd(created.as_fd())
                    .map_err(|e| mount_api_error(spec, e, "fstat(bind mount target)"))?;
                state.created_file = Some((st.dev, st.ino));
            }
            Err(SysError::Os(sys::EEXIST)) => {}
            Err(e) => return Err(mount_api_error(spec, e, "create(bind mount target)")),
        },
    }
    Ok(())
}

/// 作成した（または競合で先に作られた）マウント先を開き直す。自分が作ったファイルは作成時の `(dev, ino)` と一致を確かめる。
fn reopen_created(
    spec: &BindMountSpec,
    kind: BindSourceKind,
    parent: BorrowedFd<'_>,
    c_leaf: &CString,
    state: &Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let fd = sys::open_path_nofollow(parent, c_leaf)
        .map_err(|e| mount_api_error(spec, e, "openat(bind mount target)"))?;
    if let (BindSourceKind::RegularFile, Some(recorded)) = (kind, state.created_file) {
        let st = fstat_fd(fd.as_fd())
            .map_err(|e| mount_api_error(spec, e, "fstat(bind mount target)"))?;
        if (st.dev, st.ino) != recorded {
            return Err(violation(spec, ViolationReason::TargetMoved));
        }
    }
    Ok(fd)
}

/// 固定したマウント先の種別を元と突き合わせる（symlink は拒否、種別違いは `bind_target_kind_mismatch`）。
fn check_target_kind(
    spec: &BindMountSpec,
    fd: &OwnedFd,
    kind: BindSourceKind,
) -> Result<(), ExecError> {
    let st =
        fstat_fd(fd.as_fd()).map_err(|e| mount_api_error(spec, e, "fstat(bind mount target)"))?;
    if st.is_symlink {
        return Err(violation(spec, ViolationReason::PathSymlinkOrNotDirectory));
    }
    match (kind, st.is_dir, st.is_file) {
        (BindSourceKind::Directory, true, _) | (BindSourceKind::RegularFile, _, true) => Ok(()),
        _ => Err(violation(spec, ViolationReason::BindTargetKindMismatch)),
    }
}

/// 付け替え後に、同じ要素を作らずに名前で開き直す（事後検証・観測用）。
fn reopen_target(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    state: &Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let Some((leaf, parents)) = state.names.split_last() else {
        return Err(failed(spec, "bind mount destination is empty"));
    };
    let parent_fd = if parents.is_empty() {
        None
    } else {
        Some(
            open_chain(ctx.root, Path::new("/"), parents, None)
                .map_err(|e| annotate(spec, e.at_stage(STAGE)))?,
        )
    };
    let parent = parent_fd.as_ref().map_or(ctx.root, |f| f.as_fd());
    let c_leaf = CString::new(leaf.as_bytes())
        .map_err(|_| violation(spec, ViolationReason::PathContainsNul))?;
    sys::open_path_nofollow(parent, &c_leaf)
        .map_err(|e| mount_api_error(spec, e, "openat(bind mount target)"))
}

/// 付け替え前後の fd の観測（本番）。
fn observe_real(
    before: &OwnedFd,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<BindObservation, ExecError> {
    let flags = sys::mount_flags(after.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(bind mount target)"))?;
    let st = fstat_fd(after.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstat(bind mount target)"))?;
    Ok(BindObservation {
        before_mnt_id: fd_mount_id(before, STAGE)?,
        after_mnt_id: fd_mount_id(after, STAGE)?,
        own_mnt_id: fd_mount_id(own, STAGE)?,
        flags,
        dev_ino: (st.dev, st.ino),
    })
}

/// 自分のマウントを fd 指定で `umount2(MNT_DETACH)` する（fd を直接指す syscall が無いため `/proc/thread-self/fd/N` 経由）。
fn umount_fd(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    let target = CString::new(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| SysError::Os(sys::EINVAL))?;
    sys::umount_detach_at(&target)
}

/// 付け替え前後のフラグの判定（純関数）。成功なら `Ok`、不一致なら英語の理由。
///
/// `nosuid`・`nodev` は常に必須。`ro`・`noexec` は要求と一致しなければならない（`attr_clr` を持たないため、
/// ロックされた属性や読み取り専用の FS の元は要求より強い制限が残る。黙って別の属性で載せない）。
fn check_flags(flags: MountFlags, expected: Expected) -> Result<(), String> {
    if !flags.is_valid() {
        return Err("the mount flags are not available".to_owned());
    }
    if !flags.is_nosuid() || !flags.is_nodev() {
        return Err("nosuid and nodev are not set on the bind mount".to_owned());
    }
    match (flags.is_read_only(), expected.read_only) {
        (true, false) => {
            return Err(
                "the bind mount is read-only (a locked attribute or a read-only \
                        filesystem); specify ro"
                    .to_owned(),
            );
        }
        (false, true) => return Err("ro was not applied to the bind mount".to_owned()),
        _ => {}
    }
    match (flags.is_noexec(), expected.noexec) {
        (true, false) => {
            Err("the bind mount is noexec (a locked attribute); specify noexec".to_owned())
        }
        (false, true) => Err("noexec was not applied to the bind mount".to_owned()),
        _ => Ok(()),
    }
}

/// 事後条件の判定（純関数）。マウント前とは別のマウントで、自分のマウントで、フラグが要求どおりで、元と同じ
/// `(st_dev, st_ino)` でなければ拒否する。
fn check_new_bind(
    observed: &BindObservation,
    expected: Expected,
    source: (u64, u64),
) -> Result<(), String> {
    if observed.after_mnt_id == observed.before_mnt_id {
        return Err("no new mount is present at the bind mount destination after mount".to_owned());
    }
    if observed.after_mnt_id != observed.own_mnt_id {
        return Err(
            "the mount at the bind mount destination is not the mount created by this call"
                .to_owned(),
        );
    }
    check_flags(observed.flags, expected).map_err(|why| format!("after mount: {why}"))?;
    if observed.dev_ino != source {
        return Err(
            "the bind mount destination is not the same inode as the pinned source".to_owned(),
        );
    }
    Ok(())
}

/// mountinfo の 1 行（必要なフィールドだけ）。
struct MountInfoEntry<'a> {
    id: u64,
    parent: u64,
    options: &'a str,
    optional: Vec<&'a str>,
}

/// mountinfo の 1 行に必須の固定フィールド数（`id parent major:minor root mount_point options`）。
const MOUNTINFO_FIXED_FIELDS: usize = 6;
/// 区切り `-` の後ろの必須フィールド数（`fstype source super_options`）。
const MOUNTINFO_TAIL_FIELDS: usize = 3;

fn parse_mountinfo_line(line: &str) -> Option<MountInfoEntry<'_>> {
    let fields: Vec<&str> = line.split(' ').collect();
    let sep = fields
        .iter()
        .skip(MOUNTINFO_FIXED_FIELDS)
        .position(|f| *f == "-")?
        + MOUNTINFO_FIXED_FIELDS;
    if fields.len() < sep + 1 + MOUNTINFO_TAIL_FIELDS {
        return None;
    }
    Some(MountInfoEntry {
        id: fields.first()?.parse().ok()?,
        parent: fields.get(1)?.parse().ok()?,
        options: fields.get(5)?,
        optional: fields.get(MOUNTINFO_FIXED_FIELDS..sep)?.to_vec(),
    })
}

/// 自分のマウント（`recursive` なら配下全体）の mountinfo を判定する（純関数）。
///
/// 全マウントに `shared:`・`master:`・`propagate_from:` が無く、per-mount options に `nosuid`・`nodev` があること。
/// 自分のマウント（mount top）は `ro`・`noexec` の有無が要求と完全に一致すること。配下は、要求した制限
/// （`ro`・`noexec`）が付いていれば足りる（元が持つ、より強い制限は安全側のため許す）。書式に反する行・該当なし・
/// 重複は fail-closed。
fn check_bind_subtree(
    info: &str,
    own_id: u64,
    expected: Expected,
    recursive: bool,
) -> Result<(), String> {
    let malformed = || "malformed line in /proc/thread-self/mountinfo".to_owned();
    let entries: Vec<MountInfoEntry<'_>> = info
        .lines()
        .map(|l| parse_mountinfo_line(l).ok_or_else(malformed))
        .collect::<Result<_, _>>()?;
    let mut own = entries.iter().filter(|e| e.id == own_id);
    let Some(top) = own.next() else {
        return Err("no mount entry found for the bind mount".to_owned());
    };
    if own.next().is_some() {
        return Err("duplicate mount ID in /proc/thread-self/mountinfo".to_owned());
    }
    let has = |e: &MountInfoEntry<'_>, opt: &str| e.options.split(',').any(|o| o == opt);
    let mut members: Vec<&MountInfoEntry<'_>> = vec![top];
    if recursive {
        // 親子関係で配下を集める（件数は行数が上限）。
        let mut ids = vec![top.id];
        loop {
            let before = ids.len();
            for e in &entries {
                if !ids.contains(&e.id) && ids.contains(&e.parent) {
                    ids.push(e.id);
                    members.push(e);
                }
            }
            if ids.len() == before {
                break;
            }
        }
    }
    for e in &members {
        if e.optional.iter().any(|f| {
            f.starts_with("shared:") || f.starts_with("master:") || f.starts_with("propagate_from:")
        }) {
            return Err(
                "the bind mount is shared or a slave in /proc/thread-self/mountinfo".to_owned(),
            );
        }
        if !has(e, "nosuid") || !has(e, "nodev") {
            return Err("nosuid and nodev are not set in /proc/thread-self/mountinfo".to_owned());
        }
        let is_top = e.id == top.id;
        if (expected.read_only || is_top) && has(e, "ro") != expected.read_only {
            return Err(if expected.read_only {
                "ro is not set in /proc/thread-self/mountinfo".to_owned()
            } else {
                "the bind mount is read-only in /proc/thread-self/mountinfo; specify ro".to_owned()
            });
        }
        if (expected.noexec || is_top) && has(e, "noexec") != expected.noexec {
            return Err(if expected.noexec {
                "noexec is not set in /proc/thread-self/mountinfo".to_owned()
            } else {
                "the bind mount is noexec in /proc/thread-self/mountinfo; specify noexec".to_owned()
            });
        }
    }
    Ok(())
}

/// 後始末で失敗した 1 件（元のエラーへ併記する。#1913・REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupFailure {
    /// [`display_destination`] を通した宛先（エスケープ・切り詰め済み）。
    destination: String,
    /// 失敗した操作（`umount2`・`unlink`・`rmdir`・`open`・`rename`・`verify`）。
    what: &'static str,
    /// 失敗理由（英語の短い文）。
    detail: String,
}

/// 後始末の失敗を、元のエラーの message に `; cleanup failed: <what>(<dest>) failed: <detail>` として併記する
/// （`code`・`stage`・`violation` は保つ）。失敗が無ければ `err` をそのまま返す。件数は集合側の上限で抑えられる。
fn with_cleanup_failures(mut err: ExecError, failures: &[CleanupFailure]) -> ExecError {
    for f in failures {
        err.message.push_str(&format!(
            "; cleanup failed: {}({}) failed: {}",
            f.what, f.destination, f.detail
        ));
    }
    err
}

/// 要素列を表示用の宛先文字列にする。
fn destination_of(names: &[&OsStr]) -> String {
    display_destination(&format!(
        "/{}",
        names
            .iter()
            .map(|n| n.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    ))
}

/// 失敗時の後始末（最善努力）。新しい順に、自分のマウントを外し、自分が作った空ファイル・ディレクトリを消す。
///
/// 解除するのは付け替え時に得た自分のマウントの fd が指すマウントだけで、名前から開き直した先は解除しない。
/// 空ファイル・ディレクトリは [`remove_verified`] で、作成時に記録した `(dev, ino)` と一致した実体だけを消す。
/// 失敗（umount・開き直し・照合不一致・削除）は戻り値で返し、呼び出し元が元のエラーに併記する（黙って捨てない）。
fn roll_back_binds(ctx: &Ctx<'_>, applied: &[Applied<'_>]) -> Vec<CleanupFailure> {
    let mut failures = Vec::new();
    for state in applied.iter().rev() {
        if let Some(mount) = &state.mounted
            && let Err(error) = (ctx.deps.umount)(mount.as_fd())
        {
            failures.push(CleanupFailure {
                destination: destination_of(&state.names),
                what: "umount2",
                detail: super::describe(error),
            });
        }
        if let Some(recorded) = state.created_file {
            let last = state.names.len().saturating_sub(1);
            remove_created(ctx, state, last, recorded, false, &mut failures);
        }
        for &index in state.created_dirs.iter().rev() {
            let Some((_, recorded)) = state.created_dir_ids.iter().find(|(i, _)| *i == index)
            else {
                failures.push(CleanupFailure {
                    destination: destination_of(state.names.get(..=index).unwrap_or(&[])),
                    what: "verify",
                    detail: "the created directory was not recorded; left in place".to_owned(),
                });
                break;
            };
            if !remove_created(ctx, state, index, *recorded, true, &mut failures) {
                break;
            }
        }
    }
    failures
}

/// `state.names[index]` の要素（自分が作ったもの）を消す。失敗は `failures` へ積み、続行してよければ `true`。
fn remove_created(
    ctx: &Ctx<'_>,
    state: &Applied<'_>,
    index: usize,
    recorded: (u64, u64),
    is_dir: bool,
    failures: &mut Vec<CleanupFailure>,
) -> bool {
    let destination = destination_of(state.names.get(..=index).unwrap_or(&[]));
    let mut fail = |what: &'static str, detail: String| {
        failures.push(CleanupFailure {
            destination: destination.clone(),
            what,
            detail,
        });
        false
    };
    let (Some(name), Some(prefix)) = (state.names.get(index), state.names.get(..index)) else {
        return fail("verify", "the created element is out of range".to_owned());
    };
    let Ok(c_name) = CString::new(name.as_bytes()) else {
        return fail("verify", "the element name contains NUL".to_owned());
    };
    let parent_fd = if prefix.is_empty() {
        None
    } else {
        match open_chain(ctx.root, Path::new("/"), prefix, None) {
            Ok(fd) => Some(fd),
            Err(e) => return fail("open", e.message),
        }
    };
    let parent = parent_fd.as_ref().map_or(ctx.root, |f| f.as_fd());
    match remove_verified(parent, &c_name, recorded, is_dir) {
        Ok(()) => true,
        Err((what, detail)) => fail(what, detail),
    }
}

/// 後始末用の隔離ディレクトリ名の連番（同一プロセス内の衝突回避）。
static QUARANTINE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 隔離ディレクトリの中での、移した実体の名前。
const QUARANTINED: &str = "victim";

/// 隔離ディレクトリの権限（所有者のみ）。
const QUARANTINE_MODE: u32 = 0o700;

/// `parent` 配下の `name` を、記録した `(dev, ino)` と一致する実体のときだけ消す（検証対象と削除対象を一致させる）。
///
/// 名前のまま照合して `unlinkat` すると、照合と削除の間に別プロセスが同名の別実体へ差し替えられる。同じ親の中に
/// 隔離名で改名するだけでも、その隔離名が他者から見えて書けるため差し替えられる。そこで
/// (1) `parent` の中に自分専用（0700・実効 uid 所有）の隔離ディレクトリを作って fd で固定し、
/// (2) `RENAME_NOREPLACE` の `renameat2` で対象をその中へ原子的に移し（他者はそこへ入れない）、
/// (3) 移した実体を開いて `(dev, ino)` を照合し、(4) 一致したときだけ消す。不一致・削除失敗のときは元の名前へ
/// `RENAME_NOREPLACE` で戻す。戻し先に別の実体が作られていれば上書きせず、実体を隔離ディレクトリに残して
/// 失敗として報告する。マウントが残っている要素は改名が `EBUSY` で拒否されるため、umount に失敗した場合も消さない。
fn remove_verified(
    parent: BorrowedFd<'_>,
    name: &CString,
    recorded: (u64, u64),
    is_dir: bool,
) -> Result<(), (&'static str, String)> {
    let errno = |e: SysError| super::describe(e);
    let seq = QUARANTINE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let qname = CString::new(format!(
        ".fandhe-rollback-{}-{seq}-{nanos:08x}",
        std::process::id()
    ))
    .map_err(|_| ("rename", "invalid quarantine name".to_owned()))?;
    let victim =
        CString::new(QUARANTINED).map_err(|_| ("rename", "invalid quarantine name".to_owned()))?;
    sys::mkdir_at(parent, &qname, QUARANTINE_MODE).map_err(|e| ("mkdir", errno(e)))?;
    // 隔離ディレクトリを（空のときだけ）消す。差し替えられていても空ディレクトリしか消えない。失敗は文字列で返す。
    let drop_qdir = || -> Option<String> {
        sys::remove_dir_at(parent, &qname).err().map(|e| {
            format!(
                "removing the quarantine directory failed: {}; it was left in place",
                errno(e)
            )
        })
    };
    let qdir = match sys::open_dir_path_nofollow(Some(parent), &qname) {
        Ok(fd) => fd,
        Err(e) => return Err(("open", join_detail(errno(e), drop_qdir()))),
    };
    let qst = match fstat_fd(qdir.as_fd()) {
        Ok(st) => st,
        Err(e) => return Err(("verify", join_detail(errno(e), drop_qdir()))),
    };
    if !qst.is_dir || qst.uid != sys::effective_uid() || qst.mode & 0o777 != QUARANTINE_MODE {
        // 作った直後に他者が差し替えた。中へ移すと他者から触れるため何もしない。
        return Err((
            "verify",
            join_detail(
                "the quarantine directory is not private to this process; left in place".to_owned(),
                drop_qdir(),
            ),
        ));
    }
    match sys::rename_noreplace_at(parent, name, qdir.as_fd(), &victim) {
        Ok(()) => {}
        // 既に無い（自分の作った実体が消えている）なら後始末は済んでいる。
        Err(SysError::Os(sys::ENOENT)) => {
            return match drop_qdir() {
                None => Ok(()),
                Some(x) => Err(("rmdir", x)),
            };
        }
        Err(e) => return Err(("rename", join_detail(errno(e), drop_qdir()))),
    }
    let put_back = |what: &'static str, detail: String| {
        let detail = match sys::rename_noreplace_at(qdir.as_fd(), &victim, parent, name) {
            Ok(()) => join_detail(detail, drop_qdir()),
            Err(SysError::Os(sys::EEXIST)) => format!(
                "{detail}; the original name was re-created by another process, so the element was left in the quarantine directory"
            ),
            Err(e) => format!(
                "{detail}; restoring the original name failed: {}; the element was left in the quarantine directory",
                errno(e)
            ),
        };
        Err((what, detail))
    };
    let id = sys::open_path_nofollow(qdir.as_fd(), &victim)
        .and_then(|fd| fstat_fd(fd.as_fd()))
        .map(|st| (st.dev, st.ino));
    match id {
        Ok(id) if id == recorded => {}
        Ok(_) => {
            return put_back(
                "verify",
                "the element is not the one created by this call; left in place".to_owned(),
            );
        }
        Err(e) => return put_back("verify", errno(e)),
    }
    let removed = if is_dir {
        sys::remove_dir_at(qdir.as_fd(), &victim)
    } else {
        sys::remove_file_at(qdir.as_fd(), &victim)
    };
    match removed {
        Ok(()) => match drop_qdir() {
            None => Ok(()),
            Some(x) => Err(("rmdir", x)),
        },
        Err(e) => put_back(if is_dir { "rmdir" } else { "unlink" }, errno(e)),
    }
}

/// 元のエラー文に、後始末の失敗（あれば）を併記する。
fn join_detail(detail: String, extra: Option<String>) -> String {
    match extra {
        Some(x) => format!("{detail}; {x}"),
        None => detail,
    }
}

/// `create_dir_proven` の結果（作った fd と `(dev, ino)`、既存なら `None`、失敗は段名と詳細）。
///
/// 3 つ目はステージングディレクトリを消せなかったときの詳細。配置は済んでいるため `Ok` で返し、呼び出し側が
/// 配置した実体を `created_dirs` / `created_dir_ids` へ記録してからエラー扱いにする（記録しないと後始末が回収できない）。
type CreateProven = Result<Option<(OwnedFd, (u64, u64), Option<String>)>, (&'static str, String)>;

/// `parent` 配下に新しいディレクトリ `name` を作り、自分が作った実体であることを証明した fd と `(dev, ino)` を返す。
/// 既に `name` がある（競合を含む）ときは `Ok(None)`（何も作らない）。
///
/// `mkdirat` してから名前で開き直すと、その間に別プロセスが改名して別の同名ディレクトリを置ける。そこで
/// (1) `parent` の中に自分専用（0700・実効 uid 所有）のステージングディレクトリを作って fd で固定し、
/// (2) その中（他者は入れない）に `mkdirat` して fd を開き直し `(dev, ino)` を取り、
/// (3) `RENAME_NOREPLACE` の `renameat2` で `name` へ原子的に移す（inode は変わらない）。
/// 記録する実体は常に自分が作ったものになる。ステージングディレクトリは成否に関わらず空にして消し、
/// 削除の失敗はエラーに併記する（SEC-1・REPAIR-4）。
fn create_dir_proven(parent: BorrowedFd<'_>, name: &CString) -> CreateProven {
    let errno = |e: SysError| super::describe(e);
    let seq = QUARANTINE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let stage = CString::new(format!(
        ".fandhe-stage-{}-{seq}-{nanos:08x}",
        std::process::id()
    ))
    .map_err(|_| ("mkdir", "invalid staging name".to_owned()))?;
    let inner = CString::new("new").map_err(|_| ("mkdir", "invalid staging name".to_owned()))?;
    sys::mkdir_at(parent, &stage, QUARANTINE_MODE).map_err(|e| ("mkdir", errno(e)))?;
    let drop_stage = || -> Option<String> {
        sys::remove_dir_at(parent, &stage).err().map(|e| {
            format!(
                "removing the staging directory failed: {}; it was left in place",
                errno(e)
            )
        })
    };
    let sdir = match sys::open_dir_path_nofollow(Some(parent), &stage) {
        Ok(fd) => fd,
        Err(e) => return Err(("open", join_detail(errno(e), drop_stage()))),
    };
    match fstat_fd(sdir.as_fd()) {
        Ok(st)
            if st.is_dir
                && st.uid == sys::effective_uid()
                && st.mode & 0o777 == QUARANTINE_MODE => {}
        Ok(_) => {
            return Err((
                "verify",
                join_detail(
                    "the staging directory is not private to this process; left in place"
                        .to_owned(),
                    drop_stage(),
                ),
            ));
        }
        Err(e) => return Err(("verify", join_detail(errno(e), drop_stage()))),
    }
    // ステージング内の `new`（作っていれば）とステージング自体を消し、失敗を元のエラーへ併記する。
    let unstage = |made: bool| -> Option<String> {
        let first = if made {
            sys::remove_dir_at(sdir.as_fd(), &inner)
                .err()
                .map(|e| format!("removing the staged directory failed: {}", errno(e)))
        } else {
            None
        };
        match (first, drop_stage()) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        }
    };
    if let Err(e) = sys::mkdir_at(sdir.as_fd(), &inner, DIR_MODE) {
        return Err(("mkdir", join_detail(errno(e), unstage(false))));
    }
    let fd = match sys::open_dir_path_nofollow(Some(sdir.as_fd()), &inner) {
        Ok(fd) => fd,
        Err(e) => return Err(("open", join_detail(errno(e), unstage(true)))),
    };
    let id = match fstat_fd(fd.as_fd()) {
        Ok(st) => (st.dev, st.ino),
        Err(e) => return Err(("verify", join_detail(errno(e), unstage(true)))),
    };
    match sys::rename_noreplace_at(sdir.as_fd(), &inner, parent, name) {
        Ok(()) => Ok(Some((fd, id, drop_stage()))),
        // 既に同名がある。作った分は捨てて、既存を使わせる。
        Err(SysError::Os(sys::EEXIST)) => match unstage(true) {
            None => Ok(None),
            Some(x) => Err(("rmdir", x)),
        },
        Err(e) => Err(("rename", join_detail(errno(e), unstage(true)))),
    }
}

/// rootfs とその祖先の `(st_dev, st_ino)`（先頭が rootfs 自身）。`..` を `O_NOFOLLOW` で辿り、同じ位置に戻ったら
/// （namespace のルート）終わる。上限 [`MAX_ANCESTORS`] 段を超えたら fail-closed。
fn rootfs_identity_chain(root: BorrowedFd<'_>) -> Result<Vec<(u64, u64)>, ExecError> {
    let id = |fd: BorrowedFd<'_>| {
        fstat_fd(fd)
            .map(|st| (st.dev, st.ino))
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstat(rootfs ancestor)"))
    };
    let mut ids = vec![id(root)?];
    let mut cur = root
        .try_clone_to_owned()
        .map_err(|e| ExecError::from_io(&e, STAGE, "dup(rootfs)"))?;
    loop {
        let parent = sys::open_dir_path_nofollow(Some(cur.as_fd()), c"..")
            .map_err(|e| ExecError::from_sys(e, STAGE, "openat(rootfs ancestor)"))?;
        let parent_id = id(parent.as_fd())?;
        if ids.last() == Some(&parent_id) {
            return Ok(ids);
        }
        ids.push(parent_id);
        if ids.len() > MAX_ANCESTORS {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "the rootfs has too many ancestors to verify the bind mount sources",
            ));
        }
        cur = parent;
    }
}

/// `fstat` の結果のうち必要な値。
struct FdStat {
    dev: u64,
    ino: u64,
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
    uid: u32,
    mode: u32,
}

/// `fd`（`O_PATH` でもよい）の `fstat`。fd は複製して見るだけで、呼び出し側の fd は保持される。
fn fstat_fd(fd: BorrowedFd<'_>) -> Result<FdStat, SysError> {
    use std::os::unix::fs::MetadataExt as _;
    let os = |e: std::io::Error| SysError::Os(e.raw_os_error().unwrap_or(sys::EINVAL));
    let dup = fd.try_clone_to_owned().map_err(os)?;
    let meta = std::fs::File::from(dup).metadata().map_err(os)?;
    Ok(FdStat {
        dev: meta.dev(),
        ino: meta.ino(),
        is_dir: meta.file_type().is_dir(),
        is_file: meta.file_type().is_file(),
        is_symlink: meta.file_type().is_symlink(),
        uid: meta.uid(),
        mode: meta.mode(),
    })
}

/// user namespace の確認（純関数）。PID 1 が初期 user namespace にいる、またはホストの ID 0 を写像した経路は拒否する
/// （user namespace なしでは特権ランチャー由来の capability がホストの inode に効くため適用しない。SEC-5）。
fn judge_user_namespace(
    user_ns_inode: u64,
    uid_map: &[IdMapping],
    gid_map: &[IdMapping],
) -> Result<(), ViolationReason> {
    if user_ns_inode == USER_NS_INIT_INO {
        return Err(ViolationReason::UserNamespaceRequired);
    }
    if uid_map
        .iter()
        .chain(gid_map)
        .any(|m| m.host_id == 0 && m.count > 0)
    {
        return Err(ViolationReason::HostRootIdentityMapping);
    }
    Ok(())
}

/// 呼び出しスレッドの user namespace を確認する（[`judge_user_namespace`] の入力を `/proc` から集める）。
fn check_user_namespace() -> Result<(), ExecError> {
    let fail = |msg: &str| ExecError::new(ErrorCode::FailedPrecondition, STAGE, msg);
    let link = thread_ns_link("user").map_err(|_| fail("cannot read /proc/thread-self/ns/user"))?;
    let inode = link
        .strip_prefix("user:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| fail("malformed /proc/thread-self/ns/user"))?;
    let read_map = |name: &str| -> Result<Vec<IdMapping>, ExecError> {
        let file = std::fs::File::open(format!("/proc/thread-self/{name}"))
            .map_err(|_| fail("cannot read the id map of the user namespace"))?;
        let mut buf = Vec::new();
        file.take(MAX_ID_MAP_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|_| fail("cannot read the id map of the user namespace"))?;
        if buf.len() as u64 > MAX_ID_MAP_BYTES {
            return Err(fail("the id map of the user namespace is too large"));
        }
        parse_id_map(&buf).map_err(|_| fail("malformed id map of the user namespace"))
    };
    let uid = read_map("uid_map")?;
    let gid = read_map("gid_map")?;
    judge_user_namespace(inode, &uid, &gid)
        .map_err(|r| ExecError::from_violation_at(r, None, STAGE))
}

/// 違反の拒否を作る。違反記録の対象と message のパスは**コンテナ内の宛先**（ホスト側のマウント元は載せない）。
fn violation(spec: &BindMountSpec, reason: ViolationReason) -> ExecError {
    let mut err = ExecError::from_violation_at(reason, Some(spec.destination().as_path()), STAGE);
    err.message = format!(
        "mounts[{}] ({}): {}",
        spec.index(),
        display_destination(spec.destination().as_str()),
        reason.message()
    );
    err
}

/// 違反ではない前提不成立（`FAILED_PRECONDITION`）。message の先頭に位置と宛先を付ける。
fn failed(spec: &BindMountSpec, what: &str) -> ExecError {
    ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "mounts[{}] ({}): {what}",
            spec.index(),
            display_destination(spec.destination().as_str())
        ),
    )
}

/// 共有ヘルパが返したエラーの message に位置と宛先を前置きする（違反記録・code・段は保つ）。
fn annotate(spec: &BindMountSpec, mut err: ExecError) -> ExecError {
    err.message = format!(
        "mounts[{}] ({}): {}",
        spec.index(),
        display_destination(spec.destination().as_str()),
        err.message
    );
    err
}

/// 新マウント API・syscall の失敗を写す。`Unsupported` は縮退せず `UNIMPLEMENTED` で拒否する。
fn mount_api_error(spec: &BindMountSpec, e: SysError, what: &str) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        let mut err = failed(
            spec,
            "bind mount requires the new mount API (open_tree, mount_setattr, move_mount; \
             Linux 5.12 or later)",
        );
        err.code = ErrorCode::Unimplemented;
        return err;
    }
    annotate(spec, ExecError::from_sys(e, STAGE, what))
}

/// `open_tree(OPEN_TREE_CLONE)` の失敗を写す。非再帰の `EINVAL` は、配下にロックされたマウントを持つ元を
/// user namespace の中で非再帰に複製できないときに返る（`rbind` を促す）。
fn open_tree_error(spec: &BindMountSpec, e: SysError, scope: MountTreeScope) -> ExecError {
    if e == SysError::Os(sys::EINVAL) && scope == MountTreeScope::MountOnly {
        return failed(
            spec,
            "the source has submounts that cannot be bound non-recursively in a user namespace; \
             use rbind",
        );
    }
    mount_api_error(spec, e, "open_tree(bind mount source)")
}
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use crate::audit_log::mount::tests::VecSink;
    use crate::audit_log::{AuditDelivery, AuditLayer};
    use crate::exec::{ViolationKind, audit_mount_violation};
    use crate::oci_runtime::parse_config_bytes;
    use crate::test_support::TestTempDir;
    use serde_json::{Value, json};
    use std::cell::{Cell, RefCell};

    /// `statfs.f_flags` の値（include/linux/statfs.h）。
    const VALID: i64 = 0x20;
    const RDONLY: i64 = 0x1;
    const NOSUID: i64 = 0x2;
    const NODEV: i64 = 0x4;
    const NOEXEC: i64 = 0x8;

    /// 一時ディレクトリ配下の rootfs と元の置き場。
    struct Fx {
        tmp: TestTempDir,
        rootfs: PathBuf,
        src: PathBuf,
    }

    fn fx() -> Fx {
        let tmp = TestTempDir::new("bind-mounts").expect("temp dir");
        let rootfs = tmp.path().join("rootfs");
        let src = tmp.path().join("src");
        std::fs::create_dir(&rootfs).expect("rootfs");
        std::fs::create_dir(&src).expect("src");
        std::fs::create_dir(src.join("dir")).expect("src/dir");
        std::fs::write(src.join("file"), b"data").expect("src/file");
        Fx { tmp, rootfs, src }
    }

    impl Fx {
        fn src(&self, rel: &str) -> String {
            self.src.join(rel).to_str().expect("utf8").to_owned()
        }

        fn rootfs_fd(&self) -> OwnedFd {
            let c = CString::new(self.rootfs.as_os_str().as_bytes()).expect("cstring");
            sys::open_dir_path_nofollow(None, &c).expect("open rootfs")
        }

        /// `tmp` からの相対表記（記録を決定的にするため）。
        fn rel(&self, p: &Path) -> String {
            p.strip_prefix(self.tmp.path())
                .map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
        }
    }

    fn set_of(mounts: Vec<Value>) -> BindMountSet {
        let cfg = json!({"ociVersion": "1.2.0", "root": {"path": "rootfs"}, "mounts": mounts});
        let cfg = parse_config_bytes(cfg.to_string().as_bytes()).expect("valid config");
        BindMountSet::from_mounts(cfg.mounts()).expect("valid bind set")
    }

    fn m(dest: &str, src: &str, opts: &[&str]) -> Value {
        json!({"destination": dest, "type": "bind", "source": src, "options": opts})
    }

    fn one(dest: &str, src: &str, opts: &[&str]) -> BindMountSet {
        set_of(vec![m(dest, src, opts)])
    }

    /// dry-run の挙動を変える設定。
    #[derive(Default)]
    struct Knobs {
        shared: bool,
        moved: bool,
        open_tree_err: Option<SysError>,
        /// 2 件目の `is_shared` だけを真にする。
        shared_on_second: bool,
        clone_flags: Option<i64>,
        observe_mod: Option<fn(BindObservation) -> BindObservation>,
        mountinfo: Option<String>,
        umount_fail: bool,
    }

    fn bits(read_only: bool, noexec: bool) -> i64 {
        VALID
            | NOSUID
            | NODEV
            | if read_only { RDONLY } else { 0 }
            | if noexec { NOEXEC } else { 0 }
    }

    fn ideal_mountinfo(own: u64, read_only: bool, noexec: bool) -> String {
        let opts = format!(
            "{},nosuid,nodev{}",
            if read_only { "ro" } else { "rw" },
            if noexec { ",noexec" } else { "" }
        );
        format!("{own} 1 0:1 / /x {opts} - tmpfs none rw\n")
    }

    /// dry-run で `mount_binds_at` を回し、結果と呼び出し記録を返す。
    fn run(
        fx: &Fx,
        set: &BindMountSet,
        k: &Knobs,
    ) -> (Result<BindMountReport, ExecError>, Vec<String>) {
        let log = RefCell::new(Vec::<String>::new());
        let attrs = Cell::new((false, false));
        let src_id = Cell::new((0u64, 0u64));
        let shared_calls = Cell::new(0usize);
        let push = |s: String| log.borrow_mut().push(s);
        let deps = BindDeps {
            is_shared: &|_| {
                push("is_shared".into());
                shared_calls.set(shared_calls.get() + 1);
                Ok(k.shared || (k.shared_on_second && shared_calls.get() == 2))
            },
            still_at: &|_, p| {
                push(format!("still_at({})", fx.rel(p)));
                !k.moved
            },
            open_tree: &|src, scope| {
                push(format!("open_tree({scope:?})"));
                if let Some(e) = k.open_tree_err {
                    return Err(e);
                }
                src_id.set(src.dev_ino());
                src.as_fd()
                    .try_clone_to_owned()
                    .map_err(|_| SysError::Os(sys::EBADF))
            },
            set_attrs: &|_, a, scope| {
                let (set, clr, _, _, flags, _) = sys::bind_mount_call_params(a, scope);
                push(format!("setattr({set:#x},{clr:#x},{flags:#x})"));
                attrs.set((a.read_only, a.noexec));
                Ok(())
            },
            flags_of: &|_| {
                push("statfs_clone".into());
                let (ro, ne) = attrs.get();
                Ok(MountFlags::from_bits(k.clone_flags.unwrap_or(bits(ro, ne))))
            },
            attach: &|_, to| {
                let path = std::fs::read_link(format!("/proc/thread-self/fd/{}", to.as_raw_fd()))
                    .expect("readlink dest");
                push(format!("move_mount({})", fx.rel(&path)));
                Ok(())
            },
            observe: &|_, _, _| {
                push("observe".into());
                let (ro, ne) = attrs.get();
                let o = BindObservation {
                    before_mnt_id: 100,
                    after_mnt_id: 200,
                    own_mnt_id: 200,
                    flags: MountFlags::from_bits(bits(ro, ne)),
                    dev_ino: src_id.get(),
                };
                Ok(k.observe_mod.map_or(o, |f| f(o)))
            },
            mountinfo: &|| {
                push("mountinfo".into());
                let (ro, ne) = attrs.get();
                Ok(k.mountinfo
                    .clone()
                    .unwrap_or_else(|| ideal_mountinfo(200, ro, ne)))
            },
            umount: &|fd| {
                let path = std::fs::read_link(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))
                    .expect("readlink clone");
                push(format!("umount({})", fx.rel(&path)));
                if k.umount_fail {
                    Err(SysError::Os(sys::EBUSY))
                } else {
                    Ok(())
                }
            },
            before_attach: &|| push("before_attach".into()),
        };
        let root = fx.rootfs_fd();
        let result = mount_binds_at(root.as_fd(), set, &deps);
        (result, log.into_inner())
    }

    fn ok(fx: &Fx, set: &BindMountSet) -> BindMountReport {
        let (r, log) = run(fx, set, &Knobs::default());
        r.unwrap_or_else(|e| panic!("unexpected error: {e}; log: {log:?}"))
    }

    fn reason_of(err: &ExecError) -> Option<ViolationReason> {
        err.violation.as_ref().map(|v| v.reason)
    }

    /// CORE-1・SEC-1・OCI-4: ディレクトリ・非再帰・rw の呼び出し順と具体値。
    #[test]
    fn core1_sec1_directory_bind_runs_in_order() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let report = r.expect("applied");
        assert_eq!(
            log,
            [
                "is_shared",
                "open_tree(MountOnly)",
                "setattr(0x6,0x0,0x1000)",
                "statfs_clone",
                "still_at(rootfs/mnt/d)",
                "before_attach",
                "move_mount(rootfs/mnt/d)",
                "observe",
                "mountinfo",
            ]
        );
        assert_eq!(report.mounts.len(), 1);
        let o = &report.mounts[0];
        assert_eq!(
            (
                o.index,
                o.destination.as_str(),
                o.source_kind,
                o.read_only,
                o.noexec,
                o.recursive,
                o.created_target
            ),
            (
                0,
                "/mnt/d",
                BindSourceType::Directory,
                false,
                false,
                false,
                true
            )
        );
        assert!(fx.rootfs.join("mnt/d").is_dir());
    }

    /// CORE-1・SEC-1: `rbind`＋`ro`＋`noexec` は再帰で複製し、属性は 0xf・`AT_RECURSIVE` を足す。
    #[test]
    fn core1_sec1_rbind_ro_noexec_uses_recursive_scope_and_all_attrs() {
        let fx = fx();
        let set = one("/d", &fx.src("dir"), &["rbind", "ro", "noexec"]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let report = r.expect("applied");
        assert_eq!(log.get(1).map(String::as_str), Some("open_tree(Recursive)"));
        assert_eq!(
            log.get(2).map(String::as_str),
            Some("setattr(0xf,0x0,0x9000)")
        );
        let o = &report.mounts[0];
        assert_eq!((o.read_only, o.noexec, o.recursive), (true, true, true));
    }

    /// CORE-1: 通常ファイルの元で宛先が無い場合、親ディレクトリと空の通常ファイルを作る。
    #[test]
    fn core1_file_source_creates_parent_and_empty_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let fx = fx();
        let set = one("/etc/app/conf", &fx.src("file"), &[]);
        let report = ok(&fx, &set);
        let o = &report.mounts[0];
        assert_eq!(
            (o.source_kind, o.created_target),
            (BindSourceType::RegularFile, true)
        );
        let target = fx.rootfs.join("etc/app/conf");
        let meta = std::fs::symlink_metadata(&target).expect("target");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 0);
        let dir = std::fs::metadata(fx.rootfs.join("etc/app")).expect("dir");
        assert_eq!(dir.permissions().mode() & 0o700, 0o700);
    }

    /// CORE-1: 既存のマウント先は作らず（`created_target` は偽）、中身も消さない。
    #[test]
    fn core1_existing_target_is_not_created() {
        let fx = fx();
        std::fs::create_dir(fx.rootfs.join("mnt")).expect("mnt");
        std::fs::write(fx.rootfs.join("existing"), b"keep").expect("file");
        let set = set_of(vec![
            m("/mnt", &fx.src("dir"), &[]),
            m("/existing", &fx.src("file"), &[]),
        ]);
        let report = ok(&fx, &set);
        assert_eq!(
            report
                .mounts
                .iter()
                .map(|o| o.created_target)
                .collect::<Vec<_>>(),
            [false, false]
        );
        assert_eq!(
            std::fs::read(fx.rootfs.join("existing")).expect("read"),
            b"keep"
        );
    }

    /// 元の拒否は syscall の記録が 0 件で、宛先に何も作らない。
    fn assert_source_rejected(
        fx: &Fx,
        source: &str,
        reason: Option<ViolationReason>,
        code: ErrorCode,
    ) -> ExecError {
        let set = one("/mnt/x", source, &[]);
        let (r, log) = run(fx, &set, &Knobs::default());
        let err = r.expect_err("must be rejected");
        assert_eq!(log, Vec::<String>::new(), "{source}");
        assert!(!fx.rootfs.join("mnt").exists(), "{source}");
        assert_eq!(reason_of(&err), reason, "{source}: {err}");
        assert_eq!((err.code, err.stage), (code, IsolationStage::MountBinds));
        err
    }

    /// SEC-1: 元の経路の symlink（中間・末端）は辿らず拒否する。
    #[test]
    fn sec1_source_symlinks_are_rejected() {
        let fx = fx();
        std::fs::create_dir(fx.src.join("real")).expect("real");
        std::fs::create_dir(fx.src.join("real/sub")).expect("sub");
        std::os::unix::fs::symlink("real", fx.src.join("lnk")).expect("symlink");
        std::os::unix::fs::symlink("file", fx.src.join("flnk")).expect("symlink");
        for source in [fx.src("lnk/sub"), fx.src("lnk"), fx.src("flnk")] {
            assert_source_rejected(
                &fx,
                &source,
                Some(ViolationReason::BindSourceSymlink),
                ErrorCode::InvalidArgument,
            );
        }
    }

    /// SEC-1: ソケットなどディレクトリ・通常ファイル以外は拒否する。
    #[test]
    fn sec1_source_unsupported_type_is_rejected() {
        let fx = fx();
        let _listener =
            std::os::unix::net::UnixListener::bind(fx.src.join("sock")).expect("socket");
        assert_source_rejected(
            &fx,
            &fx.src("sock"),
            Some(ViolationReason::BindSourceUnsupportedType),
            ErrorCode::InvalidArgument,
        );
    }

    /// 存在しない元は違反ではなく `NOT_FOUND`（何も作らない）。
    #[test]
    fn missing_source_is_not_found_without_violation() {
        let fx = fx();
        let err = assert_source_rejected(&fx, &fx.src("nope"), None, ErrorCode::NotFound);
        assert!(err.message.contains("does not exist"), "{}", err.message);
        let err = assert_source_rejected(&fx, &fx.src("nope/deeper"), None, ErrorCode::NotFound);
        assert!(
            err.message.starts_with("mounts[0] (/mnt/x): "),
            "{}",
            err.message
        );
    }

    /// 後始末の前に権限を戻す（`TestTempDir` の再帰削除が失敗しないように）。
    struct RestoreMode(PathBuf);

    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }

    /// SEC-1: 起動を依頼した利用者の権限で読めない元（ディレクトリ・ファイル）は拒否する。
    ///
    /// 非 root 前提（CI の GitHub ホステッド runner と開発コンテナは非 root）。root で読めてしまう場合は
    /// 黙って通さず、前提が崩れたことを明示して失敗させる。
    #[test]
    fn sec1_unreadable_source_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;
        let fx = fx();
        std::fs::create_dir(fx.src.join("locked")).expect("locked");
        std::fs::write(fx.src.join("locked.txt"), b"x").expect("locked file");
        let _g1 = RestoreMode(fx.src.join("locked"));
        let _g2 = RestoreMode(fx.src.join("locked.txt"));
        for p in ["locked", "locked.txt"] {
            std::fs::set_permissions(fx.src.join(p), std::fs::Permissions::from_mode(0o000))
                .expect("chmod");
        }
        assert!(
            std::fs::read_dir(fx.src.join("locked")).is_err()
                && std::fs::read(fx.src.join("locked.txt")).is_err(),
            "this test requires a non-root user; the fixture is readable"
        );
        for source in [fx.src("locked"), fx.src("locked.txt")] {
            let err = assert_source_rejected(
                &fx,
                &source,
                Some(ViolationReason::BindSourceNotAccessible),
                ErrorCode::PermissionDenied,
            );
            assert!(
                !err.message.contains("locked"),
                "host path leaked: {}",
                err.message
            );
        }
    }

    /// SEC-1: rootfs 自身とその祖先は元にできない（実体の `(dev, ino)` で照合する）。
    #[test]
    fn sec1_source_containing_rootfs_is_rejected() {
        let fx = fx();
        for source in [
            fx.rootfs.to_str().expect("utf8").to_owned(),
            fx.tmp.path().to_str().expect("utf8").to_owned(),
        ] {
            assert_source_rejected(
                &fx,
                &source,
                Some(ViolationReason::BindSourceContainsRootfs),
                ErrorCode::InvalidArgument,
            );
        }
    }

    /// rootfs の祖先の鎖は rootfs 自身から始まり、名前空間のルートで終わる。
    #[test]
    fn rootfs_identity_chain_starts_at_rootfs_and_ends_at_root() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let root = fx.rootfs_fd();
        let chain = rootfs_identity_chain(root.as_fd()).expect("chain");
        let id = |p: &Path| {
            let m = std::fs::metadata(p).expect("metadata");
            (m.dev(), m.ino())
        };
        assert_eq!(chain.first(), Some(&id(&fx.rootfs)));
        assert_eq!(chain.get(1), Some(&id(fx.tmp.path())));
        assert_eq!(chain.last(), Some(&id(Path::new("/"))));
        assert!(chain.len() >= 3);
    }

    /// SEC-1: マウント先の symlink（中間・末端）は拒否し、既存の内容は残る。
    #[test]
    fn sec1_target_symlinks_are_rejected() {
        let fx = fx();
        std::fs::create_dir(fx.rootfs.join("keep")).expect("keep");
        std::fs::write(fx.rootfs.join("keep/inside"), b"x").expect("inside");
        std::os::unix::fs::symlink("/etc", fx.rootfs.join("keep/sym")).expect("symlink");
        std::os::unix::fs::symlink("/etc", fx.rootfs.join("leaf")).expect("symlink");
        for dest in ["/keep/sym/x", "/leaf"] {
            let set = one(dest, &fx.src("dir"), &[]);
            let (r, log) = run(&fx, &set, &Knobs::default());
            let err = r.expect_err("must be rejected");
            assert_eq!(
                reason_of(&err),
                Some(ViolationReason::PathSymlinkOrNotDirectory),
                "{dest}"
            );
            assert_eq!(log, Vec::<String>::new(), "{dest}");
        }
        assert!(fx.rootfs.join("keep/inside").is_file());
        // 拒否前に作ったディレクトリ（`new/...`）は後始末で消える。
        let set = set_of(vec![
            m("/new/deep", &fx.src("dir"), &[]),
            m("/leaf", &fx.src("dir"), &[]),
        ]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        assert!(r.is_err());
        assert!(log.iter().any(|l| l.starts_with("umount")), "{log:?}");
        assert!(!fx.rootfs.join("new").exists());
    }

    /// SEC-1: 既存のマウント先の種別が元と違えば拒否し、既存のものは消さない。
    #[test]
    fn sec1_target_kind_mismatch_is_rejected() {
        let fx = fx();
        std::fs::write(fx.rootfs.join("afile"), b"keep").expect("file");
        std::fs::create_dir(fx.rootfs.join("adir")).expect("dir");
        for (dest, source) in [("/afile", fx.src("dir")), ("/adir", fx.src("file"))] {
            let set = one(dest, &source, &[]);
            let (r, log) = run(&fx, &set, &Knobs::default());
            let err = r.expect_err("must be rejected");
            assert_eq!(
                reason_of(&err),
                Some(ViolationReason::BindTargetKindMismatch),
                "{dest}"
            );
            assert_eq!(err.code, ErrorCode::InvalidArgument);
            assert_eq!(log, Vec::<String>::new());
        }
        assert_eq!(
            std::fs::read(fx.rootfs.join("afile")).expect("read"),
            b"keep"
        );
        assert!(fx.rootfs.join("adir").is_dir());
    }

    /// SEC-1・CORE-1: shared の宛先には載せない（複製に進まず、作った要素は消える）。
    #[test]
    fn sec1_shared_target_is_rejected_before_clone() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let k = Knobs {
            shared: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(reason_of(&err), Some(ViolationReason::TargetOnSharedMount));
        assert_eq!(log, ["is_shared"]);
        assert!(!fx.rootfs.join("mnt").exists());
    }

    /// SEC-1: 付け替え直前の移動検査。付け替えには進まず、作った要素は消える。
    #[test]
    fn sec1_moved_target_is_rejected_before_attach() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let k = Knobs {
            moved: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(reason_of(&err), Some(ViolationReason::TargetMoved));
        assert_eq!(
            log.last().map(String::as_str),
            Some("still_at(rootfs/mnt/d)")
        );
        assert!(!log.iter().any(|l| l.starts_with("move_mount")), "{log:?}");
        assert!(!log.iter().any(|l| l == "before_attach"), "{log:?}");
        assert!(!log.iter().any(|l| l.starts_with("umount")), "{log:?}");
        assert!(!fx.rootfs.join("mnt").exists());
    }

    /// SEC-1: 付け替え前の属性確認。読み取り専用の元を rw で載せない・要求した `ro`/`noexec` が付かなければ拒否する。
    #[test]
    fn sec1_pre_attach_flag_mismatch_is_rejected() {
        let fx = fx();
        let cases: [(&[&str], i64, &str); 4] = [
            (&[], bits(true, false), "specify ro"),
            (&[], bits(false, true), "specify noexec"),
            (&["ro"], bits(false, false), "ro was not applied"),
            (&["noexec"], bits(false, false), "noexec was not applied"),
        ];
        for (opts, flags, needle) in cases {
            let set = one("/mnt/d", &fx.src("dir"), opts);
            let k = Knobs {
                clone_flags: Some(flags),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &k);
            let err = r.expect_err("must be rejected");
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{opts:?}");
            assert_eq!(err.violation, None);
            assert!(err.message.contains(needle), "{}", err.message);
            assert!(err.message.contains("before attach"), "{}", err.message);
            assert!(!log.iter().any(|l| l.starts_with("move_mount")), "{log:?}");
            assert!(!fx.rootfs.join("mnt").exists());
        }
    }

    /// SEC-1: 事後検証の各失敗は `FAILED_PRECONDITION`。自分のマウントを外し、作った要素を消す。
    #[test]
    fn sec1_post_verification_failures_roll_back() {
        let fx = fx();
        type Modify = fn(BindObservation) -> BindObservation;
        let observed: [(Modify, &str); 4] = [
            (
                |o| BindObservation {
                    after_mnt_id: o.before_mnt_id,
                    ..o
                },
                "no new mount",
            ),
            (
                |o| BindObservation { own_mnt_id: 7, ..o },
                "not the mount created by this call",
            ),
            (
                |o| BindObservation {
                    flags: MountFlags::from_bits(VALID | NODEV),
                    ..o
                },
                "after mount: nosuid and nodev",
            ),
            (
                |o| BindObservation {
                    dev_ino: (1, 2),
                    ..o
                },
                "not the same inode",
            ),
        ];
        for (modify, needle) in observed {
            let set = one("/mnt/d", &fx.src("dir"), &[]);
            let k = Knobs {
                observe_mod: Some(modify),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &k);
            let err = r.expect_err("must be rejected");
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert!(err.message.contains(needle), "{}", err.message);
            assert_eq!(
                log.last().map(String::as_str),
                Some("umount(src/dir)"),
                "{log:?}"
            );
            assert!(!fx.rootfs.join("mnt").exists(), "{needle}");
        }
        let infos = [
            (
                "200 1 0:1 / /x rw,nosuid,nodev shared:5 - tmpfs none rw\n",
                "shared or a slave",
            ),
            (
                "200 1 0:1 / /x rw,nosuid,nodev master:3 - tmpfs none rw\n",
                "shared or a slave",
            ),
            (
                "200 1 0:1 / /x rw,nosuid - tmpfs none rw\n",
                "nosuid and nodev",
            ),
            (
                "201 1 0:1 / /x rw,nosuid,nodev - tmpfs none rw\n",
                "no mount entry",
            ),
            ("garbage\n", "malformed line"),
        ];
        for (info, needle) in infos {
            let set = one("/mnt/d", &fx.src("dir"), &[]);
            let k = Knobs {
                mountinfo: Some(info.to_owned()),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &k);
            let err = r.expect_err("must be rejected");
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert!(err.message.contains(needle), "{}", err.message);
            assert_eq!(
                log.last().map(String::as_str),
                Some("umount(src/dir)"),
                "{log:?}"
            );
            assert!(!fx.rootfs.join("mnt").exists());
        }
    }

    /// REPAIR-4: 2 件目の失敗で 1 件目の自分のマウントが外れる。後始末の失敗は message に併記し、
    /// code・stage・violation は保つ。
    #[test]
    fn repair4_second_failure_rolls_back_first_and_reports_cleanup_failure() {
        let fx = fx();
        let set = set_of(vec![
            m("/a", &fx.src("dir"), &[]),
            m("/b/c", &fx.src("file"), &[]),
        ]);
        let k = Knobs {
            shared_on_second: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let base = r.expect_err("second must fail");
        assert_eq!(reason_of(&base), Some(ViolationReason::TargetOnSharedMount));
        assert_eq!(base.stage, IsolationStage::MountBinds);
        assert_eq!(log.last().map(String::as_str), Some("umount(src/dir)"));
        assert_eq!(
            log.iter().filter(|l| l.starts_with("umount")).count(),
            1,
            "{log:?}"
        );
        assert!(!fx.rootfs.join("a").exists());
        assert!(!fx.rootfs.join("b").exists());
        assert!(
            base.message.starts_with("mounts[1] (/b/c): "),
            "{}",
            base.message
        );

        let k = Knobs {
            shared_on_second: true,
            umount_fail: true,
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &k);
        let failed = r.expect_err("second must fail");
        assert_eq!(
            (failed.code, failed.stage, &failed.violation),
            (base.code, base.stage, &base.violation)
        );
        let suffix = failed
            .message
            .strip_prefix(&base.message)
            .expect("same prefix");
        assert!(
            suffix.starts_with("; cleanup failed: umount2(/a) failed: "),
            "{suffix}"
        );
    }

    /// 新マウント API の無いカーネルは `mount(2)` へ縮退せず `UNIMPLEMENTED`。非再帰の `EINVAL` は `rbind` を促す。
    #[test]
    fn unsupported_kernel_is_unimplemented_and_einval_hints_rbind() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let k = Knobs {
            open_tree_err: Some(SysError::Unsupported),
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert!(err.message.contains("new mount API"), "{}", err.message);
        assert_eq!(log, ["is_shared", "open_tree(MountOnly)"]);
        assert!(!fx.rootfs.join("mnt").exists());

        let k = Knobs {
            open_tree_err: Some(SysError::Os(sys::EINVAL)),
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("use rbind"), "{}", err.message);
        let rset = one("/mnt/d", &fx.src("dir"), &["rbind"]);
        let (r, _) = run(&fx, &rset, &k);
        assert!(!r.expect_err("rejected").message.contains("use rbind"));
    }

    /// 空の集合は何もしない（rootfs の祖先も辿らない）。
    #[test]
    fn empty_set_does_nothing() {
        let fx = fx();
        let (r, log) = run(&fx, &BindMountSet::default(), &Knobs::default());
        assert_eq!(r.expect("empty"), BindMountReport { mounts: Vec::new() });
        assert_eq!(log, Vec::<String>::new());
    }

    /// SEC-5: user namespace の判定（初期 user namespace・ホストの ID 0 の写像は拒否）。
    #[test]
    fn sec5_judge_user_namespace() {
        let map = |c, h, n| IdMapping {
            container_id: c,
            host_id: h,
            count: n,
        };
        let ok_ns = USER_NS_INIT_INO + 100;
        assert_eq!(
            judge_user_namespace(USER_NS_INIT_INO, &[map(0, 1000, 1)], &[map(0, 1000, 1)]),
            Err(ViolationReason::UserNamespaceRequired)
        );
        assert_eq!(
            judge_user_namespace(ok_ns, &[map(0, 0, 4_294_967_295)], &[map(0, 1000, 1)]),
            Err(ViolationReason::HostRootIdentityMapping)
        );
        assert_eq!(
            judge_user_namespace(ok_ns, &[map(0, 1000, 1)], &[map(0, 0, 1)]),
            Err(ViolationReason::HostRootIdentityMapping)
        );
        assert_eq!(
            judge_user_namespace(ok_ns, &[map(0, 1000, 1)], &[map(0, 1000, 1)]),
            Ok(())
        );
        assert_eq!(
            judge_user_namespace(
                ok_ns,
                &[map(0, 1000, 1), map(1, 100_000, 65_536)],
                &[map(0, 1000, 1), map(1, 100_000, 65_536)]
            ),
            Ok(())
        );
    }

    fn flags(b: i64) -> MountFlags {
        MountFlags::from_bits(b)
    }

    /// `check_flags` の具体値。
    #[test]
    fn check_flags_is_exact() {
        let rw = Expected {
            read_only: false,
            noexec: false,
        };
        let ro_ne = Expected {
            read_only: true,
            noexec: true,
        };
        assert_eq!(check_flags(flags(bits(false, false)), rw), Ok(()));
        assert_eq!(check_flags(flags(bits(true, true)), ro_ne), Ok(()));
        assert!(check_flags(flags(NOSUID | NODEV), rw).is_err());
        assert!(check_flags(flags(VALID | NODEV), rw).is_err());
        assert!(check_flags(flags(VALID | NOSUID), rw).is_err());
        assert!(
            check_flags(flags(bits(true, false)), rw)
                .unwrap_err()
                .ends_with("specify ro")
        );
        assert!(
            check_flags(flags(bits(false, true)), rw)
                .unwrap_err()
                .ends_with("specify noexec")
        );
        assert!(check_flags(flags(bits(false, false)), ro_ne).is_err());
    }

    fn line(id: u64, parent: u64, opts: &str, optional: &str) -> String {
        format!("{id} {parent} 0:1 / /x {opts} {optional} - tmpfs none rw\n")
    }

    /// `check_bind_subtree`: 自分のマウントは `ro`・`noexec` が要求と完全一致、配下は要求した制限が付いていればよい。
    #[test]
    fn check_bind_subtree_is_exact_for_top_and_requires_restrictions_for_children() {
        let rw = Expected {
            read_only: false,
            noexec: false,
        };
        let ro = Expected {
            read_only: true,
            noexec: false,
        };
        let good_top = line(10, 1, "rw,nosuid,nodev", "");
        let child_ro = line(11, 10, "ro,nosuid,nodev,noexec", "");
        let child_plain = line(11, 10, "rw,nosuid,nodev", "");
        let child_no_nosuid = line(11, 10, "rw,nodev", "");
        let child_shared = line(11, 10, "rw,nosuid,nodev", "shared:9");
        let grandchild_shared = line(12, 11, "rw,nosuid,nodev", "master:9");
        let other = line(50, 1, "rw", "shared:1");

        assert_eq!(check_bind_subtree(&good_top, 10, rw, false), Ok(()));
        // 非再帰では配下を見ない。
        assert_eq!(
            check_bind_subtree(&format!("{good_top}{child_no_nosuid}"), 10, rw, false),
            Ok(())
        );
        // 無関係のマウントは見ない。
        assert_eq!(
            check_bind_subtree(&format!("{other}{good_top}"), 10, rw, true),
            Ok(())
        );
        // 配下の元が持つより強い制限は許す。
        assert_eq!(
            check_bind_subtree(&format!("{good_top}{child_ro}"), 10, rw, true),
            Ok(())
        );
        for (info, needle) in [
            (format!("{good_top}{child_no_nosuid}"), "nosuid and nodev"),
            (format!("{good_top}{child_shared}"), "shared or a slave"),
            (
                format!("{good_top}{child_plain}{grandchild_shared}"),
                "shared or a slave",
            ),
        ] {
            let e = check_bind_subtree(&info, 10, rw, true).unwrap_err();
            assert!(e.contains(needle), "{e}");
        }
        // 配下に要求した `ro` が付いていなければ拒否。
        let ro_top = line(10, 1, "ro,nosuid,nodev", "");
        assert_eq!(check_bind_subtree(&ro_top, 10, ro, true), Ok(()));
        let e = check_bind_subtree(&format!("{ro_top}{child_plain}"), 10, ro, true).unwrap_err();
        assert!(e.contains("ro is not set"), "{e}");
        // 自分のマウントは完全一致。
        let e = check_bind_subtree(&ro_top, 10, rw, false).unwrap_err();
        assert!(e.contains("specify ro"), "{e}");
        let e = check_bind_subtree(&good_top, 10, ro, false).unwrap_err();
        assert!(e.contains("ro is not set"), "{e}");
        // 該当なし・重複・書式違反は fail-closed。
        assert!(
            check_bind_subtree(&good_top, 99, rw, false)
                .unwrap_err()
                .contains("no mount entry")
        );
        assert!(
            check_bind_subtree(&format!("{good_top}{good_top}"), 10, rw, false)
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(
            check_bind_subtree("10 1 0:1 / /x rw,nosuid,nodev\n", 10, rw, false)
                .unwrap_err()
                .contains("malformed")
        );
        assert!(
            check_bind_subtree(&format!("{good_top}x y\n"), 10, rw, false)
                .unwrap_err()
                .contains("malformed")
        );
    }

    /// 宛先をエスケープして message に入れる（ログ注入の防止）。
    #[test]
    fn message_escapes_destination() {
        let fx = fx();
        let set = one("/new\ndir", &fx.src("dir"), &[]);
        let k = Knobs {
            shared: true,
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &k);
        let err = r.expect_err("rejected");
        assert!(err.message.contains("/new\\ndir"), "{}", err.message);
        assert!(!err.message.contains('\n'), "{}", err.message);
    }

    /// SEC-4: 新しい理由の `ExecError` は `audit_mount_violation` で `Mount` レコードになり、パスはコンテナ内の宛先。
    #[test]
    fn sec4_violations_become_mount_audit_records_with_container_path() {
        let fx = fx();
        std::os::unix::fs::symlink("file", fx.src.join("flnk")).expect("symlink");
        std::fs::write(fx.rootfs.join("afile"), b"x").expect("file");
        let cases = [
            (
                one("/mnt/x", &fx.src("flnk"), &[]),
                "bind_source_symlink",
                "/mnt/x",
            ),
            (
                one("/afile", &fx.src("dir"), &[]),
                "bind_target_kind_mismatch",
                "/afile",
            ),
        ];
        for (set, token, dest) in cases {
            let (r, _) = run(&fx, &set, &Knobs::default());
            let err = r.expect_err("rejected");
            let sink = VecSink::new(false);
            let out = audit_mount_violation(err, None, &sink);
            assert_eq!(out.delivery, AuditDelivery::Recorded, "{token}");
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(
                recs[0].reason().map(crate::audit_log::AuditReason::as_str),
                Some(token)
            );
            assert_eq!(recs[0].path(), Some(Path::new(dest)));
        }
    }

    /// 新しい 5 理由の具体値（種別・ビヘイビア ID・`ErrorCode`・トークン）。
    #[test]
    fn violation_reasons_have_exact_attributes() {
        let table = [
            (
                ViolationReason::BindSourceSymlink,
                "bind_source_symlink",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindSourceUnsupportedType,
                "bind_source_unsupported_type",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindSourceNotAccessible,
                "bind_source_not_accessible",
                ErrorCode::PermissionDenied,
            ),
            (
                ViolationReason::BindSourceContainsRootfs,
                "bind_source_contains_rootfs",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindTargetKindMismatch,
                "bind_target_kind_mismatch",
                ErrorCode::InvalidArgument,
            ),
        ];
        for (reason, token, code) in table {
            assert_eq!(reason.as_str(), token);
            assert_eq!(reason.kind(), ViolationKind::MountTarget);
            assert_eq!(reason.behavior_id(), "SEC-1");
            assert_eq!(reason.error_code(), code);
            assert_eq!(ViolationReason::from_launch_token(token), Some(reason));
            assert!(!reason.message().is_empty());
        }
    }

    /// ディレクトリ `dir` を開いた fd と `(dev, ino)`。
    fn dir_fd_and_id(dir: &Path) -> (OwnedFd, (u64, u64)) {
        use std::os::unix::fs::MetadataExt as _;
        let c = CString::new(dir.as_os_str().as_bytes()).expect("cstring");
        let fd = sys::open_dir_path_nofollow(None, &c).expect("open dir");
        let meta = std::fs::metadata(dir).expect("metadata");
        (fd, (meta.dev(), meta.ino()))
    }

    /// SEC-1・REPAIR-4: ステージング経由で作ったディレクトリの `(dev, ino)` は配置後の実体と一致し、ステージングは残らない。
    /// 既存の名前は作らず `None`（上書きしない）。
    #[test]
    fn sec1_create_dir_proven_returns_the_placed_inode_and_leaves_no_staging() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let name = CString::new("d").expect("cstring");
        let (fd, id, leftover) = create_dir_proven(parent.as_fd(), &name)
            .expect("created")
            .expect("some");
        assert_eq!(leftover, None);
        let meta = std::fs::metadata(fx.rootfs.join("d")).expect("meta");
        assert_eq!(id, (meta.dev(), meta.ino()));
        let st = fstat_fd(fd.as_fd()).expect("fstat");
        assert_eq!((st.dev, st.ino), id);
        let names: Vec<_> = std::fs::read_dir(&fx.rootfs)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .filter(|n| n.to_string_lossy().starts_with(".fandhe-"))
            .collect();
        assert!(names.is_empty(), "leftover: {names:?}");
        assert!(
            create_dir_proven(parent.as_fd(), &name)
                .expect("exists")
                .is_none()
        );
    }

    /// SEC-1・REPAIR-4: 照合と削除の間に同名の別実体へ差し替えられたら消さず、元の名前へ戻して失敗を返す。
    #[test]
    fn sec1_remove_verified_leaves_a_swapped_file_and_reports() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let path = fx.rootfs.join("t");
        std::fs::write(&path, b"").expect("create");
        let meta = std::fs::metadata(&path).expect("meta");
        let ours = (meta.dev(), meta.ino());
        // 自分が作った実体を別プロセスが改名し、同名の別ファイルを置いた状況。
        std::fs::rename(&path, fx.rootfs.join("moved")).expect("rename");
        std::fs::write(&path, b"other").expect("swap");
        let name = CString::new("t").expect("cstring");
        let (what, _) = remove_verified(parent.as_fd(), &name, ours, false).expect_err("mismatch");
        assert_eq!(what, "verify");
        assert_eq!(std::fs::read(&path).expect("kept"), b"other");
        // 一致する実体は消える。
        let meta = std::fs::metadata(&path).expect("meta");
        remove_verified(parent.as_fd(), &name, (meta.dev(), meta.ino()), false).expect("removed");
        assert!(!path.exists());
        // 既に無い要素は成功扱い。
        remove_verified(parent.as_fd(), &name, ours, false).expect("already gone");
    }

    /// SEC-1・REPAIR-4: 差し替えられた空ディレクトリは消さず、中身のあるディレクトリは削除失敗として返す。
    #[test]
    fn sec1_remove_verified_leaves_a_swapped_or_non_empty_dir_and_reports() {
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let path = fx.rootfs.join("d");
        std::fs::create_dir(&path).expect("mkdir");
        let (_, ours) = dir_fd_and_id(&path);
        std::fs::rename(&path, fx.rootfs.join("moved")).expect("rename");
        std::fs::create_dir(&path).expect("swap");
        let name = CString::new("d").expect("cstring");
        let (what, _) = remove_verified(parent.as_fd(), &name, ours, true).expect_err("mismatch");
        assert_eq!(what, "verify");
        assert!(path.is_dir());

        let (_, id) = dir_fd_and_id(&path);
        std::fs::write(path.join("f"), b"x").expect("content");
        let (what, _) = remove_verified(parent.as_fd(), &name, id, true).expect_err("not empty");
        assert_eq!(what, "rmdir");
        assert!(path.join("f").exists(), "restored under the original name");
    }

    /// SEC-1: 成功した削除は隔離ディレクトリを残さない。`RENAME_NOREPLACE` の改名は既存の同名を上書きしない。
    #[test]
    fn sec1_remove_verified_leaves_no_quarantine_and_rename_never_replaces() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let path = fx.rootfs.join("t");
        std::fs::write(&path, b"").expect("create");
        let meta = std::fs::metadata(&path).expect("meta");
        let name = CString::new("t").expect("cstring");
        remove_verified(parent.as_fd(), &name, (meta.dev(), meta.ino()), false).expect("removed");
        let left: Vec<_> = std::fs::read_dir(&fx.rootfs)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .filter(|n| n.to_string_lossy().starts_with(".fandhe-rollback-"))
            .collect();
        assert!(left.is_empty(), "quarantine left: {left:?}");

        std::fs::write(fx.rootfs.join("a"), b"a").expect("a");
        std::fs::write(fx.rootfs.join("b"), b"b").expect("b");
        let (a, b) = (
            CString::new("a").expect("cstring"),
            CString::new("b").expect("cstring"),
        );
        let err = sys::rename_noreplace_at(parent.as_fd(), &a, parent.as_fd(), &b)
            .expect_err("must not replace");
        assert!(matches!(err, SysError::Os(sys::EEXIST)), "{err:?}");
        assert_eq!(std::fs::read(fx.rootfs.join("b")).expect("kept"), b"b");
    }

    /// SEC-1・REPAIR-4: `create_dir_proven` が配置したディレクトリを記録すれば、`roll_back_binds` が回収して残さない
    /// （ステージング掃除の失敗でも配置済みの実体を記録する契約の回帰）。
    #[test]
    fn sec1_placed_dir_recorded_from_create_dir_proven_is_rolled_back() {
        let fx = fx();
        let fd = fx.rootfs_fd();
        let name = CString::new("p").expect("cstring");
        let (_pfd, id, leftover) = create_dir_proven(fd.as_fd(), &name)
            .expect("created")
            .expect("some");
        assert_eq!(leftover, None);
        let unused = || SysError::Os(sys::EINVAL);
        let deps = BindDeps {
            is_shared: &|_| Ok(false),
            still_at: &|_, _| true,
            open_tree: &|_, _| Err(unused()),
            set_attrs: &|_, _, _| Err(unused()),
            flags_of: &|_| Err(unused()),
            attach: &|_, _| Err(unused()),
            observe: &|_, _, _| Err(ExecError::new(ErrorCode::Internal, STAGE, "unused")),
            mountinfo: &|| Ok(String::new()),
            umount: &|_| Ok(()),
            before_attach: &|| {},
        };
        let ctx = Ctx {
            root: fd.as_fd(),
            host_root: fx.rootfs.clone(),
            rootfs_ids: Vec::new(),
            deps: &deps,
        };
        let set = one("/p", &fx.src("dir"), &[]);
        let mut state = Applied::new(&set.mounts()[0]);
        state.created_dirs = vec![0];
        state.created_dir_ids = vec![(0, id)];
        let failures = roll_back_binds(&ctx, &[state]);
        assert!(failures.is_empty(), "{failures:?}");
        assert!(!fx.rootfs.join("p").exists());
    }

    /// REPAIR-4: 後始末中の開き直しの失敗も `; cleanup failed: ...` として元のエラーへ併記する。
    #[test]
    fn repair4_cleanup_open_failure_is_reported() {
        let fx = fx();
        let fd = fx.rootfs_fd();
        let unused = || SysError::Os(sys::EINVAL);
        let deps = BindDeps {
            is_shared: &|_| Ok(false),
            still_at: &|_, _| true,
            open_tree: &|_, _| Err(unused()),
            set_attrs: &|_, _, _| Err(unused()),
            flags_of: &|_| Err(unused()),
            attach: &|_, _| Err(unused()),
            observe: &|_, _, _| Err(ExecError::new(ErrorCode::Internal, STAGE, "unused")),
            mountinfo: &|| Ok(String::new()),
            umount: &|_| Ok(()),
            before_attach: &|| {},
        };
        let ctx = Ctx {
            root: fd.as_fd(),
            host_root: fx.rootfs.clone(),
            rootfs_ids: Vec::new(),
            deps: &deps,
        };
        let set = one("/a/b", &fx.src("dir"), &[]);
        let spec = &set.mounts()[0];
        let mut state = Applied::new(spec);
        state.created_dirs = vec![0, 1];
        state.created_dir_ids = vec![(0, (1, 1)), (1, (1, 1))];
        let failures = roll_back_binds(&ctx, &[state]);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].what, "open");
        let err = with_cleanup_failures(failed(spec, "x"), &failures);
        assert!(
            err.message
                .contains("; cleanup failed: open(/a/b) failed: "),
            "{}",
            err.message
        );
    }
}
