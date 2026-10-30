//! namespaced な sysctl のコンテナ内への適用（pivot 前段 `apply_sysctls`。CRI-2・CORE-3・SEC-1・#2670）。
//!
//! # 役割と呼び出し文脈
//!
//! `config.json` の `linux.sysctl`（検証済みの [`SysctlSet`]。キーの文法と名前空間の分類は [`crate::sysctl`]）を、
//! `run_pre_pivot` が `verify_pinned` の直後（`mount_sysfs` の前）に `rootfs/proc/sys` 配下へ書く。`readonly_paths` が
//! `/proc/sys` を読み取り専用にする前でなければ書けないため、pivot 前の段に置く。IPC 系の sysctl は書き込むプロセスの
//! IPC namespace（`current->nsproxy`）に効くので、子が新しい IPC namespace に入った後なら、書かれるのはコンテナ側の値で
//! ホストの値は変わらない。pod の user・ipc namespace へ join する起動（`oci_runtime::NamespaceJoin`。#2674）では、
//! 中間プロセスが join した後に子がこの段を通るため、書かれるのは共有された pod の IPC namespace の値になる（join 先は
//! 自身の子の user namespace が所有するものに限られ、ホストの IPC namespace ではない）。
//!
//! ```text
//! prepare_rootfs -> verify_pinned -> apply_sysctls(&isolation, &prepared, &plan) -> mount_sysfs
//!   -> create_default_devices -> ... -> readonly_paths -> masked_paths -> pivot_root
//! ```
//!
//! # ホストの値を書かせない型 [`SysctlPlan`]
//!
//! 起動前に launcher が、実効の名前空間（`--ipc=host` で IPC namespace を外した場合を含む）と
//! [`SysctlPlan::new`] で照合する。必要な名前空間が無ければ plan を作れないため、ホストの名前空間へ向かう書き込みは
//! 子へ渡る値として表現できない。network namespace は Loopback / Attachable モード（NET-6・NET-9・#3064・#1939）で子が新しく作る netns が実効の集合に
//! 入るときだけ `net.*` の plan を作れる（ホストの netns のままなら作れない）。pod の netns の結線は未対応（#2675。REPAIR-3）。
//!
//! # 契約
//!
//! - **fd 起点**: `new_root` から `proc` → `sys` → 各要素を `O_PATH|O_DIRECTORY|O_NOFOLLOW` で 1 要素ずつ辿り、
//!   パス文字列を再解決しない。`proc` と葉が procfs 上であること（`fstatfs`）と、葉が通常ファイルであることを確かめる
//! - **書き込みは 1 回**: 値を 1 回の `write(2)` で書き、書けた長さが値の長さと一致しなければ失敗とする。部分書き込みを
//!   再送しない（検証した値と違う値を残さない）
//! - **存在しないキーは失敗**: `ENOENT`（このカーネル・名前空間に無いキー）を読み飛ばさない。利用者が要求した値のため、
//!   `readonly_paths` の不在の読み飛ばしとは違い起動を止める（`InvalidArgument`）。`EINVAL`（値の不正）も同様
//! - **失敗時**: 後始末はしない。呼び出し側はプロセスを破棄する（`crate::exec` のモジュール doc の契約）
//! - **監査**: 失敗は分離違反の試行ではないため、違反の理由（`ViolationReason`）は付けない
//! - **メッセージ**: キー・値を含めない（固定文言のみ）
//!
//! # rootless の前提
//!
//! user namespace の root が IPC 系の sysctl に書けるかはカーネルの所有者づけに依存する（ipc namespace ごとの
//! `set_ownership` がある版に限る）。書けない環境では `PermissionDenied` で起動が失敗する（縮退・skip しない）。

use std::ffi::CString;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::sys::{self, SysError};
use crate::sysctl::{SysctlNamespace, SysctlSet};
use crate::traits::types::ErrorCode;

use super::{ExecError, IsolationStage, MountIsolation, NamespaceSet, PreparedRootfs};
use super::{Namespace, errno_to_code};

const STAGE: IsolationStage = IsolationStage::ApplySysctls;

/// 実効の名前空間と照合済みの sysctl の適用計画。生成は [`SysctlPlan::new`] だけ。
#[derive(Debug, Clone, Copy)]
pub(crate) struct SysctlPlan<'a> {
    set: &'a SysctlSet,
}

impl<'a> SysctlPlan<'a> {
    /// `set` が要る名前空間がすべて `effective`（子が新しく作るか、pod の namespace へ join する名前空間。ホストの
    /// 名前空間のまま残すものは含まない）にあるときだけ計画を作る。
    ///
    /// 空集合は `Ok(None)`（何も適用しない）。足りない名前空間があれば、その種別を `Err` で返す
    /// （IPC 系は IPC namespace、`net.*` は network namespace が要る。`net.*` は実効の集合に `Net` が無ければ `Err(Net)`。
    /// `Net` は Loopback / Attachable モードで子が新しく作る netns に限る。NET-6・NET-9・#3064・#1939）。
    pub(crate) fn new(
        set: &'a SysctlSet,
        effective: NamespaceSet,
    ) -> Result<Option<Self>, SysctlNamespace> {
        if set.is_empty() {
            return Ok(None);
        }
        if set.has_namespace(SysctlNamespace::Ipc) && !effective.contains(Namespace::Ipc) {
            return Err(SysctlNamespace::Ipc);
        }
        if set.has_namespace(SysctlNamespace::Net) && !effective.contains(Namespace::Net) {
            return Err(SysctlNamespace::Net);
        }
        Ok(Some(Self { set }))
    }
}

/// 計画の sysctl を `prepared` の `proc/sys` 配下へ書く。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。契約はモジュール doc。
pub(super) fn apply_sysctls(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    plan: &SysctlPlan<'_>,
) -> Result<(), ExecError> {
    isolation.verify_caller(STAGE)?;
    apply_at(prepared.new_root(), plan.set, sys::PROC_MAGIC)
}

/// [`apply_sysctls`] の証跡検証後の本体。`magic` は procfs として期待するファイルシステム種別
/// （本番は `PROC_MAGIC`。単体テストは偽の `proc` を作る一時ディレクトリの種別を渡す）。
fn apply_at(root: BorrowedFd<'_>, set: &SysctlSet, magic: i64) -> Result<(), ExecError> {
    let fail = |code: ErrorCode, message: &'static str| ExecError::new(code, STAGE, message);
    let proc_dir = sys::open_dir_path_nofollow(Some(root), c"proc")
        .map_err(|e| ExecError::from_sys(e, STAGE, "opening the proc directory of the rootfs"))?;
    if sys::fs_type(proc_dir.as_fd()) != Ok(magic) {
        return Err(fail(
            ErrorCode::FailedPrecondition,
            "the proc directory of the rootfs is not procfs",
        ));
    }
    let sys_dir = sys::open_dir_path_nofollow(Some(proc_dir.as_fd()), c"sys")
        .map_err(|e| ExecError::from_sys(e, STAGE, "opening proc/sys of the rootfs"))?;
    for (key, value) in set.iter() {
        let mut names = key.segments().peekable();
        let mut cur: Option<OwnedFd> = None;
        let mut leaf = None;
        while let Some(name) = names.next() {
            let c = CString::new(name)
                .map_err(|_| fail(ErrorCode::Internal, "a sysctl key segment contains NUL"))?;
            let parent = cur.as_ref().map_or(sys_dir.as_fd(), |f| f.as_fd());
            if names.peek().is_none() {
                leaf = Some(sys::open_write_at(parent, &c).map_err(open_error)?);
            } else {
                cur = Some(sys::open_dir_path_nofollow(Some(parent), &c).map_err(open_error)?);
            }
        }
        let Some(leaf) = leaf else {
            return Err(fail(ErrorCode::Internal, "a sysctl key is empty"));
        };
        if sys::fs_type(leaf.as_fd()) != Ok(magic) {
            return Err(fail(
                ErrorCode::FailedPrecondition,
                "a sysctl file is not on procfs",
            ));
        }
        let mut file = std::fs::File::from(leaf);
        match file.metadata() {
            Ok(m) if m.file_type().is_file() => {}
            Ok(_) => {
                return Err(fail(
                    ErrorCode::FailedPrecondition,
                    "a sysctl path is not a regular file",
                ));
            }
            Err(e) => return Err(ExecError::from_io(&e, STAGE, "checking a sysctl file")),
        }
        let bytes = value.as_str().as_bytes();
        match file.write(bytes) {
            Ok(n) if n == bytes.len() => {}
            Ok(_) => {
                return Err(fail(
                    ErrorCode::Internal,
                    "a sysctl value was written only partially",
                ));
            }
            Err(e) => return Err(write_error(&e)),
        }
    }
    Ok(())
}

/// 開く段の errno の写像。不在は利用者の指定の誤り（このカーネル・名前空間に無いキー）で `InvalidArgument`。
fn open_error(err: SysError) -> ExecError {
    if err == SysError::Os(sys::ENOENT) {
        return ExecError::new(
            ErrorCode::InvalidArgument,
            STAGE,
            "a sysctl key does not exist in this kernel or namespace",
        );
    }
    ExecError::from_sys(err, STAGE, "opening a sysctl file")
}

/// 書く段の errno の写像。値の不正（`EINVAL`）は `InvalidArgument`、それ以外は共通の写像。
fn write_error(err: &std::io::Error) -> ExecError {
    let sys_err = SysError::Os(err.raw_os_error().unwrap_or(0));
    if sys_err == SysError::Os(sys::EINVAL) {
        return ExecError::new(
            ErrorCode::InvalidArgument,
            STAGE,
            "the kernel rejected a sysctl value",
        );
    }
    ExecError::new(
        errno_to_code(sys_err),
        STAGE,
        "writing a sysctl value failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysctl::{SysctlKey, SysctlValue};
    use std::path::PathBuf;

    fn set_of(entries: &[(&str, &str)]) -> SysctlSet {
        let mut set = SysctlSet::new();
        for (k, v) in entries {
            set.insert(SysctlKey::parse(k).unwrap(), SysctlValue::parse(v).unwrap())
                .unwrap();
        }
        set
    }

    /// 偽の rootfs（`proc/sys/kernel/*` の空ファイル）。ScratchDir の drop で削除する。
    struct FakeRoot(PathBuf, #[allow(dead_code)] crate::scratch_root::ScratchDir);

    impl FakeRoot {
        fn new(tag: &str) -> Self {
            // pid＋nanos の名前を create_dir_all せず、排他作成の ScratchDir の子を使う（#3478・REPAIR-12）。
            let (scratch, dir) =
                crate::test_support::scratch_child(&format!("fandhe-sysctls-{tag}"), "root");
            std::fs::create_dir_all(dir.join("proc/sys/kernel")).unwrap();
            Self(dir, scratch)
        }
        fn file(&self, rel: &str) -> PathBuf {
            self.0.join("proc/sys").join(rel)
        }
        fn open(&self) -> OwnedFd {
            sys::open_dir_path_nofollow(None, &CString::new(self.0.to_str().unwrap()).unwrap())
                .unwrap()
        }
    }

    fn magic_of(root: &OwnedFd) -> i64 {
        sys::fs_type(root.as_fd()).unwrap()
    }

    /// CRI-2・CORE-3: 値を 1 回の書き込みで該当ファイルへ書く。
    #[test]
    fn writes_each_value_to_its_file() {
        let root = FakeRoot::new("write");
        std::fs::write(root.file("kernel/shmmax"), "").unwrap();
        std::fs::write(root.file("kernel/sem"), "").unwrap();
        let fd = root.open();
        let set = set_of(&[
            ("kernel.shmmax", "16384"),
            ("kernel.sem", "250 32000 32 128"),
        ]);
        apply_at(fd.as_fd(), &set, magic_of(&fd)).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.file("kernel/shmmax")).unwrap(),
            "16384"
        );
        assert_eq!(
            std::fs::read_to_string(root.file("kernel/sem")).unwrap(),
            "250 32000 32 128"
        );
    }

    /// CRI-2・CORE-3: 存在しないキーは読み飛ばさず `InvalidArgument` で止める。
    #[test]
    fn missing_key_stops_with_invalid_argument() {
        let root = FakeRoot::new("missing");
        let fd = root.open();
        let err = apply_at(
            fd.as_fd(),
            &set_of(&[("kernel.shmmax", "1")]),
            magic_of(&fd),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::ApplySysctls);
        assert!(!err.message.contains("shmmax"), "{}", err.message);
    }

    /// CORE-3・SEC-1: procfs でなければ（偽の種別を期待させて）書かずに拒否する。
    #[test]
    fn non_procfs_is_rejected_before_any_write() {
        let root = FakeRoot::new("magic");
        std::fs::write(root.file("kernel/shmmax"), "").unwrap();
        let fd = root.open();
        let err = apply_at(
            fd.as_fd(),
            &set_of(&[("kernel.shmmax", "1")]),
            magic_of(&fd) ^ 1,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            std::fs::read_to_string(root.file("kernel/shmmax")).unwrap(),
            ""
        );
    }

    /// SEC-1: 葉が symlink なら辿らず拒否する（`O_NOFOLLOW`。rootfs の外へ書かせない）。
    #[test]
    fn leaf_symlink_is_not_followed() {
        let root = FakeRoot::new("symlink");
        let target = root.0.join("outside");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, root.file("kernel/shmmax")).unwrap();
        let fd = root.open();
        let err = apply_at(
            fd.as_fd(),
            &set_of(&[("kernel.shmmax", "1")]),
            magic_of(&fd),
        )
        .unwrap_err();
        assert_ne!(err.code, ErrorCode::Unimplemented);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
    }

    /// SEC-1: 途中のディレクトリが symlink なら辿らず拒否する（rootfs の外へ書かせない）。
    #[test]
    fn intermediate_symlink_is_not_followed() {
        let root = FakeRoot::new("dirlink");
        let outside = root.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("msgmax"), "").unwrap();
        std::fs::remove_dir(root.file("kernel")).unwrap();
        std::os::unix::fs::symlink(&outside, root.file("kernel")).unwrap();
        let fd = root.open();
        assert!(
            apply_at(
                fd.as_fd(),
                &set_of(&[("kernel.msgmax", "1")]),
                magic_of(&fd)
            )
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(outside.join("msgmax")).unwrap(), "");
    }

    /// CORE-3・SEC-1: 計画は必要な名前空間が実効の集合にあるときだけ作れる（ホストの名前空間へ書かせない）。
    #[test]
    fn plan_requires_effective_namespaces() {
        let ipc = set_of(&[("kernel.shmmax", "1")]);
        let with_ipc = NamespaceSet::empty().with(Namespace::Ipc);
        assert!(SysctlPlan::new(&ipc, with_ipc).unwrap().is_some());
        assert_eq!(
            SysctlPlan::new(&ipc, NamespaceSet::empty()).unwrap_err(),
            SysctlNamespace::Ipc
        );
        assert!(
            SysctlPlan::new(&SysctlSet::new(), NamespaceSet::empty())
                .unwrap()
                .is_none()
        );
        let net = set_of(&[("net.ipv4.ip_forward", "1")]);
        assert!(
            SysctlPlan::new(&net, NamespaceSet::all())
                .unwrap()
                .is_some()
        );
        assert_eq!(
            SysctlPlan::new(&net, NamespaceSet::all().without(Namespace::Net)).unwrap_err(),
            SysctlNamespace::Net
        );
        assert_eq!(
            SysctlPlan::new(&net, NamespaceSet::empty()).unwrap_err(),
            SysctlNamespace::Net
        );
    }
}
