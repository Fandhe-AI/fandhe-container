//! init user namespace 所有の netns（置き場へ pin 済み）への参加指定の検証と fd 固定（NET-1・SEC-1・CORE-3・SEC-4。#3069）。
//!
//! # 役割と呼び出し元
//!
//! rootful のユーザー定義ネットワーク（bridge）は、`NetworkPlugin::create_netns` 側（init user namespace 所有）が netns を
//! 作って置き場へ pin する（`docs/design/network-wiring.md` D12）。supervisor が `LaunchOptions::with_netns_join` で
//! 置き場・pin のパス・(dev, ino) を [`NetnsJoinTarget`] として渡し、`start` が [`PinnedNetnsJoin::pin`] で 1 回だけ開いて
//! fd に固定する。本番 launcher の中間プロセス I は、**user namespace を作る前に** その fd へ `setns(CLONE_NEWNET)` する
//! （`exec::join_pinned_netns`）。
//!
//! pod の join（`NamespaceJoin`。#2872。pod の user namespace 所有の netns に限る）とは別の入口で、`linux.namespaces[].path` では
//! なく起動オプションから入る。pod join の表・文言・語彙は変えない。
//!
//! # なぜ user namespace の作成前か
//!
//! カーネルは `netns_install` で、参加先の netns を所有する user namespace（init）と呼び出し側の現在の user namespace の
//! **両方**で `CAP_SYS_ADMIN` を要求する。コンテナの user namespace を作った後では、init 所有の netns に対して子の
//! user namespace は権限を持てず `EPERM` になる。作る前なら、ambient に `CAP_SYS_ADMIN` を持つ非 root の supervisor 由来の
//! 中間プロセスが両方を満たす。
//!
//! # 検証（すべて fork・予約の前。メッセージは固定文言でパスを含めない）
//!
//! | 順 | 検査 | 不合格 |
//! | -- | ---- | ------ |
//! | 0 | 置き場・pin が絶対・`..` なし・4096 バイト以内・pin が置き場の直下の 1 要素 | `InvalidArgument` |
//! | 0 | 置き場を "/" から全要素 symlink 非追従で 1 要素ずつ辿ってディレクトリとして固定し、その fd 起点で pin を `O_NOFOLLOW` / `O_NONBLOCK` で 1 回だけ開く | symlink は `InvalidArgument`、権限不足は `PermissionDenied`、不在は `FailedPrecondition`（監査しない） |
//! | 1 | `fstatfs` が nsfs | `InvalidArgument` |
//! | 2 | `NS_GET_NSTYPE` が net | `InvalidArgument` |
//! | 3 | 開いた fd の (dev, ino) が指定と一致 | `PermissionDenied` |
//! | 4 | 所有する user namespace が init（nsfs の固定 inode） | `PermissionDenied` |
//!
//! 受理と拒否は閉じた語彙（[`NetnsJoinOutcome`]）で監査に残す（SEC-4）。置き場の fd 起点の単一要素 `openat` により、
//! 配下性（置き場の外へ出ない）が構造的に成り立つ。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - 供給側（`NetworkPlugin::create_netns` の結果を supervisor がこの型へ詰めて渡す配線）は #3074・#4724 の範囲。
//! - 非 Linux では固定できず `Unimplemented`（fail-closed。CLI-1）。

use std::path::{Component, Path, PathBuf};

use crate::audit_log::NetnsJoinOutcome;
use crate::traits::{ErrorCode, TraitError};

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::sync::Arc;

/// パス長の上限（`CONFIG_MAX_PATH_BYTES` と同値）。
const PATH_MAX_BYTES: usize = 4096;

/// init user namespace の固定 inode（カーネルの `include/linux/proc_ns.h` の `PROC_USER_INIT_INO` = `0xEFFFFFFD`。
/// 3.8 以降の ABI として固定）。`libc` に対応物は無く、`sys` の FFI 宣言でもないため `libc_abi` の照合の対象外。
#[cfg(target_os = "linux")]
const PROC_USER_INIT_INO: u64 = 0xEFFF_FFFD;

const MALFORMED_MESSAGE: &str =
    "a netns join path must be absolute without .. components and within the length limit";

fn malformed_path() -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, MALFORMED_MESSAGE)
}

/// 絶対パスで、`.`・`..` を含まず、上限以内で NUL を含まないこと。
fn check_lexical(path: &Path) -> Result<(), TraitError> {
    let bad = path.as_os_str().len() > PATH_MAX_BYTES
        || !path.is_absolute()
        || path.to_string_lossy().contains('\0')
        // `Path::components` は途中の `.` を畳むため、文字列の要素でも確かめる。
        || path.to_string_lossy().split('/').any(|seg| seg == ".")
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)));
    if bad { Err(malformed_path()) } else { Ok(()) }
}

/// 置き場の直下の 1 要素の名前（`path.parent() == Some(root)` かつ最終要素が通常の名前）を返す。
fn entry_name<'a>(root: &Path, path: &'a Path) -> Result<&'a std::ffi::OsStr, TraitError> {
    if path.parent() != Some(root) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the netns join path must be a single entry directly under the netns join root",
        ));
    }
    match path.components().next_back() {
        Some(Component::Normal(name)) => Ok(name),
        _ => Err(malformed_path()),
    }
}

/// init user namespace 所有の pin 済み netns への参加指定（OS 非依存の純データ。NET-1・SEC-1・#3069）。
///
/// supervisor が `NetworkPlugin::create_netns` の結果から作り、[`LaunchOptions::with_netns_join`](
/// crate::oci_runtime::LaunchOptions::with_netns_join) で渡す。構築時に字句を検査し（絶対・`..` なし・長さ上限・
/// pin が置き場の直下の 1 要素）、core は `start` で自前に再検証する。`(dev, ino)` は plugin が pin 時に取った素性で、
/// 開いた fd と一致しなければ拒否する（差し替えと取り違えの防止）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetnsJoinTarget {
    root: PathBuf,
    path: PathBuf,
    identity: (u64, u64),
}

impl NetnsJoinTarget {
    /// 字句を検査して作る。不合格は `InvalidArgument`（固定文言でパスを含めない）。
    pub fn new(root: PathBuf, path: PathBuf, dev: u64, ino: u64) -> Result<Self, TraitError> {
        check_lexical(&root)?;
        check_lexical(&path)?;
        entry_name(&root, &path)?;
        Ok(Self {
            root,
            path,
            identity: (dev, ino),
        })
    }

    /// 置き場のディレクトリ。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// pin のパス（置き場の直下の 1 要素）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// plugin が pin 時に取った netns の (dev, ino)。
    pub fn identity(&self) -> (u64, u64) {
        self.identity
    }
}

/// `PinnedNetnsJoin::pin` の拒否。監査に残す結果は、素性検査による拒否のときだけ `Some`
/// （不在・I/O の失敗・非 Linux は `None`）。
#[derive(Debug)]
pub(in crate::oci_runtime) struct NetnsPinRejection {
    pub(in crate::oci_runtime) error: TraitError,
    pub(in crate::oci_runtime) outcome: Option<NetnsJoinOutcome>,
}

impl NetnsPinRejection {
    #[cfg(target_os = "linux")]
    fn audited(outcome: NetnsJoinOutcome) -> Self {
        let (code, message) = match outcome {
            // `Accepted` は拒否ではない(呼ばれない)が、網羅のため字句の拒否と同じ扱いにする。
            NetnsJoinOutcome::Accepted | NetnsJoinOutcome::PathMalformed => {
                (ErrorCode::InvalidArgument, MALFORMED_MESSAGE)
            }
            NetnsJoinOutcome::PathSymlink => (
                ErrorCode::InvalidArgument,
                "a netns join path is a symlink or not a directory",
            ),
            NetnsJoinOutcome::OpenDenied => (
                ErrorCode::PermissionDenied,
                "a netns join path cannot be opened: permission denied",
            ),
            NetnsJoinOutcome::NotNamespaceFile => (
                ErrorCode::InvalidArgument,
                "the netns join path is not a namespace file",
            ),
            NetnsJoinOutcome::NotNetworkNamespace => (
                ErrorCode::InvalidArgument,
                "the netns join path is not a network namespace",
            ),
            NetnsJoinOutcome::IdentityMismatch => (
                ErrorCode::PermissionDenied,
                "the netns join path does not match the expected network namespace",
            ),
            NetnsJoinOutcome::OwnerNotInit => (
                ErrorCode::PermissionDenied,
                "the netns join path is not owned by the init user namespace",
            ),
        };
        Self {
            error: TraitError::new(code, message),
            outcome: Some(outcome),
        }
    }

    #[cfg(target_os = "linux")]
    fn silent(code: ErrorCode, message: &'static str) -> Self {
        Self {
            error: TraitError::new(code, message),
            outcome: None,
        }
    }
}

impl From<TraitError> for NetnsPinRejection {
    fn from(error: TraitError) -> Self {
        Self {
            error,
            outcome: None,
        }
    }
}

/// 検証済みの pin 済み netns の fd（Linux のみ。他 OS では作れない）。
///
/// `LaunchSpec` に載り、restart の再 launch でも同じ fd を使う（clone は fd を共有する。パスは再解決しない）。
/// 同一性は fd の同一性。
#[derive(Debug, Clone)]
pub struct PinnedNetnsJoin {
    #[cfg(target_os = "linux")]
    fd: Arc<OwnedFd>,
    /// pin 時に取った (dev, ino)。exec 直前の同期点が PID 1 の netns と照合する（D8。SEC-1）。
    #[cfg(target_os = "linux")]
    identity: (u64, u64),
    /// Linux 以外では構築できないことを型で表す。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl PartialEq for PinnedNetnsJoin {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            Arc::ptr_eq(&self.fd, &other.fd)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            match self.never {}
        }
    }
}

impl Eq for PinnedNetnsJoin {}

/// 開いた fd から集めた観測値（`classify` の入力。I/O なし）。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observed {
    /// `fstatfs` の `f_type`。
    fs_magic: i64,
    /// `NS_GET_NSTYPE`（nsfs でないときは問い合わせない）。
    ns_type: Option<i32>,
    /// fd の (dev, ino)。dev は nsfs のデバイスで、所有者の user namespace の dev とも一致する。
    identity: (u64, u64),
    /// 所有する user namespace の (dev, ino)。取れない（`EPERM`＝呼び出し側の外側）ときは `None`。
    owner: Option<(u64, u64)>,
}

/// 観測値を判定する純関数（検査の順は モジュール doc の表）。受理は `Ok`。
#[cfg(target_os = "linux")]
fn classify(observed: &Observed, expected: (u64, u64)) -> Result<(), NetnsJoinOutcome> {
    use crate::sys::{self, NsFlag};
    if observed.fs_magic != sys::NSFS_MAGIC {
        return Err(NetnsJoinOutcome::NotNamespaceFile);
    }
    if observed.ns_type != Some(NsFlag::Net.bits()) {
        return Err(NetnsJoinOutcome::NotNetworkNamespace);
    }
    if observed.identity != expected {
        return Err(NetnsJoinOutcome::IdentityMismatch);
    }
    // init の判定は文字どおり（固定 inode と nsfs の dev）。「呼び出し側と同じ」では入れ子の user namespace 内の
    // supervisor を init と取り違える。
    if observed.owner != Some((observed.identity.0, PROC_USER_INIT_INO)) {
        return Err(NetnsJoinOutcome::OwnerNotInit);
    }
    Ok(())
}

impl PinnedNetnsJoin {
    /// 置き場と pin を開いて素性を照合し、fd に固定する（モジュール doc の表）。
    ///
    /// 拒否は [`NetnsPinRejection`] で、素性検査による拒否には監査に残す結果が付く。
    #[cfg(target_os = "linux")]
    pub(in crate::oci_runtime) fn pin(
        target: &NetnsJoinTarget,
    ) -> Result<(Self, NetnsJoinOutcome), NetnsPinRejection> {
        use crate::sys::{self, NsFlag, SysError};
        use std::os::unix::ffi::OsStrExt as _;
        let internal = |_: SysError| {
            NetnsPinRejection::silent(ErrorCode::Internal, "failed to inspect a network namespace")
        };
        // core は supervisor の検証を信用せず、字句を再検査する。
        let malformed = |e: TraitError| NetnsPinRejection {
            error: e,
            outcome: Some(NetnsJoinOutcome::PathMalformed),
        };
        check_lexical(&target.root).map_err(malformed)?;
        check_lexical(&target.path).map_err(malformed)?;
        let name = entry_name(&target.root, &target.path).map_err(malformed)?;
        let name_c = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| NetnsPinRejection::audited(NetnsJoinOutcome::PathMalformed))?;
        let classify_open = |e: SysError, what: &'static str| match e {
            SysError::Os(errno) if errno == sys::ENOTDIR || errno == sys::ELOOP => {
                NetnsPinRejection::audited(NetnsJoinOutcome::PathSymlink)
            }
            SysError::Os(errno) if errno == sys::EACCES || errno == sys::EPERM => {
                NetnsPinRejection::audited(NetnsJoinOutcome::OpenDenied)
            }
            SysError::Os(errno) if errno == sys::ENOENT => {
                NetnsPinRejection::silent(ErrorCode::FailedPrecondition, what)
            }
            _ => NetnsPinRejection::silent(ErrorCode::Internal, what),
        };
        // 置き場を symlink 非追従で固定し、その fd 起点で pin の単一要素だけを開く（配下性が構造的に閉じる）。
        // `O_NONBLOCK` により FIFO への差し替えでも止まらない（REPAIR-5）。
        // 絶対パスの全要素を "/" から 1 要素ずつ `O_NOFOLLOW` で辿る（途中の symlink も辿らない。末尾の `/` は
        // `components` が畳むため、`/run/link/` で symlink を辿らせる迂回も閉じる）。
        let slash = std::ffi::CString::new("/")
            .map_err(|_| NetnsPinRejection::audited(NetnsJoinOutcome::PathMalformed))?;
        let mut root = sys::open_dir_path_nofollow(None, &slash)
            .map_err(|e| classify_open(e, "the netns join root cannot be opened"))?;
        for comp in target.root.components() {
            let Component::Normal(seg) = comp else {
                continue;
            };
            let seg_c = std::ffi::CString::new(seg.as_bytes())
                .map_err(|_| NetnsPinRejection::audited(NetnsJoinOutcome::PathMalformed))?;
            root = sys::open_dir_path_nofollow(Some(root.as_fd()), &seg_c)
                .map_err(|e| classify_open(e, "the netns join root cannot be opened"))?;
        }
        let fd = sys::open_read_nonblock_at(root.as_fd(), &name_c)
            .map_err(|e| classify_open(e, "the netns join path cannot be opened"))?;

        let fs_magic = sys::fs_type(fd.as_fd()).map_err(internal)?;
        let ns_type = if fs_magic == sys::NSFS_MAGIC {
            Some(sys::ns_type(fd.as_fd()).map_err(internal)?)
        } else {
            None
        };
        let identity = super::identity(fd.as_fd()).map_err(|r| r.error)?;
        let owner = if ns_type == Some(NsFlag::Net.bits()) {
            match sys::ns_owner_userns(fd.as_fd()) {
                Ok(owner) => Some(super::identity(owner.as_fd()).map_err(|r| r.error)?),
                Err(SysError::Os(errno)) if errno == sys::EPERM => None,
                Err(e) => return Err(internal(e)),
            }
        } else {
            None
        };
        let observed = Observed {
            fs_magic,
            ns_type,
            identity,
            owner,
        };
        classify(&observed, target.identity).map_err(NetnsPinRejection::audited)?;
        Ok((
            Self {
                fd: Arc::new(fd),
                identity,
            },
            NetnsJoinOutcome::Accepted,
        ))
    }

    /// 非 Linux は namespace を固定できない（`Unimplemented`。fail-closed。CLI-1）。
    #[cfg(not(target_os = "linux"))]
    pub(in crate::oci_runtime) fn pin(
        _target: &NetnsJoinTarget,
    ) -> Result<(Self, NetnsJoinOutcome), NetnsPinRejection> {
        Err(NetnsPinRejection::from(TraitError::new(
            ErrorCode::Unimplemented,
            "joining a pinned network namespace requires Linux",
        )))
    }

    /// 試験専用: 検証を通さずに任意の fd から作る（launcher の分岐を、実際の init 所有 netns なしで確かめる）。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test(fd: OwnedFd) -> Self {
        let identity = super::identity(fd.as_fd()).unwrap_or((0, 0));
        Self {
            fd: Arc::new(fd),
            identity,
        }
    }

    /// 固定した netns の fd（`setns` 専用。中間プロセス I が user namespace の作成前に使う）。
    #[cfg(target_os = "linux")]
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// pin 時に取った netns の素性。exec 直前の同期点が PID 1 の netns と照合する（D8）。
    #[cfg(target_os = "linux")]
    pub(crate) fn identity(&self) -> crate::exec::NetnsIdentity {
        crate::exec::NetnsIdentity::from_parts(self.identity.0, self.identity.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(root: &str, path: &str) -> Result<NetnsJoinTarget, TraitError> {
        NetnsJoinTarget::new(PathBuf::from(root), PathBuf::from(path), 5, 4_026_532_008)
    }

    /// NET-1・SEC-1(#3069): 字句の不正(相対・`..`・`.`・置き場の直下でない・長さ超過・NUL)は固定文言の
    /// `InvalidArgument` で、文言にパスを含めない。
    #[test]
    fn net1_sec1_3069_target_rejects_malformed_paths() {
        let long = format!("/run/n/{}", "a".repeat(PATH_MAX_BYTES));
        let cases: Vec<(&str, &str, &str)> = vec![
            ("run/n", "run/n/x", "absolute"),
            ("/run/n", "/run/n/../x", "absolute"),
            ("/run/./n", "/run/./n/x", "absolute"),
            ("/run/n", &long, "absolute"),
            ("/run/n", "/run/n/a\0b", "absolute"),
            ("/run/n", "/run/n/a/b", "single entry"),
            ("/run/n", "/run/other/x", "single entry"),
            ("/run/n", "/run/n", "single entry"),
            ("/run/n", "/x", "single entry"),
        ];
        for (root, path, kind) in cases {
            let err = target(root, path).expect_err(path);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{path}");
            assert!(err.message().contains(kind), "{path}: {}", err.message());
            assert!(!err.message().contains("/run"), "{path}");
        }
        let ok = target("/run/n", "/run/n/web").expect("valid");
        assert_eq!(ok.root(), Path::new("/run/n"));
        assert_eq!(ok.path(), Path::new("/run/n/web"));
        assert_eq!(ok.identity(), (5, 4_026_532_008));
    }

    #[cfg(target_os = "linux")]
    fn good() -> Observed {
        Observed {
            fs_magic: 0x6e73_6673,
            ns_type: Some(0x4000_0000),
            identity: (4, 4_026_532_008),
            owner: Some((4, 4_026_531_837)),
        }
    }

    /// NET-1・SEC-1(#3069): 全分岐を具体値で照合する(受理・nsfs でない・net でない・素性違い・所有者が init でない)。
    #[cfg(target_os = "linux")]
    #[test]
    fn net1_sec1_3069_classify_each_branch() {
        use NetnsJoinOutcome as O;
        let expected = (4, 4_026_532_008);
        assert_eq!(classify(&good(), expected), Ok(()));
        let mut o = good();
        o.fs_magic = 0x0102_1994; // tmpfs
        o.ns_type = None;
        assert_eq!(classify(&o, expected), Err(O::NotNamespaceFile));
        let mut o = good();
        o.ns_type = Some(0x0800_0000); // ipc
        assert_eq!(classify(&o, expected), Err(O::NotNetworkNamespace));
        let mut o = good();
        o.ns_type = None;
        assert_eq!(classify(&o, expected), Err(O::NotNetworkNamespace));
        let o = good();
        assert_eq!(classify(&o, (4, 4_026_532_009)), Err(O::IdentityMismatch));
        assert_eq!(classify(&o, (5, 4_026_532_008)), Err(O::IdentityMismatch));
        let mut o = good();
        o.owner = Some((4, 4_026_532_100));
        assert_eq!(classify(&o, expected), Err(O::OwnerNotInit));
        let mut o = good();
        o.owner = Some((5, 4_026_531_837));
        assert_eq!(classify(&o, expected), Err(O::OwnerNotInit));
        let mut o = good();
        o.owner = None;
        assert_eq!(classify(&o, expected), Err(O::OwnerNotInit));
    }

    /// NET-1・SEC-1(#3069): 複数の条件が同時に不合格のときは、先の検査の結果になる(D12 の列挙順)。
    #[cfg(target_os = "linux")]
    #[test]
    fn net1_sec1_3069_classify_reports_the_earliest_failure() {
        use NetnsJoinOutcome as O;
        let mut o = good();
        o.fs_magic = 1;
        o.ns_type = Some(0x0800_0000);
        o.identity = (9, 9);
        o.owner = None;
        assert_eq!(classify(&o, (4, 4_026_532_008)), Err(O::NotNamespaceFile));
        o.fs_magic = 0x6e73_6673;
        assert_eq!(
            classify(&o, (4, 4_026_532_008)),
            Err(O::NotNetworkNamespace)
        );
        o.ns_type = Some(0x4000_0000);
        assert_eq!(classify(&o, (4, 4_026_532_008)), Err(O::IdentityMismatch));
        o.identity = (4, 4_026_532_008);
        assert_eq!(classify(&o, (4, 4_026_532_008)), Err(O::OwnerNotInit));
    }

    #[cfg(target_os = "linux")]
    fn pin_in(
        scratch: &crate::scratch_root::ScratchDir,
        name: &str,
    ) -> Result<(PinnedNetnsJoin, NetnsJoinOutcome), NetnsPinRejection> {
        let target = NetnsJoinTarget::new(
            scratch.path().to_path_buf(),
            scratch.path().join(name),
            0,
            0,
        )
        .expect("target");
        PinnedNetnsJoin::pin(&target)
    }

    /// NET-1・SEC-1(#3069): 実ファイルシステムでの拒否。通常ファイルは `NotNamespaceFile`、最終要素が symlink・置き場自体が
    /// symlink は `PathSymlink`、不在は `FailedPrecondition` で監査しない。
    #[cfg(target_os = "linux")]
    #[test]
    fn net1_sec1_3069_pin_rejects_live_non_namespace_entries() {
        let scratch = crate::scratch_root::ScratchDir::new(
            "netns-pin-reject",
            std::time::Duration::from_secs(10),
        );
        std::fs::write(scratch.path().join("plain"), b"x").expect("write");
        let r = pin_in(&scratch, "plain").expect_err("plain file");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::NotNamespaceFile));
        assert_eq!(r.error.code(), ErrorCode::InvalidArgument);

        std::os::unix::fs::symlink("/proc/self/ns/net", scratch.path().join("link")).expect("ln");
        let r = pin_in(&scratch, "link").expect_err("symlink");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::PathSymlink));
        assert_eq!(r.error.code(), ErrorCode::InvalidArgument);

        let r = pin_in(&scratch, "absent").expect_err("absent");
        assert_eq!(r.outcome, None);
        assert_eq!(r.error.code(), ErrorCode::FailedPrecondition);

        // 置き場自体が symlink。
        let real = scratch.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let linked = scratch.path().join("linked-root");
        std::os::unix::fs::symlink(&real, &linked).expect("ln root");
        let target = NetnsJoinTarget::new(linked.clone(), linked.join("x"), 0, 0).expect("target");
        let r = PinnedNetnsJoin::pin(&target).expect_err("symlink root");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::PathSymlink));
        assert_eq!(r.error.code(), ErrorCode::InvalidArgument);

        // 置き場の末尾が `/` でも symlink を辿らない(components が畳み、各要素を O_NOFOLLOW で開く)。
        let slashed = std::path::PathBuf::from(format!("{}/", linked.display()));
        let target =
            NetnsJoinTarget::new(slashed.clone(), slashed.join("x"), 0, 0).expect("target");
        let r = PinnedNetnsJoin::pin(&target).expect_err("trailing slash symlink root");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::PathSymlink));

        // 置き場の途中の要素が symlink。
        let nested = linked.join("sub");
        std::fs::create_dir(real.join("sub")).expect("mkdir sub");
        let target = NetnsJoinTarget::new(nested.clone(), nested.join("x"), 0, 0).expect("target");
        let r = PinnedNetnsJoin::pin(&target).expect_err("intermediate symlink");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::PathSymlink));

        // 置き場が通常ファイル。
        let file_root = scratch.path().join("plain");
        let target =
            NetnsJoinTarget::new(file_root.clone(), file_root.join("x"), 0, 0).expect("target");
        let r = PinnedNetnsJoin::pin(&target).expect_err("file root");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::PathSymlink));
    }

    /// 開いたものが FIFO でも `O_NONBLOCK` で止まらず、nsfs でないとして拒否する(REPAIR-5)。
    #[cfg(target_os = "linux")]
    #[test]
    fn net1_sec1_3069_pin_does_not_block_on_a_fifo() {
        let scratch = crate::scratch_root::ScratchDir::new(
            "netns-pin-fifo",
            std::time::Duration::from_secs(10),
        );
        let fifo = scratch.path().join("fifo");
        run_bounded("mkfifo", &[fifo.as_os_str()]).expect("mkfifo");
        let r = pin_in(&scratch, "fifo").expect_err("fifo");
        assert_eq!(r.outcome, Some(NetnsJoinOutcome::NotNamespaceFile));
    }

    /// 実機前提の補助: `path` の (dev, ino)。
    #[cfg(target_os = "linux")]
    fn stat_identity(path: &str) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).expect("stat");
        (meta.dev(), meta.ino())
    }

    /// 実機前提の補助: 子を kill し、有限の猶予(5 秒)の間だけ回収を待つ(REPAIR-5)。kill の失敗と
    /// 回収できなかったこと(D 状態など)は戻り値の文言に残し、無期限には待たない。
    #[cfg(target_os = "linux")]
    fn kill_and_reap(child: &mut std::process::Child) -> String {
        let mut note = String::new();
        if let Err(e) = child.kill() {
            note.push_str(&format!("; kill failed: {e}"));
        }
        let grace = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return note,
                Ok(None) if std::time::Instant::now() < grace => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Ok(None) => {
                    note.push_str("; child not reaped within the grace period");
                    return note;
                }
                Err(e) => {
                    note.push_str(&format!("; reap failed: {e}"));
                    return note;
                }
            }
        }
    }

    /// 実機前提の補助: 外部コマンドを期限つきで実行する(REPAIR-5)。超過したら kill して回収し、`Err` を返す。
    #[cfg(target_os = "linux")]
    fn run_bounded(program: &str, args: &[&std::ffi::OsStr]) -> Result<(), String> {
        let mut child = std::process::Command::new(program)
            .args(args)
            .spawn()
            .map_err(|e| format!("cannot run {program}: {e}"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(format!("{program} failed: {status}")),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Ok(None) => {
                    return Err(format!("{program} timed out{}", kill_and_reap(&mut child)));
                }
                Err(e) => {
                    return Err(format!(
                        "{program} wait failed: {e}{}",
                        kill_and_reap(&mut child)
                    ));
                }
            }
        }
    }

    /// 実機前提の補助: 作った bind mount を panic でも必ず外す guard(特権操作の後始末)。
    /// `umount` の失敗は Drop 内では panic せず stderr に残す。
    #[cfg(target_os = "linux")]
    struct MountGuard(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl Drop for MountGuard {
        fn drop(&mut self) {
            if let Err(e) = run_bounded("umount", &[self.0.as_os_str()]) {
                eprintln!("cleanup: umount {} failed: {e}", self.0.display());
            }
        }
    }

    /// 実機前提の補助: 外部コマンドを実行し、失敗したら `PRECONDITION FAILED` で落とす(skip しない)。
    #[cfg(target_os = "linux")]
    fn run_precondition(program: &str, args: &[&std::ffi::OsStr]) {
        if let Err(e) = run_bounded(program, args) {
            panic!("PRECONDITION FAILED: {e}");
        }
    }

    /// NET-1・SEC-1・CORE-3(#3069)。実機前提(非 root。非特権 user + mount + network namespace と util-linux の
    /// `mount` が要る)。`unshare -r -m -n` の中で実行する(docs/verification/real-machine-tests.md)。
    ///
    /// 自分の user namespace が所有する netns(init 所有でない)を bind mount で pin し、`OwnerNotInit`・
    /// `PermissionDenied` で拒否されること、素性を 1 ずらすと `IdentityMismatch`、net でない namespace(ipc)は
    /// `NotNetworkNamespace` になることを実カーネルで確かめる。前提が欠けるときは skip せず `PRECONDITION FAILED` で落とす。
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs an unprivileged user + mount + network namespace (run under `unshare -r -m -n`); see docs/verification/real-machine-tests.md"]
    fn net1_3069_real_child_owned_netns_rejected() {
        use std::ffi::OsStr;
        let own_user = stat_identity("/proc/self/ns/user");
        assert_ne!(
            own_user.1, PROC_USER_INIT_INO,
            "PRECONDITION FAILED: run inside `unshare -r -m -n` (the user namespace is init's)"
        );
        let scratch = crate::scratch_root::ScratchDir::new(
            "netns-pin-real-child",
            std::time::Duration::from_secs(10),
        );
        let net_pin = scratch.path().join("net");
        let ipc_pin = scratch.path().join("ipc");
        let mut guards = Vec::new();
        for (pin, src) in [
            (&net_pin, "/proc/self/ns/net"),
            (&ipc_pin, "/proc/self/ns/ipc"),
        ] {
            std::fs::write(pin, b"").expect("create pin file");
            run_precondition(
                "mount",
                &[OsStr::new("--bind"), OsStr::new(src), pin.as_os_str()],
            );
            // mount の直後に guard を置く(以降の panic でも umount される)。
            guards.push(MountGuard(pin.clone()));
        }
        let net_id = stat_identity("/proc/self/ns/net");
        let ipc_id = stat_identity("/proc/self/ns/ipc");
        let target = |pin: &std::path::Path, id: (u64, u64)| {
            NetnsJoinTarget::new(scratch.path().to_path_buf(), pin.to_path_buf(), id.0, id.1)
                .expect("target")
        };
        let owner = PinnedNetnsJoin::pin(&target(&net_pin, net_id)).expect_err("child-owned");
        assert_eq!(owner.outcome, Some(NetnsJoinOutcome::OwnerNotInit));
        assert_eq!(owner.error.code(), ErrorCode::PermissionDenied);
        let moved = PinnedNetnsJoin::pin(&target(&net_pin, (net_id.0, net_id.1 + 1)))
            .expect_err("identity");
        assert_eq!(moved.outcome, Some(NetnsJoinOutcome::IdentityMismatch));
        let ipc = PinnedNetnsJoin::pin(&target(&ipc_pin, ipc_id)).expect_err("ipc");
        assert_eq!(ipc.outcome, Some(NetnsJoinOutcome::NotNetworkNamespace));
        assert_eq!(ipc.error.code(), ErrorCode::InvalidArgument);
        drop(guards);
        println!("net1_3069_real_child_owned_netns_rejected: ok");
    }

    /// NET-1・SEC-1・CORE-3(#3069)。実機前提(root。人間担当)。init user namespace 所有の netns を
    /// `unshare --net=<pin>` で pin し、`Accepted` になること、`exec::join_pinned_netns` で `setns` した
    /// スレッドの netns が pin の素性と一致することを確かめる。`setns(CLONE_NEWUSER)` は単一スレッドを要し lib 試験では
    /// 使えないため、「user namespace の作成前でないと `EPERM`」の順序の実証は production_launcher の実機場面
    /// (供給側の結線後。#3074)に残す。
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root (CAP_SYS_ADMIN in the init user namespace); see docs/verification/real-machine-tests.md"]
    fn net1_3069_real_init_netns_join_before_userns() {
        use std::ffi::OsStr;
        assert_eq!(
            crate::sys::effective_uid(),
            0,
            "PRECONDITION FAILED: run as root in the init user namespace"
        );
        assert_eq!(
            stat_identity("/proc/self/ns/user").1,
            PROC_USER_INIT_INO,
            "PRECONDITION FAILED: not in the init user namespace"
        );
        let scratch = crate::scratch_root::ScratchDir::new(
            "netns-pin-real-init",
            std::time::Duration::from_secs(10),
        );
        let pin = scratch.path().join("pin");
        // unshare は既存ファイルへ bind mount するため、先に空の通常ファイルを作る。
        std::fs::write(&pin, b"").expect("create pin file");
        // unshare が mount した後に失敗しても外れるよう、実行の前に guard を置く(未 mount なら失敗を表示するだけ)。
        let _guard = MountGuard(pin.clone());
        run_precondition(
            "unshare",
            &[
                OsStr::new(&format!("--net={}", pin.display())),
                OsStr::new("true"),
            ],
        );
        let id = stat_identity(pin.to_str().expect("utf8"));
        let target = NetnsJoinTarget::new(scratch.path().to_path_buf(), pin.clone(), id.0, id.1)
            .expect("target");
        let (pinned, outcome) = PinnedNetnsJoin::pin(&target).expect("init-owned pin");
        assert_eq!(outcome, NetnsJoinOutcome::Accepted);
        let expected = pinned.identity();
        let joined = std::thread::scope(|s| {
            s.spawn(|| {
                crate::exec::join_pinned_netns(pinned.fd(), expected)
                    .map(|()| stat_identity("/proc/thread-self/ns/net"))
            })
            .join()
            .expect("thread")
        });
        assert_eq!(joined.expect("join"), id);
        println!("net1_3069_real_init_netns_join_before_userns: ok");
    }
}
