//! pod の `/dev/shm` の元（保持役の mount namespace）の指定の検証と fd 固定（CRI-2・CORE-3・SEC-1・SEC-5。#4822。S2）。
//!
//! # 役割と呼び出し元
//!
//! pod で共有する `/dev/shm` は、保持役が自分の mount namespace の `/dev/shm` に載せた tmpfs（#4821。S1）である。
//! コンテナの init は pivot 前に、その mount namespace の fd へ `setns` して tmpfs を `open_tree` で複製し、自分の
//! mount namespace へ戻って載せる（`exec::pod_shm`）。本モジュールはその **fd の固定と検証** を担い、`start` が
//! pod の user・ipc の join の固定（[`NamespaceJoin::pin`](super::NamespaceJoin)）の直後に、fork の前に 1 回だけ呼ぶ。
//!
//! 指定の受け渡しは supervisor の argv（`--pod-shm <dev>:<ino>:<パス>`）から [`LaunchOptions`](
//! crate::oci_runtime::LaunchOptions) 経由で、config.json は純 OCI のまま（オーナー決定 2026-11-19。設計は
//! `docs/design/pod-namespace-holder.md` の S2）。`(dev, ino)` は保持役が READY で報告した **tmpfs のルート** の素性で、
//! init が保持役の mount namespace で開いた `/dev/shm` と照合する（namespace の素性ではない）。
//!
//! # 検証（すべて fork の前。メッセージは固定文言でパスを含めない）
//!
//! | 順 | 検査 | 不合格 |
//! | -- | ---- | ------ |
//! | 0 | パスが `/proc/<正の整数>/ns/mnt` の字句（[`PodShmSource::new`] が型で保証） | `InvalidArgument` |
//! | 1 | 同じ config の `linux.namespaces[]` に user と ipc の join がある | `Unimplemented` |
//! | 2 | パスの pid が user の join の path の pid と同じ（字句の照合） | `InvalidArgument` |
//! | 3 | 1 回だけ開く（`sys::open_ns_file`。`O_RDONLY\|O_NONBLOCK\|O_NOCTTY\|O_CLOEXEC` で magic link を辿る。種別は次の行の nsfs と `NS_GET_NSTYPE` で確かめる。不在は `FailedPrecondition`、権限不足は `PermissionDenied`） | |
//! | 4 | `fstatfs` が nsfs で、`NS_GET_NSTYPE` が mount | `InvalidArgument` |
//! | 5 | 所有する user namespace が、固定済みの user の join と同じ（呼び出し側自身の mount namespace もここで落ちる） | `PermissionDenied` |
//!
//! 拒否は閉じた語彙（[`PodNamespaceJoinOutcome`](crate::audit_log::PodNamespaceJoinOutcome)）で監査に残す。受理の記録は user・ipc の join が残した 1 件で足りるため、
//! 本検査では出さない。fd を持つ間は参加先の mount namespace が生き続ける。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - 本番の呼び出し元（plugin-cri が保持役の pid と READY の素性から指定を組んで supervisor の argv へ渡す配線）は S3（#4823）。
//! - 非 Linux では固定できず `Unimplemented`（fail-closed）。

use std::path::{Path, PathBuf};

use super::PinRejection;
#[cfg(target_os = "linux")]
use crate::audit_log::PodNamespaceJoinOutcome;
use crate::traits::{ErrorCode, TraitError};

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::sync::Arc;

const MALFORMED_MESSAGE: &str =
    "a pod shm path must be /proc/<pid>/ns/mnt with a canonical positive pid";

fn malformed() -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, MALFORMED_MESSAGE)
}

/// `/proc/<pid>/ns/<kind>` の `<pid>` の部分（字句。`self` 等も返す）。形が違えば `None`。
fn proc_pid_token<'a>(path: &'a Path, kind: &str) -> Option<&'a str> {
    let text = path.to_str()?;
    let mut parts = text.strip_prefix("/proc/")?.split('/');
    let (pid, ns, leaf) = (parts.next()?, parts.next()?, parts.next()?);
    (parts.next().is_none() && ns == "ns" && leaf == kind && !pid.is_empty()).then_some(pid)
}

/// pod の `/dev/shm` の元の指定（保持役の mount namespace のパスと、その `/dev/shm` の tmpfs の素性。OS 非依存の純データ）。
///
/// 構築時に字句を検査する（パスは `/proc/<正の整数>/ns/mnt`・pid は 10 進の正準形、`dev`・`ino` は非 0）。
/// 本番の launcher の起動オプション（[`LaunchOptions::with_pod_shm`](crate::oci_runtime::LaunchOptions::with_pod_shm)）だけが
/// 受け取る。fd は持たない（開いて固定するのは `start`。[`PinnedPodShm`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodShmSource {
    path: PathBuf,
    pid: u32,
    dev: u64,
    ino: u64,
}

impl PodShmSource {
    /// 字句を検査して作る。不合格は `InvalidArgument`（固定文言でパスを含めない）。
    pub fn new(path: PathBuf, dev: u64, ino: u64) -> Result<Self, TraitError> {
        let token = proc_pid_token(&path, "mnt").ok_or_else(malformed)?;
        let pid: u32 = token.parse().map_err(|_| malformed())?;
        // 正準形（先頭 0・`+` を許さない）で、1 以上。
        if pid == 0 || pid.to_string() != token {
            return Err(malformed());
        }
        if dev == 0 || ino == 0 {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "a pod shm identity must be non-zero",
            ));
        }
        Ok(Self {
            path,
            pid,
            dev,
            ino,
        })
    }

    /// 保持役の mount namespace のパス（`/proc/<pid>/ns/mnt`）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 保持役の pid（パスの字句から取った値）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 保持役の mount namespace の `/dev/shm`（tmpfs のルート）の `(st_dev, st_ino)`。
    pub fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

/// 検証済みの保持役の mount namespace の fd と、期待する tmpfs の素性（Linux のみ。他 OS では作れない）。
///
/// `LaunchSpec` に載り、restart の再 launch でも同じ fd を使う（clone は fd を共有する。パスは再解決しない）。
/// 同一性は fd の同一性。
#[derive(Debug, Clone)]
pub struct PinnedPodShm {
    #[cfg(target_os = "linux")]
    fd: Arc<OwnedFd>,
    /// 保持役の `/dev/shm`（tmpfs のルート）の `(st_dev, st_ino)`。init が複製元を開いて照合する。
    #[cfg(target_os = "linux")]
    expected: (u64, u64),
    /// Linux 以外では構築できないことを型で表す。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl PartialEq for PinnedPodShm {
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

impl Eq for PinnedPodShm {}

/// 開いた fd から集めた観測値（`classify` の入力。I/O なし）。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observed {
    /// `fstatfs` の `f_type`。
    fs_magic: i64,
    /// `NS_GET_NSTYPE`（nsfs でないときは問い合わせない）。
    ns_type: Option<i32>,
    /// 所有する user namespace の素性。取れない（`EPERM`＝呼び出し側の外側）ときは `None`。
    owner: Option<(u64, u64)>,
}

/// 観測値を判定する純関数（検査の順はモジュール doc の表の 4・5）。受理は `Ok`。
#[cfg(target_os = "linux")]
fn classify(observed: &Observed, join_user: (u64, u64)) -> Result<(), PinRejection> {
    use crate::sys::{self, NsFlag};
    if observed.fs_magic != sys::NSFS_MAGIC || observed.ns_type != Some(NsFlag::Mount.bits()) {
        return Err(PinRejection::new(
            ErrorCode::InvalidArgument,
            "the pod shm path is not a mount namespace file",
            PodNamespaceJoinOutcome::NotNamespaceFile,
        ));
    }
    if observed.owner != Some(join_user) {
        return Err(PinRejection::new(
            ErrorCode::PermissionDenied,
            "the pod shm mount namespace is not owned by the pod user namespace",
            PodNamespaceJoinOutcome::PodShmOwnerMismatch,
        ));
    }
    Ok(())
}

impl PinnedPodShm {
    /// 保持役の mount namespace を開いて検証し、fd に固定する（モジュール doc の表）。
    ///
    /// `join` と `join_paths` は同じ config の user・ipc の join（固定済みの fd と、その元の path）。無ければ `Unimplemented`。
    #[cfg(target_os = "linux")]
    pub(in crate::oci_runtime) fn pin(
        source: &PodShmSource,
        join: Option<&super::NamespaceJoin>,
        join_paths: Option<&super::JoinPaths<'_>>,
    ) -> Result<Self, PinRejection> {
        use crate::sys::{self, SysError};
        let (Some(join), Some(paths)) = (join, join_paths) else {
            return Err(PinRejection::from(TraitError::new(
                ErrorCode::Unimplemented,
                "a pod shm requires a pod user and ipc namespace join",
            )));
        };
        // 同じ保持役の namespace に限る（取り違えを字句で弾く。pid の再利用は 1 回開いた fd の素性で見る）。
        let user_token = proc_pid_token(paths.user, "user");
        if user_token != Some(source.pid.to_string().as_str()) {
            return Err(PinRejection::new(
                ErrorCode::InvalidArgument,
                "the pod shm path does not belong to the same holder as the pod user namespace",
                PodNamespaceJoinOutcome::PathMalformed,
            ));
        }
        let fd = super::open_ns(&source.path)?;
        let inspect = |_: SysError| {
            PinRejection::from(TraitError::new(
                ErrorCode::Internal,
                "failed to inspect a mount namespace",
            ))
        };
        let fs_magic = sys::fs_type(fd.as_fd()).map_err(inspect)?;
        let ns_type = if fs_magic == sys::NSFS_MAGIC {
            Some(sys::ns_type(fd.as_fd()).map_err(inspect)?)
        } else {
            None
        };
        let owner = if ns_type == Some(sys::NsFlag::Mount.bits()) {
            match sys::ns_owner_userns(fd.as_fd()) {
                Ok(owner) => Some(super::identity(owner.as_fd())?),
                Err(SysError::Os(errno)) if errno == sys::EPERM => None,
                Err(e) => return Err(inspect(e)),
            }
        } else {
            None
        };
        let join_user = super::identity(join.user_fd())?;
        classify(
            &Observed {
                fs_magic,
                ns_type,
                owner,
            },
            join_user,
        )?;
        Ok(Self {
            fd: Arc::new(fd),
            expected: source.identity(),
        })
    }

    /// 非 Linux は namespace を固定できない（`Unimplemented`。fail-closed。CLI-1）。
    #[cfg(not(target_os = "linux"))]
    pub(in crate::oci_runtime) fn pin(
        _source: &PodShmSource,
        _join: Option<&super::NamespaceJoin>,
        _join_paths: Option<&super::JoinPaths<'_>>,
    ) -> Result<Self, PinRejection> {
        Err(PinRejection::from(TraitError::new(
            ErrorCode::Unimplemented,
            "a pod shm requires Linux",
        )))
    }

    /// 試験専用: 検証を通さずに任意の fd から作る（launcher の分岐を、実際の保持役なしで確かめる）。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test(fd: OwnedFd, expected: (u64, u64)) -> Self {
        Self {
            fd: Arc::new(fd),
            expected,
        }
    }

    /// 固定した保持役の mount namespace の fd（`setns` 専用。init の pivot 前段が使う）。
    #[cfg(target_os = "linux")]
    pub(crate) fn mnt_ns_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// 期待する tmpfs のルートの `(st_dev, st_ino)`。
    #[cfg(target_os = "linux")]
    pub(crate) fn expected(&self) -> (u64, u64) {
        self.expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str) -> Result<PodShmSource, TraitError> {
        PodShmSource::new(PathBuf::from(path), 48, 2)
    }

    /// CRI-2・CORE-3・SEC-1（#4822）: 字句は `/proc/<正準な正の整数>/ns/mnt` だけを受け、pid と素性を具体値で返す。
    #[test]
    fn cri2_4822_source_accepts_only_proc_pid_ns_mnt() {
        let ok = source("/proc/1234/ns/mnt").expect("valid");
        assert_eq!(ok.path(), Path::new("/proc/1234/ns/mnt"));
        assert_eq!(ok.pid(), 1234);
        assert_eq!(ok.identity(), (48, 2));
        for bad in [
            "/proc/self/ns/mnt",
            "/proc/0/ns/mnt",
            "/proc/01234/ns/mnt",
            "/proc/+5/ns/mnt",
            "/proc/-5/ns/mnt",
            "/proc/4294967296/ns/mnt",
            "/proc//ns/mnt",
            "/proc/12/ns/user",
            "/proc/12/ns/mnt/",
            "/proc/12/ns/mnt/x",
            "/proc/12/../12/ns/mnt",
            "proc/12/ns/mnt",
            "/run/12/ns/mnt",
            "",
        ] {
            let e = source(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(e.message(), MALFORMED_MESSAGE, "{bad}");
        }
        for (dev, ino) in [(0, 2), (48, 0)] {
            let e = PodShmSource::new(PathBuf::from("/proc/1/ns/mnt"), dev, ino).expect_err("zero");
            assert_eq!(e.message(), "a pod shm identity must be non-zero");
        }
    }

    /// 字句の取り出しは種別を区別する（user の join の path との pid 照合に使う）。
    #[test]
    fn cri2_4822_proc_pid_token_matches_the_kind() {
        assert_eq!(
            proc_pid_token(Path::new("/proc/77/ns/user"), "user"),
            Some("77")
        );
        assert_eq!(proc_pid_token(Path::new("/proc/77/ns/user"), "mnt"), None);
        assert_eq!(
            proc_pid_token(Path::new("/proc/self/ns/user"), "user"),
            Some("self")
        );
        assert_eq!(proc_pid_token(Path::new("/run/x"), "user"), None);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::sys::{self, NsFlag};

        const USER: (u64, u64) = (4, 4_026_532_001);

        fn observed(owner: Option<(u64, u64)>) -> Observed {
            Observed {
                fs_magic: sys::NSFS_MAGIC,
                ns_type: Some(NsFlag::Mount.bits()),
                owner,
            }
        }

        fn rejection(o: &Observed) -> (ErrorCode, Option<PodNamespaceJoinOutcome>) {
            let r = classify(o, USER).expect_err("rejected");
            (r.error.code(), r.outcome)
        }

        /// SEC-5・SEC-4（#4822）: 所有者が join する user namespace なら受理し、違う・取れない（呼び出し側の外側）なら
        /// `PermissionDenied` と専用の結果、nsfs でない・種別が違えば `InvalidArgument` と `NotNamespaceFile`。
        #[test]
        fn sec5_4822_classify_checks_type_and_owner() {
            assert!(classify(&observed(Some(USER)), USER).is_ok());
            let denied = (
                ErrorCode::PermissionDenied,
                Some(PodNamespaceJoinOutcome::PodShmOwnerMismatch),
            );
            assert_eq!(rejection(&observed(Some((4, 4_026_532_002)))), denied);
            assert_eq!(rejection(&observed(None)), denied);
            let not_ns = (
                ErrorCode::InvalidArgument,
                Some(PodNamespaceJoinOutcome::NotNamespaceFile),
            );
            let mut o = observed(Some(USER));
            o.fs_magic = sys::TMPFS_MAGIC;
            o.ns_type = None;
            assert_eq!(rejection(&o), not_ns);
            let mut o = observed(Some(USER));
            o.ns_type = Some(NsFlag::Ipc.bits());
            assert_eq!(rejection(&o), not_ns);
        }

        /// join が無い（または path が無い）指定は fd を開く前に `Unimplemented`（監査なし）。
        #[test]
        fn cri2_4822_pin_without_a_join_is_unimplemented() {
            let src = source("/proc/1234/ns/mnt").expect("valid");
            let e = PinnedPodShm::pin(&src, None, None).expect_err("no join");
            assert_eq!(e.error.code(), ErrorCode::Unimplemented);
            assert_eq!(e.outcome, None);
        }

        /// 別の保持役の pid の指定は、開く前に `InvalidArgument` と `PathMalformed`（user の join の path の pid と照合）。
        #[test]
        fn cri2_4822_pin_rejects_a_different_holder_pid() {
            use super::super::super::{JoinPaths, NamespaceJoin};
            let own = |p: &str| sys::open_ns_file(&std::ffi::CString::new(p).expect("c")).expect(p);
            let join = NamespaceJoin::for_test(own("/proc/self/ns/user"), own("/proc/self/ns/ipc"));
            let paths = JoinPaths {
                user: Path::new("/proc/1234/ns/user"),
                ipc: Path::new("/proc/1234/ns/ipc"),
                net: None,
                pid: None,
            };
            let other = source("/proc/4321/ns/mnt").expect("valid");
            let e = PinnedPodShm::pin(&other, Some(&join), Some(&paths)).expect_err("pid mismatch");
            assert_eq!(e.error.code(), ErrorCode::InvalidArgument);
            assert_eq!(e.outcome, Some(PodNamespaceJoinOutcome::PathMalformed));
        }
    }
}
