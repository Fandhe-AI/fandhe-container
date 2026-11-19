//! pid namespace の TARGET（別コンテナの pid namespace の init の直下の子として参加する）の解決と fd 固定
//! （CRI-2・CORE-3・SEC-1・SEC-5。#4819・T1）。
//!
//! # 役割と呼び出し元
//!
//! CRI の `NamespaceMode::TARGET`（`pid: TARGET`。対象のコンテナと pid namespace を共有する）を、core が受ける **起動オプション**
//! として扱う。supervisor の `build_launcher`（fork の前・cgroup の準備の後）が [`PinnedPidTarget::resolve`] を呼び、対象の
//! launch pidfd（対象の supervisor が起動時から保持するもの。制御チャネル kind 6）から対象の pid ns の fd を固定して
//! `LaunchOptions::with_pid_target` へ渡す。`start` が [`NamespaceJoin::pin`](super::NamespaceJoin) の pid の参加先として
//! この fd を使い、以降（`setns(pid)`・`InitPidNamespace::Joined`・`LaunchIsolationRecord::with_pod_pid_ns`・exec の
//! launch pidfd 限定〔#4813〕・kill-all〔#4811〕）は pod の pid ns の join（#4809）と同じ経路を通る。
//!
//! config.json は純 OCI のままで、pid は path なしの entry 1 件のまま。起動オプションに TARGET があるときだけ、path なしの pid を
//! 「対象の pid ns へ参加」と読み替える（`--pod-shm` と同じ作り）。
//!
//! # 解決の手順（`resolve`。メッセージは固定文言で ID・パス・pid を含めない）
//!
//! | 順 | 検査 | 不合格 |
//! | -- | ---- | ------ |
//! | 1 | 状態ストアに対象の記録がある | `NotFound` |
//! | 2 | 状態が Running で pid があり、cgroup の配置と launch の分離の記録がある | `FailedPrecondition` |
//! | 3 | 対象が pod の pid ns を共有していない（自分の pid ns の init であること） | `FailedPrecondition` |
//! | 4 | 呼び出し側の注入口（制御チャネル）から launch pidfd を 1 回だけ受け取る | `Unavailable` |
//! | 5 | `Pid1Target::open_with_launch_pidfd`（pidfd の `Pid:` と記録 pid の照合・未終了・直接入れ子の PID 1・cgroup の所属） | 下の写像（違反は監査へ） |
//! | 6 | `Pid1Target::open_pid_namespace`（pidfd で固定した後に開き、開いた後に未終了を再確認） | 下の写像 |
//!
//! 分離違反（`ExecError::violation` が `Some`。pidfd の不一致・cgroup 所属の不一致・直接入れ子の PID 1 でない等）は、固定文言へ
//! 写す前に `resolve` の `audit` へ層 `exec_target` の記録として 1 件届ける（`record_exec_target_rejection`。exec の対象の拒否と
//! 同じ形。コンテナ ID は対象。SEC-4）。違反を伴わない失敗（対象の不在・終了・supervisor 不在・obtain 失敗）は記録しない。
//! 記録の失敗は返すエラーを覆さない（fail-closed。失敗の診断は `audit` の実装が担う）。
//!
//! 記録の pid から `pidfd_open` や `/proc` を開く縮退経路は持たない（pid の再利用。SEC-1）。pid ns の所有 user namespace が
//! 参加する pod の user namespace と同じこと・親が呼び出し側の pid ns であることは、固定済みの fd に対して
//! `NamespaceJoin::pin` が検査する（既存の `PidOwnerMismatch`・`PidNotChild`）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - 対象の再起動（restart）には追従しない。restart の再 launch は同じ launcher・同じ固定を使い、対象の終了済み・素性の
//!   食い違いは launch の前に拒否する（再解決しない）。
//! - 非 Linux では固定できない（型は作れない）。

#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use crate::traits::{ErrorCode, TraitError};

#[cfg(target_os = "linux")]
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, OwnedFd};

#[cfg(target_os = "linux")]
use crate::audit_log::AuditSink;
#[cfg(target_os = "linux")]
use crate::exec::{ExecError, Pid1Target, ViolationReason, record_exec_target_rejection};
#[cfg(target_os = "linux")]
use crate::traits::{ContainerId, ContainerState, GetStateRequest, StateStore};

/// 対象の記録がない。
#[cfg(target_os = "linux")]
const MSG_NOT_FOUND: &str = "the pid namespace target does not exist";
/// 対象が稼働中でない（Created・Stopped・pid なし）。
#[cfg(target_os = "linux")]
const MSG_NOT_RUNNING: &str = "the pid namespace target is not running";
/// 対象が終了済み。
#[cfg(target_os = "linux")]
const MSG_EXITED: &str = "the pid namespace target has exited";
/// launch pidfd を得られない（supervisor 不在・保持していない・上限など）。
#[cfg(target_os = "linux")]
const MSG_UNAVAILABLE: &str = "the launch pidfd of the pid namespace target is unavailable";
/// pidfd が対象のものでない。
#[cfg(target_os = "linux")]
const MSG_MISMATCH: &str = "the launch pidfd does not match the pid namespace target";
/// 対象が自分の pid namespace の init でない。
#[cfg(target_os = "linux")]
const MSG_NOT_OWNER: &str = "the pid namespace target does not own its pid namespace";
/// 記録不足・その他。
#[cfg(target_os = "linux")]
const MSG_UNVERIFIED: &str = "the pid namespace target could not be verified";

/// 固定済みの対象の pid namespace（Linux のみ。他 OS では作れない）。
///
/// `LaunchOptions` に載り、`start` が参加先の fd として使う。launch pidfd（`Pid1Target`）も保持し、restart の再 launch の前に
/// 対象の生存を確かめる。clone は fd を共有し、同一性は fd の同一性。
#[derive(Clone)]
pub struct PinnedPidTarget {
    #[cfg(target_os = "linux")]
    target: Arc<Pid1Target>,
    #[cfg(target_os = "linux")]
    ns: Arc<OwnedFd>,
    /// 固定した pid namespace の `(st_dev, st_ino)`。
    #[cfg(target_os = "linux")]
    identity: (u64, u64),
    /// Linux 以外では構築できないことを型で表す。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl PartialEq for PinnedPidTarget {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            Arc::ptr_eq(&self.ns, &other.ns)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            match self.never {}
        }
    }
}

impl Eq for PinnedPidTarget {}

/// 固定した pid ns の素性だけを出す（`Pid1Target` の pid・cgroup のパス〔コンテナ ID を含む〕をログへ出さない。SEC-1）。
impl std::fmt::Debug for PinnedPidTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("PinnedPidTarget");
        #[cfg(target_os = "linux")]
        d.field("identity", &self.identity);
        d.finish_non_exhaustive()
    }
}

impl PinnedPidTarget {
    /// 固定した pid namespace の素性 `(st_dev, st_ino)`。
    #[cfg(target_os = "linux")]
    pub fn identity(&self) -> (u64, u64) {
        self.identity
    }

    /// 固定した pid namespace の fd（`NamespaceJoin::pin` が参加先として使う）。
    #[cfg(target_os = "linux")]
    pub(super) fn ns(&self) -> &Arc<OwnedFd> {
        &self.ns
    }

    /// 対象が終了していないことを確かめる（restart の再 launch の前。終了済みは `FailedPrecondition`）。
    #[cfg(target_os = "linux")]
    pub fn ensure_alive(&self) -> Result<(), TraitError> {
        self.target
            .ensure_alive()
            .map_err(|_| TraitError::new(ErrorCode::FailedPrecondition, MSG_EXITED))
    }

    /// 対象の記録と launch pidfd から pid namespace を解決して固定する（モジュール doc の手順）。
    ///
    /// `obtain` は対象の記録の pid を受け、launch pidfd の複製を返す（本番は対象の supervisor の制御チャネル。ちょうど 1 回だけ
    /// 呼ぶ。失敗はすべて `Unavailable` に写す）。`audit` は分離違反（モジュール doc）の記録先。
    #[cfg(target_os = "linux")]
    pub fn resolve(
        store: &dyn StateStore,
        target: &ContainerId,
        audit: &dyn AuditSink,
        obtain: impl FnOnce(NonZeroU32) -> Result<OwnedFd, TraitError>,
    ) -> Result<Self, TraitError> {
        let fail = |code, message| TraitError::new(code, message);
        let record = store
            .get(&GetStateRequest::new(target.clone()))
            .map_err(|e| {
                if e.code() == ErrorCode::NotFound {
                    fail(ErrorCode::NotFound, MSG_NOT_FOUND)
                } else {
                    fail(ErrorCode::FailedPrecondition, MSG_UNVERIFIED)
                }
            })?;
        let status = record.status();
        let pid = match status.pid() {
            Some(pid) if status.state() == ContainerState::Running => pid,
            _ => return Err(fail(ErrorCode::FailedPrecondition, MSG_NOT_RUNNING)),
        };
        let (Some(placement), Some(isolation)) = (record.cgroup(), record.launch_isolation())
        else {
            return Err(fail(ErrorCode::FailedPrecondition, MSG_UNVERIFIED));
        };
        // 対象が pod の pid ns を共有している（init の直下の子）と、対象の pid ns への参加は「孫」になり PID 1 の検査も成り立たない。
        if isolation.pod_pid_ns().is_some() {
            return Err(fail(ErrorCode::FailedPrecondition, MSG_NOT_OWNER));
        }
        let pidfd = obtain(pid).map_err(|_| fail(ErrorCode::Unavailable, MSG_UNAVAILABLE))?;
        let pinned = Pid1Target::open_with_launch_pidfd(pidfd, pid, status.id(), placement, None)
            .map_err(|e| map_exec_error(&e, target, audit))?;
        let ns = pinned
            .open_pid_namespace()
            .map_err(|e| map_exec_error(&e, target, audit))?;
        let identity = super::identity_plain(ns.as_fd())
            .map_err(|_| fail(ErrorCode::FailedPrecondition, MSG_UNVERIFIED))?;
        Ok(Self {
            target: Arc::new(pinned),
            ns: Arc::new(ns),
            identity,
        })
    }

    /// 試験専用（`exec-test-support`。リリースビルドでは有効にできない）: 検証を通さずに作る（launcher の対の検査・転送の照合を、
    /// 実際の namespace なしで確かめる。本番の固定は [`Self::resolve`] だけ。SEC-1）。
    #[cfg(all(any(test, feature = "exec-test-support"), target_os = "linux"))]
    #[doc(hidden)]
    pub fn for_test(pidfd: OwnedFd, ns: OwnedFd, identity: (u64, u64)) -> Self {
        Self {
            target: Arc::new(Pid1Target::for_test(pidfd)),
            ns: Arc::new(ns),
            identity,
        }
    }
}

/// `Pid1Target` の失敗を固定の語彙へ写す（pid を含む文言をそのまま返さない。表に無いものは「検証できない」）。
/// 違反つきの失敗は写す前に `audit` へ 1 件記録する（記録の成否で結果は変わらない。SEC-4）。
#[cfg(target_os = "linux")]
fn map_exec_error(e: &ExecError, target: &ContainerId, audit: &dyn AuditSink) -> TraitError {
    let reason = e.violation.as_ref().map(|v| v.reason);
    if let Some(r) = reason {
        let _ = record_exec_target_rejection((), r, Some(target), audit);
    }
    let (code, message) = match (reason, e.code) {
        (Some(ViolationReason::ExecTargetPidfdMismatch), _) => {
            (ErrorCode::FailedPrecondition, MSG_MISMATCH)
        }
        (Some(ViolationReason::ExecTargetNotNestedPid1), _) => {
            (ErrorCode::FailedPrecondition, MSG_NOT_OWNER)
        }
        (None, ErrorCode::NotFound) => (ErrorCode::FailedPrecondition, MSG_EXITED),
        (None, ErrorCode::FailedPrecondition) if e.message.contains("already exited") => {
            (ErrorCode::FailedPrecondition, MSG_EXITED)
        }
        (None, ErrorCode::InvalidArgument) if e.message.contains("not a pidfd") => {
            (ErrorCode::FailedPrecondition, MSG_MISMATCH)
        }
        _ => (ErrorCode::FailedPrecondition, MSG_UNVERIFIED),
    };
    TraitError::new(code, message)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::cell::Cell;
    use std::os::fd::OwnedFd;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use super::*;
    use crate::launch_isolation::{
        LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
    };
    use crate::traits::{
        CgroupPlacement, CgroupScope, ContainerStatus, CreateStateRequest, DeleteStateRequest,
        DeleteStateResponse, ListStateRequest, StateList, StateRecord, StateRevision,
        UpdateStateRequest,
    };

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    struct Store(Option<StateRecord>);

    fn unused() -> TraitError {
        TraitError::new(ErrorCode::Unimplemented, "unused")
    }

    impl StateStore for Store {
        fn create(&self, _r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(unused())
        }
        fn get(&self, _r: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0
                .clone()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "no such record"))
        }
        fn update(&self, _r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(unused())
        }
        fn delete(&self, _r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(unused())
        }
        fn list(&self, _r: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(unused())
        }
    }

    fn isolation(pod_pid_ns: bool) -> LaunchIsolationRecord {
        let rules = vec![RecordedRule::new(RecordedTarget::Root, 0x7)];
        let r = LaunchIsolationRecord::from_parts(
            RootIdentity::new(44, 7),
            RecordedLandlock::new(0xFFFF, rules).expect("landlock"),
        );
        if pod_pid_ns {
            r.with_pod_pid_ns(4, 5)
        } else {
            r
        }
    }

    fn record(status: ContainerStatus, pod_pid_ns: bool, full: bool) -> StateRecord {
        let r = StateRecord::new(status, PathBuf::from("/bundle"), StateRevision::INITIAL)
            .expect("record");
        if !full {
            return r;
        }
        r.with_cgroup(CgroupPlacement::new(
            CgroupScope::new("/fc").expect("scope"),
            StateRevision::INITIAL,
        ))
        .with_launch_isolation(isolation(pod_pid_ns))
    }

    fn running(pid: u32, pod_pid_ns: bool, full: bool) -> StateRecord {
        let status = ContainerStatus::running(cid("t1"), NonZeroU32::new(pid));
        record(status, pod_pid_ns, full)
    }

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    fn pidfd_of(child: &Child) -> OwnedFd {
        crate::sys::pidfd_open(child.id()).expect("pidfd_open")
    }

    /// 届いた監査記録を数える sink。
    #[derive(Default)]
    struct Audit(std::sync::Mutex<Vec<crate::audit_log::AuditRecord>>);

    impl AuditSink for Audit {
        fn record(&self, r: &crate::audit_log::AuditRecord) -> Result<(), TraitError> {
            self.0.lock().expect("lock").push(r.clone());
            Ok(())
        }
    }

    fn resolve_audited(
        store: &Store,
        calls: &Cell<u32>,
        audit: &Audit,
        pidfd: impl FnOnce() -> Result<OwnedFd, TraitError>,
    ) -> Result<PinnedPidTarget, TraitError> {
        PinnedPidTarget::resolve(store, &cid("t1"), audit, |_pid| {
            calls.set(calls.get() + 1);
            pidfd()
        })
    }

    fn resolve_with(
        store: &Store,
        calls: &Cell<u32>,
        pidfd: impl FnOnce() -> Result<OwnedFd, TraitError>,
    ) -> Result<PinnedPidTarget, TraitError> {
        resolve_audited(store, calls, &Audit::default(), pidfd)
    }

    fn expect_err(r: Result<PinnedPidTarget, TraitError>, code: ErrorCode, message: &str) {
        let e = r.expect_err("must be rejected");
        assert_eq!((e.code(), e.message()), (code, message));
    }

    /// CRI-2・CORE-3・SEC-1・#4819: 記録なしは `NotFound`・固定文言で、`obtain` は呼ばれない。
    #[test]
    fn cri2_4819_missing_record_is_not_found() {
        let calls = Cell::new(0);
        let r = resolve_with(&Store(None), &calls, || Err(unused()));
        expect_err(
            r,
            ErrorCode::NotFound,
            "the pid namespace target does not exist",
        );
        assert_eq!(calls.get(), 0);
    }

    /// CRI-2・CORE-3・SEC-1・#4819: Created・Stopped・pid なしは「稼働中でない」。
    #[test]
    fn cri2_4819_not_running_is_refused_before_obtain() {
        let statuses = [
            ContainerStatus::created(cid("t1"), None),
            ContainerStatus::stopped(cid("t1"), Some(0)),
            ContainerStatus::running(cid("t1"), None),
        ];
        for status in statuses {
            let calls = Cell::new(0);
            let store = Store(Some(record(status.clone(), false, true)));
            let r = resolve_with(&store, &calls, || Err(unused()));
            expect_err(
                r,
                ErrorCode::FailedPrecondition,
                "the pid namespace target is not running",
            );
            assert_eq!(calls.get(), 0, "{status:?}");
        }
    }

    /// CRI-2・CORE-3・SEC-1・#4819: cgroup の配置か launch の分離の記録が無ければ「検証できない」。
    #[test]
    fn cri2_4819_incomplete_record_is_unverified() {
        let calls = Cell::new(0);
        let store = Store(Some(running(1234, false, false)));
        let r = resolve_with(&store, &calls, || Err(unused()));
        expect_err(
            r,
            ErrorCode::FailedPrecondition,
            "the pid namespace target could not be verified",
        );
        assert_eq!(calls.get(), 0);
    }

    /// CRI-2・CORE-3・SEC-1・#4819: 対象が pod の pid ns を共有していれば `obtain` の前に拒否する。
    #[test]
    fn cri2_4819_target_sharing_a_pod_pid_ns_is_refused() {
        let calls = Cell::new(0);
        let store = Store(Some(running(1234, true, true)));
        let r = resolve_with(&store, &calls, || Err(unused()));
        expect_err(
            r,
            ErrorCode::FailedPrecondition,
            "the pid namespace target does not own its pid namespace",
        );
        assert_eq!(calls.get(), 0);
    }

    /// CRI-2・CORE-3・SEC-1・#4819: `obtain` の失敗（supervisor 不在等）はすべて `Unavailable`・固定文言（ちょうど 1 回の呼び出し）。
    #[test]
    fn cri2_4819_obtain_failure_is_unavailable() {
        for inner in [
            ErrorCode::NotFound,
            ErrorCode::Unimplemented,
            ErrorCode::Timeout,
        ] {
            let calls = Cell::new(0);
            let store = Store(Some(running(1234, false, true)));
            let r = resolve_with(&store, &calls, || {
                Err(TraitError::new(inner, "/secret/path pid 99"))
            });
            expect_err(
                r,
                ErrorCode::Unavailable,
                "the launch pidfd of the pid namespace target is unavailable",
            );
            assert_eq!(calls.get(), 1, "{inner:?}");
        }
    }

    /// CRI-2・CORE-3・SEC-1・#4819: 終了済みの子の pidfd は「終了済み」（zombie・回収済みの両方）。
    #[test]
    fn cri2_4819_exited_target_is_refused() {
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        let pidfd = pidfd_of(&child);
        let store = Store(Some(running(pid, false, true)));
        // zombie（未回収）
        std::thread::sleep(std::time::Duration::from_millis(200));
        let calls = Cell::new(0);
        let fd = pidfd.try_clone().expect("dup");
        expect_err(
            resolve_with(&store, &calls, || Ok(fd)),
            ErrorCode::FailedPrecondition,
            "the pid namespace target has exited",
        );
        // 回収済み
        child.wait().expect("wait");
        let calls = Cell::new(0);
        expect_err(
            resolve_with(&store, &calls, || Ok(pidfd)),
            ErrorCode::FailedPrecondition,
            "the pid namespace target has exited",
        );
        assert_eq!(calls.get(), 1);
    }

    /// CRI-2・CORE-3・SEC-1・#4819: 記録の pid と違うプロセスの pidfd は「一致しない」。pidfd でない fd も同じ。
    #[test]
    fn cri2_4819_foreign_pidfd_is_a_mismatch() {
        let mut other = sleeper();
        let mut recorded = sleeper();
        let store = Store(Some(running(recorded.id(), false, true)));
        let calls = Cell::new(0);
        let r = resolve_with(&store, &calls, || Ok(pidfd_of(&other)));
        expect_err(
            r,
            ErrorCode::FailedPrecondition,
            "the launch pidfd does not match the pid namespace target",
        );
        let not_pidfd: OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
        let r = resolve_with(&store, &Cell::new(0), || Ok(not_pidfd));
        expect_err(
            r,
            ErrorCode::FailedPrecondition,
            "the launch pidfd does not match the pid namespace target",
        );
        for c in [&mut other, &mut recorded] {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// CRI-2・CORE-3・SEC-1・#4819: 対象が自分の pid ns の init でない（呼び出し側と同じ pid ns の子）は、PID 1 の検査で拒否する。
    #[test]
    fn cri2_4819_non_init_target_is_refused() {
        let mut child = sleeper();
        let store = Store(Some(running(child.id(), false, true)));
        let r = resolve_with(&store, &Cell::new(0), || Ok(pidfd_of(&child)));
        // `NSpid:` が 1 要素（自分と同じ pid ns）で、直接入れ子の PID 1 ではない。
        expect_err(
            r,
            ErrorCode::FailedPrecondition,
            "the pid namespace target does not own its pid namespace",
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// SEC-4・CRI-2・#4819: 別プロセスの pidfd は監査に 1 件（層 `exec_target`・理由 `exec_target_pidfd_mismatch`・対象の ID）届き、
    /// 返すエラーは固定文言のまま。違反の無い失敗（記録なし・終了済み・obtain 失敗）は何も届かない。
    #[test]
    fn sec4_4819_violation_is_audited_and_plain_failures_are_not() {
        let mut other = sleeper();
        let mut recorded = sleeper();
        let store = Store(Some(running(recorded.id(), false, true)));
        let audit = Audit::default();
        let r = resolve_audited(&store, &Cell::new(0), &audit, || Ok(pidfd_of(&other)));
        expect_err(
            r,
            ErrorCode::FailedPrecondition,
            "the launch pidfd does not match the pid namespace target",
        );
        {
            let recs = audit.0.lock().expect("lock");
            assert_eq!(recs.len(), 1);
            let json = format!("{:?}", recs[0]);
            assert!(json.contains("exec_target_pidfd_mismatch"), "{json}");
            assert!(json.contains("t1"), "{json}");
        }
        let quiet = Audit::default();
        let _ = resolve_audited(&Store(None), &Cell::new(0), &quiet, || Err(unused()));
        let _ = resolve_audited(&store, &Cell::new(0), &quiet, || Err(unused()));
        assert!(quiet.0.lock().expect("lock").is_empty());
        for c in [&mut other, &mut recorded] {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
