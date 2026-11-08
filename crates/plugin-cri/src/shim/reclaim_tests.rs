//! delete action の停止・回収の試験（CRI-5・CRI-7・REPAIR-3・REPAIR-5・SEC-1・#4152）。
//!
//! 親の `shim` から `#[cfg(all(test, target_os = "linux"))]` で取り込む。実の `FileStateStore` の上に、呼び出しを記録して
//! 状態を実際に書き換える偽の実行層（`Fake`）を載せ、呼び出しの順序・回数と状態ルートの木で照合する。

use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::state_store::FileStateStore;
use fandhe_container_core::traits::{
    ContainerStatus, DeleteRequest, DeleteResponse, DeleteStateRequest, ErrorCode, ExitTime,
    GetStateRequest, StateStore, StopRequest, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::error::CriErrorCode;

use super::delete_tests::{cid, make_bundle, parse, seed, snapshot};
use super::reclaim::{ReclaimBudget, ReclaimRuntime, SHIM_DELETE_DEADLINE};
use super::*;
use crate::test_root;

const EXIT_NANOS: i64 = 1_700_000_000_000_000_005;

/// 段で注入する失敗。
#[derive(Clone, Copy, Debug)]
enum Inject {
    /// 効果の前で止まる（解放されても効果を出さずに失敗する）。
    HangBefore,
    /// 効果を出してから止まる。
    HangAfter,
    /// 効果を出す前に `Timeout` を返す。
    TimeoutErr,
}

struct Fake {
    store: FileStateStore,
    calls: Arc<Mutex<Vec<String>>>,
    inject_stop: Option<Inject>,
    inject_delete: Option<Inject>,
    release: Mutex<Option<Receiver<()>>>,
}

impl Fake {
    fn log(&self, what: &str, id: &ContainerId) {
        self.calls.lock().unwrap().push(format!("{what}:{id}"));
    }

    /// 注入を適用する。`true` なら効果を出してよい。
    fn gate(&self, inject: Option<Inject>) -> Result<bool, TraitError> {
        match inject {
            None => Ok(true),
            Some(Inject::TimeoutErr) => Err(TraitError::new(ErrorCode::Timeout, "injected")),
            Some(Inject::HangBefore) => {
                self.wait_release();
                Err(TraitError::new(ErrorCode::Unavailable, "released"))
            }
            Some(Inject::HangAfter) => Ok(true),
        }
    }

    fn wait_release(&self) {
        let rx = self.release.lock().unwrap().take();
        if let Some(rx) = rx {
            let _ = rx.recv();
        }
    }
}

impl ReclaimRuntime for Fake {
    fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.log("stop", req.id());
        self.gate(self.inject_stop)?;
        let rec = self.store.get(&GetStateRequest::new(req.id().clone()))?;
        let stopped = ContainerStatus::stopped_at(
            req.id().clone(),
            Some(137),
            ExitTime::from_unix_nanos(EXIT_NANOS),
        );
        self.store
            .update(&UpdateStateRequest::new(stopped.clone(), rec.revision()))?;
        if matches!(self.inject_stop, Some(Inject::HangAfter)) {
            self.wait_release();
        }
        Ok(stopped)
    }

    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.log("delete", req.id());
        self.gate(self.inject_delete)?;
        let rec = self.store.get(&GetStateRequest::new(req.id().clone()))?;
        self.store
            .delete(&DeleteStateRequest::new(req.id().clone(), rec.revision()))?;
        if matches!(self.inject_delete, Some(Inject::HangAfter)) {
            self.wait_release();
        }
        Ok(DeleteResponse::new())
    }
}

/// 1 回の `delete_in` の結果と観測。
struct Run {
    result: Result<Option<ShimDeleteExit>, CriError>,
    calls: Vec<String>,
    made: usize,
    /// 解放用の送信側（落とすと止まった呼び出しが戻る）。
    _release: mpsc::Sender<()>,
}

fn run(
    inv: &ShimInvocation,
    base: &Path,
    inject_stop: Option<Inject>,
    inject_delete: Option<Inject>,
    budget: &ReclaimBudget,
) -> Run {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let made = Arc::new(Mutex::new(0usize));
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let (c, m) = (Arc::clone(&calls), Arc::clone(&made));
    let result = delete_in(
        inv,
        base,
        move |store| {
            *m.lock().unwrap() += 1;
            Arc::new(Fake {
                store,
                calls: c,
                inject_stop,
                inject_delete,
                release: Mutex::new(rx.lock().unwrap().take()),
            })
        },
        budget,
    );
    let calls = calls.lock().unwrap().clone();
    let made = *made.lock().unwrap();
    Run {
        result,
        calls,
        made,
        _release: tx,
    }
}

const FAST: ReclaimBudget = ReclaimBudget {
    stop: Duration::from_millis(300),
    remove: Duration::from_millis(300),
};

fn entry(base: &Path, inv: &ShimInvocation, id: &str) -> std::path::PathBuf {
    scoped_root_path(base, inv.namespace.as_ref(), inv.address.as_deref())
        .unwrap()
        .join(id)
}

/// CRI-5・REPAIR-3・#4152: Running の記録は stop → delete の順で回収され、状態ルートの `<id>` が消え、
/// 応答は停止で得た終了コード・終了時刻と記録の pid になる。
#[test]
fn cri5_4152_running_is_stopped_then_deleted() {
    let guard = test_root::test_root("shim", "r-running");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(
        &base,
        ContainerStatus::running(cid("abc"), std::num::NonZeroU32::new(99)),
        &bundle,
    );
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    assert!(entry(&base, &inv, "abc").is_dir());

    let r = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
    assert_eq!(r.calls, ["stop:abc", "delete:abc"]);
    let exit = r.result.unwrap().expect("reclaimed");
    assert_eq!((exit.pid(), exit.exit_status()), (99, 137));
    let at = exit.exited_at().expect("exited_at");
    assert_eq!((at.seconds, at.nanos), (1_700_000_000, 5));
    assert!(!entry(&base, &inv, "abc").exists());

    // 2 回目は回収済み: 実行層を作らず成功（冪等）。
    let again = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
    assert!(again.result.unwrap().is_none());
    assert_eq!((again.made, again.calls.len()), (0, 0));
}

/// CRI-5・REPAIR-4・#4152: 記録なし・回収済みは実行層を作らず、状態ルートの木を変えずに `Ok(None)`。何度呼んでも同じ。
#[test]
fn cri5_4152_not_recorded_and_reclaimed_touch_nothing() {
    let guard = test_root::test_root("shim", "r-none");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();

    // 階層が無い（NotRecorded）。
    for _ in 0..2 {
        let r = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
        assert!(r.result.unwrap().is_none());
        assert_eq!((r.made, r.calls.len()), (0, 0));
        assert!(!guard.join("state-shim-state").exists());
    }

    // ストアはあるが別 id の記録だけ（AlreadyReclaimed）。
    let other = make_bundle(&guard, "other");
    seed(&base, ContainerStatus::created(cid("other"), None), &other);
    let sib = guard.join("state-shim-state");
    let before = snapshot(&sib);
    for _ in 0..2 {
        let r = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
        assert!(r.result.unwrap().is_none());
        assert_eq!((r.made, r.calls.len()), (0, 0));
        assert_eq!(snapshot(&sib), before);
    }
}

/// CRI-5・REPAIR-5・#4152: 段ごとの期限切れ・失敗は `DEADLINE_EXCEEDED` で、再実行すると続きの段から回収できる。
#[test]
fn cri5_4152_stage_deadline_then_resume() {
    // (停止の注入, 削除の注入, 最初の実行の呼び出し, 再実行の呼び出し, 再実行が回収を返すか)
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Option<Inject>, Option<Inject>, Vec<&str>, Vec<&str>, bool)> = vec![
        (
            Some(Inject::HangBefore),
            None,
            vec!["stop:abc"],
            vec!["stop:abc", "delete:abc"],
            true,
        ),
        (
            Some(Inject::TimeoutErr),
            None,
            vec!["stop:abc"],
            vec!["stop:abc", "delete:abc"],
            true,
        ),
        // 停止の効果が出た後に止まった: 再実行は Stopped として delete だけ。
        (
            Some(Inject::HangAfter),
            None,
            vec!["stop:abc"],
            vec!["delete:abc"],
            true,
        ),
        (
            None,
            Some(Inject::HangBefore),
            vec!["stop:abc", "delete:abc"],
            vec!["delete:abc"],
            true,
        ),
        (
            None,
            Some(Inject::TimeoutErr),
            vec!["stop:abc", "delete:abc"],
            vec!["delete:abc"],
            true,
        ),
        // 削除の効果が出た後に止まった: 再実行は回収済みで何も呼ばない。
        (
            None,
            Some(Inject::HangAfter),
            vec!["stop:abc", "delete:abc"],
            vec![],
            false,
        ),
    ];
    for (i, (is, id, first, second, reclaimed)) in rows.into_iter().enumerate() {
        let guard = test_root::test_root("shim", &format!("r-stage-{i}"));
        let base = guard.join("state");
        let bundle = make_bundle(&guard, "abc");
        seed(
            &base,
            ContainerStatus::running(cid("abc"), std::num::NonZeroU32::new(5)),
            &bundle,
        );
        let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();

        let r1 = run(&inv, &base, is, id, &FAST);
        let (res, calls1) = (r1.result, r1.calls);
        let e = res.expect_err(&format!("row {i}"));
        assert_eq!(e.code(), CriErrorCode::Timeout, "row {i}");
        assert_eq!(calls1, first, "row {i}");
        if matches!(is.or(id), Some(Inject::HangBefore | Inject::HangAfter)) {
            assert!(
                e.message().starts_with("shim delete ")
                    && e.message().ends_with(" did not finish within the deadline"),
                "row {i}: {}",
                e.message()
            );
        }

        let r2 = run(&inv, &base, None, None, &FAST);
        assert_eq!(r2.calls, second, "row {i}");
        let out = r2.result.unwrap_or_else(|e| panic!("row {i}: {e:?}"));
        assert_eq!(out.is_some(), reclaimed, "row {i}");
        assert!(!entry(&base, &inv, "abc").exists(), "row {i}");
        drop(r1._release);
    }
}

/// CRI-5・#4152: 記録の状態ごとの呼び出しと応答の終了状態。
#[test]
fn cri5_4152_exit_state_by_recorded_state() {
    let nz = std::num::NonZeroU32::new;
    let at = ExitTime::from_unix_nanos(EXIT_NANOS);
    // (状態, 呼び出し, exit_status, exited_at の有無, pid)
    let rows: Vec<(ContainerStatus, Vec<&str>, u32, bool, u32)> = vec![
        (
            ContainerStatus::stopped_at(cid("abc"), Some(3), at),
            vec!["delete:abc"],
            3,
            true,
            0,
        ),
        (
            ContainerStatus::stopped_at(cid("abc"), Some(3), None),
            vec!["delete:abc"],
            3,
            false,
            0,
        ),
        (
            ContainerStatus::stopped(cid("abc"), None),
            vec!["delete:abc"],
            255,
            false,
            0,
        ),
        (
            ContainerStatus::created(cid("abc"), None),
            vec!["delete:abc"],
            0,
            false,
            0,
        ),
        (
            ContainerStatus::created(cid("abc"), nz(7)),
            vec!["stop:abc", "delete:abc"],
            137,
            true,
            7,
        ),
    ];
    for (i, (status, calls, code, has_at, pid)) in rows.into_iter().enumerate() {
        let guard = test_root::test_root("shim", &format!("r-exit-{i}"));
        let base = guard.join("state");
        let bundle = make_bundle(&guard, "abc");
        seed(&base, status, &bundle);
        let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
        let r = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
        assert_eq!(r.calls, calls, "row {i}");
        let exit = r.result.unwrap().expect("reclaimed");
        assert_eq!(
            (exit.exit_status(), exit.exited_at().is_some(), exit.pid()),
            (code, has_at, pid),
            "row {i}"
        );
    }
}

/// CRI-5・SEC-1・fail-closed・#4152: Creating の記録は実行層を呼ばず `FAILED_PRECONDITION`、記録も残る。
#[test]
fn cri5_4152_creating_is_rejected_without_calls() {
    let guard = test_root::test_root("shim", "r-creating");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::creating(cid("abc")), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let r = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
    let e = r.result.unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "container is not in a reclaimable state");
    assert!(r.calls.is_empty());
    assert!(entry(&base, &inv, "abc").is_dir());
}

/// CRI-5・SEC-1・#4152: 他のコンテナの記録には触れない。実行層の呼び出しは対象の id だけ。
#[test]
fn cri5_4152_other_containers_are_untouched() {
    let guard = test_root::test_root("shim", "r-others");
    let base = guard.join("state");
    let target = make_bundle(&guard, "abc");
    let b1 = make_bundle(&guard, "run1");
    let b2 = make_bundle(&guard, "stop1");
    seed(
        &base,
        ContainerStatus::running(cid("abc"), std::num::NonZeroU32::new(9)),
        &target,
    );
    let store = seed(
        &base,
        ContainerStatus::running(cid("run1"), std::num::NonZeroU32::new(10)),
        &b1,
    );
    seed(&base, ContainerStatus::stopped(cid("stop1"), Some(1)), &b2);
    let get = |id: &str| store.get(&GetStateRequest::new(cid(id))).unwrap();
    let (r1, r2) = (get("run1"), get("stop1"));

    let inv = parse("abc", Some(target.to_str().unwrap())).unwrap();
    let r = run(&inv, &base, None, None, &ReclaimBudget::PRODUCTION);
    assert!(r.calls.iter().all(|c| c.ends_with(":abc")), "{:?}", r.calls);
    assert!(r.result.unwrap().is_some());
    assert!(!entry(&base, &inv, "abc").exists());
    for (id, before) in [("run1", r1), ("stop1", r2)] {
        let after = get(id);
        assert_eq!(after.revision(), before.revision(), "{id}");
        assert_eq!(after.status(), before.status(), "{id}");
        assert!(entry(&base, &inv, id).is_dir(), "{id}");
    }
}

/// REPAIR-5・#4152: 段の予算の合計は全体の上限に収まり、全体の上限は containerd の cleanup の 5 秒より短い。
#[test]
fn cri5_4152_production_budget_fits_containerd_cleanup() {
    assert!(ReclaimBudget::PRODUCTION.total() <= SHIM_DELETE_DEADLINE);
    assert!(SHIM_DELETE_DEADLINE < Duration::from_secs(5));
}

/// CRI-5・REPAIR-3・#4152: 本番の `CoreLifecycleRuntime` で、pid の無い Created の記録が回収される（supervisor 不要の経路）。
#[test]
fn cri5_4152_real_core_runtime_reclaims_created_without_pid() {
    let guard = test_root::test_root("shim", "r-real");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let budget = ReclaimBudget::PRODUCTION;
    let out = delete_in(
        &inv,
        &base,
        |store| {
            Arc::new(
                core_runtime_for(Arc::new(store))
                    .with_delete_deadline(budget.remove)
                    .with_container_log_lock_wait(budget.remove)
                    .with_cleanup_warning_sink(Arc::new(|_| {})),
            )
        },
        &budget,
    )
    .unwrap()
    .expect("reclaimed");
    assert_eq!((out.pid(), out.exit_status()), (0, 0));
    assert!(out.exited_at().is_none());
    assert!(!entry(&base, &inv, "abc").exists());
    let again = delete_in(
        &inv,
        &base,
        |_| unreachable!("no runtime for a reclaimed container"),
        &budget,
    );
    assert!(again.unwrap().is_none());
}
