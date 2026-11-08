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
use super::reclaim::{
    Generation, GuardedCore, ReclaimBudget, ReclaimRuntime, SHIM_DELETE_DEADLINE,
};
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

impl Fake {
    fn check_generation(
        &self,
        id: &ContainerId,
        generation: &Generation,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        let rec = self.store.get(&GetStateRequest::new(id.clone()))?;
        if Generation::of(&rec) != *generation {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "changed"));
        }
        Ok(rec)
    }
}

impl ReclaimRuntime for Fake {
    fn stop(
        &self,
        req: &StopRequest,
        generation: &Generation,
    ) -> Result<(ContainerStatus, Option<Generation>), TraitError> {
        self.log("stop", req.id());
        self.gate(self.inject_stop)?;
        let rec = self.check_generation(req.id(), generation)?;
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
        let after = self.store.get(&GetStateRequest::new(req.id().clone()))?;
        Ok((stopped, Some(Generation::of(&after))))
    }

    fn delete(
        &self,
        req: &DeleteRequest,
        generation: &Generation,
        _stage_end: std::time::Instant,
    ) -> Result<DeleteResponse, TraitError> {
        self.log("delete", req.id());
        self.gate(self.inject_delete)?;
        let rec = self.check_generation(req.id(), generation)?;
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
        std::time::Instant::now() + SHIM_DELETE_DEADLINE,
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

/// 注入なしの再実行用の予算。期限切れの挙動は初回の注入ケースで検証し、再実行は負荷で FAST（300ms）を超えて
/// 間欠的に Timeout になるのを避けるため十分に長くする（#4252 の CI の間欠失敗。REPAIR-5・REPAIR-12）。
const RERUN: ReclaimBudget = ReclaimBudget {
    stop: Duration::from_secs(5),
    remove: Duration::from_secs(5),
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
    type StageRow<'a> = (
        Option<Inject>,
        Option<Inject>,
        Vec<&'a str>,
        Vec<&'a str>,
        bool,
    );
    let rows: Vec<StageRow> = vec![
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

        let r2 = run(&inv, &base, None, None, &RERUN);
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
    // 内側の後始末の期限は外側の remove の待ちより短い（Kept の応答を組み立てる余裕。#4152）。
    assert!(ReclaimBudget::PRODUCTION.cleanup() < ReclaimBudget::PRODUCTION.remove);
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
            let store: Arc<dyn StateStore> = Arc::new(store);
            Arc::new(GuardedCore::new(
                store,
                budget.cleanup(),
                |pinned, cleanup| {
                    core_runtime_for(pinned)
                        .with_delete_deadline(cleanup)
                        .with_container_log_lock_wait(cleanup)
                        .with_cleanup_warning_sink(Arc::new(|_| {}))
                },
            ))
        },
        &budget,
        std::time::Instant::now() + SHIM_DELETE_DEADLINE,
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
        std::time::Instant::now() + SHIM_DELETE_DEADLINE,
    );
    assert!(again.unwrap().is_none());
}

/// 本番の窓口で `Generation` を使う補助: 記録を別の bundle で作り直す（世代が変わる）。
fn recreate_with_other_bundle(base: &Path, inv: &ShimInvocation, id: &str, other: &Path) {
    let root = entry(base, inv, id).parent().unwrap().to_path_buf();
    let state_root = fandhe_container_core::state_store::StateRoot::from_override(root).unwrap();
    let store = FileStateStore::open(state_root).unwrap();
    let rec = store.get(&GetStateRequest::new(cid(id))).unwrap();
    store
        .delete(&DeleteStateRequest::new(cid(id), rec.revision()))
        .unwrap();
    store
        .create(
            &fandhe_container_core::traits::CreateStateRequest::new(
                ContainerStatus::created(cid(id), None),
                other.to_path_buf(),
            )
            .unwrap(),
        )
        .unwrap();
}

/// SEC-1・CORE-1・#4152: 照合の後に同じ id が別の bundle で再作成されたとき、旧世代の stop・delete は新しい記録に触れず
/// `FAILED_PRECONDITION` で拒否し、新しい記録はそのまま残る。
#[test]
fn sec1_4152_stale_generation_does_not_touch_recreated_container() {
    let guard = test_root::test_root("shim", "r-gen");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let (_, store, matched) = delete_preflight_store_in(&inv, &base).unwrap();
    let DeleteRecordMatch::Recorded(rec) = matched else {
        panic!("expected recorded");
    };
    let stale = Generation::of(&rec);
    let store: Arc<dyn StateStore> = Arc::new(store.expect("store"));
    let other = guard.join("other-bundle");
    std::fs::create_dir_all(&other).unwrap();
    recreate_with_other_bundle(&base, &inv, "abc", &other);
    let rt = GuardedCore::new(Arc::clone(&store), Duration::from_secs(1), |p, _| {
        core_runtime_for(p)
    });
    let stop = StopRequest::new(cid("abc"), Duration::ZERO).unwrap();
    let e = rt.stop(&stop, &stale).expect_err("stale stop");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let e = rt
        .delete(
            &DeleteRequest::new(cid("abc")),
            &stale,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect_err("stale delete");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let now = store.get(&GetStateRequest::new(cid("abc"))).unwrap();
    assert_eq!(now.bundle(), other.as_path());
}

/// SEC-1・CORE-1・#4152: 同じ id・同じ bundle で再作成されても revision が変わるので、旧世代の stop・delete は拒否される。
#[test]
fn sec1_4152_stale_revision_rejected_for_same_bundle_recreation() {
    let guard = test_root::test_root("shim", "r-rev");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let (_, store, matched) = delete_preflight_store_in(&inv, &base).unwrap();
    let DeleteRecordMatch::Recorded(rec) = matched else {
        panic!("expected recorded");
    };
    let stale = Generation::of(&rec);
    let store: Arc<dyn StateStore> = Arc::new(store.expect("store"));
    recreate_with_other_bundle(&base, &inv, "abc", &bundle);
    let rt = GuardedCore::new(Arc::clone(&store), Duration::from_secs(1), |p, _| {
        core_runtime_for(p)
    });
    let stop = StopRequest::new(cid("abc"), Duration::ZERO).unwrap();
    let e = rt.stop(&stop, &stale).expect_err("stale stop");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let e = rt
        .delete(
            &DeleteRequest::new(cid("abc")),
            &stale,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect_err("stale delete");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let now = store.get(&GetStateRequest::new(cid("abc"))).unwrap();
    assert_eq!(now.bundle(), bundle.as_path());
    assert!(now.revision() > rec.revision());
}

/// REPAIR-5・#4152: 全体の絶対期限が尽きていれば、段を始める前に `DEADLINE_EXCEEDED` で終わり、実行層を作らない。
#[test]
fn repair5_4152_exhausted_deadline_fails_before_any_stage() {
    let guard = test_root::test_root("shim", "r-dl");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let r = delete_in(
        &inv,
        &base,
        |_| unreachable!("no runtime after the deadline"),
        &ReclaimBudget::PRODUCTION,
        std::time::Instant::now(),
    );
    assert_eq!(r.unwrap_err().code(), CriErrorCode::Timeout);
}

/// SEC-1・CORE-1・#4152: cgroup 未記録で照合時が Created（PID なし）の世代は、同じ id・同じ bundle で再作成された
/// 大きい revision の記録を受け入れない（core の get が固定の世代で拒否する）。
#[test]
fn sec1_4152_cgroupless_created_generation_rejects_recreated_record() {
    let guard = test_root::test_root("shim", "r-nocg");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let (_, store, matched) = delete_preflight_store_in(&inv, &base).unwrap();
    let DeleteRecordMatch::Recorded(rec) = matched else {
        panic!("expected recorded");
    };
    let generation = Generation::of(&rec);
    let store: Arc<dyn StateStore> = Arc::new(store.expect("store"));
    assert!(generation.accepts(&rec));
    recreate_with_other_bundle(&base, &inv, "abc", &bundle);
    let now = store.get(&GetStateRequest::new(cid("abc"))).unwrap();
    assert!(now.revision() > rec.revision());
    assert!(!generation.accepts(&now));
}

/// REPAIR-5・CRI-5・#4152: 内側の後始末期限は remove 段の実際の残りに収まり、外側より先に切れる。
#[test]
fn repair5_4152_cleanup_within_fits_remaining_limit() {
    let b = ReclaimBudget::PRODUCTION;
    assert_eq!(b.cleanup_within(Duration::from_millis(1500)), b.cleanup());
    assert_eq!(
        b.cleanup_within(Duration::from_millis(600)),
        Duration::from_millis(400)
    );
    assert!(b.cleanup_within(Duration::from_millis(30)) < Duration::from_millis(30));
    // 残りが 1ms 未満なら内側も 1ms 未満（下限で外側を超えない）。core の delete は始めない。
    for micros in [0u64, 1, 500, 1000, 1499] {
        let limit = Duration::from_micros(micros);
        assert!(b.cleanup_within(limit) <= limit);
        if micros < 1500 {
            assert!(b.cleanup_within(limit) < super::reclaim::MIN_CLEANUP);
        }
    }
    assert!(b.cleanup_within(Duration::from_millis(900)) <= Duration::from_millis(600));
}

/// `get` が遅い `StateStore`（状態ロックの待ちの偽物。`get` の都度 `delay` 眠る）。
struct SlowGet {
    inner: Arc<dyn StateStore>,
    delay: Duration,
}

impl StateStore for SlowGet {
    fn create(
        &self,
        r: &fandhe_container_core::traits::CreateStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        self.inner.create(r)
    }
    fn update(
        &self,
        r: &UpdateStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        self.inner.update(r)
    }
    fn get(
        &self,
        r: &GetStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        std::thread::sleep(self.delay);
        self.inner.get(r)
    }
    fn list(
        &self,
        r: &fandhe_container_core::traits::ListStateRequest,
    ) -> Result<fandhe_container_core::traits::StateList, TraitError> {
        self.inner.list(r)
    }
    fn delete(
        &self,
        r: &DeleteStateRequest,
    ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError> {
        self.inner.delete(r)
    }
    fn host_state_root(&self) -> Option<&Path> {
        self.inner.host_state_root()
    }
}

/// 照合済みの記録と、`get` が `delay` かかる store を用意する。
fn slow_setup(
    name: &str,
    delay: Duration,
) -> (
    test_root::TestRoot,
    Arc<dyn StateStore>,
    Arc<dyn StateStore>,
    Generation,
) {
    let guard = test_root::test_root("shim", name);
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &bundle);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let (_, store, matched) = delete_preflight_store_in(&inv, &base).unwrap();
    let DeleteRecordMatch::Recorded(rec) = matched else {
        panic!("expected recorded");
    };
    let fast: Arc<dyn StateStore> = Arc::new(store.expect("store"));
    let slow: Arc<dyn StateStore> = Arc::new(SlowGet {
        inner: Arc::clone(&fast),
        delay,
    });
    (guard, fast, slow, Generation::of(&rec))
}

/// REPAIR-5・REPAIR-4・#4152: 世代確認が段の期限を使い切ったら、core を作らず記録に触れずに `Timeout`（記録を消してから止まらない）。
#[test]
fn repair5_4152_slow_generation_check_exhausting_stage_keeps_record() {
    let (_g, fast, slow, generation) = slow_setup("r-slow1", Duration::from_millis(400));
    let rt = GuardedCore::new(slow, Duration::from_secs(1), |_, _| {
        unreachable!("core must not be built after the stage is exhausted")
    });
    let t0 = std::time::Instant::now();
    let e = rt
        .delete(
            &DeleteRequest::new(cid("abc")),
            &generation,
            t0 + Duration::from_millis(300),
        )
        .expect_err("exhausted");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(fast.get(&GetStateRequest::new(cid("abc"))).is_ok());
}

/// REPAIR-5・#4152: 世代確認が段の期限の一部を使ったら、core へ渡す後始末の期限は事前の値ではなく残りの 2/3 以下に決め直される。
#[test]
fn repair5_4152_slow_generation_check_shrinks_cleanup_budget() {
    let (_g, _fast, slow, generation) = slow_setup("r-slow2", Duration::from_millis(150));
    let seen = Arc::new(Mutex::new(None));
    let s2 = Arc::clone(&seen);
    let rt = GuardedCore::new(slow, Duration::from_secs(1), move |p, c| {
        *s2.lock().unwrap() = Some(c);
        core_runtime_for(p)
    });
    let t0 = std::time::Instant::now();
    let _ = rt.delete(
        &DeleteRequest::new(cid("abc")),
        &generation,
        t0 + Duration::from_millis(400),
    );
    // 残りは 400 - 150 = 250ms 以下。2/3 は 167ms 以下（既定の 1 秒ではない）。
    let c = seen.lock().unwrap().expect("core built");
    assert!(
        c <= Duration::from_millis(167) && c >= Duration::from_millis(50),
        "{c:?}"
    );
}

/// REPAIR-5・REPAIR-4・#4152・#4239: core の中の状態の読み取りが後始末の期限（300ms）を使い切ったら、core が記録を消す直前の期限確認で
/// `Timeout` にし、記録は残る（再試行できる）。期限は `GuardedCore` が絶対期限として core へ渡している。
#[test]
fn repair5_4152_slow_read_inside_core_keeps_record_instead_of_deleting() {
    let (_g, fast, slow, generation) = slow_setup("r-slow3", Duration::from_millis(350));
    let rt = GuardedCore::new(slow, Duration::from_millis(300), |p, c| {
        core_runtime_for(p)
            .with_delete_deadline(c)
            .with_container_log_lock_wait(c)
            .with_cleanup_warning_sink(Arc::new(|_| {}))
    });
    // 世代確認で 350ms、残り 1650ms → 後始末 300ms。core の最初の `get` の 350ms で期限を過ぎる。
    let e = rt
        .delete(
            &DeleteRequest::new(cid("abc")),
            &generation,
            std::time::Instant::now() + Duration::from_millis(2000),
        )
        .expect_err("deadline passed");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(fast.get(&GetStateRequest::new(cid("abc"))).is_ok());
    // 記録が残っているので、期限に余裕のある再試行は成功する（再実行が成り立つ）。
    let again = GuardedCore::new(Arc::clone(&fast), Duration::from_secs(1), |p, _| {
        core_runtime_for(p)
    });
    again
        .delete(
            &DeleteRequest::new(cid("abc")),
            &generation,
            std::time::Instant::now() + Duration::from_secs(3),
        )
        .expect("retry succeeds");
    assert!(fast.get(&GetStateRequest::new(cid("abc"))).is_err());
}

/// 呼ばれた `delete` / `delete_until` を数える `StateStore`。
struct CountDelete {
    inner: Arc<dyn StateStore>,
    plain: Arc<Mutex<u32>>,
    until: Arc<Mutex<Vec<std::time::Instant>>>,
}

impl StateStore for CountDelete {
    fn create(
        &self,
        r: &fandhe_container_core::traits::CreateStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        self.inner.create(r)
    }
    fn update(
        &self,
        r: &UpdateStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        self.inner.update(r)
    }
    fn get(
        &self,
        r: &GetStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
        self.inner.get(r)
    }
    fn list(
        &self,
        r: &fandhe_container_core::traits::ListStateRequest,
    ) -> Result<fandhe_container_core::traits::StateList, TraitError> {
        self.inner.list(r)
    }
    fn delete(
        &self,
        r: &DeleteStateRequest,
    ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError> {
        *self.plain.lock().unwrap() += 1;
        self.inner.delete(r)
    }
    fn delete_until(
        &self,
        r: &DeleteStateRequest,
        deadline: std::time::Instant,
    ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError> {
        self.until.lock().unwrap().push(deadline);
        self.inner.delete(r)
    }
    fn host_state_root(&self) -> Option<&Path> {
        self.inner.host_state_root()
    }
}

/// REPAIR-5・#4152・#4239: 固定つきの store は core の絶対期限を落とさず `delete_until` で中の store へ渡す（`delete` へ縮退しない）。
/// 渡る期限は呼び出し時点から後始末の予算（ここでは 300ms）以内。
#[test]
fn repair5_4152_pinned_store_forwards_deadline_to_delete_until() {
    let (_g, fast, _slow, generation) = slow_setup("r-fwd", Duration::ZERO);
    let (plain, until) = (Arc::new(Mutex::new(0)), Arc::new(Mutex::new(Vec::new())));
    let counting: Arc<dyn StateStore> = Arc::new(CountDelete {
        inner: fast,
        plain: Arc::clone(&plain),
        until: Arc::clone(&until),
    });
    let rt = GuardedCore::new(counting, Duration::from_millis(300), |p, c| {
        core_runtime_for(p)
            .with_delete_deadline(c)
            .with_cleanup_warning_sink(Arc::new(|_| {}))
    });
    let t0 = std::time::Instant::now();
    rt.delete(
        &DeleteRequest::new(cid("abc")),
        &generation,
        t0 + Duration::from_secs(5),
    )
    .expect("delete");
    assert_eq!(*plain.lock().unwrap(), 0);
    let seen = until.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0] <= t0 + Duration::from_millis(300) + Duration::from_millis(50));
    assert!(seen[0] > t0);
}
