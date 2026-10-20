//! healthcheck の内部状態と外部公開状態の同期の結合試験（TASK-161.4・#497・SUP-4・REPAIR-12）。
//!
//! PoC-17（supervisor-model）では、監視スレッドが healthy / unhealthy を判定しても `state.json` へ
//! 書かず、STACK-2 の `depends_on`（healthy 条件）が永遠に待つ不具合が出た。その再発を防ぐため、
//! 次の 2 つを tick ごとに具体値で突き合わせる。
//!
//! - 内部状態: 集約器が決めた `health`（テスト側の影の `HealthAggregator` と判定閉包の記録）、
//!   tick が報告するレコードと連続失敗数、ループ終了後の `SupervisedState::record()`。
//! - 外部公開状態: 監視側とは別に持ったストアのハンドルで `get()` した値（`depends_on` の読み手の役）。
//!
//! 偽の時計とメモリ上のストアは 3 OS で、実物の `FileStateStore`（`state.json`）を 2 回開く試験は
//! Linux 限定で動く。実時間の待ちは無く、root 不要で既定のテスト集合で動く。

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
    ErrorCode, GetStateRequest, HealthStatus, ListStateRequest, StateList, StateRecord,
    StateRevision, StateStore, SupervisionState, TraitError, UpdateStateRequest,
};
use fandhe_container_supervisor::health::{
    Demotion, HealthProbe, ProbeRunner, probe_aggregate_and_record, record_starting,
};
use fandhe_container_supervisor::healthcheck::{
    HealthAggregator, HealthcheckClock, HealthcheckDefinition, HealthcheckSchedule, RawHealthcheck,
    run_periodic,
};
use fandhe_container_supervisor::run::{MonitorEvent, MonitorObserver, StopToken};
use fandhe_container_supervisor::state::SupervisedState;

const ST: Option<HealthStatus> = Some(HealthStatus::Starting);
const HE: Option<HealthStatus> = Some(HealthStatus::Healthy);
const UN: Option<HealthStatus> = Some(HealthStatus::Unhealthy);

type Probed = Result<HealthStatus, TraitError>;
/// 外部の読み手: 監視側とは別のハンドルで読んだ `(health, revision)`。
type Reader = Arc<dyn Fn() -> (Option<HealthStatus>, u64) + Send + Sync>;

struct MemStore(Mutex<StateRecord>);

impl StateStore for MemStore {
    fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
    }
    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let mut g = self.0.lock().unwrap();
        if g.revision() != req.expected_revision() {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
        }
        let sup = req.supervision().unwrap_or_else(|| g.supervision());
        let next = StateRecord::new(
            req.status().clone(),
            g.bundle().to_path_buf(),
            StateRevision::from_raw(g.revision().value() + 1),
        )
        .unwrap()
        .with_supervision(sup);
        *g = next.clone();
        Ok(next)
    }
    fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
    }
    fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
    }
}

struct Proc;
impl LaunchedProcess for Proc {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(42).unwrap()
    }
    fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
        Ok(None)
    }
    fn terminate(&self, _: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct NoObs;
impl MonitorObserver for NoObs {
    fn observe(&self, _: &MonitorEvent) {}
}

/// `sleep_until` でだけ進む偽の時計。
struct FakeClock(Mutex<Instant>);

impl HealthcheckClock for FakeClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
    fn sleep_until(&self, deadline: Instant, stop: &StopToken) -> bool {
        if stop.is_stop_requested() {
            return false;
        }
        let mut now = self.0.lock().unwrap();
        if deadline > *now {
            *now = deadline;
        }
        true
    }
}

/// 用意した結果を順に返し、probe の入口で外部の読み手の値を記録する probe。
struct Spy {
    script: Mutex<std::collections::VecDeque<Probed>>,
    reader: Reader,
    entry: Arc<Mutex<Vec<Option<HealthStatus>>>>,
}

impl HealthProbe for Spy {
    fn probe(&self, _: Duration) -> Probed {
        self.entry.lock().unwrap().push((self.reader)().0);
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(HealthStatus::Healthy))
    }
}

fn u() -> Probed {
    Ok(HealthStatus::Unhealthy)
}
fn h() -> Probed {
    Ok(HealthStatus::Healthy)
}

fn schedule(start_period: &str, retries: i64) -> HealthcheckSchedule {
    let def = HealthcheckDefinition::parse(&RawHealthcheck {
        command: vec!["pg_isready".into()],
        interval: Some("5s".into()),
        timeout: Some("2s".into()),
        start_period: Some(start_period.into()),
        retries: Some(retries),
    })
    .unwrap();
    HealthcheckSchedule::from_definition(&def).unwrap()
}

fn me() -> NonZeroU32 {
    NonZeroU32::new(std::process::id()).unwrap()
}

fn cid() -> ContainerId {
    ContainerId::new("c1").unwrap()
}

/// 1 回の周期実行で、内部の値と外部の値を tick ごとに並べた記録。
#[derive(Debug)]
struct SyncLog {
    /// probe の入口で外部の読み手が見た health（tick ごと）。
    entry: Vec<Option<HealthStatus>>,
    /// tick 後に外部の読み手が見た health。
    public: Vec<Option<HealthStatus>>,
    /// tick 後に外部の読み手が見た revision。
    public_rev: Vec<u64>,
    /// 影の集約器が決めた health（内部の判断）。
    internal: Vec<HealthStatus>,
    /// tick が報告した連続失敗数。
    fails: Vec<u32>,
    /// 影の集約器の連続失敗数。
    shadow_fails: Vec<u32>,
    /// `Err(ProbeFailure)` の tick の (エラーコード, 降格の結果)。`Ok` の tick は `None`。
    errs: Vec<Option<(ErrorCode, Demotion)>>,
    /// 終了後の `SupervisedState::record()` の (health, revision)。
    final_record: (Option<HealthStatus>, u64),
}

/// `run_periodic` を回し、tick ごとに内部の値と外部の値を照合しながら記録する。
///
/// 照合（どの tick でも成り立つ不変条件）: 公開値 == 影の集約器の判断、tick の連続失敗数 == 影の数、
/// probe の入口の公開値 == 前の tick の公開値（1 回目は `Starting`）、`Ok` の tick のレコード == 公開値、
/// 終了後のレコード == 最後の公開値。
fn drive_sync(
    mut st: SupervisedState,
    reader: Reader,
    sched: &HealthcheckSchedule,
    script: Vec<Probed>,
) -> SyncLog {
    let n = script.len() as u64;
    let entry = Arc::new(Mutex::new(Vec::new()));
    let spy = Spy {
        script: Mutex::new(script.clone().into()),
        reader: reader.clone(),
        entry: entry.clone(),
    };
    let runner = ProbeRunner::new(Arc::new(spy));
    let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
    let stop = StopToken::new();
    let mut shadow = HealthAggregator::from_schedule(sched);
    let mut log = SyncLog {
        entry: Vec::new(),
        public: Vec::new(),
        public_rev: Vec::new(),
        internal: Vec::new(),
        fails: Vec::new(),
        shadow_fails: Vec::new(),
        errs: Vec::new(),
        final_record: (None, 0),
    };
    let mut prev_public = ST;
    run_periodic(
        sched,
        &mut st,
        &Proc,
        &runner,
        clock.as_ref(),
        &stop,
        &NoObs,
        &mut |t| {
            let i = (t.index - 1) as usize;
            let (public, rev) = reader();
            let decided = shadow.observe(&script[i], t.elapsed, prev_public);
            match &t.result {
                Ok(rec) => {
                    assert_eq!(rec.health(), public, "tick {}: record vs public", t.index);
                    assert_eq!(rec.revision().value(), rev, "tick {}: revision", t.index);
                    log.errs.push(None);
                }
                Err(f) => log
                    .errs
                    .push(Some((f.error().code(), f.demotion().clone()))),
            }
            assert_eq!(
                public,
                Some(decided),
                "tick {}: internal vs public",
                t.index
            );
            assert_eq!(
                t.consecutive_failures,
                shadow.consecutive_failures(),
                "tick {}: failure count",
                t.index
            );
            log.public.push(public);
            log.public_rev.push(rev);
            log.internal.push(decided);
            log.fails.push(t.consecutive_failures);
            log.shadow_fails.push(shadow.consecutive_failures());
            prev_public = public;
            if t.index >= n || t.index >= 64 {
                stop.request_stop();
            }
        },
    );
    log.entry = entry.lock().unwrap().clone();
    let (last_public, last_rev) = reader();
    log.final_record = (st.record().health(), st.record().revision().value());
    assert_eq!(log.final_record, (last_public, last_rev), "final record");
    assert_eq!(log.entry.len(), log.public.len(), "probe count");
    let mut expect_entry = vec![ST];
    expect_entry.extend(log.public.iter().take(log.public.len().saturating_sub(1)));
    assert_eq!(log.entry, expect_entry, "probe-entry lag");
    log
}

/// メモリストアの SupervisedState と、別ハンドルの読み手を作る。
fn mem_setup(init: Option<HealthStatus>) -> (SupervisedState, Reader) {
    let rec = StateRecord::new(
        ContainerStatus::running(cid(), NonZeroU32::new(42)),
        std::env::temp_dir().join("healthcheck-sync-it"),
        StateRevision::from_raw(1),
    )
    .unwrap()
    .with_supervision(SupervisionState::new(Some(me()), init, 0));
    let mem = Arc::new(MemStore(Mutex::new(rec)));
    let store: Arc<dyn StateStore> = mem.clone();
    let st = SupervisedState::attach(store, cid()).unwrap();
    let reader: Reader = Arc::new(move || {
        let g = mem.0.lock().unwrap();
        (g.health(), g.revision().value())
    });
    (st, reader)
}

fn mem_drive(init: Option<HealthStatus>, sched: &HealthcheckSchedule, s: Vec<Probed>) -> SyncLog {
    let (st, reader) = mem_setup(init);
    drive_sync(st, reader, sched, s)
}

/// SUP-4・TASK-161.4: 前の process の Healthy が残っていても、最初の probe の入口では Starting が公開済み。
#[test]
fn sup4_task161_4_starting_published_before_first_probe() {
    let log = mem_drive(HE, &schedule("0s", 3), vec![h()]);
    assert_eq!(log.entry, vec![ST]);
    assert_eq!(log.public, vec![HE]);
}

/// SUP-4・TASK-161.4: start_period 中の失敗は数えず Starting を公開し続け、成功で Healthy。
#[test]
fn sup4_task161_4_start_period_hold_then_healthy() {
    let log = mem_drive(None, &schedule("12s", 2), vec![u(), u(), h()]);
    assert_eq!(log.public, vec![ST, ST, HE]);
    assert_eq!(
        log.internal,
        vec![
            HealthStatus::Starting,
            HealthStatus::Starting,
            HealthStatus::Healthy
        ]
    );
    assert_eq!(log.fails, vec![0, 0, 0]);
}

/// SUP-4・TASK-161.4: 書き込みを省く tick（値が変わらない）でも、公開値は内部の判断と一致する。
#[test]
fn sup4_task161_4_healthy_held_while_write_skipped() {
    let log = mem_drive(None, &schedule("0s", 3), vec![h(), u(), u()]);
    assert_eq!(log.public, vec![HE, HE, HE]);
    // 初期 1 → Starting で 2 → Healthy で 3 → 以降は書かない。
    assert_eq!(log.public_rev, vec![3, 3, 3]);
    assert_eq!(log.fails, vec![0, 1, 2]);
}

/// SUP-4・TASK-161.4: retries 到達で Unhealthy が公開され、成功で Healthy へ戻る。
#[test]
fn sup4_task161_4_unhealthy_at_retries_and_recovery() {
    let log = mem_drive(None, &schedule("0s", 3), vec![h(), u(), u(), u(), h()]);
    assert_eq!(log.public, vec![HE, HE, HE, UN, HE]);
    assert_eq!(log.fails, vec![0, 1, 2, 3, 0]);
    assert_eq!(log.shadow_fails, log.fails);
}

/// SUP-4・TASK-161.4: probe が Err でも、tick が Err(ProbeFailure) を返しても、集約後の値は公開される。
#[test]
fn sup4_task161_4_probe_err_still_published() {
    let t = || Err(TraitError::new(ErrorCode::Timeout, "t"));
    let i = || Err(TraitError::new(ErrorCode::Internal, "i"));
    let log = mem_drive(None, &schedule("0s", 2), vec![t(), i()]);
    assert_eq!(log.public, vec![ST, UN]);
    assert_eq!(
        log.errs,
        vec![
            Some((ErrorCode::Timeout, Demotion::NotNeeded)),
            Some((ErrorCode::Internal, Demotion::NotNeeded)),
        ]
    );
    // Healthy から Err で落ちる場合は降格が適用され、公開値も Unhealthy。
    let log = mem_drive(None, &schedule("0s", 1), vec![h(), t()]);
    assert_eq!(log.public, vec![HE, UN]);
    assert_eq!(
        log.errs,
        vec![None, Some((ErrorCode::Timeout, Demotion::Applied))]
    );
}

/// SUP-4・TASK-161.4: 成功・失敗が混ざる 6 tick で、probe の入口の公開値が常に前の tick の判断と一致する。
#[test]
fn sup4_task161_4_no_lag_at_probe_entry() {
    let log = mem_drive(None, &schedule("0s", 2), vec![h(), u(), u(), h(), u(), u()]);
    assert_eq!(log.public, vec![HE, HE, UN, HE, HE, UN]);
    assert_eq!(log.entry, vec![ST, HE, HE, UN, HE, HE]);
}

/// SUP-4・TASK-161.4: 停止後の SupervisedState の記録が、外部の読み手の値と一致する。
#[test]
fn sup4_task161_4_final_record_matches_after_stop() {
    let log = mem_drive(None, &schedule("0s", 2), vec![u(), u()]);
    assert_eq!(log.public, vec![ST, UN]);
    assert_eq!(log.final_record.0, UN);
    assert_eq!(Some(log.final_record.1), log.public_rev.last().copied());
}

/// SUP-4・TASK-161.4: 判定閉包の返した値の列が、probe 呼び出しごとに外部の読み手が見る値の列と同じ
/// （決めたのに書いていない、を直接捉える）。
#[test]
fn sup4_task161_4_decider_log_matches_store() {
    let sched = schedule("0s", 2);
    let (mut st, reader) = mem_setup(None);
    let script: Vec<Probed> = vec![u(), u(), h(), u()];
    let entry = Arc::new(Mutex::new(Vec::new()));
    let runner = ProbeRunner::new(Arc::new(Spy {
        script: Mutex::new(script.clone().into()),
        reader: reader.clone(),
        entry,
    }));
    record_starting(&mut st, &Proc, &runner, &NoObs).unwrap();
    assert_eq!(reader().0, ST);
    let mut agg = HealthAggregator::from_schedule(&sched);
    let mut decided = Vec::new();
    let mut calls = 0u32;
    let mut seen = Vec::new();
    for r in &script {
        let out = probe_aggregate_and_record(
            &mut st,
            &Proc,
            &runner,
            Duration::from_secs(2),
            &NoObs,
            &mut |res, cur| {
                calls += 1;
                let d = agg.observe(res, Duration::from_secs(100), cur);
                decided.push(Some(d));
                d
            },
        );
        assert_eq!(out.is_ok(), r.is_ok());
        let (public, rev) = reader();
        if let Ok(rec) = &out {
            assert_eq!(rec.revision().value(), rev);
        }
        seen.push(public);
    }
    assert_eq!(calls, 4);
    assert_eq!(decided, vec![ST, UN, HE, HE]);
    assert_eq!(seen, decided);
}

#[cfg(target_os = "linux")]
mod file_backed {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use fandhe_container_supervisor::state::open_default_store;

    use super::*;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（0700。drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fandhe-sup-sync-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(root: &Path) -> Arc<dyn StateStore> {
        open_default_store(Some(root.to_path_buf())).unwrap()
    }

    /// 実物の `state.json` を作って Running にし、監視側ハンドルと別に開いた読み手を返す。
    fn file_setup(root: &Path, init: Option<HealthStatus>) -> (SupervisedState, Reader) {
        let sup_store = open(root);
        let req = CreateStateRequest::new(
            ContainerStatus::created(cid(), None),
            std::env::temp_dir().join("fandhe-sup-sync-bundle"),
        )
        .unwrap();
        sup_store.create(&req).unwrap();
        let mut st = SupervisedState::attach(sup_store, cid()).unwrap();
        st.write(
            ContainerStatus::running(cid(), NonZeroU32::new(42)),
            SupervisionState::new(Some(me()), init, 0),
        )
        .unwrap();
        let reader_store = open(root);
        let reader: Reader = Arc::new(move || {
            let r = reader_store.get(&GetStateRequest::new(cid())).unwrap();
            (r.health(), r.revision().value())
        });
        (st, reader)
    }

    fn file_drive(init: Option<HealthStatus>, sched: &HealthcheckSchedule, s: Vec<Probed>) {
        let t = TmpDir::new();
        let (st, reader) = file_setup(t.path(), init);
        let log = drive_sync(st, reader, sched, s);
        // 開き直したハンドルから読んだ値も、最後の内部の判断と一致する。
        let reopened = SupervisedState::attach(open(t.path()), cid()).unwrap();
        assert_eq!(reopened.record().health(), log.internal.last().copied());
    }

    /// SUP-4・TASK-161.4: state.json でも、古い Healthy は probe の入口までに Starting へ戻る。
    #[test]
    fn sup4_task161_4_file_starting_published_before_first_probe() {
        file_drive(HE, &schedule("0s", 3), vec![h()]);
    }

    /// SUP-4・TASK-161.4: state.json でも、retries 到達と回復が内部の判断と一致する。
    #[test]
    fn sup4_task161_4_file_unhealthy_at_retries_and_recovery() {
        file_drive(None, &schedule("0s", 3), vec![h(), u(), u(), u(), h()]);
    }

    /// SUP-4・TASK-161.4: state.json でも、probe の Err が公開値に反映される。
    #[test]
    fn sup4_task161_4_file_probe_err_still_published() {
        let t = || Err(TraitError::new(ErrorCode::Timeout, "t"));
        file_drive(None, &schedule("0s", 2), vec![t(), t()]);
    }

    /// SUP-4・TASK-161.4: state.json でも、混在列で probe の入口の遅れが無く、停止後の記録が一致する。
    #[test]
    fn sup4_task161_4_file_no_lag_and_final_record() {
        file_drive(None, &schedule("0s", 2), vec![h(), u(), u(), h(), u(), u()]);
    }
}
