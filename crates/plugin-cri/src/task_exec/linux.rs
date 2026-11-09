//! `TaskExecLauncher` の Linux 実装（stream-exec helper 経由）。契約と残余は親モジュール `task_exec` の doc を参照
//! （CRI-5・CRI-1・SEC-1・REPAIR-3・REPAIR-5・#4148）。

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{ExecCgroupName, ExecCgroupPresence, exec_child_cgroup_presence};
use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::{
    CgroupPlacement, ContainerId, ContainerInstance, ContainerState, ErrorCode, GetStateRequest,
    Signal, StateStore,
};
use fandhe_container_cri::adapter::instance_matches;
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::{
    ExecId, ExecProcessSpec, ExecProcessStatus, TaskExecLauncher, TaskExecProcess,
};
use fandhe_container_cri::streaming::exec::MSG_EXEC_INSTANCE_CHANGED;
use fandhe_container_supervisor::stream_exec::channel::{
    HelperMessage, StdioSend, recv_from_helper, send_signal, send_stdio_handover,
};
use fandhe_container_supervisor::stream_exec::helper::StreamExecArgs;
use fandhe_container_supervisor::stream_exec::wire::{
    ExecSignal, SignalAckCode, StdioMask, StreamExecOutcome,
};

use crate::streaming::exec_launcher::{
    HANDOVER_BUDGET, HelperGuard, HelperSpawner, ProductionHelperSpawner, RESULT_GRACE,
    SESSION_TIMEOUT, STARTED_BUDGET, Shared, SpawnedHelper, channel_error, cri_error, diagnostics,
    map_outcome,
};

/// 待ちの刻み。取り消しと期限をこの刻みで確かめる（REPAIR-5）。
const WAIT_SLICE: Duration = Duration::from_millis(10);

const UNCONFIRMED: &str = "exec termination is not confirmed";

/// 消滅の確認の結果（[`ExecExtinctionProbe::confirm`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtinctionOutcome {
    /// exec のプロセスと exec 子 cgroup の消滅を確認した。
    Confirmed,
    /// 回収に失敗したことを確認した。
    Failed,
    /// 確認の手段が無い、または未確定。
    Unknown,
}

/// 消滅を確かめる exec の材料（launch の時点で固定する。#4221）。
///
/// `placement` は launch が読んだ状態記録の cgroup 配置。helper は同じ記録を読み pid の一致を確かめてから exec 子 cgroup を作る
/// ため、同じ世代の配置になる。確認の時点で記録を読み直すと restart で別の世代の経路を見て誤って「不在」と判定しうるので、
/// ここへ固定する。`cgroup` は helper が `Started` で通知した exec 子 cgroup の名前（検証済み）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExecExtinctionTarget {
    /// exec の対象コンテナ。
    pub container: ContainerId,
    /// 起動時点の記録の cgroup 配置（記録に無ければ `None`。確認の材料が無いので `Unknown` になる）。
    pub placement: Option<CgroupPlacement>,
    /// helper が通知した exec 子 cgroup の名前。
    pub cgroup: ExecCgroupName,
}

/// kill・期限切れ・失敗の後に exec の消滅を確かめる差し込み口（CRI-5・SEC-1・REPAIR-3）。
///
/// `Confirmed` のときだけハンドルは `Exited` へ進む。それ以外は未確認のまま `Err` を保つ（fail-closed）。
pub trait ExecExtinctionProbe: Send + Sync + 'static {
    /// `target` の exec の消滅を確かめる。有界でブロッキングしてよい。
    fn confirm(&self, target: &ExecExtinctionTarget) -> ExtinctionOutcome;
}

/// 本番の probe（#4221・CRI-5・SEC-1・REPAIR-3）。exec 子 cgroup のディレクトリが **無いこと** を読み取り専用で確かめる。
///
/// cgroup v2 のディレクトリはプロセスが残る間 `rmdir` できない。回収する supervisor の `ExecGuardPool`（helper の切断時）と
/// helper 自身（正常終了・期限切れ）はどちらも `cgroup.kill` → 空の待ち → `rmdir` の順に進むため、通知された名前のディレクトリの
/// 不在は、そこにいたプロセス全体の消滅の証拠になる。**kill も rmdir も書かない**: 名前は helper の pid と連番で作られ、
/// helper の回収後に別の helper が同じ名前を作りうるため、ここで kill すると別の exec を止めかねない。読むだけなら再利用で
/// 起きるのは「まだある」と見える安全側の誤りだけで、`Unknown` のまま purge で回収される。
///
/// 判定の写像: 子が無い・コンテナ cgroup 自体が無い（親は子を持ったまま消えない）→ `Confirmed`、子がある・照合に失敗した・
/// cgroup ルートを開けない・記録に配置が無い → `Unknown`。
#[derive(Debug, Default, Clone, Copy)]
pub struct CgroupExtinctionProbe;

impl CgroupExtinctionProbe {
    /// core の読み取り専用の確認結果を消滅確認の結果へ写す（`Err` と将来の未知の値は `Unknown`。fail-closed）。
    pub(crate) fn map_presence(
        presence: Result<ExecCgroupPresence, fandhe_container_core::exec::ExecError>,
    ) -> ExtinctionOutcome {
        match presence {
            Ok(ExecCgroupPresence::Absent | ExecCgroupPresence::ContainerCgroupAbsent) => {
                ExtinctionOutcome::Confirmed
            }
            _ => ExtinctionOutcome::Unknown,
        }
    }
}

impl ExecExtinctionProbe for CgroupExtinctionProbe {
    fn confirm(&self, target: &ExecExtinctionTarget) -> ExtinctionOutcome {
        let Some(placement) = target.placement.as_ref() else {
            return ExtinctionOutcome::Unknown;
        };
        Self::map_presence(exec_child_cgroup_presence(
            &target.container,
            placement,
            &target.cgroup,
        ))
    }
}

/// 待ちの期限（本番は既定値。試験が短い値を差す）。
#[derive(Debug, Clone, Copy)]
pub struct ExecBudgets {
    /// stdio の fd を helper へ渡す期限。
    pub handover: Duration,
    /// `Started` を待つ上限。
    pub started: Duration,
    /// helper の `--timeout-ms`（exec の保持の最長）。
    pub session: Duration,
    /// `Result` を待つ余裕（session に足す）。
    pub result_grace: Duration,
    /// 未確認になってから、Wait が消滅の確認を待つ猶予（supervisor の exec 子 cgroup の回収の上限に余裕を足した値。#4221）。
    /// 過ぎても確認できなければ従来どおり `UNAVAILABLE` を返す。
    pub extinction_grace: Duration,
    /// SIGKILL 以外のシグナルの `SignalAck` を待つ上限（helper の保留の猶予 2 秒より長くする。#4282・REPAIR-5）。
    /// 過ぎたら `DEADLINE_EXCEEDED`。
    pub signal_ack: Duration,
    /// `Started` の後、`Spawned`（コマンドのホスト側 pid）を launch が待つ上限（#4318・CRI-5・REPAIR-5）。
    /// 過ぎても届かなければ pid 不明のまま launch は成功する（pid は表示用）。
    pub spawned: Duration,
}

/// `Spawned` を launch が待つ既定の上限。helper が worker から pid と pidfd を待つ猶予（`SIGNAL_START_GRACE` 2 秒）に揃える。
/// 通常は fork からの待ちの刻み（数十〜100 ms）で届く。`start_exec` はコンテナ単位のゲートを持ったまま launch を呼ぶため、
/// worker が詰まった異常時は最悪この時間だけ同じコンテナの操作を待たせる（#4318）。
const SPAWNED_BUDGET: Duration = Duration::from_secs(2);

/// 未確認になってから Wait が消滅の確認を待つ既定の猶予（supervisor の `REAP_BUDGET` と同じ 10 秒）。
const EXTINCTION_GRACE: Duration = Duration::from_secs(10);

/// `Signal` frame の送信に割り当てる上限（#4282・REPAIR-5）。
const SIGNAL_SEND_BUDGET: Duration = Duration::from_secs(2);

/// `SignalAck` を待つ既定の上限（helper の保留の猶予〔2 秒〕に刻みと送信の余裕を足した値。#4282・REPAIR-5）。
const SIGNAL_ACK_BUDGET: Duration = Duration::from_secs(5);

impl Default for ExecBudgets {
    fn default() -> Self {
        Self {
            handover: HANDOVER_BUDGET,
            started: STARTED_BUDGET,
            session: SESSION_TIMEOUT,
            result_grace: RESULT_GRACE,
            extinction_grace: EXTINCTION_GRACE,
            signal_ack: SIGNAL_ACK_BUDGET,
            spawned: SPAWNED_BUDGET,
        }
    }
}

enum Phase {
    Running,
    Exited(Option<i32>),
    /// 消滅を確認できていない。`since` は遷移した時刻（Wait の確認の猶予の起点。#4221）。
    Unconfirmed {
        error: CriError,
        since: Instant,
    },
}

impl Phase {
    fn unconfirmed(error: CriError) -> Self {
        Self::Unconfirmed {
            error,
            since: Instant::now(),
        }
    }
}

/// 未応答の要求の保持上限（これ以上は新しい要求を送らず `UNAVAILABLE`。無制限の蓄積を防ぐ。REPAIR-5）。
const MAX_PENDING_SIGNALS: usize = 16;

/// SIGKILL 以外のシグナルの `SignalAck` の受け渡し口（待っている要求 1 件と、監視スレッドが受けた結果。#4282）。
#[derive(Default)]
struct AckSlot {
    /// helper へ送って ack をまだ受けていない要求（送信順。helper は frame の順に 1 件ずつ ack する）。
    /// 各要素は (シグナル, 待ち手が諦めた〔期限切れ・結果先着〕か)。諦めていない要求は高々 1 件で、必ず末尾（要求は排他）。
    /// 諦めた要求の遅れた ack は黙って消費し、停止も新要求の成功扱いもしない（REPAIR-5・#4282）。
    pending: VecDeque<(ExecSignal, bool)>,
    /// 受けた結果（待っている要求のものだけ）。
    received: Option<SignalAckCode>,
}

/// `Inner::wait_spawned` が戻った理由。数えるのは `Expired` だけ（#4379・REPAIR-4）。
enum SpawnedWait {
    /// pid を記録した。
    Recorded,
    /// pid 未記録のまま実行が終わった（`Spawned` 無しの `Result`・違反・切断など）。予算の不足ではないので数えない。
    Settled,
    /// 期限まで pid が届かず、実行も続いている。
    Expired,
}

/// 登録時のインスタンスと現在の記録が食い違い、helper の起動前に拒否した回の操作名（#4379・CRI-5・REPAIR-4）。
/// shim の `TaskService` から見て、`purge_mismatched` の後の読み取りの窓で作り直された回だけがここに届く。
const OP_EXEC_INSTANCE_CHANGED: &str = "shim_exec_instance_changed";
/// `Started` の後、`Spawned` が `ExecBudgets::spawned` 内に届かず pid 0 のまま返した回の操作名（#4379・CRI-5・REPAIR-4）。
const OP_EXEC_PID_UNREPORTED: &str = "shim_exec_pid_unreported";

/// 発生時の構造化行の送り先（本番は `telemetry::stderr_sink` の `submit`。有界で満杯なら捨て、exec を待たせない）。
type EventEmit = Arc<dyn Fn(String) + Send + Sync>;

fn default_event_emit() -> EventEmit {
    Arc::new(|line| {
        let _ = crate::telemetry::stderr_sink().submit(line);
    })
}

/// 発生時の 1 行（固定の操作名と経過ミリ秒のみ。ID・argv・パスは載せない。serve 開始後も外から観測できる。#4379・REPAIR-4）。
/// stderr は JSON Lines のため、近傍の occurrence ログと同じ `{"event":"<操作名>","elapsed_ms":N}` の JSON 1 行にする
/// （操作名は本ファイルの固定 ASCII 定数のみで、エスケープは要らない）。
fn event_line(name: &str, elapsed: Duration) -> String {
    format!(
        r#"{{"event":"{name}","elapsed_ms":{}}}"#,
        elapsed.as_millis()
    )
}

fn record_failure(recorder: &OpRecorder, emit: &EventEmit, name: &str, elapsed: Duration) {
    // 記録できなくても exec の応答は変えない（既存の記録の流儀）。固定の操作名のみで ID・argv・パスは載せない。
    if let Ok(op) = OpName::new(name) {
        let _ = recorder.record(&op, OpOutcome::Failure, elapsed);
    }
    emit(event_line(name, elapsed));
}

struct Inner {
    phase: Mutex<Phase>,
    changed: Condvar,
    /// `SignalAck` の受け渡し（#4282）。ロックの順序は「ack → phase」だけ（phase を持ったまま ack を取らない）。
    ack: Mutex<AckSlot>,
    acked: Condvar,
    /// helper の `Spawned` が運んだコマンドのホスト側 pid（0 は未着。#4316・CRI-5・SUP-6）。ロックを増やさないため原子にする
    /// （「ack → phase」のロック順に加わらない）。表示用で、シグナルの宛先にしない（pid は再利用される）。
    pid: AtomicU32,
}

impl Inner {
    fn new() -> Self {
        Self {
            phase: Mutex::new(Phase::Running),
            changed: Condvar::new(),
            ack: Mutex::new(AckSlot::default()),
            acked: Condvar::new(),
            pid: AtomicU32::new(0),
        }
    }

    /// `Spawned` の pid を記録する。2 回目以降（プロトコル違反）は `false` で、値は最初のものを保つ。
    fn record_pid(&self, pid: NonZeroU32) -> bool {
        let ok = self
            .pid
            .compare_exchange(0, pid.get(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if ok {
            // 待ち手は phase のロック下で pid を確かめるため、ロックを一瞬取ってから起こして取りこぼしを防ぐ（#4318）。
            drop(self.lock());
            self.changed.notify_all();
        }
        ok
    }

    /// `Spawned` の記録・実行の終了・期限のいずれかまで待ち、戻った理由を返す（launch から。#4318・#4379・REPAIR-5）。
    /// 期限切れの判定はロック下の同じ判断で決める（遅れて届いた `Spawned` との競合で数えが揺れないため）。
    fn wait_spawned(&self, until: Instant) -> SpawnedWait {
        let mut p = self.lock();
        loop {
            if self.recorded_pid().is_some() {
                return SpawnedWait::Recorded;
            }
            if !matches!(*p, Phase::Running) {
                return SpawnedWait::Settled;
            }
            let now = Instant::now();
            if now >= until {
                return SpawnedWait::Expired;
            }
            let slice = WAIT_SLICE.min(until - now);
            p = self
                .changed
                .wait_timeout(p, slice)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// 記録済みの pid（未着なら `None`）。
    fn recorded_pid(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.pid.load(Ordering::Acquire))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_ack(&self) -> std::sync::MutexGuard<'_, AckSlot> {
        self.ack.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 実行中のときだけ遷移させる（終了済みを上書きしない）。
    fn settle_if_running(&self, next: Phase) {
        let mut p = self.lock();
        if matches!(*p, Phase::Running) {
            *p = next;
        }
        drop(p);
        self.changed.notify_all();
        // ack を待っている要求を起こす（結果・切断が先に来たことを知らせる）。
        self.acked.notify_all();
    }

    /// 受けた `SignalAck` を先頭の未応答の要求へ対応づける。諦められた要求の ack は黙って消費して `true`。
    /// 未応答が無い・シグナルが合わない・既に受け取り済みなら `false`（プロトコル違反。呼び出し側が helper を止める）。
    fn deliver_ack(&self, signal: ExecSignal, code: SignalAckCode) -> bool {
        let mut a = self.lock_ack();
        // ack が来なかった（送信失敗後の欠落等）諦め済みの要求は読み飛ばす。
        while matches!(a.pending.front(), Some((s, true)) if *s != signal) {
            a.pending.pop_front();
        }
        match a.pending.pop_front() {
            Some((s, true)) if s == signal => true,
            Some((s, false)) if s == signal && a.received.is_none() => {
                a.received = Some(code);
                drop(a);
                self.acked.notify_all();
                true
            }
            _ => false,
        }
    }
}

/// 末尾の（待ち手が今いる）要求を「諦めた」印にする。
fn abandon_last(a: &mut AckSlot) {
    if let Some(last) = a.pending.back_mut() {
        last.1 = true;
    }
}

/// 追跡中の helper（強参照）と停止の印。停止の印と登録を同じ lock で扱う。
#[derive(Default)]
struct Tracker {
    stopped: bool,
    guards: Vec<Arc<HelperGuard>>,
}

fn lock_tracker(t: &Mutex<Tracker>) -> std::sync::MutexGuard<'_, Tracker> {
    t.lock().unwrap_or_else(PoisonError::into_inner)
}

fn untrack(t: &Mutex<Tracker>, guard: &Arc<HelperGuard>) {
    lock_tracker(t).guards.retain(|g| !Arc::ptr_eq(g, guard));
}

/// 本番の `TaskExecLauncher`。
pub struct ShimExecLauncher {
    state_root: PathBuf,
    store: Arc<dyn StateStore>,
    spawner: Arc<dyn HelperSpawner>,
    probe: Arc<dyn ExecExtinctionProbe>,
    budgets: ExecBudgets,
    shared: Arc<Shared>,
    tracker: Arc<Mutex<Tracker>>,
    /// 拒否・pid 未着の計数先。shim の serve では core の共有記録器を差し込む（#4379）。
    recorder: Arc<OpRecorder>,
    /// 計数と同時に出す発生時の行の送り先（#4379・REPAIR-4）。
    emit: EventEmit,
}

impl ShimExecLauncher {
    /// 発生時の行の送り先を差し替える（試験用）。
    #[must_use]
    #[cfg(test)]
    pub(crate) fn with_event_emit(mut self, emit: EventEmit) -> Self {
        self.emit = emit;
        self
    }

    /// 計数先の記録器を差し替える（shim の共有記録器。#4379・REPAIR-4）。
    #[must_use]
    pub fn with_recorder(mut self, recorder: Arc<OpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }

    /// 計数先の記録器（観測・試験用）。
    pub fn recorder(&self) -> &Arc<OpRecorder> {
        &self.recorder
    }

    /// 状態ルート（絶対パス）・状態ストア・helper の起動口・消滅確認の口から作る。
    pub fn new(
        state_root: PathBuf,
        store: Arc<dyn StateStore>,
        spawner: Arc<dyn HelperSpawner>,
        probe: Arc<dyn ExecExtinctionProbe>,
    ) -> Self {
        Self::with_budgets(state_root, store, spawner, probe, ExecBudgets::default())
    }

    /// 期限を指定して作る（試験用）。
    pub(crate) fn with_budgets(
        state_root: PathBuf,
        store: Arc<dyn StateStore>,
        spawner: Arc<dyn HelperSpawner>,
        probe: Arc<dyn ExecExtinctionProbe>,
        budgets: ExecBudgets,
    ) -> Self {
        Self {
            state_root,
            store,
            spawner,
            probe,
            budgets,
            shared: Arc::new(Shared::default()),
            tracker: Arc::new(Mutex::new(Tracker::default())),
            recorder: Arc::new(OpRecorder::new()),
            emit: default_event_emit(),
        }
    }

    /// 本番の spawner と probe で作る。
    pub fn production(state_root: PathBuf, store: Arc<dyn StateStore>) -> Self {
        Self::new(
            state_root,
            store,
            Arc::new(ProductionHelperSpawner),
            Arc::new(CgroupExtinctionProbe),
        )
    }

    /// 追跡中の helper の数（観測・試験用）。
    pub fn tracked_helpers(&self) -> usize {
        lock_tracker(&self.tracker).guards.len()
    }

    /// 追跡中の全 helper を kill し、以後の `launch` を拒否する（shim の停止時。REPAIR-5）。
    pub fn shutdown_all(&self) {
        let guards = {
            let mut t = lock_tracker(&self.tracker);
            t.stopped = true;
            std::mem::take(&mut t.guards)
        };
        for g in guards {
            g.kill();
        }
    }

    /// spec のうち helper が受けない欄を黙って捨てずに拒否する（cri の `parse_process_spec` との多重防御）。
    fn check_spec(spec: &ExecProcessSpec) -> Result<(), CriError> {
        if !spec.env().is_empty() {
            return Err(CriError::unimplemented("exec env is not supported"));
        }
        if spec.cwd() != "/" {
            return Err(CriError::unimplemented("exec cwd is not supported"));
        }
        if spec.user().is_some() {
            return Err(CriError::unimplemented("exec user is not supported"));
        }
        Ok(())
    }

    /// helper へ空の stdio を渡し `Started` まで進め、helper が通知した exec 子 cgroup の名前を返す（wire v2・#4221。現行は v4・#4316）。
    ///
    /// 旧い helper（v1〜v3）とは version の不一致で `Started` に至らず、ここで `Err`（exec は始まらず、登録も probe も作らない。fail-closed）。
    fn handshake(
        &self,
        channel: &std::os::unix::net::UnixStream,
    ) -> Result<ExecCgroupName, CriError> {
        send_stdio_handover(
            channel,
            &StdioSend {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            Instant::now() + self.budgets.handover,
        )
        .map_err(|e| channel_error(&e))?;
        match recv_from_helper(channel, Instant::now() + self.budgets.started) {
            Ok(HelperMessage::Started(name)) => Ok(name),
            Ok(HelperMessage::Result(outcome)) => Err(match map_outcome(outcome) {
                Err(e) => e,
                Ok(_) => CriError::internal("exec ended before it started"),
            }),
            // `Spawned` は `Started` より前には来ない（fork の後に送られる。#4316）。順序違反は想定外の frame として失敗にする。
            Ok(
                HelperMessage::PtyMaster(_)
                | HelperMessage::SignalAck { .. }
                | HelperMessage::Spawned { .. },
            ) => Err(CriError::internal("exec failed")),
            Err(e) => Err(channel_error(&e)),
        }
    }
}

impl TaskExecLauncher for ShimExecLauncher {
    fn launch(
        &self,
        container: &ContainerId,
        _exec_id: &ExecId,
        spec: &ExecProcessSpec,
        expected_instance: Option<u64>,
    ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
        let launch_started = Instant::now();
        Self::check_spec(spec)?;
        if lock_tracker(&self.tracker).stopped {
            return Err(CriError::unavailable("exec launcher is stopped"));
        }
        let slot = self.shared.acquire()?;

        let record = self
            .store
            .get(&GetStateRequest::new(container.clone()))
            .map_err(|e| {
                if e.code() == ErrorCode::NotFound {
                    CriError::not_found("container not found")
                } else {
                    CriError::unavailable("container state is unavailable")
                }
            })?;
        // 登録時のインスタンスを、pid を決めるのと同じ record で照合する。shim の `purge_mismatched` は別の読み取りなので、
        // その後に外で作り直されても旧登録の argv を新インスタンスへ起動しない。helper の起動前に返す
        // （作り直し後に停止していても "not running" ではなくこちらを返す。#4323・CRI-5・SEC-1・CORE-1）。
        if !instance_matches(
            expected_instance,
            record.instance().map(ContainerInstance::value),
        ) {
            record_failure(
                &self.recorder,
                &self.emit,
                OP_EXEC_INSTANCE_CHANGED,
                launch_started.elapsed(),
            );
            return Err(CriError::failed_precondition(MSG_EXEC_INSTANCE_CHANGED));
        }
        let placement = record.cgroup().cloned();
        let status = record.status();
        let pid: NonZeroU32 = match (status.state(), status.pid()) {
            (ContainerState::Running, Some(pid)) => pid,
            _ => return Err(CriError::failed_precondition("container is not running")),
        };
        let args = StreamExecArgs::new(
            self.state_root.clone(),
            container.clone(),
            pid,
            self.budgets.session,
            StdioMask::from_presence(false, false, false),
            spec.args().to_vec(),
        )
        .map_err(|_| CriError::invalid_argument("exec request was rejected"))?;

        let SpawnedHelper {
            child,
            channel,
            diagnostics,
        } = self.spawner.spawn(&args)?;
        let diag_stop = Arc::new(AtomicBool::new(false));
        let guard = Arc::new(HelperGuard {
            child: Mutex::new(Some(child)),
            shared: Arc::clone(&self.shared),
            diag_stop: Arc::clone(&diag_stop),
            _slot: slot,
        });
        // helper の fd 2 は CRI の exec と同じく上限つきの読み手で固定語彙の構造化ログへ転送する（#4171）。
        // 作れなくても exec は失敗にしない（観測は最善努力）。
        if let Some(sock) = diagnostics {
            let reader_deadline = Instant::now()
                + self.budgets.started
                + self.budgets.session
                + self.budgets.result_grace;
            let sink = crate::telemetry::stderr_sink().clone();
            if diagnostics::spawn_reader(
                sock,
                diag_stop,
                reader_deadline,
                sink.clone(),
                &self.shared.diag,
            )
            .is_err()
            {
                let _ = sink.submit(diagnostics::reader_unavailable_line());
            }
        }
        {
            let mut t = lock_tracker(&self.tracker);
            if t.stopped {
                drop(t);
                guard.kill();
                return Err(CriError::unavailable("exec launcher is stopped"));
            }
            t.guards.push(Arc::clone(&guard));
        }

        let fail = |e: CriError| {
            untrack(&self.tracker, &guard);
            guard.kill();
            e
        };
        let cgroup = self.handshake(&channel).map_err(fail)?;

        let watch_channel = channel
            .try_clone()
            .map_err(|_| fail(CriError::unavailable("exec channel setup failed")))?;
        let inner = Arc::new(Inner::new());
        let deadline = Instant::now() + self.budgets.session + self.budgets.result_grace;
        let thread_inner = Arc::clone(&inner);
        let thread_guard = Arc::clone(&guard);
        let thread_tracker = Arc::clone(&self.tracker);
        std::thread::Builder::new()
            .name("exec-result".to_string())
            .spawn(move || {
                watch_result(
                    &watch_channel,
                    deadline,
                    &thread_inner,
                    &thread_guard,
                    &thread_tracker,
                );
            })
            .map_err(|_| fail(CriError::unavailable("failed to start the exec watcher")))?;
        // `Spawned` か終了か予算切れまで待ってから返す。cri の Start 応答と TaskExecStarted が実 pid を持てる（#4318）。
        // 届かなくても失敗にはしない（pid は表示用で、不明なら 0 のまま）。予算切れの回だけ数える（#4379・REPAIR-4）。
        let wait_started = Instant::now();
        if let Some(until) = wait_started.checked_add(self.budgets.spawned)
            && matches!(inner.wait_spawned(until), SpawnedWait::Expired)
        {
            record_failure(
                &self.recorder,
                &self.emit,
                OP_EXEC_PID_UNREPORTED,
                wait_started.elapsed(),
            );
        }
        // 送信用の端は手放さず `ShimExecProcess` が持つ（SIGKILL 以外のシグナルの `Signal` frame を送る。#4282）。
        // 要求元の消滅の検知は「端がすべて閉じる」ことなので、監視スレッドの端が残る間は handle の drop で誤検知しない。

        Ok(Arc::new(ShimExecProcess {
            signal_tx: Mutex::new(Some(channel)),
            signal_ack: self.budgets.signal_ack,
            inner,
            guard: Arc::downgrade(&guard),
            tracker: Arc::clone(&self.tracker),
            probe: Arc::clone(&self.probe),
            target: ExecExtinctionTarget {
                container: container.clone(),
                placement,
                cgroup,
            },
            extinction_grace: self.budgets.extinction_grace,
        }))
    }
}

/// `Result` を待つ専用スレッドの本体。終了で `Exited`、失敗・期限切れ・切断で未確認にし、追跡から外す。
fn watch_result(
    channel: &std::os::unix::net::UnixStream,
    deadline: Instant,
    inner: &Inner,
    guard: &Arc<HelperGuard>,
    tracker: &Mutex<Tracker>,
) {
    // helper → plugin-cri の唯一の読み手。`SignalAck` は待っている要求へ渡して読み続け、`Result` で抜ける（#4282）。
    let next = loop {
        match recv_from_helper(channel, deadline) {
            Ok(HelperMessage::SignalAck { signal, code }) => {
                if inner.deliver_ack(signal, code) {
                    continue;
                }
                // 待っていない・番号違いの ack はプロトコル違反（helper の kill → 未確認）。
                guard.kill();
                break Phase::unconfirmed(CriError::unavailable(UNCONFIRMED));
            }
            // コマンドのホスト側 pid（#4316）。高々 1 回で、2 回目はプロトコル違反。届かないまま `Result` が来ても正当（pid は不明のまま）。
            Ok(HelperMessage::Spawned { pid }) => {
                if inner.record_pid(pid) {
                    continue;
                }
                guard.kill();
                break Phase::unconfirmed(CriError::unavailable(UNCONFIRMED));
            }
            Ok(HelperMessage::Result(StreamExecOutcome::Failed(code))) => {
                break Phase::unconfirmed(cri_error(code));
            }
            Ok(HelperMessage::Result(outcome)) => {
                break match map_outcome(outcome) {
                    Ok(code) => Phase::Exited(Some(code)),
                    Err(e) => Phase::unconfirmed(e),
                };
            }
            Ok(_) | Err(_) => {
                guard.kill();
                break Phase::unconfirmed(CriError::unavailable(UNCONFIRMED));
            }
        }
    };
    inner.settle_if_running(next);
    untrack(tracker, guard);
}

/// 起動した exec のハンドル。helper の強参照は追跡一覧と監視スレッドが持ち、ここは弱参照だけ（drop で止めない）。
struct ShimExecProcess {
    inner: Arc<Inner>,
    guard: Weak<HelperGuard>,
    tracker: Arc<Mutex<Tracker>>,
    probe: Arc<dyn ExecExtinctionProbe>,
    /// 消滅確認の材料（launch の時点で固定。#4221）。
    target: ExecExtinctionTarget,
    extinction_grace: Duration,
    /// helper への `Signal` frame の送信用の端（`launch` の channel）。ロックが SIGKILL 以外のシグナルの要求を 1 件ずつ排他する。
    /// 送信に失敗したら `None` にして以後は送らない（frame の境界を信頼できないため）。#4282
    signal_tx: Mutex<Option<std::os::unix::net::UnixStream>>,
    /// `SignalAck` を待つ上限。
    signal_ack: Duration,
}

impl ShimExecProcess {
    /// SIGKILL 以外の許可されたシグナルを helper へ送り、`SignalAck` を期限つきで待って CRI の結果へ写す（#4282・SUP-6・CRI-5）。
    ///
    /// 要求は 1 件ずつ排他する。結果・切断が ack より先に来たら `NOT_FOUND` / `UNAVAILABLE`。期限切れは `DEADLINE_EXCEEDED`。
    fn send_exec_signal(&self, signal: ExecSignal) -> Result<(), CriError> {
        let undelivered = || CriError::unavailable("exec signal could not be delivered");
        let mut tx = self
            .signal_tx
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(stream) = tx.as_ref() else {
            return Err(undelivered());
        };
        {
            let mut a = self.inner.lock_ack();
            if a.pending.len() >= MAX_PENDING_SIGNALS {
                return Err(undelivered());
            }
            a.pending.push_back((signal, false));
            a.received = None;
        }
        if send_signal(stream, signal, Instant::now() + SIGNAL_SEND_BUDGET).is_err() {
            // 途中まで書いた frame は境界が崩れている。以後この channel へは送らない（helper は受信失敗で signal を無視する）。
            *tx = None;
            // 送り切れていないので ack は来ない。末尾の自分の要求を取り除く。
            self.inner.lock_ack().pending.pop_back();
            return Err(undelivered());
        }
        let until = Instant::now() + self.signal_ack;
        let mut a = self.inner.lock_ack();
        loop {
            if let Some(code) = a.received.take() {
                return match code {
                    SignalAckCode::Delivered => Ok(()),
                    SignalAckCode::NotStarted => Err(CriError::failed_precondition(
                        "exec process is not started yet",
                    )),
                    SignalAckCode::Exited => Err(CriError::not_found("process already finished")),
                    SignalAckCode::Unavailable => Err(undelivered()),
                };
            }
            // ack より先に結果・切断が来た（ack は来ない）。
            let ended = match &*self.inner.lock() {
                Phase::Running => None,
                Phase::Exited(_) => Some(CriError::not_found("process already finished")),
                Phase::Unconfirmed { .. } => Some(CriError::unavailable(UNCONFIRMED)),
            };
            if let Some(e) = ended {
                abandon_last(&mut a);
                return Err(e);
            }
            let now = Instant::now();
            if now >= until {
                // helper は後から ack しうる。その ack は諦め済みとして消費させる。
                abandon_last(&mut a);
                return Err(CriError::timeout("exec signal was not acknowledged"));
            }
            let slice = WAIT_SLICE.min(until - now);
            a = self
                .inner
                .acked
                .wait_timeout(a, slice)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// 未確認のとき probe を 1 回照会し、`Confirmed` なら `Exited(None)` へ進める。lock の外で probe を呼ぶ。
    fn try_confirm(&self) {
        if self.probe.confirm(&self.target) == ExtinctionOutcome::Confirmed {
            let mut p = self.inner.lock();
            if matches!(*p, Phase::Unconfirmed { .. }) {
                *p = Phase::Exited(None);
            }
            drop(p);
            self.inner.changed.notify_all();
        }
    }

    fn snapshot(&self) -> Snapshot {
        match &*self.inner.lock() {
            Phase::Running => Snapshot::Running,
            Phase::Exited(code) => Snapshot::Exited(*code),
            Phase::Unconfirmed { error, since } => Snapshot::Unconfirmed {
                error: error.clone(),
                since: *since,
            },
        }
    }
}

/// `Phase` の写し（lock を持ち越さずに判定するため）。
enum Snapshot {
    Running,
    Exited(Option<i32>),
    Unconfirmed { error: CriError, since: Instant },
}

impl TaskExecProcess for ShimExecProcess {
    /// コマンドのホスト側 pid（plugin-cri と同じ pid namespace の値。#4316）。launch は `Spawned` を `spawned` の予算まで待つため
    /// 通常は戻りの時点で値がある（#4318）。予算内に届かなかった・`Spawned` 無しで終わった（起動の失敗・中継の失敗）ときは
    /// `None`（後で届けば値になる）。表示用で、シグナルの宛先にしてはならない（pid は再利用される）。
    fn pid(&self) -> Option<NonZeroU32> {
        self.inner.recorded_pid()
    }

    fn status(&self) -> Result<ExecProcessStatus, CriError> {
        let err = match self.snapshot() {
            Snapshot::Running => return Ok(ExecProcessStatus::Running),
            Snapshot::Exited(code) => return Ok(ExecProcessStatus::Exited { code }),
            Snapshot::Unconfirmed { error, .. } => error,
        };
        // lock の外で probe を呼ぶ。確認できたときだけ終了へ進める。
        self.try_confirm();
        match self.snapshot() {
            Snapshot::Exited(code) => Ok(ExecProcessStatus::Exited { code }),
            _ => Err(err),
        }
    }

    fn signal(&self, signal: Signal) -> Result<(), CriError> {
        if matches!(*self.inner.lock(), Phase::Exited(_)) {
            return Err(CriError::not_found("process already finished"));
        }
        if signal != Signal::SIGKILL {
            // 許可リスト（SIGHUP・SIGINT・SIGQUIT・SIGUSR1・SIGUSR2・SIGTERM）の外は従来どおり `UNIMPLEMENTED`（#4282）。
            let allowed = ExecSignal::new(signal.as_u8())
                .map_err(|_| CriError::unimplemented("exec signal is not supported"))?;
            // 未確認の exec へは送らない（cri の `kill_exec` も SIGKILL 以外は拒否する。helper の生存を確かめられない）。
            if matches!(*self.inner.lock(), Phase::Unconfirmed { .. }) {
                return Err(CriError::unavailable(UNCONFIRMED));
            }
            return self.send_exec_signal(allowed);
        }
        // helper だけを kill する。init へは送らない（SEC-1）。helper が既に無ければ止まっている。
        if let Some(g) = self.guard.upgrade() {
            g.kill();
            untrack(&self.tracker, &g);
        }
        self.inner
            .settle_if_running(Phase::unconfirmed(CriError::unavailable(UNCONFIRMED)));
        Ok(())
    }

    fn wait_exit(
        &self,
        timeout: Duration,
        poll_interval: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<i32>, CriError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| CriError::internal("wait deadline overflow"))?;
        // 未確認の間の probe の照会の刻み（`WAIT_SLICE` を下限にし、過度に叩かない）。
        let probe_slice = poll_interval.max(WAIT_SLICE);
        loop {
            if cancelled() {
                return Err(CriError::unavailable("wait cancelled"));
            }
            let unconfirmed = match self.snapshot() {
                Snapshot::Exited(code) => return Ok(code),
                Snapshot::Running => false,
                Snapshot::Unconfirmed { error, since } => {
                    // kill・期限切れの直後は supervisor の回収が終わる前のことがあるため、猶予の間だけ刻みごとに確かめる。
                    self.try_confirm();
                    if let Snapshot::Exited(code) = self.snapshot() {
                        return Ok(code);
                    }
                    if since.elapsed() >= self.extinction_grace {
                        return Err(error);
                    }
                    true
                }
            };
            let now = Instant::now();
            if now >= deadline {
                return Err(CriError::timeout("wait exceeded its deadline"));
            }
            let slice = if unconfirmed { probe_slice } else { WAIT_SLICE }.min(deadline - now);
            if unconfirmed {
                std::thread::sleep(slice);
                continue;
            }
            let p = self.inner.lock();
            if matches!(*p, Phase::Running) {
                // 通知か刻みのどちらか早い方で起きる。
                let _ = self
                    .inner
                    .changed
                    .wait_timeout(p, slice)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
    }
}

#[cfg(test)]
mod tests;
