//! seccomp の通知を受けて記録し、`-EPERM` で応答する listener ループ（SEC-4・REPAIR-5・SUP-2・TASK-41 追補・#2025。
//! 監査配送 3/6。方式は `docs/design/audit-delivery.md`）。
//!
//! # 役割と呼び出し文脈
//!
//! 本番 launcher は supervisor の start 経路の opt-in で ERRNO 側の 40 件の syscall を `SECCOMP_RET_USER_NOTIF` にし、
//! PID 1 が `NEW_LISTENER` 付きで載せた listener fd を supervisor へ渡す（core の `exec::seccomp_listener`。#2024）。
//! 本モジュールの [`SeccompNotifyHub`] は、その listener を監視の間保持し、専用スレッドで通知を読んで
//! 「PID を対象自身の PID namespace の値へ変換 → cookie 検証 → 記録 → `-EPERM` 応答」を行う。
//! 呼び出し元は `start_entry::run_supervised`（初回の listener）と `restart::LauncherRelauncher`（再 launch のたび）。
//! 記録先は `ControlAuditRelay`（複数スレッドの supervisor から使える。`start_entry::run_main` が作る）。
//!
//! # 守ること（申し送り: PR #2290 の事後監査・SEC-4）
//!
//! - **許可しない**: 応答は `-EPERM` の 1 種類だけ（core の `SeccompListener::deny_eperm`）。通知の引数・命令ポインタは
//!   core が公開しないので、ポインタ先を判断に使う TOCTOU の余地が無い。記録の可否に関わらず必ず応答する
//! - **対象を止め続けない（REPAIR-5）**: 記録の完了は通知ごとに `NotifyConfig` の応答の期限まで待ち、超えても応答する。
//!   記録は別スレッド（recorder）で行い、listener は受信と完了待ちを分けて有界(`MAX_IN_FLIGHT`)の待ち行列で管理する。
//!   sink が詰まっても後続の受信と応答期限は遅れず、上限を超えた分は待たずに拒否応答する
//! - **洪水で DoS されない**: 記録の段にだけトークンバケットと有界キューを置き、超えた分は記録せず待たずに応答して
//!   集計する（間引きは応答を遅らせない）。集計は固定語彙と数値だけの構造化ログを間隔を空けてまとめて出す
//! - **取り違えない**: `/proc/<tid>/status` を読んだ **後** に `ID_VALID` で cookie を検証し、pid の再利用や対象の終了で
//!   別プロセスの情報を記録しない（無効なら記録しない）
//! - **応答者の不在でも拒否は保たれる**: スレッドが終了して listener が閉じると、カーネルは待機中の syscall を
//!   `ENOSYS` にする（許可に倒れない）
//!
//! # 未実装（REPAIR-3）
//!
//! 記録経路が使えないときの起動拒否・縮退の表示（#2027）は扱わず、`unrecorded` の集計とログまで。exec 経路（SUP-6）の
//! listener 受け渡しは #2385。restart の再 launch を本番で成り立たせること自体は #2043（本モジュールの差し替えは
//! 偽の launcher でだけ試している）。

use std::collections::VecDeque;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::{
    AuditRecord, AuditSink, AuditTimestamp, SeccompDenialReport, record_seccomp_denial_for,
};
use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

/// 1 件の応答を待つ記録の完了の上限（既定。REPAIR-5）。
pub const NOTIFY_RESPONSE_DEADLINE: Duration = Duration::from_secs(1);
/// 応答の期限として受け付ける最大値（これを超える指定は拒否する。対象が止まる時間の上限）。
pub const MAX_RESPONSE_DEADLINE: Duration = Duration::from_secs(5);
/// recorder の有界キューの容量。
pub const RECORD_QUEUE_CAPACITY: usize = 64;
/// 記録のレート（件/秒）とバースト。
pub const RECORD_RATE_PER_SEC: u32 = 20;
/// トークンバケットのバースト（一度に記録できる件数）。
pub const RECORD_BURST: u32 = 64;
/// listener を待つ 1 回の長さ（停止フラグを見る間隔）。
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// 集計の構造化ログを出す最小間隔。
const REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// `/proc/<tid>/status` を読む量の上限（`NSpid` は先頭付近。無制限に読まない）。
const PROC_STATUS_READ_LIMIT: u64 = 64 * 1024;
/// スレッドの終了を待つ間隔。
const JOIN_STEP: Duration = Duration::from_millis(5);

/// ループの設定。既定は本番の値。試験は短い期限などを注入する。
#[derive(Debug, Clone, Copy)]
pub struct NotifyConfig {
    response_deadline: Duration,
    queue_capacity: usize,
    rate_per_sec: u32,
    burst: u32,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            response_deadline: NOTIFY_RESPONSE_DEADLINE,
            queue_capacity: RECORD_QUEUE_CAPACITY,
            rate_per_sec: RECORD_RATE_PER_SEC,
            burst: RECORD_BURST,
        }
    }
}

impl NotifyConfig {
    /// 応答の期限を指定する。0 と [`MAX_RESPONSE_DEADLINE`] 超は `InvalidArgument`（対象を無期限に止めない。REPAIR-5）。
    pub fn with_response_deadline(mut self, deadline: Duration) -> Result<Self, TraitError> {
        if deadline.is_zero() || deadline > MAX_RESPONSE_DEADLINE {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "the seccomp response deadline must be within (0, 5s]",
            ));
        }
        self.response_deadline = deadline;
        Ok(self)
    }

    /// キュー容量とレートを指定する（試験用）。いずれも 1 以上。
    pub fn with_limits(
        mut self,
        queue_capacity: usize,
        rate_per_sec: u32,
        burst: u32,
    ) -> Result<Self, TraitError> {
        if queue_capacity == 0 || rate_per_sec == 0 || burst == 0 {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "the seccomp record limits must be positive",
            ));
        }
        self.queue_capacity = queue_capacity;
        self.rate_per_sec = rate_per_sec;
        self.burst = burst;
        Ok(self)
    }
}

/// ループが扱う通知の中身（記録に要る値だけ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notified {
    /// listener の PID namespace での対象 TID。
    pub pid_in_listener_ns: u32,
    /// 拒否された syscall 番号。
    pub nr: i32,
    /// `AUDIT_ARCH_*`。
    pub arch: u32,
}

/// 応答の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Responded {
    /// `-EPERM` を返した。
    Sent,
    /// 応答の前に対象が消えていた。
    TargetGone,
}

/// listener の待機状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ready {
    /// 通知なし。
    Idle,
    /// 通知あり。
    Readable,
    /// 利用者がいなくなった。
    Closed,
}

/// 供給元の失敗（原因は呼び出し側で区別しない。ループは受信側の失敗で終了し、listener を閉じる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceError;

/// 通知の供給元。本番は core の `SeccompListener`、試験は偽物（ループの全分岐を実カーネル無しで確かめる）。
pub trait NotifySource: Send + 'static {
    /// 通知の識別子。
    type Id: Copy + Send + 'static;
    /// 最大 `timeout` 待つ。
    fn wait(&self, timeout: Duration) -> Result<Ready, SourceError>;
    /// 通知を 1 件受け取る（対象が消えていれば `None`）。
    fn receive(&self) -> Result<Option<(Self::Id, Notified)>, SourceError>;
    /// 通知が応答待ちか（cookie 検証）。
    fn is_pending(&self, id: Self::Id) -> Result<bool, SourceError>;
    /// `-EPERM` で応答する。
    fn deny_eperm(&self, id: Self::Id) -> Result<Responded, SourceError>;
}

/// 取り出した pid を対象自身の PID namespace の値へ変換する。変換できなければ `None`。
type PidResolver = Box<dyn Fn(u32) -> Option<u32> + Send>;

/// 集計（原子的。listener スレッドと recorder が書き、`finish` が読む）。
#[derive(Debug, Default)]
pub struct Counters {
    recorded: AtomicU64,
    suppressed: AtomicU64,
    late: AtomicU64,
    unrecorded: AtomicU64,
    target_gone: AtomicU64,
    pid_unresolved: AtomicU64,
    respond_failed: AtomicU64,
    wait_failed: AtomicU64,
    receive_failed: AtomicU64,
    /// listener スレッドが最終ログで報告済みとした時点の値（回収後に recorder の増分だけを出すため）。
    reported_at_exit: Mutex<Option<CounterSnapshot>>,
}

/// [`Counters`] の時点の値。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// sink に記録できた件数。
    pub recorded: u64,
    /// レート超過・キュー満杯で記録しなかった件数。
    pub suppressed: u64,
    /// 期限内に記録が終わらず、先に応答した件数。
    pub late: u64,
    /// sink が失敗した（または記録先が無い）件数。
    pub unrecorded: u64,
    /// 応答の前に対象が消えた（または cookie が無効だった）件数。
    pub target_gone: u64,
    /// pid を変換できず、記録せずに応答した件数。
    pub pid_unresolved: u64,
    /// 応答の送信が失敗した件数。
    pub respond_failed: u64,
    /// listener の待機（poll）が失敗してループを終えた件数。以後の禁止 syscall は ENOSYS になる（監査配送の停止）。
    pub wait_failed: u64,
    /// 通知の受信が失敗してループを終えた件数。意味は `wait_failed` と同じ。
    pub receive_failed: u64,
}

impl Counters {
    fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            recorded: self.recorded.load(Ordering::Relaxed),
            suppressed: self.suppressed.load(Ordering::Relaxed),
            late: self.late.load(Ordering::Relaxed),
            unrecorded: self.unrecorded.load(Ordering::Relaxed),
            target_gone: self.target_gone.load(Ordering::Relaxed),
            pid_unresolved: self.pid_unresolved.load(Ordering::Relaxed),
            respond_failed: self.respond_failed.load(Ordering::Relaxed),
            wait_failed: self.wait_failed.load(Ordering::Relaxed),
            receive_failed: self.receive_failed.load(Ordering::Relaxed),
        }
    }
}

/// 構造化ログの固定語彙と値の組。入力由来の値は含めない。
fn report_events(now: CounterSnapshot, prev: CounterSnapshot) -> Vec<(&'static str, u64)> {
    [
        ("seccomp_audit_suppressed", now.suppressed, prev.suppressed),
        ("seccomp_audit_late", now.late, prev.late),
        ("seccomp_audit_unrecorded", now.unrecorded, prev.unrecorded),
        (
            "seccomp_audit_target_gone",
            now.target_gone,
            prev.target_gone,
        ),
        (
            "seccomp_audit_pid_unresolved",
            now.pid_unresolved,
            prev.pid_unresolved,
        ),
        (
            "seccomp_audit_respond_failed",
            now.respond_failed,
            prev.respond_failed,
        ),
        (
            "seccomp_audit_wait_failed",
            now.wait_failed,
            prev.wait_failed,
        ),
        (
            "seccomp_audit_receive_failed",
            now.receive_failed,
            prev.receive_failed,
        ),
    ]
    .into_iter()
    .filter_map(|(event, n, p)| n.checked_sub(p).filter(|d| *d > 0).map(|d| (event, d)))
    .collect()
}

fn emit_report(events: &[(&'static str, u64)]) {
    for (event, count) in events {
        let line =
            format!("{{\"component\":\"supervisor\",\"event\":\"{event}\",\"count\":{count}}}\n");
        // 満杯・書き込み失敗でも処理は止めない（ログの欠落は許す。REPAIR-5）。
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
    }
}

/// トークンバケット（時計は呼び出し側が渡す）。
#[derive(Debug)]
struct Bucket {
    /// 1 トークン = 1000 ミリトークン。
    milli: u64,
    cap_milli: u64,
    rate_milli_per_sec: u64,
    last: Instant,
}

impl Bucket {
    fn new(rate_per_sec: u32, burst: u32, now: Instant) -> Self {
        let cap = u64::from(burst) * 1000;
        Self {
            milli: cap,
            cap_milli: cap,
            rate_milli_per_sec: u64::from(rate_per_sec) * 1000,
            last: now,
        }
    }

    /// 1 件分を取れたら `true`。
    fn take(&mut self, now: Instant) -> bool {
        let elapsed_ms =
            u64::try_from(now.saturating_duration_since(self.last).as_millis()).unwrap_or(u64::MAX);
        if elapsed_ms > 0 {
            let add = elapsed_ms.saturating_mul(self.rate_milli_per_sec) / 1000;
            self.milli = self.milli.saturating_add(add).min(self.cap_milli);
            self.last = now;
        }
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// `/proc/<pid>/status` の本文から `NSpid` の末尾（対象自身の PID namespace での pid）を取り出す。
/// 行が無い・空・0・壊れた値は `None`（捏造しない）。
pub fn parse_nspid_innermost(status: &str) -> Option<u32> {
    let line = status.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
    let last = line.split_whitespace().last()?;
    last.parse::<u32>().ok().filter(|n| *n > 0)
}

/// 本番の pid 変換: `/proc/<tid>/status` を上限つきで読み、`NSpid` の末尾を返す。
fn resolve_pid_from_proc(pid_in_listener_ns: u32) -> Option<u32> {
    let file = std::fs::File::open(format!("/proc/{pid_in_listener_ns}/status")).ok()?;
    let mut body = String::new();
    file.take(PROC_STATUS_READ_LIMIT)
        .read_to_string(&mut body)
        .ok()?;
    parse_nspid_innermost(&body)
}

/// recorder への依頼。
struct Job {
    report: SeccompDenialReport,
    at: AuditTimestamp,
    done: SyncSender<()>,
}

/// 記録先が無いときの sink（ループは止めず、`unrecorded` として数える。起動の拒否は #2027）。
#[derive(Debug, Default)]
pub struct UnavailableAuditSink;

impl AuditSink for UnavailableAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
        Err(TraitError::new(
            ErrorCode::Unavailable,
            "no audit sink is available for seccomp records",
        ))
    }
}

/// recorder スレッドの本体。依頼ごとに sink へ記録し、完了を知らせる。sender が全部消えたら終わる。
fn recorder_main(
    jobs: &Receiver<Job>,
    sink: &Arc<dyn AuditSink>,
    container_id: &ContainerId,
    counters: &Counters,
) {
    while let Ok(job) = jobs.recv() {
        // ロックを持たずに呼ぶ（sink が詰まっても他を巻き込まない）。
        match record_seccomp_denial_for(&job.report, job.at, Some(container_id), sink.as_ref()) {
            Ok(()) => counters.recorded.fetch_add(1, Ordering::Relaxed),
            Err(_) => counters.unrecorded.fetch_add(1, Ordering::Relaxed),
        };
        // 待っていなければ（期限切れ）送れないだけ。
        let _ = job.done.try_send(());
    }
}

/// 記録の完了待ちの通知(応答は完了か期限のどちらか早い方で返す)。
struct InFlight<I> {
    id: I,
    deadline: Instant,
    finished: Receiver<()>,
}

/// 完了待ちの通知の上限。recorder のキュー容量(`RECORD_QUEUE_CAPACITY`)と recorder が処理中の 1 件までしか入らないが、
/// 受信と待ちを分けた構造の上限として明示する。超える分は待たずに拒否応答する(REPAIR-5)。
const MAX_IN_FLIGHT: usize = RECORD_QUEUE_CAPACITY + 1;
/// 完了待ちがあるときに listener を待つ 1 回の長さ(完了は poll を起こさないため短く刻んで確かめる)。
const IN_FLIGHT_POLL: Duration = Duration::from_millis(2);

/// `-EPERM` で応答して結果を数える。
fn respond<S: NotifySource>(source: &S, counters: &Counters, id: S::Id) {
    match source.deny_eperm(id) {
        Ok(Responded::Sent) => {}
        Ok(Responded::TargetGone) => {
            counters.target_gone.fetch_add(1, Ordering::Relaxed);
        }
        Err(SourceError) => {
            counters.respond_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 先頭から、記録が完了したか期限を過ぎた通知に応答する。FIFO の recorder と同じ期限幅のため先頭だけ見れば足りる。
fn settle_in_flight<S: NotifySource>(
    source: &S,
    counters: &Counters,
    in_flight: &mut VecDeque<InFlight<S::Id>>,
) {
    while let Some(front) = in_flight.front() {
        match front.finished.try_recv() {
            Ok(()) => {}
            Err(TryRecvError::Empty) => {
                if Instant::now() < front.deadline {
                    return;
                }
                // 期限切れ: 先に応答する。記録は recorder で続く。
                counters.late.fetch_add(1, Ordering::Relaxed);
            }
            Err(TryRecvError::Disconnected) => {
                counters.unrecorded.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(done) = in_flight.pop_front() {
            respond(source, counters, done.id);
        }
    }
}

/// 待たずに全件へ応答する(停止要求・供給元の異常)。記録は recorder で続くか、捨てられる。
fn drain_in_flight<S: NotifySource>(
    source: &S,
    counters: &Counters,
    in_flight: &mut VecDeque<InFlight<S::Id>>,
) {
    while let Some(done) = in_flight.pop_front() {
        counters.late.fetch_add(1, Ordering::Relaxed);
        respond(source, counters, done.id);
    }
}

/// listener スレッドの本体。受信と記録の完了待ちを分け、1 件の記録の遅れが後続の応答期限に響かないようにする(REPAIR-5)。
// 理由: ループは供給元・pid 変換・設定・キュー・集計・停止フラグを毎回使う独立した入力で、束ねる型を作っても
// 呼び出しが増えるだけのため引数のまま渡す。
#[allow(clippy::too_many_arguments)]
fn listener_main<S: NotifySource>(
    source: &S,
    resolve: &PidResolver,
    config: NotifyConfig,
    jobs: &SyncSender<Job>,
    counters: &Counters,
    stop: &AtomicBool,
) {
    let mut bucket = Bucket::new(config.rate_per_sec, config.burst, Instant::now());
    let mut reported = CounterSnapshot::default();
    let mut last_report = Instant::now();
    let mut in_flight: VecDeque<InFlight<S::Id>> = VecDeque::new();
    // 供給元が閉じた後は、完了待ちの分だけ期限まで見届けてから終わる(対象は既にいないが記録は残す)。
    let mut closing = false;
    loop {
        // 通知が連続していても毎反復で停止要求を確かめる(REPAIR-5)。
        if stop.load(Ordering::Acquire) {
            break;
        }
        settle_in_flight(source, counters, &mut in_flight);
        if closing {
            if in_flight.is_empty() {
                break;
            }
            std::thread::sleep(IN_FLIGHT_POLL);
            continue;
        }
        let wait = if in_flight.is_empty() {
            POLL_INTERVAL
        } else {
            IN_FLIGHT_POLL
        };
        match source.wait(wait) {
            Ok(Ready::Readable) => {}
            Ok(Ready::Idle) => {
                report_if_due(counters, &mut reported, &mut last_report);
                continue;
            }
            // 利用者の消滅(コンテナの全プロセスが終了)。以後通知は来ない。
            Ok(Ready::Closed) => {
                closing = true;
                continue;
            }
            // 読めない状態。以後の完了待ちは見届けず応答して終わる。
            Err(SourceError) => {
                counters.wait_failed.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        let (id, notified) = match source.receive() {
            Ok(Some(n)) => n,
            Ok(None) => {
                counters.target_gone.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Err(SourceError) => {
                counters.receive_failed.fetch_add(1, Ordering::Relaxed);
                break;
            }
        };
        match handle_one(
            source,
            resolve,
            jobs,
            counters,
            &mut bucket,
            id,
            notified,
            in_flight.len(),
        ) {
            Handled::Done => {}
            Handled::Waiting(finished) => in_flight.push_back(InFlight {
                id,
                deadline: Instant::now() + config.response_deadline,
                finished,
            }),
        }
        report_if_due(counters, &mut reported, &mut last_report);
    }
    drain_in_flight(source, counters, &mut in_flight);
    let last = counters.snapshot();
    emit_report(&report_events(last, reported));
    *counters
        .reported_at_exit
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(last);
}

fn report_if_due(counters: &Counters, reported: &mut CounterSnapshot, last: &mut Instant) {
    if last.elapsed() < REPORT_INTERVAL {
        return;
    }
    *last = Instant::now();
    let now = counters.snapshot();
    emit_report(&report_events(now, *reported));
    *reported = now;
}

/// [`handle_one`] の結果。
enum Handled {
    /// 応答まで済んだ。
    Done,
    /// 記録の完了待ち(応答は呼び出し側が完了か期限で返す)。
    Waiting(Receiver<()>),
}

/// 受け取った 1 件の処理: 変換 → 検証 → 記録の依頼。記録を待たない場合はその場で応答する。必ず応答する(検証が無効のときを除く)。
// 理由: listener_main と同じく、毎回使う独立した入力のため引数のまま渡す。
#[allow(clippy::too_many_arguments)]
fn handle_one<S: NotifySource>(
    source: &S,
    resolve: &PidResolver,
    jobs: &SyncSender<Job>,
    counters: &Counters,
    bucket: &mut Bucket,
    id: S::Id,
    notified: Notified,
    in_flight_len: usize,
) -> Handled {
    // /proc を読んだ後に cookie を検証する(読んでいる間に対象が消えて pid が再利用されていないことの確認)。
    let resolved = resolve(notified.pid_in_listener_ns);
    let valid = match source.is_pending(id) {
        Ok(true) => true,
        // 応答待ちでない通知には応答できない(対象は既に消えた)。記録もしない。
        Ok(false) => {
            counters.target_gone.fetch_add(1, Ordering::Relaxed);
            return Handled::Done;
        }
        // 検証できなかったときは記録しない(取り違えの恐れ)。ただし対象は止まっているので応答は試みる。
        Err(SourceError) => false,
    };
    if valid {
        let report = resolved.and_then(|pid| {
            SeccompDenialReport::from_user_notif(pid, notified.nr, notified.arch).ok()
        });
        match report {
            None => {
                counters.pid_unresolved.fetch_add(1, Ordering::Relaxed);
            }
            Some(report) => {
                if let Some(finished) = submit_record(jobs, counters, bucket, report, in_flight_len)
                {
                    return Handled::Waiting(finished);
                }
            }
        }
    } else {
        counters.unrecorded.fetch_add(1, Ordering::Relaxed);
    }
    respond(source, counters, id);
    Handled::Done
}

/// 記録を recorder へ渡す。完了待ちにするときは受け取り口を返す。レート超過・キュー満杯・完了待ちの上限超えは
/// 待たずに数えて `None`(その場で応答させる)。
fn submit_record(
    jobs: &SyncSender<Job>,
    counters: &Counters,
    bucket: &mut Bucket,
    report: SeccompDenialReport,
    in_flight_len: usize,
) -> Option<Receiver<()>> {
    if in_flight_len >= MAX_IN_FLIGHT {
        counters.suppressed.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if !bucket.take(Instant::now()) {
        counters.suppressed.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let Ok(at) = AuditTimestamp::now() else {
        counters.unrecorded.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let (done, finished) = sync_channel(1);
    match jobs.try_send(Job { report, at, done }) {
        Ok(()) => Some(finished),
        Err(TrySendError::Full(_)) => {
            counters.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
        Err(TrySendError::Disconnected(_)) => {
            counters.unrecorded.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// 動作中の 2 本のスレッド。
struct Live {
    stop: Arc<AtomicBool>,
    listener: JoinHandle<()>,
    recorder: JoinHandle<()>,
    counters: Arc<Counters>,
}

/// `handle` の終了を `timeout` まで待つ。終了したら回収して `true`。間に合わなければ放置して `false`。
fn join_within(handle: JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(JOIN_STEP);
    }
    handle.join().is_ok()
}

/// seccomp の listener ループの所有者。start と restart の再 launch で同じものを使い、listener を差し替える。
pub struct SeccompNotifyHub {
    sink: Arc<dyn AuditSink>,
    container_id: ContainerId,
    config: NotifyConfig,
    live: Mutex<Option<Live>>,
}

impl std::fmt::Debug for SeccompNotifyHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeccompNotifyHub").finish_non_exhaustive()
    }
}

impl SeccompNotifyHub {
    /// `sink`（`ControlAuditRelay` 等）へ、`container_id` を付けて記録するハブを作る。スレッドはまだ作らない。
    pub fn new(sink: Arc<dyn AuditSink>, container_id: ContainerId, config: NotifyConfig) -> Self {
        Self {
            sink,
            container_id,
            config,
            live: Mutex::new(None),
        }
    }

    /// 新しい listener の監視を始める。直前の監視があれば畳む（呼び出し側は先に [`Self::quiesce`] する）。
    /// スレッドを作れなければ `Err`（`source` は破棄される。呼び出し側がコンテナを回収すること。fail-closed）。
    pub fn attach_source<S: NotifySource>(&self, source: S) -> Result<(), TraitError> {
        self.attach_with(source, Box::new(resolve_pid_from_proc))
    }

    /// [`Self::attach_source`] の pid 変換を差し替える版（試験用）。
    pub fn attach_with<S: NotifySource>(
        &self,
        source: S,
        resolve: PidResolver,
    ) -> Result<(), TraitError> {
        self.quiesce();
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (jobs_tx, jobs_rx) = sync_channel::<Job>(self.config.queue_capacity);
        let thread_err = |_e: std::io::Error| {
            TraitError::new(
                ErrorCode::Unavailable,
                "failed to start the seccomp notification threads",
            )
        };
        let recorder = {
            let sink = Arc::clone(&self.sink);
            let id = self.container_id.clone();
            let counters = Arc::clone(&counters);
            std::thread::Builder::new()
                .name("seccomp-audit-rec".into())
                .spawn(move || recorder_main(&jobs_rx, &sink, &id, &counters))
                .map_err(thread_err)?
        };
        let listener = {
            let config = self.config;
            let counters = Arc::clone(&counters);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("seccomp-notify".into())
                .spawn(move || {
                    listener_main(&source, &resolve, config, &jobs_tx, &counters, &stop);
                    // source（listener fd）と jobs_tx をここで閉じる。以後カーネルは待機中の syscall を ENOSYS にする。
                })
                .map_err(thread_err)
                .inspect_err(|_| {
                    // recorder は sender（jobs_tx）が listener 用の move で作れず残るため、ここで終わらせる手段が無い。
                    // jobs_tx は closure と共に破棄済みなので、recorder の recv は Err で終わる。
                })?
        };
        *self.live.lock().unwrap_or_else(PoisonError::into_inner) = Some(Live {
            stop,
            listener,
            recorder,
            counters,
        });
        Ok(())
    }

    /// 現在の監視を畳み、スレッドを 0 本にする（restart の再 launch の直前。core の launch は `Threads: 1` を要する）。
    /// 旧プロセスは回収済みで listener は `Closed` になり、通常は即座に終わる。間に合わなければ放置して先へ進む
    /// （スレッドが残ると再 launch が `MultiThreaded` で拒否され、restart が失敗として表に出る）。
    pub fn quiesce(&self) {
        let live = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(live) = live {
            stop_and_join(live, QUIESCE_TIMEOUT);
        }
    }

    /// 監視が動いているか（listener を渡し済みか）。start の報告の前に attach 済みなら `run_supervised` は渡し直さない。
    pub fn is_attached(&self) -> bool {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// 監視を `timeout` まで待って畳む。集計を返す（動いていなければ `None`）。supervisor の全終了経路で呼ぶ。
    pub fn finish(&self, timeout: Duration) -> Option<CounterSnapshot> {
        let live = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        live.map(|l| stop_and_join(l, timeout))
    }
}

/// `quiesce` が listener スレッドを待つ上限（旧プロセスは回収済み。REPAIR-5）。
const QUIESCE_TIMEOUT: Duration = Duration::from_secs(2);

/// 停止を要求して 2 本を期限内に回収し、最終の集計を返す。
fn stop_and_join(live: Live, timeout: Duration) -> CounterSnapshot {
    let Live {
        stop,
        listener,
        recorder,
        counters,
    } = live;
    stop.store(true, Ordering::Release);
    let deadline = Instant::now() + timeout;
    let listener_done = join_within(listener, timeout);
    // listener が終わると jobs_tx が閉じ、recorder は残りの依頼を処理して終わる。
    let remaining = deadline.saturating_duration_since(Instant::now());
    let recorder_done = join_within(recorder, remaining.max(Duration::from_millis(50)));
    if !listener_done || !recorder_done {
        let line = "{\"component\":\"supervisor\",\"event\":\"seccomp_notify_join_timeout\"}\n";
        let _ = crate::stderr_sink::stderr().emit(line.as_bytes().to_vec());
    }
    let last = counters.snapshot();
    // listener の最終ログより後に recorder が確定した記録失敗などの増分を、回収後に出す（REPAIR-4）。
    if listener_done {
        let reported = counters
            .reported_at_exit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or_default();
        emit_report(&report_events(last, reported));
    }
    last
}

#[cfg(target_os = "linux")]
mod real {
    use super::{Notified, NotifySource, Ready, Responded, SourceError};
    use fandhe_container_core::exec::{
        DenyOutcome, ListenerReadiness, NotificationId, SeccompListener,
    };
    use std::time::Duration;

    /// core の `SeccompListener` を [`NotifySource`] として使うアダプタ。
    pub struct ListenerSource(pub SeccompListener);

    impl NotifySource for ListenerSource {
        type Id = NotificationId;

        fn wait(&self, timeout: Duration) -> Result<Ready, SourceError> {
            self.0
                .wait(timeout)
                .map(|r| match r {
                    ListenerReadiness::Readable => Ready::Readable,
                    ListenerReadiness::Closed => Ready::Closed,
                    _ => Ready::Idle,
                })
                .map_err(|_| SourceError)
        }

        fn receive(&self) -> Result<Option<(NotificationId, Notified)>, SourceError> {
            self.0
                .receive()
                .map(|n| {
                    n.map(|n| {
                        (
                            n.id(),
                            Notified {
                                pid_in_listener_ns: n.pid_in_listener_ns(),
                                nr: n.nr(),
                                arch: n.arch(),
                            },
                        )
                    })
                })
                .map_err(|_| SourceError)
        }

        fn is_pending(&self, id: NotificationId) -> Result<bool, SourceError> {
            self.0.is_pending(id).map_err(|_| SourceError)
        }

        fn deny_eperm(&self, id: NotificationId) -> Result<Responded, SourceError> {
            self.0
                .deny_eperm(id)
                .map(|o| match o {
                    DenyOutcome::Sent => Responded::Sent,
                    _ => Responded::TargetGone,
                })
                .map_err(|_| SourceError)
        }
    }
}

#[cfg(target_os = "linux")]
impl SeccompNotifyHub {
    /// core が渡した listener の監視を始める（`LaunchedProcess::take_seccomp_listener` の戻り値）。
    pub fn attach(
        &self,
        listener: fandhe_container_core::exec::SeccompListener,
    ) -> Result<(), TraitError> {
        self.attach_source(real::ListenerSource(listener))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Condvar;

    /// 偽の供給元。台本の通知を順に返し、応答を記録する。台本が尽きたら `Closed`。
    struct Fake {
        script: Mutex<VecDeque<Option<(u64, Notified)>>>,
        pending: bool,
        answered: Arc<Mutex<Vec<u64>>>,
        gone_on_send: bool,
        /// 1: wait が失敗する / 2: receive が失敗する。
        fail_at: u8,
    }

    impl Fake {
        fn new(items: Vec<Option<(u64, Notified)>>) -> (Self, Arc<Mutex<Vec<u64>>>) {
            let answered = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    script: Mutex::new(items.into()),
                    pending: true,
                    answered: Arc::clone(&answered),
                    gone_on_send: false,
                    fail_at: 0,
                },
                answered,
            )
        }
    }

    impl NotifySource for Fake {
        type Id = u64;
        fn wait(&self, _t: Duration) -> Result<Ready, SourceError> {
            if self.fail_at == 1 {
                return Err(SourceError);
            }
            if self.script.lock().unwrap().is_empty() {
                Ok(Ready::Closed)
            } else {
                Ok(Ready::Readable)
            }
        }
        fn receive(&self) -> Result<Option<(u64, Notified)>, SourceError> {
            if self.fail_at == 2 {
                return Err(SourceError);
            }
            Ok(self.script.lock().unwrap().pop_front().flatten())
        }
        fn is_pending(&self, _id: u64) -> Result<bool, SourceError> {
            Ok(self.pending)
        }
        fn deny_eperm(&self, id: u64) -> Result<Responded, SourceError> {
            self.answered.lock().unwrap().push(id);
            Ok(if self.gone_on_send {
                Responded::TargetGone
            } else {
                Responded::Sent
            })
        }
    }

    fn n(pid: u32) -> Notified {
        Notified {
            pid_in_listener_ns: pid,
            nr: 312,
            arch: 0xC000_003E,
        }
    }

    /// 記録を集める sink。`gate` が閉じている間は `record` が戻らない。
    #[derive(Default)]
    struct Sink {
        records: Mutex<Vec<AuditRecord>>,
        gate: Mutex<bool>,
        gate_cv: Condvar,
        fail: bool,
    }

    impl Sink {
        fn closed() -> Self {
            Self {
                gate: Mutex::new(true),
                ..Self::default()
            }
        }
        fn open(&self) {
            *self.gate.lock().unwrap() = false;
            self.gate_cv.notify_all();
        }
    }

    impl AuditSink for Sink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            let mut closed = self.gate.lock().unwrap();
            while *closed {
                closed = self.gate_cv.wait(closed).unwrap();
            }
            drop(closed);
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "sink failed"));
            }
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    fn hub(sink: Arc<Sink>, config: NotifyConfig) -> SeccompNotifyHub {
        SeccompNotifyHub::new(sink, ContainerId::new("web-1").unwrap(), config)
    }

    fn identity() -> PidResolver {
        Box::new(Some)
    }

    fn run(
        sink: &Arc<Sink>,
        config: NotifyConfig,
        fake: Fake,
        resolve: PidResolver,
    ) -> CounterSnapshot {
        let h = hub(Arc::clone(sink), config);
        h.attach_with(fake, resolve).unwrap();
        // 台本が尽きると Closed でスレッドが終わる。終わる前に finish（停止要求）を出すと、毎反復の停止確認で
        // 台本を処理し切る前に抜けるので、先に終了を待つ。
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end
            && !h
                .live
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(|l| l.listener.is_finished())
        {
            std::thread::sleep(Duration::from_millis(2));
        }
        h.finish(Duration::from_secs(10)).expect("live")
    }

    /// SEC-4・#2025: 1 件を記録して EPERM で応答する。記録の pid・番号・arch・コンテナ ID を具体値で確かめる。
    #[test]
    fn sec4_2025_one_notification_is_recorded_then_denied() {
        let sink = Arc::new(Sink::default());
        let (fake, answered) = Fake::new(vec![Some((7, n(4242)))]);
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert_eq!(answered.lock().unwrap().as_slice(), &[7]);
        let recs = sink.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].pid().get(), 4242);
        assert_eq!(recs[0].syscall().map(|s| s.get()), Some(312));
        assert_eq!(recs[0].seccomp_arch().map(|a| a.get()), Some(0xC000_003E));
        assert_eq!(
            recs[0].container_id().map(ContainerId::as_str),
            Some("web-1")
        );
        assert_eq!(
            snap,
            CounterSnapshot {
                recorded: 1,
                ..CounterSnapshot::default()
            }
        );
    }

    /// SEC-4: cookie が無効なら記録せず、応答もしない（取り違えない）。`target_gone` は 1。
    #[test]
    fn sec4_2025_invalid_cookie_records_nothing() {
        let sink = Arc::new(Sink::default());
        let (mut fake, answered) = Fake::new(vec![Some((1, n(10)))]);
        fake.pending = false;
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert!(sink.records.lock().unwrap().is_empty());
        assert!(answered.lock().unwrap().is_empty());
        assert_eq!((snap.target_gone, snap.recorded), (1, 0));
    }

    /// SEC-4: pid を変換できなければ記録せずに EPERM で応答し、`pid_unresolved` は 1。
    #[test]
    fn sec4_2025_unresolved_pid_is_denied_without_a_record() {
        let sink = Arc::new(Sink::default());
        let (fake, answered) = Fake::new(vec![Some((3, n(10)))]);
        let snap = run(&sink, NotifyConfig::default(), fake, Box::new(|_| None));
        assert_eq!(answered.lock().unwrap().as_slice(), &[3]);
        assert!(sink.records.lock().unwrap().is_empty());
        assert_eq!(snap.pid_unresolved, 1);
    }

    /// REPAIR-5・#2025: sink が詰まっても期限で EPERM を返し、`late` は 1。ゲートを開けると記録は後から 1 件届く。
    #[test]
    fn repair5_2025_slow_sink_is_answered_at_the_deadline_and_recorded_later() {
        let sink = Arc::new(Sink::closed());
        let (fake, answered) = Fake::new(vec![Some((9, n(55)))]);
        let config = NotifyConfig::default()
            .with_response_deadline(Duration::from_millis(100))
            .unwrap();
        let h = hub(Arc::clone(&sink), config);
        h.attach_with(fake, identity()).unwrap();
        let started = Instant::now();
        while answered.lock().unwrap().is_empty() {
            assert!(started.elapsed() < Duration::from_secs(5), "no response");
            std::thread::sleep(Duration::from_millis(5));
        }
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert!(sink.records.lock().unwrap().is_empty());
        sink.open();
        let snap = h.finish(Duration::from_secs(10)).expect("live");
        assert_eq!((snap.late, snap.recorded), (1, 1));
        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    /// REPAIR-5・#2025: sink が詰まっていても、2 件目の応答は自分の受信から期限以内(1 件目の完了待ちに積まれない)。
    #[test]
    fn repair5_2025_stuck_sink_does_not_delay_the_second_response() {
        let sink = Arc::new(Sink::closed());
        let (fake, answered) = Fake::new(vec![Some((1, n(55))), Some((2, n(56)))]);
        let config = NotifyConfig::default()
            .with_response_deadline(Duration::from_millis(200))
            .unwrap();
        let h = hub(Arc::clone(&sink), config);
        h.attach_with(fake, identity()).unwrap();
        let started = Instant::now();
        while answered.lock().unwrap().len() < 2 {
            assert!(started.elapsed() < Duration::from_secs(5), "no response");
            std::thread::sleep(Duration::from_millis(2));
        }
        let waited = started.elapsed();
        assert!(waited < Duration::from_millis(380), "{waited:?}");
        sink.open();
        let snap = h.finish(Duration::from_secs(10)).expect("live");
        assert_eq!(snap.late, 2);
    }

    /// #2025: sink の失敗は `unrecorded` に数え、応答は止めない。
    #[test]
    fn sec4_2025_sink_failure_is_counted_and_still_denied() {
        let sink = Arc::new(Sink {
            fail: true,
            ..Sink::default()
        });
        let (fake, answered) = Fake::new(vec![Some((5, n(8)))]);
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert_eq!(answered.lock().unwrap().as_slice(), &[5]);
        assert_eq!((snap.unrecorded, snap.recorded), (1, 0));
    }

    /// REPAIR-5・#2025: バースト 2 を超えた分は記録せずに応答し、`suppressed` に数える（全件が応答される）。
    #[test]
    fn repair5_2025_rate_limit_suppresses_records_but_not_responses() {
        let sink = Arc::new(Sink::default());
        let items = (1..=5).map(|i| Some((i, n(100)))).collect();
        let (fake, answered) = Fake::new(items);
        let config = NotifyConfig::default().with_limits(64, 1, 2).unwrap();
        let snap = run(&sink, config, fake, identity());
        assert_eq!(answered.lock().unwrap().len(), 5);
        assert_eq!(snap.recorded, 2);
        assert_eq!(snap.suppressed, 3);
        assert_eq!(sink.records.lock().unwrap().len(), 2);
    }

    /// REPAIR-5: 受信時点で消えていた通知（`None`）と、応答時に消えた対象は `target_gone`。
    #[test]
    fn sec4_2025_vanished_targets_are_counted() {
        let sink = Arc::new(Sink::default());
        let (mut fake, _answered) = Fake::new(vec![None, Some((2, n(9)))]);
        fake.gone_on_send = true;
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert_eq!(snap.target_gone, 2);
    }

    /// REPAIR-5・#2025: キューが満杯なら待たずに応答する（recorder が詰まっても listener は止まらない）。
    #[test]
    fn repair5_2025_full_queue_does_not_block_responses() {
        let sink = Arc::new(Sink::closed());
        let items = (1..=6).map(|i| Some((i, n(100)))).collect();
        let (fake, answered) = Fake::new(items);
        let config = NotifyConfig::default()
            .with_response_deadline(Duration::from_millis(50))
            .unwrap()
            .with_limits(1, 1000, 1000)
            .unwrap();
        let h = hub(Arc::clone(&sink), config);
        h.attach_with(fake, identity()).unwrap();
        let started = Instant::now();
        while answered.lock().unwrap().len() < 6 {
            assert!(started.elapsed() < Duration::from_secs(10), "stalled");
            std::thread::sleep(Duration::from_millis(5));
        }
        sink.open();
        let snap = h.finish(Duration::from_secs(10)).expect("live");
        // 1 件目は recorder が取り（late）、2 件目がキューに入り（late）、残りは満杯で間引かれる。
        assert_eq!(snap.late + snap.suppressed, 6);
        assert!(snap.suppressed >= 3, "{snap:?}");
    }

    /// REPAIR-5: 停止要求で、通知が来ていなくてもスレッドが終わり、`finish` が期限内に戻る。
    #[test]
    fn repair5_2025_stop_ends_an_idle_loop_within_the_deadline() {
        struct Idle;
        impl NotifySource for Idle {
            type Id = u64;
            fn wait(&self, t: Duration) -> Result<Ready, SourceError> {
                std::thread::sleep(t);
                Ok(Ready::Idle)
            }
            fn receive(&self) -> Result<Option<(u64, Notified)>, SourceError> {
                Ok(None)
            }
            fn is_pending(&self, _: u64) -> Result<bool, SourceError> {
                Ok(false)
            }
            fn deny_eperm(&self, _: u64) -> Result<Responded, SourceError> {
                Ok(Responded::Sent)
            }
        }
        let sink = Arc::new(Sink::default());
        let h = hub(sink, NotifyConfig::default());
        h.attach_with(Idle, identity()).unwrap();
        let started = Instant::now();
        assert!(h.finish(Duration::from_secs(5)).is_some());
        assert!(started.elapsed() < Duration::from_secs(2));
        // 2 回目は動いていないので None。
        assert!(h.finish(Duration::from_secs(1)).is_none());
    }

    /// REPAIR-5: 応答の期限は 0 と 5 秒超を拒否する。
    #[test]
    fn repair5_2025_deadline_bounds_are_enforced() {
        for d in [Duration::ZERO, Duration::from_secs(6)] {
            let e = NotifyConfig::default()
                .with_response_deadline(d)
                .unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
        assert!(
            NotifyConfig::default()
                .with_response_deadline(MAX_RESPONSE_DEADLINE)
                .is_ok()
        );
    }

    /// SEC-4・REPAIR-2: `NSpid` の末尾（対象自身の namespace の pid）だけを採る。壊れた値・0・欠落は `None`。
    #[test]
    fn sec4_2025_nspid_parsing() {
        assert_eq!(
            parse_nspid_innermost("Name:\tx\nNSpid:\t4242\t17\t1\nUmask:\t0022\n"),
            Some(1)
        );
        assert_eq!(parse_nspid_innermost("NSpid:\t77\n"), Some(77));
        assert_eq!(parse_nspid_innermost("NSpid:\t77\t0\n"), None);
        assert_eq!(parse_nspid_innermost("NSpid:\t77\tabc\n"), None);
        assert_eq!(parse_nspid_innermost("NSpid:\n"), None);
        assert_eq!(parse_nspid_innermost("Pid:\t1\n"), None);
        assert_eq!(parse_nspid_innermost("NSpid:\t-3\n"), None);
        assert_eq!(parse_nspid_innermost("NSpid:\t99999999999\n"), None);
    }

    /// トークンバケットは時間経過で補充され、バースト以上には溜まらない。
    #[test]
    fn sec4_2025_bucket_refills_with_time_and_caps_at_burst() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10, 2, t0);
        assert!(b.take(t0));
        assert!(b.take(t0));
        assert!(!b.take(t0));
        // 100 ms で 1 トークン。
        assert!(b.take(t0 + Duration::from_millis(100)));
        assert!(!b.take(t0 + Duration::from_millis(100)));
        // 長く待ってもバースト（2）まで。
        let later = t0 + Duration::from_secs(60);
        assert!(b.take(later));
        assert!(b.take(later));
        assert!(!b.take(later));
    }

    /// REPAIR-4・#2025: wait / receive の失敗は正常な Closed と区別して数える。
    #[test]
    fn repair4_2025_source_failures_are_counted_separately_from_close() {
        let sink = Arc::new(Sink::default());
        let (mut fake, _a) = Fake::new(vec![Some((1, n(10)))]);
        fake.fail_at = 1;
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert_eq!((snap.wait_failed, snap.receive_failed), (1, 0));
        let (mut fake, _a) = Fake::new(vec![Some((1, n(10)))]);
        fake.fail_at = 2;
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert_eq!((snap.wait_failed, snap.receive_failed), (0, 1));
        let (fake, _a) = Fake::new(vec![]);
        let snap = run(&sink, NotifyConfig::default(), fake, identity());
        assert_eq!((snap.wait_failed, snap.receive_failed), (0, 0));
    }

    /// 構造化ログの語彙は固定で、増分のあるものだけを出す。
    #[test]
    fn sec4_2025_report_events_are_fixed_vocabulary_deltas() {
        let prev = CounterSnapshot {
            suppressed: 2,
            ..CounterSnapshot::default()
        };
        let now = CounterSnapshot {
            suppressed: 5,
            late: 1,
            ..CounterSnapshot::default()
        };
        assert_eq!(
            report_events(now, prev),
            vec![("seccomp_audit_suppressed", 3), ("seccomp_audit_late", 1)]
        );
        assert!(report_events(now, now).is_empty());
    }
}
