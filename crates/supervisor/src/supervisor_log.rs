//! supervisor 自身の構造化ログ（stderr に出す固定スキーマの JSON 1 行）の保存先（TASK-79 追補・#2067・REPAIR-4・REPAIR-5）。
//!
//! CLI の `start` は supervisor の stderr を `Stdio::null()` にする（CLI の stderr は失敗時の 1 行 JSON の契約で、
//! supervisor のログを混ぜない。ERR-2）。そのままでは `start_entry::log_event`・`run::StderrLogObserver`・起動の
//! 計測行がどこにも残らないため、supervisor が自分で状態ルート配下のローテーションログを開き、
//! [`crate::stderr_sink::install_stderr_writer`] で共有の出口（[`crate::stderr_sink`]）の書き先をそこへ差し替える。
//! 特権ランチャー経由の起動（#1719）も最後は同じ `run_main` で開くので、保存先は同じになる。
//!
//! # 保存先と名前
//! - ディレクトリ: `<state_root>/@supervisor-logs/`（unix では 0700）。`@` で始まる名前は `ContainerId` にならないため、
//!   core の `FileStateStore` はコンテナ ID として扱わず、コンテナのログ（`<root>/@container-logs`）とも衝突しない
//! - ファイル: [`RotatingFileSink`] の名前空間どおり `<id>.log`（現在）・`.log.1`・`.log.2`（世代）・`.log.lock`（排他）。
//!   記録は 1 行ごとに `stderr <JSON 1 行>`（コンテナログと同じ形式と読み出し入口）
//! - 権限・作成: ファイルは 0600 で `create_new` のみ、既存の現在ログは開かず世代へ退避する。symlink・ディレクトリ・
//!   名前空間の別名があれば何も動かさず拒否する（SEC-1。[`RotatingFileSink::open`] の契約）
//!
//! # 上限とローテーション
//! 1 ファイル [`SUPERVISOR_LOG_FILE_BYTES`]（1 MiB）・[`SUPERVISOR_LOG_GENERATIONS`]（3 世代）で、1 ID あたり最大 3 MiB。
//! 起動のたびに既存の現在ログを 1 世代送る（空なら世代を消費しない）。同じ ID の supervisor が生存中なら flock で
//! 2 本目の open が `FailedPrecondition` になり、稼働中のファイルは動かない。
//!
//! # 書き込みが詰まる・失敗するとき（REPAIR-5）
//! 呼び出し側は `stderr_sink` の有界キューへ `try_send` するだけで、満杯なら捨てる。ファイルへの書き込みが失敗
//! （ENOSPC・EIO 等）すると sink は失敗状態に固定され、以後の書き込みはすぐ `Err` になる。`stderr_sink` の専用スレッドが
//! 失敗行を数えて続けるだけで、監視・回収・restart の経路は止まらない。FS が止まって書き込みが戻らない場合に止まる
//! のも専用スレッドだけで、呼び出し側の待ちは期限つき。
//!
//! # 後始末
//! [`remove_guarded_bounded_waiting`] が delete 時に best effort で全ファイルを消す（stderr へ何も書かない。ERR-2）。消せなかった分は
//! 1 ID あたり 3 MiB に収まり、同じ ID の次の start で世代として回される。CLI の `delete` は
//! [`remove_guarded_bounded_waiting`] で、ロック保持中（`stop` 直後の drain 中）だけ期限つきで待つ（#2892）。
//! plugin-cri の `RemoveContainer` も同じ関数で、コンテナログと待ちを共有する（#2964）。
//!
//! # 未実装・残余（REPAIR-3）
//! 保存されるのは `stderr_sink` を通る構造化ログだけ。次は fd 2 へ直接書かれ、CLI 起動では null、ランチャー経由では
//! 呼び出し元の fd 2 を継承する: core の `writeln!(stderr)`（`rootless`・`exec/process`）・監査 sink の stderr
//! フォールバック・panic のメッセージ。core の `exec::diagnostic::emit_diagnostic_line`（`legacy_tiocsti` の警告）は
//! fd 2 が AF_UNIX のソケットのときだけ書くため、保存先には届かない。
//! `legacy_tiocsti` の警告は #2008 の決定で、start の成功後に supervisor が自分で観測し（`start_entry`）、
//! `stderr_sink` 経由で本ログへ 1 行残す（core の fd 2 経路は AF_UNIX の socket のときだけ届き、その構成では重複する）。
//!
//! 呼び出し元: `start_entry::run_main_inner`（open と差し込み）・CLI の `delete` と plugin-cri の `RemoveContainer`（[`remove_guarded_bounded_waiting`]）。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

use crate::logs::rotating::{DEFAULT_LOG_FILE_BYTES, RemovedLogs};
use crate::logs::{LogSink, RotatingFileSink, RotationConfig, StreamKind};

/// 状態ルート直下の保存先ディレクトリ名（`ContainerId` にならない `@` 始まり）。
pub const SUPERVISOR_LOG_DIR_NAME: &str = "@supervisor-logs";
/// 1 ファイルの上限バイト数（コンテナログの既定と同じ 1 MiB）。
pub const SUPERVISOR_LOG_FILE_BYTES: u64 = DEFAULT_LOG_FILE_BYTES;
/// 保持する世代数（現在ログを含む）。
pub const SUPERVISOR_LOG_GENERATIONS: u32 = 3;

/// 保存先ディレクトリのパス（作成はしない）。
pub fn log_dir(root: &Path) -> PathBuf {
    root.join(SUPERVISOR_LOG_DIR_NAME)
}

/// `stderr_sink` の書き手として使う、[`LogSink`] へ行を流すアダプタ。
///
/// 書き込まれたバイト列を LF で割り、空でない区切りごとに 1 行として `append` する（末尾に LF が無い区切りも 1 行）。
/// 失敗は固定文言の `io::Error` にし、パス・errno を含めない（ERR-1）。
pub struct SupervisorLogWriter {
    sink: Arc<dyn LogSink>,
}

impl SupervisorLogWriter {
    /// 任意の sink を包む（試験で失敗・停止する sink を渡す入口）。
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        Self { sink }
    }
}

impl Write for SupervisorLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for seg in buf.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
            self.sink
                .append(StreamKind::Stderr, seg)
                .map_err(|_| std::io::Error::other("supervisor log write failed"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink
            .flush()
            .map_err(|_| std::io::Error::other("supervisor log flush failed"))
    }
}

/// 保存先ディレクトリを（無ければ 0700 で）作り、`id` のローテーションログを開いて書き手を返す。
///
/// 既存のディレクトリの検証（symlink・種別・権限）は [`RotatingFileSink::open`] が行う。同じ ID の supervisor が
/// 生存中なら `FailedPrecondition`。スレッドは作らない（`start_entry` の手順 2 の単一スレッド前提）。
pub fn open(root: &Path, id: &ContainerId) -> Result<SupervisorLogWriter, TraitError> {
    let config = RotationConfig::new(SUPERVISOR_LOG_FILE_BYTES, SUPERVISOR_LOG_GENERATIONS)?;
    open_with_config(root, id, config)
}

fn open_with_config(
    root: &Path,
    id: &ContainerId,
    config: RotationConfig,
) -> Result<SupervisorLogWriter, TraitError> {
    let dir = log_dir(root);
    create_dir(&dir)?;
    let sink = RotatingFileSink::open(&dir, id, config)?;
    Ok(SupervisorLogWriter::new(Arc::new(sink)))
}

fn create_dir(dir: &Path) -> Result<(), TraitError> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        b
    };
    // unix 以外ではモード指定が無く、変更しないので mut を付けない（unused_mut 回避）。
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    match builder.create(dir) {
        Ok(()) => Ok(()),
        // 既存の検証（symlink・種別・権限）は RotatingFileSink::open の check_dir に任せる。
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(TraitError::new(
            ErrorCode::Internal,
            "failed to create the supervisor log directory",
        )),
    }
}

/// `id` の supervisor ログ（現在ログ・世代・ロック）を消す（stderr へは何も書かない）。
///
/// ディレクトリが無ければ 0 件で成功する（冪等）。同じ ID の supervisor が生存中なら `FailedPrecondition` で何も消さない。
pub fn remove(root: &Path, id: &ContainerId) -> Result<RemovedLogs, TraitError> {
    let dir = log_dir(root);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => RotatingFileSink::remove_all_quiet(&dir, id),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RemovedLogs::default()),
        Err(_) => Err(TraitError::new(
            ErrorCode::Internal,
            "supervisor log directory inspection failed",
        )),
    }
}

/// [`remove`] に、ロック取得後・削除前の確認 `guard` を足したもの（#2892・SUP-7・REPAIR-5）。
///
/// `guard` が `false`（同じ ID が再作成済み）なら何も消さず 0 件で成功する。確認はロック保持中に行うため、待ちの間に
/// 再作成された別インスタンスの supervisor ログを消さない。ディレクトリが無ければ 0 件で成功する。
pub fn remove_guarded(
    root: &Path,
    id: &ContainerId,
    guard: &dyn Fn() -> bool,
) -> Result<RemovedLogs, TraitError> {
    let dir = log_dir(root);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => RotatingFileSink::remove_all_quiet_guarded(&dir, id, guard),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RemovedLogs::default()),
        Err(_) => Err(TraitError::new(
            ErrorCode::Internal,
            "supervisor log directory inspection failed",
        )),
    }
}

/// [`remove_guarded`] を作業スレッドで `timeout` までだけ待って 1 回試す（#2892・REPAIR-5）。
///
/// 枠の満杯（何も実行していない）は `ResourceExhausted`、期限切れ・起動失敗・panic は `Timeout`（コンテナログの
/// `remove_container_logs_guarded_bounded` と同じ分類）。
pub fn remove_guarded_bounded(
    root: &Path,
    id: &ContainerId,
    timeout: std::time::Duration,
    guard: impl Fn() -> bool + Send + 'static,
) -> Result<RemovedLogs, TraitError> {
    let root = root.to_path_buf();
    let id = id.clone();
    run_bounded_classified(move || remove_guarded(&root, &id, &guard), timeout).unwrap_or_else(
        |f| {
            Err(match f {
                BoundedFailure::Busy => TraitError::new(
                    ErrorCode::ResourceExhausted,
                    "supervisor log removal workers are busy",
                ),
                BoundedFailure::Unfinished => TraitError::new(
                    ErrorCode::Timeout,
                    "supervisor log removal did not finish within the deadline",
                ),
            })
        },
    )
}

/// [`remove_guarded_bounded`] を、`FailedPrecondition`（同じ ID の supervisor がログのロックを保持中）のあいだ
/// `lock_wait` まで試し直す版（CLI の `delete` 用。#2892・SUP-7・CLI-1・REPAIR-5）。
///
/// `stop` 直後は supervisor が `Stopped` の記録後も drain を続け、プロセス終了までロックを持つ。待ちは呼び出し元
/// スレッドの sleep（[`crate::logs::CONTAINER_LOG_LOCK_POLL`] 刻み）だけで、同時実行枠は試行の間しか使わない。
/// 試し直すのは `FailedPrecondition` だけで、他のエラーは即座に返す。`lock_wait` が 0 なら 1 回だけ試す。
/// 最悪の所要は `lock_wait` + `attempt_timeout`。plugin-cri の `RemoveContainer` も使う（#2964）。
pub fn remove_guarded_bounded_waiting(
    root: &Path,
    id: &ContainerId,
    lock_wait: std::time::Duration,
    attempt_timeout: std::time::Duration,
    guard: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Result<RemovedLogs, TraitError> {
    let started = std::time::Instant::now();
    loop {
        let g = Arc::clone(&guard);
        let result = remove_guarded_bounded(root, id, attempt_timeout, move || g());
        match &result {
            Err(e) if e.code() == ErrorCode::FailedPrecondition => {
                let Some(remaining) = lock_wait
                    .checked_sub(started.elapsed())
                    .filter(|r| !r.is_zero())
                else {
                    return result;
                };
                std::thread::sleep(crate::logs::CONTAINER_LOG_LOCK_POLL.min(remaining));
            }
            _ => return result,
        }
    }
}

/// ログ削除を待つ既定の上限。ローカル FS の小さなファイル数個（世代数 × 3 MiB 以下）の unlink には十分長く、
/// I/O 停止（NFS ハング等）でも呼び出し元が秒単位で戻れる値にする（REPAIR-5）。
pub const SUPERVISOR_LOG_REMOVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// ログ削除を期限つきで試した結果（REPAIR-5）。
#[derive(Debug, PartialEq, Eq)]
pub enum LogRemoval {
    /// 期限内に終わった（削除自体の成否は問わない。best effort）。
    Finished,
    /// 期限内に終わらなかった。作業スレッドは I/O で止まったまま残る。
    TimedOut,
    /// 同時実行枠が満杯で、作業スレッドを起動しなかった（削除は試していない。期限切れではない。#2894・ERR-1）。
    Busy,
}

/// 同時に走らせる削除作業スレッドの上限。枠は期限切れではなく作業の実終了まで保持する（REPAIR-5）。
const MAX_INFLIGHT_LOG_REMOVALS: usize = 8;

/// 実行中の削除作業の数（常駐する plugin-cri の `delete` で I/O 停止時にスレッドが無制限に増えるのを防ぐ）。
static INFLIGHT_LOG_REMOVALS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// 作業スレッドが終わる（panic を含む）ときに枠を返す。
struct InflightSlot;

impl InflightSlot {
    /// 枠が空いていれば確保する。満杯なら `None`。
    fn acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        INFLIGHT_LOG_REMOVALS
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_INFLIGHT_LOG_REMOVALS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for InflightSlot {
    fn drop(&mut self) {
        INFLIGHT_LOG_REMOVALS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// `job` を作業スレッドで実行し、`timeout` までだけ待つ。呼び出し元スレッドは削除 I/O で止まらない。
///
/// 期限切れのとき作業スレッドは join せず残す（止まった I/O を中断する手段は無く、待てば呼び出し元が無期限に戻らなく
/// なるため）。残るスレッドは `MAX_INFLIGHT_LOG_REMOVALS` 個までで、枠は作業の実終了まで保持する。枠が埋まっている
/// ときは best effort として削除を諦め、スレッドを起動せず `Busy` を返す（期限切れの `TimedOut` とは区別する。#2894・REPAIR-5）。
/// スレッドを起動できなかった場合は削除を諦めて `Finished` 扱いにする（同期実行へ退避しない。ブロックし得るため）。
/// CLI の `delete` の警告出力の期限（`emit_warning_bounded`）も同じ仕組みを使う（#2434 で CLI から移設）。
pub fn run_log_removal_bounded(
    job: impl FnOnce() + Send + 'static,
    timeout: std::time::Duration,
) -> LogRemoval {
    // 起動失敗・job の panic（`NoResult`）は、同期実行へ退避せず結果の無い job として `Finished` に畳む。
    match run_bounded_inner(job, timeout) {
        BoundedOutcome::TimedOut => LogRemoval::TimedOut,
        BoundedOutcome::Busy => LogRemoval::Busy,
        BoundedOutcome::NoResult | BoundedOutcome::Done(()) => LogRemoval::Finished,
    }
}

/// [`run_log_removal_bounded`]・[`run_bounded_classified`]・`run_bounded_waiting` が共有する内部結果。結果が無い理由（起動失敗・job の panic）を期限切れと区別するために持つ。
enum BoundedOutcome<T> {
    Done(T),
    TimedOut,
    /// 同時実行枠が満杯でスレッドを起動しなかった（期限切れではない。#2760）。
    Busy,
    NoResult,
}

fn run_bounded_inner<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
    timeout: std::time::Duration,
) -> BoundedOutcome<T> {
    let Some(slot) = InflightSlot::acquire() else {
        return BoundedOutcome::Busy;
    };
    run_bounded_with_slot(slot, job, timeout)
}

/// 確保済みの枠で `job` を作業スレッドへ渡し、`timeout` までだけ待つ（枠は作業の実終了まで保持する）。
fn run_bounded_with_slot<T: Send + 'static>(
    slot: InflightSlot,
    job: impl FnOnce() -> T + Send + 'static,
    timeout: std::time::Duration,
) -> BoundedOutcome<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("supervisor-log-remove".to_string())
        .spawn(move || {
            let _slot = slot;
            let _ = tx.send(job());
        });
    let Ok(handle) = spawned else {
        return BoundedOutcome::NoResult;
    };
    match rx.recv_timeout(timeout) {
        Ok(v) => {
            // 結果送信後の作業スレッドが生きたまま戻ると、呼び出し元が単一スレッド前提の処理
            // （`FileAuditSink` の fork。SEC-4）へ進めなくなる。終了を有限時間だけ確かめ、確認できなければ
            // 結果を捨てて期限切れ扱いにする（fail-closed。REPAIR-5）。
            if join_worker_bounded(handle) {
                BoundedOutcome::Done(v)
            } else {
                BoundedOutcome::TimedOut
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => BoundedOutcome::TimedOut,
        // job の panic（結果を送らず終了）。従来どおり「終わった」扱いだが、値は無い。
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = join_worker_bounded(handle);
            BoundedOutcome::NoResult
        }
    }
}

/// 結果送信後の作業スレッドの終了を待つ上限（送信後は枠の返却だけで即終わるため短くてよい。REPAIR-5）。
const WORKER_EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// 作業スレッドが `WORKER_EXIT_GRACE` 内に終了したら join して `true`。終わらなければ join せず `false`。
fn join_worker_bounded(handle: std::thread::JoinHandle<()>) -> bool {
    let deadline = std::time::Instant::now() + WORKER_EXIT_GRACE;
    while !handle.is_finished() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = handle.join();
    true
}

/// [`run_bounded_classified`] が結果を得られなかった理由（#2760・REPAIR-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedFailure {
    /// 同時実行枠が満杯で、作業スレッドを起動しなかった（何も実行していない）。
    Busy,
    /// 期限切れ、スレッド起動失敗、または job の panic（作業スレッドが残り得る）。
    Unfinished,
}

/// `job` を作業スレッドで実行して結果を持ち帰る期限つき実行で、枠の満杯とそれ以外の失敗を区別する（#2446・#2760）。
/// [`run_log_removal_bounded`] の汎用版で、枠（`MAX_INFLIGHT_LOG_REMOVALS`）は supervisor ログの削除と共有する。
/// 枠の満杯は即時に `Busy`、期限切れ・スレッド起動失敗・job の panic は `Unfinished`。枠を待つ場合は
/// `run_bounded_waiting` を使う。両者を `None` に潰す `Option` 版は誤分類を呼ぶため削除済み（#2965）。
///
/// 枠が満杯なら job は実行されず `Busy`。長寿命の plugin-cri で、止まった作業が枠を埋めたことと、この job 自身の
/// 期限切れを同じ失敗として扱わないために使う。
pub fn run_bounded_classified<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
    timeout: std::time::Duration,
) -> Result<T, BoundedFailure> {
    match run_bounded_inner(job, timeout) {
        BoundedOutcome::Done(v) => Ok(v),
        BoundedOutcome::Busy => Err(BoundedFailure::Busy),
        BoundedOutcome::TimedOut | BoundedOutcome::NoResult => Err(BoundedFailure::Unfinished),
    }
}

/// 枠が空くのを待つときの再試行間隔（枠の返却は作業スレッドの終了で、短い作業なら数 ms で空くため短くてよい）。
const SLOT_WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// [`run_bounded_classified`] の、枠の満杯を `timeout` の範囲で待つ版（#2834・REPAIR-5）。
///
/// 枠が満杯でも即座に `Busy` にせず、`timeout` を上限に `SLOT_WAIT_POLL` 間隔で空きを待つ。待った時間は `timeout` から
/// 引かれるので、全体の待ちは `timeout` を超えない（期限を延ばさない）。待っても空かなければ job を実行せず `Busy`
/// （期限切れ `Unfinished` とは区別する）。CLI の `create` が 1 プロセスの中で複数の作業を同時に走らせる場面
/// （並列の結合試験・止まった作業が枠を占めた後）で、一時的な満杯を `TIMEOUT` に誤分類しないために使う。
/// 常駐の plugin-cri が使う即時 `Busy` の [`run_bounded_classified`]（#2760）は変えない。
pub fn run_bounded_waiting<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
    timeout: std::time::Duration,
) -> Result<T, BoundedFailure> {
    let started = std::time::Instant::now();
    // 枠の確保の前後に毎回残り時間を確認する。期限が尽きていれば（最後の sleep 中に過ぎた場合を含む）
    // 作業スレッドを生成せず `Busy` を返す（期限切れ後に job の副作用を走らせない。REPAIR-5）。
    let (slot, remaining) = loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(BoundedFailure::Busy);
        }
        if let Some(slot) = InflightSlot::acquire() {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                // 確保後に期限が尽きた: 枠を返して job を起動しない。
                drop(slot);
                return Err(BoundedFailure::Busy);
            }
            break (slot, remaining);
        }
        std::thread::sleep(SLOT_WAIT_POLL.min(remaining));
    };
    match run_bounded_with_slot(slot, job, remaining) {
        BoundedOutcome::Done(v) => Ok(v),
        BoundedOutcome::Busy => Err(BoundedFailure::Busy),
        BoundedOutcome::TimedOut | BoundedOutcome::NoResult => Err(BoundedFailure::Unfinished),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::logs::rotating::MIN_LOG_FILE_BYTES;
    use crate::stderr_sink::{EmitOutcome, StderrSink};

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-2067-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn id() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// REPAIR-4: ディレクトリは 0700、ログは 0600、ロックが作られる。
    #[test]
    fn repair4_open_creates_dir_0700_and_log_0600() {
        let t = TmpDir::new("perm");
        let _w = open(&t.0, &id()).unwrap();
        let dir = t.0.join("@supervisor-logs");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("c1.log")), 0o600);
        assert!(dir.join("c1.log.lock").exists());
    }

    /// REPAIR-4: LF 区切りの各行が `stderr <行>` で記録され、空の write は何も書かない。
    #[test]
    fn repair4_writer_records_stderr_prefixed_lines() {
        let t = TmpDir::new("lines");
        let mut w = open(&t.0, &id()).unwrap();
        w.write_all(b"").unwrap();
        w.write_all(b"{\"a\":1}\n{\"b\":2}\n").unwrap();
        w.write_all(b"{\"c\":3}").unwrap();
        w.flush().unwrap();
        let body = fs::read_to_string(t.0.join("@supervisor-logs/c1.log")).unwrap();
        assert_eq!(
            body,
            "stderr {\"a\":1}\nstderr {\"b\":2}\nstderr {\"c\":3}\n"
        );
    }

    /// SEC-1: 保存先ディレクトリが symlink なら拒否し、リンク先に何も作らない。
    #[test]
    fn sec1_open_rejects_symlinked_dir() {
        let t = TmpDir::new("symdir");
        let target = t.0.join("elsewhere");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, t.0.join("@supervisor-logs")).unwrap();
        let e = open(&t.0, &id()).err().expect("must be rejected");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    /// SEC-1: 現在ログが symlink なら拒否し、リンク先の内容は変わらない。
    #[test]
    fn sec1_open_rejects_symlink_log() {
        let t = TmpDir::new("symlog");
        let dir = t.0.join("@supervisor-logs");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = t.0.join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("c1.log")).unwrap();
        let e = open(&t.0, &id()).err().expect("must be rejected");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
    }

    /// SUP-7: 内容のある既存の現在ログは世代 1 へ移り、新しい現在ログは空になる。
    #[test]
    fn sup7_open_rotates_existing_log() {
        let t = TmpDir::new("rot");
        let dir = t.0.join("@supervisor-logs");
        {
            let mut w = open(&t.0, &id()).unwrap();
            w.write_all(b"old\n").unwrap();
            w.flush().unwrap();
        }
        let _w = open(&t.0, &id()).unwrap();
        assert_eq!(fs::read(dir.join("c1.log.1")).unwrap(), b"stderr old\n");
        assert_eq!(fs::metadata(dir.join("c1.log")).unwrap().len(), 0);
    }

    /// REPAIR-5: 上限を超える書き込みでも全ファイルが上限以内で、ファイル数は世代数以内。
    #[test]
    fn repair5_size_cap() {
        let t = TmpDir::new("cap");
        let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 2).unwrap();
        let mut w = open_with_config(&t.0, &id(), cfg).unwrap();
        let line = vec![b'x'; 1000];
        for _ in 0..200 {
            w.write_all(&line).unwrap();
        }
        w.flush().unwrap();
        let dir = t.0.join("@supervisor-logs");
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".lock"))
            .collect();
        names.sort();
        assert_eq!(names, ["c1.log", "c1.log.1"]);
        for n in names {
            assert!(fs::metadata(dir.join(n)).unwrap().len() <= MIN_LOG_FILE_BYTES);
        }
    }

    /// SUP-7: 1 本目が生きている間の 2 本目は FailedPrecondition で、既存ファイルを動かさない。
    #[test]
    fn sup7_second_open_while_alive_is_failed_precondition() {
        let t = TmpDir::new("second");
        let mut w = open(&t.0, &id()).unwrap();
        w.write_all(b"live\n").unwrap();
        w.flush().unwrap();
        let e = open(&t.0, &id()).err().expect("must be rejected");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        let dir = t.0.join("@supervisor-logs");
        assert_eq!(fs::read(dir.join("c1.log")).unwrap(), b"stderr live\n");
        assert!(!dir.join("c1.log.1").exists());
    }

    /// REPAIR-4: remove は全ファイルを消し冪等。生存中は FailedPrecondition で何も消さない。
    /// REPAIR-5: 枠が埋まっているとスレッドを起動せず Busy を返し(期限切れの TimedOut とは別。#2894)、実終了で枠が戻る。
    #[test]
    fn repair5_inflight_cap_gives_up_and_releases_on_finish() {
        let slots: Vec<_> = std::iter::from_fn(InflightSlot::acquire).collect();
        assert!(!slots.is_empty());
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = Arc::clone(&ran);
        let out = run_log_removal_bounded(
            move || r.store(true, Ordering::SeqCst),
            Duration::from_millis(50),
        );
        assert_eq!(out, LogRemoval::Busy);
        assert!(!ran.load(Ordering::SeqCst));
        drop(slots);
        assert_eq!(
            run_log_removal_bounded(|| {}, Duration::from_secs(5)),
            LogRemoval::Finished
        );
    }

    #[test]
    fn repair4_remove_deletes_all_and_is_idempotent() {
        let t = TmpDir::new("rm");
        assert_eq!(remove(&t.0, &id()).unwrap().log_files(), 0);
        let dir = t.0.join("@supervisor-logs");
        {
            let mut w = open(&t.0, &id()).unwrap();
            w.write_all(b"a\n").unwrap();
            w.flush().unwrap();
            let e = remove(&t.0, &id()).expect_err("alive");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert!(dir.join("c1.log").exists());
        }
        // 現在ログ（空）と世代 1（"a"）を持つ状態を作ってから消す。
        drop(open(&t.0, &id()).unwrap());
        assert_eq!(remove(&t.0, &id()).unwrap().log_files(), 2);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(remove(&t.0, &id()).unwrap().log_files(), 0);
    }

    struct FailingSink;

    impl LogSink for FailingSink {
        fn append(&self, _s: StreamKind, _l: &[u8]) -> Result<(), TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "log write failed"))
        }
    }

    /// 解放されるまで `append` が戻らない sink。
    struct StuckSink(std::sync::Mutex<std::sync::mpsc::Receiver<()>>);

    impl LogSink for StuckSink {
        fn append(&self, _s: StreamKind, _l: &[u8]) -> Result<(), TraitError> {
            let _ = self.0.lock().unwrap().recv();
            Ok(())
        }
    }

    /// REPAIR-5: 書き込みが失敗しても呼び出し側は待たず、失敗は行数つきで返る。
    #[test]
    fn repair5_failing_log_sink_does_not_block() {
        let w = SupervisorLogWriter::new(Arc::new(FailingSink));
        let sink = StderrSink::spawn(w, 8);
        let started = Instant::now();
        assert_eq!(sink.emit(b"{}\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(
            sink.flush(Duration::from_secs(5)),
            EmitOutcome::WriteFailed { failed_lines: 1 }
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// REPAIR-5: 書き込みが戻らなくても `emit` は待たず、`emit_and_wait` は期限で打ち切られる。
    #[test]
    fn repair5_stuck_log_sink_does_not_block_callers() {
        let (release, rx) = std::sync::mpsc::channel();
        let w = SupervisorLogWriter::new(Arc::new(StuckSink(std::sync::Mutex::new(rx))));
        let sink = StderrSink::spawn(w, 8);
        let started = Instant::now();
        assert_eq!(sink.emit(b"{}\n".to_vec()), EmitOutcome::Queued);
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(
            sink.emit_and_wait(b"{}\n".to_vec(), Duration::from_millis(200)),
            EmitOutcome::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(release);
    }

    fn container_sink(root: &Path, name: &str) -> crate::logs::RotatingFileSink {
        let dir = crate::logs::container_log_dir(root);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let id = ContainerId::new(name).unwrap();
        let sink = crate::logs::RotatingFileSink::open(
            &dir,
            &id,
            crate::logs::container_log_rotation_config(),
        )
        .unwrap();
        // 空の現在ログは次の open で世代へ退避されないため、内容を書いて確定させる。
        crate::logs::LogSink::append(&sink, crate::logs::StreamKind::Stdout, b"x").unwrap();
        crate::logs::LogSink::flush(&sink).unwrap();
        sink
    }

    fn sorted_names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// SUP-7・#2446: 対象 ID の現在ログ・世代・ロックだけが消え、他の ID のログは残る。
    #[test]
    fn sup7_remove_container_logs_removes_only_target() {
        let t = TmpDir::new("rmc");
        let dir = crate::logs::container_log_dir(&t.0);
        drop(container_sink(&t.0, "c1"));
        drop(container_sink(&t.0, "c1"));
        drop(container_sink(&t.0, "c2"));
        assert_eq!(
            sorted_names(&dir),
            ["c1.log", "c1.log.1", "c1.log.lock", "c2.log", "c2.log.lock"]
        );
        let removed = crate::logs::remove_container_logs(&t.0, &id()).unwrap();
        assert_eq!(removed.log_files(), 2);
        assert_eq!(sorted_names(&dir), ["c2.log", "c2.log.lock"]);
    }

    /// SUP-7・#2446: sink 生存中は `FailedPrecondition` で何も消さない。
    #[test]
    fn sup7_remove_container_logs_refuses_while_sink_alive() {
        let t = TmpDir::new("rmalive");
        let dir = crate::logs::container_log_dir(&t.0);
        let _sink = container_sink(&t.0, "c1");
        let e = crate::logs::remove_container_logs(&t.0, &id()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(sorted_names(&dir), ["c1.log", "c1.log.lock"]);
    }

    /// SUP-7・#2446: 確認 `guard` が `false`（同じ ID が再作成済み）なら何も消さず、ロックファイルだけ掃除する。
    /// `guard` はロック保持中に評価される（評価中は別の sink が同じ ID を開けない）。
    #[test]
    fn sup7_remove_container_logs_guard_false_keeps_logs_and_holds_lock() {
        let t = TmpDir::new("rmguard");
        let dir = crate::logs::container_log_dir(&t.0);
        drop(container_sink(&t.0, "c1"));
        drop(container_sink(&t.0, "c1"));
        let root = t.0.clone();
        let removed = crate::logs::remove_container_logs_guarded(&t.0, &id(), &|| {
            // 評価中に同じ ID の sink を開こうとしてもロックで拒否される。
            let e = crate::logs::RotatingFileSink::open(
                &crate::logs::container_log_dir(&root),
                &id(),
                crate::logs::container_log_rotation_config(),
            );
            assert!(e.is_err());
            false
        })
        .unwrap();
        assert_eq!(removed.log_files(), 0);
        assert_eq!(sorted_names(&dir), ["c1.log", "c1.log.1"]);
    }

    /// SUP-7・#2446: `guard` が `true` なら従来どおり消す。
    #[test]
    fn sup7_remove_container_logs_guard_true_removes() {
        let t = TmpDir::new("rmguardtrue");
        let dir = crate::logs::container_log_dir(&t.0);
        drop(container_sink(&t.0, "c1"));
        let removed = crate::logs::remove_container_logs_guarded_bounded(
            &t.0,
            &id(),
            Duration::from_secs(10),
            || true,
        )
        .unwrap();
        assert_eq!(removed.log_files(), 1);
        assert_eq!(sorted_names(&dir), Vec::<String>::new());
    }

    /// SUP-7・CRI-2・#2634: sink が待ちの途中で閉じれば、試し直して消せる。
    #[test]
    fn sup7_waiting_removes_after_sink_released() {
        let t = TmpDir::new("waitok");
        let dir = crate::logs::container_log_dir(&t.0);
        let sink = container_sink(&t.0, "c1");
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(sink);
        });
        let removed = crate::logs::remove_container_logs_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Arc::new(|| true),
        )
        .unwrap();
        h.join().unwrap();
        assert_eq!(removed.log_files(), 1);
        assert_eq!(sorted_names(&dir), Vec::<String>::new());
    }

    /// REPAIR-5・#2634: sink が閉じなければ期限で `FailedPrecondition` になり、何も消さない。
    #[test]
    fn repair5_waiting_gives_up_after_deadline() {
        let t = TmpDir::new("waitdl");
        let dir = crate::logs::container_log_dir(&t.0);
        let _sink = container_sink(&t.0, "c1");
        let started = Instant::now();
        let e = crate::logs::remove_container_logs_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::from_millis(150),
            Duration::from_secs(5),
            Arc::new(|| true),
        )
        .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
        assert!(
            elapsed < Duration::from_millis(150) + Duration::from_secs(1),
            "{elapsed:?}"
        );
        assert_eq!(sorted_names(&dir), ["c1.log", "c1.log.lock"]);
    }

    /// SUP-7・#2634: `lock_wait` が 0 なら 1 回だけ試す。
    #[test]
    fn sup7_waiting_zero_wait_is_single_attempt() {
        let t = TmpDir::new("waitzero");
        let _sink = container_sink(&t.0, "c1");
        let started = Instant::now();
        let e = crate::logs::remove_container_logs_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::ZERO,
            Duration::from_secs(5),
            Arc::new(|| true),
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    /// SUP-7・#2634: `guard` が `false` なら 0 件で成功し、試し直さない（guard は 1 回だけ評価される）。
    #[test]
    fn sup7_waiting_guard_false_does_not_retry() {
        use std::sync::atomic::AtomicUsize;
        let t = TmpDir::new("waitguard");
        drop(container_sink(&t.0, "c1"));
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let removed = crate::logs::remove_container_logs_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Arc::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
                false
            }),
        )
        .unwrap();
        assert_eq!(removed.log_files(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// SUP-7・#2446: ディレクトリが無ければ 0 件で成功し（冪等）、作らない。
    #[test]
    fn sup7_remove_container_logs_missing_dir_is_ok() {
        let t = TmpDir::new("rmmissing");
        for _ in 0..2 {
            let removed = crate::logs::remove_container_logs_bounded(
                &t.0,
                &id(),
                std::time::Duration::from_secs(10),
            )
            .unwrap();
            assert_eq!(removed.log_files(), 0);
        }
        assert!(!crate::logs::container_log_dir(&t.0).exists());
    }

    /// REPAIR-5・#2446・#2965: `run_bounded_classified` は結果を返し、止まった job は期限で `Unfinished` になる。
    #[test]
    fn repair5_run_bounded_classified_returns_result_or_unfinished() {
        assert_eq!(
            run_bounded_classified(|| 7_u32, Duration::from_secs(10)),
            Ok(7)
        );
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let out = run_bounded_classified(
            move || {
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
                1_u32
            },
            Duration::from_millis(100),
        );
        assert_eq!(out, Err(BoundedFailure::Unfinished));
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(release_tx);
    }

    fn always() -> Arc<dyn Fn() -> bool + Send + Sync> {
        Arc::new(|| true)
    }

    /// SUP-7・REPAIR-5・#2892: ロックを持ち続ける書き手がいると、待ちを使い切って `FailedPrecondition`。ログは残る。
    #[test]
    fn sup7_repair5_waiting_keeps_logs_when_lock_held() {
        let t = TmpDir::new("waitheld");
        let _w = open(&t.0, &id()).unwrap();
        let started = Instant::now();
        let e = remove_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::from_millis(200),
            Duration::from_secs(5),
            always(),
        )
        .expect_err("held");
        let elapsed = started.elapsed();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        let dir = t.0.join("@supervisor-logs");
        assert!(dir.join("c1.log").exists());
        assert!(dir.join("c1.log.lock").exists());
    }

    /// SUP-7・#2892: 書き手が待ちの途中で閉じれば、待ちが終わり次第すべて消える。
    #[test]
    fn sup7_waiting_removes_after_release() {
        let t = TmpDir::new("waitrel");
        let w = open(&t.0, &id()).unwrap();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(w);
        });
        let removed = remove_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            always(),
        )
        .expect("removed after release");
        h.join().unwrap();
        assert_eq!(removed.log_files(), 1);
        assert_eq!(
            fs::read_dir(t.0.join("@supervisor-logs")).unwrap().count(),
            0
        );
    }

    /// REPAIR-5・#2892: `lock_wait` が 0 なら 1 回だけ試して即座に返る。
    #[test]
    fn repair5_waiting_zero_wait_tries_once() {
        let t = TmpDir::new("waitzero");
        let _w = open(&t.0, &id()).unwrap();
        let started = Instant::now();
        let e = remove_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::ZERO,
            Duration::from_secs(5),
            always(),
        )
        .expect_err("held");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// SUP-7・#2892: guard が false（同じ ID が再作成済み）ならログ本体を消さず 0 件で成功する。
    #[test]
    fn sup7_waiting_guard_false_keeps_logs() {
        let t = TmpDir::new("waitguard");
        let mut w = open(&t.0, &id()).unwrap();
        w.write_all(b"new\n").unwrap();
        w.flush().unwrap();
        drop(w);
        let removed = remove_guarded_bounded_waiting(
            &t.0,
            &id(),
            Duration::from_millis(100),
            Duration::from_secs(5),
            Arc::new(|| false),
        )
        .expect("guard skip");
        assert_eq!(removed.log_files(), 0);
        let body = fs::read_to_string(t.0.join("@supervisor-logs/c1.log")).unwrap();
        assert_eq!(body, "stderr new\n");
    }
}
