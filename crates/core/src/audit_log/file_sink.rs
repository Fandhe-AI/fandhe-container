//! 本番用の監査記録先 [`FileAuditSink`]（SEC-4・SUP-6・TASK-41・TASK-163 追補・#1594）。
//!
//! # 役割
//!
//! 主経路（ローカルファイルへの JSON Lines 追記。`AuditFileWriter`）と代替経路（カーネル監査。
//! `KernelAuditFallback`）を `write_with_fallback` で束ね、[`AuditSink`] を実装する。supervisor の
//! `exec::run_command`（exec 対象の拒否の永続化）のほか、mount 検証/API・plugin 信頼検証・seccomp フックが
//! 同じ [`AuditSink`] 経由で使う想定の、全レイヤー共有の本番実体。
//!
//! # 置き場所の判断
//!
//! core に置く。利用者が supervisor に限られない（CLI 側の plugin 信頼検証などからも使う）ことと、
//! `StateStore` がトレイトもファイルベース既定実装も core に置く前例（TASK-31・OCI-5）に揃えるため。
//! 別の記録先は [`AuditSink`] の別実装として差し替えられる。
//!
//! # 既定パスと所有者・権限の前提
//!
//! - 既定パスは `<状態ルート>/@audit.log`（[`AUDIT_LOG_FILE_NAME`]。OCI-5 の状態ルート。root 実行は
//!   `/run/fandhe-container`、rootless は `$XDG_RUNTIME_DIR/fandhe-container`）。`@` 始まりは `ContainerId` の
//!   許容文字に含まれないため、コンテナ ID と衝突せず `list` 等からも読み飛ばされる
//! - 構築（本番）は [`FileAuditSink::in_state_store`] のみ。open 済みの `FileStateStore` を要求して順序を型で固定する
//!   （`FileStateStore::open` は状態ルートに `@revision.init-*` 以外のエントリがあると既存ストアとみなして
//!   `@revision` を初期化しないため、open より前に `@audit.log` を作ると永久に fail-closed になる）
//! - ファイルは 0600・実効 uid 所有・ハードリンク数 1、親は 0700 の状態ルート。symlink・FIFO・他者所有・
//!   g/o 権限付きは `AuditFileWriter::open` が拒否し、その場合は代替経路へ回る
//!
//! # 排他とタイムアウト（REPAIR-5）
//!
//! - プロセス内 `Mutex` は持たない。排他は `AuditFileWriter::write_record` の `flock`（open file description
//!   単位）が担い、同一プロセスの別スレッド・別プロセスのいずれも直列化される
//! - **主経路のファイル I/O は fork した使い捨ての子プロセスで行い、親は [`PRIMARY_WRITE_TIMEOUT`] だけ待つ**。
//!   `write_all`・`sync_data` には期限を付けられず（ストレージ停止で戻らない）、スレッドでの隔離は時間切れ後に
//!   スレッドが残って以後の fork（exec の worker は `Threads: 1` 必須）を妨げるため、プロセスで隔離する。
//!   時間切れの子は SIGKILL で止め、親は `isolation_timeout` を主経路の失敗として代替経路（カーネル監査）へ進む
//!   （代替経路はストレージに触れず、ACK は [`KERNEL_AUDIT_ACK_TIMEOUT`] が上限）。D 状態で SIGKILL が
//!   効かない子はゾンビとして残り得るが、スレッドではないので親の `Threads` は増えない
//! - 子は `fork_single_threaded` で作る。呼び出しプロセスが複数スレッドだと fork できないため、その場合は
//!   主経路を試行せず `isolation_unavailable` で代替経路へ進む（期限を保証できない I/O を呼び出しスレッドで
//!   実行しない。fail-closed）。supervisor の exec は単一スレッドのプロセスから呼ぶ契約
//! - 1 回の `record` の待ち時間の上限は、主経路 [`PRIMARY_WRITE_TIMEOUT`]（＋ kill 後の回収待ち 1 秒）＋代替経路の
//!   ACK 上限＋失敗通知 [`NOTIFY_WAIT`]
//! - 呼び出し側（supervisor）の記録点は worker を回収した後の親プロセスで、sink が詰まっても worker・
//!   コマンドは残らない
//!
//! # 書くたびに開き直す理由
//!
//! 1. `KernelAuditFallback` は `Send` 境界のない transport を持つため、保持すると `AuditSink: Send + Sync` を
//!    満たせない。生成関数を持ち毎回作る（送信ごとに socket を開閉する設計なのでコストは変わらない）
//! 2. fd を持たないので、sink 生成後に fork する exec の worker（コンテナの mnt ns・cgroup に入る）へ
//!    ホストの監査ファイルの fd が継承されない
//! 3. 毎回、親ディレクトリ・ファイルの信頼検査をやり直すため、差し替え・ローテーションに追従しつつ検査を保てる
//!
//! # 両経路失敗時
//!
//! 固定スキーマの 1 行（`AuditWriteFailure::write_json_line`）を **本 sink が 1 回だけ** stderr へ出し、
//! `INTERNAL` を返す。stderr への出力も fork した子プロセスで行い、[`NOTIFY_WAIT`] で打ち切る（出力先が満杯の
//! パイプで詰まっても、スレッドを残さず以後の exec を妨げない。複数スレッドのプロセスでは fork できないため
//! 短命スレッドでの出力に退避する。そのプロセスは既に単一スレッドではなく、未完了 8 件で頭打ちにする）。`AuditDelivery::SinkFailed` はこの行を再構成できないため、呼び出し側は二重に出さない。
//! 拒否の判定は覆らない（fail-closed）。主経路だけ失敗して代替経路に記録できた場合の運用通知は未実装。
//!
//! # 未実装（REPAIR-3）
//!
//! `/run` は tmpfs のため再起動を越える保持は保証しない。永続的な置き場所（`/var/log` 等）・ローテーション・
//! 常時の二重記録（tee）は未実装。非 Linux では `FileStateStore::open` が `Unimplemented` を返すため
//! 構築入口も fail-closed になる。

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::state_store::FileStateStore;
use crate::sys;
use crate::traits::TraitError;

use super::{
    AuditFallback, AuditFileWriter, AuditRecord, AuditSink, AuditWriteError, AuditWriteErrorKind,
    AuditWriteFailure, KernelAuditFallback,
};

/// 状態ルート直下の監査ログのファイル名。
pub const AUDIT_LOG_FILE_NAME: &str = "@audit.log";

/// 主経路（ファイル書き込み）を隔離した子プロセスの待ち時間の上限（REPAIR-5）。
///
/// `flock` の待ち上限（5 秒）に open・write・`sync_data` の余裕を足した値。超過した子は SIGKILL する。
pub const PRIMARY_WRITE_TIMEOUT: Duration = Duration::from_secs(8);

/// 失敗通知（stderr 出力）を隔離した子プロセスの待ち時間の上限。超過した子は SIGKILL する。
pub const NOTIFY_WAIT: Duration = Duration::from_millis(200);

/// kill 後に子の回収を待つ上限。SIGKILL が効かない子（D 状態）はゾンビのまま諦める。
const KILL_REAP_WAIT: Duration = Duration::from_secs(1);
/// 子の終了を確認するポーリング間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 同時に未完了でいられる通知スレッド数の上限（複数スレッドのプロセスでの退避経路のみ）。
const NOTIFY_QUEUE_CAP: usize = 8;

type FallbackFactory = Arc<dyn Fn() -> Box<dyn AuditFallback> + Send + Sync>;
type FailureNotifier = Arc<dyn Fn(&AuditWriteFailure) + Send + Sync>;
/// 主経路の 1 回分の書き込み（パスを開いて 1 件追記）。隔離した子の中で実行される。
type PrimaryStep = Arc<dyn Fn(&Path, &AuditRecord) -> Result<(), AuditWriteError> + Send + Sync>;
/// 通知の出力先の生成関数（隔離した子の中で呼ぶ）。
type NotifyOut = Arc<dyn Fn() -> Box<dyn Write> + Send + Sync>;

/// 隔離した子プロセスの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IsolatedOutcome {
    /// 子が終了コード付きで終了した。
    Exited(i32),
    /// 期限内に終わらず SIGKILL した。
    TimedOut,
    /// 呼び出しプロセスが複数スレッドで fork できない。
    MultiThreaded,
    /// fork・待機に失敗した、または子がシグナルで死んだ（非対応 OS を含む）。
    Failed,
}

/// `child` を fork した子プロセスで実行し、`timeout` まで終了を待つ（REPAIR-5）。
///
/// 親にはスレッドも fd も残さない。子は `_exit` するため、終了コードは 0〜255。panic は 2。
/// 期限超過は SIGKILL して回収を [`KILL_REAP_WAIT`] まで待つ。
fn run_isolated(timeout: Duration, child: impl FnOnce() -> i32) -> IsolatedOutcome {
    let pid = match sys::fork_single_threaded(child, 2) {
        Ok(pid) => pid,
        Err(sys::SysError::MultiThreaded) => return IsolatedOutcome::MultiThreaded,
        Err(_) => return IsolatedOutcome::Failed,
    };
    let deadline = Instant::now() + timeout;
    loop {
        match sys::wait_pid_nohang(pid) {
            Ok(Some(status)) => return decode_status(status),
            Ok(None) => {}
            Err(_) => {
                let _ = sys::kill_pid(pid, sys::Signal::Kill);
                return IsolatedOutcome::Failed;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    // 期限超過。未回収の自分の子にだけ送る（回収済みなら上の分岐で戻っている）。
    let _ = sys::kill_pid(pid, sys::Signal::Kill);
    let reap_deadline = Instant::now() + KILL_REAP_WAIT;
    while Instant::now() < reap_deadline {
        if !matches!(sys::wait_pid_nohang(pid), Ok(None)) {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    IsolatedOutcome::TimedOut
}

/// `waitpid` の status を解釈する。正常終了以外（シグナル死）は `Failed`。
fn decode_status(status: i32) -> IsolatedOutcome {
    if status & 0x7f == 0 {
        IsolatedOutcome::Exited((status >> 8) & 0xff)
    } else {
        IsolatedOutcome::Failed
    }
}

/// 子が終了コードで返せる主経路の失敗種別（コード = 添字 + [`KIND_EXIT_BASE`]）。範囲外は `Write` として扱う。
const PRIMARY_KINDS: [AuditWriteErrorKind; 11] = [
    AuditWriteErrorKind::RelativePath,
    AuditWriteErrorKind::Unsupported,
    AuditWriteErrorKind::NotRegularFile,
    AuditWriteErrorKind::InsecureFile,
    AuditWriteErrorKind::Open,
    AuditWriteErrorKind::Encode,
    AuditWriteErrorKind::LineTooLong,
    AuditWriteErrorKind::Write,
    AuditWriteErrorKind::Lock,
    AuditWriteErrorKind::LockFailed,
    AuditWriteErrorKind::Sync,
];
/// 失敗種別の終了コードの起点（0 は成功、2 は子の panic に使うため 10 から）。
const KIND_EXIT_BASE: i32 = 10;
/// `PRIMARY_KINDS` 内の `Write` の添字（未知の種別の既定）。
const WRITE_INDEX: usize = 7;

fn kind_to_exit(kind: AuditWriteErrorKind) -> i32 {
    let idx = PRIMARY_KINDS
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(WRITE_INDEX);
    KIND_EXIT_BASE + i32::try_from(idx).unwrap_or(0)
}

fn exit_to_kind(code: i32) -> AuditWriteErrorKind {
    usize::try_from(code - KIND_EXIT_BASE)
        .ok()
        .and_then(|i| PRIMARY_KINDS.get(i).copied())
        .unwrap_or(AuditWriteErrorKind::Write)
}

/// 主経路の既定の 1 回分: パスを検査付きで開いて 1 件追記する。
fn default_primary_step(path: &Path, record: &AuditRecord) -> Result<(), AuditWriteError> {
    AuditFileWriter::open(path)?.write_record(record)
}

/// 主経路をどこで実行するか。
#[derive(Clone, Copy)]
enum Isolation {
    /// fork した子プロセス。`timeout` で SIGKILL する（本番）。
    Process { timeout: Duration },
    /// 呼び出しスレッドで直接実行する（libtest のように複数スレッドで fork できないユニットテスト専用）。
    #[cfg(test)]
    InProcess,
}

/// 通知を子プロセスで出す通知器を作る（複数スレッドで fork できないときだけ短命スレッドに退避する）。
///
/// 出力先の生成・書き込みはすべて子の中で行うため、出力先が詰まっても親にスレッドは残らない。
fn isolated_notifier(out: NotifyOut, wait: Duration) -> FailureNotifier {
    let threaded = {
        let out = Arc::clone(&out);
        notifier_to(move || out(), NOTIFY_QUEUE_CAP, wait)
    };
    Arc::new(move |failure| {
        let mut line = Vec::new();
        if failure.write_json_line(&mut line).is_err() {
            return;
        }
        let outcome = run_isolated(wait, || {
            let mut sink = out();
            // 書き込み失敗は握りつぶす（拒否経路を止めない）。
            let _ = sink.write_all(&line);
            let _ = sink.flush();
            0
        });
        if outcome == IsolatedOutcome::MultiThreaded {
            threaded(failure);
        }
    })
}

/// 書き込み時に毎回 stderr をロックする `Write`（ロック取得も通知側で行う）。
struct StderrLine;

impl Write for StderrLine {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().lock().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().lock().flush()
    }
}

/// 出力先を生成する関数から、非同期・有限待ちの短命スレッド通知器を作る（複数スレッドのプロセス向けの退避経路）。
///
/// 生成時にはスレッドを起動しない（遅延起動）。未完了スレッドが `cap` 件に達していれば通知を捨てる。
/// **限界**: 出力先が詰まり続けるとそのスレッドは残る。fork できる（単一スレッドの）プロセスでは使われない。
fn notifier_to(
    make: impl Fn() -> Box<dyn Write> + Send + Sync + 'static,
    cap: usize,
    wait: Duration,
) -> FailureNotifier {
    let make = Arc::new(make);
    let in_flight = Arc::new(AtomicUsize::new(0));
    Arc::new(move |failure| {
        let mut line = Vec::new();
        if failure.write_json_line(&mut line).is_err() {
            return;
        }
        // 満杯なら待たずに捨てる。
        if in_flight.fetch_add(1, Ordering::AcqRel) >= cap {
            in_flight.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel::<()>(1);
        let make = Arc::clone(&make);
        let counter = Arc::clone(&in_flight);
        let spawned = std::thread::Builder::new()
            .name("audit-notify".into())
            .spawn(move || {
                let mut out = make();
                // 書き込み失敗は握りつぶす（拒否経路を止めない）。
                let _ = out.write_all(&line);
                let _ = out.flush();
                counter.fetch_sub(1, Ordering::AcqRel);
                let _ = ack_tx.try_send(());
            });
        match spawned {
            Ok(handle) => {
                // 完了を確認できたら join してスレッドを確実に消す。時間切れなら切り離す。
                if ack_rx.recv_timeout(wait).is_ok() {
                    let _ = handle.join();
                }
            }
            Err(_) => {
                in_flight.fetch_sub(1, Ordering::AcqRel);
            }
        }
    })
}

/// ファイル（主経路）＋カーネル監査（代替経路）の本番 [`AuditSink`]。
pub struct FileAuditSink {
    path: PathBuf,
    primary: PrimaryStep,
    isolation: Isolation,
    fallback: FallbackFactory,
    notify: FailureNotifier,
}

impl FileAuditSink {
    /// open 済みの状態ストアの正規化済みルート直下 `@audit.log` を主経路とする本番 sink を作る。
    ///
    /// 呼び出し元: supervisor の `exec::default_audit_sink`。ファイルはここでは開かない（`record` ごとに、
    /// fork した子プロセスで開く）。
    pub fn in_state_store(store: &FileStateStore) -> Self {
        Self {
            path: store.root().join(AUDIT_LOG_FILE_NAME),
            primary: Arc::new(default_primary_step),
            isolation: Isolation::Process {
                timeout: PRIMARY_WRITE_TIMEOUT,
            },
            fallback: Arc::new(|| Box::new(KernelAuditFallback::new())),
            notify: isolated_notifier(Arc::new(|| Box::new(StderrLine)), NOTIFY_WAIT),
        }
    }

    /// 結合試験専用: 主経路の 1 回分・待ち上限・代替経路・通知の出力先を差し込む。隔離は本番と同じ
    /// 子プロセス方式（`tests/audit_sink_isolation.rs`。REPAIR-5・SEC-4・TASK-163）。
    #[cfg(feature = "exec-test-support")]
    #[doc(hidden)]
    pub fn isolated_for_test(
        path: PathBuf,
        primary: PrimaryStep,
        primary_timeout: Duration,
        fallback: FallbackFactory,
        notify_out: NotifyOut,
        notify_wait: Duration,
    ) -> Self {
        Self {
            path,
            primary,
            isolation: Isolation::Process {
                timeout: primary_timeout,
            },
            fallback,
            notify: isolated_notifier(notify_out, notify_wait),
        }
    }

    /// テスト用: 主経路パス・代替経路・通知先を差し込む（呼び出しスレッドで直接実行）。
    #[cfg(test)]
    pub(crate) fn with_parts(
        path: PathBuf,
        fallback: FallbackFactory,
        notify: FailureNotifier,
    ) -> Self {
        Self {
            path,
            primary: Arc::new(default_primary_step),
            isolation: Isolation::InProcess,
            fallback,
            notify,
        }
    }

    /// 主経路を 1 回試す。隔離した子の結果（終了コード・時間切れ・fork 不能）を主経路の失敗へ写す。
    fn write_primary(&self, record: &AuditRecord) -> Result<(), AuditWriteError> {
        match self.isolation {
            #[cfg(test)]
            Isolation::InProcess => (self.primary)(&self.path, record),
            Isolation::Process { timeout } => {
                let outcome = run_isolated(timeout, || match (self.primary)(&self.path, record) {
                    Ok(()) => 0,
                    Err(e) => kind_to_exit(e.kind()),
                });
                match outcome {
                    IsolatedOutcome::Exited(0) => Ok(()),
                    IsolatedOutcome::Exited(code) => Err(AuditWriteError::new(exit_to_kind(code))),
                    IsolatedOutcome::TimedOut => {
                        Err(AuditWriteError::new(AuditWriteErrorKind::IsolationTimeout))
                    }
                    IsolatedOutcome::MultiThreaded | IsolatedOutcome::Failed => Err(
                        AuditWriteError::new(AuditWriteErrorKind::IsolationUnavailable),
                    ),
                }
            }
        }
    }
}

impl fmt::Debug for FileAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAuditSink").finish_non_exhaustive()
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        let primary = match self.write_primary(record) {
            Ok(()) => return Ok(()),
            Err(primary) => primary,
        };
        // 主経路の失敗（open・時間切れ・隔離不能を含む）は代替経路へ回す。代替経路はストレージに触れない。
        let mut fallback = (self.fallback)();
        let failure = match fallback.record_fallback(record, &primary) {
            Ok(()) => return Ok(()),
            Err(fb) => AuditWriteFailure::new(primary, fb),
        };
        (self.notify)(&failure);
        Err(TraitError::new(failure.error_code(), failure.message()))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{
        AuditDelivery, AuditEvent, AuditPid, AuditReason, AuditTimestamp, AuditWriteError,
        AuditWriteErrorKind, NoAuditFallback, record_mount_rejection,
    };
    use crate::traits::ErrorCode;
    use std::sync::Mutex;
    use std::time::Instant;

    fn sample() -> AuditRecord {
        AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(4242).unwrap(),
            AuditEvent::ExecTarget {
                reason: AuditReason::new("exec_target_not_nested_pid1"),
            },
        )
    }

    struct Rec {
        calls: Arc<Mutex<Vec<AuditWriteErrorKind>>>,
        ok: bool,
    }

    impl AuditFallback for Rec {
        fn record_fallback(
            &mut self,
            _r: &AuditRecord,
            primary: &AuditWriteError,
        ) -> Result<(), AuditWriteError> {
            self.calls.lock().unwrap().push(primary.kind());
            if self.ok {
                Ok(())
            } else {
                Err(AuditWriteError::fallback_unavailable())
            }
        }
    }

    fn missing_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("fandhe-auditsink-missing-{}", std::process::id()))
            .join("nodir")
            .join(AUDIT_LOG_FILE_NAME)
    }

    type Notes = Arc<Mutex<Vec<u8>>>;
    type Calls = Arc<Mutex<Vec<AuditWriteErrorKind>>>;

    fn sink_with(path: PathBuf, ok: bool) -> (FileAuditSink, Calls, Notes) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let notes: Notes = Arc::new(Mutex::new(Vec::new()));
        let c = calls.clone();
        let n = notes.clone();
        let sink = FileAuditSink::with_parts(
            path,
            Arc::new(move || {
                Box::new(Rec {
                    calls: c.clone(),
                    ok,
                })
            }),
            Arc::new(move |f| {
                let mut g = n.lock().unwrap();
                f.write_json_line(&mut *g).unwrap();
            }),
        );
        (sink, calls, notes)
    }

    fn primary_kind() -> AuditWriteErrorKind {
        if cfg!(target_os = "linux") {
            AuditWriteErrorKind::Open
        } else {
            AuditWriteErrorKind::Unsupported
        }
    }

    /// SEC-4・SUP-6・TASK-163: 主経路が失敗すると代替経路へ 1 回だけ回り、成功を返す。
    #[test]
    fn sec4_task163_primary_failure_goes_to_fallback() {
        let (sink, calls, notes) = sink_with(missing_path(), true);
        sink.record(&sample()).unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![primary_kind()]);
        assert!(notes.lock().unwrap().is_empty());
    }

    /// SEC-4・SUP-6・TASK-163: 両経路失敗は固定スキーマ 1 行を通知し INTERNAL を返す。
    #[test]
    fn sec4_task163_both_fail_notifies_fixed_line_and_errors() {
        let (sink, _calls, notes) = sink_with(missing_path(), false);
        let e = sink.record(&sample()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(
            e.message(),
            "audit record could not be persisted by primary or fallback path"
        );
        let (p, pc) = if cfg!(target_os = "linux") {
            ("open", "INTERNAL")
        } else {
            ("unsupported", "UNIMPLEMENTED")
        };
        let expect = format!(
            "{{\"event\":\"audit_write_failure\",\"code\":\"INTERNAL\",\"primary\":\"{p}\",\"primary_code\":\"{pc}\",\"fallback\":\"fallback_unavailable\",\"fallback_code\":\"UNIMPLEMENTED\"}}\n"
        );
        assert_eq!(
            String::from_utf8(notes.lock().unwrap().clone()).unwrap(),
            expect
        );
    }

    /// SEC-4・SUP-6・TASK-163: 両経路失敗でも mount 拒否の判定は覆らない。
    #[test]
    fn sec4_task163_both_fail_keeps_rejection() {
        let f: FallbackFactory = Arc::new(|| Box::new(NoAuditFallback));
        let sink = FileAuditSink::with_parts(missing_path(), f, Arc::new(|_| {}));
        let r = record_mount_rejection("denied", None, &sink);
        assert_eq!(r.error, "denied");
        assert!(matches!(
            r.delivery,
            AuditDelivery::SinkFailed(ref e) if e.code() == ErrorCode::Internal
        ));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::audit_log::encode_json_line;
        use crate::state_store::StateRoot;
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn fresh_dir(tag: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("fandhe-auditsink-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        fn open_store(dir: &std::path::Path) -> FileStateStore {
            FileStateStore::open(StateRoot::from_override(dir.join("root")).unwrap()).unwrap()
        }

        /// SEC-4・SUP-6・TASK-163: 拒否 1 件がファイルへ 1 行記録される。
        #[test]
        fn sec4_task163_production_sink_writes_one_line() {
            let dir = fresh_dir("one");
            let store = open_store(&dir);
            let (sink, _calls, _notes) = sink_with(store.root().join(AUDIT_LOG_FILE_NAME), false);
            sink.record(&sample()).unwrap();
            let text = std::fs::read_to_string(store.root().join(AUDIT_LOG_FILE_NAME)).unwrap();
            let expect = String::from_utf8(encode_json_line(&sample()).unwrap()).unwrap();
            assert_eq!(text, expect);
            assert_eq!(text.lines().count(), 1);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// SEC-4・TASK-163: symlink の @audit.log は主経路で拒否され代替経路へ回る。
        #[test]
        fn sec4_task163_symlinked_log_goes_to_fallback() {
            let dir = fresh_dir("sym");
            let store = open_store(&dir);
            let target = dir.join("target");
            std::fs::write(&target, b"").unwrap();
            symlink(&target, store.root().join(AUDIT_LOG_FILE_NAME)).unwrap();
            let (sink, calls, _n) = sink_with(store.root().join(AUDIT_LOG_FILE_NAME), true);
            sink.record(&sample()).unwrap();
            assert_eq!(*calls.lock().unwrap(), vec![AuditWriteErrorKind::Open]);
            assert_eq!(std::fs::read(&target).unwrap(), b"");
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// OCI-5: sink が @audit.log を作った後でも、ストアの再 open で @revision が保たれる。
        #[test]
        fn oci5_task163_audit_log_does_not_break_store_reopen() {
            let dir = fresh_dir("reopen");
            let store = open_store(&dir);
            let (sink, _calls, _notes) = sink_with(store.root().join(AUDIT_LOG_FILE_NAME), false);
            sink.record(&sample()).unwrap();
            let rev = std::fs::read(store.root().join("@revision")).unwrap();
            let again = open_store(&dir);
            assert_eq!(std::fs::read(again.root().join("@revision")).unwrap(), rev);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 書き込みが戻らない出力先（満杯パイプ相当）。
    struct Stuck(Arc<Mutex<mpsc::Receiver<()>>>);

    impl Write for Stuck {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.lock().map(|r| r.recv());
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// REPAIR-5・SEC-4・TASK-163: 通知先が無期限に詰まっても `record` は上限時間内に拒否結果を返す。
    #[test]
    fn repair5_task163_stuck_notifier_does_not_block_record() {
        let (hold_tx, hold_rx) = mpsc::channel::<()>();
        let hold_rx = Arc::new(Mutex::new(hold_rx));
        let notify = notifier_to(
            move || Box::new(Stuck(Arc::clone(&hold_rx))),
            2,
            Duration::from_millis(50),
        );
        let f: FallbackFactory = Arc::new(|| Box::new(NoAuditFallback));
        let sink = FileAuditSink::with_parts(missing_path(), f, notify);
        let start = Instant::now();
        // キュー上限を超える回数を呼んでも、各呼び出しが有限時間で戻る。
        for _ in 0..6 {
            let e = sink.record(&sample()).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Internal);
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        drop(hold_tx);
    }

    /// REPAIR-5・SEC-4・TASK-163: 隔離した子の終了コードと主経路の失敗種別が往復し、未知のコードは `Write`。
    #[test]
    fn repair5_task163_primary_kind_exit_code_roundtrip() {
        for kind in PRIMARY_KINDS {
            assert_eq!(exit_to_kind(kind_to_exit(kind)), kind);
        }
        assert_eq!(kind_to_exit(AuditWriteErrorKind::Open), 14);
        assert_eq!(exit_to_kind(255), AuditWriteErrorKind::Write);
        assert_eq!(exit_to_kind(2), AuditWriteErrorKind::Write);
        assert_eq!(
            kind_to_exit(AuditWriteErrorKind::IsolationTimeout),
            KIND_EXIT_BASE + 7
        );
    }

    /// REPAIR-5・TASK-163: `waitpid` の status は正常終了だけ終了コードに、シグナル死は `Failed`。
    #[test]
    fn repair5_task163_decode_status() {
        assert_eq!(decode_status(0), IsolatedOutcome::Exited(0));
        assert_eq!(decode_status(14 << 8), IsolatedOutcome::Exited(14));
        assert_eq!(decode_status(9), IsolatedOutcome::Failed);
    }

    /// REPAIR-5・SUP-6・TASK-163: 通知器は生成時にスレッドを起動せず（出力先も作らず）、通知のたびに短命スレッドを
    /// 起動して完了後に残さない（exec の fork 前単一スレッド要件の維持）。
    #[test]
    fn repair5_task163_notifier_spawns_lazily_and_leaves_no_thread() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let made = Arc::new(AtomicUsize::new(0));
        let m = made.clone();
        let notify = notifier_to(
            move || {
                m.fetch_add(1, Ordering::SeqCst);
                Box::new(std::io::sink())
            },
            2,
            Duration::from_secs(5),
        );
        assert_eq!(made.load(Ordering::SeqCst), 0);
        let f: FallbackFactory = Arc::new(|| Box::new(NoAuditFallback));
        let sink = FileAuditSink::with_parts(missing_path(), f, notify);
        for n in 1..=3 {
            sink.record(&sample()).unwrap_err();
            assert_eq!(made.load(Ordering::SeqCst), n);
        }
    }
}
