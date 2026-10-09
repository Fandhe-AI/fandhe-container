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
//! - 構築は [`FileAuditSink::in_state_store`] のみ。open 済みの `FileStateStore` を要求して順序を型で固定する
//!   （`FileStateStore::open` は状態ルートに `@revision.init-*` 以外のエントリがあると既存ストアとみなして
//!   `@revision` を初期化しないため、open より前に `@audit.log` を作ると永久に fail-closed になる）
//! - ファイルは 0600・実効 uid 所有・ハードリンク数 1、親は 0700 の状態ルート。symlink・FIFO・他者所有・
//!   g/o 権限付きは `AuditFileWriter::open` が拒否し、その場合は代替経路へ回る
//!
//! # 排他とタイムアウト（REPAIR-5）
//!
//! - プロセス内 `Mutex` は持たない。排他は `AuditFileWriter::write_record` の `flock`（open file description
//!   単位）が担い、同一プロセスの別スレッド・別プロセスのいずれも直列化される
//! - 1 回の `record` の待ち時間: open は `O_NOFOLLOW|O_NONBLOCK` でブロックしない。`flock` は
//!   `AUDIT_LOCK_TIMEOUT`（5 秒）が上限。カーネル監査の ACK は [`KERNEL_AUDIT_ACK_TIMEOUT`] が上限。
//!   **限界**: `sync_data` はストレージ障害時に上限を持たない（既存 writer と同じ）
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
//! `INTERNAL` を返す。`AuditDelivery::SinkFailed` はこの行を再構成できないため、呼び出し側は二重に出さない。
//! 拒否の判定は覆らない（fail-closed）。主経路だけ失敗して代替経路に記録できた場合の運用通知は未実装。
//!
//! # 未実装（REPAIR-3）
//!
//! `/run` は tmpfs のため再起動を越える保持は保証しない。永続的な置き場所（`/var/log` 等）・ローテーション・
//! 常時の二重記録（tee）は未実装。非 Linux では `FileStateStore::open` が `Unimplemented` を返すため
//! 構築入口も fail-closed になる。

use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use crate::state_store::FileStateStore;
use crate::traits::TraitError;

use super::{
    AuditFallback, AuditFileWriter, AuditRecord, AuditSink, AuditWriteFailure, KernelAuditFallback,
    write_with_fallback,
};

/// 状態ルート直下の監査ログのファイル名。
pub const AUDIT_LOG_FILE_NAME: &str = "@audit.log";

type FallbackFactory = Arc<dyn Fn() -> Box<dyn AuditFallback> + Send + Sync>;
type FailureNotifier = Arc<dyn Fn(&AuditWriteFailure) + Send + Sync>;

/// 同時に未完了でいられる通知スレッド数の上限。超過時は通知を捨てる（拒否経路を止めない）。
const NOTIFY_QUEUE_CAP: usize = 8;
/// 通知の完了を呼び出し側が待つ上限。stderr が詰まっていても `record` はこの時間内に戻る（REPAIR-5）。
const NOTIFY_WAIT: Duration = Duration::from_millis(200);

/// 通知ごとに短命スレッドへ渡して出力する通知器を作る。
///
/// stderr のロック取得・書き込みは満杯パイプで無期限に停止し得るため、呼び出し側のスレッドでは行わない。
/// スレッドは通知時にだけ起動し、出力後すぐ終了する。sink の生成時や平常時にスレッドを常駐させないのは、
/// supervisor の exec が worker を `fork_single_threaded`（`Threads: 1` 必須）で作るため。
/// 呼び出し側は最大 [`NOTIFY_WAIT`] だけ完了を待って戻る（プロセス終了直前でも通常は出力が間に合う）。
/// **限界**: 出力先が詰まり続けると、そのスレッドは残る（以降の fork は単一スレッド検証で拒否され得る）。
fn stderr_notifier() -> FailureNotifier {
    notifier_to(|| Box::new(StderrLine), NOTIFY_QUEUE_CAP, NOTIFY_WAIT)
}

/// 書き込み時に毎回 stderr をロックする `Write`（ロック取得も通知スレッド側で行う）。
struct StderrLine;

impl Write for StderrLine {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().lock().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().lock().flush()
    }
}

/// 出力先を生成する関数から、非同期・有限待ちの通知器を作る。出力先の生成も通知スレッド側で行う。
///
/// 生成時にはスレッドを起動しない（遅延起動）。未完了スレッドが `cap` 件に達していれば通知を捨てる。
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
                // 完了を確認できたら join してスレッドを確実に消す（直後の fork が単一スレッド検証を通るように）。
                // 時間切れなら切り離す。
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
    fallback: FallbackFactory,
    notify: FailureNotifier,
}

impl FileAuditSink {
    /// open 済みの状態ストアの正規化済みルート直下 `@audit.log` を主経路とする本番 sink を作る。
    ///
    /// 呼び出し元: supervisor の `exec::default_audit_sink`。ファイルはここでは開かない（`record` ごとに開く）。
    pub fn in_state_store(store: &FileStateStore) -> Self {
        Self {
            path: store.root().join(AUDIT_LOG_FILE_NAME),
            fallback: Arc::new(|| Box::new(KernelAuditFallback::new())),
            notify: stderr_notifier(),
        }
    }

    /// テスト用: 主経路パス・代替経路・通知先を差し込む。
    #[cfg(test)]
    pub(crate) fn with_parts(
        path: PathBuf,
        fallback: FallbackFactory,
        notify: FailureNotifier,
    ) -> Self {
        Self {
            path,
            fallback,
            notify,
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
        let mut fallback = (self.fallback)();
        let failure = match AuditFileWriter::open(&self.path) {
            Ok(mut writer) => match write_with_fallback(&mut writer, &mut *fallback, record) {
                Ok(_) => return Ok(()),
                Err(failure) => failure,
            },
            // 主経路の open 自体の失敗も代替経路へ回す。
            Err(primary) => match fallback.record_fallback(record, &primary) {
                Ok(()) => return Ok(()),
                Err(fb) => AuditWriteFailure::new(primary, fb),
            },
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
            let sink = FileAuditSink::in_state_store(&store);
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
            let sink = FileAuditSink::in_state_store(&store);
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
