//! shim v2 のイベント publish（TaskCreate・TaskStart・TaskDelete・TaskExit の 4 種）。期限つきの子プロセスで containerd の `publish` を呼ぶ（CRI-5・TASK-62.6・REPAIR-3・REPAIR-5・#4155）。
//!
//! containerd（特に CRI）はコンテナの終了を `/tasks/exit` の TaskExit で知る。Create・Start・Delete の成功も
//! `/tasks/create`・`/tasks/start`・`/tasks/delete` で送る（#4156。init だけで、exec の経路は送らない）。shim は `-publish-binary`
//! （検証済みの `PublishBinary`。#4154）を子として起動し、stdin へ `google.protobuf.Any` を渡す。
//! 呼び出し元は [`super::task_service::TaskService`] の終了 watcher（`Start` 成功後に起こす）で、
//! 差し込み口は `exec_publisher_for`（plugin-cri の `registry_in` が呼ぶ）。
//!
//! 契約:
//! - 呼び出し形: `<publish-binary> --address <address> publish --namespace <namespace> --topic /tasks/exit`。
//!   値は検証済みの `PublishBinary`・`ShimIdentifier`・`-address` からだけ組み立て、シェルを経由しない。
//!   子は `env_clear()`・cwd `/`・stdout / stderr は null（`daemon.log` の fd を渡さない）。
//! - stdin: `Any` の protobuf 符号化そのもの（長さ接頭辞・改行なし）。`type_url` は `containerd.events.TaskExit`。
//! - [`EventPublisher::publish`] は有界時間で戻る（キューへ入れるだけ）。子の起動・待ち・回収は worker スレッド 1 本が直列に行い、
//!   各 publish は [`PublishConfig::timeout`] で打ち切って kill し、猶予内に回収する（REPAIR-5）。
//! - 失敗は RPC の応答を変えず、固定語彙の構造化ログ 1 行（[`PublishFailure`]）を出す。1 回の publish が出す失敗は高々 1 件。
//!   ログは段名・errno・終了コード・シグナル・topic だけを持ち、argv・アドレス・namespace・コンテナ ID・環境変数・イベントの本文は出さない（REPAIR-4）。
//!
//! 範囲外（REPAIR-3。未実装を装わない）と残余:
//! - 送らない種別: TaskExecAdded・TaskExecStarted・TaskPaused・TaskResumed・TaskCheckpointed・TaskOOM（対応する RPC・仕組みが無い）。
//! - Create・Start・Delete は RPC が成功する直前に 1 回だけ [`EventPublisher::publish`] で投入する（世代の guard は使わない。完了済みの事実の記録で、
//!   ゲート保持中の投入順が FIFO の worker で保たれる）。符号化後 [`MAX_EVENT_LEN`] を超える TaskCreate（bundle が約 3.6 KiB 超）は送れず、
//!   `encode` の失敗が 1 件記録される（RPC の応答は変えない）。上限を上げるのは stdin 書き込みの非ブロッキング化と同時に再評価する。
//! - shim の Shutdown でキューに残った未送信のイベントは捨てうる（worker は切り離されたスレッド。排出は未実装）。
//! - `Child::kill` は直接の子だけを止める。publish バイナリの孫は止めない（containerd の `publish` は fork しない）。
//!   プロセスグループごとの kill は `sys` の新規 unsafe が要るため採らない。
//! - D 状態で kill が効かない子は猶予の後に放置する（shim の終了までゾンビが残りうる）。
//! - 検査から exec までの差し替え（TOCTOU）・祖先ディレクトリの検査・検査した fd での exec（`fexecve`）は見送り。
//!   新しい unsafe が要るため。再評価条件は #4154 の設計メモと同じ。
//! - worker は publish を直列に処理するため、詰まった 1 件は後続を最大で「期限 + 猶予」遅らせる。キューは有界で、満杯なら捨てて `enqueue` を記録する。

use std::time::Duration;

use prost::Message;

use super::task_api::{Any, Timestamp};
use crate::error::CriError;

/// TaskExit の type URL（接頭辞なし。containerd の `typeurl` の形）。
pub const TASK_EXIT_TYPE_URL: &str = "containerd.events.TaskExit";
/// TaskCreate の type URL。
pub const TASK_CREATE_TYPE_URL: &str = "containerd.events.TaskCreate";
/// TaskStart の type URL。
pub const TASK_START_TYPE_URL: &str = "containerd.events.TaskStart";
/// TaskDelete の type URL。
pub const TASK_DELETE_TYPE_URL: &str = "containerd.events.TaskDelete";
/// TaskCreate の topic。
pub const TASK_CREATE_TOPIC: &str = "/tasks/create";
/// TaskStart の topic。
pub const TASK_START_TOPIC: &str = "/tasks/start";
/// TaskDelete の topic。
pub const TASK_DELETE_TOPIC: &str = "/tasks/delete";
/// TaskExit の topic。
pub const TASK_EXIT_TOPIC: &str = "/tasks/exit";
/// 符号化後の `Any` の上限。pipe の容量（`PIPE_BUF` 以上）に収め、stdin への書き込みがブロックしないようにする。
pub const MAX_EVENT_LEN: usize = 4096;
/// 設定に許す最大の期限。
const MAX_PUBLISH_TIMEOUT: Duration = Duration::from_secs(60);

/// `containerd.events.TaskExit`（`api/events/task.proto` の番号 1〜5）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskExit {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub container_id: String,
    /// プロセス ID（init は `container_id` と同じ）。
    #[prost(string, tag = "2")]
    pub id: String,
    /// プロセスの pid。
    #[prost(uint32, tag = "3")]
    pub pid: u32,
    /// 終了コード（不明は 255）。
    #[prost(uint32, tag = "4")]
    pub exit_status: u32,
    /// 終了時刻。core が記録していないときは未設定（値を捏造しない。containerd 側ではゼロ時刻になりうる）。
    #[prost(message, optional, tag = "5")]
    pub exited_at: Option<Timestamp>,
}

/// TaskCreate・TaskDelete が載せる `containerd.events.TaskIO`（`api/events/task.proto`）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskIo {
    /// stdin（常に空）。
    #[prost(string, tag = "1")]
    pub stdin: String,
    /// stdout（常に空）。
    #[prost(string, tag = "2")]
    pub stdout: String,
    /// stderr（常に空）。
    #[prost(string, tag = "3")]
    pub stderr: String,
    /// pty の要否。
    #[prost(bool, tag = "4")]
    pub terminal: bool,
}

/// `containerd.events.TaskCreate`（番号 1〜6）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskCreate {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub container_id: String,
    /// OCI bundle のパス。
    #[prost(string, tag = "2")]
    pub bundle: String,
    /// rootfs の mount（Create が非空を拒否するため常に空）。
    #[prost(message, repeated, tag = "3")]
    pub rootfs: Vec<super::task_api::Mount>,
    /// IO（runc は常に非 nil で送る）。
    #[prost(message, optional, tag = "4")]
    pub io: Option<TaskIo>,
    /// checkpoint（常に空）。
    #[prost(string, tag = "5")]
    pub checkpoint: String,
    /// init の pid。
    #[prost(uint32, tag = "6")]
    pub pid: u32,
}

/// `containerd.events.TaskStart`（番号 1〜2）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskStart {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub container_id: String,
    /// init の pid。
    #[prost(uint32, tag = "2")]
    pub pid: u32,
}

/// `containerd.events.TaskDelete`（番号 1〜5）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskDelete {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub container_id: String,
    /// 削除前の pid（無ければ 0）。
    #[prost(uint32, tag = "2")]
    pub pid: u32,
    /// 終了コード（`DeleteResponse` と同じ値）。
    #[prost(uint32, tag = "3")]
    pub exit_status: u32,
    /// 終了時刻（未記録は未設定）。
    #[prost(message, optional, tag = "4")]
    pub exited_at: Option<Timestamp>,
    /// プロセス ID（init は `container_id` と同じ。runc shim の `p.ID()` に揃える）。
    #[prost(string, tag = "5")]
    pub id: String,
}

/// publish するイベント（#4155・#4156）。
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TaskEvent {
    /// コンテナの作成成功（`/tasks/create`）。
    Create(TaskCreate),
    /// init の起動成功（`/tasks/start`）。
    Start(TaskStart),
    /// コンテナの削除成功（`/tasks/delete`）。
    Delete(TaskDelete),
    /// コンテナ init の終了（`/tasks/exit`）。
    Exit(TaskExit),
}

impl TaskEvent {
    /// イベントの topic（固定語彙）。
    pub fn topic(&self) -> &'static str {
        match self {
            Self::Create(_) => TASK_CREATE_TOPIC,
            Self::Start(_) => TASK_START_TOPIC,
            Self::Delete(_) => TASK_DELETE_TOPIC,
            Self::Exit(_) => TASK_EXIT_TOPIC,
        }
    }

    /// stdin へ渡す `Any` の符号化。上限（[`MAX_EVENT_LEN`]）を超えたら失敗する。
    pub fn encode_any(&self) -> Result<Vec<u8>, PublishFailure> {
        let (type_url, value) = match self {
            Self::Create(e) => (TASK_CREATE_TYPE_URL, e.encode_to_vec()),
            Self::Start(e) => (TASK_START_TYPE_URL, e.encode_to_vec()),
            Self::Delete(e) => (TASK_DELETE_TYPE_URL, e.encode_to_vec()),
            Self::Exit(e) => (TASK_EXIT_TYPE_URL, e.encode_to_vec()),
        };
        let bytes = Any {
            type_url: type_url.to_owned(),
            value,
        }
        .encode_to_vec();
        if bytes.len() > MAX_EVENT_LEN {
            return Err(PublishFailure::new(
                PublishStage::Encode,
                Some(self.topic()),
            ));
        }
        Ok(bytes)
    }
}

/// 失敗した段の閉じた語彙（ログの `stage`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishStage {
    /// イベントの符号化（上限超過）。
    Encode,
    /// キューへの投入（満杯・切断）。
    Enqueue,
    /// worker スレッドの起動。
    WorkerSpawn,
    /// 子の起動。
    Spawn,
    /// 子の stdin への書き込み。
    WriteStdin,
    /// 子の待ち（`try_wait` の失敗）。
    Wait,
    /// 期限切れ（kill して回収を試みた）。
    Deadline,
    /// 子が非 0 で終了した。
    ExitStatus,
    /// 終了 watcher スレッドの起動失敗。
    WatchSpawn,
    /// 終了 watcher の数の上限超過。
    WatchLimit,
    /// 終了 watcher が照会の失敗を繰り返して諦めた。
    Watch,
    /// Stopped の状態の pid が Start 時と食い違う（同じ ID の作り直し）。
    InstanceMismatch,
    /// `-publish-binary` が無く、イベントを送らない。
    Disabled,
}

impl PublishStage {
    /// ログに出す固定の段名。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encode => "encode",
            Self::Enqueue => "enqueue",
            Self::WorkerSpawn => "worker_spawn",
            Self::Spawn => "spawn",
            Self::WriteStdin => "write_stdin",
            Self::Wait => "wait",
            Self::Deadline => "deadline",
            Self::ExitStatus => "exit_status",
            Self::WatchSpawn => "watch_spawn",
            Self::WatchLimit => "watch_limit",
            Self::Watch => "watch",
            Self::InstanceMismatch => "instance_mismatch",
            Self::Disabled => "disabled",
        }
    }
}

/// publish の失敗 1 件。段名・errno・終了コード・シグナル・topic だけを持つ（秘匿情報を持てない型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishFailure {
    /// 失敗した段。
    pub stage: PublishStage,
    /// イベントの topic（固定語彙。イベントに紐づかない失敗は `None`）。
    pub topic: Option<&'static str>,
    /// OS の errno（あれば）。
    pub errno: Option<i32>,
    /// 子の終了コード（`ExitStatus` のとき）。
    pub exit_code: Option<i32>,
    /// 子を終わらせたシグナル（あれば）。
    pub signal: Option<i32>,
    /// 期限切れの後に子を回収できたか（`Deadline` のとき）。
    pub reaped: Option<bool>,
}

impl PublishFailure {
    /// 段と topic だけの失敗を作る。
    pub fn new(stage: PublishStage, topic: Option<&'static str>) -> Self {
        Self {
            stage,
            topic,
            errno: None,
            exit_code: None,
            signal: None,
            reaped: None,
        }
    }

    #[cfg(unix)]
    fn with_errno(mut self, e: &std::io::Error) -> Self {
        self.errno = e.raw_os_error();
        self
    }

    /// 1 行の JSON（`report_cleanup_failure` と同じ code / message の形）。
    pub fn to_json_line(&self) -> String {
        serde_json::json!({
            "code": "UNAVAILABLE",
            "message": "task event publish failed",
            "stage": self.stage.as_str(),
            "topic": self.topic,
            "errno": self.errno,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "reaped": self.reaped,
        })
        .to_string()
    }
}

/// 失敗の出力先。本番は [`StderrPublishLog`]（デーモンの stderr = `daemon.log`）、試験は捕捉用の実装。
pub trait PublishLog: Send + Sync {
    /// 失敗を 1 件記録する。有界時間で戻ること。
    fn record(&self, failure: &PublishFailure);

    /// publish 1 件の結果（成功・失敗）と経過時間を記録する（REPAIR-4・#4155）。既定は何もしない。
    /// 失敗の詳細は [`PublishLog::record`] が別に出す。topic と経過ミリ秒だけを持ち、秘匿情報を含めない。
    fn record_outcome(&self, _topic: &'static str, _ok: bool, _elapsed: Duration) {}
}

/// デーモンの stderr へ JSON 1 行を出す本番の出力先。
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrPublishLog;

impl PublishLog for StderrPublishLog {
    fn record(&self, failure: &PublishFailure) {
        use std::io::Write;
        // stderr が閉じていても panic しない（eprintln! は書き込み失敗で panic する）。
        let _ = writeln!(std::io::stderr(), "{}", failure.to_json_line());
    }

    fn record_outcome(&self, topic: &'static str, ok: bool, elapsed: Duration) {
        use std::io::Write;
        let line = serde_json::json!({
            "event": "task_event_publish",
            "topic": topic,
            "ok": ok,
            "elapsed_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        });
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

/// イベントがまだ有効（取り消されていない世代）かを返す述語。worker スレッドから呼ばれる。
pub type EventGuard = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

/// イベントの送り先。`TaskService::with_event_publisher` で差し込む。
pub trait EventPublisher: Send + Sync {
    /// イベントを送る。有界時間で戻る契約（キューへ入れるだけ）。失敗は戻り値でなくログに出す。
    fn publish(&self, event: TaskEvent);

    /// 送信直前に `still_valid` を再確認して送る。false なら破棄する（Delete 後の旧世代のイベントを送らない。CRI-5・#4155）。
    ///
    /// 既定は呼び出し時に 1 回確認して [`Self::publish`] する。キューを持つ実装は、キューに積んだ後の取り消しを守るため
    /// 子の起動の直前（worker 側）で再確認する。確認から exec までの極小の窓は残る（子の起動を Delete と直列にはしない。Delete を詰まらせないため）。
    fn publish_guarded(&self, event: TaskEvent, still_valid: EventGuard) {
        if still_valid() {
            self.publish(event);
        }
    }

    /// publish 以外の失敗（watcher の起動失敗・上限・食い違い）を記録する。
    fn report(&self, failure: PublishFailure);
}

/// 子プロセスの期限。壊れた値（ゼロ・60 秒超）は [`PublishConfig::new`] で拒否する（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishConfig {
    timeout: Duration,
}

impl PublishConfig {
    /// 期限から作る。ゼロまたは 60 秒超は `InvalidArgument`。
    pub fn new(timeout: Duration) -> Result<Self, CriError> {
        if timeout.is_zero() || timeout > MAX_PUBLISH_TIMEOUT {
            return Err(CriError::invalid_argument(
                "publish timeout must be in 1ns..=60s",
            ));
        }
        Ok(Self { timeout })
    }

    /// 子 1 件の期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for PublishConfig {
    /// 期限 5 秒（暫定値。実 containerd での実測は #3685）。
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(unix)]
pub use unix::{ExecEventPublisher, PublishTarget, exec_publisher_for, exec_publisher_for_with};

#[cfg(unix)]
mod unix {
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{
        EventGuard, EventPublisher, PublishConfig, PublishFailure, PublishLog, PublishStage,
        StderrPublishLog, TaskEvent,
    };
    use crate::shim_v2::bootstrap::{PublishBinary, ServeContext, ShimIdentifier};

    /// キューの長さ。満杯なら捨てて `enqueue` を記録する。
    const QUEUE_CAP: usize = 128;
    /// kill の後に回収を待つ猶予。
    const REAP_GRACE: Duration = Duration::from_secs(1);
    /// `try_wait` の刻み。
    const WAIT_SLICE: Duration = Duration::from_millis(10);

    /// キューの 1 件。世代の述語（任意）をイベントと一緒に保持し、送信直前に再確認する。
    type Queued = (TaskEvent, Option<EventGuard>);

    /// 子の起動に必要な検証済みの値の組。
    #[derive(Debug, Clone)]
    pub struct PublishTarget {
        binary: PublishBinary,
        address: PathBuf,
        namespace: ShimIdentifier,
    }

    impl PublishTarget {
        /// 3 つが揃うときだけ作る（serve では `-address`・`-namespace` が必須のため、欠けるのは `-publish-binary` だけ）。
        pub fn from_context(ctx: &ServeContext) -> Option<Self> {
            Some(Self {
                binary: ctx.publish_binary()?.clone(),
                address: ctx.address()?.to_path_buf(),
                namespace: ctx.namespace()?.clone(),
            })
        }

        /// 子の argv（`argv[0]` を除く）。値は検証済みのものと固定語彙だけ。
        pub fn args(&self, topic: &'static str) -> Vec<OsString> {
            vec![
                "--address".into(),
                self.address.clone().into_os_string(),
                "publish".into(),
                "--namespace".into(),
                self.namespace.as_str().into(),
                "--topic".into(),
                topic.into(),
            ]
        }

        /// 検査済みの実行ファイル。
        pub fn binary(&self) -> &Path {
            self.binary.as_path()
        }
    }

    /// 子プロセスで publish する本番の送り先。worker スレッドは最初の publish のときに遅延して起こす。
    pub struct ExecEventPublisher {
        target: Arc<PublishTarget>,
        config: PublishConfig,
        log: Arc<dyn PublishLog>,
        tx: Mutex<Option<SyncSender<Queued>>>,
    }

    impl std::fmt::Debug for ExecEventPublisher {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ExecEventPublisher")
                .field("config", &self.config)
                .finish_non_exhaustive()
        }
    }

    impl ExecEventPublisher {
        /// 送り先・期限・ログ出力先から作る。
        pub fn new(target: PublishTarget, config: PublishConfig, log: Arc<dyn PublishLog>) -> Self {
            Self {
                target: Arc::new(target),
                config,
                log,
                tx: Mutex::new(None),
            }
        }

        fn sender(&self, topic: &'static str) -> Option<SyncSender<Queued>> {
            let mut guard = self.tx.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(tx) = guard.as_ref() {
                return Some(tx.clone());
            }
            let (tx, rx) = sync_channel(QUEUE_CAP);
            let (target, config, log) =
                (Arc::clone(&self.target), self.config, Arc::clone(&self.log));
            let spawned = std::thread::Builder::new()
                .name("shim-event-publish".into())
                .spawn(move || worker(&rx, &target, config, log.as_ref()));
            match spawned {
                Ok(_) => {
                    *guard = Some(tx.clone());
                    Some(tx)
                }
                Err(e) => {
                    self.log.record(
                        &PublishFailure::new(PublishStage::WorkerSpawn, Some(topic)).with_errno(&e),
                    );
                    None
                }
            }
        }
    }

    impl EventPublisher for ExecEventPublisher {
        fn publish(&self, event: TaskEvent) {
            self.enqueue(event, None);
        }

        fn publish_guarded(&self, event: TaskEvent, still_valid: EventGuard) {
            if still_valid() {
                self.enqueue(event, Some(still_valid));
            }
        }

        fn report(&self, failure: PublishFailure) {
            self.log.record(&failure);
        }
    }

    impl ExecEventPublisher {
        fn enqueue(&self, event: TaskEvent, guard: Option<EventGuard>) {
            let topic = event.topic();
            let Some(tx) = self.sender(topic) else {
                return;
            };
            match tx.try_send((event, guard)) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    self.log
                        .record(&PublishFailure::new(PublishStage::Enqueue, Some(topic)));
                }
            }
        }
    }

    /// キューを直列に処理する。送り側（publisher）が落ちたら終わる。
    fn worker(
        rx: &Receiver<Queued>,
        target: &PublishTarget,
        config: PublishConfig,
        log: &dyn PublishLog,
    ) {
        while let Ok((event, guard)) = rx.recv() {
            // キューで待つ間に Delete された世代のイベントは送らない（CRI-5・#4155）。
            if guard.as_ref().is_some_and(|g| !g()) {
                continue;
            }
            let started = Instant::now();
            let result = run_bounded(target, config, &event);
            if let Err(failure) = &result {
                log.record(failure);
            }
            log.record_outcome(event.topic(), result.is_ok(), started.elapsed());
        }
    }

    /// 子を 1 件、期限つきで実行する。失敗は最初に起きた段 1 件だけ返す。
    fn run_bounded(
        target: &PublishTarget,
        config: PublishConfig,
        event: &TaskEvent,
    ) -> Result<(), PublishFailure> {
        let topic = event.topic();
        let fail = |stage| PublishFailure::new(stage, Some(topic));
        let payload = event.encode_any()?;
        let mut child = Command::new(target.binary())
            .args(target.args(topic))
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| fail(PublishStage::Spawn).with_errno(&e))?;
        let deadline = Instant::now() + config.timeout();
        // 最初の失敗だけを覚え、回収は必ず続ける。
        let mut first: Option<PublishFailure> = None;
        if let Some(mut stdin) = child.stdin.take() {
            // 上限（MAX_EVENT_LEN）が pipe の容量に収まるため、子が読まなくてもブロックしない。drop で EOF を送る。
            if let Err(e) = stdin.write_all(&payload) {
                first = Some(fail(PublishStage::WriteStdin).with_errno(&e));
            }
        }
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(f) = first {
                        return Err(f);
                    }
                    if status.success() {
                        return Ok(());
                    }
                    let mut f = fail(PublishStage::ExitStatus);
                    f.exit_code = status.code();
                    f.signal = status.signal();
                    return Err(f);
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.try_wait();
                    return Err(first.unwrap_or_else(|| fail(PublishStage::Wait).with_errno(&e)));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                let _ = child.kill();
                let reaped = reap(&mut child);
                let mut f = first.unwrap_or_else(|| fail(PublishStage::Deadline));
                if f.stage == PublishStage::Deadline {
                    f.reaped = Some(reaped);
                }
                return Err(f);
            }
            std::thread::sleep(WAIT_SLICE.min(deadline - now));
        }
    }

    /// kill の後、猶予内に回収する。回収できたか。
    fn reap(child: &mut std::process::Child) -> bool {
        let until = Instant::now() + REAP_GRACE;
        loop {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(WAIT_SLICE);
        }
    }

    /// 本番の差し込み口。`-publish-binary` が無いときは `disabled` を 1 件記録して `None`（エラーにはしない。#4155）。
    pub fn exec_publisher_for(ctx: &ServeContext) -> Option<Arc<dyn EventPublisher>> {
        exec_publisher_for_with(ctx, PublishConfig::default(), Arc::new(StderrPublishLog))
    }

    /// [`exec_publisher_for`] の期限とログ出力先を差し替える版（試験用）。
    pub fn exec_publisher_for_with(
        ctx: &ServeContext,
        config: PublishConfig,
        log: Arc<dyn PublishLog>,
    ) -> Option<Arc<dyn EventPublisher>> {
        match PublishTarget::from_context(ctx) {
            Some(target) => Some(Arc::new(ExecEventPublisher::new(target, config, log))),
            None => {
                log.record(&PublishFailure::new(PublishStage::Disabled, None));
                None
            }
        }
    }
}

/// 試験の共有部品（偽の publish バイナリ・捕捉用の出力先）。
#[cfg(test)]
pub(crate) mod testkit {
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use super::PublishLog;
    use super::{
        EventPublisher, PublishFailure, TaskCreate, TaskDelete, TaskEvent, TaskIo, TaskStart,
    };
    use crate::shim_v2::task_api::Timestamp;

    /// 捕捉用の出力先。
    #[cfg(unix)]
    #[derive(Default)]
    pub(crate) struct CaptureLog(pub(crate) Mutex<Vec<PublishFailure>>);

    #[cfg(unix)]
    impl PublishLog for CaptureLog {
        fn record(&self, failure: &PublishFailure) {
            self.0.lock().unwrap().push(failure.clone());
        }
    }

    /// 捕捉用の送り先。
    #[derive(Default)]
    pub(crate) struct CapturePublisher {
        pub(crate) events: Mutex<Vec<TaskEvent>>,
        pub(crate) failures: Mutex<Vec<PublishFailure>>,
    }

    impl EventPublisher for CapturePublisher {
        fn publish(&self, event: TaskEvent) {
            self.events.lock().unwrap().push(event);
        }
        fn report(&self, failure: PublishFailure) {
            self.failures.lock().unwrap().push(failure);
        }
    }

    /// 偽の publish バイナリ（`/bin/sh` スクリプト、0755）を `dir/name` に作る。
    ///
    /// ETXTBSY を避けるため、書き込みと chmod は子プロセスで行い、試験プロセスは書き込み用 fd を持たない。
    #[cfg(unix)]
    pub(crate) fn make_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let st = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#)
            .arg("sh")
            .arg(body)
            .arg(&path)
            .status()
            .expect("run sh");
        assert!(st.success(), "script creation failed");
        path
    }

    /// 引数を行ごとに argv ファイルへ、stdin を stdin ファイルへ書く記録型。
    #[cfg(unix)]
    pub(crate) fn recorder_body(out: &Path) -> String {
        let d = out.display();
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{d}/argv\"\n/bin/cat > \"{d}/stdin.tmp\"\n/bin/mv \"{d}/stdin.tmp\" \"{d}/stdin\"\n"
        )
    }

    /// stdin を読み切って終了コード 7 で終わる型。
    #[cfg(unix)]
    pub(crate) fn failing_body() -> String {
        "#!/bin/sh\n/bin/cat > /dev/null\nexit 7\n".to_owned()
    }

    /// pid を書いて 30 秒眠る型。
    #[cfg(unix)]
    pub(crate) fn sleeping_body(out: &Path) -> String {
        format!(
            "#!/bin/sh\necho $$ > \"{d}/pid\"\nexec /bin/sleep 30\n",
            d = out.display()
        )
    }

    /// Create・Start・Delete の見本（#4156）。
    pub(crate) fn three_events() -> [TaskEvent; 3] {
        [
            TaskEvent::Create(TaskCreate {
                container_id: "c1".into(),
                bundle: "/run/b".into(),
                rootfs: Vec::new(),
                io: Some(TaskIo::default()),
                checkpoint: String::new(),
                pid: 4242,
            }),
            TaskEvent::Start(TaskStart {
                container_id: "c1".into(),
                pid: 4242,
            }),
            TaskEvent::Delete(TaskDelete {
                container_id: "c1".into(),
                pid: 4242,
                exit_status: 3,
                exited_at: Some(Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 5,
                }),
                id: "c1".into(),
            }),
        ]
    }

    /// 条件が真になるまで期限つきで待つ。
    pub(crate) fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let until = Instant::now() + limit;
        loop {
            if cond() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::three_events;
    use super::*;

    /// CRI-5・#4155: TaskExit を符号化した `Any` は具体値で往復し、type URL と topic は固定語彙。
    #[test]
    fn cri5_4155_task_exit_encodes_as_any() {
        let ev = TaskEvent::Exit(TaskExit {
            container_id: "c1".into(),
            id: "c1".into(),
            pid: 4242,
            exit_status: 3,
            exited_at: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 5,
            }),
        });
        assert_eq!(ev.topic(), "/tasks/exit");
        let any = Any::decode(ev.encode_any().unwrap().as_slice()).unwrap();
        assert_eq!(any.type_url, "containerd.events.TaskExit");
        let exit = TaskExit::decode(any.value.as_slice()).unwrap();
        assert_eq!(
            exit,
            TaskExit {
                container_id: "c1".into(),
                id: "c1".into(),
                pid: 4242,
                exit_status: 3,
                exited_at: Some(Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 5
                }),
            }
        );
        // 番号 1..=5 の wire 形式（container_id = 1 の長さ付き文字列が先頭）。
        assert_eq!(&any.value[..4], &[0x0a, 0x02, b'c', b'1']);
    }

    /// CRI-5・#4156: TaskCreate・TaskStart・TaskDelete の `Any` は具体値で往復し、type URL と topic は固定語彙。
    #[test]
    fn cri5_4156_task_create_start_delete_encode_as_any() {
        let [c, s, d] = three_events();
        for (ev, topic, url) in [
            (&c, "/tasks/create", "containerd.events.TaskCreate"),
            (&s, "/tasks/start", "containerd.events.TaskStart"),
            (&d, "/tasks/delete", "containerd.events.TaskDelete"),
        ] {
            assert_eq!(ev.topic(), topic);
            let any = Any::decode(ev.encode_any().unwrap().as_slice()).unwrap();
            assert_eq!(any.type_url, url);
        }
        let any = Any::decode(c.encode_any().unwrap().as_slice()).unwrap();
        // container_id = 1、bundle = 2、io = 4（空メッセージ）、pid = 6。
        assert_eq!(
            any.value,
            [
                &[0x0a, 0x02, b'c', b'1', 0x12, 0x06][..],
                b"/run/b",
                &[0x22, 0x00, 0x30, 0x92, 0x21][..]
            ]
            .concat()
        );
        let any = Any::decode(s.encode_any().unwrap().as_slice()).unwrap();
        assert_eq!(any.value, [0x0a, 0x02, b'c', b'1', 0x10, 0x92, 0x21]);
        let any = Any::decode(d.encode_any().unwrap().as_slice()).unwrap();
        let TaskEvent::Delete(want) = &d else {
            unreachable!()
        };
        assert_eq!(&TaskDelete::decode(any.value.as_slice()).unwrap(), want);
    }

    /// REPAIR-5・#4156: 上限を超える TaskCreate（長い bundle）は `encode` で失敗し、topic つきで記録される。
    #[test]
    fn repair5_4156_oversized_task_create_is_rejected() {
        let ev = TaskEvent::Create(TaskCreate {
            container_id: "c1".into(),
            bundle: "b".repeat(MAX_EVENT_LEN),
            ..Default::default()
        });
        let err = ev.encode_any().unwrap_err();
        assert_eq!(err.stage, PublishStage::Encode);
        assert_eq!(err.topic, Some("/tasks/create"));
    }

    /// REPAIR-5: 上限を超えるイベントは `encode` で失敗する。
    #[test]
    fn repair5_4155_oversized_event_is_rejected() {
        let ev = TaskEvent::Exit(TaskExit {
            container_id: "x".repeat(MAX_EVENT_LEN),
            ..Default::default()
        });
        let f = ev.encode_any().unwrap_err();
        assert_eq!(f.stage, PublishStage::Encode);
        assert_eq!(f.topic, Some("/tasks/exit"));
    }

    /// REPAIR-2: 期限の境界（ゼロと 60 秒超は拒否、60 秒ちょうどは受理）。
    #[test]
    fn repair2_4155_publish_config_bounds() {
        assert!(PublishConfig::new(Duration::ZERO).is_err());
        assert!(PublishConfig::new(Duration::from_secs(61)).is_err());
        assert_eq!(
            PublishConfig::new(Duration::from_secs(60))
                .unwrap()
                .timeout(),
            Duration::from_secs(60)
        );
        assert_eq!(PublishConfig::default().timeout(), Duration::from_secs(5));
    }

    /// REPAIR-4: 失敗のログ行は固定語彙だけを持つ。
    #[test]
    fn repair4_4155_failure_json_line_is_fixed_vocabulary() {
        let mut f = PublishFailure::new(PublishStage::ExitStatus, Some(TASK_EXIT_TOPIC));
        f.exit_code = Some(7);
        assert_eq!(
            f.to_json_line(),
            r#"{"code":"UNAVAILABLE","errno":null,"exit_code":7,"message":"task event publish failed","reaped":null,"signal":null,"stage":"exit_status","topic":"/tasks/exit"}"#
        );
        let g = PublishFailure::new(PublishStage::Disabled, None);
        assert!(g.to_json_line().contains(r#""stage":"disabled""#));
        assert!(g.to_json_line().contains(r#""topic":null"#));
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::testkit::*;
    use super::*;
    use crate::shim_v2::bootstrap::{PublishBinary, ServeContext, ShimIdentifier};
    use crate::shim_v2::shutdown::ShutdownSignal;
    use crate::test_root;

    const ADDR: &str = "/run/secret-addr-4155/containerd.sock.ttrpc";

    fn sample() -> TaskEvent {
        TaskEvent::Exit(TaskExit {
            container_id: "c1".into(),
            id: "c1".into(),
            pid: 4242,
            exit_status: 3,
            exited_at: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123,
            }),
        })
    }

    fn publisher(
        bin: &std::path::Path,
        timeout: Duration,
        log: Arc<CaptureLog>,
    ) -> Arc<dyn EventPublisher> {
        let ctx = ServeContext::new(ShutdownSignal::new(), None)
            .with_origin(
                Some(ShimIdentifier::parse("default").unwrap()),
                Some(ADDR.into()),
            )
            .with_publish_binary(Some(PublishBinary::verify(bin).unwrap()));
        exec_publisher_for_with(&ctx, PublishConfig::new(timeout).unwrap(), log).expect("some")
    }

    /// CRI-5・#4155: 偽の publish バイナリが argv と stdin を具体値で受け取る。
    #[test]
    fn cri5_4155_publish_passes_argv_and_stdin() {
        let dir = test_root::test_root("pub", "argv");
        let bin = make_script(&dir, "fake", &recorder_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        p.publish(sample());
        assert!(wait_until(Duration::from_secs(10), || dir
            .join("stdin")
            .exists()));
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        assert_eq!(
            argv.lines().collect::<Vec<_>>(),
            vec![
                "--address",
                ADDR,
                "publish",
                "--namespace",
                "default",
                "--topic",
                "/tasks/exit"
            ]
        );
        let any = Any::decode(std::fs::read(dir.join("stdin")).unwrap().as_slice()).unwrap();
        assert_eq!(any.type_url, "containerd.events.TaskExit");
        let exit = TaskExit::decode(any.value.as_slice()).unwrap();
        assert_eq!(exit.container_id, "c1");
        assert_eq!(exit.id, "c1");
        assert_eq!(exit.pid, 4242);
        assert_eq!(exit.exit_status, 3);
        assert_eq!(
            exit.exited_at,
            Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123
            })
        );
        assert!(log.0.lock().unwrap().is_empty());
    }

    /// CRI-5・#4156: 3 種それぞれで、偽の publish バイナリが argv の topic と stdin の `Any` を具体値で受け取る。
    #[test]
    fn cri5_4156_publish_passes_argv_and_stdin_for_each_topic() {
        for (i, ev) in three_events().into_iter().enumerate() {
            let dir = test_root::test_root("pub", &format!("t4156-{i}"));
            let bin = make_script(&dir, "fake", &recorder_body(&dir));
            let log = Arc::new(CaptureLog::default());
            let p = publisher(&bin, Duration::from_secs(5), log.clone());
            let topic = ev.topic();
            p.publish(ev.clone());
            assert!(wait_until(Duration::from_secs(10), || dir
                .join("stdin")
                .exists()));
            let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
            assert_eq!(
                argv.lines().collect::<Vec<_>>(),
                [
                    "--address",
                    ADDR,
                    "publish",
                    "--namespace",
                    "default",
                    "--topic",
                    topic
                ]
            );
            let bytes = std::fs::read(dir.join("stdin")).unwrap();
            assert_eq!(bytes, ev.encode_any().unwrap());
            assert!(log.0.lock().unwrap().is_empty());
        }
    }

    /// REPAIR-5・REPAIR-4・#4156: 3 種それぞれの非 0 終了は topic つきの失敗がちょうど 1 件で、秘匿値はログに出ない。
    #[test]
    fn repair5_4156_nonzero_exit_logs_one_failure_per_topic() {
        for (i, ev) in three_events().into_iter().enumerate() {
            let dir = test_root::test_root("pub", &format!("f4156-{i}"));
            let bin = make_script(&dir, "fake", &failing_body());
            let log = Arc::new(CaptureLog::default());
            let p = publisher(&bin, Duration::from_secs(5), log.clone());
            let topic = ev.topic();
            p.publish(ev);
            assert!(wait_until(Duration::from_secs(10), || !log
                .0
                .lock()
                .unwrap()
                .is_empty()));
            std::thread::sleep(Duration::from_millis(100));
            let got = log.0.lock().unwrap().clone();
            assert_eq!(got.len(), 1, "{got:?}");
            assert_eq!(got[0].stage, PublishStage::ExitStatus);
            assert_eq!(got[0].topic, Some(topic));
            let line = got[0].to_json_line();
            for secret in [ADDR, "default", "c1", "/run/b", "secret-addr-4155"] {
                assert!(!line.contains(secret), "{line}");
            }
        }
    }

    /// CRI-5・#4155: キューに積んだ後に取り消された世代のイベントは、worker が送信直前の再確認で捨てる。
    #[test]
    fn cri5_4155_queued_event_revoked_before_send_is_dropped() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = test_root::test_root("pub", "revoked");
        let bin = make_script(&dir, "fake", &recorder_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        // 1 回目（投入時）は有効、2 回目（worker の再確認）は取り消し済み。
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        p.publish_guarded(
            sample(),
            Arc::new(move || c.fetch_add(1, Ordering::SeqCst) == 0),
        );
        assert!(wait_until(Duration::from_secs(10), || calls
            .load(Ordering::SeqCst)
            >= 2));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!dir.join("stdin").exists());
        assert!(log.0.lock().unwrap().is_empty());
        // 有効なイベントは worker が生きていて送られる。
        p.publish_guarded(sample(), Arc::new(|| true));
        assert!(wait_until(Duration::from_secs(10), || dir
            .join("stdin")
            .exists()));
    }

    /// REPAIR-5・REPAIR-4: 非 0 終了はちょうど 1 件の `exit_status` で、argv・アドレスなどはログに出ない。
    #[test]
    fn repair5_4155_nonzero_exit_logs_exactly_one_failure() {
        let dir = test_root::test_root("pub", "fail");
        let bin = make_script(&dir, "fake", &failing_body());
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        p.publish(sample());
        assert!(wait_until(Duration::from_secs(10), || !log
            .0
            .lock()
            .unwrap()
            .is_empty()));
        std::thread::sleep(Duration::from_millis(100));
        let got = log.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stage, PublishStage::ExitStatus);
        assert_eq!(got[0].exit_code, Some(7));
        let line = got[0].to_json_line();
        for secret in [ADDR, "default", "c1", "secret-addr-4155"] {
            assert!(!line.contains(secret), "{line}");
        }
    }

    /// REPAIR-5: 期限を超えて眠る子は kill して回収され、失敗はちょうど 1 件の `deadline`（`reaped = true`）。
    #[test]
    fn repair5_4155_sleeping_child_is_killed_and_reaped() {
        let dir = test_root::test_root("pub", "sleep");
        let bin = make_script(&dir, "fake", &sleeping_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let timeout = Duration::from_millis(500);
        let p = publisher(&bin, timeout, log.clone());
        let started = std::time::Instant::now();
        p.publish(sample());
        assert!(wait_until(Duration::from_secs(10), || !log
            .0
            .lock()
            .unwrap()
            .is_empty()));
        assert!(
            started.elapsed() < timeout + Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(100));
        let got = log.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stage, PublishStage::Deadline);
        assert_eq!(got[0].reaped, Some(true));
        #[cfg(target_os = "linux")]
        {
            let pid = std::fs::read_to_string(dir.join("pid")).unwrap();
            let pid = pid.trim();
            assert!(!pid.is_empty());
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "child {pid} must be reaped"
            );
        }
    }

    /// CRI-5・#4155: `-publish-binary` が無ければ `None` と `disabled` が 1 件。3 つ揃えば `Some`。
    #[test]
    fn cri5_4155_publisher_is_none_without_publish_binary() {
        let log = Arc::new(CaptureLog::default());
        let ctx = ServeContext::new(ShutdownSignal::new(), None).with_origin(
            Some(ShimIdentifier::parse("default").unwrap()),
            Some(ADDR.into()),
        );
        assert!(PublishTarget::from_context(&ctx).is_none());
        assert!(exec_publisher_for_with(&ctx, PublishConfig::default(), log.clone()).is_none());
        let got = log.0.lock().unwrap().clone();
        assert_eq!(got, vec![PublishFailure::new(PublishStage::Disabled, None)]);

        let dir = test_root::test_root("pub", "target");
        let bin = make_script(&dir, "fake", &failing_body());
        let ctx = ctx.with_publish_binary(Some(PublishBinary::verify(&bin).unwrap()));
        let t = PublishTarget::from_context(&ctx).expect("some");
        assert_eq!(t.binary(), bin.as_path());
        assert_eq!(t.args("/tasks/exit").len(), 7);
    }
}
