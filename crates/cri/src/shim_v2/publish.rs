//! shim v2 のイベント publish（TaskCreate・TaskStart・TaskDelete・TaskExit・TaskExecAdded・TaskExecStarted の 6 種）。期限つきの子プロセスで containerd の `publish` を呼ぶ（CRI-5・TASK-62.6・REPAIR-3・REPAIR-5・#4155）。
//!
//! containerd（特に CRI）はコンテナの終了を `/tasks/exit` の TaskExit で知る。Create・Start・Delete の成功も
//! `/tasks/create`・`/tasks/start`・`/tasks/delete` で送り（#4156）、exec の `Exec`・`Start(exec_id)` の成功も
//! `/tasks/exec-added`・`/tasks/exec-started` で送る（#4281。runc shim と同じ時点・同じ欄）。shim は `-publish-binary`
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
//! - 送らない種別: exec の TaskExit（exec 用の終了 watcher が無い。後続候補。containerd の CRI は exec の TaskExit を無視する）・TaskPaused・TaskResumed・TaskCheckpointed・TaskOOM（対応する RPC・仕組みが無い）。
//! - Create・Start・Delete・ExecAdded・ExecStarted は RPC が成功する直前に 1 回だけ [`EventPublisher::publish`] で投入する（世代の guard は使わない。完了済みの事実の記録で、
//!   ゲート保持中の投入順が FIFO の worker で保たれる）。符号化後 [`MAX_EVENT_LEN`]（8192）を超えるイベントは子を起動せず、
//!   `encode` の失敗が 1 件記録される（RPC の応答は変えない）。stdin は socketpair の片端で、親は非ブロッキングに期限内で書き、書き終えたら EOF を送る（#4223）。
//! - shim の Shutdown でキューに残った未送信のイベントは、[`PublisherDrains::drain_all`] が排出する（#4222）。呼ぶのは `bootstrap` の
//!   `run_serve` で、Shutdown の応答を流し切り・サーバーを止め・ID ロックと socket を片付けた後（runc shim と同じ順序）。
//!   キューへ新しい投入を止め、worker が残りを送り切るのを [`PublishConfig::drain_timeout`]（既定 3 秒）まで待つ。超えたら実行中の子を
//!   kill して回収し（最悪 `drain_timeout + REAP_GRACE` と数刻み）、残りは送らずに件数を `daemon.log` へ 1 行（[`PublishDrain`]）出す。
//!   排出の後の投入（終了 watcher の遅れた TaskExit 等）は `enqueue` として記録して捨てる。
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
/// TaskExecAdded の type URL。
pub const TASK_EXEC_ADDED_TYPE_URL: &str = "containerd.events.TaskExecAdded";
/// TaskExecStarted の type URL。
pub const TASK_EXEC_STARTED_TYPE_URL: &str = "containerd.events.TaskExecStarted";
/// TaskExecAdded の topic。
pub const TASK_EXEC_ADDED_TOPIC: &str = "/tasks/exec-added";
/// TaskExecStarted の topic。
pub const TASK_EXEC_STARTED_TOPIC: &str = "/tasks/exec-started";
/// TaskCreate の topic。
pub const TASK_CREATE_TOPIC: &str = "/tasks/create";
/// TaskStart の topic。
pub const TASK_START_TOPIC: &str = "/tasks/start";
/// TaskDelete の topic。
pub const TASK_DELETE_TOPIC: &str = "/tasks/delete";
/// TaskExit の topic。
pub const TASK_EXIT_TOPIC: &str = "/tasks/exit";
/// 符号化後の `Any` の上限。1 件の確保と stdin の送信量を有界にするための値（REPAIR-2）。
///
/// stdin は期限内の非ブロッキング書き込みのため pipe 容量には依存しない（#4223）。導出: 最大の TaskCreate は
/// `container_id` 255 バイト・`bundle` 4096 バイト（`BUNDLE_MAX_LEN`）・`pid` で約 4.4 KiB に収まり、その約 1.9 倍の余裕を取る。
pub const MAX_EVENT_LEN: usize = 8192;
/// 排出の既定の期限（暫定値。実 containerd での実測は #3685。containerd の Shutdown 呼び出しの期限 3 秒に合わせる）。
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
/// 設定に許す最大の期限（publish 1 件・排出のどちらにも使う）。
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
    /// exec の ID。init の削除では runc shim v2 と同じく空（省略は init を指す。`api/events/task.proto`。#4222）。
    #[prost(string, tag = "5")]
    pub id: String,
}

/// `containerd.events.TaskExecAdded`（番号 1〜2）。`Exec` の成功で送る（#4281）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskExecAdded {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub container_id: String,
    /// exec の ID。
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

/// `containerd.events.TaskExecStarted`（番号 1〜3）。`Start(exec_id)` の成功で送る（#4281）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TaskExecStarted {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub container_id: String,
    /// exec の ID。
    #[prost(string, tag = "2")]
    pub exec_id: String,
    /// exec プロセスの pid。`StartResponse.pid` と同じ値で、本番の起動役は pid を返さないため 0 になる（実 pid を装わない。REPAIR-3）。
    #[prost(uint32, tag = "3")]
    pub pid: u32,
}

/// publish するイベント（#4155・#4156・#4281）。
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
    /// exec の登録成功（`/tasks/exec-added`）。
    ExecAdded(TaskExecAdded),
    /// exec の起動成功（`/tasks/exec-started`）。
    ExecStarted(TaskExecStarted),
}

impl TaskEvent {
    /// イベントの topic（固定語彙）。
    pub fn topic(&self) -> &'static str {
        match self {
            Self::Create(_) => TASK_CREATE_TOPIC,
            Self::Start(_) => TASK_START_TOPIC,
            Self::Delete(_) => TASK_DELETE_TOPIC,
            Self::Exit(_) => TASK_EXIT_TOPIC,
            Self::ExecAdded(_) => TASK_EXEC_ADDED_TOPIC,
            Self::ExecStarted(_) => TASK_EXEC_STARTED_TOPIC,
        }
    }

    /// stdin へ渡す `Any` の符号化。上限（[`MAX_EVENT_LEN`]）を超えたら失敗する。
    pub fn encode_any(&self) -> Result<Vec<u8>, PublishFailure> {
        let (type_url, value) = match self {
            Self::Create(e) => (TASK_CREATE_TYPE_URL, e.encode_to_vec()),
            Self::Start(e) => (TASK_START_TYPE_URL, e.encode_to_vec()),
            Self::Delete(e) => (TASK_DELETE_TYPE_URL, e.encode_to_vec()),
            Self::Exit(e) => (TASK_EXIT_TYPE_URL, e.encode_to_vec()),
            Self::ExecAdded(e) => (TASK_EXEC_ADDED_TYPE_URL, e.encode_to_vec()),
            Self::ExecStarted(e) => (TASK_EXEC_STARTED_TYPE_URL, e.encode_to_vec()),
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

    /// Shutdown 時の排出 1 回の結果を記録する（REPAIR-4・#4222）。既定は何もしない。
    fn record_drain(&self, _drain: &PublishDrain) {}
}

/// Shutdown 時の排出 1 回の結果。件数・真偽・経過時間だけを持つ（秘匿情報を持てない型。REPAIR-4・#4222）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishDrain {
    /// 排出の開始時にキューと実行中に残っていた件数。
    pub queued: usize,
    /// 送れずに捨てた件数（期限切れで kill した実行中の 1 件を含む）。
    pub dropped: usize,
    /// 期限（[`PublishConfig::drain_timeout`]）を超えて打ち切ったか。
    pub deadline_hit: bool,
    /// worker スレッドが終了したか（false は D 状態の子などで回収できなかった）。
    pub worker_finished: bool,
    /// 排出に要した時間。
    pub elapsed: Duration,
}

impl PublishDrain {
    /// 1 行の JSON（固定語彙。topic・argv・アドレス・ID・本文は含めない）。
    pub fn to_json_line(&self) -> String {
        serde_json::json!({
            "event": "task_event_publish_drain",
            "outcome": if self.deadline_hit { "deadline" } else { "complete" },
            "queued": self.queued,
            "dropped": self.dropped,
            "worker_finished": self.worker_finished,
            "elapsed_ms": u64::try_from(self.elapsed.as_millis()).unwrap_or(u64::MAX),
        })
        .to_string()
    }
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

    fn record_drain(&self, drain: &PublishDrain) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{}", drain.to_json_line());
    }
}

/// イベントがまだ有効（取り消されていない世代）かを返す述語。worker スレッドから呼ばれる。
pub type EventGuard = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

/// イベントの送り先。`TaskService::with_event_publisher` で差し込む。
pub trait EventPublisher: Send + Sync {
    /// イベントを送る。有界時間で戻る契約（キューへ入れるだけ）。失敗は戻り値でなくログに出す。
    fn publish(&self, event: TaskEvent);

    /// 送信直前に `still_valid` を再確認して送る。false なら破棄する（Create・再 Start で取り消された旧世代のイベントを送らない。Delete は取り消さない。CRI-5・#4155・#4224）。
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

    /// Shutdown 時にキューの未送信を有界時間で排出し、以降の投入を止める（#4222）。
    /// キューを持たない実装・worker を起こしていない実装・2 回目以降は `None`。
    fn drain(&self) -> Option<PublishDrain> {
        None
    }
}

/// 作られた [`EventPublisher`] の登録口。`ServeContext` が持ち、`exec_publisher_for_with` が自動で登録し、
/// `bootstrap` の `run_serve` が Shutdown の片付けの後に [`PublisherDrains::drain_all`] を呼ぶ（#4222）。
///
/// 登録は publisher の `Arc` を 1 つ余分に持つだけで、publisher の寿命は変えない（停止は `drain` で明示する。
/// 終了 watcher のスレッドが `Arc` を持ち続けるため、`Drop` 任せでは止まらない）。
#[derive(Clone, Default)]
pub struct PublisherDrains {
    inner: std::sync::Arc<std::sync::Mutex<Vec<std::sync::Arc<dyn EventPublisher>>>>,
}

impl std::fmt::Debug for PublisherDrains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublisherDrains").finish_non_exhaustive()
    }
}

impl PublisherDrains {
    /// publisher を登録する（`exec_publisher_for_with` から）。
    #[cfg(unix)]
    pub(crate) fn register(&self, publisher: std::sync::Arc<dyn EventPublisher>) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(publisher);
    }

    /// 登録済みの publisher を順に排出し、結果を返す。各 publisher の排出は有界（[`PublishConfig::drain_timeout`]）。
    pub fn drain_all(&self) -> Vec<PublishDrain> {
        let list: Vec<_> = self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone();
        list.iter().filter_map(|p| p.drain()).collect()
    }
}

/// 子プロセスの期限。壊れた値（ゼロ・60 秒超）は [`PublishConfig::new`] で拒否する（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishConfig {
    timeout: Duration,
    drain_timeout: Duration,
}

impl PublishConfig {
    /// 期限から作る。ゼロまたは 60 秒超は `InvalidArgument`。
    pub fn new(timeout: Duration) -> Result<Self, CriError> {
        if timeout.is_zero() || timeout > MAX_PUBLISH_TIMEOUT {
            return Err(CriError::invalid_argument(
                "publish timeout must be in 1ns..=60s",
            ));
        }
        Ok(Self {
            timeout,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        })
    }

    /// Shutdown 時の排出の期限を差し替える。ゼロまたは 60 秒超は `InvalidArgument`（#4222）。
    pub fn with_drain_timeout(mut self, drain_timeout: Duration) -> Result<Self, CriError> {
        if drain_timeout.is_zero() || drain_timeout > MAX_PUBLISH_TIMEOUT {
            return Err(CriError::invalid_argument(
                "publish drain timeout must be in 1ns..=60s",
            ));
        }
        self.drain_timeout = drain_timeout;
        Ok(self)
    }

    /// Shutdown 時の排出の期限。超えたら実行中の子を kill して残りを捨てる。
    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    /// 子 1 件の期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for PublishConfig {
    /// 期限 5 秒・排出の期限 3 秒（どちらも暫定値。実 containerd での実測は #3685）。
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

#[cfg(unix)]
pub use unix::{ExecEventPublisher, PublishTarget, exec_publisher_for, exec_publisher_for_with};

#[cfg(unix)]
mod unix {
    use std::ffi::OsString;
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use super::{
        EventGuard, EventPublisher, PublishConfig, PublishDrain, PublishFailure, PublishLog,
        PublishStage, StderrPublishLog, TaskEvent,
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

    /// worker と排出が共有する計数と中止の旗（#4222）。
    #[derive(Default)]
    struct Shared {
        /// 投入済みで未完了の件数（キュー + 実行中）。完了・世代取り消しで捨てた件だけ減らし、中止で捨てた件は残す（= 捨てた件数）。
        pending: AtomicUsize,
        /// 排出の期限切れで立てる。worker は実行中の子を kill して回収し、残りを取り出さずに終わる。
        abort: AtomicBool,
    }

    /// worker の状態。`Closed` は排出の後（新しい投入を受けず、worker も起こし直さない）。
    enum State {
        Idle,
        Running {
            tx: SyncSender<Queued>,
            handle: JoinHandle<()>,
        },
        Closed,
    }

    /// 子プロセスで publish する本番の送り先。worker スレッドは最初の publish のときに遅延して起こし、
    /// Shutdown では [`EventPublisher::drain`] が有界時間で止める（#4222）。
    pub struct ExecEventPublisher {
        target: Arc<PublishTarget>,
        config: PublishConfig,
        log: Arc<dyn PublishLog>,
        state: Mutex<State>,
        shared: Arc<Shared>,
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
                state: Mutex::new(State::Idle),
                shared: Arc::new(Shared::default()),
            }
        }

        /// worker を起こす（状態ロックの下で呼ぶ）。
        fn spawn_worker(&self) -> Result<State, std::io::Error> {
            let (tx, rx) = sync_channel(QUEUE_CAP);
            let (target, config, log, shared) = (
                Arc::clone(&self.target),
                self.config,
                Arc::clone(&self.log),
                Arc::clone(&self.shared),
            );
            let handle = std::thread::Builder::new()
                .name("shim-event-publish".into())
                .spawn(move || worker(&rx, &target, config, log.as_ref(), &shared))?;
            Ok(State::Running { tx, handle })
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

        fn drain(&self) -> Option<PublishDrain> {
            let started = Instant::now();
            let prev = {
                let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
                std::mem::replace(&mut *st, State::Closed)
            };
            let State::Running { tx, handle } = prev else {
                return None;
            };
            let queued = self.shared.pending.load(Ordering::SeqCst);
            // 送り側を閉じる。worker は残りを送り切って recv の失敗で終わる。
            drop(tx);
            let mut deadline_hit = false;
            if !wait_finished(&handle, self.config.drain_timeout()) {
                deadline_hit = true;
                self.shared.abort.store(true, Ordering::SeqCst);
                // 実行中の子の kill と回収（REAP_GRACE）と数刻みを待つ。
                wait_finished(&handle, REAP_GRACE + WAIT_SLICE * 20);
            }
            let worker_finished = handle.is_finished();
            if worker_finished {
                let _ = handle.join();
            }
            let drain = PublishDrain {
                queued,
                dropped: self.shared.pending.load(Ordering::SeqCst),
                deadline_hit,
                worker_finished,
                elapsed: started.elapsed(),
            };
            self.log.record_drain(&drain);
            Some(drain)
        }
    }

    /// `limit` までスレッドの終了を待つ。終わったか。
    fn wait_finished(handle: &JoinHandle<()>, limit: Duration) -> bool {
        let until = Instant::now() + limit;
        loop {
            if handle.is_finished() {
                return true;
            }
            let now = Instant::now();
            if now >= until {
                return false;
            }
            std::thread::sleep(WAIT_SLICE.min(until - now));
        }
    }

    impl ExecEventPublisher {
        fn enqueue(&self, event: TaskEvent, guard: Option<EventGuard>) {
            let topic = event.topic();
            // ログは状態ロックを手放してから出す（ロック下では非ブロッキングの try_send だけ）。
            let failure = {
                let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
                let mut spawn_failure = None;
                if matches!(*st, State::Idle) {
                    match self.spawn_worker() {
                        Ok(running) => *st = running,
                        Err(e) => {
                            spawn_failure = Some(
                                PublishFailure::new(PublishStage::WorkerSpawn, Some(topic))
                                    .with_errno(&e),
                            );
                        }
                    }
                }
                match (&*st, spawn_failure) {
                    (_, Some(f)) => Some(f),
                    (State::Running { tx, .. }, None) => {
                        self.shared.pending.fetch_add(1, Ordering::SeqCst);
                        match tx.try_send((event, guard)) {
                            Ok(()) => None,
                            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                                self.shared.pending.fetch_sub(1, Ordering::SeqCst);
                                Some(PublishFailure::new(PublishStage::Enqueue, Some(topic)))
                            }
                        }
                    }
                    // 排出の後は受けない（worker を起こし直さない）。
                    _ => Some(PublishFailure::new(PublishStage::Enqueue, Some(topic))),
                }
            };
            if let Some(f) = failure {
                self.log.record(&f);
            }
        }
    }

    /// 子 1 件の結果。`Aborted` は排出の期限切れで kill した（失敗ではなく捨てた件として数える）。
    enum RunOutcome {
        Done(Result<(), PublishFailure>),
        Aborted,
    }

    /// キューを直列に処理する。送り側が閉じられて空になるか、排出が中止を立てたら終わる。
    fn worker(
        rx: &Receiver<Queued>,
        target: &PublishTarget,
        config: PublishConfig,
        log: &dyn PublishLog,
        shared: &Shared,
    ) {
        while let Ok((event, guard)) = rx.recv() {
            if shared.abort.load(Ordering::SeqCst) {
                // 取り出した 1 件は捨てる（pending に残す）。残りは取り出さない。
                break;
            }
            // キューで待つ間に Delete された世代のイベントは送らない（CRI-5・#4155）。
            if guard.as_ref().is_some_and(|g| !g()) {
                shared.pending.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let started = Instant::now();
            match run_bounded(target, config, &event, shared) {
                RunOutcome::Aborted => break,
                RunOutcome::Done(result) => {
                    if let Err(failure) = &result {
                        log.record(failure);
                    }
                    log.record_outcome(event.topic(), result.is_ok(), started.elapsed());
                    shared.pending.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
    }

    /// 子を 1 件、期限つきで実行する。失敗は最初に起きた段 1 件だけ返す。排出の中止では kill して回収し `Aborted`。
    fn run_bounded(
        target: &PublishTarget,
        config: PublishConfig,
        event: &TaskEvent,
        shared: &Shared,
    ) -> RunOutcome {
        match run_bounded_inner(target, config, event, shared) {
            Ok(()) => RunOutcome::Done(Ok(())),
            Err(None) => RunOutcome::Aborted,
            Err(Some(f)) => RunOutcome::Done(Err(f)),
        }
    }

    /// `Err(None)` は中止。
    fn run_bounded_inner(
        target: &PublishTarget,
        config: PublishConfig,
        event: &TaskEvent,
        shared: &Shared,
    ) -> Result<(), Option<PublishFailure>> {
        let topic = event.topic();
        let fail = |stage| PublishFailure::new(stage, Some(topic));
        let payload = event.encode_any().map_err(Some)?;
        // stdin は AF_UNIX の stream socket。親側を非ブロッキングにして期限ループの中で書くため、
        // 子が読まなくても worker は期限で必ず戻る（pipe 容量に依存しない。#4223・REPAIR-5）。
        let (mut parent_end, child_end) =
            UnixStream::pair().map_err(|e| Some(fail(PublishStage::Spawn).with_errno(&e)))?;
        // Command は一時値のまま spawn し、親が持つ子側の端の複製を spawn 直後に閉じる（EOF・EPIPE の検出に必要）。
        let mut child = Command::new(target.binary())
            .args(target.args(topic))
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(child_end)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Some(fail(PublishStage::Spawn).with_errno(&e)))?;
        let deadline = Instant::now() + config.timeout();
        // 最初の失敗だけを覚え、回収は必ず続ける。
        let mut first: Option<PublishFailure> = None;
        let mut rest: &[u8] = &payload;
        // 書き込み側が開いている間 true。全部書けたら shutdown して EOF を送り、false にする。
        let mut writing = true;
        if let Err(e) = parent_end.set_nonblocking(true) {
            first = Some(fail(PublishStage::WriteStdin).with_errno(&e));
            writing = false;
        }
        loop {
            if writing {
                match write_some(&mut parent_end, &mut rest) {
                    Ok(true) => {
                        // 全部書けた。書き込み側を閉じて EOF を送る。
                        let _ = parent_end.shutdown(Shutdown::Write);
                        writing = false;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        first = Some(fail(PublishStage::WriteStdin).with_errno(&e));
                        writing = false;
                    }
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(f) = first {
                        return Err(Some(f));
                    }
                    if writing && !rest.is_empty() {
                        // 子が stdin を読み切る前に終わった。
                        return Err(Some(fail(PublishStage::WriteStdin)));
                    }
                    if status.success() {
                        return Ok(());
                    }
                    let mut f = fail(PublishStage::ExitStatus);
                    f.exit_code = status.code();
                    f.signal = status.signal();
                    return Err(Some(f));
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.try_wait();
                    return Err(Some(
                        first.unwrap_or_else(|| fail(PublishStage::Wait).with_errno(&e)),
                    ));
                }
            }
            if shared.abort.load(Ordering::SeqCst) {
                let _ = child.kill();
                let _ = reap(&mut child);
                return Err(None);
            }
            let now = Instant::now();
            if now >= deadline {
                let _ = child.kill();
                let reaped = reap(&mut child);
                let mut f = first.unwrap_or_else(|| fail(PublishStage::Deadline));
                if f.stage == PublishStage::Deadline {
                    f.reaped = Some(reaped);
                }
                return Err(Some(f));
            }
            std::thread::sleep(WAIT_SLICE.min(deadline - now));
        }
    }

    /// 非ブロッキングの stream へ未送信分を可能な限り書く。全部書けたら `Ok(true)`、
    /// 詰まった（`WouldBlock`）なら `Ok(false)`（次の周回で再試行）。`rest` は書いた分だけ進む。
    ///
    /// Linux の `UnixStream::write` は `MSG_NOSIGNAL` で送るため、相手が閉じていても SIGPIPE ではなく
    /// `EPIPE` が返る。macOS はランタイムが起動時に SIGPIPE を無視することに依拠する（#4223）。
    pub(super) fn write_some(stream: &mut UnixStream, rest: &mut &[u8]) -> std::io::Result<bool> {
        while !rest.is_empty() {
            match stream.write(rest) {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(n) => *rest = &rest[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
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
            Some(target) => {
                let publisher: Arc<dyn EventPublisher> =
                    Arc::new(ExecEventPublisher::new(target, config, log));
                // Shutdown の排出（#4222）のため、`run_serve` が持つ登録口へ載せる。
                ctx.publisher_drains().register(Arc::clone(&publisher));
                Some(publisher)
            }
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

    use super::{
        EventPublisher, PublishFailure, TaskCreate, TaskDelete, TaskEvent, TaskExecAdded,
        TaskExecStarted, TaskIo, TaskStart,
    };
    #[cfg(unix)]
    use super::{PublishDrain, PublishLog};
    use crate::shim_v2::task_api::Timestamp;

    /// 捕捉用の出力先。
    #[cfg(unix)]
    #[derive(Default)]
    pub(crate) struct CaptureLog(
        pub(crate) Mutex<Vec<PublishFailure>>,
        pub(crate) Mutex<Vec<PublishDrain>>,
    );

    #[cfg(unix)]
    impl PublishLog for CaptureLog {
        fn record(&self, failure: &PublishFailure) {
            self.0.lock().unwrap().push(failure.clone());
        }

        fn record_drain(&self, drain: &PublishDrain) {
            self.1.lock().unwrap().push(*drain);
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
                id: String::new(),
            }),
        ]
    }

    /// exec の 2 種の見本（#4281）。
    pub(crate) fn exec_events() -> [TaskEvent; 2] {
        [
            TaskEvent::ExecAdded(TaskExecAdded {
                container_id: "c1".into(),
                exec_id: "e1".into(),
            }),
            TaskEvent::ExecStarted(TaskExecStarted {
                container_id: "c1".into(),
                exec_id: "e1".into(),
                pid: 4242,
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

    /// REPAIR-2・#4222: 排出の期限の境界（ゼロと 60 秒超は拒否、60 秒ちょうどは受理）。既定は 3 秒。
    #[test]
    fn repair2_4222_drain_timeout_bounds() {
        let base = PublishConfig::default();
        assert_eq!(base.drain_timeout(), Duration::from_secs(3));
        assert!(base.with_drain_timeout(Duration::ZERO).is_err());
        assert!(base.with_drain_timeout(Duration::from_secs(61)).is_err());
        assert_eq!(
            base.with_drain_timeout(Duration::from_secs(60))
                .unwrap()
                .drain_timeout(),
            Duration::from_secs(60)
        );
    }

    /// REPAIR-4・#4222: 排出のログ行は固定語彙だけを持つ。
    #[test]
    fn repair4_4222_drain_json_line_is_fixed_vocabulary() {
        let d = PublishDrain {
            queued: 2,
            dropped: 1,
            deadline_hit: true,
            worker_finished: true,
            elapsed: Duration::from_millis(1234),
        };
        assert_eq!(
            d.to_json_line(),
            r#"{"dropped":1,"elapsed_ms":1234,"event":"task_event_publish_drain","outcome":"deadline","queued":2,"worker_finished":true}"#
        );
        let ok = PublishDrain {
            deadline_hit: false,
            dropped: 0,
            ..d
        };
        assert!(ok.to_json_line().contains(r#""outcome":"complete""#));
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

    fn max_task_create() -> TaskEvent {
        TaskEvent::Create(TaskCreate {
            container_id: "c".repeat(255),
            bundle: format!(
                "/{}",
                "b".repeat(crate::shim_v2::task_service::BUNDLE_MAX_LEN - 1)
            ),
            io: Some(TaskIo::default()),
            pid: u32::MAX,
            ..Default::default()
        })
    }

    /// REPAIR-2・REPAIR-12・#4223: 検証済み入力の最大の TaskCreate は新上限に収まり、旧上限 4096 を超える（導出の機械照合）。
    #[test]
    fn repair2_4223_max_valid_task_create_fits_limit() {
        let n = max_task_create().encode_any().unwrap().len();
        assert!(n > 4096 && n <= MAX_EVENT_LEN, "{n}");
    }

    /// REPAIR-2・#4223: 符号化後ちょうど上限は成功し、1 バイト超えると `encode`（topic つき）で失敗する。
    #[test]
    fn repair2_4223_limit_boundary() {
        let enc = |len: usize| {
            TaskEvent::Create(TaskCreate {
                container_id: "c1".into(),
                bundle: "b".repeat(len),
                ..Default::default()
            })
            .encode_any()
        };
        // 長さ接頭辞の varint 幅が段階的に変わるため、受理される最大の長さを探して境界を照合する。
        let len = (0..=MAX_EVENT_LEN)
            .take_while(|l| enc(*l).is_ok())
            .last()
            .unwrap();
        assert_eq!(enc(len).unwrap().len(), MAX_EVENT_LEN);
        let err = enc(len + 1).unwrap_err();
        assert_eq!(err.stage, PublishStage::Encode);
        assert_eq!(err.topic, Some("/tasks/create"));
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

    /// CRI-5・#4281: exec の 2 種の topic・type URL・wire 形式を具体値で照合する。
    #[test]
    fn cri5_4281_task_exec_added_started_encode_as_any() {
        let [added, started] = exec_events();
        assert_eq!(added.topic(), "/tasks/exec-added");
        assert_eq!(started.topic(), "/tasks/exec-started");
        let a = Any::decode(&added.encode_any().unwrap()[..]).unwrap();
        assert_eq!(a.type_url, "containerd.events.TaskExecAdded");
        assert_eq!(a.value, [0x0a, 2, b'c', b'1', 0x12, 2, b'e', b'1']);
        let s = Any::decode(&started.encode_any().unwrap()[..]).unwrap();
        assert_eq!(s.type_url, "containerd.events.TaskExecStarted");
        assert_eq!(
            s.value,
            [0x0a, 2, b'c', b'1', 0x12, 2, b'e', b'1', 0x18, 0x92, 0x21]
        );
        assert_eq!(
            TaskExecStarted::decode(&s.value[..]).unwrap(),
            TaskExecStarted {
                container_id: "c1".into(),
                exec_id: "e1".into(),
                pid: 4242
            }
        );
    }

    /// REPAIR-2・REPAIR-12・#4281: 最大長の ID・pid でも exec の 2 種は上限に収まる。
    #[test]
    fn repair2_4281_max_exec_events_fit_limit() {
        let id = "a".repeat(255);
        for ev in [
            TaskEvent::ExecAdded(TaskExecAdded {
                container_id: id.clone(),
                exec_id: id.clone(),
            }),
            TaskEvent::ExecStarted(TaskExecStarted {
                container_id: id.clone(),
                exec_id: id.clone(),
                pid: u32::MAX,
            }),
        ] {
            let bytes = ev.encode_any().unwrap();
            assert!(bytes.len() <= MAX_EVENT_LEN, "{}", bytes.len());
        }
    }

    /// CRI-5・#4156: 3 種それぞれで、偽の publish バイナリが argv の topic と stdin の `Any` を具体値で受け取る。
    #[test]
    fn cri5_4156_publish_passes_argv_and_stdin_for_each_topic() {
        for (i, ev) in three_events().into_iter().chain(exec_events()).enumerate() {
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
        for (i, ev) in three_events().into_iter().chain(exec_events()).enumerate() {
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
            for secret in [ADDR, "default", "c1", "e1", "/run/b", "secret-addr-4155"] {
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

    /// REPAIR-5・#4222: 一度も publish していなければ排出は `None`（ログも出ない）。
    #[test]
    fn repair5_4222_drain_without_worker_is_none() {
        let dir = test_root::test_root("pub", "drain-none");
        let bin = make_script(&dir, "fake", &failing_body());
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        assert!(p.drain().is_none());
        assert!(log.1.lock().unwrap().is_empty());
        assert!(log.0.lock().unwrap().is_empty());
    }

    /// REPAIR-5・#4222: 排出の後の投入は `enqueue` がちょうど 1 件で、子は起動しない。2 回目の排出は `None`。
    #[test]
    fn repair5_4222_publish_after_drain_records_enqueue() {
        let dir = test_root::test_root("pub", "drain-after");
        let bin = make_script(&dir, "fake", &recorder_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        p.publish(sample());
        let d = p.drain().expect("worker was started");
        assert!(!d.deadline_hit && d.worker_finished, "{d:?}");
        assert_eq!(d.dropped, 0);
        assert!(dir.join("stdin").exists(), "queued event must be sent");
        std::fs::remove_file(dir.join("stdin")).unwrap();
        p.publish(sample());
        std::thread::sleep(Duration::from_millis(300));
        assert!(!dir.join("stdin").exists());
        let got = log.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stage, PublishStage::Enqueue);
        assert!(p.drain().is_none());
        assert_eq!(log.1.lock().unwrap().len(), 1);
    }

    /// CRI-5・#4222: `PublisherDrains` は `exec_publisher_for_with` が作った publisher を排出する。
    #[test]
    fn cri5_4222_registered_publisher_is_drained_via_context() {
        let dir = test_root::test_root("pub", "drain-ctx");
        let bin = make_script(&dir, "fake", &recorder_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let ctx = ServeContext::new(ShutdownSignal::new(), None)
            .with_origin(
                Some(ShimIdentifier::parse("default").unwrap()),
                Some(ADDR.into()),
            )
            .with_publish_binary(Some(PublishBinary::verify(&bin).unwrap()));
        let p = exec_publisher_for_with(&ctx, PublishConfig::default(), log.clone()).unwrap();
        p.publish(sample());
        let drains = ctx.publisher_drains().drain_all();
        assert_eq!(drains.len(), 1);
        assert_eq!(drains[0].dropped, 0);
        assert!(dir.join("stdin").exists());
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

    fn long_task_create(bundle_len: usize) -> TaskEvent {
        TaskEvent::Create(TaskCreate {
            container_id: "c1".into(),
            bundle: format!("/{}", "b".repeat(bundle_len - 1)),
            io: Some(TaskIo::default()),
            pid: 4242,
            ..Default::default()
        })
    }

    /// CRI-5・#4223: 4096 バイト近い bundle の TaskCreate（旧上限超過）が偽バイナリの stdin へ欠けずに届く。
    #[test]
    fn cri5_4223_large_task_create_reaches_fake_binary() {
        let dir = test_root::test_root("pub", "t4223-large");
        let bin = make_script(&dir, "fake", &recorder_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        let ev = long_task_create(4096);
        assert!(ev.encode_any().unwrap().len() > 4096);
        p.publish(ev.clone());
        assert!(wait_until(Duration::from_secs(10), || dir
            .join("stdin")
            .exists()));
        assert_eq!(
            std::fs::read(dir.join("stdin")).unwrap(),
            ev.encode_any().unwrap()
        );
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        assert_eq!(argv.lines().last(), Some("/tasks/create"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(log.0.lock().unwrap().is_empty());
    }

    /// REPAIR-5・#4223: stdin を読まない子に最大サイズの TaskCreate を送っても期限で戻り、子は kill・回収される。
    #[test]
    fn repair5_4223_non_reading_child_with_large_payload_is_reaped() {
        let dir = test_root::test_root("pub", "t4223-sleep");
        let bin = make_script(&dir, "fake", &sleeping_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let timeout = Duration::from_millis(500);
        let p = publisher(&bin, timeout, log.clone());
        let started = std::time::Instant::now();
        p.publish(long_task_create(4096));
        assert!(wait_until(Duration::from_secs(10), || !log
            .0
            .lock()
            .unwrap()
            .is_empty()));
        assert!(started.elapsed() < timeout + Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(100));
        let got = log.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stage, PublishStage::Deadline);
        assert_eq!(got[0].reaped, Some(true));
    }

    /// REPAIR-5・#4223: 相手が読まない stream への書き込みは `WouldBlock` で戻り（未送信が残る）、閉じた相手へは `EPIPE` で失敗する。
    #[test]
    fn repair5_4223_write_helper_never_blocks() {
        use std::os::unix::net::UnixStream;
        let (mut a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let big = vec![7u8; 4 * 1024 * 1024];
        let mut rest: &[u8] = &big;
        let started = std::time::Instant::now();
        assert!(!unix::write_some(&mut a, &mut rest).unwrap());
        assert!(!rest.is_empty() && rest.len() < big.len());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(b);
        let err = unix::write_some(&mut a, &mut rest).unwrap_err();
        assert!(
            matches!(err.raw_os_error(), Some(e) if e == 32 /* EPIPE */)
                || err.kind() == std::io::ErrorKind::BrokenPipe,
            "{err:?}"
        );
    }

    /// REPAIR-5・#4223: 上限超過のイベントは子を起動せず、`encode` の失敗がちょうど 1 件。
    #[test]
    fn repair5_4223_oversized_event_is_not_spawned() {
        let dir = test_root::test_root("pub", "t4223-over");
        let bin = make_script(&dir, "fake", &recorder_body(&dir));
        let log = Arc::new(CaptureLog::default());
        let p = publisher(&bin, Duration::from_secs(5), log.clone());
        p.publish(TaskEvent::Create(TaskCreate {
            container_id: "c1".into(),
            bundle: "b".repeat(MAX_EVENT_LEN),
            ..Default::default()
        }));
        assert!(wait_until(Duration::from_secs(10), || !log
            .0
            .lock()
            .unwrap()
            .is_empty()));
        std::thread::sleep(Duration::from_millis(200));
        let got = log.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stage, PublishStage::Encode);
        assert!(!dir.join("argv").exists() && !dir.join("stdin").exists());
    }
}
