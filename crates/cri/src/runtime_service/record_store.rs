//! sandbox・コンテナの記録（`record` サブモジュールの符号化済みバイト列）を状態ルート配下に 1 件 1 ファイルで
//! 置く記録ストア（CRI-1・OCI-7・REPAIR-5・SEC-1。#2932。設計は `docs/design/cri-record-readoption.md`）。
//!
//! 役割: plugin-cri の再起動をまたいで CRI 層の項目を残すための「バイト列の置き場」。中身（記録の解釈）は
//! 持たず、`record` の厳密な復号に委ねる。ストアは untrusted なバイト列として扱う。
//!
//! 呼び出し元: R4（#2933。sandbox の書く・消す時点。`CriRuntimeService::with_record_store` で注入。実装済み）。
//! 呼び出し元: R5（#2934。コンテナの書く・消す時点。実装済み）・R6 / R7（予定）
//! （#2935・#2936。起動時の列挙と再採用）・R9（#2938。plugin-cri の本番配線）。本単位ではトレイトと
//! ファイル実装（`FileRecordStore`。unix のみ）までを置く。
//!
//! 置き場: `<状態ルート>/.cri/records/{sandboxes,containers}/<id>.rec`。ファイル名は検証済みの
//! [`RecordId`]（64 文字の小文字 16 進）だけから作り、記録の中のパスは信頼しない。
//!
//! 契約:
//! - **置き場の検査**: 既存の置き場が symlink・ディレクトリでない・状態ルートと別の所有者・group / other の
//!   権限あり、のどれかなら消さずに拒否する（fail-closed）
//! - **原子性**: 書き込みは `O_EXCL` の一時ファイル → fsync → rename → ディレクトリの fsync。途中で落ちても
//!   旧版か新版のどちらかが残る
//! - **排他**: 置き場直下の `.lock`（決して unlink しない）を期限つきで取る。書き手は R3 のインスタンス排他と
//!   registry の `in_flight` で 1 つに保証されるため、比較交換（CAS）は持たない
//! - **上限**: 件数・1 件の長さ・保持量（列挙で読み込む総バイト量）・走査するエントリ数に上限を置く
//! - **期限（REPAIR-5）**: 列挙は専用スレッドで行い、1 件ごとと全体の期限を持つ。止まった読み取りは
//!   継続せず列挙全体を `Timeout` にする（起動を fail-closed にする。containerd が 1 件を Unknown として続行する
//!   のとの差。止まったスレッドを抱えたまま次を読めないため）
//! - **計測（REPAIR-4）**: `put` / `remove` / `list` の全終了経路で、操作名・種別・結果区分・所要時間だけを
//!   [`RecordStoreOpRecorder`] へ渡す（既定は [`NoopRecordStoreOpRecorder`]。バイト列・ID・パスは渡さない）
//! - **壊れた記録**: ファイルは消さず、列挙結果に失敗として返す（手動回収は R10）
//!
//! 残余: 通常ファイルの確認と open の間に FIFO へ差し替えられると open がブロックし得る。置き場は 0700 で
//! 同じ UID に限られ、全体の期限で起動を失敗させて抑える。非 unix にはファイル実装を置かない
//! （plugin-cri の本番自体が非 unix では `Unimplemented`）。

use std::fmt;
use std::time::Duration;

use super::container::{MAX_CONTAINERS, MAX_RETAINED_CONTAINER_CONFIG_BYTES};
use super::record::{
    CONTAINER_HEADER_BUDGET, MAX_CONTAINER_RECORD_BYTES, MAX_SANDBOX_RECORD_BYTES,
    SANDBOX_HEADER_BUDGET, is_record_id,
};
use super::{MAX_RETAINED_CONFIG_BYTES, MAX_SANDBOXES};
use crate::error::CriError;

#[cfg(unix)]
mod file;
#[cfg(unix)]
pub use file::FileRecordStore;

/// 記録 1 件の読み取りの既定の期限: 10 秒（containerd の `loadContainerTimeout` と同じ）。
pub const DEFAULT_RECORD_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 列挙全体の既定の期限: 60 秒。
pub const DEFAULT_LIST_TIMEOUT: Duration = Duration::from_secs(60);

/// sandbox 記録の列挙で読み込む総バイト量の既定の上限。
///
/// 算式: `MAX_RETAINED_CONFIG_BYTES + MAX_SANDBOXES × SANDBOX_HEADER_BUDGET`（約 64.9 MiB）。
/// 根拠: registry が受け入れる config の保持量の見積もりは「符号化長 + 要素数 × 256 + 4096」で符号化長以上
/// になり、合計は `MAX_RETAINED_CONFIG_BYTES` 以下に保たれる。記録 1 件はヘッダ予算 + config の符号化長なので、
/// registry が受け入れられる記録の集合は必ずこの上限に収まる。件数 × 1 件の上限（約 530 MiB）をそのまま
/// 読み込ませないための DoS 対策。
pub const MAX_SANDBOX_LISTING_BYTES: usize =
    MAX_RETAINED_CONFIG_BYTES + MAX_SANDBOXES * SANDBOX_HEADER_BUDGET;
/// コンテナ記録の列挙で読み込む総バイト量の既定の上限。算式は [`MAX_SANDBOX_LISTING_BYTES`] と同じ
/// （`MAX_RETAINED_CONTAINER_CONFIG_BYTES + MAX_CONTAINERS × CONTAINER_HEADER_BUDGET`）。
pub const MAX_CONTAINER_LISTING_BYTES: usize =
    MAX_RETAINED_CONTAINER_CONFIG_BYTES + MAX_CONTAINERS * CONTAINER_HEADER_BUDGET;

/// 記録の種別。置き場のサブディレクトリと各種上限を決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordKind {
    /// pod sandbox の記録。
    Sandbox,
    /// コンテナの記録。
    Container,
}

impl RecordKind {
    /// 置き場のサブディレクトリ名。
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Sandbox => "sandboxes",
            Self::Container => "containers",
        }
    }

    /// 記録 1 件の長さの上限（`record` の `MAX_*_RECORD_BYTES`）。
    pub fn max_record_bytes(self) -> usize {
        match self {
            Self::Sandbox => MAX_SANDBOX_RECORD_BYTES,
            Self::Container => MAX_CONTAINER_RECORD_BYTES,
        }
    }

    /// 件数の上限（registry の `MAX_SANDBOXES` / `MAX_CONTAINERS`）。
    pub fn max_records(self) -> usize {
        match self {
            Self::Sandbox => MAX_SANDBOXES,
            Self::Container => MAX_CONTAINERS,
        }
    }

    fn max_listing_bytes(self) -> usize {
        match self {
            Self::Sandbox => MAX_SANDBOX_LISTING_BYTES,
            Self::Container => MAX_CONTAINER_LISTING_BYTES,
        }
    }
}

/// 記録ストアの操作の種類（固定の語彙。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordStoreOp {
    /// [`RecordStore::put`]。
    Put,
    /// [`RecordStore::remove`]。
    Remove,
    /// [`RecordStore::list`]。
    List,
}

impl RecordStoreOp {
    /// 操作名の固定文字列（`[a-z_]`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Remove => "remove",
            Self::List => "list",
        }
    }
}

/// 記録ストアの操作の結果区分（固定の語彙。REPAIR-4）。パス・ID・errno・バイト列は持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordStoreOutcome {
    /// 成功。
    Ok,
    /// 1 件の長さの上限超過で拒否した（`put`）。
    TooLong,
    /// 件数または走査数の上限超過（`list`）。
    TooManyRecords,
    /// 保持量（総バイト量）の上限超過（`list`）。
    TooMuchData,
    /// 通常ファイルでない対象を拒否した（記録・`.lock`）。
    NotRegularFile,
    /// `.lock` の取得が期限切れになった。
    LockTimeout,
    /// `.lock` を開く・ロックする操作が失敗した（期限切れ以外）。
    LockError,
    /// 列挙の期限（1 件ごとまたは全体）が切れた。
    ListTimeout,
    /// 読み書き・同期・列挙の I/O が失敗した。
    Io,
    /// 上記以外の内部エラー（スレッド起動失敗・worker の異常終了）。
    Internal,
}

impl RecordStoreOutcome {
    /// 結果区分の固定文字列（`[a-z_]`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::TooLong => "too_long",
            Self::TooManyRecords => "too_many_records",
            Self::TooMuchData => "too_much_data",
            Self::NotRegularFile => "not_regular_file",
            Self::LockTimeout => "lock_timeout",
            Self::LockError => "lock_error",
            Self::ListTimeout => "list_timeout",
            Self::Io => "io_error",
            Self::Internal => "internal",
        }
    }
}

/// 記録ストアの 1 回の操作の計測結果（固定サイズの値型）。バイト列・ID・パスは持たない（REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordStoreOpSample {
    /// 操作の種類。
    pub op: RecordStoreOp,
    /// 対象の種別。
    pub kind: RecordKind,
    /// 結果区分。
    pub outcome: RecordStoreOutcome,
    /// 操作に要した時間（ロック待ち・期限切れまでの待ちを含む）。
    pub latency: Duration,
}

/// 記録ストアの計測結果の記録先（REPAIR-4）。
///
/// 契約: 呼び出し側の操作の経路から同期的に呼ばれるため、有界時間で戻り、panic しないこと
/// （相手応答待ち・無期限のロック待ちをしない。REPAIR-5）。ストアの内部ロックを解放してから呼ばれる。
/// 戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えないため。
/// 本番の配線（plugin-cri の `OpRecorder` への橋渡し）は R9（#2938）で行う。
pub trait RecordStoreOpRecorder: Send + Sync {
    /// 1 件の計測結果を記録する。
    fn record_store_op(&self, sample: &RecordStoreOpSample);
}

/// 計測しない場合の既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopRecordStoreOpRecorder;

impl RecordStoreOpRecorder for NoopRecordStoreOpRecorder {
    fn record_store_op(&self, _sample: &RecordStoreOpSample) {}
}

/// 失敗の内部表現: 呼び出し側へ返すエラーと、記録用の結果区分を一緒に運ぶ。
#[cfg(unix)]
pub(crate) struct Failed {
    pub(crate) err: CriError,
    pub(crate) outcome: RecordStoreOutcome,
}

#[cfg(unix)]
impl Failed {
    pub(crate) fn new(outcome: RecordStoreOutcome, err: CriError) -> Self {
        Self { err, outcome }
    }
}

/// 検証済みの記録 ID（64 文字の小文字 16 進。`generate_id` の出力と同じ形）。壊れた値を表現できない
/// （REPAIR-2）。ファイル名はこの値だけから作る。
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordId(String);

impl RecordId {
    /// 形を検証して作る。不正なら `INVALID_ARGUMENT`（入力値は文言に載せない）。
    pub fn new(s: &str) -> Result<Self, CriError> {
        if is_record_id(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(CriError::invalid_argument("invalid record id"))
        }
    }

    /// ID の文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecordId").field(&self.0).finish()
    }
}

/// 列挙で 1 件の読み取りに失敗した理由。どの失敗でもファイルは消さない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordReadFailure {
    /// 通常ファイルでない（ディレクトリ・symlink・FIFO 等）。
    NotRegularFile,
    /// 長さの上限を超えた。
    TooLong,
    /// 権限・I/O エラー、または open の前後で別物に差し替わった。
    Unreadable,
}

/// 列挙された 1 件。`outcome` の `Ok` は untrusted なバイト列（復号は `record` の責務）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedRecord {
    /// ファイル名由来の ID（`record` の復号の `expect_id` に渡す）。
    pub id: RecordId,
    /// 読み取り結果。
    pub outcome: Result<Vec<u8>, RecordReadFailure>,
}

/// 列挙の結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordListing {
    /// ID の昇順。
    pub records: Vec<ListedRecord>,
    /// `.rec` で終わるが、名前が ID として不正なファイルの件数。そのファイルには触れない。
    pub unrecognized: usize,
}

/// 列挙の期限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListBudget {
    /// 1 件ごとの期限（次の結果が届くまでの待ち）。
    pub per_record: Duration,
    /// 列挙全体の期限。
    pub total: Duration,
}

impl Default for ListBudget {
    fn default() -> Self {
        Self {
            per_record: DEFAULT_RECORD_READ_TIMEOUT,
            total: DEFAULT_LIST_TIMEOUT,
        }
    }
}

/// 列挙の件数・保持量の上限。既定値より大きくはできない（絞るだけ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListLimits {
    max_records: usize,
    max_total_bytes: usize,
}

impl ListLimits {
    /// 種別ごとの既定の上限。
    pub fn for_kind(kind: RecordKind) -> Self {
        Self {
            max_records: kind.max_records(),
            max_total_bytes: kind.max_listing_bytes(),
        }
        .clamp_to(kind)
    }

    fn clamp_to(mut self, kind: RecordKind) -> Self {
        self.max_records = self.max_records.min(kind.max_records());
        self.max_total_bytes = self.max_total_bytes.min(kind.max_listing_bytes());
        self
    }

    /// 件数の上限を絞る（既定値を超える値は既定値になる）。
    pub fn with_max_records(mut self, kind: RecordKind, n: usize) -> Self {
        self.max_records = n.min(kind.max_records());
        self
    }

    /// 総バイト量の上限を絞る（既定値を超える値は既定値になる）。
    pub fn with_max_total_bytes(mut self, kind: RecordKind, n: usize) -> Self {
        self.max_total_bytes = n.min(kind.max_listing_bytes());
        self
    }

    /// 件数の上限。
    pub fn max_records(&self) -> usize {
        self.max_records
    }

    /// 総バイト量の上限。
    pub fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }
}

/// 記録ストア。書き手は 1 つ（R3 のインスタンス排他と registry の `in_flight`）と保証されるため、
/// 比較交換は持たない。エラー文言は固定の英語で、ID・パス・errno を含めない（REPAIR-4）。
pub trait RecordStore: Send + Sync + fmt::Debug {
    /// 記録を置く（同名があれば置き換える）。長さが `kind.max_record_bytes()` を超えたら何も書かずに
    /// `INTERNAL`。
    fn put(&self, kind: RecordKind, id: &RecordId, bytes: &[u8]) -> Result<(), CriError>;

    /// 記録を消す。無ければ成功（冪等）。通常ファイルでないものは消さずに `INTERNAL`。
    fn remove(&self, kind: RecordKind, id: &RecordId) -> Result<(), CriError>;

    /// 記録を ID の昇順に列挙する。壊れた記録はファイルを消さず `outcome` の失敗として返す。上限・期限を
    /// 超えたら全体を失敗にする（件数・保持量は `FAILED_PRECONDITION`、期限は `DEADLINE_EXCEEDED`）。
    fn list(
        &self,
        kind: RecordKind,
        budget: ListBudget,
        limits: ListLimits,
    ) -> Result<RecordListing, CriError>;
}

#[cfg(unix)]
mod driver {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
    use std::time::Instant;

    /// worker から呼び出し側への通知。
    enum Msg {
        Record(ListedRecord),
        Done(Result<usize, Failed>),
    }

    /// 列挙の worker が結果を流す口。
    pub(crate) struct ListSink {
        tx: Sender<Msg>,
        cancel: Arc<AtomicBool>,
    }

    impl ListSink {
        /// 期限切れ等で呼び出し側が諦めたか。worker はエントリの間で見て抜ける。
        pub(crate) fn is_cancelled(&self) -> bool {
            self.cancel.load(Ordering::Acquire)
        }

        /// 1 件を渡す。諦められていたら `false`。
        pub(crate) fn record(&self, r: ListedRecord) -> bool {
            !self.is_cancelled() && self.tx.send(Msg::Record(r)).is_ok()
        }

        /// 終了を知らせる（`Ok` は `unrecognized` の件数）。
        pub(crate) fn finish(self, result: Result<usize, Failed>) {
            let _ = self.tx.send(Msg::Done(result));
        }
    }

    fn list_timeout() -> Failed {
        Failed::new(
            RecordStoreOutcome::ListTimeout,
            CriError::timeout("timed out listing cri records"),
        )
    }

    /// 専用スレッドで `work` を走らせ、1 件ごとと全体の期限つきで結果を集める（REPAIR-5）。
    ///
    /// 期限切れのときは中止フラグを立てて worker を切り離し、`Timeout` を返す。worker は 1 本だけで再生成しない。
    pub(crate) fn run_listing<F>(budget: ListBudget, work: F) -> Result<RecordListing, Failed>
    where
        F: FnOnce(ListSink) + Send + 'static,
    {
        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let sink = ListSink {
            tx,
            cancel: Arc::clone(&cancel),
        };
        std::thread::Builder::new()
            .name("cri-record-list".into())
            .spawn(move || work(sink))
            .map_err(|_| {
                Failed::new(
                    RecordStoreOutcome::Internal,
                    CriError::internal("failed to start the cri record listing"),
                )
            })?;

        let deadline = Instant::now().checked_add(budget.total);
        let mut records = Vec::new();
        // 全体期限は受信結果と独立に判定する（呼び出し側が止まっている間に worker が完了し結果が
        // チャネルに溜まっていても、期限超過なら成功にしない。REPAIR-5）。
        let expired = || deadline.is_some_and(|d| Instant::now() >= d);
        loop {
            if expired() {
                cancel.store(true, Ordering::Release);
                return Err(list_timeout());
            }
            let wait = match deadline {
                Some(d) => budget
                    .per_record
                    .min(d.saturating_duration_since(Instant::now())),
                None => budget.per_record,
            };
            match rx.recv_timeout(wait) {
                Ok(Msg::Record(r)) => records.push(r),
                Ok(Msg::Done(Ok(unrecognized))) => {
                    if expired() {
                        cancel.store(true, Ordering::Release);
                        return Err(list_timeout());
                    }
                    return Ok(RecordListing {
                        records,
                        unrecognized,
                    });
                }
                Ok(Msg::Done(Err(e))) => return Err(e),
                Err(RecvTimeoutError::Timeout) => {
                    cancel.store(true, Ordering::Release);
                    return Err(list_timeout());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Failed::new(
                        RecordStoreOutcome::Internal,
                        CriError::internal("cri record listing ended unexpectedly"),
                    ));
                }
            }
        }
    }
}
#[cfg(unix)]
use driver::{ListSink, run_listing};
