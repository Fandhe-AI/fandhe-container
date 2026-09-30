//! read / write 操作の計装連携点（REPAIR-4・TASK-84.5）。
//!
//! core の `OpRecorder`（成功・失敗件数とレイテンシ分布の集計。TASK-84.2）へ、io の
//! read / write 経路が計測結果を渡すための境界。依存方向は `core → io` のため、io は
//! core の型を参照できない。そこで本モジュールが io 内の型だけで完結するトレイトを定義し、
//! core 側の記録器への接続は「core と io の両方に依存する上位 crate（supervisor 等）」に置く
//! newtype アダプタが担う。アダプタは `sample.kind().as_str()` を core の `OpName::new` へ
//! 渡し、`sample.outcome()` / `sample.latency()` を `OpRecorder::record` へ写す。
//!
//! 既存の [`crate::observe::ServerObserver`] / [`crate::observe::SendObserver`] は
//! イベントログ用で、`&mut self`・接続単位・単一スレッド前提である。本トレイトは集計用で、
//! 複数スレッド・複数接続から `Arc` 共有で呼ばれるため `&self` + `Send + Sync` とし、別トレイトにしている。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - io 側の実計装（`writeback` の `BatchSink::write_batch` 経路等からの呼び出し）: TASK-84.7
//! - core の `OpRecorder` との接続アダプタ: core → io（またはアダプタ配置 crate）の
//!   workspace 内依存辺の承認後
//! - [`IoOpKind::Read`] の呼び出し元: 現状の io にはファイル読み出し経路がなく、未使用
//!
//! # 機微情報
//!
//! [`IoOpSample`] は種別・結果・レイテンシのみを持ち、パス・ペイロード・エラー文言・
//! 資格情報は持たせない（`.claude/rules/security.md`）。

use std::time::{Duration, Instant};

/// 計装対象の io 操作の種別（REPAIR-4）。
///
/// [`IoOpKind::as_str`] は core の `OpName` 規則（`[A-Za-z0-9._-]`・64 バイト以下）に
/// 収まる固定文字列を返す契約を持つ。io は core の定数を import できないため規則を重複して
/// 持ち、テストで固定する。閉じた enum なので自由入力の文字列がログのキーに入る経路はない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoOpKind {
    /// ファイル読み出し（TASK-84 の対象だが、現状 io に呼び出し元はない。REPAIR-3）。
    Read,
    /// 書き込み（想定計装先は `writeback` の `BatchSink::write_batch` 経路。TASK-84.7）。
    Write,
}

impl IoOpKind {
    /// core の `OpName` へ渡す安定した操作名（`"read"` / `"write"`）。
    pub fn as_str(self) -> &'static str {
        match self {
            IoOpKind::Read => "read",
            IoOpKind::Write => "write",
        }
    }
}

/// 操作の結果区分（真偽値ではなく将来拡張できる型。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoOpOutcome {
    /// 成功。
    Success,
    /// 失敗（エラー・早期 return・panic を含む）。
    Failure,
}

impl IoOpOutcome {
    /// `Result` から結果区分を導く（中身は参照しない）。
    pub fn from_result<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => IoOpOutcome::Success,
            Err(_) => IoOpOutcome::Failure,
        }
    }
}

/// 1 回の操作の計測結果（固定サイズの値型。ヒープ確保なし）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoOpSample {
    kind: IoOpKind,
    outcome: IoOpOutcome,
    latency: Duration,
}

impl IoOpSample {
    /// サンプルを作る。
    pub fn new(kind: IoOpKind, outcome: IoOpOutcome, latency: Duration) -> Self {
        Self {
            kind,
            outcome,
            latency,
        }
    }

    /// 操作の種別。
    pub fn kind(&self) -> IoOpKind {
        self.kind
    }

    /// 操作の結果区分。
    pub fn outcome(&self) -> IoOpOutcome {
        self.outcome
    }

    /// 操作に要した時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// io の計測結果を受け取る記録先（REPAIR-4・TASK-84.5）。
///
/// 契約: データパスから呼ばれるため、有界時間で戻ること（I/O・相手応答待ち・無期限の
/// ロック待ちをしない。O(1) の短い有界ロックは許容。REPAIR-5）。panic しないこと。
/// 戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えないため。
/// `dyn IoOpRecorder` として `Arc` 共有できる。
pub trait IoOpRecorder: Send + Sync {
    /// 1 件の計測結果を記録する。
    fn record_io_op(&self, sample: &IoOpSample);
}

/// 計測しない場合に明示的に渡す既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopIoOpRecorder;

impl IoOpRecorder for NoopIoOpRecorder {
    fn record_io_op(&self, _sample: &IoOpSample) {}
}

/// 計測中の操作を表すガード。
///
/// [`success`](Self::success) / [`failure`](Self::failure) / [`finish_with`](Self::finish_with)
/// で結果を確定する。未確定のまま Drop された場合（早期 return・`?`・panic の巻き戻し）は
/// `Failure` として記録する（fail-closed。core の `OpGuard` と同じ考え方）。
#[must_use = "drop without finishing records a failure"]
pub struct IoOpTimer<'a> {
    recorder: &'a dyn IoOpRecorder,
    kind: IoOpKind,
    started: Instant,
    done: bool,
}

impl<'a> IoOpTimer<'a> {
    /// 計測を開始する。
    pub fn start(recorder: &'a dyn IoOpRecorder, kind: IoOpKind) -> Self {
        Self {
            recorder,
            kind,
            started: Instant::now(),
            done: false,
        }
    }

    fn emit(&mut self, outcome: IoOpOutcome) {
        if self.done {
            return;
        }
        self.done = true;
        let sample = IoOpSample::new(self.kind, outcome, self.started.elapsed());
        self.recorder.record_io_op(&sample);
    }

    /// 成功として確定する。
    pub fn success(mut self) {
        self.emit(IoOpOutcome::Success);
    }

    /// 失敗として確定する。
    pub fn failure(mut self) {
        self.emit(IoOpOutcome::Failure);
    }

    /// `Result` に応じて確定する。
    pub fn finish_with<T, E>(mut self, result: &Result<T, E>) {
        self.emit(IoOpOutcome::from_result(result));
    }
}

impl Drop for IoOpTimer<'_> {
    fn drop(&mut self) {
        self.emit(IoOpOutcome::Failure);
    }
}

/// クロージャを計測して結果をそのまま返すヘルパー（panic 時もガードが Failure を記録する）。
pub fn record_io_op<T, E>(
    recorder: &dyn IoOpRecorder,
    kind: IoOpKind,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let timer = IoOpTimer::start(recorder, kind);
    let result = f();
    timer.finish_with(&result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Entry = (IoOpKind, IoOpOutcome, Duration);

    #[derive(Default)]
    struct Collect(Mutex<Vec<Entry>>);

    impl IoOpRecorder for Collect {
        fn record_io_op(&self, s: &IoOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push((s.kind(), s.outcome(), s.latency()));
            }
        }
    }

    impl Collect {
        fn items(&self) -> Vec<Entry> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }
    }

    #[test]
    fn repair4_io_op_kind_as_str_is_stable() {
        assert_eq!(IoOpKind::Read.as_str(), "read");
        assert_eq!(IoOpKind::Write.as_str(), "write");
    }

    #[test]
    fn repair4_io_op_kind_names_fit_core_op_name_contract() {
        // core の OpName::new と同じ規則。io は core に依存できないため重複して固定する。
        for kind in [IoOpKind::Read, IoOpKind::Write] {
            let s = kind.as_str();
            assert!(!s.is_empty() && s.len() <= 64);
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            );
        }
    }

    #[test]
    fn repair4_record_io_op_counts_success_and_failure() {
        let c = Collect::default();
        let ok: Result<u32, ()> = record_io_op(&c, IoOpKind::Write, || Ok(7));
        assert_eq!(ok, Ok(7));
        let err: Result<u32, &str> = record_io_op(&c, IoOpKind::Read, || Err("x"));
        assert_eq!(err, Err("x"));
        let items = c.items();
        assert_eq!(items.len(), 2);
        assert_eq!(
            (items[0].0, items[0].1),
            (IoOpKind::Write, IoOpOutcome::Success)
        );
        assert_eq!(
            (items[1].0, items[1].1),
            (IoOpKind::Read, IoOpOutcome::Failure)
        );
    }

    #[test]
    fn repair4_io_op_timer_drop_records_failure() {
        let c = Collect::default();
        {
            let _t = IoOpTimer::start(&c, IoOpKind::Write);
        }
        let items = c.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, IoOpOutcome::Failure);
    }

    #[test]
    fn repair4_io_op_timer_finish_records_once() {
        let c = Collect::default();
        IoOpTimer::start(&c, IoOpKind::Read).success();
        let items = c.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, IoOpOutcome::Success);
    }

    #[test]
    fn repair4_record_io_op_records_failure_on_panic() {
        let c = Collect::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ()> = record_io_op(&c, IoOpKind::Write, || panic!("boom"));
        }));
        assert!(r.is_err());
        let items = c.items();
        assert_eq!(items.len(), 1);
        assert_eq!(
            (items[0].0, items[0].1),
            (IoOpKind::Write, IoOpOutcome::Failure)
        );
    }

    #[test]
    fn repair4_io_op_recorder_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopIoOpRecorder>();
        let r: Arc<dyn IoOpRecorder> = Arc::new(NoopIoOpRecorder);
        r.record_io_op(&IoOpSample::new(
            IoOpKind::Read,
            IoOpOutcome::Success,
            Duration::ZERO,
        ));
    }

    #[test]
    fn repair4_io_does_not_depend_on_core() {
        // 受入基準: io → core の依存辺を作らない（循環防止）。
        let manifest = include_str!("../Cargo.toml");
        assert!(!manifest.contains("fandhe-container-core"));
    }
}
