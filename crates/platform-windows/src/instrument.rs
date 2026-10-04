//! platform-windows の操作の計装連携点（REPAIR-4・TASK-67.2・WIN-2）。
//!
//! `.wslconfig` の読み込み（`wslconfig::load_with_recorder`）と virtiofs の opt-in 書き込み
//! （`wslconfig::enable_virtiofs_at_with_recorder`）が、1 回の操作ごとの結果（成功 / 失敗）と所要時間を
//! 記録先へ渡すための境界。集計（成功・失敗件数とレイテンシ分布）と構造化ログへの出力は core の
//! `OpRecorder` が担うが、本 crate は core に依存しないため、本 crate の型だけで完結するトレイトを定義する
//! （`fandhe-container-net` の `instrument`・`fandhe-container-io` の `instrument` と同じ形）。core の記録器への
//! 接続は、両方に依存する上位 crate（`fandhe-container-plugin-windows`・TASK-116）に置くアダプタが担い、
//! `sample.kind().as_str()` を core の `OpName::new` へ、`sample.outcome()` / `sample.latency()` を
//! `OpRecorder::record` へ写す。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - core の `OpRecorder` との接続アダプタ（上位 crate の担当。本 crate からは提供しない）
//! - WSL2 検出・virtiofs マウント等の後続操作（TASK-67.3〜67.5）の種別は、各操作と一緒に [`WinOpKind`] へ追加する
//!
//! # 機微情報
//!
//! [`WinOpSample`] は種別・結果・レイテンシのみを持ち、設定内容・ユーザーのパス・エラー文言は持たせない
//! （`.claude/rules/security.md`）。

use std::time::{Duration, Instant};

/// 計装対象の操作の種別（REPAIR-4）。
///
/// [`WinOpKind::as_str`] は core の `OpName` 規則（`[A-Za-z0-9._-]`・64 バイト以下）に収まる固定文字列を
/// 返す契約を持つ。本 crate は core の定数を import できないため規則を重複して持ち、テストで固定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WinOpKind {
    /// `.wslconfig` の読み込み 1 回（検証・読み込み・解析。ファイルなしは成功）。
    WslconfigLoad,
    /// `virtiofs=true` の opt-in 1 回（読み込みから作成・置換・親ディレクトリ同期まで。書き込み不要の
    /// `AlreadyEnabled` も成功として 1 件）。内側の読み込みは別サンプルとして記録しない。
    WslconfigEnableVirtiofs,
}

impl WinOpKind {
    /// core の `OpName` へ渡す安定した操作名。
    pub fn as_str(self) -> &'static str {
        match self {
            WinOpKind::WslconfigLoad => "wslconfig.load",
            WinOpKind::WslconfigEnableVirtiofs => "wslconfig.enable_virtiofs",
        }
    }
}

/// 操作の結果区分（真偽値ではなく将来拡張できる型。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WinOpOutcome {
    /// 成功。
    Success,
    /// 失敗（エラー・早期 return・panic を含む）。
    Failure,
}

impl WinOpOutcome {
    /// `Result` から結果区分を導く（中身は参照しない）。
    pub fn from_result<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => WinOpOutcome::Success,
            Err(_) => WinOpOutcome::Failure,
        }
    }
}

/// 1 回の操作の計測結果（固定サイズの値型。ヒープ確保なし）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WinOpSample {
    kind: WinOpKind,
    outcome: WinOpOutcome,
    latency: Duration,
}

impl WinOpSample {
    /// サンプルを作る。
    pub fn new(kind: WinOpKind, outcome: WinOpOutcome, latency: Duration) -> Self {
        Self {
            kind,
            outcome,
            latency,
        }
    }

    /// 操作の種別。
    pub fn kind(&self) -> WinOpKind {
        self.kind
    }

    /// 操作の結果区分。
    pub fn outcome(&self) -> WinOpOutcome {
        self.outcome
    }

    /// 操作に要した時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// 計測結果を受け取る記録先（REPAIR-4）。
///
/// 契約: 設定ファイル操作の経路から呼ばれるため、有界時間で戻ること（I/O・相手応答待ち・無期限のロック待ちを
/// しない。REPAIR-5）。panic しないこと。戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えない
/// ため。`dyn WinOpRecorder` として `Arc` 共有できる。
pub trait WinOpRecorder: Send + Sync {
    /// 1 件の計測結果を記録する。
    fn record_win_op(&self, sample: &WinOpSample);
}

/// 計測しない場合に明示的に渡す既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopWinOpRecorder;

impl WinOpRecorder for NoopWinOpRecorder {
    fn record_win_op(&self, _sample: &WinOpSample) {}
}

/// 計測中の操作を表すガード。
///
/// [`finish_with`](Self::finish_with) で結果を確定する。未確定のまま Drop された場合（早期 return・`?`・
/// panic の巻き戻し）は `Failure` として記録する（fail-closed）。
#[must_use = "drop without finishing records a failure"]
pub struct WinOpTimer<'a> {
    recorder: &'a dyn WinOpRecorder,
    kind: WinOpKind,
    started: Instant,
    done: bool,
}

impl<'a> WinOpTimer<'a> {
    /// 計測を開始する。
    pub fn start(recorder: &'a dyn WinOpRecorder, kind: WinOpKind) -> Self {
        Self {
            recorder,
            kind,
            started: Instant::now(),
            done: false,
        }
    }

    fn emit(&mut self, outcome: WinOpOutcome) {
        if self.done {
            return;
        }
        self.done = true;
        let sample = WinOpSample::new(self.kind, outcome, self.started.elapsed());
        self.recorder.record_win_op(&sample);
    }

    /// `Result` に応じて確定する。
    pub fn finish_with<T, E>(mut self, result: &Result<T, E>) {
        self.emit(WinOpOutcome::from_result(result));
    }
}

impl Drop for WinOpTimer<'_> {
    fn drop(&mut self) {
        self.emit(WinOpOutcome::Failure);
    }
}

/// クロージャを計測して結果をそのまま返すヘルパー（panic 時もガードが Failure を記録する）。
pub fn record_win_op<T, E>(
    recorder: &dyn WinOpRecorder,
    kind: WinOpKind,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let timer = WinOpTimer::start(recorder, kind);
    let result = f();
    timer.finish_with(&result);
    result
}

#[cfg(test)]
pub(crate) mod testing {
    //! 記録内容を照合するための試験用記録先。

    use super::*;
    use std::sync::Mutex;

    /// 受け取ったサンプルを順に保持する。
    #[derive(Default)]
    pub(crate) struct Collect(Mutex<Vec<WinOpSample>>);

    impl WinOpRecorder for Collect {
        fn record_win_op(&self, s: &WinOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*s);
            }
        }
    }

    impl Collect {
        /// これまでに記録されたサンプル。
        pub(crate) fn items(&self) -> Vec<WinOpSample> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }

        /// (種別, 結果) の列。
        pub(crate) fn kinds(&self) -> Vec<(WinOpKind, WinOpOutcome)> {
            self.items()
                .iter()
                .map(|s| (s.kind(), s.outcome()))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Collect;
    use super::*;
    use std::sync::Arc;

    const ALL_KINDS: [WinOpKind; 2] =
        [WinOpKind::WslconfigLoad, WinOpKind::WslconfigEnableVirtiofs];

    /// REPAIR-4: 操作名は安定した固定文字列。
    #[test]
    fn repair4_win_op_kind_as_str_is_stable() {
        assert_eq!(WinOpKind::WslconfigLoad.as_str(), "wslconfig.load");
        assert_eq!(
            WinOpKind::WslconfigEnableVirtiofs.as_str(),
            "wslconfig.enable_virtiofs"
        );
    }

    /// REPAIR-4: 操作名は core の `OpName::new` と同じ規則に収まる（本 crate は core に依存できないため
    /// 重複して固定する）。
    #[test]
    fn repair4_win_op_kind_names_fit_core_op_name_contract() {
        for kind in ALL_KINDS {
            let s = kind.as_str();
            assert!(!s.is_empty() && s.len() <= 64, "{s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "{s}"
            );
        }
    }

    /// REPAIR-4: 成功・失敗がそれぞれ 1 件ずつ、結果を変えずに記録される。
    #[test]
    fn repair4_record_win_op_counts_success_and_failure() {
        let c = Collect::default();
        let ok: Result<u32, ()> = record_win_op(&c, WinOpKind::WslconfigLoad, || Ok(7));
        assert_eq!(ok, Ok(7));
        let err: Result<u32, &str> =
            record_win_op(&c, WinOpKind::WslconfigEnableVirtiofs, || Err("x"));
        assert_eq!(err, Err("x"));
        assert_eq!(
            c.kinds(),
            vec![
                (WinOpKind::WslconfigLoad, WinOpOutcome::Success),
                (WinOpKind::WslconfigEnableVirtiofs, WinOpOutcome::Failure),
            ]
        );
    }

    /// REPAIR-4: レイテンシは操作に要した実時間を含む。
    #[test]
    fn repair4_record_win_op_measures_latency() {
        let c = Collect::default();
        let _: Result<(), ()> = record_win_op(&c, WinOpKind::WslconfigLoad, || {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        });
        let items = c.items();
        assert_eq!(items.len(), 1);
        let latency = items.first().map(WinOpSample::latency).expect("one sample");
        assert!(latency >= Duration::from_millis(20));
        assert!(latency < Duration::from_secs(5));
    }

    /// REPAIR-4: 未確定のまま Drop されたガードは Failure を 1 件記録する（fail-closed）。
    #[test]
    fn repair4_win_op_timer_drop_records_failure() {
        let c = Collect::default();
        {
            let _t = WinOpTimer::start(&c, WinOpKind::WslconfigLoad);
        }
        assert_eq!(
            c.kinds(),
            vec![(WinOpKind::WslconfigLoad, WinOpOutcome::Failure)]
        );
    }

    /// REPAIR-4: panic で巻き戻っても Failure が 1 件だけ記録される。
    #[test]
    fn repair4_record_win_op_records_failure_on_panic() {
        let c = Collect::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ()> =
                record_win_op(&c, WinOpKind::WslconfigEnableVirtiofs, || panic!("boom"));
        }));
        assert!(r.is_err());
        assert_eq!(
            c.kinds(),
            vec![(WinOpKind::WslconfigEnableVirtiofs, WinOpOutcome::Failure)]
        );
    }

    /// REPAIR-4: 記録先は `Arc<dyn WinOpRecorder>` として共有でき、Send + Sync。
    #[test]
    fn repair4_win_op_recorder_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NoopWinOpRecorder>();
        assert_send_sync::<dyn WinOpRecorder>();
        let r: Arc<dyn WinOpRecorder> = Arc::new(NoopWinOpRecorder);
        let sample = WinOpSample::new(
            WinOpKind::WslconfigLoad,
            WinOpOutcome::Success,
            Duration::from_millis(3),
        );
        r.record_win_op(&sample);
        assert_eq!(sample.kind(), WinOpKind::WslconfigLoad);
        assert_eq!(sample.outcome(), WinOpOutcome::Success);
        assert_eq!(sample.latency(), Duration::from_millis(3));
    }
}
