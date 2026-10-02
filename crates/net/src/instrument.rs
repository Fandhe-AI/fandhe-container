//! net 操作の計装連携点（REPAIR-4・NET-11・TASK-136.2.1）。
//!
//! `NETLINK_ROUTE` ソケットの open / send / recv（`crate::netlink_route::NetlinkRouteSocket`）が、
//! 1 回の操作ごとの結果（成功 / 失敗）と所要時間を記録先へ渡すための境界。集計（成功・失敗件数と
//! レイテンシ分布）と構造化ログへの出力は core の `OpRecorder` が担うが、net は core に依存しない
//! ため、本モジュールが net 内の型だけで完結するトレイトを定義する（`fandhe-container-io` の
//! `instrument` モジュールと同じ形）。core の記録器への接続は、core と net の両方に依存する上位
//! crate に置く newtype アダプタが担い、`sample.kind().as_str()` を core の `OpName::new` へ、
//! `sample.outcome()` / `sample.latency()` を `OpRecorder::record` へ写す。
//!
//! OS 非依存（型とトレイトのみ）で、Linux 以外でもアダプタをビルドできる。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - core の `OpRecorder` との接続アダプタ（上位 crate の担当。net からは提供しない）
//! - 後続の操作（#844 の request / ACK、#845・#846 の link 操作等）の種別は、各 Issue で
//!   [`NetOpKind`] へ追加する
//!
//! # 機微情報
//!
//! [`NetOpSample`] は種別・結果・レイテンシのみを持ち、メッセージ内容・アドレス・エラー文言は
//! 持たせない（`.claude/rules/security.md`）。

use std::time::{Duration, Instant};

/// 計装対象の net 操作の種別（REPAIR-4）。
///
/// [`NetOpKind::as_str`] は core の `OpName` 規則（`[A-Za-z0-9._-]`・64 バイト以下）に収まる
/// 固定文字列を返す契約を持つ。net は core の定数を import できないため規則を重複して持ち、
/// テストで固定する。閉じた enum なので自由入力の文字列がログのキーに入る経路はない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetOpKind {
    /// `NETLINK_ROUTE` ソケットの open と bind。
    NetlinkOpen,
    /// netlink メッセージ 1 件の送信（送信前検証での拒否を含む）。
    NetlinkSend,
    /// netlink データグラム 1 件の受信（期限までの待機時間を含む。時間切れは失敗）。
    NetlinkRecv,
}

impl NetOpKind {
    /// core の `OpName` へ渡す安定した操作名。
    pub fn as_str(self) -> &'static str {
        match self {
            NetOpKind::NetlinkOpen => "netlink.open",
            NetOpKind::NetlinkSend => "netlink.send",
            NetOpKind::NetlinkRecv => "netlink.recv",
        }
    }
}

/// 操作の結果区分（真偽値ではなく将来拡張できる型。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetOpOutcome {
    /// 成功。
    Success,
    /// 失敗（エラー・時間切れ・早期 return・panic を含む）。
    Failure,
}

impl NetOpOutcome {
    /// `Result` から結果区分を導く（中身は参照しない）。
    pub fn from_result<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => NetOpOutcome::Success,
            Err(_) => NetOpOutcome::Failure,
        }
    }
}

/// 1 回の操作の計測結果（固定サイズの値型。ヒープ確保なし）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetOpSample {
    kind: NetOpKind,
    outcome: NetOpOutcome,
    latency: Duration,
}

impl NetOpSample {
    /// サンプルを作る。
    pub fn new(kind: NetOpKind, outcome: NetOpOutcome, latency: Duration) -> Self {
        Self {
            kind,
            outcome,
            latency,
        }
    }

    /// 操作の種別。
    pub fn kind(&self) -> NetOpKind {
        self.kind
    }

    /// 操作の結果区分。
    pub fn outcome(&self) -> NetOpOutcome {
        self.outcome
    }

    /// 操作に要した時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// net の計測結果を受け取る記録先（REPAIR-4）。
///
/// 契約: 送受信経路から呼ばれるため、有界時間で戻ること（I/O・相手応答待ち・無期限の
/// ロック待ちをしない。O(1) の短い有界ロックは許容。REPAIR-5）。panic しないこと。
/// 戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えないため。
/// `dyn NetOpRecorder` として `Arc` 共有できる。
pub trait NetOpRecorder: Send + Sync {
    /// 1 件の計測結果を記録する。
    fn record_net_op(&self, sample: &NetOpSample);
}

/// 計測しない場合に明示的に渡す既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopNetOpRecorder;

impl NetOpRecorder for NoopNetOpRecorder {
    fn record_net_op(&self, _sample: &NetOpSample) {}
}

/// 計測中の操作を表すガード。
///
/// [`finish_with`](Self::finish_with) で結果を確定する。未確定のまま Drop された場合
/// （早期 return・`?`・panic の巻き戻し）は `Failure` として記録する（fail-closed）。
#[must_use = "drop without finishing records a failure"]
pub struct NetOpTimer<'a> {
    recorder: &'a dyn NetOpRecorder,
    kind: NetOpKind,
    started: Instant,
    done: bool,
}

impl<'a> NetOpTimer<'a> {
    /// 計測を開始する。
    pub fn start(recorder: &'a dyn NetOpRecorder, kind: NetOpKind) -> Self {
        Self {
            recorder,
            kind,
            started: Instant::now(),
            done: false,
        }
    }

    fn emit(&mut self, outcome: NetOpOutcome) {
        if self.done {
            return;
        }
        self.done = true;
        let sample = NetOpSample::new(self.kind, outcome, self.started.elapsed());
        self.recorder.record_net_op(&sample);
    }

    /// `Result` に応じて確定する。
    pub fn finish_with<T, E>(mut self, result: &Result<T, E>) {
        self.emit(NetOpOutcome::from_result(result));
    }
}

impl Drop for NetOpTimer<'_> {
    fn drop(&mut self) {
        self.emit(NetOpOutcome::Failure);
    }
}

/// クロージャを計測して結果をそのまま返すヘルパー（panic 時もガードが Failure を記録する）。
pub fn record_net_op<T, E>(
    recorder: &dyn NetOpRecorder,
    kind: NetOpKind,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let timer = NetOpTimer::start(recorder, kind);
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
    pub(crate) struct Collect(Mutex<Vec<NetOpSample>>);

    impl NetOpRecorder for Collect {
        fn record_net_op(&self, s: &NetOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*s);
            }
        }
    }

    impl Collect {
        /// これまでに記録されたサンプル。
        pub(crate) fn items(&self) -> Vec<NetOpSample> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }

        /// (種別, 結果) の列。
        pub(crate) fn kinds(&self) -> Vec<(NetOpKind, NetOpOutcome)> {
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

    const ALL_KINDS: [NetOpKind; 3] = [
        NetOpKind::NetlinkOpen,
        NetOpKind::NetlinkSend,
        NetOpKind::NetlinkRecv,
    ];

    /// REPAIR-4: 操作名は安定した固定文字列。
    #[test]
    fn repair4_net_op_kind_as_str_is_stable() {
        assert_eq!(NetOpKind::NetlinkOpen.as_str(), "netlink.open");
        assert_eq!(NetOpKind::NetlinkSend.as_str(), "netlink.send");
        assert_eq!(NetOpKind::NetlinkRecv.as_str(), "netlink.recv");
    }

    /// REPAIR-4: 操作名は core の `OpName::new` と同じ規則に収まる（net は core に依存できないため
    /// 重複して固定する）。
    #[test]
    fn repair4_net_op_kind_names_fit_core_op_name_contract() {
        for kind in ALL_KINDS {
            let s = kind.as_str();
            assert!(!s.is_empty() && s.len() <= 64);
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            );
        }
    }

    /// REPAIR-4: 成功・失敗がそれぞれ 1 件ずつ、結果を変えずに記録される。
    #[test]
    fn repair4_record_net_op_counts_success_and_failure() {
        let c = Collect::default();
        let ok: Result<u32, ()> = record_net_op(&c, NetOpKind::NetlinkSend, || Ok(7));
        assert_eq!(ok, Ok(7));
        let err: Result<u32, &str> = record_net_op(&c, NetOpKind::NetlinkRecv, || Err("x"));
        assert_eq!(err, Err("x"));
        assert_eq!(
            c.kinds(),
            vec![
                (NetOpKind::NetlinkSend, NetOpOutcome::Success),
                (NetOpKind::NetlinkRecv, NetOpOutcome::Failure),
            ]
        );
    }

    /// REPAIR-4: レイテンシは操作に要した実時間を含む。
    #[test]
    fn repair4_record_net_op_measures_latency() {
        let c = Collect::default();
        let _: Result<(), ()> = record_net_op(&c, NetOpKind::NetlinkRecv, || {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        });
        let items = c.items();
        assert_eq!(items.len(), 1);
        let latency = items.first().map(NetOpSample::latency).expect("one sample");
        assert!(latency >= Duration::from_millis(20));
        assert!(latency < Duration::from_secs(5));
    }

    /// REPAIR-4: 未確定のまま Drop されたガードは Failure を 1 件記録する（fail-closed）。
    #[test]
    fn repair4_net_op_timer_drop_records_failure() {
        let c = Collect::default();
        {
            let _t = NetOpTimer::start(&c, NetOpKind::NetlinkOpen);
        }
        assert_eq!(
            c.kinds(),
            vec![(NetOpKind::NetlinkOpen, NetOpOutcome::Failure)]
        );
    }

    /// REPAIR-4: panic で巻き戻っても Failure が 1 件だけ記録される。
    #[test]
    fn repair4_record_net_op_records_failure_on_panic() {
        let c = Collect::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ()> = record_net_op(&c, NetOpKind::NetlinkSend, || panic!("boom"));
        }));
        assert!(r.is_err());
        assert_eq!(
            c.kinds(),
            vec![(NetOpKind::NetlinkSend, NetOpOutcome::Failure)]
        );
    }

    /// REPAIR-4: 記録先は `Arc<dyn NetOpRecorder>` として共有でき、Send + Sync。
    #[test]
    fn repair4_net_op_recorder_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NoopNetOpRecorder>();
        assert_send_sync::<dyn NetOpRecorder>();
        let r: Arc<dyn NetOpRecorder> = Arc::new(NoopNetOpRecorder);
        let sample = NetOpSample::new(
            NetOpKind::NetlinkOpen,
            NetOpOutcome::Success,
            Duration::from_millis(3),
        );
        r.record_net_op(&sample);
        assert_eq!(sample.kind(), NetOpKind::NetlinkOpen);
        assert_eq!(sample.outcome(), NetOpOutcome::Success);
        assert_eq!(sample.latency(), Duration::from_millis(3));
    }
}
