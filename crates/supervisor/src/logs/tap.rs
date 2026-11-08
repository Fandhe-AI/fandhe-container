//! 捕捉リーダーから購読者への出力の tap（#4072・SUP-7・REPAIR-5。関連: CRI-6・SEC-1・REPAIR-3）。
//!
//! 完全版 Attach（親 #3765。`docs/design/cri-streaming-server.md`）の出力は、ログの follow では届かない
//! LF なしのプロンプトを含む生のバイト列でなければならない（決定 D2）。そこで、捕捉リーダー
//! （[`super::LogCapture`] の `pump`）が sink へ書いた直後に、同じチャンクを購読者ごとの非ブロッキング
//! socketpair へ複製する。購読 API は [`crate::log_pipeline::CaptureHub::subscribe_output`] で、制御チャネルの kind 9
//! （C6 #4075。実装済み）が SCM_RIGHTS で返す。
//!
//! # 契約
//! - sink が常に優先: 同じチャンクの `append` と `flush` が戻るまで tap へは書かない。
//! - 背圧なし: tap はバッファを持たず、書き込みはすべて非ブロッキング。チャンクを書き切れない購読者
//!   （`EAGAIN`）・書き込みに失敗した購読者・相手が閉じた購読者は切断する（部分的に届いたバイト列の続きを
//!   後で送るとストリームの整合が崩れるため）。切断は購読者の単位で、stdout と stderr の両方の端を落とす。
//!   切断は構造化ログ 1 行（ストリーム名と理由の語彙だけ。コンテナ ID・出力の内容は出さない）で残す。
//! - 部分行: tap はバイト単位で、LF が無くても届く（sink は行単位のまま）。`MAX_LINE_BYTES` の
//!   切り詰めも適用しない。sink が失敗して読み捨てに入った後も tap には流し続ける（tap は背圧をかけないので
//!   読み捨ての前提を壊さず、sink の故障で attach の出力まで止める理由が無い）。取り消し後は流さない。
//! - 購読後の出力だけ: 登録は publish と同じロックの下で行う。過去の出力のバッファは持たない。
//!   登録より前に read 済みで、登録より後に publish されたチャンクは届きうる。
//! - 閉じる契機: ストリームの EOF・読み取りエラー・取り消し・panic でそのストリームの端を落とし
//!   （購読者は EOF を受ける）、捕捉の世代交代・`quiesce`・`finish` で全購読者を閉じる。
//! - 購読者数の上限は [`MAX_TAP_SUBSCRIBERS`]（ハブ単位）。新しいスレッドは作らない（`Threads: 1` の前提を
//!   壊さない）。
//!
//! # 未実装（REPAIR-3）
//! 制御チャネルの kind 9 `AttachRequest` と fd の受け渡しは実装済み（`control::server`・C6 #4075）。
//! plugin-cri の結線は C9（#4077）。

use super::StreamKind;

/// 購読者数の上限（ハブ単位）。オーナー確認待ち（D10-2）の初期案で、決定ではない。
pub const MAX_TAP_SUBSCRIBERS: usize = 8;

/// 購読するストリームの指定。どちらも偽は `InvalidArgument`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapStreams {
    /// 標準出力を購読する。
    pub stdout: bool,
    /// 標準エラー出力を購読する。
    pub stderr: bool,
}

/// tap の計数（REPAIR-4 の観測口）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TapStats {
    /// 現在の購読者数。
    pub live_subscribers: u64,
    /// 書き切れず（`EAGAIN`）切断した数。
    pub disconnected_overflow: u64,
    /// 書き込みの失敗（相手の契約違反を含む）で切断した数。
    pub disconnected_write_failed: u64,
    /// 相手が閉じていて切断した数。
    pub disconnected_peer_closed: u64,
    /// 上限超過で拒否した購読の数。
    pub rejected_limit: u64,
}

/// 切断の理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// チャンクを書き切れなかった。
    Overflow,
    /// 相手が端を閉じた。
    PeerClosed,
    /// その他の書き込み失敗。
    WriteFailed,
}

impl DisconnectReason {
    /// 構造化ログの語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Overflow => "overflow",
            Self::PeerClosed => "peer_closed",
            Self::WriteFailed => "write_failed",
        }
    }
}

/// 切断の報告先。`None` のストリームは「両方」を表す。
pub(crate) type TapReporter =
    std::sync::Arc<dyn Fn(Option<StreamKind>, DisconnectReason) + Send + Sync>;

/// 既定の報告先: `stderr_sink` へ JSON 1 行（非ブロッキング。満杯なら捨てる）。
pub(crate) fn default_reporter() -> TapReporter {
    std::sync::Arc::new(|stream, reason| {
        let name = stream.map_or("both", StreamKind::as_str);
        let line = format!(
            "{{\"component\":\"supervisor\",\"event\":\"output_tap_subscriber_dropped\",\"stream\":\"{name}\",\"reason\":\"{}\"}}\n",
            reason.as_str()
        );
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
    })
}

#[cfg(unix)]
pub use imp::{OutputTap, TapSubscription};

#[cfg(not(unix))]
pub use stub::{OutputTap, TapSubscription};

#[cfg(unix)]
mod imp {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use fandhe_container_core::traits::{ErrorCode, TraitError};

    use super::{
        DisconnectReason, MAX_TAP_SUBSCRIBERS, StreamKind, TapReporter, TapStats, TapStreams,
    };

    /// 購読者側の端（kind 9 のサーバが SCM_RIGHTS で plugin-cri へ渡す。#4075）。ブロッキングのまま渡す。drop で閉じる。
    #[derive(Debug)]
    pub struct TapSubscription {
        stdout: Option<UnixStream>,
        stderr: Option<UnixStream>,
    }

    impl TapSubscription {
        /// `(stdout, stderr)` の端を取り出す。要求しなかったストリームは `None`。
        pub fn into_parts(self) -> (Option<UnixStream>, Option<UnixStream>) {
            (self.stdout, self.stderr)
        }
    }

    struct Sub {
        stdout: Option<UnixStream>,
        stderr: Option<UnixStream>,
    }

    impl Sub {
        fn end(&mut self, kind: StreamKind) -> &mut Option<UnixStream> {
            match kind {
                StreamKind::Stdout => &mut self.stdout,
                _ => &mut self.stderr,
            }
        }
    }

    fn idx(kind: StreamKind) -> usize {
        match kind {
            StreamKind::Stdout => 0,
            _ => 1,
        }
    }

    #[derive(Default)]
    struct State {
        subs: Vec<Sub>,
        /// 捕捉がそのストリームを持つか（不変）。
        has: [bool; 2],
        /// そのストリームがまだ読まれているか（EOF・取り消しで偽）。
        open: [bool; 2],
        closed: bool,
        stats: TapStats,
    }

    /// 捕捉 1 つにつき 1 つの tap。リーダースレッドが `publish` し、ハブが購読・閉鎖を行う。
    pub struct OutputTap {
        state: Mutex<State>,
        report: TapReporter,
    }

    impl std::fmt::Debug for OutputTap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OutputTap").finish_non_exhaustive()
        }
    }

    type Dropped = Vec<(Option<StreamKind>, DisconnectReason)>;

    impl OutputTap {
        /// 捕捉が持つストリームを指定して作る。
        pub(crate) fn new(has_stdout: bool, has_stderr: bool, report: TapReporter) -> Self {
            Self {
                state: Mutex::new(State {
                    has: [has_stdout, has_stderr],
                    open: [has_stdout, has_stderr],
                    ..State::default()
                }),
                report,
            }
        }

        fn lock(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn emit(&self, dropped: Dropped) {
            for (stream, reason) in dropped {
                (self.report)(stream, reason);
            }
        }

        /// sink へ書いた後のチャンクを購読者へ複製する。全購読者への非ブロッキング write だけで有界。
        pub(crate) fn publish(&self, kind: StreamKind, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            let mut dropped: Dropped = Vec::new();
            {
                let mut st = self.lock();
                if st.closed {
                    return;
                }
                let mut stats = st.stats;
                st.subs.retain_mut(|sub| {
                    let Some(end) = sub.end(kind).as_mut() else {
                        return true;
                    };
                    match write_all_nonblocking(end, data) {
                        Ok(()) => true,
                        Err(reason) => {
                            match reason {
                                DisconnectReason::Overflow => stats.disconnected_overflow += 1,
                                DisconnectReason::PeerClosed => stats.disconnected_peer_closed += 1,
                                DisconnectReason::WriteFailed => {
                                    stats.disconnected_write_failed += 1;
                                }
                            }
                            dropped.push((Some(kind), reason));
                            false
                        }
                    }
                });
                st.stats = stats;
            }
            self.emit(dropped);
        }

        /// そのストリームの終わり（EOF・エラー・取り消し・panic）。購読者の端を落として EOF を伝える。
        pub(crate) fn end_stream(&self, kind: StreamKind) {
            let mut st = self.lock();
            if let Some(o) = st.open.get_mut(idx(kind)) {
                *o = false;
            }
            for sub in &mut st.subs {
                *sub.end(kind) = None;
            }
            st.subs.retain(|s| s.stdout.is_some() || s.stderr.is_some());
        }

        /// 全購読者を閉じ、以後の購読を拒否する（世代交代・quiesce・finish）。
        pub(crate) fn close_all(&self) {
            let mut st = self.lock();
            st.closed = true;
            st.subs.clear();
        }

        /// 計数のスナップショット。
        pub(crate) fn stats(&self) -> TapStats {
            let st = self.lock();
            let mut s = st.stats;
            s.live_subscribers = st.subs.len() as u64;
            s
        }

        /// 購読者を登録する。契約はモジュール doc と `CaptureHub::subscribe_output` の doc を参照。
        pub(crate) fn subscribe(&self, streams: TapStreams) -> Result<TapSubscription, TraitError> {
            if !streams.stdout && !streams.stderr {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "at least one output stream must be requested",
                ));
            }
            let mut dropped: Dropped = Vec::new();
            let result = self.subscribe_locked(streams, &mut dropped);
            self.emit(dropped);
            result
        }

        fn subscribe_locked(
            &self,
            streams: TapStreams,
            dropped: &mut Dropped,
        ) -> Result<TapSubscription, TraitError> {
            let mut st = self.lock();
            if st.closed {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "no live output capture",
                ));
            }
            for (want, i) in [(streams.stdout, 0), (streams.stderr, 1)] {
                if want && !st.has.get(i).copied().unwrap_or(false) {
                    return Err(TraitError::new(
                        ErrorCode::FailedPrecondition,
                        "output stream is not captured",
                    ));
                }
            }
            // 相手が閉じた購読者を掃除してから上限を見る。
            let mut stats = st.stats;
            st.subs.retain_mut(|sub| match sweep(sub) {
                None => true,
                Some(reason) => {
                    match reason {
                        DisconnectReason::PeerClosed => stats.disconnected_peer_closed += 1,
                        _ => stats.disconnected_write_failed += 1,
                    }
                    dropped.push((None, reason));
                    false
                }
            });
            st.stats = stats;
            if st.subs.len() >= MAX_TAP_SUBSCRIBERS {
                st.stats.rejected_limit += 1;
                return Err(TraitError::new(
                    ErrorCode::ResourceExhausted,
                    "too many output tap subscribers",
                ));
            }
            let mut sub = Sub {
                stdout: None,
                stderr: None,
            };
            let mut out = TapSubscription {
                stdout: None,
                stderr: None,
            };
            for kind in [StreamKind::Stdout, StreamKind::Stderr] {
                let want = match kind {
                    StreamKind::Stdout => streams.stdout,
                    _ => streams.stderr,
                };
                if !want {
                    continue;
                }
                let (mine, theirs) = UnixStream::pair().map_err(|_| {
                    TraitError::new(
                        ErrorCode::Internal,
                        "failed to create output tap socketpair",
                    )
                })?;
                let still_open = st.open.get(idx(kind)).copied().unwrap_or(false);
                if still_open {
                    mine.set_nonblocking(true).map_err(|_| {
                        TraitError::new(ErrorCode::Internal, "failed to configure output tap")
                    })?;
                    *sub.end(kind) = Some(mine);
                }
                // EOF 済みのストリームは supervisor 側の端を落とし、購読者には即 EOF。
                match kind {
                    StreamKind::Stdout => out.stdout = Some(theirs),
                    _ => out.stderr = Some(theirs),
                }
            }
            if sub.stdout.is_some() || sub.stderr.is_some() {
                st.subs.push(sub);
            }
            Ok(out)
        }
    }

    /// 非ブロッキングで全体を書く。書き切れなければ切断理由を返す（続きは送らない）。
    fn write_all_nonblocking(
        end: &mut UnixStream,
        mut data: &[u8],
    ) -> Result<(), DisconnectReason> {
        while !data.is_empty() {
            match end.write(data) {
                Ok(0) => return Err(DisconnectReason::WriteFailed),
                Ok(n) => data = data.get(n..).unwrap_or_default(),
                Err(e) => match e.kind() {
                    ErrorKind::Interrupted => {}
                    ErrorKind::WouldBlock => return Err(DisconnectReason::Overflow),
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                        return Err(DisconnectReason::PeerClosed);
                    }
                    _ => return Err(DisconnectReason::WriteFailed),
                },
            }
        }
        Ok(())
    }

    /// 購読者の端を 1 回だけ読んで生死を見る。切断すべきなら理由を返す。
    fn sweep(sub: &mut Sub) -> Option<DisconnectReason> {
        for end in [sub.stdout.as_ref(), sub.stderr.as_ref()]
            .into_iter()
            .flatten()
        {
            let mut probe = [0u8; 1];
            let mut r = end;
            match r.read(&mut probe) {
                Ok(0) => return Some(DisconnectReason::PeerClosed),
                Ok(_) => return Some(DisconnectReason::WriteFailed),
                Err(e) => match e.kind() {
                    ErrorKind::WouldBlock | ErrorKind::Interrupted => {}
                    _ => return Some(DisconnectReason::PeerClosed),
                },
            }
        }
        None
    }
}

#[cfg(not(unix))]
mod stub {
    use fandhe_container_core::traits::{ErrorCode, TraitError};

    use super::{StreamKind, TapReporter, TapStats, TapStreams};

    /// 非 unix では購読を提供しない（`subscribe` は `Unimplemented`）。
    #[derive(Debug)]
    pub struct TapSubscription {
        _private: (),
    }

    /// 非 unix の何もしない tap。
    #[derive(Debug)]
    pub struct OutputTap {
        _private: (),
    }

    impl OutputTap {
        pub(crate) fn new(_has_stdout: bool, _has_stderr: bool, _report: TapReporter) -> Self {
            Self { _private: () }
        }
        pub(crate) fn publish(&self, _kind: StreamKind, _data: &[u8]) {}
        pub(crate) fn end_stream(&self, _kind: StreamKind) {}
        pub(crate) fn close_all(&self) {}
        pub(crate) fn stats(&self) -> TapStats {
            TapStats::default()
        }
        pub(crate) fn subscribe(
            &self,
            _streams: TapStreams,
        ) -> Result<TapSubscription, TraitError> {
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                "output tap is not supported on this platform",
            ))
        }
    }
}
