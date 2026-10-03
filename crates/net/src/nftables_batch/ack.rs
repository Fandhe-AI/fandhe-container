//! nf_tables バッチの ACK / エラー判定と構造化エラー（TASK-137.3・NET-11・REPAIR-2・REPAIR-5・MS-8・#306）。
//!
//! `NetlinkNetfilterSocket::send_batch`（同 crate の `socket`。Linux のみ）が受信した
//! データグラムを [`NftBatchAckCollector`] へ渡し、バッチ内の本体メッセージごとの ACK / `NLMSG_ERROR` を
//! 集める。ソケット I/O を持たない純粋な状態機械なので、判定ロジックは scripted なデータグラムで
//! 単体テストする。errno の分類に Linux 値（`netlink_route::classify_errno`）を使うため、
//! 本モジュールも Linux でのみビルドされる。
//!
//! # カーネルの挙動（`net/netfilter/nfnetlink.c`）と判定規則
//!
//! - バッチは all-or-nothing。本体にエラーがあっても処理は止まらず、全エラーを積んだうえでバッチ全体を
//!   abort し、ACK / エラー列を送信順に配送する。よって他の本体の errno 0 の ACK は「適用済み」を意味せず、
//!   1 件でも失敗があれば [`NftBatchOutcome::Aborted`]（何も適用されていない）になる
//! - 権限不足（`CAP_NET_ADMIN` なし）の `-EPERM` や `-ENOMEM` はバッチ先頭（BEGIN）の seq に対して返る。
//!   これは [`NftBatchPosition::Begin`] として即座に確定し、キューに残る後続の応答は読まない
//!   （ソケットが seq を一意に採番するため、次のバッチは seq 不一致として破棄する）
//! - BEGIN / END への errno 0 の ACK は許容して無視する（カーネル版数で返る場合がある）
//! - 完了条件は本体の全 seq に判定が揃うこと。END は `NLM_F_ACK` を持たず成功時は無応答のため待たないが、
//!   失敗（非 0 errno）が別データグラムで届き得るので、`exchange` が判定後に受信キューを読み切って
//!   `feed` へ渡し続ける（`socket::drain_trailing`）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! extended ACK（`NETLINK_EXT_ACK`）の解釈と、`NFTA_GEN_ID` による楽観的並行制御は未実装。

use std::fmt;
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLMSG_ERROR, NLMSG_NOOP, NlMsgIter};
use crate::netlink_route::{classify_errno, decode_nlmsgerr};
use crate::nftables_batch::NftBatchBytes;

/// 失敗したメッセージのバッチ内位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NftBatchPosition {
    /// `NFNL_MSG_BATCH_BEGIN`（権限不足などバッチ全体の失敗）。
    Begin,
    /// 本体メッセージ。`index` は `NftBatchBytes::body_seqs` の何番目か（0 始まり）。
    Body {
        /// 積んだ順の添字。
        index: usize,
    },
    /// `NFNL_MSG_BATCH_END`。
    End,
}

impl fmt::Display for NftBatchPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Begin => f.write_str("begin"),
            Self::Body { index } => write!(f, "body[{index}]"),
            Self::End => f.write_str("end"),
        }
    }
}

/// カーネルが失敗を返した 1 メッセージ（どのメッセージが何で失敗したか。NET-11）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftMessageFailure {
    position: NftBatchPosition,
    seq: u32,
    errno: i32,
    code: NetErrorCode,
}

impl NftMessageFailure {
    /// バッチ内の位置。
    pub fn position(&self) -> NftBatchPosition {
        self.position
    }

    /// 失敗したメッセージの `nlmsg_seq`。
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// カーネルが返した正の errno。
    pub fn errno(&self) -> i32 {
        self.errno
    }

    /// errno を分類した機械可読なコード（ERR-1）。
    pub fn code(&self) -> NetErrorCode {
        self.code
    }
}

/// バッチがカーネルに適用されたかどうか（呼び出し側が再照会の要否を判断する材料）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NftBatchOutcome {
    /// カーネルが失敗を返した。nf_tables のバッチは all-or-nothing で、何も適用されていない。
    Aborted,
    /// 時間切れ・受信欠落・応答の破損などで、適用されたかどうか不明。状態を再照会すること。
    Unknown,
    /// 送信前に拒否または期限切れになり、カーネルへは何も送っていない。
    NotSent,
}

/// バッチ送信の構造化エラー（`code` / `message` に加え、失敗メッセージの一覧と適用状態を持つ）。
///
/// `message` は英語で、件数・添字・seq・errno の数値だけを載せる（テーブル名や受信バイト列は載せない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftBatchError {
    error: NetError,
    outcome: NftBatchOutcome,
    failures: Vec<NftMessageFailure>,
}

impl NftBatchError {
    /// 送信前の失敗（空バッチ・期限切れ・組み立て失敗・送信拒否）。
    pub(crate) fn not_sent(error: NetError) -> Self {
        Self {
            error,
            outcome: NftBatchOutcome::NotSent,
            failures: Vec::new(),
        }
    }

    /// 送信後に適用されたか不明な失敗（部分送信など。失敗一覧は空）。
    pub(crate) fn unknown_outcome(error: NetError) -> Self {
        Self {
            error,
            outcome: NftBatchOutcome::Unknown,
            failures: Vec::new(),
        }
    }

    /// 機械可読な分類。`Aborted` ではカーネルが返した先頭の失敗の分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }

    /// バッチが適用されたか。
    pub fn outcome(&self) -> NftBatchOutcome {
        self.outcome
    }

    /// 失敗したメッセージの一覧（Begin・本体の添字順・End の順）。
    pub fn failures(&self) -> &[NftMessageFailure] {
        &self.failures
    }
}

impl fmt::Display for NftBatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for NftBatchError {}

impl From<NftBatchError> for NetError {
    fn from(e: NftBatchError) -> Self {
        e.error
    }
}

/// 全メッセージが成功した結果。将来の拡張に備えた構造体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftBatchAck {
    begin_seq: u32,
    end_seq: u32,
    body_seqs: Vec<u32>,
}

impl NftBatchAck {
    /// BEGIN の seq。
    pub fn begin_seq(&self) -> u32 {
        self.begin_seq
    }

    /// END の seq。
    pub fn end_seq(&self) -> u32 {
        self.end_seq
    }

    /// ACK を確認した本体メッセージの seq（積んだ順）。
    pub fn body_seqs(&self) -> &[u32] {
        &self.body_seqs
    }
}

/// [`NftBatchAckCollector::feed`] の経過。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// 判定が揃っていない。次のデータグラムを待つ。
    Pending,
    /// 全本体が成功した。
    Done(NftBatchAck),
}

/// 1 バッチ分の応答を集めて判定する状態機械。
///
/// 前提: ソケットが seq をバッチごとに一意に採番する（`[begin_seq..=end_seq]` の外の seq は以前に
/// 時間切れしたバッチの遅延応答として破棄できる）。マルチキャスト購読はなく、カーネル発の
/// 非要求メッセージは来ない。
#[derive(Debug)]
pub(crate) struct NftBatchAckCollector {
    begin_seq: u32,
    end_seq: u32,
    body_seqs: Vec<u32>,
    /// 本体ごとの判定済みフラグ（`body_seqs` と同じ添字）。
    seen: Vec<bool>,
    pending: usize,
    failures: Vec<NftMessageFailure>,
}

fn data_loss(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

impl NftBatchAckCollector {
    /// 閉じたバッチの seq 構成から作る。保持する件数は `NftBatch` の長さ上限で有界。
    pub(crate) fn new(batch: &NftBatchBytes) -> Self {
        let body_seqs = batch.body_seqs().to_vec();
        Self {
            begin_seq: batch.begin_seq(),
            end_seq: batch.end_seq(),
            seen: vec![false; body_seqs.len()],
            pending: body_seqs.len(),
            body_seqs,
            failures: Vec::new(),
        }
    }

    /// `seq` が指すバッチ内の位置。範囲外（遅延応答）は `None`。
    fn locate(&self, seq: u32) -> Option<NftBatchPosition> {
        if seq == self.begin_seq {
            return Some(NftBatchPosition::Begin);
        }
        if seq == self.end_seq {
            return Some(NftBatchPosition::End);
        }
        let index = usize::try_from(seq.wrapping_sub(self.begin_seq))
            .ok()?
            .checked_sub(1)?;
        (self.body_seqs.get(index) == Some(&seq)).then_some(NftBatchPosition::Body { index })
    }

    fn record(&mut self, position: NftBatchPosition, seq: u32, errno: i32) {
        self.failures.push(NftMessageFailure {
            position,
            seq,
            errno,
            code: classify_errno(errno),
        });
    }

    /// 受信した 1 データグラム（外部入力）を判定する。
    pub(crate) fn feed(&mut self, datagram: &[u8]) -> Result<Progress, NftBatchError> {
        for item in NlMsgIter::new(datagram) {
            let msg = item.map_err(|e| self.unknown(data_loss(e.message().to_string())))?;
            let h = msg.header();
            let Some(position) = self.locate(h.seq()) else {
                // 以前に時間切れしたバッチの遅延応答。
                continue;
            };
            if h.msg_type() == NLMSG_NOOP {
                continue;
            }
            if h.msg_type() != NLMSG_ERROR {
                return Err(self.unknown(data_loss(format!(
                    "unexpected netlink message type {} for batch seq {}",
                    h.msg_type(),
                    h.seq()
                ))));
            }
            let ack = decode_nlmsgerr(msg.payload()).map_err(|e| self.unknown(e))?;
            if ack.request_seq().is_some_and(|s| s != h.seq()) {
                return Err(self.unknown(data_loss(format!(
                    "nlmsgerr for batch seq {} embeds a different request seq",
                    h.seq()
                ))));
            }
            let errno = ack.errno();
            match position {
                NftBatchPosition::Begin | NftBatchPosition::End => {
                    if errno != 0 {
                        // バッチ全体の失敗。後続の応答は読まず即座に確定する。
                        self.record(position, h.seq(), errno);
                        return Err(self.aborted());
                    }
                }
                NftBatchPosition::Body { index } => {
                    let Some(seen) = self.seen.get_mut(index) else {
                        continue;
                    };
                    if *seen {
                        return Err(self.unknown(data_loss(format!(
                            "duplicate verdict for batch seq {}",
                            h.seq()
                        ))));
                    }
                    *seen = true;
                    self.pending = self.pending.saturating_sub(1);
                    if errno != 0 {
                        self.record(position, h.seq(), errno);
                    }
                }
            }
        }
        if self.pending > 0 {
            return Ok(Progress::Pending);
        }
        if self.failures.is_empty() {
            Ok(Progress::Done(NftBatchAck {
                begin_seq: self.begin_seq,
                end_seq: self.end_seq,
                body_seqs: self.body_seqs.clone(),
            }))
        } else {
            Err(self.aborted())
        }
    }

    fn sorted_failures(&self) -> Vec<NftMessageFailure> {
        let mut v = self.failures.clone();
        v.sort_by_key(|f| f.position);
        v
    }

    /// カーネルが失敗を返した場合のエラー（outcome は `Aborted`）。
    fn aborted(&self) -> NftBatchError {
        let failures = self.sorted_failures();
        let (code, message) = match failures.first() {
            Some(first) => (
                first.code,
                format!(
                    "nf_tables batch rejected: {} message failure(s), first at {} (seq {}, errno {})",
                    failures.len(),
                    first.position,
                    first.seq,
                    first.errno
                ),
            ),
            None => (
                NetErrorCode::Internal,
                "nf_tables batch rejected".to_string(),
            ),
        };
        NftBatchError {
            error: NetError::new(code, message),
            outcome: NftBatchOutcome::Aborted,
            failures,
        }
    }

    /// 適用されたか不明なエラー（outcome は `Unknown`）。これまでに集めた失敗を添える。
    pub(crate) fn unknown(&self, error: NetError) -> NftBatchError {
        NftBatchError {
            error,
            outcome: NftBatchOutcome::Unknown,
            failures: self.sorted_failures(),
        }
    }

    /// 期限内に判定が揃わなかった場合のエラー（`Timeout`・`Unknown`。REPAIR-5）。
    pub(crate) fn timeout_error(&self, total: Duration) -> NftBatchError {
        let received = self.body_seqs.len().saturating_sub(self.pending);
        self.unknown(NetError::new(
            NetErrorCode::Timeout,
            format!(
                "no complete reply for nf_tables batch (seq {}..={}) within {} ms; {} of {} body verdicts received",
                self.begin_seq,
                self.end_seq,
                total.as_millis(),
                received,
                self.body_seqs.len()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{NLM_F_ACK, NLM_F_REQUEST, NlMsgBuilder};
    use crate::nftables_batch::{
        NFNL_SUBSYS_NFTABLES, NFPROTO_INET, NfGenMsg, NftBatch, nfnl_msg_type,
    };

    const NEWTABLE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, 0);

    fn push_body(b: &mut NftBatch) {
        b.push_with(|seq| {
            let mut m = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
            NfGenMsg::new(NFPROTO_INET, 0).put_into(&mut m)?;
            Ok(m)
        })
        .expect("push");
    }

    /// 本体 `n` 件・begin_seq 100 のバッチ（begin=100, 本体=101.., end=101+n）。
    fn batch(n: usize) -> NftBatchBytes {
        let mut b = NftBatch::new(100).expect("new");
        for _ in 0..n {
            push_body(&mut b);
        }
        b.finish().expect("finish")
    }

    /// `NLMSG_ERROR` のデータグラム（errno は正値で渡す。`inner_seq` は埋め込む元ヘッダの seq）。
    fn err_dgram(seq: u32, errno: i32, inner_seq: u32) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(NLMSG_ERROR, 0, seq, 0);
        let mut p = Vec::new();
        p.extend_from_slice(&(-errno).to_ne_bytes());
        p.extend_from_slice(&[0u8; 8]);
        p.extend_from_slice(&inner_seq.to_ne_bytes());
        p.extend_from_slice(&[0u8; 4]);
        b.put_fixed(&p).expect("payload");
        b.finish().expect("finish")
    }

    fn ok(seq: u32) -> Vec<u8> {
        err_dgram(seq, 0, seq)
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    fn fail(index: usize, seq: u32, errno: i32) -> NftMessageFailure {
        NftMessageFailure {
            position: NftBatchPosition::Body { index },
            seq,
            errno,
            code: classify_errno(errno),
        }
    }

    /// NET-11: 本体 3 件すべて errno 0 なら成功で seq と件数を返す。
    #[test]
    fn net11_all_acks_succeed() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let p = c.feed(&cat(&[ok(101), ok(102), ok(103)])).expect("feed");
        assert_eq!(
            p,
            Progress::Done(NftBatchAck {
                begin_seq: 100,
                end_seq: 104,
                body_seqs: vec![101, 102, 103],
            })
        );
    }

    /// NET-11: 応答が複数データグラムに分かれても、揃うまで Pending。
    #[test]
    fn net11_verdicts_across_datagrams() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Pending);
        assert!(matches!(c.feed(&ok(102)), Ok(Progress::Done(_))));
    }

    /// NET-11: 3 件中 index 1 が EEXIST。失敗メッセージを特定し outcome は Aborted。
    #[test]
    fn net11_partial_failure_identifies_message() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let e = c
            .feed(&cat(&[ok(101), err_dgram(102, 17, 102), ok(103)]))
            .expect_err("failure");
        assert_eq!(e.failures(), &[fail(1, 102, 17)][..]);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(
            e.message(),
            "nf_tables batch rejected: 1 message failure(s), first at body[1] (seq 102, errno 17)"
        );
    }

    /// NET-11: 複数の失敗は添字順にすべて並び、先頭の分類が code になる。
    #[test]
    fn net11_multiple_failures_are_all_listed() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let e = c
            .feed(&cat(&[
                err_dgram(103, 22, 103),
                err_dgram(101, 2, 101),
                ok(102),
            ]))
            .expect_err("failure");
        assert_eq!(e.failures(), &[fail(0, 101, 2), fail(2, 103, 22)][..]);
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: BEGIN への EPERM はバッチ全体の失敗として即座に確定する（後続を読まない）。
    #[test]
    fn net11_begin_eperm_is_batch_level() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        let e = c
            .feed(&cat(&[err_dgram(100, 1, 100), ok(101)]))
            .expect_err("eperm");
        assert_eq!(
            e.failures(),
            &[NftMessageFailure {
                position: NftBatchPosition::Begin,
                seq: 100,
                errno: 1,
                code: NetErrorCode::PermissionDenied,
            }][..]
        );
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: END への非 0 errno も位置 End として確定する。
    #[test]
    fn net11_end_error_is_batch_level() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c.feed(&err_dgram(102, 12, 102)).expect_err("end failure");
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.errno(), f.code()))
                .collect::<Vec<_>>(),
            vec![(NftBatchPosition::End, 12, NetErrorCode::ResourceExhausted)]
        );
    }

    /// NET-11: BEGIN / END への errno 0 の ACK は無視する（DataLoss にしない）。
    #[test]
    fn marker_ack_is_tolerated() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let p = c.feed(&cat(&[ok(100), ok(101), ok(102)])).expect("feed");
        assert!(matches!(p, Progress::Done(_)));
    }

    /// NET-11: 範囲外の seq（以前のバッチの遅延応答）は破棄して続行する。
    #[test]
    fn net11_stale_seq_is_discarded() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        assert_eq!(
            c.feed(&cat(&[err_dgram(50, 17, 50), ok(99), ok(105)]))
                .expect("feed"),
            Progress::Pending
        );
        assert!(matches!(c.feed(&ok(101)), Ok(Progress::Done(_))));
    }

    /// NET-11: 同じ本体 seq への 2 回目の判定は DataLoss / Unknown。
    #[test]
    fn duplicate_verdict_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        let e = c.feed(&cat(&[ok(101), ok(101)])).expect_err("dup");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 埋め込まれた元要求の seq がヘッダと食い違えば DataLoss。
    #[test]
    fn embedded_seq_mismatch_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c.feed(&err_dgram(101, 0, 999)).expect_err("mismatch");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 範囲内の seq を持つ NLMSG_ERROR 以外（NOOP を除く）は DataLoss。
    #[test]
    fn unexpected_message_type_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let noop = NlMsgBuilder::new(NLMSG_NOOP, 0, 101, 0)
            .finish()
            .expect("finish");
        assert_eq!(c.feed(&noop).expect("noop"), Progress::Pending);
        let mut b = NlMsgBuilder::new(NEWTABLE, 0, 101, 0);
        b.put_fixed(&[0u8; 4]).expect("payload");
        let e = c.feed(&b.finish().expect("finish")).expect_err("type");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 壊れたフレームは DataLoss / Unknown（panic しない）。
    #[test]
    fn malformed_frame_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c.feed(&[1, 2, 3, 4, 5]).expect_err("malformed");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// REPAIR-5: 時間切れエラーは Timeout / Unknown で、集めた件数と失敗を添える。
    #[test]
    fn repair5_timeout_error_reports_progress() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        c.feed(&cat(&[err_dgram(101, 17, 101), ok(102)]))
            .expect("pending");
        let e = c.timeout_error(Duration::from_millis(1500));
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.failures(), &[fail(0, 101, 17)][..]);
        assert_eq!(
            e.message(),
            "no complete reply for nf_tables batch (seq 100..=104) within 1500 ms; 2 of 3 body verdicts received"
        );
    }

    /// NET-11: NftBatchError は NetError へ変換でき、Display に入力名を含まない。
    #[test]
    fn batch_error_converts_to_net_error() {
        let e = NftBatchError::not_sent(NetError::new(NetErrorCode::InvalidArgument, "empty"));
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
        assert!(e.failures().is_empty());
        assert_eq!(e.to_string(), "INVALID_ARGUMENT: empty");
        let n: NetError = e.into();
        assert_eq!(n.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-11: seq が u32 を一周するバッチでも位置を特定できる。
    #[test]
    fn locate_handles_seq_wraparound() {
        let mut b = NftBatch::new(u32::MAX - 1).expect("new");
        for _ in 0..3 {
            push_body(&mut b);
        }
        let bytes = b.finish().expect("finish");
        assert_eq!(bytes.body_seqs(), &[u32::MAX, 0, 1][..]);
        let c = NftBatchAckCollector::new(&bytes);
        assert_eq!(c.locate(u32::MAX - 1), Some(NftBatchPosition::Begin));
        assert_eq!(c.locate(0), Some(NftBatchPosition::Body { index: 1 }));
        assert_eq!(c.locate(2), Some(NftBatchPosition::End));
        assert_eq!(c.locate(3), None);
    }
}
