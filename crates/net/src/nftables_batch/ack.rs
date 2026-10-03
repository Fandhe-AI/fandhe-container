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
//! - 権限不足（`CAP_NET_ADMIN` なし）の `-EPERM` や `-ENOMEM`・commit の失敗はバッチ先頭（BEGIN）の seq に
//!   対して返る。BEGIN / END の非 0 errno は [`NftBatchPosition::Begin`] / [`NftBatchPosition::End`] として
//!   記録し、バッチ全体の失敗なので本体の判定が揃っていなくても「判定済み」（[`Progress::Decided`]）にする。
//!   ただし即座には確定せず、本体の失敗と同じく同期点まで読み、同じデータグラムの後続や別データグラムの
//!   失敗も `failures()` に集める（失敗の全件返却。NET-11）
//! - BEGIN / END への errno 0 の ACK は許容して無視する（カーネル版数で返る場合がある）
//! - 判定済みの条件は「本体の全 seq に判定が揃う」または「BEGIN / END が失敗した」。END は `NLM_F_ACK` を
//!   持たず成功時は無応答のため待てないが、失敗（非 0 errno）が別データグラムで届き得る。そこで判定後に
//!   同期点（nf_tables の `NFT_MSG_GETGEN` + `NLM_F_ACK` の別要求）を送り、その応答が届くまで読む
//!   （`socket::drain_until_barrier`）。応答は FIFO のため、同期点への応答より前の応答はすべて `feed` 済みに
//!   なり、[`NftBatchAckCollector::conclude`] で最終判定する。時間の経過で「終わり」と推定しない
//! - 同期点への応答は `NFT_MSG_NEWGEN`（同じ seq）→ errno 0 の `NLMSG_ERROR` の順に届く
//!   （`nf_tables_getgen` が NEWGEN を unicast してから 0 を返し、`netlink_rcv_skb` が ACK を積む）。
//!   NEWGEN を受けずに届いた errno 0 の ACK は GETGEN が実行された証拠にならないので `DataLoss`、
//!   同期点の seq を持つそれ以外の type も `DataLoss` にする（カーネル応答の境界検査）
//! - 同期点が非 0 errno で拒否された場合（権限不足のバッチでは同期点も `EPERM`）も、その応答はバッチより後に
//!   処理された要求への応答なので読み切りの印になる。失敗を集めていれば `Aborted`、なければ適用状態を
//!   確認できないので `Unknown` にする
//!
//! # 未実装範囲（REPAIR-3）
//!
//! extended ACK（`NETLINK_EXT_ACK`）の解釈と、`NFTA_GEN_ID` による楽観的並行制御は未実装。

use std::fmt;
use std::time::Duration;

use super::NftBatchOutcome;
use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLMSG_ERROR, NLMSG_NOOP, NlMsgIter};
use crate::netlink_route::{classify_errno, decode_nlmsgerr};
use crate::nftables_batch::{NFNL_SUBSYS_NFTABLES, NftBatchBytes, nfnl_msg_type};

/// nf_tables の世代番号の照会（`linux/netfilter/nf_tables.h` の `NFT_MSG_GETGEN`）。同期点に使う。
pub(crate) const NFT_MSG_GETGEN: u8 = 16;
/// `NFT_MSG_GETGEN` への応答（`NFT_MSG_NEWGEN`）。
pub(crate) const NFT_MSG_NEWGEN: u8 = 15;
/// 同期点への応答 `NFT_MSG_NEWGEN` の `nlmsg_type`（0x0A0F）。
const NEWGEN_TYPE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWGEN);

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// 判定が揃っていない。次のデータグラムを待つ。
    Pending,
    /// 本体の全 seq の判定が揃った、または BEGIN / END が失敗した。成功・失敗はまだ確定せず、
    /// 同期点への応答まで読んでから [`NftBatchAckCollector::conclude`] で確定する。
    Decided,
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
    /// BEGIN / END の非 0 errno を受けたか（本体の判定を待たずに判定済みにする）。
    marker_failed: bool,
    /// 判定後に送る同期点（`NFT_MSG_GETGEN` + `NLM_F_ACK`）の seq と、その応答 NEWGEN を受けたか。
    barrier_seq: Option<u32>,
    barrier_gen_seen: bool,
    /// 同期点への `NLMSG_ERROR` の errno（`Some(0)` は成功の ACK）。`Some` になれば読み切りの印。
    barrier_reply: Option<i32>,
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
            marker_failed: false,
            barrier_seq: None,
            barrier_gen_seen: false,
            barrier_reply: None,
        }
    }

    /// 同期点の seq を登録する。カーネルは送信ごとに全応答を積み終えてから戻り、応答は FIFO で届くため、
    /// 後続の同期点への応答が届けば、それより前（END の失敗を含む）の応答はすべて `feed` 済みになる。
    pub(crate) fn set_barrier(&mut self, seq: u32) {
        self.barrier_seq = Some(seq);
        self.barrier_gen_seen = false;
        self.barrier_reply = None;
    }

    /// 同期点への応答（`NLMSG_ERROR`。成功・失敗を問わない）を受け、読み切りが完了したか。
    pub(crate) fn barrier_reached(&self) -> bool {
        self.barrier_reply.is_some()
    }

    /// 同期点への応答の errno（未着は `None`、成功の ACK は `Some(0)`）。判定は `conclude` が行うため試験用。
    #[cfg(test)]
    pub(crate) fn barrier_reply(&self) -> Option<i32> {
        self.barrier_reply
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
            if self.barrier_seq == Some(h.seq()) {
                self.feed_barrier(h.msg_type(), h.seq(), msg.payload())?;
                continue;
            }
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
                        if self.failures.iter().any(|f| f.position == position) {
                            return Err(self.unknown(data_loss(format!(
                                "duplicate verdict for batch seq {}",
                                h.seq()
                            ))));
                        }
                        // バッチ全体の失敗。本体の判定を待たずに判定済みにするが、後続の失敗も集めるため
                        // ここでは確定しない（同期点まで読む）。
                        self.record(position, h.seq(), errno);
                        self.marker_failed = true;
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
        if self.pending > 0 && !self.marker_failed {
            return Ok(Progress::Pending);
        }
        Ok(Progress::Decided)
    }

    /// 同期点への応答まで読んだ後の最終判定（NET-11）。
    ///
    /// - 同期点への応答が未着: 読み切れていないので `Internal`（`Unknown`。呼び出し側の誤用の防御）
    /// - 失敗を 1 件以上集めた: 全件を並べて `Aborted`（同期点への応答の errno によらない）
    /// - 同期点が非 0 errno: 適用状態を確認できないので `Unknown`
    /// - 本体の判定が欠けている: `Internal`（`Unknown`。判定済みの条件から起こらない防御）
    /// - それ以外: 全本体が errno 0 で成功
    pub(crate) fn conclude(&self) -> Result<NftBatchAck, NftBatchError> {
        let Some(errno) = self.barrier_reply else {
            return Err(self.unknown(NetError::new(
                NetErrorCode::Internal,
                "nf_tables batch verdict concluded before the sync reply",
            )));
        };
        if !self.failures.is_empty() {
            return Err(self.aborted());
        }
        if errno != 0 {
            return Err(self.unknown(NetError::new(
                classify_errno(errno),
                format!("sync request failed with errno {errno}"),
            )));
        }
        if self.pending > 0 {
            return Err(self.unknown(NetError::new(
                NetErrorCode::Internal,
                format!(
                    "nf_tables batch concluded with {} of {} body verdicts missing",
                    self.pending,
                    self.body_seqs.len()
                ),
            )));
        }
        Ok(NftBatchAck {
            begin_seq: self.begin_seq,
            end_seq: self.end_seq,
            body_seqs: self.body_seqs.clone(),
        })
    }

    /// 同期点の seq を持つ 1 メッセージを判定する（応答は NEWGEN → errno 0 の ACK の順）。
    ///
    /// errno 0 の ACK は、先に NEWGEN を受けていた場合だけ同期点の完了とする。GETGEN の応答を積めなかった
    /// 場合は `nf_tables_getgen` がエラーを返し ACK が非 0 errno になるため、NEWGEN なしの errno 0 は
    /// 想定外の応答として扱う。非 0 errno は読み切りの印として記録し、判定は [`Self::conclude`] に委ねる。
    fn feed_barrier(
        &mut self,
        msg_type: u16,
        seq: u32,
        payload: &[u8],
    ) -> Result<(), NftBatchError> {
        match msg_type {
            NEWGEN_TYPE => {
                self.barrier_gen_seen = true;
                Ok(())
            }
            NLMSG_NOOP => Ok(()),
            NLMSG_ERROR => {
                let ack = decode_nlmsgerr(payload).map_err(|e| self.unknown(e))?;
                if ack.request_seq().is_some_and(|s| s != seq) {
                    return Err(self.unknown(data_loss(format!(
                        "sync ack for seq {seq} embeds a different request seq"
                    ))));
                }
                if ack.errno() == 0 && !self.barrier_gen_seen {
                    return Err(self.unknown(data_loss(format!(
                        "sync ack for seq {seq} arrived without a generation reply"
                    ))));
                }
                self.barrier_reply = Some(ack.errno());
                Ok(())
            }
            other => Err(self.unknown(data_loss(format!(
                "unexpected netlink message type {other} for sync seq {seq}"
            )))),
        }
    }

    fn sorted_failures(&self) -> Vec<NftMessageFailure> {
        let mut v = self.failures.clone();
        v.sort_by_key(|f| f.position);
        v
    }

    /// カーネルが失敗を返した場合のエラー（outcome は `Aborted`）。
    pub(crate) fn aborted(&self) -> NftBatchError {
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

    /// 同期点 `seq` を登録し、NEWGEN → errno `errno` の応答を与えて読み切りを完了させる。
    fn reach_barrier(c: &mut NftBatchAckCollector, seq: u32, errno: i32) {
        c.set_barrier(seq);
        c.feed(&cat(&[newgen(seq), err_dgram(seq, errno, seq)]))
            .expect("barrier reply");
        assert_eq!(c.barrier_reply(), Some(errno));
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
        assert_eq!(p, Progress::Decided);
        reach_barrier(&mut c, 105, 0);
        assert_eq!(
            c.conclude(),
            Ok(NftBatchAck {
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
        assert_eq!(c.feed(&ok(102)).expect("feed"), Progress::Decided);
    }

    /// NET-11: 3 件中 index 1 が EEXIST。失敗メッセージを特定し outcome は Aborted。
    #[test]
    fn net11_partial_failure_identifies_message() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let p = c
            .feed(&cat(&[ok(101), err_dgram(102, 17, 102), ok(103)]))
            .expect("decided");
        assert_eq!(p, Progress::Decided);
        reach_barrier(&mut c, 105, 0);
        let e = c.conclude().expect_err("aborted");
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
        let p = c
            .feed(&cat(&[
                err_dgram(103, 22, 103),
                err_dgram(101, 2, 101),
                ok(102),
            ]))
            .expect("decided");
        assert_eq!(p, Progress::Decided);
        let e = c.aborted();
        assert_eq!(e.failures(), &[fail(0, 101, 2), fail(2, 103, 22)][..]);
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: 失敗を含んで判定が揃っても即確定せず、後続データグラムの失敗も `aborted` に含まれる。
    #[test]
    fn net11_failure_in_later_datagram_is_collected_after_failed() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(
            c.feed(&err_dgram(101, 17, 101)).expect("pending"),
            Progress::Pending
        );
        assert_eq!(c.feed(&ok(102)).expect("decided"), Progress::Decided);
        // 判定済みの後に届く END の失敗も記録し、同期点まで読んでから確定する（先の失敗も保持する）。
        assert_eq!(
            c.feed(&err_dgram(103, 12, 103)).expect("end failure"),
            Progress::Decided
        );
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![
                (NftBatchPosition::Body { index: 0 }, 101, 17),
                (NftBatchPosition::End, 103, 12)
            ]
        );
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: BEGIN への EPERM はバッチ全体の失敗で、本体の判定を待たずに判定済みになる。権限不足では
    /// 同期点も EPERM で拒否されるが、読み切りの印として扱い Aborted で確定する。
    #[test]
    fn net11_begin_eperm_is_batch_level() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(
            c.feed(&err_dgram(100, 1, 100)).expect("eperm"),
            Progress::Decided
        );
        c.set_barrier(104);
        c.feed(&err_dgram(104, 1, 104)).expect("sync eperm");
        assert!(c.barrier_reached());
        let e = c.conclude().expect_err("aborted");
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

    /// NET-11: END への非 0 errno も位置 End として記録し、本体の判定を待たずに判定済みになる。
    #[test]
    fn net11_end_error_is_batch_level() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        assert_eq!(
            c.feed(&err_dgram(102, 12, 102)).expect("end failure"),
            Progress::Decided
        );
        let e = c.aborted();
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
        assert_eq!(p, Progress::Decided);
        reach_barrier(&mut c, 103, 0);
        assert!(c.conclude().is_ok());
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
        assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Decided);
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

    /// 同期点への応答 `NFT_MSG_NEWGEN`（type 0x0A0F。属性は省略）。
    fn newgen(seq: u32) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0x0A0F, 0, seq, 0);
        b.put_fixed(&[0, 0, 0, 0]).expect("nfgenmsg");
        b.finish().expect("finish")
    }

    /// NET-11: 同期点の応答は NEWGEN（0x0A0F）→ errno 0 の ACK の順で完了する。NEWGEN だけでは未完了。
    #[test]
    fn net11_barrier_completes_after_newgen_then_ack() {
        assert_eq!(NEWGEN_TYPE, 0x0A0F);
        let mut c = NftBatchAckCollector::new(&batch(1));
        assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Decided);
        c.set_barrier(103);
        assert_eq!(c.feed(&newgen(103)).expect("newgen"), Progress::Decided);
        assert!(!c.barrier_reached());
        assert_eq!(c.feed(&ok(103)).expect("ack"), Progress::Decided);
        assert_eq!(c.barrier_reply(), Some(0));
        assert_eq!(c.conclude().expect("ok").body_seqs(), &[101][..]);
    }

    /// NET-11: NEWGEN を受けずに届いた同期点の errno 0 の ACK は DataLoss / Unknown（完了にしない）。
    #[test]
    fn net11_barrier_ack_without_newgen_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        let e = c.feed(&ok(103)).expect_err("no newgen");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(
            e.message(),
            "sync ack for seq 103 arrived without a generation reply"
        );
        assert!(!c.barrier_reached());
    }

    /// NET-11: 同期点の seq を持つ NEWGEN・NOOP・NLMSG_ERROR 以外の type は DataLoss / Unknown。
    #[test]
    fn net11_unexpected_type_for_barrier_seq_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        let noop = NlMsgBuilder::new(NLMSG_NOOP, 0, 103, 0)
            .finish()
            .expect("finish");
        assert_eq!(c.feed(&noop).expect("noop"), Progress::Pending);
        let mut b = NlMsgBuilder::new(NEWTABLE, 0, 103, 0);
        b.put_fixed(&[0u8; 4]).expect("payload");
        let e = c.feed(&b.finish().expect("finish")).expect_err("type");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(
            e.message(),
            "unexpected netlink message type 2560 for sync seq 103"
        );
        assert!(!c.barrier_reached());
    }

    /// NET-11: 失敗のないバッチで同期点が EPERM で拒否されたら成功にせず PermissionDenied / Unknown。
    #[test]
    fn net11_barrier_errno_is_unknown() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.feed(&ok(101)).expect("body");
        reach_barrier(&mut c, 103, 1);
        let e = c.conclude().expect_err("eperm");
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.message(), "sync request failed with errno 1");
    }

    /// NET-11: END の失敗の後に同じデータグラムで届く本体の失敗も集める（END で打ち切らない）。
    #[test]
    fn net11_end_failure_does_not_stop_collecting_same_datagram() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(
            c.feed(&cat(&[
                err_dgram(103, 12, 103),
                err_dgram(102, 17, 102),
                ok(101)
            ]))
            .expect("decided"),
            Progress::Decided
        );
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![
                (NftBatchPosition::Body { index: 1 }, 102, 17),
                (NftBatchPosition::End, 103, 12)
            ]
        );
        assert_eq!(
            e.message(),
            "nf_tables batch rejected: 2 message failure(s), first at body[1] (seq 102, errno 17)"
        );
    }

    /// NET-11: 同じ BEGIN / END への 2 回目の失敗は DataLoss / Unknown（集めた失敗は添える）。
    #[test]
    fn net11_duplicate_marker_failure_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c
            .feed(&cat(&[err_dgram(100, 1, 100), err_dgram(100, 1, 100)]))
            .expect_err("dup");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.message(), "duplicate verdict for batch seq 100");
        assert_eq!(e.failures().len(), 1);
    }

    /// NET-11: 同期点への応答が未着のまま conclude しても成功にせず Internal / Unknown。
    #[test]
    fn net11_conclude_before_sync_reply_is_unknown() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.feed(&ok(101)).expect("body");
        let e = c.conclude().expect_err("not reached");
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        c.set_barrier(103);
        c.feed(&newgen(103)).expect("newgen");
        let e = c.conclude().expect_err("newgen only");
        assert_eq!(e.code(), NetErrorCode::Internal);
    }

    /// NET-11: 失敗を集めた後の同期点の拒否は読み切りの印として扱い、Aborted で確定する。
    #[test]
    fn net11_barrier_errno_after_failure_is_aborted() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.feed(&err_dgram(101, 17, 101)).expect("body failure");
        reach_barrier(&mut c, 103, 12);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(e.failures(), &[fail(0, 101, 17)][..]);
    }

    /// NET-11: 同期点 ACK が別の要求 seq を埋め込んでいれば成功にせず DataLoss（Unknown）にする。
    #[test]
    fn net11_barrier_ack_with_mismatched_inner_seq_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        let e = c.feed(&err_dgram(103, 0, 999)).expect_err("mismatch");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert!(!c.barrier_reached());
    }
}
