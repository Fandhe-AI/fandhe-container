//! `NETLINK_NETFILTER` ソケットでの nf_tables バッチ送信と ACK / エラー判定（TASK-137.3・NET-11・
//! REPAIR-5・MS-8・#306。Linux のみ）。
//!
//! `NftBatch`（#304・#305）が組み立てた閉じたバッチを 1 データグラムで送り、本体メッセージごとの
//! ACK / `NLMSG_ERROR` を [`NftBatchAckCollector`] で判定する。往復全体を 1 つの期限で覆い、無応答で
//! ハングしない（REPAIR-5）。
//!
//! # 構成と責務境界
//!
//! - ソケットの open / bind / send / recv は `NetlinkRouteSocket`（TASK-136.2。protocol だけ
//!   `NETLINK_NETFILTER` に差し替えて再利用）が担い、本型は seq の採番・往復の直列化・期限の管理だけを持つ。
//!   rtnetlink 固有の往復（dump / DONE の終端規則）は公開しない
//! - 判定ロジックは `ack` の状態機械。ここは「`recv(残り時間)` → `feed`」を繰り返す薄いループ
//! - seq はソケットが所有する（呼び出し側は指定できない）。以前に時間切れしたバッチの遅延応答は
//!   `[begin_seq..=end_seq]` の外になり、衝突しない。マルチキャストは購読しない
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - `SO_SNDBUF` / `SO_RCVBUF` の調整。送信できる長さはソケットの既定 `SO_SNDBUF`（sysctl 依存で約 212 KB）
//!   で決まり、超えると `EMSGSIZE` を `ResourceExhausted`（`NotSent`）で返す。ACK が大量で受信バッファが
//!   あふれた場合（`ENOBUFS`）も待ち続けず `ResourceExhausted`（`Unknown`）で返す（fail-closed）
//! - extended ACK と `NFTA_GEN_ID` による楽観的並行制御
//! - route ソケットとの共通コア（`NetlinkSocketCore` 等）の切り出し

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::ack::{NFT_MSG_GETGEN, NftBatchAck, NftBatchAckCollector, NftBatchError, Progress};
use super::{
    BATCH_MARKER_LEN, MAX_BATCH_LEN, NFNL_SUBSYS_NFTABLES, NFPROTO_UNSPEC, NfGenMsg, NftBatch,
    NftBatchBytes, nfnl_msg_type,
};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};
use crate::netlink::{NLM_F_ACK, NLM_F_REQUEST, NlMsgBuilder};
use crate::netlink_route::{NetlinkRouteSocket, RequestGate};
use crate::sys::Deadline;

/// bind 済みの `NETLINK_NETFILTER` ソケット（NET-11）。
///
/// `Send + Sync` で、バッチの往復は内部で 1 件ずつに直列化する。fd は `SOCK_CLOEXEC` で、Drop で閉じる。
/// 内部実装は `NetlinkRouteSocket` の再利用（型名と実体のずれは本モジュール doc の未実装範囲を参照）。
#[derive(Debug)]
pub struct NetlinkNetfilterSocket {
    inner: NetlinkRouteSocket,
    gate: RequestGate,
    /// 次のバッチの BEGIN の seq（0 は使わない）。`gate` 保持中だけ読み書きする。
    next_seq: AtomicU32,
}

/// `end_seq` の次に使う seq（0 は飛ばす）。
fn seq_after(end_seq: u32) -> u32 {
    match end_seq.wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

/// 1 バッチが消費し得る seq 数の上限（BEGIN + 本体 + END + 同期点）。
///
/// 本体メッセージは最小でも `BATCH_MARKER_LEN`（nlmsghdr + nfgenmsg = 20 バイト）あり、バッチ全体は
/// `MAX_BATCH_LEN` で打ち切られるため、これを超える seq は使わない。
const MAX_SEQ_PER_BATCH: u32 = (MAX_BATCH_LEN / BATCH_MARKER_LEN) as u32 + 3;

/// 組み立て前に、残りの seq 空間が最大バッチを収容できなければ 1 から採番し直す（NET-11）。
///
/// `NftBatch` は seq を `wrapping_add` で進めるため、バッチ内で `u32::MAX` を越えると本体または END の
/// `nlmsg_seq` が 0 になる。0 は非要求メッセージにも使われ応答の対応付けが曖昧になるので、
/// 周回しうる位置では先に 1 へ戻して、バッチ内に 0 を含めない。
fn reserve_first_seq(next_seq: u32) -> u32 {
    if next_seq == 0 || next_seq > u32::MAX - MAX_SEQ_PER_BATCH {
        1
    } else {
        next_seq
    }
}

fn timeout_not_sent(msg: String) -> NftBatchError {
    NftBatchError::not_sent(NetError::new(NetErrorCode::Timeout, msg))
}

/// 閉じたバッチを `send` で送り、`recv` で ACK / エラーを期限内に集める（判定の本体）。
///
/// `send` / `recv` は本番では `NetlinkNetfilterSocket` のもの、単体試験では決定的な偽物。
/// 期限後に届いた応答は成功・エラーを問わず `Timeout`（`Unknown`）に揃える（REPAIR-5）。
fn exchange(
    batch: &NftBatchBytes,
    deadline: &Deadline,
    total: Duration,
    send: impl FnOnce(&NftBatchBytes) -> Result<(), NetError>,
    send_barrier: impl FnOnce(&[u8]) -> Result<(), NetError>,
    mut recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
) -> Result<NftBatchAck, NftBatchError> {
    // 本体が無いと成功 ACK が 1 件も返らず、成功を確認できない（fail-closed）。
    if batch.body_seqs().is_empty() {
        return Err(NftBatchError::not_sent(NetError::new(
            NetErrorCode::InvalidArgument,
            "nf_tables batch has no body message",
        )));
    }
    if deadline.remaining().is_zero() {
        return Err(timeout_not_sent(format!(
            "nf_tables batch not sent: deadline of {} ms passed",
            total.as_millis()
        )));
    }
    let mut collector = NftBatchAckCollector::new(batch);
    if let Err(e) = send(batch) {
        // 部分送信（DataLoss）は一部がカーネルへ渡った可能性があるので適用状態は不明。
        return Err(if e.code() == NetErrorCode::DataLoss {
            NftBatchError::unknown_outcome(e)
        } else {
            NftBatchError::not_sent(e)
        });
    }
    loop {
        let data = match recv(deadline.remaining()) {
            Ok(d) => d,
            Err(e) if e.code() == NetErrorCode::Timeout => {
                return Err(collector.timeout_error(total));
            }
            // ENOBUFS（ACK の取りこぼし）など。待ち続けない。
            Err(e) => return Err(collector.unknown(e)),
        };
        let result = collector.feed(&data);
        // 判定中に期限を過ぎた場合は、成功も失敗も Timeout に統一する。
        if deadline.remaining().is_zero() {
            return match result {
                Err(e) if e.code() == NetErrorCode::Timeout => Err(e),
                _ => Err(collector.timeout_error(total)),
            };
        }
        // 判定済みでも成功・失敗はまだ確定しない。同期点まで読み切って全応答を集めてから確定する。
        if result? == Progress::Pending {
            continue;
        }
        // 同期点の seq は END の次（呼び出し側が範囲を予約済み）。
        let barrier_seq = seq_after(batch.end_seq());
        collector.set_barrier(barrier_seq);
        let barrier = encode_barrier(barrier_seq).map_err(|e| collector.unknown(e))?;
        // 本体判定後の期限切れでは同期点を送らず、全体期限（REPAIR-5）を超えて送信しない。
        if deadline.remaining().is_zero() {
            return Err(collector.timeout_error(total));
        }
        // 送れなければ END の判定を確認できない（適用済みかも不明）。
        send_barrier(&barrier).map_err(|e| collector.unknown(e))?;
        drain_until_barrier(&mut collector, deadline, total, recv)?;
        return collector.conclude();
    }
}

/// 判定済み（本体の判定が揃った、または BEGIN / END の失敗）の後、同期点への応答が届くまで読み、
/// END の判定と後続の失敗を確実に集める。
///
/// END は `NLM_F_ACK` を持たず成功時は無応答で、失敗（非 0 errno）は本体の ACK と別のデータグラムで
/// 届き得る。静止窓のような時間による推定では取りこぼし得るため、判定後に別要求の同期点
/// （[`encode_barrier`] の `NFT_MSG_GETGEN` + `NLM_F_ACK`）を送り、その応答（`NLMSG_ERROR`。errno 0 の
/// ACK でも拒否でもよい）を完了条件にする。最終判定は呼び出し側が `conclude` で行う。
/// 応答は FIFO なので、同期点への応答より前に積まれた END の失敗は必ず先に `feed` される（NET-11）。
/// 同期点の応答は NEWGEN と ACK の 2 データグラムになるため、1 データグラムで終わると仮定しない。
///
/// 全体期限（REPAIR-5）を `deadline` で共有し、期限切れ・確認不能は `Unknown` にする。上限
/// （[`MAX_TRAILING_DATAGRAMS`]）まで読んでも同期点への応答が来なければ `ResourceExhausted`（`Unknown`）。
fn drain_until_barrier(
    collector: &mut NftBatchAckCollector,
    deadline: &Deadline,
    total: Duration,
    mut recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
) -> Result<(), NftBatchError> {
    for _ in 0..MAX_TRAILING_DATAGRAMS {
        if collector.barrier_reached() {
            return Ok(());
        }
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(collector.timeout_error(total));
        }
        match recv(remaining) {
            Ok(data) => {
                let result = collector.feed(&data);
                // 受信・解析中に期限を過ぎた場合は、同期点の ACK 済みでも成功にしない（REPAIR-5）。
                if deadline.remaining().is_zero() {
                    return Err(collector.timeout_error(total));
                }
                result?;
            }
            Err(e) if e.code() == NetErrorCode::Timeout => {
                return Err(collector.timeout_error(total));
            }
            Err(e) => return Err(collector.unknown(e)),
        }
    }
    if collector.barrier_reached() {
        return Ok(());
    }
    Err(collector.unknown(NetError::new(
        NetErrorCode::ResourceExhausted,
        format!(
            "no sync ack within {MAX_TRAILING_DATAGRAMS} trailing netlink datagrams after nf_tables batch verdicts"
        ),
    )))
}

/// 同期点（`NFT_MSG_GETGEN` + `NLM_F_REQUEST | NLM_F_ACK`、nfgenmsg は `NFPROTO_UNSPEC`・res_id 0。
/// 計 20 バイト）のバイト列を組み立てる（NET-11）。
///
/// nfnetlink が通常の要求として受理し、必ず ACK を返す要求を選ぶ。カーネル（`net/netfilter/nfnetlink.c`・
/// `nf_tables_api.c`）での経路と選定理由:
///
/// - `nfnetlink_rcv` は `CAP_NET_ADMIN` を検査し（なければ `-EPERM` の ACK。バッチの BEGIN と同じ扱い）、
///   `NFNL_MSG_BATCH_BEGIN` 以外を `netlink_rcv_skb(nfnetlink_rcv_msg)` へ渡す
/// - `nfnetlink_rcv_msg` は nf_tables サブシステムの `NFT_MSG_GETGEN` コールバック（`nf_tables_getgen`）を
///   呼び、これは同じ seq の `NFT_MSG_NEWGEN` を unicast して 0 を返す。続いて `netlink_rcv_skb` が
///   `NLM_F_ACK` に応じて errno 0 の `NLMSG_ERROR` を積む。NEWGEN を積めなければエラーが返り、ACK は
///   非 0 errno になる。nf_tables が未ロードでも非バッチ経路は `request_module` で読み込む
/// - nfnetlink への送信はカーネル内で同期的に処理され、送信が戻った時点で直前のバッチの応答は受信
///   キューに積まれている。よって後から送った同期点への応答は、バッチのすべての応答より後に届く
/// - `NLMSG_NOOP` は `NLMSG_MIN_TYPE` 未満の制御メッセージで nfnetlink の要求ではないため使わない。
///   BEGIN / END への `NLM_F_ACK` はカーネル版数によっては ACK されないため完了条件にできない
/// - GETGEN は読み取りのみの照会で、ルールセットを変更しない
fn encode_barrier(seq: u32) -> Result<Vec<u8>, NetError> {
    let mut b = NlMsgBuilder::new(
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETGEN),
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        0,
    );
    NfGenMsg::new(NFPROTO_UNSPEC, 0).put_into(&mut b)?;
    b.finish()
}

/// 判定後に読むデータグラム数の上限。
const MAX_TRAILING_DATAGRAMS: usize = 64;

impl NetlinkNetfilterSocket {
    /// ソケットを開いて bind する（計測結果は記録しない）。
    pub fn open() -> Result<Self, NetError> {
        Self::open_with_recorder(Arc::new(NoopNetOpRecorder))
    }

    /// ソケットを開いて bind し、以後の open / send / recv / バッチ往復の結果と所要時間を
    /// `recorder` へ渡す（REPAIR-4）。
    pub fn open_with_recorder(recorder: Arc<dyn NetOpRecorder>) -> Result<Self, NetError> {
        Ok(Self {
            inner: NetlinkRouteSocket::open_netfilter_with_recorder(recorder)?,
            gate: RequestGate::default(),
            next_seq: AtomicU32::new(1),
        })
    }

    /// バッチを組み立てて送り、本体メッセージごとの ACK / エラーが揃うまで待つ（NET-11・TASK-137.3）。
    ///
    /// `fill` が `NftBatch::push_with` で本体メッセージを積む。`timeout` は順番待ち・送信・応答待ちを
    /// 通した全体の期限で、超えれば `Timeout`（REPAIR-5）。`NetOpKind::NftBatch` として記録する。
    ///
    /// `fill` は呼び出し元のスレッドで同期的に実行され、本関数はその実行を中断できない。したがって
    /// `fill` は待機・I/O・ロック取得などで止まらない短い CPU 処理に限ること。`fill` から戻った時点で
    /// 期限が過ぎていれば何も送らず `Timeout`（`NotSent`）を返す（期限切れの組み立て結果は送信しない）。
    /// seq は組み立て前に確保し、残りの seq 空間が最大バッチに足りなければ 1 から採番し直す
    /// （バッチ内に seq 0 を含めない）。
    ///
    /// 戻り値の判定:
    /// - 成功: 本体のすべてが errno 0 で ACK された
    /// - カーネルの失敗: [`NftBatchError::failures`] に失敗したメッセージの位置・seq・errno を全件並べ、
    ///   outcome は `Aborted`。nf_tables のバッチは all-or-nothing で何も適用されておらず、他メッセージの
    ///   errno 0 の ACK は「適用済み」を意味しない
    /// - `Timeout` / `DataLoss` / `ResourceExhausted`（受信欠落）: outcome は `Unknown`。適用されたか不明
    ///   なので、呼び出し側が状態を再照会すること
    /// - 空バッチ・組み立て失敗・送信前の期限切れ・送信拒否（`EMSGSIZE` を含む）: outcome は `NotSent`
    pub fn send_batch(
        &self,
        timeout: Duration,
        fill: impl FnOnce(&mut NftBatch) -> Result<(), NetError>,
    ) -> Result<NftBatchAck, NftBatchError> {
        record_net_op(self.inner.recorder().as_ref(), NetOpKind::NftBatch, || {
            let deadline = Deadline::after(timeout);
            let _turn = self
                .gate
                .acquire(&deadline, timeout)
                .map_err(NftBatchError::not_sent)?;
            let first_seq = reserve_first_seq(self.next_seq.load(Ordering::Relaxed));
            let mut batch = NftBatch::new(first_seq).map_err(NftBatchError::not_sent)?;
            fill(&mut batch).map_err(NftBatchError::not_sent)?;
            let bytes = batch.finish().map_err(NftBatchError::not_sent)?;
            // 防御: 予約により起こらないはずだが、0 の seq を含むバッチは送らない。
            if bytes.begin_seq() == 0 || bytes.end_seq() == 0 || bytes.body_seqs().contains(&0) {
                return Err(NftBatchError::not_sent(NetError::new(
                    NetErrorCode::Internal,
                    "nf_tables batch contains a zero seq",
                )));
            }
            // 送る・送らないによらず今回の範囲は再利用しない（遅延応答との衝突を避ける）。
            self.next_seq
                .store(seq_after(seq_after(bytes.end_seq())), Ordering::Relaxed);
            exchange(
                &bytes,
                &deadline,
                timeout,
                |b| self.inner.send_batch_bytes(b),
                |m| self.inner.send(m),
                |t| self.inner.recv(t),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::NetOpOutcome;
    use crate::instrument::testing::Collect;
    use crate::netlink::{NLM_F_ACK, NLM_F_REQUEST, NLMSG_ERROR, NlMsgBuilder};
    use crate::nftables_batch::{
        NFNL_SUBSYS_NFTABLES, NFPROTO_INET, NfGenMsg, NftBatchOutcome, nfnl_msg_type,
    };

    const NEWTABLE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, 0);

    fn push_body(b: &mut NftBatch) -> Result<(), NetError> {
        b.push_with(|seq| {
            let mut m = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
            NfGenMsg::new(NFPROTO_INET, 0).put_into(&mut m)?;
            Ok(m)
        })
        .map(|_| ())
    }

    fn batch(n: usize) -> NftBatchBytes {
        let mut b = NftBatch::new(10).expect("new");
        for _ in 0..n {
            push_body(&mut b).expect("push");
        }
        b.finish().expect("finish")
    }

    fn err_dgram(seq: u32, errno: i32) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(NLMSG_ERROR, 0, seq, 0);
        let mut p = Vec::new();
        p.extend_from_slice(&(-errno).to_ne_bytes());
        p.extend_from_slice(&[0u8; 8]);
        p.extend_from_slice(&seq.to_ne_bytes());
        p.extend_from_slice(&[0u8; 4]);
        b.put_fixed(&p).expect("payload");
        b.finish().expect("finish")
    }

    /// 同期点への応答 `NFT_MSG_NEWGEN`（カーネルの `nf_tables_fill_gen_info` と同じ形。属性は省略）。
    fn gen_dgram(seq: u32) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(
            nfnl_msg_type(
                NFNL_SUBSYS_NFTABLES,
                crate::nftables_batch::ack::NFT_MSG_NEWGEN,
            ),
            0,
            seq,
            0,
        );
        NfGenMsg::new(NFPROTO_UNSPEC, 0)
            .put_into(&mut b)
            .expect("nfgenmsg");
        b.finish().expect("finish")
    }

    /// 同期点の期待バイト列（具体値）: nlmsghdr(len 20・type 0x0A10・flags REQUEST|ACK = 0x0005・seq・pid 0)
    /// + nfgenmsg(family 0・version 0・res_id 0)。数値フィールドはネイティブバイトオーダー。
    fn barrier_bytes(seq: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&20u32.to_ne_bytes());
        v.extend_from_slice(&0x0A10u16.to_ne_bytes());
        v.extend_from_slice(&0x0005u16.to_ne_bytes());
        v.extend_from_slice(&seq.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    /// 偽 recv: 順に返し、尽きたら Timeout。
    fn script(
        mut items: Vec<Result<Vec<u8>, NetError>>,
    ) -> impl FnMut(Duration) -> Result<Vec<u8>, NetError> {
        items.reverse();
        move |_| {
            items
                .pop()
                .unwrap_or_else(|| Err(NetError::new(NetErrorCode::Timeout, "none")))
        }
    }

    fn run(
        b: &NftBatchBytes,
        total: Duration,
        send: impl FnOnce(&NftBatchBytes) -> Result<(), NetError>,
        recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
    ) -> Result<NftBatchAck, NftBatchError> {
        exchange(b, &Deadline::after(total), total, send, |_| Ok(()), recv)
    }

    /// NET-11: 全 ACK で成功する。
    #[test]
    fn net11_exchange_succeeds_with_all_acks() {
        let b = batch(2);
        let ack = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok([err_dgram(11, 0), err_dgram(12, 0)].concat()),
                Ok(gen_dgram(14)),
                Ok(err_dgram(14, 0)),
            ]),
        )
        .expect("ok");
        assert_eq!(ack.body_seqs(), &[11, 12][..]);
    }

    /// NET-11: 本体の ACK が揃った後に別データグラムで届く END の非 0 errno を見逃さない。
    #[test]
    fn net11_end_error_in_later_datagram_is_not_success() {
        let b = batch(2);
        // 本体 seq 11,12 / END seq 13。
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok([err_dgram(11, 0), err_dgram(12, 0)].concat()),
                Ok(err_dgram(13, 12)),
                Ok(gen_dgram(14)),
                Ok(err_dgram(14, 0)),
            ]),
        )
        .expect_err("end failure");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(e.failures().len(), 1);
    }

    /// REPAIR-5: 無応答なら Timeout / Unknown（ハングしない）。
    #[test]
    fn repair5_silent_socket_times_out() {
        let b = batch(1);
        let e = run(&b, Duration::from_millis(50), |_| Ok(()), script(vec![])).expect_err("t");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 末尾の読み切りが上限に達したら成功にせず ResourceExhausted / Unknown。
    #[test]
    fn net11_trailing_cap_is_unknown_not_success() {
        let b = batch(1);
        let mut first = true;
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            move |_| {
                if std::mem::take(&mut first) {
                    Ok(err_dgram(11, 0))
                } else {
                    Ok(Vec::new())
                }
            },
        )
        .expect_err("cap");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 本体の失敗が判定済みでも、同期点まで読み切り、別データグラムの END の失敗も失敗一覧に含む。
    #[test]
    fn net11_failures_across_datagrams_are_all_collected() {
        let b = batch(2);
        // 本体 seq 11,12 / END seq 13 / 同期点 seq 14。
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok(err_dgram(11, 17)),
                Ok(err_dgram(12, 0)),
                Ok(err_dgram(13, 12)),
                Ok(gen_dgram(14)),
                Ok(err_dgram(14, 0)),
            ]),
        )
        .expect_err("failures");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.failures().len(), 2);
    }

    /// REPAIR-5: 同期点の ACK を解析中に期限を過ぎたら成功にせず Timeout / Unknown。
    #[test]
    fn repair5_deadline_expiry_while_receiving_sync_ack_is_timeout() {
        let b = batch(1);
        let mut n = 0;
        let e = run(
            &b,
            Duration::from_millis(40),
            |_| Ok(()),
            move |_| {
                n += 1;
                match n {
                    1 => Ok(err_dgram(11, 0)),
                    2 => Ok(gen_dgram(13)),
                    _ => {
                        std::thread::sleep(Duration::from_millis(60));
                        Ok(err_dgram(13, 0))
                    }
                }
            },
        )
        .expect_err("expired");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// REPAIR-5: 末尾の読み切り中に期限が切れたら Timeout / Unknown。
    #[test]
    fn repair5_deadline_expiry_during_trailing_is_timeout() {
        let b = batch(1);
        let mut first = true;
        let e = run(
            &b,
            Duration::from_millis(40),
            |_| Ok(()),
            move |_| {
                if std::mem::take(&mut first) {
                    Ok(err_dgram(11, 0))
                } else {
                    std::thread::sleep(Duration::from_millis(60));
                    Err(NetError::new(NetErrorCode::Timeout, "none"))
                }
            },
        )
        .expect_err("expired");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 同期点の ACK より前に届いた END の失敗は成功にしない（時間窓に依存しない）。
    #[test]
    fn net11_end_error_before_barrier_ack_is_aborted() {
        let b = batch(1);
        // 本体 seq 11 / END seq 12 / 同期点 seq 13。
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok(err_dgram(11, 0)),
                Ok(err_dgram(12, 12)),
                Ok(gen_dgram(13)),
                Ok(err_dgram(13, 0)),
            ]),
        )
        .expect_err("end failure");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: 同期点を END の次の seq（13）で送り、ACK が来るまで成功にしない。
    #[test]
    fn net11_success_requires_barrier_ack() {
        let b = batch(1);
        let mut sent = Vec::new();
        let e = exchange(
            &b,
            &Deadline::after(Duration::from_millis(50)),
            Duration::from_millis(50),
            |_| Ok(()),
            |m| {
                sent = m.to_vec();
                Ok(())
            },
            script(vec![Ok(err_dgram(11, 0))]),
        )
        .expect_err("no barrier ack");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(sent, barrier_bytes(13));
    }

    /// NET-11: 同期点は nf_tables の GETGEN 要求（type 0x0A10・REQUEST|ACK）で 20 バイト。NOOP（type 1）ではない。
    #[test]
    fn net11_barrier_is_getgen_request_bytes() {
        let bytes = encode_barrier(0x0102_0304).expect("barrier");
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes, barrier_bytes(0x0102_0304));
        let msg = crate::netlink::NlMsgIter::new(&bytes)
            .next()
            .expect("one message")
            .expect("valid");
        assert_eq!(msg.header().msg_type(), 0x0A10);
        assert_eq!(nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETGEN), 0x0A10);
        assert_eq!(msg.header().seq(), 0x0102_0304);
        assert_eq!(
            NfGenMsg::decode(msg.payload()).expect("nfgenmsg"),
            NfGenMsg::new(NFPROTO_UNSPEC, 0)
        );
    }

    /// NET-11: NEWGEN と ACK が 1 データグラムにまとまって届いても成功にする。
    #[test]
    fn net11_barrier_reply_in_one_datagram_succeeds() {
        let b = batch(1);
        let ack = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok(err_dgram(11, 0)),
                Ok([gen_dgram(13), err_dgram(13, 0)].concat()),
            ]),
        )
        .expect("ok");
        assert_eq!(ack.body_seqs(), &[11][..]);
        assert_eq!(ack.end_seq(), 12);
    }

    /// NET-11: NEWGEN を受けずに届いた同期点の errno 0 の ACK は成功にせず DataLoss / Unknown。
    #[test]
    fn net11_barrier_ack_without_newgen_is_data_loss() {
        let b = batch(1);
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![Ok(err_dgram(11, 0)), Ok(err_dgram(13, 0))]),
        )
        .expect_err("no newgen");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 同期点が EPERM で拒否されたら成功にせず PermissionDenied / Unknown。
    #[test]
    fn net11_barrier_rejected_is_unknown() {
        let b = batch(1);
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![Ok(err_dgram(11, 0)), Ok(err_dgram(13, 1))]),
        )
        .expect_err("eperm");
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: END の失敗が同期点の NEWGEN より前に届けば Aborted（END の位置で記録する）。
    #[test]
    fn net11_end_error_before_newgen_is_aborted() {
        let b = batch(1);
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok(err_dgram(11, 0)),
                Ok(err_dgram(12, 12)),
                Ok(gen_dgram(13)),
                Ok(err_dgram(13, 0)),
            ]),
        )
        .expect_err("end failure");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![(crate::nftables_batch::NftBatchPosition::End, 12, 12)]
        );
    }

    /// NET-11: END の失敗が先に届いても打ち切らず、後続データグラムの本体の失敗まで全件集める。
    #[test]
    fn net11_end_failure_then_body_failure_are_all_collected() {
        let b = batch(2);
        // 本体 seq 11,12 / END seq 13 / 同期点 seq 14。
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok([err_dgram(11, 0), err_dgram(13, 12)].concat()),
                Ok(err_dgram(12, 17)),
                Ok(gen_dgram(14)),
                Ok(err_dgram(14, 0)),
            ]),
        )
        .expect_err("failures");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![
                (
                    crate::nftables_batch::NftBatchPosition::Body { index: 1 },
                    12,
                    17
                ),
                (crate::nftables_batch::NftBatchPosition::End, 13, 12)
            ]
        );
    }

    /// NET-11: 権限不足では BEGIN と同期点がともに EPERM。同期点の拒否を読み切りの印として Aborted にする。
    #[test]
    fn net11_begin_eperm_with_rejected_barrier_is_aborted() {
        let b = batch(1);
        let mut sent = Vec::new();
        let e = exchange(
            &b,
            &Deadline::after(Duration::from_secs(5)),
            Duration::from_secs(5),
            |_| Ok(()),
            |m| {
                sent = m.to_vec();
                Ok(())
            },
            script(vec![Ok(err_dgram(10, 1)), Ok(err_dgram(13, 1))]),
        )
        .expect_err("eperm");
        assert_eq!(sent, barrier_bytes(13));
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![(crate::nftables_batch::NftBatchPosition::Begin, 10, 1)]
        );
    }

    /// NET-11: 同期点を送れなければ Unknown。
    #[test]
    fn net11_barrier_send_failure_is_unknown() {
        let b = batch(1);
        let e = exchange(
            &b,
            &Deadline::after(Duration::from_secs(5)),
            Duration::from_secs(5),
            |_| Ok(()),
            |_| Err(NetError::new(NetErrorCode::Internal, "boom")),
            script(vec![Ok(err_dgram(11, 0))]),
        )
        .expect_err("barrier send");
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 実カーネルは同期点（GETGEN + NLM_F_ACK）に必ず応答する。CAP_NET_ADMIN があれば NEWGEN と
    /// errno 0 の ACK の 2 データグラム、なければ nfnetlink の入口で EPERM の 1 データグラム（権限不足の
    /// バッチは BEGIN でも EPERM になるため矛盾しない）。完了まで上限つきで読む。
    #[test]
    fn net11_kernel_answers_barrier() {
        let s = NetlinkNetfilterSocket::open().expect("open");
        s.inner
            .send(&encode_barrier(7).expect("barrier"))
            .expect("send");
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(7);
        let deadline = Deadline::after(Duration::from_secs(5));
        for _ in 0..MAX_TRAILING_DATAGRAMS {
            if c.barrier_reached() {
                break;
            }
            let data = s.inner.recv(deadline.remaining()).expect("recv");
            c.feed(&data).expect("valid sync reply");
        }
        // 0: CAP_NET_ADMIN あり（NEWGEN の後の成功 ACK）。1: EPERM。
        let errno = c.barrier_reply().expect("sync request answered");
        assert!(errno == 0 || errno == 1, "unexpected sync errno {errno}");
    }

    /// REPAIR-5: 期限後に届いた ACK は成功にせず Timeout に揃える。
    #[test]
    fn repair5_late_ack_after_deadline_is_timeout() {
        let b = batch(1);
        let total = Duration::from_millis(30);
        let mut items = vec![Ok(err_dgram(11, 0))];
        let e = run(
            &b,
            total,
            |_| Ok(()),
            move |_| {
                std::thread::sleep(Duration::from_millis(60));
                items
                    .pop()
                    .unwrap_or_else(|| Err(NetError::new(NetErrorCode::Timeout, "n")))
            },
        )
        .expect_err("late");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// REPAIR-5: 送信前に期限が切れていれば送らない（NotSent）。
    #[test]
    fn repair5_expired_before_send_is_not_sent() {
        let b = batch(1);
        let mut sent = false;
        let e = run(
            &b,
            Duration::ZERO,
            |_| {
                sent = true;
                Ok(())
            },
            script(vec![]),
        )
        .expect_err("expired");
        assert!(!sent);
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
    }

    /// NET-11: 空バッチは送らずに InvalidArgument / NotSent。
    #[test]
    fn empty_batch_is_rejected_before_send() {
        let b = batch(0);
        let mut sent = false;
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| {
                sent = true;
                Ok(())
            },
            script(vec![]),
        )
        .expect_err("empty");
        assert!(!sent);
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
    }

    /// NET-11: 受信の ENOBUFS は待ち続けず ResourceExhausted / Unknown（後続の recv を呼ばない）。
    #[test]
    fn enobufs_on_recv_is_resource_exhausted_unknown() {
        let b = batch(1);
        let mut calls = 0;
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            |_| {
                calls += 1;
                Err(NetError::new(
                    NetErrorCode::ResourceExhausted,
                    "recvfrom failed: errno 105",
                ))
            },
        )
        .expect_err("enobufs");
        assert_eq!(calls, 1);
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 送信の EMSGSIZE は ResourceExhausted / NotSent。部分送信は Unknown。
    #[test]
    fn send_errors_map_to_outcome() {
        let b = batch(1);
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| {
                Err(NetError::new(
                    NetErrorCode::ResourceExhausted,
                    "sendto failed: errno 90",
                ))
            },
            script(vec![]),
        )
        .expect_err("emsgsize");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| {
                Err(NetError::new(
                    NetErrorCode::DataLoss,
                    "partial netlink send: 1 of 2 bytes",
                ))
            },
            script(vec![]),
        )
        .expect_err("partial");
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 失敗を返した応答は Aborted で位置を特定する。
    #[test]
    fn net11_exchange_reports_failed_message() {
        let b = batch(2);
        let e = run(
            &b,
            Duration::from_secs(5),
            |_| Ok(()),
            script(vec![
                Ok([err_dgram(11, 0), err_dgram(12, 17)].concat()),
                Ok(gen_dgram(14)),
                Ok(err_dgram(14, 0)),
            ]),
        )
        .expect_err("fail");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(e.failures().len(), 1);
    }

    /// NET-11: 次の seq は END の次で、0 を飛ばす。
    #[test]
    fn seq_allocation_advances_past_end_and_skips_zero() {
        assert_eq!(seq_after(5), 6);
        assert_eq!(seq_after(u32::MAX), 1);
    }

    /// REPAIR-5: 門の順番待ちも期限で打ち切る（NotSent / Timeout）。
    #[test]
    fn repair5_gate_wait_is_bounded() {
        let s = NetlinkNetfilterSocket::open().expect("open");
        let _held = s
            .gate
            .acquire(
                &Deadline::after(Duration::from_secs(5)),
                Duration::from_secs(5),
            )
            .expect("gate");
        let e = s
            .send_batch(Duration::from_millis(50), push_body)
            .expect_err("gate wait");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
    }

    /// REPAIR-4: 送信前に失敗するバッチも NftBatch として 1 件記録される。fill の失敗は NotSent。
    #[test]
    fn repair4_send_batch_is_recorded_and_seq_advances() {
        let collect = Arc::new(Collect::default());
        let s = NetlinkNetfilterSocket::open_with_recorder(collect.clone()).expect("open");
        let e = s
            .send_batch(Duration::from_secs(5), |_| {
                Err(NetError::new(NetErrorCode::InvalidArgument, "bad"))
            })
            .expect_err("fill");
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
        let e = s
            .send_batch(Duration::from_secs(5), |_| Ok(()))
            .expect_err("empty");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(s.next_seq.load(Ordering::Relaxed), 4);
        let nft: Vec<_> = collect
            .kinds()
            .into_iter()
            .filter(|k| k.0 == NetOpKind::NftBatch)
            .collect();
        assert_eq!(
            nft,
            vec![
                (NetOpKind::NftBatch, NetOpOutcome::Failure),
                (NetOpKind::NftBatch, NetOpOutcome::Failure)
            ]
        );
    }

    /// NET-11: 複数スレッドから共有できる。
    /// NET-11: seq 空間が最大バッチに足りない位置では 1 へ戻し、バッチ内に 0 を含めない。
    #[test]
    fn net11_reserve_first_seq_avoids_zero_inside_batch() {
        assert_eq!(reserve_first_seq(1), 1);
        assert_eq!(reserve_first_seq(0), 1);
        assert_eq!(reserve_first_seq(u32::MAX), 1);
        assert_eq!(reserve_first_seq(u32::MAX - 1), 1);
        assert_eq!(reserve_first_seq(u32::MAX - MAX_SEQ_PER_BATCH + 1), 1);
        let ok = u32::MAX - MAX_SEQ_PER_BATCH;
        assert_eq!(reserve_first_seq(ok), ok);
        // 最大バッチ（最小サイズの本体で埋めた場合）でも周回しない。
        assert!(u64::from(ok) + u64::from(MAX_SEQ_PER_BATCH) <= u64::from(u32::MAX));
    }

    /// REPAIR-5: fill が期限を超えて戻った場合は何も送らず Timeout / NotSent。
    #[test]
    fn repair5_expired_after_fill_is_not_sent() {
        let sock = NetlinkNetfilterSocket::open().expect("open");
        let e = sock
            .send_batch(Duration::from_millis(20), |b| {
                std::thread::sleep(Duration::from_millis(60));
                push_body(b)
            })
            .expect_err("expired");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
    }

    #[test]
    fn socket_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetlinkNetfilterSocket>();
    }
}
