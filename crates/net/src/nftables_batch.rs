//! nfnetlink の固定ヘッダ `nfgenmsg` とバッチフレーミング（`NFNL_MSG_BATCH_BEGIN` / `END`）の
//! バイト列コーデック（TASK-137.1・NET-11・REPAIR-2・MS-8・#304）。
//!
//! `nft` コマンドや汎用 crate に頼らず nf_tables のバッチメッセージを自前で組み立てる（NET-11）ための
//! 最下層。`netlink` の `NlMsgBuilder` / `NlMsgIter` を再利用する純コーデックで、
//! ソケット I/O・`unsafe`・OS 依存は持たない（3 OS でテストされる）。
//!
//! # 呼び出し元
//!
//! - NEWTABLE / NEWCHAIN / DELTABLE 等の本体メッセージ組み立て（#305・TASK-137.2）が
//!   `NfGenMsg::put_into` と `nfnl_msg_type` を使い、`NftBatch::push_with` へ積む
//! - `NETLINK_NETFILTER` ソケットでの送信と ACK 判定（#306・TASK-137.3）が `NftBatchBytes` を送る
//!
//! # ワイヤーレイアウト
//!
//! ```text
//! nfgenmsg (4B): nfgen_family:u8 | version:u8 | res_id:u16 (ビッグエンディアン)
//! ```
//!
//! `netlink` の他フィールドはネイティブバイトオーダーだが、`res_id` だけは **ビッグエンディアン**
//! （`__be16`）。BATCH_BEGIN / END の `res_id` は `NFNL_SUBSYS_NFTABLES` を指し、
//! ここを誤るとカーネルが別サブシステムとして解釈する。
//! メッセージ type は `(subsystem << 8) | msg` で合成する（BATCH_BEGIN / END のみ生の 0x10 / 0x11）。
//!
//! # 信頼境界
//!
//! デコードは境界を `get()` で検証し panic しない。バッチへ積むメッセージは、ヘッダの妥当性・
//! seq 一致・nf_tables サブシステムであることを検証し、違反は fail-closed で拒否する。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! 本体メッセージ（#305）、ソケット送信と ACK 判定（#306）、実機結合テスト（#307）は未実装。
//! 定数値は Linux UAPI（`nfnetlink.h`・`netfilter.h`）に基づく。

use crate::error::{NetError, NetErrorCode};
use crate::netlink::{MAX_MESSAGE_LEN, NLM_F_REQUEST, NlMsgBuilder, NlMsgHeader};

/// nf_tables のサブシステム ID（`NFNL_SUBSYS_NFTABLES`）。
pub const NFNL_SUBSYS_NFTABLES: u8 = 10;
/// バッチ開始（`NFNL_MSG_BATCH_BEGIN` = `NLMSG_MIN_TYPE`）。
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
/// バッチ終了（`NFNL_MSG_BATCH_END`）。
pub const NFNL_MSG_BATCH_END: u16 = 0x11;
/// nfnetlink バージョン 0（`NFNETLINK_V0`）。
pub const NFNETLINK_V0: u8 = 0;
/// `nfgenmsg` の固定長（バイト）。
pub const NFGENMSG_LEN: usize = 4;
/// BATCH_BEGIN / END 1 件の長さ（nlmsghdr 16 + nfgenmsg 4。パディングなし）。
const BATCH_MARKER_LEN: usize = 20;

/// プロトコルファミリ `NFPROTO_UNSPEC`。
pub const NFPROTO_UNSPEC: u8 = 0;
/// `NFPROTO_INET`。
pub const NFPROTO_INET: u8 = 1;
/// `NFPROTO_IPV4`。
pub const NFPROTO_IPV4: u8 = 2;
/// `NFPROTO_ARP`。
pub const NFPROTO_ARP: u8 = 3;
/// `NFPROTO_NETDEV`。
pub const NFPROTO_NETDEV: u8 = 5;
/// `NFPROTO_BRIDGE`。
pub const NFPROTO_BRIDGE: u8 = 7;
/// `NFPROTO_IPV6`。
pub const NFPROTO_IPV6: u8 = 10;

/// バッチ全体の上限長。暫定値で `MAX_MESSAGE_LEN`（1 MiB）を流用する（REPAIR-3）。
/// kernel 由来の値ではなく、実際の上限はソケットの `SO_SNDBUF`（超過で `EMSGSIZE`）に依存する。
/// 実効値の決定は #306 の担当。
pub const MAX_BATCH_LEN: usize = MAX_MESSAGE_LEN as usize;

fn invalid(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

fn data_loss(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// サブシステム ID とサブシステム内メッセージ番号から nfnetlink の `nlmsg_type` を合成する。
pub const fn nfnl_msg_type(subsys: u8, msg: u8) -> u16 {
    ((subsys as u16) << 8) | msg as u16
}

/// `nlmsg_type` の上位 8 ビット（サブシステム ID）を取り出す。
pub const fn nfnl_subsys_id(msg_type: u16) -> u8 {
    (msg_type >> 8) as u8
}

/// nfgenmsg。フィールドは非公開で、version は `NFNETLINK_V0` 固定（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfGenMsg {
    family: u8,
    version: u8,
    res_id: u16,
}

impl NfGenMsg {
    /// version を `NFNETLINK_V0` に固定して作る。
    pub const fn new(family: u8, res_id: u16) -> Self {
        Self {
            family,
            version: NFNETLINK_V0,
            res_id,
        }
    }

    /// ワイヤー表現へ変換する。`res_id` のみビッグエンディアン。
    pub fn to_bytes(&self) -> [u8; NFGENMSG_LEN] {
        let r = self.res_id.to_be_bytes();
        [self.family, self.version, r[0], r[1]]
    }

    /// 既存の `NlMsgBuilder` へ固定ヘッダとして追記する。
    pub fn put_into(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        b.put_fixed(&self.to_bytes())
    }

    /// メッセージペイロード先頭から復号する。4 バイトを超える分（属性）は無視する。
    /// version は受信値を保持し拒否しない。
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        let head = payload.get(..NFGENMSG_LEN).ok_or_else(|| {
            data_loss(format!(
                "payload too short for nfgenmsg: {} bytes",
                payload.len()
            ))
        })?;
        match head {
            [family, version, hi, lo] => Ok(Self {
                family: *family,
                version: *version,
                res_id: u16::from_be_bytes([*hi, *lo]),
            }),
            _ => Err(data_loss("malformed nfgenmsg")),
        }
    }

    /// プロトコルファミリ。
    pub fn family(&self) -> u8 {
        self.family
    }

    /// nfnetlink バージョン。
    pub fn version(&self) -> u8 {
        self.version
    }

    /// リソース ID（バッチ制御メッセージではサブシステム ID）。
    pub fn res_id(&self) -> u16 {
        self.res_id
    }
}

fn encode_batch_marker(msg_type: u16, seq: u32) -> Result<Vec<u8>, NetError> {
    let mut b = NlMsgBuilder::new(msg_type, NLM_F_REQUEST, seq, 0);
    NfGenMsg::new(NFPROTO_UNSPEC, u16::from(NFNL_SUBSYS_NFTABLES)).put_into(&mut b)?;
    b.finish()
}

/// `NFNL_MSG_BATCH_BEGIN`（20 バイト）を組み立てる。
pub fn encode_batch_begin(seq: u32) -> Result<Vec<u8>, NetError> {
    encode_batch_marker(NFNL_MSG_BATCH_BEGIN, seq)
}

/// `NFNL_MSG_BATCH_END`（20 バイト）を組み立てる。
pub fn encode_batch_end(seq: u32) -> Result<Vec<u8>, NetError> {
    encode_batch_marker(NFNL_MSG_BATCH_END, seq)
}

/// BEGIN と END の間に nf_tables メッセージを積むバッチ容器。
#[derive(Debug)]
pub struct NftBatch {
    buf: Vec<u8>,
    begin_seq: u32,
    next_seq: u32,
    body_seqs: Vec<u32>,
}

/// 閉じたバッチ。#306 が送信と seq 照合に使う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftBatchBytes {
    bytes: Vec<u8>,
    begin_seq: u32,
    end_seq: u32,
    body_seqs: Vec<u32>,
}

impl NftBatchBytes {
    /// 送信するバイト列全体。
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// BEGIN の seq。
    pub fn begin_seq(&self) -> u32 {
        self.begin_seq
    }

    /// END の seq。
    pub fn end_seq(&self) -> u32 {
        self.end_seq
    }

    /// 本体メッセージの seq（積んだ順）。
    pub fn body_seqs(&self) -> &[u32] {
        &self.body_seqs
    }
}

impl NftBatch {
    /// `first_seq` の BEGIN を積んだバッチを作る。
    pub fn new(first_seq: u32) -> Result<Self, NetError> {
        Ok(Self {
            buf: encode_batch_begin(first_seq)?,
            begin_seq: first_seq,
            next_seq: first_seq.wrapping_add(1),
            body_seqs: Vec::new(),
        })
    }

    /// 次の seq を `f` に渡して本体メッセージを組み立てさせ、検証のうえ追記する。
    /// 失敗時はバッファも seq も変えない。戻り値は割り当てた seq。
    pub fn push_with(
        &mut self,
        f: impl FnOnce(u32) -> Result<NlMsgBuilder, NetError>,
    ) -> Result<u32, NetError> {
        let seq = self.next_seq;
        let msg = f(seq)?.finish()?;
        let header = NlMsgHeader::decode(&msg)?;
        if header.seq() != seq {
            return Err(invalid(format!(
                "message seq {} does not match assigned seq {seq}",
                header.seq()
            )));
        }
        if nfnl_subsys_id(header.msg_type()) != NFNL_SUBSYS_NFTABLES {
            return Err(invalid(format!(
                "message type {:#x} is not an nf_tables message",
                header.msg_type()
            )));
        }
        // 末尾に積む END の分を常に残して上限判定する。
        let total = self
            .buf
            .len()
            .checked_add(msg.len())
            .and_then(|n| n.checked_add(BATCH_MARKER_LEN));
        match total {
            Some(n) if n <= MAX_BATCH_LEN => {}
            _ => return Err(invalid("batch exceeds maximum length")),
        }
        self.buf.extend_from_slice(&msg);
        self.body_seqs.push(seq);
        self.next_seq = seq.wrapping_add(1);
        Ok(seq)
    }

    /// END を積んで閉じる。空バッチ（BEGIN + END のみ）も許す。
    pub fn finish(mut self) -> Result<NftBatchBytes, NetError> {
        let end_seq = self.next_seq;
        let end = encode_batch_end(end_seq)?;
        if self.buf.len().saturating_add(end.len()) > MAX_BATCH_LEN {
            return Err(invalid("batch exceeds maximum length"));
        }
        self.buf.extend_from_slice(&end);
        Ok(NftBatchBytes {
            bytes: self.buf,
            begin_seq: self.begin_seq,
            end_seq,
            body_seqs: self.body_seqs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::NlMsgIter;

    const NEWTABLE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, 0);

    fn body(seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST, seq, 0);
        NfGenMsg::new(NFPROTO_INET, 0).put_into(&mut b)?;
        Ok(b)
    }

    /// NET-11・REPAIR-2: encode → decode が一致し version は 0。
    #[test]
    fn nfgenmsg_roundtrip() {
        for (f, r) in [
            (NFPROTO_INET, 10u16),
            (NFPROTO_IPV6, 0xABCD),
            (0, 0),
            (0xFF, 0xFFFF),
        ] {
            let m = NfGenMsg::new(f, r);
            let d = NfGenMsg::decode(&m.to_bytes()).unwrap();
            assert_eq!(d, m);
            assert_eq!((d.family(), d.version(), d.res_id()), (f, 0, r));
        }
    }

    /// NET-11: res_id はビッグエンディアン（ホスト順に依存しない）。
    #[test]
    fn nfgenmsg_res_id_is_big_endian() {
        assert_eq!(NfGenMsg::new(1, 0xABCD).to_bytes(), [1, 0, 0xAB, 0xCD]);
    }

    /// REPAIR-2: 短い入力は DataLoss、長い入力は先頭 4 バイトのみ解釈。
    #[test]
    fn nfgenmsg_decode_short_is_data_loss() {
        for n in 0..NFGENMSG_LEN {
            let e = NfGenMsg::decode(&[1u8; 4][..n]).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::DataLoss);
        }
        let d = NfGenMsg::decode(&[2, 0, 0, 10, 9, 9, 9]).unwrap();
        assert_eq!((d.family(), d.res_id()), (2, 10));
    }

    fn check_marker(bytes: &[u8], ty: u16, seq: u32) {
        assert_eq!(bytes.len(), 20);
        let msg = NlMsgIter::new(bytes).next().unwrap().unwrap();
        let h = msg.header();
        assert_eq!(h.msg_type(), ty);
        assert_eq!(h.flags(), NLM_F_REQUEST);
        assert_eq!(h.seq(), seq);
        assert_eq!(h.pid(), 0);
        assert_eq!(bytes[16..20], [0x00, 0x00, 0x00, 0x0A]);
        let g = NfGenMsg::decode(msg.payload()).unwrap();
        assert_eq!(g.res_id(), u16::from(NFNL_SUBSYS_NFTABLES));
        assert_eq!(msg.attrs(NFGENMSG_LEN).unwrap().count(), 0);
    }

    /// NET-11: BEGIN の res_id が NFNL_SUBSYS_NFTABLES を指す。
    #[test]
    fn batch_begin_specifies_nftables_subsys() {
        check_marker(&encode_batch_begin(7).unwrap(), 0x10, 7);
    }

    /// NET-11: END の res_id が NFNL_SUBSYS_NFTABLES を指す。
    #[test]
    fn batch_end_specifies_nftables_subsys() {
        check_marker(&encode_batch_end(8).unwrap(), 0x11, 8);
    }

    /// NET-11: type の合成と分解。
    #[test]
    fn nfnl_msg_type_compose_split() {
        assert_eq!(nfnl_msg_type(10, 0), 0x0A00);
        assert_eq!(nfnl_subsys_id(0x0A03), 10);
        assert_eq!(nfnl_subsys_id(NFNL_MSG_BATCH_BEGIN), 0);
    }

    /// NET-11: BEGIN → 本体 → END の順序と seq。
    #[test]
    fn batch_framing_order_and_seq() {
        let mut b = NftBatch::new(100).unwrap();
        assert_eq!(b.push_with(body).unwrap(), 101);
        assert_eq!(b.push_with(body).unwrap(), 102);
        let out = b.finish().unwrap();
        let got: Vec<(u16, u32)> = NlMsgIter::new(out.bytes())
            .map(|m| {
                let h = m.unwrap().header();
                (h.msg_type(), h.seq())
            })
            .collect();
        assert_eq!(
            got,
            vec![(0x10, 100), (NEWTABLE, 101), (NEWTABLE, 102), (0x11, 103)]
        );
        assert_eq!(
            (out.begin_seq(), out.end_seq(), out.body_seqs()),
            (100, 103, &[101, 102][..])
        );
    }

    /// NET-11: 空バッチは BEGIN + END のみ。
    #[test]
    fn batch_empty_is_begin_end_only() {
        let out = NftBatch::new(1).unwrap().finish().unwrap();
        assert_eq!(out.bytes().len(), 40);
        assert_eq!(NlMsgIter::new(out.bytes()).count(), 2);
    }

    /// REPAIR-2: seq は u32 を巡回し panic しない。
    #[test]
    fn batch_seq_wraps() {
        let mut b = NftBatch::new(u32::MAX - 1).unwrap();
        assert_eq!(b.push_with(body).unwrap(), u32::MAX);
        assert_eq!(b.push_with(body).unwrap(), 0);
        assert_eq!(b.finish().unwrap().end_seq(), 1);
    }

    /// REPAIR-2: seq 不一致は拒否し状態を変えない。
    #[test]
    fn batch_rejects_seq_mismatch() {
        let mut b = NftBatch::new(10).unwrap();
        let e = b.push_with(|s| body(s + 5)).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(b.push_with(body).unwrap(), 11);
        assert_eq!(b.finish().unwrap().bytes().len(), 20 + 20 + 20);
    }

    /// REPAIR-2: nf_tables 以外のサブシステムは拒否しバッファを変えない。
    #[test]
    fn batch_rejects_foreign_subsys() {
        let mut b = NftBatch::new(1).unwrap();
        for ty in [NFNL_MSG_BATCH_BEGIN, 16u16, nfnl_msg_type(11, 0)] {
            let e = b
                .push_with(|s| {
                    let mut m = NlMsgBuilder::new(ty, NLM_F_REQUEST, s, 0);
                    NfGenMsg::new(0, 0).put_into(&mut m)?;
                    Ok(m)
                })
                .unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
        assert_eq!(b.finish().unwrap().bytes().len(), 40);
    }

    /// REPAIR-2: closure のエラー伝播と総長上限。
    #[test]
    fn batch_rejects_closure_error_and_oversize() {
        let mut b = NftBatch::new(1).unwrap();
        let e = b.push_with(|_| Err(invalid("boom"))).unwrap_err();
        assert_eq!(e.message(), "boom");
        let big = |s: u32| {
            let mut m = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST, s, 0);
            NfGenMsg::new(0, 0).put_into(&mut m)?;
            m.put_fixed(&vec![0u8; MAX_BATCH_LEN / 2])?;
            Ok(m)
        };
        b.push_with(big).unwrap();
        let e = b.push_with(big).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let out = b.finish().unwrap();
        assert_eq!(NlMsgIter::new(out.bytes()).count(), 3);
    }
}
