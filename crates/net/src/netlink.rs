//! ファミリ非依存の netlink メッセージ（nlmsghdr）と属性（rtattr）のバイト列コーデック
//! （TASK-136.1・NET-11・REPAIR-2・MS-8・#298）。
//!
//! 汎用 netlink crate や `ip` / `nft` コマンドに頼らず自前でメッセージを組み立てる（NET-11）ための
//! 最下層。呼び出し元は `netlink_route`（`NETLINK_ROUTE`。#843〜#846・#301）と、将来の
//! nftables バッチ組み立て（#304・TASK-137.1。nfgenmsg が本エンコーダを再利用する）。
//! ソケット I/O・`unsafe`・OS 依存は持たない。
//!
//! # ワイヤーレイアウト
//!
//! 整数はすべて **ホスト（ネイティブ）バイトオーダー**（`to_ne_bytes` / `from_ne_bytes`）。
//!
//! ```text
//! nlmsghdr (16B): len:u32 | type:u16 | flags:u16 | seq:u32 | pid:u32
//! rtattr   ( 4B): len:u16 | type:u16 | payload... | 0 padding (4B 境界まで)
//! ```
//!
//! `len` はヘッダを含み末尾パディングを含まない。次要素へは 4 の倍数へ切り上げた長さ進む。
//! ネスト属性の `len` は子属性（子の末尾パディング含む）すべてを覆う。
//!
//! # 信頼境界
//!
//! カーネル応答も外部入力として扱う。デコーダは長さフィールドを使う前に下限・上限・バッファ長で
//! 検証し、`Err` を返す（panic しない）。ヘッダ長未満の長さは前進不能（無限ループ）を招くため拒否し、
//! エラーを返したイテレータは以後 `None` を返す。
//! 長さを呼び出し側が任意指定できる経路は公開せず、`NlMsgBuilder` が長さを計算する（REPAIR-2）。

use crate::error::{NetError, NetErrorCode};

/// nlmsghdr の固定長（バイト）。
pub const NLMSG_HEADER_LEN: usize = 16;
/// rtattr ヘッダの固定長（バイト）。
pub const ATTR_HEADER_LEN: usize = 4;
/// メッセージ・属性の境界（`NLMSG_ALIGNTO` = `RTA_ALIGNTO`）。
pub const ALIGN_TO: usize = 4;
/// 1 メッセージの上限長。暫定値 1 MiB（spec に根拠値なし。REPAIR-3）。#843 のソケット層は受信する
/// 1 データグラムの上限長にも同じ値を使う（`netlink_route::MAX_RECV_DATAGRAM_LEN`）。
pub const MAX_MESSAGE_LEN: u32 = 1024 * 1024;
/// `rta_len` が u16 のため、属性ペイロードの上限は 65535 - 4。
pub const MAX_ATTR_PAYLOAD_LEN: usize = 65531;

/// 何もしないメッセージ。
pub const NLMSG_NOOP: u16 = 1;
/// エラー / ACK 応答（ペイロードは `netlink_route::decode_nlmsgerr` で解釈する。#844）。
pub const NLMSG_ERROR: u16 = 2;
/// マルチパート応答の終端。
pub const NLMSG_DONE: u16 = 3;
/// 受信オーバーラン。
pub const NLMSG_OVERRUN: u16 = 4;

/// リクエスト。
pub const NLM_F_REQUEST: u16 = 0x01;
/// マルチパート応答の一部。
pub const NLM_F_MULTI: u16 = 0x02;
/// ACK を要求。
pub const NLM_F_ACK: u16 = 0x04;
/// リクエストをエコー。
pub const NLM_F_ECHO: u16 = 0x08;
/// ダンプ中に一貫性が崩れた。
pub const NLM_F_DUMP_INTR: u16 = 0x10;
/// GET: ツリー全体。
pub const NLM_F_ROOT: u16 = 0x100;
/// GET: 一致するもの全て。
pub const NLM_F_MATCH: u16 = 0x200;
/// NEW: 既存を置換。
pub const NLM_F_REPLACE: u16 = 0x100;
/// NEW: 既存なら失敗。
pub const NLM_F_EXCL: u16 = 0x200;
/// NEW: 無ければ作成。
pub const NLM_F_CREATE: u16 = 0x400;
/// NEW: 末尾に追加。
pub const NLM_F_APPEND: u16 = 0x800;

/// `rta_type` のフラグ: ネスト属性。
pub const NLA_F_NESTED: u16 = 0x8000;
/// `rta_type` のフラグ: ネットワークバイトオーダー。
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
/// `rta_type` から種別だけを取り出すマスク。
pub const NLA_TYPE_MASK: u16 = 0x3fff;

fn invalid(msg: &str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

fn data_loss(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// 4 バイト境界へ切り上げる（オーバーフロー時は `None`）。
fn align(len: usize) -> Option<usize> {
    len.checked_add(ALIGN_TO - 1).map(|v| v & !(ALIGN_TO - 1))
}

/// デコード済みの nlmsghdr。フィールドは非公開で、`decode` を通った値のみ存在する（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlMsgHeader {
    len: u32,
    msg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

impl NlMsgHeader {
    /// バッファ先頭から nlmsghdr を復号する。
    ///
    /// 検証順: 16 バイト以上 → `len >= 16` → `len <= MAX_MESSAGE_LEN` → `len <= buf.len()`。
    pub fn decode(buf: &[u8]) -> Result<Self, NetError> {
        let head = buf.get(..NLMSG_HEADER_LEN).ok_or_else(|| {
            data_loss(format!(
                "buffer too short for nlmsghdr: {} bytes",
                buf.len()
            ))
        })?;
        let u32_at = |o: usize| {
            head.get(o..o + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_ne_bytes)
        };
        let u16_at = |o: usize| {
            head.get(o..o + 2)
                .and_then(|b| b.try_into().ok())
                .map(u16::from_ne_bytes)
        };
        let (Some(len), Some(msg_type), Some(flags), Some(seq), Some(pid)) =
            (u32_at(0), u16_at(4), u16_at(6), u32_at(8), u32_at(12))
        else {
            return Err(data_loss("malformed nlmsghdr"));
        };
        if (len as usize) < NLMSG_HEADER_LEN {
            return Err(data_loss(format!("nlmsg_len {len} is smaller than header")));
        }
        if len > MAX_MESSAGE_LEN {
            return Err(data_loss(format!(
                "nlmsg_len {len} exceeds limit {MAX_MESSAGE_LEN}"
            )));
        }
        if len as usize > buf.len() {
            return Err(data_loss(format!(
                "nlmsg_len {len} exceeds buffer length {}",
                buf.len()
            )));
        }
        Ok(Self {
            len,
            msg_type,
            flags,
            seq,
            pid,
        })
    }

    /// ヘッダを含むメッセージ長。
    pub fn len(&self) -> u32 {
        self.len
    }

    /// 常に false（ヘッダを含むため空にならない）。`len` との対。
    pub fn is_empty(&self) -> bool {
        false
    }

    /// メッセージ種別。
    pub fn msg_type(&self) -> u16 {
        self.msg_type
    }

    /// `NLM_F_*` フラグ。
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// シーケンス番号。
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// 送信元ポート ID。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// ヘッダを除いたペイロード長。
    pub fn payload_len(&self) -> usize {
        self.len as usize - NLMSG_HEADER_LEN
    }
}

/// nlmsghdr + ペイロードの組み立て器。長さは内部で計算し、呼び出し側は指定できない（REPAIR-2）。
#[derive(Debug)]
pub struct NlMsgBuilder {
    buf: Vec<u8>,
    /// 末尾要素のパディングを含まない論理長。`finish` が `nlmsg_len` として書く（ワイヤーレイアウト参照）。
    logical_len: usize,
}

impl NlMsgBuilder {
    /// ヘッダ（`nlmsg_len` は `finish` で確定）を持つ空のメッセージを作る。
    pub fn new(msg_type: u16, flags: u16, seq: u32, pid: u32) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&pid.to_ne_bytes());
        Self {
            buf,
            logical_len: NLMSG_HEADER_LEN,
        }
    }

    /// 追記後の長さが上限内か確認する。
    fn check_room(&self, extra: usize) -> Result<(), NetError> {
        match self.buf.len().checked_add(extra) {
            Some(n) if n <= MAX_MESSAGE_LEN as usize => Ok(()),
            _ => Err(invalid("message exceeds maximum length")),
        }
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(ALIGN_TO) {
            self.buf.push(0);
        }
    }

    /// ファミリ固有の固定ヘッダ（`ifinfomsg`・`nfgenmsg` 等）を追記し、4 バイト境界まで 0 埋めする。
    pub fn put_fixed(&mut self, bytes: &[u8]) -> Result<(), NetError> {
        let padded = align(bytes.len()).ok_or_else(|| invalid("fixed header too large"))?;
        self.check_room(padded)?;
        self.buf.extend_from_slice(bytes);
        self.logical_len = self.buf.len();
        self.pad();
        Ok(())
    }

    /// 属性を追記する。`attr_type` が `NLA_TYPE_MASK` を超える、またはペイロードが
    /// `MAX_ATTR_PAYLOAD_LEN` を超える場合は `Err`。
    pub fn put_attr(&mut self, attr_type: u16, payload: &[u8]) -> Result<(), NetError> {
        self.put_attr_with_flags(attr_type, 0, payload)
    }

    /// フラグ付きで属性を追記する。`flags` に指定できるのは `NLA_F_NET_BYTEORDER` のみ
    /// （`NLA_F_NESTED` は `put_nested` 経由で付与する）。型番号は `NLA_TYPE_MASK` 以下であること。
    /// デコーダ側（`is_net_byteorder`）と対称に、ネットワークバイトオーダー属性を送出できる。
    pub fn put_attr_with_flags(
        &mut self,
        attr_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> Result<(), NetError> {
        if attr_type > NLA_TYPE_MASK {
            return Err(invalid("attribute type out of range"));
        }
        if flags & !NLA_F_NET_BYTEORDER != 0 {
            return Err(invalid("attribute flags not allowed"));
        }
        self.put_attr_raw(attr_type | flags, payload)
    }

    fn put_attr_raw(&mut self, raw_type: u16, payload: &[u8]) -> Result<(), NetError> {
        if payload.len() > MAX_ATTR_PAYLOAD_LEN {
            return Err(invalid("attribute payload too large"));
        }
        let total = ATTR_HEADER_LEN + payload.len();
        let padded = align(total).ok_or_else(|| invalid("attribute too large"))?;
        self.check_room(padded)?;
        let rta_len = u16::try_from(total).map_err(|_| invalid("attribute length exceeds u16"))?;
        self.buf.extend_from_slice(&rta_len.to_ne_bytes());
        self.buf.extend_from_slice(&raw_type.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        self.logical_len = self.buf.len();
        self.pad();
        Ok(())
    }

    /// ネスト属性を追記する。`f` が子属性を追記し、終了時に `rta_len` を書き戻す（`NLA_F_NESTED` を付与）。
    pub fn put_nested(
        &mut self,
        attr_type: u16,
        f: impl FnOnce(&mut Self) -> Result<(), NetError>,
    ) -> Result<(), NetError> {
        if attr_type > NLA_TYPE_MASK {
            return Err(invalid("attribute type out of range"));
        }
        self.check_room(ATTR_HEADER_LEN)?;
        let start = self.buf.len();
        let saved_logical = self.logical_len;
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(attr_type | NLA_F_NESTED).to_ne_bytes());
        // 失敗時は追記済みバイトを start まで巻き戻し、不正な rta_len を持つ半端な属性を残さない（REPAIR-2）。
        let result = f(self).and_then(|()| {
            let total = self.buf.len() - start;
            let rta_len =
                u16::try_from(total).map_err(|_| invalid("nested attribute length exceeds u16"))?;
            let slot = self
                .buf
                .get_mut(start..start + 2)
                .ok_or_else(|| invalid("nested attribute bookkeeping error"))?;
            slot.copy_from_slice(&rta_len.to_ne_bytes());
            Ok(())
        });
        match result {
            Ok(()) => {
                self.logical_len = self.buf.len();
                Ok(())
            }
            Err(e) => {
                self.buf.truncate(start);
                self.logical_len = saved_logical;
                Err(e)
            }
        }
    }

    /// `nlmsg_len`（末尾パディングを除く論理長）を確定し、パディング込みのバイト列を返す。
    pub fn finish(mut self) -> Result<Vec<u8>, NetError> {
        let len =
            u32::try_from(self.logical_len).map_err(|_| invalid("message length exceeds u32"))?;
        if len > MAX_MESSAGE_LEN {
            return Err(invalid("message exceeds maximum length"));
        }
        let slot = self
            .buf
            .get_mut(..4)
            .ok_or_else(|| invalid("message bookkeeping error"))?;
        slot.copy_from_slice(&len.to_ne_bytes());
        Ok(self.buf)
    }
}

/// 1 件のメッセージの借用ビュー。
#[derive(Debug, Clone, Copy)]
pub struct NlMsg<'a> {
    header: NlMsgHeader,
    payload: &'a [u8],
}

impl<'a> NlMsg<'a> {
    /// 復号済みヘッダ。
    pub fn header(&self) -> NlMsgHeader {
        self.header
    }

    /// ヘッダ直後のペイロード（ファミリ固有ヘッダ + 属性）。
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// ファミリ固有の固定ヘッダ `fixed_len` バイト（4 バイト切り上げ）を飛ばして属性を走査する。
    pub fn attrs(&self, fixed_len: usize) -> Result<AttrIter<'a>, NetError> {
        let skip = align(fixed_len).ok_or_else(|| invalid("fixed header too large"))?;
        // 固定ヘッダのみで属性 0 件のメッセージは nlmsg_len が固定ヘッダ実長（4 の倍数と限らない）で、
        // 末尾パディングが省略される。実長ちょうどなら空の走査として扱う。
        if self.payload.len() == fixed_len {
            return Ok(AttrIter::new(&[]));
        }
        let rest = self
            .payload
            .get(skip..)
            .ok_or_else(|| data_loss("payload shorter than fixed header"))?;
        Ok(AttrIter::new(rest))
    }
}

/// 受信バッファ（複数メッセージ連結）を走査するイテレータ。遅延評価・非再帰・アロケーションなし。
#[derive(Debug, Clone)]
pub struct NlMsgIter<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> NlMsgIter<'a> {
    /// バッファ全体を走査対象にする（空なら 0 件）。
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            rest: buf,
            done: false,
        }
    }
}

impl<'a> Iterator for NlMsgIter<'a> {
    type Item = Result<NlMsg<'a>, NetError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        let step = (|| {
            let header = NlMsgHeader::decode(self.rest)?;
            let payload = self
                .rest
                .get(NLMSG_HEADER_LEN..header.len() as usize)
                .ok_or_else(|| data_loss("nlmsg_len inconsistent with buffer"))?;
            let adv = align(header.len() as usize)
                .ok_or_else(|| data_loss("nlmsg_len overflow"))?
                .min(self.rest.len());
            let rest = self
                .rest
                .get(adv..)
                .ok_or_else(|| data_loss("advance beyond buffer"))?;
            Ok((NlMsg { header, payload }, rest))
        })();
        match step {
            Ok((msg, rest)) => {
                self.rest = rest;
                Some(Ok(msg))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// 1 件の属性の借用ビュー。
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    raw_type: u16,
    payload: &'a [u8],
}

impl<'a> Attr<'a> {
    /// フラグを除いた属性種別。
    pub fn attr_type(&self) -> u16 {
        self.raw_type & NLA_TYPE_MASK
    }

    /// `NLA_F_NESTED` が立っているか。
    pub fn is_nested(&self) -> bool {
        self.raw_type & NLA_F_NESTED != 0
    }

    /// `NLA_F_NET_BYTEORDER` が立っているか。
    pub fn is_net_byteorder(&self) -> bool {
        self.raw_type & NLA_F_NET_BYTEORDER != 0
    }

    /// 属性ペイロード（ヘッダ・パディングを除く）。
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// ペイロードを子属性列として走査する。
    pub fn nested(&self) -> AttrIter<'a> {
        AttrIter::new(self.payload)
    }
}

/// 属性列を走査するイテレータ。遅延評価・非再帰。エラー後は `None`。
#[derive(Debug, Clone)]
pub struct AttrIter<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> AttrIter<'a> {
    /// 属性領域を走査対象にする。
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            rest: buf,
            done: false,
        }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<Attr<'a>, NetError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        let step = (|| {
            let (head, _) = self.rest.split_at_checked(ATTR_HEADER_LEN).ok_or_else(|| {
                data_loss(format!(
                    "trailing {} bytes shorter than rtattr",
                    self.rest.len()
                ))
            })?;
            let len = head
                .get(..2)
                .and_then(|b| b.try_into().ok())
                .map(u16::from_ne_bytes);
            let ty = head
                .get(2..4)
                .and_then(|b| b.try_into().ok())
                .map(u16::from_ne_bytes);
            let (Some(len), Some(raw_type)) = (len, ty) else {
                return Err(data_loss("malformed rtattr"));
            };
            let len = len as usize;
            if len < ATTR_HEADER_LEN {
                return Err(data_loss(format!("rta_len {len} is smaller than header")));
            }
            if len > self.rest.len() {
                return Err(data_loss(format!(
                    "rta_len {len} exceeds remaining {}",
                    self.rest.len()
                )));
            }
            let payload = self
                .rest
                .get(ATTR_HEADER_LEN..len)
                .ok_or_else(|| data_loss("rta_len inconsistent with buffer"))?;
            let adv = align(len)
                .ok_or_else(|| data_loss("rta_len overflow"))?
                .min(self.rest.len());
            let rest = self
                .rest
                .get(adv..)
                .ok_or_else(|| data_loss("advance beyond buffer"))?;
            Ok((Attr { raw_type, payload }, rest))
        })();
        match step {
            Ok((attr, rest)) => {
                self.rest = rest;
                Some(Ok(attr))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(len: u32, ty: u16, flags: u16, seq: u32, pid: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(&flags.to_ne_bytes());
        v.extend_from_slice(&seq.to_ne_bytes());
        v.extend_from_slice(&pid.to_ne_bytes());
        v
    }

    fn attr_bytes(len: u16, ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn code(e: &NetError) -> NetErrorCode {
        e.code()
    }

    /// NET-11・REPAIR-2: ヘッダの往復とネイティブバイトオーダー。
    #[test]
    fn header_roundtrip_and_native_order() {
        let flags = NLM_F_REQUEST | NLM_F_ACK;
        let bytes = NlMsgBuilder::new(16, flags, 0x01020304, 0xA0B0C0D0)
            .finish()
            .unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes, hdr(16, 16, 0x05, 0x01020304, 0xA0B0C0D0));
        let h = NlMsgHeader::decode(&bytes).unwrap();
        assert_eq!(
            (
                h.len(),
                h.msg_type(),
                h.flags(),
                h.seq(),
                h.pid(),
                h.payload_len()
            ),
            (16, 16, 0x05, 0x01020304, 0xA0B0C0D0, 0)
        );
    }

    /// NET-11: 固定ヘッダ 5 バイトは len=21、出力 24 バイトで末尾 0 埋め。
    #[test]
    fn fixed_header_padding() {
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        b.put_fixed(&[1, 2, 3, 4, 5]).unwrap();
        let bytes = b.finish().unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(NlMsgHeader::decode(&bytes).unwrap().len(), 21);
        assert_eq!(&bytes[16..], &[1, 2, 3, 4, 5, 0, 0, 0]);
        let msg = NlMsgIter::new(&bytes).next().unwrap().unwrap();
        assert_eq!(msg.payload(), &[1, 2, 3, 4, 5]);
    }

    /// NET-11: rtattr のパディングと rta_len。
    #[test]
    fn attr_padding_lengths() {
        for (payload, rta_len, occupied) in [
            (&[1u8, 2, 3, 4, 5][..], 9u16, 12usize),
            (&[1, 2, 3, 4][..], 8, 8),
            (&[][..], 4, 4),
        ] {
            let mut b = NlMsgBuilder::new(1, 0, 0, 0);
            b.put_attr(7, payload).unwrap();
            let bytes = b.finish().unwrap();
            assert_eq!(bytes.len(), 16 + occupied);
            assert_eq!(&bytes[16..18], &rta_len.to_ne_bytes());
            assert!(bytes[16 + 4 + payload.len()..].iter().all(|&x| x == 0));
            let msg = NlMsgIter::new(&bytes).next().unwrap().unwrap();
            let a = msg.attrs(0).unwrap().next().unwrap().unwrap();
            assert_eq!((a.attr_type(), a.payload()), (7, payload));
        }
    }

    /// NET-11: 2 段ネストの rta_len と復元。
    #[test]
    fn nested_roundtrip() {
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        b.put_nested(18, |b| {
            b.put_attr(1, &[1, 2, 3, 4, 5])?;
            b.put_nested(2, |b| b.put_attr(1, &[9, 8]))
        })
        .unwrap();
        let bytes = b.finish().unwrap();
        // inner-most: 4+2=6 -> 8, mid: 4+8=12, outer: 4+12(5B attr)+12 = 28
        assert_eq!(bytes.len(), 16 + 28);
        assert_eq!(&bytes[16..18], &28u16.to_ne_bytes());
        assert_eq!(&bytes[16 + 4 + 12..16 + 4 + 12 + 2], &12u16.to_ne_bytes());
        let msg = NlMsgIter::new(&bytes).next().unwrap().unwrap();
        let outer = msg.attrs(0).unwrap().next().unwrap().unwrap();
        assert!(outer.is_nested());
        assert_eq!(outer.attr_type(), 18);
        let kids: Vec<_> = outer.nested().collect::<Result<_, _>>().unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(
            (kids[0].attr_type(), kids[0].payload()),
            (1, &[1u8, 2, 3, 4, 5][..])
        );
        assert!(kids[1].is_nested());
        let inner: Vec<_> = kids[1].nested().collect::<Result<_, _>>().unwrap();
        assert_eq!(
            (inner[0].attr_type(), inner[0].payload()),
            (1, &[9u8, 8][..])
        );
    }

    /// NET-11: `NLA_F_NET_BYTEORDER` 付き属性の送出と復元、不許可フラグ・型範囲の拒否。
    #[test]
    fn put_attr_with_flags_net_byteorder() {
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        b.put_attr_with_flags(3, NLA_F_NET_BYTEORDER, &[0, 0, 0, 1])
            .unwrap();
        let bytes = b.finish().unwrap();
        assert_eq!(&bytes[18..20], &(0x4000u16 | 3).to_ne_bytes());
        let msg = NlMsgIter::new(&bytes).next().unwrap().unwrap();
        let a = msg.attrs(0).unwrap().next().unwrap().unwrap();
        assert_eq!(
            (a.attr_type(), a.is_net_byteorder(), a.payload()),
            (3, true, &[0u8, 0, 0, 1][..])
        );
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        assert!(b.put_attr_with_flags(3, NLA_F_NESTED, &[]).is_err());
        assert!(b.put_attr_with_flags(0x4000, 0, &[]).is_err());
        assert!(b.put_attr(0x4003, &[]).is_err());
    }

    /// NET-11: rta_type 上位ビットのフラグ。
    #[test]
    fn attr_flags() {
        let buf = attr_bytes(4, 0x8000 | 18, &[]);
        let a = AttrIter::new(&buf).next().unwrap().unwrap();
        assert_eq!(
            (a.attr_type(), a.is_nested(), a.is_net_byteorder()),
            (18, true, false)
        );
        let buf = attr_bytes(4, 0x4000 | 3, &[]);
        let a = AttrIter::new(&buf).next().unwrap().unwrap();
        assert_eq!(
            (a.attr_type(), a.is_nested(), a.is_net_byteorder()),
            (3, false, true)
        );
    }

    /// NET-11: 連結メッセージと、最後の属性の末尾パディング欠落の受理。
    #[test]
    fn multi_message_and_missing_trailing_padding() {
        let mut buf = hdr(20, 3, 0, 1, 2);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&hdr(16, 2, 0, 3, 4));
        let msgs: Vec<_> = NlMsgIter::new(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload(), &[1, 2, 3, 4]);
        assert_eq!(msgs[1].header().seq(), 3);

        let buf = attr_bytes(5, 1, &[7]);
        let a: Vec<_> = AttrIter::new(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].payload(), &[7]);
    }

    /// NET-11・REPAIR-2: 不正な nlmsghdr の長さは Err（panic しない）。
    #[test]
    fn message_length_errors() {
        assert_eq!(NlMsgIter::new(&[]).count(), 0);
        for n in 1..16 {
            let buf = vec![0u8; n];
            let r = NlMsgIter::new(&buf).next().unwrap();
            assert_eq!(code(&r.unwrap_err()), NetErrorCode::DataLoss);
        }
        for len in [0u32, 15] {
            let buf = hdr(len, 1, 0, 0, 0);
            assert!(NlMsgHeader::decode(&buf).is_err());
            let mut it = NlMsgIter::new(&buf);
            assert!(it.next().unwrap().is_err());
            assert!(it.next().is_none());
        }
        assert!(NlMsgHeader::decode(&hdr(17, 1, 0, 0, 0)).is_err());
        let big = MAX_MESSAGE_LEN + 1;
        let mut buf = hdr(big, 1, 0, 0, 0);
        buf.resize(big as usize, 0);
        assert!(NlMsgHeader::decode(&buf).is_err());
    }

    /// NET-11・REPAIR-2: 不正な rtattr の長さは Err 1 回の後 None（無限ループしない）。
    #[test]
    fn attr_length_errors() {
        for buf in [
            attr_bytes(100, 1, &[0; 4]),
            attr_bytes(0, 1, &[0; 4]),
            attr_bytes(3, 1, &[0; 4]),
            vec![1, 2, 3],
        ] {
            let mut it = AttrIter::new(&buf);
            assert_eq!(
                code(&it.next().unwrap().unwrap_err()),
                NetErrorCode::DataLoss
            );
            assert!(it.next().is_none());
        }
        let mut buf = attr_bytes(8, 1, &[0; 4]);
        buf.extend_from_slice(&[0, 0]);
        let mut it = AttrIter::new(&buf);
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    /// REPAIR-2: エンコード側の上限超過は Err。
    #[test]
    fn encode_limits() {
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        let e = b.put_attr(1, &vec![0; 65532]).unwrap_err();
        assert_eq!(code(&e), NetErrorCode::InvalidArgument);
        assert!(b.put_attr(0x4000, &[]).is_err());
        assert!(b.put_attr(1, &vec![0; 65531]).is_ok());
        let r = NlMsgBuilder::new(1, 0, 0, 0).put_nested(1, |b| {
            for _ in 0..2 {
                b.put_attr(1, &vec![0; 40000])?;
            }
            Ok(())
        });
        assert_eq!(code(&r.unwrap_err()), NetErrorCode::InvalidArgument);
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        let mut err = None;
        for _ in 0..40 {
            if let Err(e) = b.put_attr(1, &vec![0; 65531]) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(code(&err.unwrap()), NetErrorCode::InvalidArgument);
    }

    /// REPAIR-2: put_nested 失敗時は追記済みバイトを巻き戻し、以後の finish が壊れた属性を含まない。
    #[test]
    fn nested_failure_rolls_back() {
        let mut b = NlMsgBuilder::new(1, 0, 0, 0);
        b.put_attr(1, &[9]).unwrap();
        let r = b.put_nested(2, |b| {
            b.put_attr(1, &[1, 2, 3])?;
            b.put_attr(0x4000, &[])
        });
        assert!(r.is_err());
        let r = b.put_nested(3, |b| {
            for _ in 0..2 {
                b.put_attr(1, &vec![0; 40000])?;
            }
            Ok(())
        });
        assert!(r.is_err());
        let bytes = b.finish().unwrap();
        assert_eq!(bytes.len(), 24);
        let msg = NlMsgIter::new(&bytes).next().unwrap().unwrap();
        let attrs: Vec<_> = msg.attrs(0).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].payload(), &[9]);
    }

    /// REPAIR-2: 全バイト値・切り詰めでも panic しない。
    #[test]
    fn no_panic_on_arbitrary_bytes() {
        for fill in 0..=255u8 {
            for n in 0..40usize {
                let buf = vec![fill; n];
                for m in NlMsgIter::new(&buf).flatten() {
                    for a in m.attrs(0).into_iter().flatten() {
                        let _ = a.map(|a| a.nested().count());
                    }
                }
                let _ = AttrIter::new(&buf).count();
            }
        }
    }

    /// NET-11・REPAIR-2: 4 バイト境界でない固定ヘッダのみのメッセージは属性 0 件として往復できる。
    #[test]
    fn header_only_unaligned_fixed_roundtrip() {
        let mut b = NlMsgBuilder::new(16, 0, 1, 2);
        b.put_fixed(&[1, 2, 3, 4, 5]).unwrap();
        let bytes = b.finish().unwrap();
        assert_eq!(bytes.len(), 24);
        let msg = NlMsgIter::new(&bytes).next().unwrap().unwrap();
        assert_eq!(msg.header().len(), 21);
        assert_eq!(msg.payload(), &[1, 2, 3, 4, 5]);
        assert_eq!(msg.attrs(5).unwrap().count(), 0);
        assert_eq!(code(&msg.attrs(6).unwrap_err()), NetErrorCode::DataLoss);
    }
}
