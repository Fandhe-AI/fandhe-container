//! supervisor と netns holder の間の固定長フレーム（NET-9・REPAIR-2・#3197。`docs/design/rootless-network.md` 12.2）。
//!
//! 生の `Vec<u8>` を手で組まず、型付きの [`HolderMessage`] から [`HolderFrame`]（32 バイトの newtype）を作り、
//! 受信側は [`HolderFrame::decode`] で全項目を検証する（壊れた値を表現できない）。OS 非依存の純関数だけで、
//! ソケットの送受信は `channel`（supervisor 側）と `holder`（holder 側）が担う。
//!
//! # レイアウト（32 バイト・整数は LE）
//! | offset | 長さ | 内容 |
//! | ------ | ---- | ---- |
//! | 0 | 4 | magic `b"FCNH"` |
//! | 4 | 1 | version（`1`） |
//! | 5 | 1 | kind |
//! | 6 | 2 | reserved（0 でなければ拒否） |
//! | 8 | 8 | a |
//! | 16 | 8 | b |
//! | 24 | 8 | c |
//!
//! `Ready` は a = ns の `st_dev`・b = net の inode・c = user の inode、`Error` は a = エラーコード表の値、
//! それ以外の kind は a・b・c がすべて 0 でなければ拒否する。

use crate::error::{NetError, NetErrorCode};

/// フレームの長さ（固定）。
pub const FRAME_LEN: usize = 32;

const MAGIC: [u8; 4] = *b"FCNH";
const VERSION: u8 = 1;

const KIND_NAMESPACES: u8 = 1;
const KIND_READY: u8 = 2;
const KIND_STOP: u8 = 3;
const KIND_ERROR: u8 = 4;

/// holder が参加した namespace の識別（READY で返す。supervisor が送った fd の `fstat` と照合する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsIdentity {
    /// nsfs の `st_dev`（user と net で同じ値）。
    pub dev: u64,
    /// network namespace の inode。
    pub net_ino: u64,
    /// user namespace の inode。
    pub user_ino: u64,
}

/// フレームが運ぶメッセージ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderMessage {
    /// supervisor → holder。`SCM_RIGHTS` の fd 2 本（順は user、net）と一緒に送る。
    Namespaces,
    /// holder → supervisor。参加完了・capability 破棄済み。
    Ready(NsIdentity),
    /// supervisor → holder。終了の要求。
    Stop,
    /// holder → supervisor。参加前後の失敗（READY の前だけ）。
    Error(NetErrorCode),
}

/// エンコード済みの 32 バイトのフレーム。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderFrame([u8; FRAME_LEN]);

/// `NetErrorCode` の固定のワイヤー値（`NetErrorCode::ALL` の並びに依存しない。`from_name` の文字列は使わない）。
fn code_to_wire(code: NetErrorCode) -> u64 {
    match code {
        NetErrorCode::InvalidArgument => 1,
        NetErrorCode::DataLoss => 2,
        NetErrorCode::Timeout => 3,
        NetErrorCode::PermissionDenied => 4,
        NetErrorCode::Unimplemented => 5,
        NetErrorCode::ResourceExhausted => 6,
        NetErrorCode::NotFound => 7,
        NetErrorCode::AlreadyExists => 8,
        NetErrorCode::FailedPrecondition => 9,
        // `NetErrorCode` は `non_exhaustive`。将来の variant は分類不能として Internal に写す。
        _ => 10,
    }
}

fn code_from_wire(v: u64) -> Option<NetErrorCode> {
    Some(match v {
        1 => NetErrorCode::InvalidArgument,
        2 => NetErrorCode::DataLoss,
        3 => NetErrorCode::Timeout,
        4 => NetErrorCode::PermissionDenied,
        5 => NetErrorCode::Unimplemented,
        6 => NetErrorCode::ResourceExhausted,
        7 => NetErrorCode::NotFound,
        8 => NetErrorCode::AlreadyExists,
        9 => NetErrorCode::FailedPrecondition,
        10 => NetErrorCode::Internal,
        _ => return None,
    })
}

fn bad(message: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, message)
}

impl HolderFrame {
    /// メッセージからフレームを作る。
    pub fn encode(msg: HolderMessage) -> Self {
        let (kind, a, b, c) = match msg {
            HolderMessage::Namespaces => (KIND_NAMESPACES, 0, 0, 0),
            HolderMessage::Ready(id) => (KIND_READY, id.dev, id.net_ino, id.user_ino),
            HolderMessage::Stop => (KIND_STOP, 0, 0, 0),
            HolderMessage::Error(code) => (KIND_ERROR, code_to_wire(code), 0, 0),
        };
        let mut buf = [0u8; FRAME_LEN];
        let mut at = 0usize;
        for chunk in [
            &MAGIC[..],
            &[VERSION, kind, 0, 0],
            &a.to_le_bytes(),
            &b.to_le_bytes(),
            &c.to_le_bytes(),
        ] {
            if let Some(dst) = buf.get_mut(at..at + chunk.len()) {
                dst.copy_from_slice(chunk);
            }
            at += chunk.len();
        }
        Self(buf)
    }

    /// 送信するバイト列。
    pub fn as_bytes(&self) -> &[u8; FRAME_LEN] {
        &self.0
    }

    /// 受信したバイト列を検証してメッセージへ戻す。長さ・magic・version・kind・予約欄・使わない欄・コード表の
    /// どれが外れても拒否する（`FailedPrecondition`。メッセージは固定の英文で、受信内容を含めない）。
    pub fn decode(bytes: &[u8]) -> Result<HolderMessage, NetError> {
        let Ok(buf) = <&[u8; FRAME_LEN]>::try_from(bytes) else {
            return Err(bad("netns holder frame has an unexpected length"));
        };
        let u64_at = |at: usize| -> Option<u64> {
            Some(u64::from_le_bytes(buf.get(at..at + 8)?.try_into().ok()?))
        };
        if buf.get(0..4) != Some(&MAGIC[..]) {
            return Err(bad("netns holder frame has a bad magic"));
        }
        if buf.get(4) != Some(&VERSION) {
            return Err(bad("netns holder frame has an unsupported version"));
        }
        if buf.get(6..8) != Some(&[0u8, 0u8][..]) {
            return Err(bad("netns holder frame has a nonzero reserved field"));
        }
        let (Some(kind), Some(a), Some(b), Some(c)) =
            (buf.get(5).copied(), u64_at(8), u64_at(16), u64_at(24))
        else {
            return Err(bad("netns holder frame is truncated"));
        };
        let zero_rest = |fields: &[u64]| fields.iter().all(|f| *f == 0);
        match kind {
            KIND_NAMESPACES if zero_rest(&[a, b, c]) => Ok(HolderMessage::Namespaces),
            KIND_STOP if zero_rest(&[a, b, c]) => Ok(HolderMessage::Stop),
            KIND_READY => Ok(HolderMessage::Ready(NsIdentity {
                dev: a,
                net_ino: b,
                user_ino: c,
            })),
            KIND_ERROR if zero_rest(&[b, c]) => code_from_wire(a)
                .map(HolderMessage::Error)
                .ok_or_else(|| bad("netns holder frame has an unknown error code")),
            KIND_NAMESPACES | KIND_STOP | KIND_ERROR => {
                Err(bad("netns holder frame has a nonzero unused field"))
            }
            _ => Err(bad("netns holder frame has an unknown kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> NsIdentity {
        NsIdentity {
            dev: 4,
            net_ino: 0xf000_0001,
            user_ino: 0xf000_0002,
        }
    }

    /// NET-9・REPAIR-2: すべての kind が往復し、ワイヤーの具体値（先頭 8 バイトと a・b・c）が固定される。
    #[test]
    fn roundtrip_and_wire_layout() {
        for msg in [
            HolderMessage::Namespaces,
            HolderMessage::Ready(ready()),
            HolderMessage::Stop,
            HolderMessage::Error(NetErrorCode::PermissionDenied),
        ] {
            let f = HolderFrame::encode(msg);
            assert_eq!(HolderFrame::decode(f.as_bytes()).expect("decode"), msg);
        }
        let f = HolderFrame::encode(HolderMessage::Ready(ready()));
        let b = f.as_bytes();
        assert_eq!(b.get(..8), Some(&[b'F', b'C', b'N', b'H', 1, 2, 0, 0][..]));
        assert_eq!(b.get(8..16), Some(&4u64.to_le_bytes()[..]));
        assert_eq!(b.get(16..24), Some(&0xf000_0001u64.to_le_bytes()[..]));
        assert_eq!(b.get(24..32), Some(&0xf000_0002u64.to_le_bytes()[..]));
        let e = HolderFrame::encode(HolderMessage::Error(NetErrorCode::Timeout));
        assert_eq!(e.as_bytes().get(5..8), Some(&[4u8, 0, 0][..]));
        assert_eq!(e.as_bytes().get(8..16), Some(&3u64.to_le_bytes()[..]));
    }

    /// 全 `NetErrorCode` がワイヤー表で往復する（表と `ALL` の食い違いを検出する）。
    #[test]
    fn every_error_code_roundtrips() {
        for code in NetErrorCode::ALL {
            let f = HolderFrame::encode(HolderMessage::Error(code));
            assert_eq!(
                HolderFrame::decode(f.as_bytes()).expect("decode"),
                HolderMessage::Error(code)
            );
        }
    }

    /// 壊れたフレームは具体的に拒否される（長さ・magic・version・kind・予約・使わない欄・コード）。
    #[test]
    fn rejects_malformed_frames() {
        let good = *HolderFrame::encode(HolderMessage::Stop).as_bytes();
        assert!(HolderFrame::decode(&good[..31]).is_err());
        let mut long = good.to_vec();
        long.push(0);
        assert!(HolderFrame::decode(&long).is_err());
        for (idx, val) in [
            (0usize, b'X'),
            (4, 2),
            (5, 99),
            (6, 1),
            (7, 1),
            (9, 1),
            (31, 1),
        ] {
            let mut b = good;
            b[idx] = val;
            let err = HolderFrame::decode(&b).expect_err("must reject");
            assert_eq!(err.code(), NetErrorCode::FailedPrecondition, "idx {idx}");
        }
        let mut e = *HolderFrame::encode(HolderMessage::Error(NetErrorCode::Timeout)).as_bytes();
        e[8] = 0;
        assert!(HolderFrame::decode(&e).is_err());
        e[8] = 11;
        assert!(HolderFrame::decode(&e).is_err());
    }
}
