//! DNS ヘルパーの制御 UDS で運ぶ型付きの長さ接頭辞フレーム（NET-5・REPAIR-2・PLUG-12・#3071）。
//!
//! 役割: 起動元（`reload_dns_helper`・`ControlStopRequest`）とヘルパー側の制御サーバーが交わす
//! `Reload{generation}` / `Loaded{generation}` / `Stop` / `Error{code}` を、生の `Vec<u8>` を手で組まずに
//! 符号化・復号する。OS 非依存の純関数だけで、ソケットの送受信は `control::os` が担う。
//! 設計の正は `docs/design/network-wiring.md` の D11（`Error` は ack が来ない場合を EOF や時間切れに頼らず
//! すぐ失敗として返すための語彙の追加で、D11 の「ack が無ければ attach を失敗にする」決定には反しない）。
//!
//! # レイアウト（ヘッダー 12 バイト固定・整数は LE）
//! | offset | 長さ | 内容 |
//! | ------ | ---- | ---- |
//! | 0 | 4 | magic `b"FCDC"` |
//! | 4 | 1 | version（`1`） |
//! | 5 | 1 | kind（1=Reload / 2=Loaded / 3=Stop / 4=Error） |
//! | 6 | 2 | reserved（0 でなければ拒否） |
//! | 8 | 4 | payload_len |
//!
//! ペイロードは Reload・Loaded が `generation: u64`（0 は拒否）、Error がコードの固定のワイヤー値 `u64`、
//! Stop が空。受信側は kind ごとの期待長を **ペイロードを読む前に** 照合し、固定長の配列に読む
//! （ヒープ確保なし。上限 [`MAX_PAYLOAD`]）。

use std::io::{self, Read, Write};
use std::num::NonZeroU64;

use crate::error::{NetError, NetErrorCode};
use crate::netns_holder::frame::{code_from_wire, code_to_wire};

/// ヘッダーの長さ（固定）。
pub const HEADER_LEN: usize = 12;
/// ペイロードの上限（確保の前に検証する。最大の kind が 8 バイト）。
pub const MAX_PAYLOAD: usize = 8;

const MAGIC: [u8; 4] = *b"FCDC";
const VERSION: u8 = 1;
const KIND_RELOAD: u8 = 1;
const KIND_LOADED: u8 = 2;
const KIND_STOP: u8 = 3;
const KIND_ERROR: u8 = 4;

fn bad(message: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, message)
}

/// 再読込の世代（0 でない乱数。送り手が作り、`Loaded` で同じ値が返ることを照合する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReloadGeneration(NonZeroU64);

impl ReloadGeneration {
    /// 0 を拒否して作る。
    pub fn new(v: u64) -> Result<Self, NetError> {
        NonZeroU64::new(v).map(Self).ok_or_else(|| {
            NetError::new(NetErrorCode::InvalidArgument, "reload generation is zero")
        })
    }

    /// 値。
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// `/dev/urandom` から作る（制御 UDS は Linux 限定）。
    #[cfg(target_os = "linux")]
    pub fn random() -> Result<Self, NetError> {
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|_| NetError::new(NetErrorCode::Internal, "cannot open the random source"))?;
        let mut b = [0u8; 8];
        for _ in 0..4 {
            f.read_exact(&mut b).map_err(|_| {
                NetError::new(NetErrorCode::Internal, "cannot read the random source")
            })?;
            if let Ok(g) = Self::new(u64::from_le_bytes(b)) {
                return Ok(g);
            }
        }
        Err(NetError::new(
            NetErrorCode::Internal,
            "random source returned zero repeatedly",
        ))
    }
}

/// 制御フレームが運ぶメッセージ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlMessage {
    /// 起動元 → ヘルパー。メンバー記録から名前を読み直す要求。
    Reload(ReloadGeneration),
    /// ヘルパー → 起動元。`Reload` の読み込みを終えた（同じ世代を返す）。
    Loaded(ReloadGeneration),
    /// 起動元 → ヘルパー。正常終了の要求。
    Stop,
    /// ヘルパー → 起動元。読み込みに失敗した（前のレジストリは保っている）。
    Error(NetErrorCode),
}

/// 符号化済みのフレーム（ヘッダー + 最大 8 バイトのペイロード）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    buf: [u8; HEADER_LEN + MAX_PAYLOAD],
    len: usize,
}

impl ControlFrame {
    /// メッセージからフレームを作る。
    pub fn encode(msg: ControlMessage) -> Self {
        let (kind, payload): (u8, Option<u64>) = match msg {
            ControlMessage::Reload(g) => (KIND_RELOAD, Some(g.get())),
            ControlMessage::Loaded(g) => (KIND_LOADED, Some(g.get())),
            ControlMessage::Stop => (KIND_STOP, None),
            ControlMessage::Error(c) => (KIND_ERROR, Some(code_to_wire(c))),
        };
        let payload_len: u32 = if payload.is_some() { 8 } else { 0 };
        let mut buf = [0u8; HEADER_LEN + MAX_PAYLOAD];
        let mut at = 0usize;
        let mut put = |chunk: &[u8]| {
            if let Some(dst) = buf.get_mut(at..at + chunk.len()) {
                dst.copy_from_slice(chunk);
            }
            at += chunk.len();
        };
        put(&MAGIC);
        put(&[VERSION, kind, 0, 0]);
        put(&payload_len.to_le_bytes());
        if let Some(p) = payload {
            put(&p.to_le_bytes());
        }
        Self { buf, len: at }
    }

    /// 送信するバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// ヘッダー 12 バイトを検証して、kind と続くペイロードの長さを返す。magic・version・kind・予約欄・長さ
    /// （kind ごとの期待値と [`MAX_PAYLOAD`]）のどれが外れても拒否する。ペイロードを読む前に呼ぶ。
    fn parse_header(h: &[u8; HEADER_LEN]) -> Result<(u8, usize), NetError> {
        if h.get(0..4) != Some(&MAGIC[..]) {
            return Err(bad("dns control frame has a bad magic"));
        }
        if h.get(4) != Some(&VERSION) {
            return Err(bad("dns control frame has an unsupported version"));
        }
        if h.get(6..8) != Some(&[0u8, 0u8][..]) {
            return Err(bad("dns control frame has a nonzero reserved field"));
        }
        let kind = h.get(5).copied().unwrap_or(0);
        let len = h
            .get(8..12)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| bad("dns control frame header is truncated"))?;
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_PAYLOAD {
            return Err(bad("dns control frame payload exceeds the limit"));
        }
        let want = match kind {
            KIND_RELOAD | KIND_LOADED | KIND_ERROR => 8,
            KIND_STOP => 0,
            _ => return Err(bad("dns control frame has an unknown kind")),
        };
        if len != want {
            return Err(bad(
                "dns control frame payload length does not match its kind",
            ));
        }
        Ok((kind, len))
    }

    fn build(kind: u8, payload: &[u8]) -> Result<ControlMessage, NetError> {
        let value = || -> Result<u64, NetError> {
            payload
                .get(..8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_le_bytes)
                .ok_or_else(|| bad("dns control frame payload is truncated"))
        };
        let generation = || {
            ReloadGeneration::new(value()?)
                .map_err(|_| bad("dns control frame has a zero generation"))
        };
        match kind {
            KIND_RELOAD => Ok(ControlMessage::Reload(generation()?)),
            KIND_LOADED => Ok(ControlMessage::Loaded(generation()?)),
            KIND_STOP => Ok(ControlMessage::Stop),
            KIND_ERROR => code_from_wire(value()?)
                .map(ControlMessage::Error)
                .ok_or_else(|| bad("dns control frame has an unknown error code")),
            _ => Err(bad("dns control frame has an unknown kind")),
        }
    }

    /// バイト列全体（ヘッダー + ペイロード）を復号する。余りや不足は拒否する。
    pub fn decode(bytes: &[u8]) -> Result<ControlMessage, NetError> {
        let h = bytes
            .get(..HEADER_LEN)
            .and_then(|b| <&[u8; HEADER_LEN]>::try_from(b).ok())
            .ok_or_else(|| bad("dns control frame is shorter than its header"))?;
        let (kind, len) = Self::parse_header(h)?;
        let payload = bytes.get(HEADER_LEN..).unwrap_or(&[]);
        if payload.len() != len {
            return Err(bad("dns control frame length does not match its header"));
        }
        Self::build(kind, payload)
    }

    /// ストリームから 1 フレーム読む。ヘッダーを検証して長さを確かめてからペイロードを固定長の配列へ読む
    /// （確保なし）。EOF・時間切れ・不正は `Err`（`io` の分類は呼び出し側が写す）。
    pub fn read_from(r: &mut impl Read) -> Result<ControlMessage, ReadError> {
        let mut h = [0u8; HEADER_LEN];
        r.read_exact(&mut h).map_err(ReadError::Io)?;
        let (kind, len) = Self::parse_header(&h).map_err(ReadError::Invalid)?;
        let mut p = [0u8; MAX_PAYLOAD];
        let dst = p.get_mut(..len).ok_or_else(|| {
            ReadError::Invalid(bad("dns control frame payload exceeds the limit"))
        })?;
        r.read_exact(dst).map_err(ReadError::Io)?;
        Self::build(kind, p.get(..len).unwrap_or(&[])).map_err(ReadError::Invalid)
    }

    /// ストリームへ書く。
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(self.as_bytes())
    }
}

/// [`ControlFrame::read_from`] の失敗。
#[derive(Debug)]
pub enum ReadError {
    /// 読み取りの失敗（EOF・時間切れ・切断）。
    Io(io::Error),
    /// フレームの検証の失敗。
    Invalid(NetError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: u64) -> ReloadGeneration {
        ReloadGeneration::new(v).expect("generation")
    }

    /// NET-5・REPAIR-2・#3071: 各メッセージの具体的なバイト列。
    #[test]
    fn net5_3071_frame_encodes_exact_bytes() {
        let reload = ControlFrame::encode(ControlMessage::Reload(g(0x0102_0304_0506_0708)));
        assert_eq!(
            reload.as_bytes(),
            &[
                b'F', b'C', b'D', b'C', 1, 1, 0, 0, 8, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1
            ]
        );
        let loaded = ControlFrame::encode(ControlMessage::Loaded(g(1)));
        assert_eq!(
            loaded.as_bytes(),
            &[
                b'F', b'C', b'D', b'C', 1, 2, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let stop = ControlFrame::encode(ControlMessage::Stop);
        assert_eq!(
            stop.as_bytes(),
            &[b'F', b'C', b'D', b'C', 1, 3, 0, 0, 0, 0, 0, 0]
        );
        let error = ControlFrame::encode(ControlMessage::Error(NetErrorCode::DataLoss));
        assert_eq!(
            error.as_bytes(),
            &[
                b'F', b'C', b'D', b'C', 1, 4, 0, 0, 8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    /// NET-5・REPAIR-2・#3071: 符号化と復号は往復で一致する。
    #[test]
    fn net5_3071_frame_round_trips() {
        let mut msgs = vec![
            ControlMessage::Reload(g(7)),
            ControlMessage::Loaded(g(u64::MAX)),
            ControlMessage::Stop,
        ];
        for c in [
            NetErrorCode::InvalidArgument,
            NetErrorCode::DataLoss,
            NetErrorCode::Timeout,
            NetErrorCode::FailedPrecondition,
            NetErrorCode::Internal,
        ] {
            msgs.push(ControlMessage::Error(c));
        }
        for m in msgs {
            let f = ControlFrame::encode(m);
            assert_eq!(ControlFrame::decode(f.as_bytes()).expect("decode"), m);
            let mut cur = io::Cursor::new(f.as_bytes().to_vec());
            assert_eq!(ControlFrame::read_from(&mut cur).expect("read"), m);
        }
    }

    fn reload_bytes() -> Vec<u8> {
        ControlFrame::encode(ControlMessage::Reload(g(5)))
            .as_bytes()
            .to_vec()
    }

    fn rejected(bytes: &[u8]) {
        let e = ControlFrame::decode(bytes).expect_err("must reject");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-5・REPAIR-2・#3071: magic・version・reserved・kind・長さ違い・generation 0 を拒否する。
    #[test]
    fn net5_3071_frame_rejects_malformed() {
        let mut b = reload_bytes();
        b[0] = b'X';
        rejected(&b);
        let mut b = reload_bytes();
        b[4] = 2;
        rejected(&b);
        let mut b = reload_bytes();
        b[6] = 1;
        rejected(&b);
        let mut b = reload_bytes();
        b[5] = 9;
        rejected(&b);
        // Stop に payload がある。
        let mut b = ControlFrame::encode(ControlMessage::Stop)
            .as_bytes()
            .to_vec();
        b[8] = 8;
        b.extend_from_slice(&[0; 8]);
        rejected(&b);
        // Reload の payload が短い。
        let mut b = reload_bytes();
        b[8] = 4;
        b.truncate(HEADER_LEN + 4);
        rejected(&b);
        // generation 0。
        let mut b = reload_bytes();
        for x in b.iter_mut().skip(HEADER_LEN) {
            *x = 0;
        }
        rejected(&b);
        // 余りがある。
        let mut b = reload_bytes();
        b.push(0);
        rejected(&b);
        // ヘッダーより短い。
        rejected(&[0u8; 5]);
        // 未知のエラーコード。
        let mut b = ControlFrame::encode(ControlMessage::Error(NetErrorCode::DataLoss))
            .as_bytes()
            .to_vec();
        b[12] = 99;
        rejected(&b);
    }

    /// NET-5・REPAIR-2・#3071: `payload_len` が上限を超えるフレームは、ペイロードを読む前に拒否する。
    #[test]
    fn net5_3071_frame_oversized_length_is_rejected_before_payload() {
        let mut h = reload_bytes();
        h.truncate(HEADER_LEN);
        h[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut cur = io::Cursor::new(h);
        match ControlFrame::read_from(&mut cur) {
            Err(ReadError::Invalid(e)) => {
                assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
                assert!(e.message().contains("exceeds the limit"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        // 読んだのはヘッダーだけ（ペイロードの読み取りに進んでいない）。
        assert_eq!(cur.position(), HEADER_LEN as u64);
    }

    /// NET-5・#3071: 世代 0 は作れない。
    #[test]
    fn net5_3071_generation_zero_is_invalid() {
        assert_eq!(
            ReloadGeneration::new(0).expect_err("zero").code(),
            NetErrorCode::InvalidArgument
        );
    }

    /// NET-5・#3071: ヘッダーの途中で切れたストリームは Io（EOF）。
    #[test]
    fn net5_3071_frame_truncated_stream_is_io_error() {
        let mut cur = io::Cursor::new(reload_bytes()[..6].to_vec());
        assert!(matches!(
            ControlFrame::read_from(&mut cur),
            Err(ReadError::Io(_))
        ));
    }
}
