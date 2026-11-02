//! SPDY/3.1 のフレーム codec（CRI-6・TASK-63.3・#681。設計記録は `docs/design/cri-streaming-server.md`）。
//!
//! kubelet / crictl が `Attach`・`Exec`・`PortForward` で使う Upgrade 後のワイヤー形式（`Upgrade: SPDY/3.1`）を、
//! バイト列と型付きの [`Frame`] の間で変換する。呼び出し元は `streaming::attach` のセッションと、将来の Exec
//! （#680）・PortForward（#682）。HTTP の Upgrade・`streamType` の割り当て・k8s のサブプロトコルは
//! `streaming::remotecommand` が持ち、本モジュールは SPDY の層だけを扱う。
//!
//! ## 形式（SPDY/3 draft。SPDY/3.1 もフレームの版は 3）
//!
//! - 制御フレーム: `1 | version(15) | type(16) | flags(8) | length(24) | payload`
//! - データフレーム: `0 | stream-id(31) | flags(8) | length(24) | payload`
//! - ヘッダブロック: `count(32)` の後に `name-len(32) name value-len(32) value` を繰り返し、
//!   送信方向ごとにセッション全体で 1 つの zlib ストリーム（SPDY/3 の辞書つき）で圧縮する。
//!   ブロックごとに `Z_SYNC_FLUSH` で区切る。複数値は NUL 区切りで 1 つの値に入れる。
//! - 一次情報: moby/spdystream の `spdy/read.go`・`write.go`（commit c59e5d73daa301bde452ea77545bdf51e32554a2）で
//!   バイト配置を確認した。Python の zlib（辞書つき）が作ったブロックを復号する試験で他実装との互換を固定している
//!
//! ## 安全側の上限（外部入力。REPAIR-5）
//!
//! フレーム長（[`MAX_INCOMING_PAYLOAD`]）は確保の前に検査する。ヘッダブロックは展開後のサイズ
//! （[`MAX_HEADER_BLOCK`]）・組数（[`MAX_HEADER_COUNT`]）に上限があり、zlib bomb は上限に達した時点で拒否する。
//! 違反はすべて [`SpdyError`] になり、呼び出し側が GOAWAY で接続を閉じる（部分的に解釈して続行しない）。
//!
//! ## flow control を送信側で強制しない（draft からの意図的な逸脱）
//!
//! SPDY/3.1 は窓（既定 64 KiB）を超える DATA の送信を禁じる。しかし実際のクライアント（client-go が使う
//! moby/spdystream）は flow control を実装せず、WINDOW_UPDATE を送らず、受け取っても「unhandled frame type」として
//! 捨てる。窓を強制すると 64 KiB を送った時点で永久に止まるため、本実装は WINDOW_UPDATE と SETTINGS を
//! 受理して無視し、DATA の送信を窓で止めない。代わりに送信側の滞留はセッションの出力バッファ上限で、
//! 受信側の滞留は stdin の滞留上限（`attach.rs`）で有界にする。

use std::fmt;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use super::spdy_dictionary::SPDY3_DICTIONARY;

/// SPDY/3 の辞書の Adler-32（zlib ヘッダの DICTID。辞書の取り違え検出に使う）。
pub const DICTIONARY_ADLER32: u32 = 0xe3c6_a7c2;
/// フレームに載る版。SPDY/3.1 も 3 のまま（3.1 は flow control の拡張）。
const SPDY_VERSION: u16 = 3;
/// ストリーム ID の最大値（31 ビット）。
pub const MAX_STREAM_ID: u32 = 0x7fff_ffff;
/// 受信するフレームのペイロードの最大バイト数。長さは確保の前に検査する。
pub const MAX_INCOMING_PAYLOAD: usize = 256 * 1024;
/// 送信する DATA フレームの 1 つあたりの最大バイト数（これを超える分は呼び出し側が分割する）。
pub const MAX_OUTGOING_DATA: usize = 32 * 1024;
/// ヘッダブロックの展開後の最大バイト数（zlib bomb 対策）。
pub const MAX_HEADER_BLOCK: usize = 16 * 1024;
/// ヘッダの組の最大件数。
pub const MAX_HEADER_COUNT: usize = 64;
/// SETTINGS のエントリの最大件数。
const MAX_SETTINGS_ENTRIES: usize = 64;
/// 24 ビットの長さの最大値。
const MAX_LENGTH_24: usize = 0x00ff_ffff;

/// 制御フレームの type（draft の値）。
const TYPE_SYN_STREAM: u16 = 1;
const TYPE_SYN_REPLY: u16 = 2;
const TYPE_RST_STREAM: u16 = 3;
const TYPE_SETTINGS: u16 = 4;
const TYPE_PING: u16 = 6;
const TYPE_GOAWAY: u16 = 7;
const TYPE_HEADERS: u16 = 8;
const TYPE_WINDOW_UPDATE: u16 = 9;

/// FLAG_FIN（SYN_STREAM・SYN_REPLY・HEADERS・DATA）。
const FLAG_FIN: u8 = 0x01;
/// FLAG_UNIDIRECTIONAL（SYN_STREAM）。
const FLAG_UNIDIRECTIONAL: u8 = 0x02;
/// FLAG_SETTINGS_CLEAR_SETTINGS（SETTINGS）。
const FLAG_CLEAR_SETTINGS: u8 = 0x01;

/// RST_STREAM のステータスコード（draft の値）。
pub mod rst_status {
    /// PROTOCOL_ERROR。
    pub const PROTOCOL_ERROR: u32 = 1;
    /// INVALID_STREAM。
    pub const INVALID_STREAM: u32 = 2;
    /// REFUSED_STREAM。
    pub const REFUSED_STREAM: u32 = 3;
    /// CANCEL。
    pub const CANCEL: u32 = 5;
    /// INTERNAL_ERROR。
    pub const INTERNAL_ERROR: u32 = 6;
    /// STREAM_IN_USE。
    pub const STREAM_IN_USE: u32 = 8;
    /// STREAM_ALREADY_CLOSED。
    pub const STREAM_ALREADY_CLOSED: u32 = 9;
}

/// GOAWAY のステータスコード（draft の値）。
pub mod goaway_status {
    /// OK（正常終了）。
    pub const OK: u32 = 0;
    /// PROTOCOL_ERROR。
    pub const PROTOCOL_ERROR: u32 = 1;
    /// INTERNAL_ERROR。
    pub const INTERNAL_ERROR: u32 = 11;
}

/// SPDY の層の失敗。理由は固定の英語で、入力値を含めない（REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdyError {
    /// フレームの版が 3 ではない。
    UnsupportedVersion,
    /// フレーム長が上限を超えた。
    FrameTooLarge,
    /// フレームの構造が壊れている（長さの不一致・ID 0・重複ヘッダ等）。
    InvalidFrame(&'static str),
    /// ヘッダブロックの展開後のサイズまたは件数が上限を超えた。
    HeaderBlockTooLarge,
    /// ヘッダブロックの zlib 展開・圧縮に失敗した。
    Compression(&'static str),
}

impl fmt::Display for SpdyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpdyError::UnsupportedVersion => f.write_str("unsupported spdy version"),
            SpdyError::FrameTooLarge => f.write_str("spdy frame is too large"),
            SpdyError::InvalidFrame(why) => write!(f, "invalid spdy frame: {why}"),
            SpdyError::HeaderBlockTooLarge => f.write_str("spdy header block is too large"),
            SpdyError::Compression(why) => write!(f, "spdy header compression failed: {why}"),
        }
    }
}

impl std::error::Error for SpdyError {}

/// 0 でも MSB 付きでもないストリーム ID（31 ビット）。壊れた ID を型で表せなくする（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u32);

impl StreamId {
    /// `1..=MAX_STREAM_ID` だけ受理する。
    pub fn new(raw: u32) -> Option<Self> {
        (1..=MAX_STREAM_ID).contains(&raw).then_some(Self(raw))
    }

    /// 生の値。
    pub fn get(self) -> u32 {
        self.0
    }
}

/// ヘッダの組（名前は小文字へ正規化済み。値の複数値は NUL 区切りのまま）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// 空のヘッダ。
    pub fn new() -> Self {
        Self::default()
    }

    /// 組を足す（名前は小文字にする）。
    pub fn push(&mut self, name: &str, value: &str) {
        self.0.push((name.to_ascii_lowercase(), value.to_string()));
    }

    /// 名前（小文字）の最初の値。
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// 組の件数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 全組を順に返す。
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }
}

/// SETTINGS の 1 エントリ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// エントリのフラグ。
    pub flags: u8,
    /// 設定 ID（24 ビット）。
    pub id: u32,
    /// 値。
    pub value: u32,
}

/// 型付きのフレーム。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// SYN_STREAM（ストリームを開く）。
    SynStream {
        /// 開くストリーム。
        stream_id: StreamId,
        /// 関連ストリーム（0 は無し）。
        associated_to: u32,
        /// 優先度（0..=7）。
        priority: u8,
        /// FLAG_FIN。
        fin: bool,
        /// FLAG_UNIDIRECTIONAL。
        unidirectional: bool,
        /// ヘッダ。
        headers: Headers,
    },
    /// SYN_REPLY（ストリームの開設への応答）。
    SynReply {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// FLAG_FIN。
        fin: bool,
        /// ヘッダ。
        headers: Headers,
    },
    /// RST_STREAM（ストリームの異常終了）。
    RstStream {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// [`rst_status`] の値。
        status: u32,
    },
    /// SETTINGS。
    Settings {
        /// FLAG_SETTINGS_CLEAR_SETTINGS。
        clear: bool,
        /// エントリ。
        entries: Vec<Setting>,
    },
    /// PING（受け取った ID をそのまま返す）。
    Ping {
        /// 識別子。
        id: u32,
    },
    /// GOAWAY（セッションの終了）。
    GoAway {
        /// 処理済みの最後のストリーム。
        last_good_stream_id: u32,
        /// [`goaway_status`] の値。
        status: u32,
    },
    /// HEADERS（ストリームへの追加ヘッダ）。
    Headers {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// FLAG_FIN。
        fin: bool,
        /// ヘッダ。
        headers: Headers,
    },
    /// WINDOW_UPDATE（0 はセッション窓）。本実装は強制しない（モジュール doc）。
    WindowUpdate {
        /// 対象ストリーム（0 はセッション）。
        stream_id: u32,
        /// 窓の増分。
        delta: u32,
    },
    /// DATA。
    Data {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// FLAG_FIN（この方向の終端）。
        fin: bool,
        /// ペイロード。
        data: Vec<u8>,
    },
    /// 未知の制御フレーム（CREDENTIAL 等。draft に従い無視する）。
    Unknown {
        /// 制御フレームの type。
        frame_type: u16,
    },
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(at..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn read_u24(buf: &[u8], at: usize) -> Option<usize> {
    let bytes: [u8; 3] = buf.get(at..at.checked_add(3)?)?.try_into().ok()?;
    let [a, b, c] = bytes;
    Some((usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c))
}

fn nonzero_stream_id(raw: u32) -> Result<StreamId, SpdyError> {
    StreamId::new(raw & MAX_STREAM_ID).ok_or(SpdyError::InvalidFrame("stream id is zero"))
}

fn dictionary_error<T>() -> Result<T, SpdyError> {
    Err(SpdyError::Compression("unexpected dictionary id"))
}

/// フレーム列を復号する。受信バイトを [`Self::extend`] で渡し、[`Self::next_frame`] で 1 フレームずつ取り出す。
///
/// ヘッダブロックの展開状態（zlib ストリーム）を持つため、1 セッションの受信方向ごとに 1 つ使う。
pub struct FrameDecoder {
    buf: Vec<u8>,
    start: usize,
    zlib: Decompress,
}

impl fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("buffered", &self.buffered_len())
            .finish()
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// 空の復号器を作る。
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            zlib: Decompress::new(true),
        }
    }

    /// まだフレームになっていない受信済みバイト数。
    pub fn buffered_len(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }

    /// 受信したバイトを足す。呼び出し側は 1 回の読み取りを小さく保つこと（確保の上限は呼び出し側の責務）。
    pub fn extend(&mut self, bytes: &[u8]) {
        if self.start > 0 && (self.start >= self.buf.len() || self.start >= 8192) {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// 完全なフレームが溜まっていれば 1 つ取り出す。足りなければ `Ok(None)`。
    pub fn next_frame(&mut self) -> Result<Option<Frame>, SpdyError> {
        let pending = self.buf.get(self.start..).unwrap_or(&[]);
        let Some(first) = pending.first().copied() else {
            return Ok(None);
        };
        if pending.len() < 8 {
            return Ok(None);
        }
        let is_control = first & 0x80 != 0;
        let flags = pending.get(4).copied().unwrap_or(0);
        let length = read_u24(pending, 5).ok_or(SpdyError::InvalidFrame("short header"))?;
        if length > MAX_INCOMING_PAYLOAD {
            return Err(SpdyError::FrameTooLarge);
        }
        let total = 8usize.checked_add(length).ok_or(SpdyError::FrameTooLarge)?;
        if pending.len() < total {
            return Ok(None);
        }
        let header = pending
            .get(..8)
            .ok_or(SpdyError::InvalidFrame("short header"))?;
        let payload = pending
            .get(8..total)
            .ok_or(SpdyError::InvalidFrame("short payload"))?
            .to_vec();
        let word0 = read_u32(header, 0).ok_or(SpdyError::InvalidFrame("short header"))?;
        self.start += total;
        if !is_control {
            let stream_id = nonzero_stream_id(word0)?;
            return Ok(Some(Frame::Data {
                stream_id,
                fin: flags & FLAG_FIN != 0,
                data: payload,
            }));
        }
        let version = u16::try_from((word0 >> 16) & 0x7fff).unwrap_or(0);
        if version != SPDY_VERSION {
            return Err(SpdyError::UnsupportedVersion);
        }
        let frame_type = u16::try_from(word0 & 0xffff).unwrap_or(0);
        self.control_frame(frame_type, flags, &payload).map(Some)
    }

    fn control_frame(
        &mut self,
        frame_type: u16,
        flags: u8,
        payload: &[u8],
    ) -> Result<Frame, SpdyError> {
        let fin = flags & FLAG_FIN != 0;
        match frame_type {
            TYPE_SYN_STREAM => {
                // stream-id(4) + associated(4) + priority/unused(1) + slot(1) + header block。
                if payload.len() < 10 {
                    return Err(SpdyError::InvalidFrame("syn_stream is too short"));
                }
                let stream_id = nonzero_stream_id(read_u32(payload, 0).unwrap_or(0))?;
                let associated_to = read_u32(payload, 4).unwrap_or(0) & MAX_STREAM_ID;
                let priority = payload.get(8).copied().unwrap_or(0) >> 5;
                let block = payload.get(10..).unwrap_or(&[]);
                let headers = self.decode_header_block(block)?;
                Ok(Frame::SynStream {
                    stream_id,
                    associated_to,
                    priority,
                    fin,
                    unidirectional: flags & FLAG_UNIDIRECTIONAL != 0,
                    headers,
                })
            }
            TYPE_SYN_REPLY | TYPE_HEADERS => {
                if payload.len() < 4 {
                    return Err(SpdyError::InvalidFrame("header frame is too short"));
                }
                let stream_id = nonzero_stream_id(read_u32(payload, 0).unwrap_or(0))?;
                let headers = self.decode_header_block(payload.get(4..).unwrap_or(&[]))?;
                if frame_type == TYPE_SYN_REPLY {
                    Ok(Frame::SynReply {
                        stream_id,
                        fin,
                        headers,
                    })
                } else {
                    Ok(Frame::Headers {
                        stream_id,
                        fin,
                        headers,
                    })
                }
            }
            TYPE_RST_STREAM => {
                if payload.len() != 8 {
                    return Err(SpdyError::InvalidFrame("rst_stream length"));
                }
                Ok(Frame::RstStream {
                    stream_id: nonzero_stream_id(read_u32(payload, 0).unwrap_or(0))?,
                    status: read_u32(payload, 4).unwrap_or(0),
                })
            }
            TYPE_SETTINGS => {
                let count = read_u32(payload, 0)
                    .and_then(|c| usize::try_from(c).ok())
                    .ok_or(SpdyError::InvalidFrame("settings is too short"))?;
                if count > MAX_SETTINGS_ENTRIES
                    || payload.len() != count.saturating_mul(8).saturating_add(4)
                {
                    return Err(SpdyError::InvalidFrame("settings length"));
                }
                let mut entries = Vec::with_capacity(count);
                for i in 0..count {
                    let at = 4 + i * 8;
                    let word = read_u32(payload, at).unwrap_or(0);
                    entries.push(Setting {
                        flags: u8::try_from(word >> 24).unwrap_or(0),
                        id: word & 0x00ff_ffff,
                        value: read_u32(payload, at + 4).unwrap_or(0),
                    });
                }
                Ok(Frame::Settings {
                    clear: flags & FLAG_CLEAR_SETTINGS != 0,
                    entries,
                })
            }
            TYPE_PING => {
                if payload.len() != 4 {
                    return Err(SpdyError::InvalidFrame("ping length"));
                }
                Ok(Frame::Ping {
                    id: read_u32(payload, 0).unwrap_or(0),
                })
            }
            TYPE_GOAWAY => {
                if payload.len() != 8 {
                    return Err(SpdyError::InvalidFrame("goaway length"));
                }
                Ok(Frame::GoAway {
                    last_good_stream_id: read_u32(payload, 0).unwrap_or(0) & MAX_STREAM_ID,
                    status: read_u32(payload, 4).unwrap_or(0),
                })
            }
            TYPE_WINDOW_UPDATE => {
                if payload.len() != 8 {
                    return Err(SpdyError::InvalidFrame("window_update length"));
                }
                Ok(Frame::WindowUpdate {
                    stream_id: read_u32(payload, 0).unwrap_or(0) & MAX_STREAM_ID,
                    delta: read_u32(payload, 4).unwrap_or(0) & MAX_STREAM_ID,
                })
            }
            other => Ok(Frame::Unknown { frame_type: other }),
        }
    }

    /// 圧縮されたヘッダブロックを展開して組へ分解する。展開後のサイズは [`MAX_HEADER_BLOCK`] で打ち切る。
    fn decode_header_block(&mut self, block: &[u8]) -> Result<Headers, SpdyError> {
        let raw = self.inflate(block)?;
        let count = read_u32(&raw, 0)
            .and_then(|c| usize::try_from(c).ok())
            .ok_or(SpdyError::InvalidFrame("header block is too short"))?;
        if count > MAX_HEADER_COUNT {
            return Err(SpdyError::HeaderBlockTooLarge);
        }
        let mut at = 4usize;
        let mut headers = Headers::new();
        for _ in 0..count {
            let name = read_chunk(&raw, &mut at)?;
            let value = read_chunk(&raw, &mut at)?;
            let name = std::str::from_utf8(name)
                .map_err(|_| SpdyError::InvalidFrame("header name is not utf-8"))?
                .to_ascii_lowercase();
            let value = std::str::from_utf8(value)
                .map_err(|_| SpdyError::InvalidFrame("header value is not utf-8"))?;
            if name.is_empty() {
                return Err(SpdyError::InvalidFrame("header name is empty"));
            }
            if headers.get(&name).is_some() {
                return Err(SpdyError::InvalidFrame("duplicate header name"));
            }
            headers.0.push((name, value.to_string()));
        }
        if at != raw.len() {
            return Err(SpdyError::InvalidFrame("trailing bytes in header block"));
        }
        Ok(headers)
    }

    fn inflate(&mut self, block: &[u8]) -> Result<Vec<u8>, SpdyError> {
        // 容量を上限 + 1 に固定し、満杯になった時点で拒否する（zlib bomb。`decompress_vec` は容量を超えて伸ばさない）。
        let mut out: Vec<u8> = Vec::with_capacity(MAX_HEADER_BLOCK + 1);
        let start_in = self.zlib.total_in();
        let mut dictionary_set = false;
        loop {
            let consumed = usize::try_from(self.zlib.total_in().saturating_sub(start_in))
                .map_err(|_| SpdyError::Compression("input size"))?;
            let rest = block.get(consumed..).unwrap_or(&[]);
            let before = (self.zlib.total_in(), self.zlib.total_out());
            match self
                .zlib
                .decompress_vec(rest, &mut out, FlushDecompress::Sync)
            {
                Ok(Status::StreamEnd) => {
                    return Err(SpdyError::Compression("unexpected end of zlib stream"));
                }
                Ok(_) => {}
                Err(e) => {
                    let Some(adler) = e.needs_dictionary() else {
                        return Err(SpdyError::Compression("invalid zlib data"));
                    };
                    if adler != DICTIONARY_ADLER32 || dictionary_set {
                        return dictionary_error();
                    }
                    self.zlib
                        .set_dictionary(SPDY3_DICTIONARY)
                        .map_err(|_| SpdyError::Compression("dictionary rejected"))?;
                    dictionary_set = true;
                    continue;
                }
            }
            if out.len() > MAX_HEADER_BLOCK {
                return Err(SpdyError::HeaderBlockTooLarge);
            }
            let after = (self.zlib.total_in(), self.zlib.total_out());
            let consumed_all = usize::try_from(after.0.saturating_sub(start_in))
                .map(|c| c >= block.len())
                .unwrap_or(false);
            // 入力を使い切り、かつ出力に余地が残っている（取りこぼしが無い）なら終わり。
            if consumed_all && out.len() < out.capacity() {
                return Ok(out);
            }
            if after == before && !consumed_all {
                return Err(SpdyError::Compression("zlib made no progress"));
            }
        }
    }
}

fn read_chunk<'a>(raw: &'a [u8], at: &mut usize) -> Result<&'a [u8], SpdyError> {
    let len = read_u32(raw, *at)
        .and_then(|l| usize::try_from(l).ok())
        .ok_or(SpdyError::InvalidFrame("header block is truncated"))?;
    let begin = at
        .checked_add(4)
        .ok_or(SpdyError::InvalidFrame("header block is truncated"))?;
    let end = begin
        .checked_add(len)
        .ok_or(SpdyError::InvalidFrame("header block is truncated"))?;
    let chunk = raw
        .get(begin..end)
        .ok_or(SpdyError::InvalidFrame("header block is truncated"))?;
    *at = end;
    Ok(chunk)
}

/// フレーム列を符号化する。ヘッダブロックの圧縮状態を持つため、1 セッションの送信方向ごとに 1 つ使う。
pub struct FrameEncoder {
    zlib: Compress,
}

impl fmt::Debug for FrameEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FrameEncoder")
    }
}

impl Default for FrameEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameEncoder {
    /// 辞書を設定済みの符号化器を作る。
    pub fn new() -> Self {
        let mut zlib = Compress::new(Compression::default(), true);
        // 辞書は固定の定数で、最初の圧縮の前に設定すれば失敗しない。失敗すれば辞書なしの別形式になるため
        // 後続の `encode` で必ず検出できるよう、結果の Adler-32 を保持せず試験で固定する。
        let _ = zlib.set_dictionary(SPDY3_DICTIONARY);
        Self { zlib }
    }

    /// フレームを符号化して `out` の末尾へ足す。
    pub fn encode(&mut self, frame: &Frame, out: &mut Vec<u8>) -> Result<(), SpdyError> {
        match frame {
            Frame::SynStream {
                stream_id,
                associated_to,
                priority,
                fin,
                unidirectional,
                headers,
            } => {
                let block = self.header_block(headers)?;
                let mut flags = if *fin { FLAG_FIN } else { 0 };
                if *unidirectional {
                    flags |= FLAG_UNIDIRECTIONAL;
                }
                control_header(out, TYPE_SYN_STREAM, flags, 10 + block.len())?;
                out.extend_from_slice(&stream_id.get().to_be_bytes());
                out.extend_from_slice(&(associated_to & MAX_STREAM_ID).to_be_bytes());
                out.push((priority & 0x07) << 5);
                out.push(0);
                out.extend_from_slice(&block);
            }
            Frame::SynReply {
                stream_id,
                fin,
                headers,
            }
            | Frame::Headers {
                stream_id,
                fin,
                headers,
            } => {
                let frame_type = if matches!(frame, Frame::SynReply { .. }) {
                    TYPE_SYN_REPLY
                } else {
                    TYPE_HEADERS
                };
                let block = self.header_block(headers)?;
                control_header(
                    out,
                    frame_type,
                    if *fin { FLAG_FIN } else { 0 },
                    4 + block.len(),
                )?;
                out.extend_from_slice(&stream_id.get().to_be_bytes());
                out.extend_from_slice(&block);
            }
            Frame::RstStream { stream_id, status } => {
                control_header(out, TYPE_RST_STREAM, 0, 8)?;
                out.extend_from_slice(&stream_id.get().to_be_bytes());
                out.extend_from_slice(&status.to_be_bytes());
            }
            Frame::Settings { clear, entries } => {
                if entries.len() > MAX_SETTINGS_ENTRIES {
                    return Err(SpdyError::InvalidFrame("too many settings"));
                }
                let flags = if *clear { FLAG_CLEAR_SETTINGS } else { 0 };
                control_header(out, TYPE_SETTINGS, flags, 4 + entries.len() * 8)?;
                let count = u32::try_from(entries.len())
                    .map_err(|_| SpdyError::InvalidFrame("too many settings"))?;
                out.extend_from_slice(&count.to_be_bytes());
                for entry in entries {
                    let word = (u32::from(entry.flags) << 24) | (entry.id & 0x00ff_ffff);
                    out.extend_from_slice(&word.to_be_bytes());
                    out.extend_from_slice(&entry.value.to_be_bytes());
                }
            }
            Frame::Ping { id } => {
                control_header(out, TYPE_PING, 0, 4)?;
                out.extend_from_slice(&id.to_be_bytes());
            }
            Frame::GoAway {
                last_good_stream_id,
                status,
            } => {
                control_header(out, TYPE_GOAWAY, 0, 8)?;
                out.extend_from_slice(&(last_good_stream_id & MAX_STREAM_ID).to_be_bytes());
                out.extend_from_slice(&status.to_be_bytes());
            }
            Frame::WindowUpdate { stream_id, delta } => {
                control_header(out, TYPE_WINDOW_UPDATE, 0, 8)?;
                out.extend_from_slice(&(stream_id & MAX_STREAM_ID).to_be_bytes());
                out.extend_from_slice(&(delta & MAX_STREAM_ID).to_be_bytes());
            }
            Frame::Data {
                stream_id,
                fin,
                data,
            } => {
                if data.len() > MAX_LENGTH_24 {
                    return Err(SpdyError::FrameTooLarge);
                }
                out.extend_from_slice(&stream_id.get().to_be_bytes());
                let word = (if *fin { u32::from(FLAG_FIN) } else { 0 } << 24)
                    | u32::try_from(data.len()).map_err(|_| SpdyError::FrameTooLarge)?;
                out.extend_from_slice(&word.to_be_bytes());
                out.extend_from_slice(data);
            }
            Frame::Unknown { .. } => {
                return Err(SpdyError::InvalidFrame("cannot encode an unknown frame"));
            }
        }
        Ok(())
    }

    fn header_block(&mut self, headers: &Headers) -> Result<Vec<u8>, SpdyError> {
        if headers.len() > MAX_HEADER_COUNT {
            return Err(SpdyError::HeaderBlockTooLarge);
        }
        let mut raw = Vec::new();
        let count = u32::try_from(headers.len()).map_err(|_| SpdyError::HeaderBlockTooLarge)?;
        raw.extend_from_slice(&count.to_be_bytes());
        for (name, value) in headers.iter() {
            for part in [name, value] {
                let len = u32::try_from(part.len()).map_err(|_| SpdyError::HeaderBlockTooLarge)?;
                raw.extend_from_slice(&len.to_be_bytes());
                raw.extend_from_slice(part.as_bytes());
            }
            if raw.len() > MAX_HEADER_BLOCK {
                return Err(SpdyError::HeaderBlockTooLarge);
            }
        }
        self.deflate(&raw)
    }

    /// `input` を 1 ブロックとして `Z_SYNC_FLUSH` まで圧縮する。
    fn deflate(&mut self, input: &[u8]) -> Result<Vec<u8>, SpdyError> {
        let mut out: Vec<u8> = Vec::with_capacity(input.len() + input.len() / 8 + 64);
        let start_in = self.zlib.total_in();
        // 反復回数に上限を置く（zlib が進まない場合のハング防止。REPAIR-5）。
        for _ in 0..64 {
            let consumed = usize::try_from(self.zlib.total_in().saturating_sub(start_in))
                .map_err(|_| SpdyError::Compression("input size"))?;
            let rest = input.get(consumed..).unwrap_or(&[]);
            if out.capacity() - out.len() < 64 {
                out.reserve(256);
            }
            self.zlib
                .compress_vec(rest, &mut out, FlushCompress::Sync)
                .map_err(|_| SpdyError::Compression("compress failed"))?;
            let consumed_all = usize::try_from(self.zlib.total_in().saturating_sub(start_in))
                .map(|c| c >= input.len())
                .unwrap_or(false);
            if consumed_all && out.len() < out.capacity() {
                return Ok(out);
            }
        }
        Err(SpdyError::Compression("compress made no progress"))
    }
}

fn control_header(
    out: &mut Vec<u8>,
    frame_type: u16,
    flags: u8,
    payload_len: usize,
) -> Result<(), SpdyError> {
    if payload_len > MAX_LENGTH_24 {
        return Err(SpdyError::FrameTooLarge);
    }
    let word0 = 0x8000_0000u32 | (u32::from(SPDY_VERSION) << 16) | u32::from(frame_type);
    let word1 = (u32::from(flags) << 24)
        | u32::try_from(payload_len).map_err(|_| SpdyError::FrameTooLarge)?;
    out.extend_from_slice(&word0.to_be_bytes());
    out.extend_from_slice(&word1.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn sid(n: u32) -> StreamId {
        StreamId::new(n).expect("stream id")
    }

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        let mut h = Headers::new();
        for (n, v) in pairs {
            h.push(n, v);
        }
        h
    }

    fn roundtrip(frame: &Frame) -> Frame {
        let mut out = Vec::new();
        FrameEncoder::new().encode(frame, &mut out).expect("encode");
        let mut dec = FrameDecoder::new();
        dec.extend(&out);
        let got = dec.next_frame().expect("decode").expect("one frame");
        assert_eq!(dec.next_frame().expect("no error"), None);
        got
    }

    /// SPDY/3 の辞書の長さと Adler-32 が draft の辞書 ID と一致する（取り違えの検出）。
    #[test]
    fn cri6_spdy_dictionary_matches_spdy3_dictionary_id() {
        assert_eq!(SPDY3_DICTIONARY.len(), 1423);
        let mut a = 1u32;
        let mut b = 0u32;
        for byte in SPDY3_DICTIONARY.iter() {
            a = (a + u32::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!((b << 16) | a, DICTIONARY_ADLER32);
    }

    /// 符号化した SYN_REPLY の先頭が zlib ヘッダ（FDICT 付き）と辞書 ID になる。
    #[test]
    fn cri6_spdy_encoded_header_block_starts_with_dictionary_id() {
        let mut out = Vec::new();
        FrameEncoder::new()
            .encode(
                &Frame::SynReply {
                    stream_id: sid(1),
                    fin: false,
                    headers: headers(&[("streamtype", "error")]),
                },
                &mut out,
            )
            .expect("encode");
        // 制御ヘッダ 8 + stream id 4 の後が zlib ヘッダ（CMF=0x78・FDICT）と DICTID。
        assert_eq!(&out[..4], &[0x80, 0x03, 0x00, 0x02]);
        assert_eq!(out.get(12), Some(&0x78));
        assert_eq!(out.get(13).map(|b| b & 0x20), Some(0x20));
        assert_eq!(&out[14..18], &DICTIONARY_ADLER32.to_be_bytes());
    }

    /// 他実装（CPython の zlib・辞書つき・Z_SYNC_FLUSH）が作った 2 ブロックを同じ復号器で続けて復号できる。
    #[test]
    fn cri6_spdy_decodes_header_blocks_made_by_another_zlib() {
        let blocks = [
            "78f9e3c6a7c202a62346703a2b294a4dcc851625aca9a08006000000ffff",
            "02651c4ca9e212607601a5e00adddcd29c924c7039ca9004000000ffff",
        ];
        let mut dec = FrameDecoder::new();
        let mut frames = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            let block = hex(block);
            let mut f = Vec::new();
            control_header(&mut f, TYPE_SYN_REPLY, 0, 4 + block.len()).expect("header");
            f.extend_from_slice(&u32::try_from(i + 1).expect("id").to_be_bytes());
            f.extend_from_slice(&block);
            dec.extend(&f);
            frames.push(dec.next_frame().expect("decode").expect("frame"));
        }
        assert_eq!(
            frames[0],
            Frame::SynReply {
                stream_id: sid(1),
                fin: false,
                headers: headers(&[("streamtype", "error")]),
            }
        );
        assert_eq!(
            frames[1],
            Frame::SynReply {
                stream_id: sid(2),
                fin: false,
                headers: headers(&[("streamtype", "stdin"), ("x-multi", "a\0b")]),
            }
        );
    }

    #[test]
    fn cri6_spdy_all_frame_kinds_roundtrip() {
        let frames = vec![
            Frame::SynStream {
                stream_id: sid(5),
                associated_to: 0,
                priority: 7,
                fin: true,
                unidirectional: true,
                headers: headers(&[("streamtype", "stdout"), ("requestid", "7")]),
            },
            Frame::SynReply {
                stream_id: sid(5),
                fin: false,
                headers: Headers::new(),
            },
            Frame::Headers {
                stream_id: sid(MAX_STREAM_ID),
                fin: true,
                headers: headers(&[("a", "b")]),
            },
            Frame::RstStream {
                stream_id: sid(3),
                status: rst_status::REFUSED_STREAM,
            },
            Frame::Settings {
                clear: true,
                entries: vec![Setting {
                    flags: 1,
                    id: 7,
                    value: 65536,
                }],
            },
            Frame::Ping { id: 0xffff_fffe },
            Frame::GoAway {
                last_good_stream_id: 9,
                status: goaway_status::PROTOCOL_ERROR,
            },
            Frame::WindowUpdate {
                stream_id: 0,
                delta: 4096,
            },
            Frame::Data {
                stream_id: sid(1),
                fin: true,
                data: vec![1, 2, 3],
            },
            Frame::Data {
                stream_id: sid(1),
                fin: false,
                data: Vec::new(),
            },
        ];
        // 同一の符号化器・復号器で続けて往復し、圧縮状態の連続性も確かめる。
        let mut enc = FrameEncoder::new();
        let mut out = Vec::new();
        for f in &frames {
            enc.encode(f, &mut out).expect("encode");
        }
        let mut dec = FrameDecoder::new();
        dec.extend(&out);
        for f in &frames {
            assert_eq!(&dec.next_frame().expect("decode").expect("frame"), f);
        }
        assert_eq!(dec.next_frame().expect("end"), None);
        assert_eq!(dec.buffered_len(), 0);
    }

    #[test]
    fn cri6_spdy_exact_bytes_for_fixed_size_frames() {
        let mut enc = FrameEncoder::new();
        let mut out = Vec::new();
        enc.encode(&Frame::Ping { id: 1 }, &mut out).expect("ping");
        assert_eq!(out, [0x80, 0x03, 0x00, 0x06, 0, 0, 0, 4, 0, 0, 0, 1]);
        out.clear();
        enc.encode(
            &Frame::RstStream {
                stream_id: sid(7),
                status: 5,
            },
            &mut out,
        )
        .expect("rst");
        assert_eq!(
            out,
            [0x80, 0x03, 0x00, 0x03, 0, 0, 0, 8, 0, 0, 0, 7, 0, 0, 0, 5]
        );
        out.clear();
        enc.encode(
            &Frame::Data {
                stream_id: sid(3),
                fin: true,
                data: b"ab".to_vec(),
            },
            &mut out,
        )
        .expect("data");
        assert_eq!(out, [0, 0, 0, 3, 1, 0, 0, 2, b'a', b'b']);
        out.clear();
        enc.encode(
            &Frame::WindowUpdate {
                stream_id: 3,
                delta: 100,
            },
            &mut out,
        )
        .expect("window");
        assert_eq!(
            out,
            [0x80, 0x03, 0x00, 0x09, 0, 0, 0, 8, 0, 0, 0, 3, 0, 0, 0, 100]
        );
    }

    #[test]
    fn cri6_spdy_partial_input_waits_for_more() {
        let mut out = Vec::new();
        FrameEncoder::new()
            .encode(
                &Frame::Data {
                    stream_id: sid(1),
                    fin: false,
                    data: vec![9; 100],
                },
                &mut out,
            )
            .expect("encode");
        let mut dec = FrameDecoder::new();
        for byte in &out[..out.len() - 1] {
            dec.extend(&[*byte]);
            assert_eq!(dec.next_frame().expect("partial"), None);
        }
        dec.extend(&out[out.len() - 1..]);
        assert!(matches!(
            dec.next_frame().expect("complete"),
            Some(Frame::Data { .. })
        ));
    }

    #[test]
    fn cri6_spdy_rejects_oversize_frame_before_buffering_it() {
        let mut dec = FrameDecoder::new();
        // 24 ビット長 0xffffff の DATA フレームのヘッダだけで拒否する。
        dec.extend(&[0, 0, 0, 1, 0, 0xff, 0xff, 0xff]);
        assert_eq!(dec.next_frame(), Err(SpdyError::FrameTooLarge));
    }

    #[test]
    fn cri6_spdy_rejects_bad_version_and_zero_stream_id() {
        let mut dec = FrameDecoder::new();
        dec.extend(&[0x80, 0x02, 0x00, 0x06, 0, 0, 0, 4, 0, 0, 0, 1]);
        assert_eq!(dec.next_frame(), Err(SpdyError::UnsupportedVersion));
        let mut dec = FrameDecoder::new();
        dec.extend(&[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::InvalidFrame("stream id is zero"))
        );
        let mut dec = FrameDecoder::new();
        dec.extend(&[0x80, 0x03, 0x00, 0x06, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::InvalidFrame("ping length"))
        );
    }

    #[test]
    fn cri6_spdy_ignores_unknown_control_frame() {
        let mut dec = FrameDecoder::new();
        dec.extend(&[0x80, 0x03, 0x00, 0x0a, 0, 0, 0, 2, 7, 7]);
        assert_eq!(
            dec.next_frame().expect("decode"),
            Some(Frame::Unknown { frame_type: 10 })
        );
    }

    /// 展開後に上限を超えるヘッダブロック（zlib bomb）は上限で拒否し、巨大な確保をしない。
    #[test]
    fn cri6_spdy_header_block_bomb_is_rejected() {
        let mut enc = FrameEncoder::new();
        let raw = vec![0u8; 4 * 1024 * 1024];
        let block = enc.deflate(&raw).expect("deflate");
        assert!(block.len() < MAX_INCOMING_PAYLOAD, "bomb must fit a frame");
        let mut f = Vec::new();
        control_header(&mut f, TYPE_SYN_REPLY, 0, 4 + block.len()).expect("header");
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&block);
        let mut dec = FrameDecoder::new();
        dec.extend(&f);
        assert_eq!(dec.next_frame(), Err(SpdyError::HeaderBlockTooLarge));
    }

    #[test]
    fn cri6_spdy_rejects_duplicate_header_and_too_many_headers() {
        let mut enc = FrameEncoder::new();
        let mut dup = Headers::new();
        dup.0.push(("a".to_string(), "1".to_string()));
        dup.0.push(("a".to_string(), "2".to_string()));
        let mut out = Vec::new();
        enc.encode(
            &Frame::SynReply {
                stream_id: sid(1),
                fin: false,
                headers: dup,
            },
            &mut out,
        )
        .expect("encode");
        let mut dec = FrameDecoder::new();
        dec.extend(&out);
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::InvalidFrame("duplicate header name"))
        );
        let mut many = Headers::new();
        for i in 0..=MAX_HEADER_COUNT {
            many.0.push((format!("h{i}"), "v".to_string()));
        }
        assert_eq!(
            FrameEncoder::new().encode(
                &Frame::SynReply {
                    stream_id: sid(1),
                    fin: false,
                    headers: many,
                },
                &mut Vec::new()
            ),
            Err(SpdyError::HeaderBlockTooLarge)
        );
    }

    #[test]
    fn cri6_spdy_rejects_garbage_header_block() {
        let mut f = Vec::new();
        control_header(&mut f, TYPE_SYN_REPLY, 0, 4 + 6).expect("header");
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let mut dec = FrameDecoder::new();
        dec.extend(&f);
        assert!(matches!(dec.next_frame(), Err(SpdyError::Compression(_))));
    }

    #[test]
    fn cri6_spdy_stream_id_bounds() {
        assert_eq!(StreamId::new(0), None);
        assert_eq!(StreamId::new(1).map(StreamId::get), Some(1));
        assert_eq!(
            StreamId::new(MAX_STREAM_ID).map(StreamId::get),
            Some(MAX_STREAM_ID)
        );
        assert_eq!(StreamId::new(MAX_STREAM_ID + 1), None);
    }

    #[test]
    fn cri6_spdy_roundtrip_helper_keeps_large_data() {
        let data = vec![0xab; MAX_OUTGOING_DATA];
        let got = roundtrip(&Frame::Data {
            stream_id: sid(1),
            fin: false,
            data: data.clone(),
        });
        assert_eq!(
            got,
            Frame::Data {
                stream_id: sid(1),
                fin: false,
                data
            }
        );
    }
}
