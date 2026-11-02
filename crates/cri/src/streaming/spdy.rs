//! SPDY/3.1 のフレーム層（CRI-6・TASK-63.4・#682。判断は #678、設計記録は `docs/design/cri-streaming-server.md`）。
//!
//! kubelet / kubectl（client-go）は Exec・Attach・PortForward を HTTP/1.1 の `Upgrade: SPDY/3.1` で張る。
//! 本モジュールはその上のバイナリフレーム（制御フレーム・DATA フレーム）の符号化・増分復号と、名前/値ヘッダ
//! ブロックの zlib（辞書つき）圧縮・展開を持つ。PortForward（[`super::port_forward`]）が使い、Exec（#680）・
//! Attach（#681）からも再利用できるよう、PortForward 固有の語は持たない。
//!
//! ## 安全側の設計
//!
//! - 復号は相手の入力を untrusted として扱う。フレーム長・展開後のヘッダ長・件数・名前/値の長さを検証してから
//!   確保し、panic する操作（`unwrap`・添字アクセス）を使わない（無制限確保による DoS を防ぐ）
//! - ストリーム ID は 31 ビットで 0 を持てない型（[`StreamId`]）で表し、壊れた値を表現できないようにする（REPAIR-2）
//! - zlib の圧縮文脈は方向ごとに接続の寿命まで 1 本を保持する（ブロックごとに作り直すと相手が展開できない）
//!
//! ## 範囲
//!
//! フロー制御（WINDOW_UPDATE の送出・窓の追跡）は持たない。受け取った WINDOW_UPDATE・SETTINGS・未知の制御
//! フレームは読み飛ばす（未実装を装わない。REPAIR-3）。kubelet の SPDY 実装も窓を強制しない前提で、実
//! クライアントとの相互運用は #683（TASK-63.5）で確かめる。

use std::fmt;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};

/// 扱う SPDY のバージョン（SPDY/3.1 のフレーム版数は 3）。
pub const SPDY_VERSION: u16 = 3;
/// 制御フレーム・DATA フレーム共通のヘッダ長（バイト）。
pub const FRAME_HEADER_LEN: usize = 8;
/// 24 ビット長フィールドで表せる最大値。
pub const MAX_FRAME_LEN: usize = 0x00ff_ffff;
/// フラグ: このフレームで送信側が閉じる（FIN）。
pub const FLAG_FIN: u8 = 0x01;

/// 展開後のヘッダブロックの最大バイト数。
pub const MAX_HEADER_BLOCK_BYTES: usize = 64 * 1024;
/// 1 ブロックのヘッダ件数の上限。
pub const MAX_HEADER_COUNT: usize = 64;
/// ヘッダの名前・値それぞれの最大バイト数。
pub const MAX_HEADER_FIELD_BYTES: usize = 8 * 1024;

/// RST_STREAM の状態コード: PROTOCOL_ERROR。
pub const RST_PROTOCOL_ERROR: u32 = 1;
/// RST_STREAM の状態コード: REFUSED_STREAM。
pub const RST_REFUSED_STREAM: u32 = 3;
/// RST_STREAM の状態コード: CANCEL。
pub const RST_CANCEL: u32 = 5;
/// GOAWAY の状態コード: OK。
pub const GOAWAY_OK: u32 = 0;
/// GOAWAY の状態コード: PROTOCOL_ERROR。
pub const GOAWAY_PROTOCOL_ERROR: u32 = 1;

const TYPE_SYN_STREAM: u16 = 1;
const TYPE_SYN_REPLY: u16 = 2;
const TYPE_RST_STREAM: u16 = 3;
const TYPE_PING: u16 = 6;
const TYPE_GOAWAY: u16 = 7;
const TYPE_HEADERS: u16 = 8;

/// 辞書の Adler-32（SPDY/3 の仕様の既知値。zlib の DICTID として圧縮ストリームの先頭に現れる）。
pub const SPDY3_DICTIONARY_ADLER32: u32 = 0xe3c6_a7c2;
/// 辞書の長さ（バイト）。
pub const SPDY3_DICTIONARY_LEN: usize = 1423;

/// 名前/値ヘッダブロックの zlib 辞書（SPDY Protocol Draft 3 の 2.6.10.1「Compression」節。
/// <https://datatracker.ietf.org/doc/html/draft-mbelshe-httpbis-spdy-00#section-2.6.10.1> と同内容）。
///
/// 仕様文書の定義を一次情報にし、実装コード（spdystream 等）からは写していない。長さ（1423）と Adler-32
/// （`0xe3c6a7c2`）が仕様の既知値と一致することを試験で固定している。帰属表示の要否は PR で確認事項にしている。
pub const SPDY3_DICTIONARY: &[u8] = SPDY3_DICTIONARY_BYTES;

const SPDY3_DICTIONARY_BYTES: &[u8] = b"\
    \x00\x00\x00\x07options\x00\x00\x00\x04head\x00\x00\x00\x04post\x00\x00\x00\x03\
    put\x00\x00\x00\x06delete\x00\x00\x00\x05trace\x00\x00\x00\x06accept\x00\x00\
    \x00\x0eaccept-charset\x00\x00\x00\x0faccept-encoding\x00\x00\x00\x0faccept-\
    language\x00\x00\x00\x0daccept-ranges\x00\x00\x00\x03age\x00\x00\x00\x05allo\
    w\x00\x00\x00\x0dauthorization\x00\x00\x00\x0dcache-control\x00\x00\x00\x0ac\
    onnection\x00\x00\x00\x0ccontent-base\x00\x00\x00\x10content-encoding\x00\x00\
    \x00\x10content-language\x00\x00\x00\x0econtent-length\x00\x00\x00\x10conten\
    t-location\x00\x00\x00\x0bcontent-md5\x00\x00\x00\x0dcontent-range\x00\x00\x00\
    \x0ccontent-type\x00\x00\x00\x04date\x00\x00\x00\x04etag\x00\x00\x00\x06expe\
    ct\x00\x00\x00\x07expires\x00\x00\x00\x04from\x00\x00\x00\x04host\x00\x00\x00\
    \x08if-match\x00\x00\x00\x11if-modified-since\x00\x00\x00\x0dif-none-match\x00\
    \x00\x00\x08if-range\x00\x00\x00\x13if-unmodified-since\x00\x00\x00\x0dlast-\
    modified\x00\x00\x00\x08location\x00\x00\x00\x0cmax-forwards\x00\x00\x00\x06\
    pragma\x00\x00\x00\x12proxy-authenticate\x00\x00\x00\x13proxy-authorization\x00\
    \x00\x00\x05range\x00\x00\x00\x07referer\x00\x00\x00\x0bretry-after\x00\x00\x00\
    \x06server\x00\x00\x00\x02te\x00\x00\x00\x07trailer\x00\x00\x00\x11transfer-\
    encoding\x00\x00\x00\x07upgrade\x00\x00\x00\x0auser-agent\x00\x00\x00\x04var\
    y\x00\x00\x00\x03via\x00\x00\x00\x07warning\x00\x00\x00\x10www-authenticate\x00\
    \x00\x00\x06method\x00\x00\x00\x03get\x00\x00\x00\x06status\x00\x00\x00\x062\
    00 OK\x00\x00\x00\x07version\x00\x00\x00\x08HTTP/1.1\x00\x00\x00\x03url\x00\x00\
    \x00\x06public\x00\x00\x00\x0aset-cookie\x00\x00\x00\x0akeep-alive\x00\x00\x00\
    \x06origin100101201202205206300302303304305306307402405406407408409410411412\
    413414415416417502504505203 Non-Authoritative Information204 No Content301 M\
    oved Permanently400 Bad Request401 Unauthorized403 Forbidden404 Not Found500 \
    Internal Server Error501 Not Implemented503 Service UnavailableJan Feb Mar A\
    pr May Jun Jul Aug Sept Oct Nov Dec 00:00:00 Mon, Tue, Wed, Thu, Fri, Sat, S\
    un, GMTchunked,text/html,image/png,image/jpg,image/gif,application/xml,appli\
    cation/xhtml+xml,text/plain,text/javascript,publicprivatemax-age=gzip,deflat\
    e,sdchcharset=utf-8charset=iso-8859-1,utf-,*,enq=0.";

/// SPDY 層の失敗（接続を閉じるべき種類）。メッセージは固定の英語で、入力の内容を含めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdyError {
    /// フレームの構造が不正（版数・長さ・予約ビット・ストリーム ID 0 等）。
    Malformed(&'static str),
    /// 上限（フレーム長・ヘッダ件数・展開後サイズ・バッファ）を超えた。
    LimitExceeded(&'static str),
    /// ヘッダブロックの zlib が壊れている・辞書が合わない。
    Compression(&'static str),
}

impl fmt::Display for SpdyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpdyError::Malformed(m) | SpdyError::LimitExceeded(m) | SpdyError::Compression(m) => {
                f.write_str(m)
            }
        }
    }
}

impl std::error::Error for SpdyError {}

/// ストリーム ID（31 ビット・0 は持てない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u32);

impl StreamId {
    /// 値が 1..=0x7fff_ffff のときだけ作る。
    pub fn new(value: u32) -> Option<Self> {
        (value != 0 && value <= 0x7fff_ffff).then_some(Self(value))
    }

    /// 数値。
    pub fn get(self) -> u32 {
        self.0
    }
}

/// 名前（小文字化済み）と値の組。値の複数値は NUL 区切りのまま保持する。
pub type Headers = Vec<(String, String)>;

/// 復号済み・符号化前のフレーム。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// DATA フレーム。
    Data {
        /// 対象ストリーム。
        stream: StreamId,
        /// FIN フラグ。
        fin: bool,
        /// 本体。
        data: Vec<u8>,
    },
    /// SYN_STREAM。
    SynStream {
        /// 新しいストリーム。
        stream: StreamId,
        /// 関連ストリーム（0 は無し）。
        associated: u32,
        /// 優先度（0..=7）。
        priority: u8,
        /// FIN フラグ。
        fin: bool,
        /// ヘッダ。
        headers: Headers,
    },
    /// SYN_REPLY。
    SynReply {
        /// 対象ストリーム。
        stream: StreamId,
        /// FIN フラグ。
        fin: bool,
        /// ヘッダ。
        headers: Headers,
    },
    /// RST_STREAM。
    RstStream {
        /// 対象ストリーム。
        stream: StreamId,
        /// 状態コード。
        status: u32,
    },
    /// PING。
    Ping(u32),
    /// GOAWAY。
    GoAway {
        /// 最後に受理したストリーム ID（無ければ 0）。
        last_good: u32,
        /// 状態コード。
        status: u32,
    },
    /// 受理して読み飛ばす制御フレーム（SETTINGS・HEADERS・WINDOW_UPDATE・未知の種別）。
    Ignored,
}

/// ヘッダブロックの圧縮器。接続の送信方向ごとに 1 本を保持する。
pub struct HeaderCompressor {
    inner: Compress,
}

impl fmt::Debug for HeaderCompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HeaderCompressor")
    }
}

impl HeaderCompressor {
    /// 辞書を設定した圧縮器を作る。
    pub fn new() -> Result<Self, SpdyError> {
        let mut inner = Compress::new(Compression::default(), true);
        inner
            .set_dictionary(SPDY3_DICTIONARY)
            .map_err(|_| SpdyError::Compression("failed to set header dictionary"))?;
        Ok(Self { inner })
    }

    /// 生のヘッダブロック（件数・長さ接頭辞つきの並び）を圧縮する。Sync flush で区切る。
    fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>, SpdyError> {
        let fail = SpdyError::Compression("header compression failed");
        let start_in = self.inner.total_in();
        let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_add(64));
        for _ in 0..64 {
            let consumed = usize::try_from(self.inner.total_in() - start_in).map_err(|_| fail)?;
            let rest = input.get(consumed..).ok_or(fail)?;
            if out.capacity() - out.len() < 64 {
                out.reserve(256);
            }
            self.inner
                .compress_vec(rest, &mut out, FlushCompress::Sync)
                .map_err(|_| fail)?;
            let consumed = usize::try_from(self.inner.total_in() - start_in).map_err(|_| fail)?;
            if consumed >= input.len() && out.len() < out.capacity() {
                return Ok(out);
            }
        }
        Err(fail)
    }
}

/// ヘッダブロックの展開器。接続の受信方向ごとに 1 本を保持する。
pub struct HeaderDecompressor {
    inner: Decompress,
    dictionary_set: bool,
}

impl fmt::Debug for HeaderDecompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HeaderDecompressor")
    }
}

impl Default for HeaderDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderDecompressor {
    /// 展開器を作る。辞書は最初のブロックで zlib が要求したときに設定する。
    pub fn new() -> Self {
        Self {
            inner: Decompress::new(true),
            dictionary_set: false,
        }
    }

    /// 圧縮されたヘッダブロックを展開する（展開後 [`MAX_HEADER_BLOCK_BYTES`] まで）。
    fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>, SpdyError> {
        let corrupt = SpdyError::Compression("header block is corrupt");
        let start_in = self.inner.total_in();
        let mut out: Vec<u8> = Vec::new();
        for _ in 0..256 {
            let consumed =
                usize::try_from(self.inner.total_in() - start_in).map_err(|_| corrupt)?;
            let rest = input.get(consumed..).ok_or(corrupt)?;
            if out.len() > MAX_HEADER_BLOCK_BYTES {
                return Err(SpdyError::LimitExceeded("header block is too large"));
            }
            if out.capacity() - out.len() < 1024 {
                out.reserve(4096);
            }
            let before_out = self.inner.total_out();
            match self
                .inner
                .decompress_vec(rest, &mut out, FlushDecompress::Sync)
            {
                Ok(_) => {}
                Err(e) => match e.needs_dictionary() {
                    Some(adler) if !self.dictionary_set => {
                        if adler != SPDY3_DICTIONARY_ADLER32 {
                            return Err(SpdyError::Compression("unexpected header dictionary"));
                        }
                        self.inner
                            .set_dictionary(SPDY3_DICTIONARY)
                            .map_err(|_| corrupt)?;
                        self.dictionary_set = true;
                        continue;
                    }
                    _ => return Err(corrupt),
                },
            }
            let consumed =
                usize::try_from(self.inner.total_in() - start_in).map_err(|_| corrupt)?;
            let produced = self.inner.total_out() != before_out;
            if consumed >= input.len() && out.len() < out.capacity() {
                break;
            }
            if consumed >= input.len() && !produced {
                break;
            }
        }
        if out.len() > MAX_HEADER_BLOCK_BYTES {
            return Err(SpdyError::LimitExceeded("header block is too large"));
        }
        Ok(out)
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn get_u32(buf: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// ヘッダを SPDY/3 の生ブロック（u32 件数・u32 長さ＋バイト列）へ並べる。
fn encode_header_block(headers: &Headers) -> Result<Vec<u8>, SpdyError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(SpdyError::LimitExceeded("too many headers"));
    }
    let mut total: usize = 4;
    let mut raw = Vec::new();
    put_u32(
        &mut raw,
        u32::try_from(headers.len()).map_err(|_| SpdyError::LimitExceeded("too many headers"))?,
    );
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > MAX_HEADER_FIELD_BYTES
            || value.len() > MAX_HEADER_FIELD_BYTES
        {
            return Err(SpdyError::LimitExceeded("header field is too large"));
        }
        // 復号側の生ブロック上限（長さ接頭辞を含む）を、確保・圧縮の前に検査する。
        total = total
            .checked_add(8)
            .and_then(|t| t.checked_add(name.len()))
            .and_then(|t| t.checked_add(value.len()))
            .filter(|t| *t <= MAX_HEADER_BLOCK_BYTES)
            .ok_or(SpdyError::LimitExceeded("header block is too large"))?;
        put_u32(&mut raw, name.len() as u32);
        raw.extend_from_slice(name.as_bytes());
        put_u32(&mut raw, value.len() as u32);
        raw.extend_from_slice(value.as_bytes());
    }
    Ok(raw)
}

/// 展開済みの生ブロックを検証しながらヘッダへ読む。名前は小文字化する。
fn decode_header_block(raw: &[u8]) -> Result<Headers, SpdyError> {
    let bad = SpdyError::Malformed("header block is malformed");
    let count = get_u32(raw, 0).ok_or(bad)? as usize;
    if count > MAX_HEADER_COUNT {
        return Err(SpdyError::LimitExceeded("too many headers"));
    }
    let mut at = 4usize;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let mut fields: [String; 2] = [String::new(), String::new()];
        for slot in &mut fields {
            let len = get_u32(raw, at).ok_or(bad)? as usize;
            at += 4;
            if len > MAX_HEADER_FIELD_BYTES {
                return Err(SpdyError::LimitExceeded("header field is too large"));
            }
            let end = at.checked_add(len).ok_or(bad)?;
            let bytes = raw.get(at..end).ok_or(bad)?;
            *slot = String::from_utf8(bytes.to_vec()).map_err(|_| bad)?;
            at = end;
        }
        let [name, value] = fields;
        if name.is_empty() {
            return Err(bad);
        }
        headers.push((name.to_ascii_lowercase(), value));
    }
    if at != raw.len() {
        return Err(bad);
    }
    Ok(headers)
}

fn control_header(out: &mut Vec<u8>, kind: u16, flags: u8, len: usize) -> Result<(), SpdyError> {
    if len > MAX_FRAME_LEN {
        return Err(SpdyError::LimitExceeded("frame is too large"));
    }
    out.extend_from_slice(&(0x8000 | SPDY_VERSION).to_be_bytes());
    out.extend_from_slice(&kind.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    Ok(())
}

impl Frame {
    /// 送信用のバイト列へ符号化する。ヘッダブロックを持つフレームは `compressor` を通す（呼び出し順 = 送信順）。
    pub fn encode(&self, compressor: &mut HeaderCompressor) -> Result<Vec<u8>, SpdyError> {
        let mut out = Vec::new();
        match self {
            Frame::Data { stream, fin, data } => {
                if data.len() > MAX_FRAME_LEN {
                    return Err(SpdyError::LimitExceeded("frame is too large"));
                }
                put_u32(&mut out, stream.get());
                out.push(if *fin { FLAG_FIN } else { 0 });
                out.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
                out.extend_from_slice(data);
            }
            Frame::SynStream {
                stream,
                associated,
                priority,
                fin,
                headers,
            } => {
                let block = compressor.compress(&encode_header_block(headers)?)?;
                control_header(
                    &mut out,
                    TYPE_SYN_STREAM,
                    if *fin { FLAG_FIN } else { 0 },
                    10 + block.len(),
                )?;
                put_u32(&mut out, stream.get());
                put_u32(&mut out, *associated & 0x7fff_ffff);
                out.push((priority & 0x07) << 5);
                out.push(0);
                out.extend_from_slice(&block);
            }
            Frame::SynReply {
                stream,
                fin,
                headers,
            } => {
                let block = compressor.compress(&encode_header_block(headers)?)?;
                control_header(
                    &mut out,
                    TYPE_SYN_REPLY,
                    if *fin { FLAG_FIN } else { 0 },
                    4 + block.len(),
                )?;
                put_u32(&mut out, stream.get());
                out.extend_from_slice(&block);
            }
            Frame::RstStream { stream, status } => {
                control_header(&mut out, TYPE_RST_STREAM, 0, 8)?;
                put_u32(&mut out, stream.get());
                put_u32(&mut out, *status);
            }
            Frame::Ping(id) => {
                control_header(&mut out, TYPE_PING, 0, 4)?;
                put_u32(&mut out, *id);
            }
            Frame::GoAway { last_good, status } => {
                control_header(&mut out, TYPE_GOAWAY, 0, 8)?;
                put_u32(&mut out, *last_good & 0x7fff_ffff);
                put_u32(&mut out, *status);
            }
            Frame::Ignored => return Err(SpdyError::Malformed("frame cannot be encoded")),
        }
        Ok(out)
    }
}

/// 増分フレームデコーダ。受信バイト列を `push` し、`next_frame` で 1 フレームずつ取り出す。
pub struct FrameDecoder {
    buf: Vec<u8>,
    max_frame: usize,
    decompressor: HeaderDecompressor,
}

impl fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("buffered", &self.buf.len())
            .field("max_frame", &self.max_frame)
            .finish()
    }
}

impl FrameDecoder {
    /// フレーム本体の最大長（制御・DATA 共通）を指定して作る。24 ビットで表せる最大値で頭打ちにする。
    pub fn new(max_frame: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_frame: max_frame.min(MAX_FRAME_LEN),
            decompressor: HeaderDecompressor::new(),
        }
    }

    /// 未処理のバイト数。
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// `push` で受け付けられる残りのバイト数。
    pub fn free_capacity(&self) -> usize {
        self.max_frame
            .saturating_add(FRAME_HEADER_LEN)
            .saturating_mul(2)
            .saturating_sub(self.buf.len())
    }

    /// 受信バイトを追加する。バッファが「1 フレーム + ヘッダ」を大きく超えるなら拒否する。
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SpdyError> {
        let cap = self
            .max_frame
            .saturating_add(FRAME_HEADER_LEN)
            .saturating_mul(2);
        if self.buf.len().saturating_add(bytes.len()) > cap {
            return Err(SpdyError::LimitExceeded("receive buffer is full"));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// 完全に揃ったフレームがあれば 1 つ取り出す。
    pub fn next_frame(&mut self) -> Result<Option<Frame>, SpdyError> {
        let Some(head) = self
            .buf
            .get(..FRAME_HEADER_LEN)
            .and_then(|h| <[u8; FRAME_HEADER_LEN]>::try_from(h).ok())
        else {
            return Ok(None);
        };
        let [w0a, w0b, w1a, w1b, flags, l0, l1, l2] = head;
        let word0 = u16::from_be_bytes([w0a, w0b]);
        let word1 = u16::from_be_bytes([w1a, w1b]);
        let len = (usize::from(l0) << 16) | (usize::from(l1) << 8) | usize::from(l2);
        let control = word0 & 0x8000 != 0;
        if control && word0 & 0x7fff != SPDY_VERSION {
            return Err(SpdyError::Malformed("unsupported spdy version"));
        }
        if len > self.max_frame {
            return Err(SpdyError::LimitExceeded("frame is too large"));
        }
        let total = FRAME_HEADER_LEN + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let stream_word = get_u32(&self.buf, 0).unwrap_or(0);
        let body: Vec<u8> = self
            .buf
            .get(FRAME_HEADER_LEN..total)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        self.buf.drain(..total);
        let fin = flags & FLAG_FIN != 0;
        if !control {
            let stream = StreamId::new(stream_word)
                .ok_or(SpdyError::Malformed("data frame has invalid stream id"))?;
            return Ok(Some(Frame::Data {
                stream,
                fin,
                data: body,
            }));
        }
        self.control_frame(word1, fin, &body).map(Some)
    }

    fn control_frame(&mut self, kind: u16, fin: bool, body: &[u8]) -> Result<Frame, SpdyError> {
        let short = SpdyError::Malformed("control frame is too short");
        let stream_at = |at: usize| -> Result<StreamId, SpdyError> {
            let raw = get_u32(body, at).ok_or(short)?;
            StreamId::new(raw & 0x7fff_ffff)
                .ok_or(SpdyError::Malformed("control frame has invalid stream id"))
        };
        match kind {
            TYPE_SYN_STREAM => {
                let stream = stream_at(0)?;
                let associated = get_u32(body, 4).ok_or(short)? & 0x7fff_ffff;
                let priority = body.get(8).copied().ok_or(short)? >> 5;
                let block = body.get(10..).ok_or(short)?;
                let headers = decode_header_block(&self.decompressor.decompress(block)?)?;
                Ok(Frame::SynStream {
                    stream,
                    associated,
                    priority,
                    fin,
                    headers,
                })
            }
            TYPE_SYN_REPLY => {
                let stream = stream_at(0)?;
                let block = body.get(4..).ok_or(short)?;
                let headers = decode_header_block(&self.decompressor.decompress(block)?)?;
                Ok(Frame::SynReply {
                    stream,
                    fin,
                    headers,
                })
            }
            TYPE_HEADERS => {
                // 圧縮文脈を進めるため、内容は使わなくても展開する。
                let block = body.get(4..).ok_or(short)?;
                decode_header_block(&self.decompressor.decompress(block)?)?;
                Ok(Frame::Ignored)
            }
            TYPE_RST_STREAM => {
                if body.len() != 8 {
                    return Err(SpdyError::Malformed("rst_stream has invalid length"));
                }
                Ok(Frame::RstStream {
                    stream: stream_at(0)?,
                    status: get_u32(body, 4).ok_or(short)?,
                })
            }
            TYPE_PING => {
                if body.len() != 4 {
                    return Err(SpdyError::Malformed("ping has invalid length"));
                }
                Ok(Frame::Ping(get_u32(body, 0).ok_or(short)?))
            }
            TYPE_GOAWAY => {
                if body.len() != 8 {
                    return Err(SpdyError::Malformed("goaway has invalid length"));
                }
                Ok(Frame::GoAway {
                    last_good: get_u32(body, 0).ok_or(short)? & 0x7fff_ffff,
                    status: get_u32(body, 4).ok_or(short)?,
                })
            }
            // SETTINGS・WINDOW_UPDATE・未知の種別は読み飛ばす（フロー制御は持たない）。
            _ => Ok(Frame::Ignored),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(v: u32) -> StreamId {
        StreamId::new(v).expect("stream id")
    }

    fn hdr(pairs: &[(&str, &str)]) -> Headers {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect()
    }

    fn decode_all(dec: &mut FrameDecoder, bytes: &[u8]) -> Vec<Frame> {
        dec.push(bytes).expect("push");
        let mut out = Vec::new();
        while let Some(f) = dec.next_frame().expect("next") {
            out.push(f);
        }
        out
    }

    /// CRI-6: 辞書の長さと Adler-32 が SPDY/3 の仕様の既知値と一致する。
    #[test]
    fn cri6_spdy3_dictionary_matches_known_adler32() {
        assert_eq!(SPDY3_DICTIONARY.len(), SPDY3_DICTIONARY_LEN);
        let mut c = Compress::new(Compression::default(), true);
        let adler = c.set_dictionary(SPDY3_DICTIONARY).expect("set dict");
        assert_eq!(adler, SPDY3_DICTIONARY_ADLER32);
    }

    /// CRI-6: 各フレームが往復し、同じ圧縮文脈で 2 つ目のヘッダブロックも展開できる。
    #[test]
    fn cri6_frames_round_trip() {
        let mut comp = HeaderCompressor::new().expect("comp");
        let mut dec = FrameDecoder::new(1 << 20);
        let frames = vec![
            Frame::SynStream {
                stream: sid(1),
                associated: 0,
                priority: 3,
                fin: false,
                headers: hdr(&[
                    ("streamtype", "error"),
                    ("port", "8080"),
                    ("requestid", "0"),
                ]),
            },
            Frame::SynStream {
                stream: sid(3),
                associated: 0,
                priority: 0,
                fin: true,
                headers: hdr(&[("streamtype", "data"), ("port", "8080"), ("requestid", "0")]),
            },
            Frame::SynReply {
                stream: sid(1),
                fin: false,
                headers: Vec::new(),
            },
            Frame::Data {
                stream: sid(3),
                fin: true,
                data: b"hello".to_vec(),
            },
            Frame::RstStream {
                stream: sid(5),
                status: RST_CANCEL,
            },
            Frame::Ping(7),
            Frame::GoAway {
                last_good: 3,
                status: GOAWAY_OK,
            },
        ];
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend(f.encode(&mut comp).expect("encode"));
        }
        // 1 バイトずつ流しても同じ結果になる（増分復号）。
        let mut got = Vec::new();
        for b in &wire {
            got.extend(decode_all(&mut dec, std::slice::from_ref(b)));
        }
        assert_eq!(got, frames);
    }

    /// CRI-6: DATA の長さは 24 ビットで、境界の 0 と最大長を符号化できる。
    #[test]
    fn cri6_data_length_boundaries() {
        let mut comp = HeaderCompressor::new().expect("comp");
        let empty = Frame::Data {
            stream: sid(1),
            fin: true,
            data: Vec::new(),
        };
        assert_eq!(
            empty.encode(&mut comp).expect("encode"),
            vec![0, 0, 0, 1, 1, 0, 0, 0]
        );
        let big = Frame::Data {
            stream: sid(1),
            fin: false,
            data: vec![0xab; 70_000],
        };
        let wire = big.encode(&mut comp).expect("encode");
        assert_eq!(wire.get(5..8), Some(&[0x01, 0x11, 0x70][..]));
        let mut dec = FrameDecoder::new(1 << 20);
        assert_eq!(decode_all(&mut dec, &wire), vec![big]);
    }

    /// CRI-6: ストリーム ID 0 と予約ビットつきの値は作れない・DATA の ID 0 は拒否する。
    #[test]
    fn cri6_stream_id_zero_rejected() {
        assert_eq!(StreamId::new(0), None);
        assert_eq!(StreamId::new(0x8000_0000), None);
        assert_eq!(
            StreamId::new(0x7fff_ffff).map(StreamId::get),
            Some(0x7fff_ffff)
        );
        let mut dec = FrameDecoder::new(1024);
        dec.push(&[0, 0, 0, 0, 0, 0, 0, 0]).expect("push");
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::Malformed("data frame has invalid stream id"))
        );
    }

    /// CRI-6: 未知の制御種別と WINDOW_UPDATE・SETTINGS は読み飛ばし、後続のフレームを読める。
    #[test]
    fn cri6_unknown_control_frames_skipped() {
        let mut comp = HeaderCompressor::new().expect("comp");
        let mut wire = vec![0x80, 0x03, 0x00, 0x09, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 1, 0];
        wire.extend([0x80, 0x03, 0x00, 0x63, 0, 0, 0, 2, 9, 9]);
        wire.extend(Frame::Ping(1).encode(&mut comp).expect("encode"));
        let mut dec = FrameDecoder::new(1024);
        assert_eq!(
            decode_all(&mut dec, &wire),
            vec![Frame::Ignored, Frame::Ignored, Frame::Ping(1)]
        );
    }

    /// CRI-6: 版数違い・上限超過のフレーム長は接続を閉じるべき失敗になる。
    #[test]
    fn cri6_bad_version_and_oversize_rejected() {
        let mut dec = FrameDecoder::new(1024);
        dec.push(&[0x80, 0x02, 0, 6, 0, 0, 0, 4, 0, 0, 0, 1])
            .expect("push");
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::Malformed("unsupported spdy version"))
        );
        let mut dec = FrameDecoder::new(1024);
        dec.push(&[0, 0, 0, 1, 0, 0x00, 0x04, 0x01]).expect("push");
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::LimitExceeded("frame is too large"))
        );
        // バッファの上限（(max_frame + 8) * 2）を超える push は拒否する。
        let mut dec = FrameDecoder::new(16);
        assert_eq!(
            dec.push(&[0u8; 49]),
            Err(SpdyError::LimitExceeded("receive buffer is full"))
        );
    }

    /// CRI-6: 壊れた zlib のヘッダブロックは Compression エラーになる。
    #[test]
    fn cri6_corrupt_header_block_rejected() {
        let mut wire = vec![0x80, 0x03, 0x00, 0x01, 0, 0, 0, 20];
        wire.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        wire.extend([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut dec = FrameDecoder::new(1024);
        dec.push(&wire).expect("push");
        assert!(matches!(dec.next_frame(), Err(SpdyError::Compression(_))));
    }

    /// CRI-6: ヘッダ件数・フィールド長の上限を符号化側が拒否する。
    #[test]
    fn cri6_header_limits_enforced_on_encode() {
        let mut comp = HeaderCompressor::new().expect("comp");
        let many: Headers = (0..=MAX_HEADER_COUNT)
            .map(|i| (format!("h{i}"), "v".to_string()))
            .collect();
        let frame = Frame::SynReply {
            stream: sid(1),
            fin: false,
            headers: many,
        };
        assert_eq!(
            frame.encode(&mut comp),
            Err(SpdyError::LimitExceeded("too many headers"))
        );
        let big = Frame::SynReply {
            stream: sid(1),
            fin: false,
            headers: vec![("x".to_string(), "a".repeat(MAX_HEADER_FIELD_BYTES + 1))],
        };
        assert_eq!(
            big.encode(&mut comp),
            Err(SpdyError::LimitExceeded("header field is too large"))
        );
    }

    /// CRI-6: 件数・各長が上限内でも、長さ接頭辞を含む合計が復号側の上限を超える符号化は拒否する。
    #[test]
    fn cri6_header_block_total_limit_enforced_on_encode() {
        let mut comp = HeaderCompressor::new().expect("comp");
        // 名前 1 バイト・値 8192 バイトの 8 件 = 4 + 8 * (8 + 1 + 8192) = 65612 バイト（> 65536）。
        let headers: Headers = (0..8)
            .map(|i| (format!("{i}"), "a".repeat(MAX_HEADER_FIELD_BYTES)))
            .collect();
        let frame = Frame::SynReply {
            stream: sid(1),
            fin: false,
            headers,
        };
        assert_eq!(
            frame.encode(&mut comp),
            Err(SpdyError::LimitExceeded("header block is too large"))
        );
    }

    /// CRI-6: 展開後に上限を超えるヘッダブロック（高圧縮率の入力）は展開の途中で拒否する。
    #[test]
    fn cri6_decompression_bomb_rejected() {
        // 圧縮前は上限内だが、受信側の上限（件数）を超えるブロックを手で組んで流す。
        let mut raw = Vec::new();
        put_u32(&mut raw, 1);
        put_u32(&mut raw, 1);
        raw.push(b'x');
        put_u32(&mut raw, (MAX_HEADER_FIELD_BYTES + 1) as u32);
        raw.extend(vec![b'a'; MAX_HEADER_FIELD_BYTES + 1]);
        let mut comp = HeaderCompressor::new().expect("comp");
        let block = comp.compress(&raw).expect("compress");
        let mut wire = Vec::new();
        control_header(&mut wire, TYPE_SYN_REPLY, 0, 4 + block.len()).expect("hdr");
        put_u32(&mut wire, 1);
        wire.extend(&block);
        let mut dec = FrameDecoder::new(1 << 20);
        dec.push(&wire).expect("push");
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::LimitExceeded("header field is too large"))
        );
    }

    /// CRI-6: 展開後 64 KiB を超えるブロックは展開で打ち切る（巨大な値を何度も含む入力）。
    #[test]
    fn cri6_decompressed_block_over_limit_rejected() {
        let mut raw = Vec::new();
        put_u32(&mut raw, 1);
        put_u32(&mut raw, 1);
        raw.push(b'x');
        put_u32(&mut raw, 1_000_000);
        raw.extend(vec![b'a'; 1_000_000]);
        let mut comp = HeaderCompressor::new().expect("comp");
        let block = comp.compress(&raw).expect("compress");
        assert!(block.len() < 8 * 1024, "compressed size {}", block.len());
        let mut wire = Vec::new();
        control_header(&mut wire, TYPE_SYN_REPLY, 0, 4 + block.len()).expect("hdr");
        put_u32(&mut wire, 1);
        wire.extend(&block);
        let mut dec = FrameDecoder::new(1 << 20);
        dec.push(&wire).expect("push");
        assert_eq!(
            dec.next_frame(),
            Err(SpdyError::LimitExceeded("header block is too large"))
        );
    }
}
