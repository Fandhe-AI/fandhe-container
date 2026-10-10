//! vhost-user メッセージの codec（ヘッダ・ペイロードの復号と符号化。GPU-6・MVM-4・REPAIR-2・TASK-172 F1.1・#1516）。
//!
//! 役割: 治具 VMM（暫定選定は crosvm の vhost-user frontend）とネゴシエーションするのに要る最小の要求種別だけを、
//! 固定長の型で復号・符号化する。呼び出し元は `fd_passing`（F1.2。#1517）の受け渡し結果を
//! 復号する `crate::session`（F1.4。#1519）。
//!
//! fd（`SCM_RIGHTS`）の送受信と共有メモリの mmap は `fd_passing` / `guest_memory`（Linux 限定。F1.2・#1517）が担当する。
//!
//! ヘッダ単位のソケット読み書きとネゴシエーション済み feature の照合は `crate::session`（F1.4・#1519）が実装済み。
//! virtqueue と vring アドレスの値の意味の検証（アラインメント・log ビット）は `crate::virtqueue`（F1.3・#1518）が実装済み。
//! ここで検査するのはワイヤー上の予約ビット・長さ・個数の上限だけ。
//!
//! 入力は frontend 由来の untrusted。検査順は固定で、復号は 12 バイト未満（`SHORT_HEADER`）、version（`UNSUPPORTED_VERSION`）、
//! 予約ビット・方向（`INVALID_FLAGS`）、size 上限（`PAYLOAD_TOO_LARGE`。ペイロードを読む前）、最小集合外の要求
//! （`UNKNOWN_REQUEST`）、全体長（`LENGTH_MISMATCH`）、種別ごとの期待長（`LENGTH_MISMATCH`）、値（`INVALID_VALUE`）の順。
//!
//! 出典（確認日 2026-10-09。値＝要求 ID・ビット値・フィールド配置のみ転記し、コードは流用していない。crosvm の
//! `vmm_vhost` は rust-vmm の `vhost` 由来の系統のため構造体定義やロジックは写さない。MVM-4）:
//! - QEMU `docs/interop/vhost-user.rst` タグ `v10.1.0`（SHA-256 `1c06e32a3306172499767170b0b64ce8de4a8a90cbe543a00cc1b3861ae5bccd`）
//! - crosvm コミット `044c3e3fc53d` の `third_party/vmm_vhost/src/message.rs`
//!   （`df6c31711167fe3b94080db4655826bb834cd2e9ac085915ce448652b8ab3495`）・`backend_client.rs`
//!   （`709fe08830a38c5e15a00c0c5af47ef7dabf19a784c0694abf8c10d335dec7c2`）・
//!   `devices/src/virtio/vhost_user_frontend/mod.rs`（`9506fcaae2e7e4aec09baa1374cbbd0a3807c5f38f8566b5c4f5856e4ea22266`）
//!
//! バイト順: rst は「ホストのネイティブ順」と定める。治具の動作環境（Linux x86_64 / aarch64、CI の 3 OS）はすべて
//! little-endian なので little-endian 固定とし、big-endian ターゲットはコンパイルエラーにする（fail-closed）。

#[cfg(target_endian = "big")]
compile_error!("vhost-user codec supports little-endian targets only");

mod error;
mod message;

#[cfg(target_os = "linux")]
pub mod fd_passing;
#[cfg(target_os = "linux")]
pub mod guest_memory;
#[cfg(target_os = "linux")]
pub mod observe;
#[cfg(target_os = "linux")]
mod transport_error;

#[cfg(test)]
mod tests;

pub use error::{CodecError, CodecErrorCode};
pub use message::{
    Ack, ConfigPayload, Decoded, MemRegion, MemTable, Reply, Request, VringAddr, VringFd,
    VringState, decode_reply, decode_request, decode_request_payload,
};
#[cfg(target_os = "linux")]
pub use transport_error::{TransportError, TransportErrorCode};

/// ヘッダ長（request・flags・size の各 u32）。
pub const HEADER_LEN: usize = 12;
/// 1 メッセージのペイロード長の上限。最大の形は `SET_MEM_TABLE`（8 + 32 領域 × 32 バイト）。
pub const MAX_PAYLOAD_LEN: usize = 8 + MAX_MEM_REGIONS * MEM_REGION_LEN;
/// ヘッダを含む 1 メッセージの最大長。
pub const MAX_MSG_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;
/// `SET_MEM_TABLE` の領域数の上限。crosvm の上限（`MAX_ATTACHED_FD_ENTRIES`）に合わせる。QEMU の rst は 8 だが、
/// crosvm の正当な要求を拒否しないよう大きい方に揃える。0 領域は拒否する。
pub const MAX_MEM_REGIONS: usize = 32;
/// メモリ領域 1 個の長さ（guest_phys_addr・memory_size・userspace_addr・mmap_offset の各 u64）。
pub const MEM_REGION_LEN: usize = 32;
/// config データの上限。治具独自の上限（`virtio_gpu_config` は 16 バイトで足りる）。
pub const MAX_CONFIG_SIZE: usize = 256;
/// config ペイロードの固定部（offset・size・flags の各 u32）。
pub const CONFIG_FIXED_LEN: usize = 12;

/// flags の version 部（下位 2 ビット）のマスク。
pub const FLAG_VERSION_MASK: u32 = 0x3;
/// 現行の version。
pub const VERSION: u32 = 0x1;
/// `REPLY` ビット（応答）。
pub const FLAG_REPLY: u32 = 1 << 2;
/// `NEED_REPLY` ビット（要求側が応答を求める）。
pub const FLAG_NEED_REPLY: u32 = 1 << 3;
/// 定義済みビットの集合。これ以外は予約。
const FLAGS_DEFINED: u32 = FLAG_VERSION_MASK | FLAG_REPLY | FLAG_NEED_REPLY;
/// config の flags で定義済みのビット（crosvm の `WRITABLE`=0x1・`LIVE_MIGRATION`=0x2）。
pub const CONFIG_FLAGS_DEFINED: u32 = 0x3;
/// `SET_VRING_KICK` / `SET_VRING_CALL` の u64 のうち vring index（bit 0-7）のマスク。
pub const VRING_INDEX_MASK: u64 = 0xff;
/// 同 u64 の「fd なし」ビット（bit 8）。
pub const VRING_NOFD: u64 = 1 << 8;
/// virtio feature の `VHOST_USER_F_PROTOCOL_FEATURES`（bit 30）。
pub const F_PROTOCOL_FEATURES: u64 = 1 << 30;
/// protocol feature の MQ（bit 0）。治具が広告する（F1.4）。
pub const PROTOCOL_F_MQ: u64 = 1 << 0;
/// protocol feature の REPLY_ACK（bit 3）。確定すると、frontend が NEED_REPLY を立てた要求へ backend が応答する義務を負う
/// （GPU-6・TASK-172 F5.2b.1・#1639。応答規則は `docs/design/venus-decoder-poc.md` 10.8）。
pub const PROTOCOL_F_REPLY_ACK: u64 = 1 << 3;
/// protocol feature の CONFIG（bit 9）。virtio-gpu config の読み出しに要る。
pub const PROTOCOL_F_CONFIG: u64 = 1 << 9;

/// 治具が扱う最小の要求種別（16 種）。値は QEMU rst と crosvm で一致する要求 ID。
///
/// 前提: 治具は virtio feature の bit 30 を立て、protocol feature は MQ・REPLY_ACK・CONFIG だけを広告する。
/// BACKEND_REQ・SHMEM・DEVICE_STATE・CONFIGURE_MEM_SLOTS は host-visible 共有メモリの方式（#1057）が
/// 決まるまで後送りで、それらの要求は `UNKNOWN_REQUEST` で拒否する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RequestCode {
    /// `GET_FEATURES`。
    GetFeatures = 1,
    /// `SET_FEATURES`。
    SetFeatures = 2,
    /// `SET_OWNER`。
    SetOwner = 3,
    /// `SET_MEM_TABLE`。
    SetMemTable = 5,
    /// `SET_VRING_NUM`。
    SetVringNum = 8,
    /// `SET_VRING_ADDR`。
    SetVringAddr = 9,
    /// `SET_VRING_BASE`。
    SetVringBase = 10,
    /// `GET_VRING_BASE`。
    GetVringBase = 11,
    /// `SET_VRING_KICK`。
    SetVringKick = 12,
    /// `SET_VRING_CALL`。
    SetVringCall = 13,
    /// `GET_PROTOCOL_FEATURES`。
    GetProtocolFeatures = 15,
    /// `SET_PROTOCOL_FEATURES`。
    SetProtocolFeatures = 16,
    /// `GET_QUEUE_NUM`。
    GetQueueNum = 17,
    /// `SET_VRING_ENABLE`。
    SetVringEnable = 18,
    /// `GET_CONFIG`。
    GetConfig = 24,
    /// `SET_CONFIG`。
    SetConfig = 25,
}

impl RequestCode {
    /// 最小集合の要求 ID なら `Some`。集合外（既知の ID も含む）は `None`。
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::GetFeatures,
            2 => Self::SetFeatures,
            3 => Self::SetOwner,
            5 => Self::SetMemTable,
            8 => Self::SetVringNum,
            9 => Self::SetVringAddr,
            10 => Self::SetVringBase,
            11 => Self::GetVringBase,
            12 => Self::SetVringKick,
            13 => Self::SetVringCall,
            15 => Self::GetProtocolFeatures,
            16 => Self::SetProtocolFeatures,
            17 => Self::GetQueueNum,
            18 => Self::SetVringEnable,
            24 => Self::GetConfig,
            25 => Self::SetConfig,
            _ => return None,
        })
    }

    /// ワイヤー上の要求 ID。
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// この要求がもともと明示的な応答本体を持つなら真（`GET_*`）。
    ///
    /// QEMU `docs/interop/vhost-user.rst`（v10.1.0）の Communication 節は応答を求める要求として `GET_FEATURES`・
    /// `GET_PROTOCOL_FEATURES`・`GET_QUEUE_NUM`・`GET_VRING_BASE`・`GET_CONFIG` を挙げ、REPLY_ACK 節は「応答本体を持つ要求は
    /// NEED_REPLY があっても挙動が変わらない」とする。このため真の要求には追加の ack を返さず、既存の応答で兼ねる
    /// （GPU-6・TASK-172 F5.2b.1・#1639）。
    pub fn has_reply_body(self) -> bool {
        matches!(
            self,
            Self::GetFeatures
                | Self::GetProtocolFeatures
                | Self::GetQueueNum
                | Self::GetVringBase
                | Self::GetConfig
        )
    }
}

/// どちら向きのメッセージとして復号するか。flags の方向ビットの妥当性が変わる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// frontend から backend（REPLY 不可・NEED_REPLY 可）。
    Request,
    /// backend から frontend（REPLY 必須・NEED_REPLY 不可）。
    Reply,
}

/// 検証済みの 12 バイトヘッダ。フィールドは非公開で、`decode` 以外に壊れた値を作る経路を持たない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    request: RequestCode,
    reply: bool,
    need_reply: bool,
    size: u32,
}

impl Header {
    /// 先頭 12 バイトを検査して復号する。ペイロードには触れない（F1.2 が「ヘッダ → size 検証 → ペイロード読み」の
    /// 2 段で使うため、size の上限判定はここで済ませる）。
    pub(crate) fn decode(buf: &[u8], dir: Direction) -> Result<Self, CodecError> {
        let short = || CodecError::new(CodecErrorCode::ShortHeader, None);
        let raw_request = read_u32(buf, 0).ok_or_else(short)?;
        let flags = read_u32(buf, 4).ok_or_else(short)?;
        let size = read_u32(buf, 8).ok_or_else(short)?;
        let req = Some(raw_request);
        if flags & FLAG_VERSION_MASK != VERSION {
            return Err(CodecError::new(CodecErrorCode::UnsupportedVersion, req));
        }
        let reply = flags & FLAG_REPLY != 0;
        let need_reply = flags & FLAG_NEED_REPLY != 0;
        let bad_dir = match dir {
            Direction::Request => reply,
            Direction::Reply => !reply || need_reply,
        };
        if flags & !FLAGS_DEFINED != 0 || bad_dir {
            return Err(CodecError::new(CodecErrorCode::InvalidFlags, req));
        }
        if usize::try_from(size).map_or(true, |s| s > MAX_PAYLOAD_LEN) {
            return Err(CodecError::new(CodecErrorCode::PayloadTooLarge, req));
        }
        let request = RequestCode::from_u32(raw_request)
            .ok_or_else(|| CodecError::new(CodecErrorCode::UnknownRequest, req))?;
        Ok(Self {
            request,
            reply,
            need_reply,
            size,
        })
    }

    /// 先頭 12 バイトを「frontend から backend への要求」として検査して復号する公開入口。
    /// 方向を要求に固定するため、crate 外の呼び出し元（F1.2）は「ヘッダ検証 → `payload_len` 確認 →
    /// ペイロード読み → `decode_request_payload`」の 2 段復号を公開 API だけで行える（REPAIR-2・GPU-6）。
    /// `buf` は 12 バイト以上であればよく、ペイロードには触れない。
    pub fn decode_request(buf: &[u8]) -> Result<Self, CodecError> {
        Self::decode(buf, Direction::Request)
    }

    /// 要求種別。
    pub fn request(&self) -> RequestCode {
        self.request
    }

    /// 応答メッセージなら true。
    pub fn is_reply(&self) -> bool {
        self.reply
    }

    /// `NEED_REPLY` が立っているか。
    pub fn need_reply(&self) -> bool {
        self.need_reply
    }

    /// 後続ペイロードの長さ（`MAX_PAYLOAD_LEN` 以下であることは `decode` が保証する）。
    pub fn payload_len(&self) -> usize {
        // decode で MAX_PAYLOAD_LEN 以下と検証済みなので変換は失敗しない。
        usize::try_from(self.size).unwrap_or(MAX_PAYLOAD_LEN)
    }

    /// 12 バイトへ符号化する。
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut flags = VERSION;
        if self.reply {
            flags |= FLAG_REPLY;
        }
        if self.need_reply {
            flags |= FLAG_NEED_REPLY;
        }
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.request.as_u32().to_le_bytes());
        out[4..8].copy_from_slice(&flags.to_le_bytes());
        out[8..12].copy_from_slice(&self.size.to_le_bytes());
        out
    }

    /// 符号化側の組み立て用。`payload_len` は呼び出し側で `MAX_PAYLOAD_LEN` 以下にしてから渡す。
    pub(crate) fn new(
        request: RequestCode,
        reply: bool,
        need_reply: bool,
        payload_len: usize,
    ) -> Result<Self, CodecError> {
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(CodecError::new(
                CodecErrorCode::PayloadTooLarge,
                Some(request.as_u32()),
            ));
        }
        let size = u32::try_from(payload_len).map_err(|_| {
            CodecError::new(CodecErrorCode::PayloadTooLarge, Some(request.as_u32()))
        })?;
        Ok(Self {
            request,
            reply,
            need_reply,
            size,
        })
    }
}

/// 符号化済みメッセージ。固定長配列と有効長で持ち、ヒープ確保をしない（REPAIR-2）。
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedMessage {
    buf: [u8; MAX_MSG_LEN],
    len: usize,
}

impl std::fmt::Debug for EncodedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodedMessage")
            .field("len", &self.len)
            .finish()
    }
}

impl EncodedMessage {
    /// 送出するバイト列（ヘッダ + ペイロード）。
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// ヘッダ + ペイロードを組み立てる。ペイロードは `fill` が書く。
    pub(crate) fn build(
        header: &Header,
        fill: impl FnOnce(&mut Writer) -> Result<(), CodecError>,
    ) -> Result<Self, CodecError> {
        let req = Some(header.request().as_u32());
        let mut w = Writer {
            buf: [0u8; MAX_MSG_LEN],
            pos: 0,
            req,
        };
        w.put(&header.encode())?;
        fill(&mut w)?;
        // size とペイロードの実長が食い違う組み立て（実装の誤り）は fail-closed にする。
        if w.pos != HEADER_LEN + header.payload_len() {
            return Err(CodecError::new(CodecErrorCode::LengthMismatch, req));
        }
        Ok(Self {
            buf: w.buf,
            len: w.pos,
        })
    }
}

/// 固定長バッファへの境界検査付き書き込み。
pub(crate) struct Writer {
    buf: [u8; MAX_MSG_LEN],
    pos: usize,
    req: Option<u32>,
}

impl Writer {
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        let err = || CodecError::new(CodecErrorCode::PayloadTooLarge, self.req);
        let end = self.pos.checked_add(bytes.len()).ok_or_else(err)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or_else(err)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub(crate) fn u32(&mut self, v: u32) -> Result<(), CodecError> {
        self.put(&v.to_le_bytes())
    }

    pub(crate) fn u64(&mut self, v: u64) -> Result<(), CodecError> {
        self.put(&v.to_le_bytes())
    }
}

/// 境界検査付きの読み取りカーソル。不足は `LENGTH_MISMATCH`。
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    req: Option<u32>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], req: RequestCode) -> Self {
        Self {
            buf,
            pos: 0,
            req: Some(req.as_u32()),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let err = || CodecError::new(CodecErrorCode::LengthMismatch, self.req);
        let end = self.pos.checked_add(n).ok_or_else(err)?;
        let s = self.buf.get(self.pos..end).ok_or_else(err)?;
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().map_err(|_| {
            CodecError::new(CodecErrorCode::LengthMismatch, self.req)
        })?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().map_err(|_| {
            CodecError::new(CodecErrorCode::LengthMismatch, self.req)
        })?))
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        self.take(n)
    }

    /// 未読の残りバイト数。
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// 全部読み切ったか（余りがあれば `LENGTH_MISMATCH`）。
    pub(crate) fn finish(&self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::new(CodecErrorCode::LengthMismatch, self.req))
        }
    }
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(off..end)?.try_into().ok()?))
}
