//! backend 要求 `SHMEM_MAP` / `SHMEM_UNMAP` の codec（GPU-6・MVM-4・REPAIR-2・TASK-172 F5.2b.3・#1642）。OS 非依存。
//!
//! 役割: 治具（backend）が `SET_BACKEND_REQ_FD` の UDS で frontend（crosvm 等）へ送る要求と、その応答（REPLY）を、
//! 固定長配列と「壊れた値を表現できない型」で組み立て・検査する。呼び出し元は `crate::session` の backend 要求送信
//! （`Session::shmem_map` / `shmem_unmap`。Linux 限定）と、偽 frontend を動かす試験。実際の送受信・期限・fd の受け渡しは
//! `session` と `fd_passing` が担い、ここは I/O を持たない。ctrl の `MAP_BLOB` / `UNMAP_BLOB` からの呼び出しは `session`（#1643）。
//!
//! 名前空間の分離: backend 要求の ID（9 = `SHMEM_MAP`、10 = `SHMEM_UNMAP`）は frontend 要求の 9（`SET_VRING_ADDR`）・
//! 10（`SET_VRING_BASE`）と数値が重なる。そのため既存の `RequestCode` / `Header` / `decode_reply` は使わず
//! （`decode_reply` に渡すと `SET_VRING_ADDR` の応答として読んでしまう）、専用の [`BackendRequestCode`] と
//! 固定長の符号化・復号を持つ。エラーも `CodecError`（`request: Option<u32>`）とは別の型にして、ログ上で
//! 9 / 10 が frontend 要求と紛れないようにする。
//!
//! 入力（応答）は frontend 由来の untrusted。検査順は固定: version・予約ビット（`REPLY_INVALID_FLAGS`）→ REPLY ビット
//! （`REPLY_FLAG_MISSING`）→ NEED_REPLY が付いていない（`REPLY_INVALID_FLAGS`）→ 要求 ID 一致（`REPLY_REQUEST_MISMATCH`）→
//! size = 8（`REPLY_SIZE_MISMATCH`。ペイロードを読む前）。エラーに受信バイト列は載せない。
//!
//! 送信前の検査（fail-closed）は [`ShmemMapping::new`] と [`ShmemMapRequest::new`] が担う。UNMAP は MAP と同じ
//! [`ShmemMapping`] からしか作れないので、shmid・shm_offset・len の食い違いは型として作れない。
//! 出典（確認日 2026-10-10。値＝ID・ビット値・配置のみ転記し、コードは流用していない。MVM-4）:
//! QEMU `docs/interop/vhost-user.rst` master（`615ece3c406b`。SHA-256 `684b11b15330ee23f2922aab9abd116efa1f48eb15b1b02b0233418e1a224257`）、
//! crosvm `044c3e3fc53d` の `third_party/vmm_vhost/src/frontend_server.rs`（`f79e44ad86f34f0ad45e153eeb291035dea67f61c2204c6023e1a1834af21bf2`）。
//! 設計書 `docs/design/venus-decoder-poc.md` 10.4.4。

use std::fmt;

use super::{
    FLAG_NEED_REPLY, FLAG_REPLY, FLAG_VERSION_MASK, HEADER_LEN, SHMEM_PAGE_ALIGN, ShmemConfig,
    VERSION,
};

/// backend 要求のペイロード長（shmid u8・padding 7・fd_offset・shm_offset・len・flags の各 u64）。
pub const BACKEND_REQ_PAYLOAD_LEN: usize = 40;
/// backend 要求全体の長さ（ヘッダ 12 + ペイロード 40）。
pub const BACKEND_REQ_LEN: usize = HEADER_LEN + BACKEND_REQ_PAYLOAD_LEN;
/// 応答のペイロード長（u64 が 1 個。0 = 成功、非 0 = 失敗）。
pub const BACKEND_REPLY_PAYLOAD_LEN: usize = 8;
/// 応答全体の長さ。
pub const BACKEND_REPLY_LEN: usize = HEADER_LEN + BACKEND_REPLY_PAYLOAD_LEN;
/// MMap の flags: 読み書き可（0 は読み取り専用。治具は使わない）。
pub const MMAP_FLAG_RW: u64 = 1;

const FLAGS_DEFINED: u32 = FLAG_VERSION_MASK | FLAG_REPLY | FLAG_NEED_REPLY;

/// backend 要求の ID。frontend 要求の `RequestCode` とは別の名前空間（同じ数値 9・10 を持つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BackendRequestCode {
    /// fd を共有メモリ領域へ map させる。
    ShmemMap = 9,
    /// map 済み領域を解放させる（fd なし）。
    ShmemUnmap = 10,
}

impl BackendRequestCode {
    /// ワイヤー上の ID。
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    fn from_u32(v: u32) -> Option<Self> {
        match v {
            9 => Some(Self::ShmemMap),
            10 => Some(Self::ShmemUnmap),
            _ => None,
        }
    }

    /// ログに出す固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShmemMap => "SHMEM_MAP",
            Self::ShmemUnmap => "SHMEM_UNMAP",
        }
    }
}

/// codec エラーの種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendCodecErrorCode {
    /// shmid が `GET_SHMEM_CONFIG` で広告していない領域（大きさ 0）。
    InvalidShmid,
    /// len が 0、またはページ（4096）の倍数でない。
    InvalidLength,
    /// shm_offset または fd_offset がページ境界にない。
    Unaligned,
    /// `shm_offset + len` または `fd_offset + len` が u64 を溢れる。
    Overflow,
    /// `shm_offset + len` が領域の大きさを超える。
    OutOfRegion,
    /// 応答の flags が不正（version・予約ビット・NEED_REPLY 付き）。
    ReplyInvalidFlags,
    /// 応答に REPLY ビットが無い。
    ReplyFlagMissing,
    /// 応答の要求 ID が送った要求と違う（未知の ID を含む）。
    ReplyRequestMismatch,
    /// 応答の size が 8 ではない。
    ReplySizeMismatch,
    /// （偽 frontend 役の復号）要求の長さが 52 バイトでない。
    LengthMismatch,
    /// （偽 frontend 役の復号）要求の flags が NEED_REPLY 付きの version 1 ではない。
    InvalidFlags,
    /// （偽 frontend 役の復号）padding が 0 でない・flags 未定義ビット・溢れ・UNMAP に fd_offset / flags がある。
    InvalidValue,
}

impl BackendCodecErrorCode {
    /// 外部へ出す固定の code 文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidShmid => "INVALID_SHMID",
            Self::InvalidLength => "INVALID_LENGTH",
            Self::Unaligned => "UNALIGNED",
            Self::Overflow => "OVERFLOW",
            Self::OutOfRegion => "OUT_OF_REGION",
            Self::ReplyInvalidFlags => "REPLY_INVALID_FLAGS",
            Self::ReplyFlagMissing => "REPLY_FLAG_MISSING",
            Self::ReplyRequestMismatch => "REPLY_REQUEST_MISMATCH",
            Self::ReplySizeMismatch => "REPLY_SIZE_MISMATCH",
            Self::LengthMismatch => "LENGTH_MISMATCH",
            Self::InvalidFlags => "INVALID_FLAGS",
            Self::InvalidValue => "INVALID_VALUE",
        }
    }
}

/// 構造化エラー。`request` は判明している場合の backend 要求 ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCodecError {
    /// 機械可読な種別。
    pub code: BackendCodecErrorCode,
    /// 判明している backend 要求（送った側の要求。frontend 要求の ID とは別型）。
    pub request: Option<BackendRequestCode>,
}

impl BackendCodecError {
    fn new(code: BackendCodecErrorCode, request: Option<BackendRequestCode>) -> Self {
        Self { code, request }
    }

    /// 英語の固定文（入力由来の文字列を含まない）。
    pub fn message(&self) -> &'static str {
        match self.code {
            BackendCodecErrorCode::InvalidShmid => {
                "shmid is not an advertised shared memory region"
            }
            BackendCodecErrorCode::InvalidLength => {
                "length is zero or not a multiple of the page size"
            }
            BackendCodecErrorCode::Unaligned => "offset is not page aligned",
            BackendCodecErrorCode::Overflow => "offset plus length overflows",
            BackendCodecErrorCode::OutOfRegion => "mapping exceeds the shared memory region",
            BackendCodecErrorCode::ReplyInvalidFlags => "backend reply header flags are invalid",
            BackendCodecErrorCode::ReplyFlagMissing => "backend reply is missing the REPLY flag",
            BackendCodecErrorCode::ReplyRequestMismatch => {
                "backend reply request id does not match"
            }
            BackendCodecErrorCode::ReplySizeMismatch => "backend reply size is not 8",
            BackendCodecErrorCode::LengthMismatch => "backend request length is not 52",
            BackendCodecErrorCode::InvalidFlags => "backend request header flags are invalid",
            BackendCodecErrorCode::InvalidValue => "backend request field value is invalid",
        }
    }
}

impl fmt::Display for BackendCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.request {
            Some(r) => write!(
                f,
                "{} (backend request={}): {}",
                self.code.as_str(),
                r.as_str(),
                self.message()
            ),
            None => write!(f, "{}: {}", self.code.as_str(), self.message()),
        }
    }
}

impl std::error::Error for BackendCodecError {}

fn is_page_aligned(v: u64) -> bool {
    v.is_multiple_of(SHMEM_PAGE_ALIGN)
}

/// 共有メモリ領域の中の 1 区間（shmid・shm_offset・len）。検査済みの値しか持てない（フィールドは非公開）。
///
/// MAP と UNMAP の両方がこの値から作られるので、UNMAP が MAP と同じ範囲を指すことは型で保証される
/// （rst は「UNMAP の範囲は map 済み領域全体と一致」と定める）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmemMapping {
    shmid: u8,
    shm_offset: u64,
    len: u64,
}

impl ShmemMapping {
    /// `config`（`GET_SHMEM_CONFIG` で広告した値）に照らして検査して作る。検査順は固定:
    /// shmid（`INVALID_SHMID`）→ len（`INVALID_LENGTH`）→ shm_offset のページ境界（`UNALIGNED`）→
    /// `shm_offset + len` の溢れ（`OVERFLOW`）→ 領域内（`OUT_OF_REGION`）。
    pub fn new(
        config: &ShmemConfig,
        shmid: u8,
        shm_offset: u64,
        len: u64,
    ) -> Result<Self, BackendCodecError> {
        let err = |c| BackendCodecError::new(c, None);
        let region = config.size(shmid);
        if region == 0 {
            return Err(err(BackendCodecErrorCode::InvalidShmid));
        }
        if len == 0 || !is_page_aligned(len) {
            return Err(err(BackendCodecErrorCode::InvalidLength));
        }
        if !is_page_aligned(shm_offset) {
            return Err(err(BackendCodecErrorCode::Unaligned));
        }
        let end = shm_offset
            .checked_add(len)
            .ok_or_else(|| err(BackendCodecErrorCode::Overflow))?;
        if end > region {
            return Err(err(BackendCodecErrorCode::OutOfRegion));
        }
        Ok(Self {
            shmid,
            shm_offset,
            len,
        })
    }

    /// 共有メモリ領域の id。
    pub fn shmid(&self) -> u8 {
        self.shmid
    }
    /// 領域内のオフセット。
    pub fn shm_offset(&self) -> u64 {
        self.shm_offset
    }
    /// 長さ。
    pub fn len(&self) -> u64 {
        self.len
    }
    /// 長さは 0 にならない（常に偽）。clippy の `len_without_is_empty` 用。
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// `SHMEM_MAP` の内容（区間と、渡す fd の中のオフセット）。flags は型として `MAP_RW` に固定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmemMapRequest {
    mapping: ShmemMapping,
    fd_offset: u64,
}

impl ShmemMapRequest {
    /// `fd_offset` は mmap(2) の offset 制約でページ境界であること（`UNALIGNED`。frontend の失敗を送る前に防ぐ）、
    /// `fd_offset + len` が溢れないこと（`OVERFLOW`。crosvm の `is_valid` も拒否する）。
    pub fn new(mapping: ShmemMapping, fd_offset: u64) -> Result<Self, BackendCodecError> {
        let err = |c| BackendCodecError::new(c, Some(BackendRequestCode::ShmemMap));
        if !is_page_aligned(fd_offset) {
            return Err(err(BackendCodecErrorCode::Unaligned));
        }
        fd_offset
            .checked_add(mapping.len)
            .ok_or_else(|| err(BackendCodecErrorCode::Overflow))?;
        Ok(Self { mapping, fd_offset })
    }

    /// map する区間。
    pub fn mapping(&self) -> &ShmemMapping {
        &self.mapping
    }
    /// fd 内のオフセット。
    pub fn fd_offset(&self) -> u64 {
        self.fd_offset
    }
}

/// 送れる backend 要求。NEED_REPLY は常に立てる（応答で確かめられない map をしないため、立てない形は作れない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRequest {
    /// `SHMEM_MAP`（fd を 1 本添える）。
    ShmemMap(ShmemMapRequest),
    /// `SHMEM_UNMAP`（fd なし。MAP と同じ区間）。
    ShmemUnmap(ShmemMapping),
}

impl BackendRequest {
    /// 要求 ID。
    pub fn code(&self) -> BackendRequestCode {
        match self {
            Self::ShmemMap(_) => BackendRequestCode::ShmemMap,
            Self::ShmemUnmap(_) => BackendRequestCode::ShmemUnmap,
        }
    }

    /// 対象の区間。
    pub fn mapping(&self) -> &ShmemMapping {
        match self {
            Self::ShmemMap(m) => m.mapping(),
            Self::ShmemUnmap(m) => m,
        }
    }

    /// 52 バイトのワイヤー表現（ヘッダ `[ID, 0x9, 40]` + shmid・padding 7・fd_offset・shm_offset・len・flags）。
    /// UNMAP の fd_offset と flags は 0。
    pub fn encode(&self) -> [u8; BACKEND_REQ_LEN] {
        let (fd_offset, flags) = match self {
            Self::ShmemMap(m) => (m.fd_offset, MMAP_FLAG_RW),
            Self::ShmemUnmap(_) => (0, 0),
        };
        let m = self.mapping();
        let mut out = [0u8; BACKEND_REQ_LEN];
        let mut put = |at: usize, bytes: &[u8]| {
            if let Some(dst) = out.get_mut(at..at + bytes.len()) {
                dst.copy_from_slice(bytes);
            }
        };
        put(0, &self.code().as_u32().to_le_bytes());
        put(4, &(VERSION | FLAG_NEED_REPLY).to_le_bytes());
        // 40 は定数なので変換は失敗しない。
        put(8, &(BACKEND_REQ_PAYLOAD_LEN as u32).to_le_bytes());
        put(12, &[m.shmid]);
        put(20, &fd_offset.to_le_bytes());
        put(28, &m.shm_offset.to_le_bytes());
        put(36, &m.len.to_le_bytes());
        put(44, &flags.to_le_bytes());
        out
    }
}

fn le32(buf: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = buf.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

fn le64(buf: &[u8], at: usize) -> Option<u64> {
    let b: [u8; 8] = buf.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(b))
}

/// 応答ヘッダ（12 バイト）を検査する。ペイロードを読む前に size = 8 まで確かめるので、大きな size を受けても
/// 追加の読み込みをしない。`expected` は送った要求。
pub fn decode_backend_reply_header(
    header: &[u8; HEADER_LEN],
    expected: BackendRequestCode,
) -> Result<(), BackendCodecError> {
    let err = |c| BackendCodecError::new(c, Some(expected));
    let (Some(id), Some(flags), Some(size)) = (le32(header, 0), le32(header, 4), le32(header, 8))
    else {
        return Err(err(BackendCodecErrorCode::ReplyInvalidFlags));
    };
    if flags & FLAG_VERSION_MASK != VERSION || flags & !FLAGS_DEFINED != 0 {
        return Err(err(BackendCodecErrorCode::ReplyInvalidFlags));
    }
    if flags & FLAG_REPLY == 0 {
        return Err(err(BackendCodecErrorCode::ReplyFlagMissing));
    }
    if flags & FLAG_NEED_REPLY != 0 {
        return Err(err(BackendCodecErrorCode::ReplyInvalidFlags));
    }
    if BackendRequestCode::from_u32(id) != Some(expected) {
        return Err(err(BackendCodecErrorCode::ReplyRequestMismatch));
    }
    if usize::try_from(size) != Ok(BACKEND_REPLY_PAYLOAD_LEN) {
        return Err(err(BackendCodecErrorCode::ReplySizeMismatch));
    }
    Ok(())
}

/// 応答ペイロード（u64。0 = 成功）を読む。
pub fn decode_backend_reply_value(payload: &[u8; BACKEND_REPLY_PAYLOAD_LEN]) -> u64 {
    u64::from_le_bytes(*payload)
}

/// 偽 frontend 役が復号した backend 要求（試験用。フィールドは生の値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedBackendRequest {
    /// 要求 ID。
    pub request: BackendRequestCode,
    /// 共有メモリ領域の id。
    pub shmid: u8,
    /// fd 内のオフセット（UNMAP は 0）。
    pub fd_offset: u64,
    /// 領域内のオフセット。
    pub shm_offset: u64,
    /// 長さ。
    pub len: u64,
    /// MMap の flags（UNMAP は 0）。
    pub flags: u64,
}

/// 偽 frontend 役: 52 バイトの backend 要求を復号する（試験用。crosvm の `is_valid` と同じく flags が `MAP_RW` の集合に
/// 収まり、`fd_offset + len` と `shm_offset + len` が溢れないことを確かめる）。
/// 検査順: 長さ（`LENGTH_MISMATCH`）→ ヘッダ（`INVALID_FLAGS`・`INVALID_VALUE`）→ ペイロード（`INVALID_VALUE`）。
pub fn decode_backend_request(buf: &[u8]) -> Result<DecodedBackendRequest, BackendCodecError> {
    let e = |c, r| BackendCodecError::new(c, r);
    if buf.len() != BACKEND_REQ_LEN {
        return Err(e(BackendCodecErrorCode::LengthMismatch, None));
    }
    let bad = |r| e(BackendCodecErrorCode::InvalidValue, r);
    let (Some(id), Some(flags), Some(size)) = (le32(buf, 0), le32(buf, 4), le32(buf, 8)) else {
        return Err(bad(None));
    };
    let Some(request) = BackendRequestCode::from_u32(id) else {
        return Err(bad(None));
    };
    let r = Some(request);
    if flags != (VERSION | FLAG_NEED_REPLY) {
        return Err(e(BackendCodecErrorCode::InvalidFlags, r));
    }
    if usize::try_from(size) != Ok(BACKEND_REQ_PAYLOAD_LEN) {
        return Err(bad(r));
    }
    let padding_zero = buf.get(13..20).is_some_and(|p| p.iter().all(|b| *b == 0));
    let (Some(shmid), Some(fd_offset), Some(shm_offset), Some(len), Some(mflags)) = (
        buf.get(12).copied(),
        le64(buf, 20),
        le64(buf, 28),
        le64(buf, 36),
        le64(buf, 44),
    ) else {
        return Err(bad(r));
    };
    let unmap_clean = request == BackendRequestCode::ShmemMap || (fd_offset == 0 && mflags == 0);
    if !padding_zero
        || mflags & !MMAP_FLAG_RW != 0
        || !unmap_clean
        || fd_offset.checked_add(len).is_none()
        || shm_offset.checked_add(len).is_none()
    {
        return Err(bad(r));
    }
    Ok(DecodedBackendRequest {
        request,
        shmid,
        fd_offset,
        shm_offset,
        len,
        flags: mflags,
    })
}

/// 偽 frontend 役: 応答 20 バイト（ヘッダ `[ID, 0x5, 8]` + u64）を組み立てる。
pub fn encode_backend_reply(code: BackendRequestCode, value: u64) -> [u8; BACKEND_REPLY_LEN] {
    let mut out = [0u8; BACKEND_REPLY_LEN];
    let mut put = |at: usize, bytes: &[u8]| {
        if let Some(dst) = out.get_mut(at..at + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
    };
    put(0, &code.as_u32().to_le_bytes());
    put(4, &(VERSION | FLAG_REPLY).to_le_bytes());
    put(8, &(BACKEND_REPLY_PAYLOAD_LEN as u32).to_le_bytes());
    put(12, &value.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::super::{RequestCode, ShmemRegion, decode_reply};
    use super::*;

    const MIB128: u64 = 128 * 1024 * 1024;

    fn config() -> ShmemConfig {
        ShmemConfig::new(&[ShmemRegion {
            id: 1,
            size: MIB128,
        }])
        .expect("config")
    }

    fn mapping(off: u64, len: u64) -> ShmemMapping {
        ShmemMapping::new(&config(), 1, off, len).expect("mapping")
    }

    fn code_of<T: fmt::Debug>(r: Result<T, BackendCodecError>) -> &'static str {
        r.expect_err("must be rejected").code.as_str()
    }

    #[test]
    fn f5_2b_3_gpu6_map_request_wire_bytes() {
        let req = BackendRequest::ShmemMap(
            ShmemMapRequest::new(mapping(0x1000, 0x2000), 0).expect("req"),
        );
        let mut want = Vec::new();
        want.extend_from_slice(&[9, 0, 0, 0, 0x09, 0, 0, 0, 40, 0, 0, 0]);
        want.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        want.extend_from_slice(&0u64.to_le_bytes());
        want.extend_from_slice(&0x1000u64.to_le_bytes());
        want.extend_from_slice(&0x2000u64.to_le_bytes());
        want.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(req.encode().to_vec(), want);
        assert_eq!(req.encode().len(), 52);
    }

    #[test]
    fn f5_2b_3_gpu6_unmap_request_reuses_mapping_with_zero_fd_offset_and_flags() {
        let m = mapping(0x1000, 0x2000);
        let map = BackendRequest::ShmemMap(ShmemMapRequest::new(m, 0x3000).expect("req")).encode();
        let unmap = BackendRequest::ShmemUnmap(m).encode();
        assert_eq!(
            unmap.get(..12),
            Some(&[10, 0, 0, 0, 0x09, 0, 0, 0, 40, 0, 0, 0][..])
        );
        // shmid・shm_offset・len は MAP と同じ。
        assert_eq!(unmap.get(12..20), map.get(12..20));
        assert_eq!(unmap.get(28..44), map.get(28..44));
        // fd_offset と flags は 0。
        assert_eq!(unmap.get(20..28), Some(&[0u8; 8][..]));
        assert_eq!(unmap.get(44..52), Some(&[0u8; 8][..]));
        assert_eq!(map.get(20..28), Some(&0x3000u64.to_le_bytes()[..]));
    }

    #[test]
    fn f5_2b_3_gpu6_pre_send_rejections() {
        let c = config();
        let new = |shmid, off, len| ShmemMapping::new(&c, shmid, off, len);
        assert_eq!(code_of(new(2, 0, 4096)), "INVALID_SHMID");
        assert_eq!(code_of(new(1, 0, 0)), "INVALID_LENGTH");
        assert_eq!(code_of(new(1, 0, 4095)), "INVALID_LENGTH");
        assert_eq!(code_of(new(1, 4095, 4096)), "UNALIGNED");
        assert_eq!(code_of(new(1, u64::MAX - 4095, 8192)), "OVERFLOW");
        assert_eq!(code_of(new(1, MIB128 - 4096, 8192)), "OUT_OF_REGION");
        assert!(new(1, MIB128 - 8192, 8192).is_ok());
        let m = mapping(0, 8192);
        assert_eq!(code_of(ShmemMapRequest::new(m, 4095)), "UNALIGNED");
        assert_eq!(code_of(ShmemMapRequest::new(m, !4095u64)), "OVERFLOW");
        assert!(ShmemMapRequest::new(m, 0x10_0000).is_ok());
    }

    fn hdr(id: u32, flags: u32, size: u32) -> [u8; 12] {
        let mut h = [0u8; 12];
        h[..4].copy_from_slice(&id.to_le_bytes());
        h[4..8].copy_from_slice(&flags.to_le_bytes());
        h[8..].copy_from_slice(&size.to_le_bytes());
        h
    }

    #[test]
    fn f5_2b_3_gpu6_reply_header_checks() {
        use BackendRequestCode::ShmemMap;
        let check = |h: [u8; 12]| decode_backend_reply_header(&h, ShmemMap);
        assert_eq!(check(hdr(9, 0x5, 8)), Ok(()));
        assert_eq!(code_of(check(hdr(10, 0x5, 8))), "REPLY_REQUEST_MISMATCH");
        assert_eq!(code_of(check(hdr(99, 0x5, 8))), "REPLY_REQUEST_MISMATCH");
        assert_eq!(code_of(check(hdr(9, 0x1, 8))), "REPLY_FLAG_MISSING");
        assert_eq!(code_of(check(hdr(9, 0xd, 8))), "REPLY_INVALID_FLAGS");
        assert_eq!(code_of(check(hdr(9, 0x6, 8))), "REPLY_INVALID_FLAGS");
        assert_eq!(code_of(check(hdr(9, 0x15, 8))), "REPLY_INVALID_FLAGS");
        assert_eq!(code_of(check(hdr(9, 0x5, 16))), "REPLY_SIZE_MISMATCH");
        assert_eq!(code_of(check(hdr(9, 0x5, u32::MAX))), "REPLY_SIZE_MISMATCH");
    }

    #[test]
    fn f5_2b_3_gpu6_fake_frontend_roles_roundtrip_and_reject() {
        let m = mapping(0x1000, 0x2000);
        let req = BackendRequest::ShmemMap(ShmemMapRequest::new(m, 0x4000).expect("req"));
        let d = decode_backend_request(&req.encode()).expect("decode");
        assert_eq!(
            d,
            DecodedBackendRequest {
                request: BackendRequestCode::ShmemMap,
                shmid: 1,
                fd_offset: 0x4000,
                shm_offset: 0x1000,
                len: 0x2000,
                flags: 1,
            }
        );
        let reply = encode_backend_reply(BackendRequestCode::ShmemMap, 7);
        assert_eq!(reply.get(..12), Some(&hdr(9, 0x5, 8)[..]));
        assert_eq!(reply.get(12..), Some(&7u64.to_le_bytes()[..]));
        // 不正な要求（crosvm の is_valid 相当）。
        let mut bad = req.encode();
        bad[44] = 2; // 未定義の flags ビット
        assert_eq!(code_of(decode_backend_request(&bad)), "INVALID_VALUE");
        let mut bad = req.encode();
        bad[13] = 1; // padding
        assert_eq!(code_of(decode_backend_request(&bad)), "INVALID_VALUE");
        let mut bad = req.encode();
        bad[28..36].copy_from_slice(&u64::MAX.to_le_bytes()); // shm_offset + len が溢れる
        assert_eq!(code_of(decode_backend_request(&bad)), "INVALID_VALUE");
        let mut bad = req.encode();
        bad[4] = 0x01; // NEED_REPLY なし
        assert_eq!(code_of(decode_backend_request(&bad)), "INVALID_FLAGS");
        assert_eq!(
            code_of(decode_backend_request(&[0u8; 51])),
            "LENGTH_MISMATCH"
        );
    }

    #[test]
    fn f5_2b_3_gpu6_namespace_is_separate_from_frontend_requests() {
        // 数値は frontend 要求の 9・10 と同じだが、専用 codec の型は別。decode_reply は SET_VRING_ADDR の
        // 応答として読むので、backend 応答の復号には使わない。
        let reply = encode_backend_reply(BackendRequestCode::ShmemMap, 0);
        let decoded = decode_reply(&reply, RequestCode::SetVringAddr).expect("decode");
        assert!(
            format!("{decoded:?}").contains("SetVringAddr"),
            "{decoded:?}"
        );
        assert_eq!(BackendRequestCode::ShmemMap.as_u32(), 9);
        assert_eq!(BackendRequestCode::ShmemUnmap.as_u32(), 10);
    }
}
