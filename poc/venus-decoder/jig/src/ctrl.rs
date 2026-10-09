//! virtio-gpu ctrl メッセージの復号と応答符号化（capset クエリ・GET_DISPLAY_INFO・CTX_CREATE / DESTROY 分。
//! GPU-6・TASK-172.4・#1520）。
//!
//! 入力はゲスト由来の untrusted バイト列で、全読み取りを `get` / `try_into` で境界検査する。応答は固定長の
//! [`CtrlResponse`] で組み立て、生の `Vec` を手で組まない（REPAIR-2）。
//!
//! 出典: Linux `include/uapi/linux/virtio_gpu.h`（タグ `v6.12`、確認日 2026-10-08。取得時 SHA-256
//! `7c9e2f7d47fa0b1a2c737fc5a741f57c5cf25303dd5c68c2c9738e9bb761eee6`）。値（事実情報）のみ転記しコードは流用していない。
//! ライセンス: ファイル先頭に SPDX 行は無く、BSD 系の許諾文（3 条項。Copyright Red Hat, Inc. 2013-2014）が
//! 書かれている。帰属表示の要否は未決（#1603）。

use fandhe_container_plugin_macos::gpu::venus::{VENUS_CAPSET_ID, VENUS_CAPSET_LEN};

/// `VIRTIO_GPU_CMD_GET_CAPSET_INFO`。
pub const CMD_GET_CAPSET_INFO: u32 = 0x0108;
/// `VIRTIO_GPU_CMD_GET_CAPSET`。
pub const CMD_GET_CAPSET: u32 = 0x0109;
/// `VIRTIO_GPU_CMD_GET_DISPLAY_INFO`。
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
/// `VIRTIO_GPU_CMD_CTX_CREATE`。
pub const CMD_CTX_CREATE: u32 = 0x0200;
/// `VIRTIO_GPU_CMD_CTX_DESTROY`。
pub const CMD_CTX_DESTROY: u32 = 0x0201;
/// `VIRTIO_GPU_RESP_OK_NODATA`。
pub const RESP_OK_NODATA: u32 = 0x1100;
/// `VIRTIO_GPU_RESP_OK_DISPLAY_INFO`。
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
/// `VIRTIO_GPU_RESP_OK_CAPSET_INFO`。
pub const RESP_OK_CAPSET_INFO: u32 = 0x1102;
/// `VIRTIO_GPU_RESP_OK_CAPSET`。
pub const RESP_OK_CAPSET: u32 = 0x1103;
/// `VIRTIO_GPU_RESP_ERR_UNSPEC`。
pub const RESP_ERR_UNSPEC: u32 = 0x1200;
/// `VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY`。
pub const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
/// `VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID`。
pub const RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
/// `VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER`。
pub const RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

/// `VIRTIO_GPU_FLAG_FENCE`。
pub const FLAG_FENCE: u32 = 1 << 0;
/// `VIRTIO_GPU_FLAG_INFO_RING_IDX`。
pub const FLAG_INFO_RING_IDX: u32 = 1 << 1;

/// `struct virtio_gpu_ctrl_hdr` の長さ（type・flags・fence_id・ctx_id・ring_idx・padding[3]）。
pub const HDR_LEN: usize = 24;
/// 固定部を含む要求の長さ（ヘッダ 24 + 本体 8）。
pub const REQ_LEN: usize = HDR_LEN + 8;
/// `VIRTIO_GPU_MAX_SCANOUTS`。
pub const MAX_SCANOUTS: usize = 16;
/// `struct virtio_gpu_display_one` の長さ（rect 16 + enabled 4 + flags 4）。
pub const DISPLAY_ONE_LEN: usize = 24;
/// `OK_DISPLAY_INFO` の本体長（`pmodes[MAX_SCANOUTS]`）。
pub const DISPLAY_INFO_BODY_LEN: usize = MAX_SCANOUTS * DISPLAY_ONE_LEN;
/// `VIRTIO_GPU_CONTEXT_INIT_CAPSET_ID_MASK`。
pub const CONTEXT_INIT_CAPSET_ID_MASK: u32 = 0x0000_00ff;
/// `struct virtio_gpu_ctx_create.debug_name` の配列長（`nlen` の上限）。
pub const DEBUG_NAME_LEN: usize = 64;
/// `GET_DISPLAY_INFO` 要求の長さ（ヘッダのみ）。
pub const DISPLAY_INFO_REQ_LEN: usize = HDR_LEN;
/// `CTX_CREATE` 要求の長さ（ヘッダ + nlen 4 + context_init 4 + debug_name 64）。
pub const CTX_CREATE_REQ_LEN: usize = HDR_LEN + 8 + DEBUG_NAME_LEN;
/// `CTX_DESTROY` 要求の長さ（ヘッダのみ）。
pub const CTX_DESTROY_REQ_LEN: usize = HDR_LEN;
/// 応答の最大長（ヘッダ + capset データ または display info 本体の大きい方）。
pub const MAX_RESP_LEN: usize = HDR_LEN
    + if VENUS_CAPSET_LEN > DISPLAY_INFO_BODY_LEN {
        VENUS_CAPSET_LEN
    } else {
        DISPLAY_INFO_BODY_LEN
    };

/// 復号済みの `CTX_CREATE` 本体（debug_name は保持もログ出力もしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtxCreate {
    /// 名前長（`DEBUG_NAME_LEN` 以下）。
    pub nlen: u32,
    /// `context_init` の capset id（下位 8 bit。VENUS のみ受理）。
    pub capset_id: u8,
}

/// `CTX_CREATE` の復号失敗理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxCreateError {
    /// 要求長が `CTX_CREATE_REQ_LEN` でない。
    BadLength,
    /// `nlen` が上限超え（復号できた値を保持する）。
    NameTooLong(u32),
    /// capset id が VENUS でない、または予約 bit が立っている（`nlen` と下位 8 bit を保持する）。
    BadContextInit { nlen: u32, capset_id: u8 },
}

impl CtxCreate {
    /// 要求全体（ヘッダ込み）を検査して復号する。
    pub fn parse(req: &[u8]) -> Result<Self, CtxCreateError> {
        if req.len() != CTX_CREATE_REQ_LEN {
            return Err(CtxCreateError::BadLength);
        }
        let nlen = le32(req, HDR_LEN).ok_or(CtxCreateError::BadLength)?;
        let init = le32(req, HDR_LEN + 4).ok_or(CtxCreateError::BadLength)?;
        if usize::try_from(nlen).map_or(true, |n| n > DEBUG_NAME_LEN) {
            return Err(CtxCreateError::NameTooLong(nlen));
        }
        let capset_id = (init & CONTEXT_INIT_CAPSET_ID_MASK) as u8;
        if init & !CONTEXT_INIT_CAPSET_ID_MASK != 0 || u32::from(capset_id) != VENUS_CAPSET_ID {
            return Err(CtxCreateError::BadContextInit { nlen, capset_id });
        }
        Ok(Self { nlen, capset_id })
    }
}

/// 復号済みの ctrl ヘッダ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlHeader {
    /// コマンド種別。
    pub cmd_type: u32,
    /// フラグ。
    pub flags: u32,
    /// fence id。
    pub fence_id: u64,
    /// コンテキスト id。
    pub ctx_id: u32,
    /// ring index。
    pub ring_idx: u8,
}

impl CtrlHeader {
    /// 先頭 24 バイトを復号する。短ければ `None`。
    pub fn parse(req: &[u8]) -> Option<Self> {
        let hdr = req.get(..HDR_LEN)?;
        Some(Self {
            cmd_type: le32(hdr, 0)?,
            flags: le32(hdr, 4)?,
            fence_id: u64::from_le_bytes(hdr.get(8..16)?.try_into().ok()?),
            ctx_id: le32(hdr, 16)?,
            ring_idx: *hdr.get(20)?,
        })
    }
}

/// `buf` の `off` から little-endian `u32` を読む。範囲外なら `None`。
pub(crate) fn le32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(off..end)?.try_into().ok()?))
}

/// 固定長バッファに入った ctrl 応答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrlResponse {
    buf: [u8; MAX_RESP_LEN],
    len: usize,
}

impl CtrlResponse {
    /// 応答ヘッダ（要求ヘッダが fence 付きなら flags・fence_id・ctx_id・ring_idx を引き継ぐ）に本体を付けて作る。
    /// 本体が上限を超える場合は本体なしにする（呼び出し側は上限内のみ渡す）。
    pub(crate) fn new(req_hdr: Option<&CtrlHeader>, resp_type: u32, body: &[u8]) -> Self {
        let mut buf = [0u8; MAX_RESP_LEN];
        let mut put = |off: usize, bytes: &[u8]| {
            if let Some(dst) = buf.get_mut(off..off + bytes.len()) {
                dst.copy_from_slice(bytes);
            }
        };
        put(0, &resp_type.to_le_bytes());
        if let Some(h) = req_hdr.filter(|h| h.flags & FLAG_FENCE != 0) {
            let flags = h.flags & (FLAG_FENCE | FLAG_INFO_RING_IDX);
            put(4, &flags.to_le_bytes());
            put(8, &h.fence_id.to_le_bytes());
            put(16, &h.ctx_id.to_le_bytes());
            put(20, &[h.ring_idx]);
        }
        let len = if HDR_LEN + body.len() <= MAX_RESP_LEN {
            put(HDR_LEN, body);
            HDR_LEN + body.len()
        } else {
            HDR_LEN
        };
        Self { buf, len }
    }

    /// 送出するバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// 応答の type。
    pub fn resp_type(&self) -> u32 {
        le32(&self.buf, 0).unwrap_or(RESP_ERR_UNSPEC)
    }
}
