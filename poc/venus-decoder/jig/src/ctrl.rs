//! virtio-gpu ctrl メッセージの復号と応答符号化（capset クエリ分のみ。GPU-6・TASK-172.4）。
//!
//! 入力はゲスト由来の untrusted バイト列で、全読み取りを `get` / `try_into` で境界検査する。応答は固定長の
//! [`CtrlResponse`] で組み立て、生の `Vec` を手で組まない（REPAIR-2）。
//!
//! 出典: Linux `include/uapi/linux/virtio_gpu.h`（タグ `v6.12`、確認日 2026-10-08。取得時 SHA-256
//! `7c9e2f7d47fa0b1a2c737fc5a741f57c5cf25303dd5c68c2c9738e9bb761eee6`）。値（事実情報）のみ転記しコードは流用していない。

use fandhe_container_plugin_macos::gpu::venus::VENUS_CAPSET_LEN;

/// `VIRTIO_GPU_CMD_GET_CAPSET_INFO`。
pub const CMD_GET_CAPSET_INFO: u32 = 0x0108;
/// `VIRTIO_GPU_CMD_GET_CAPSET`。
pub const CMD_GET_CAPSET: u32 = 0x0109;
/// `VIRTIO_GPU_RESP_OK_CAPSET_INFO`。
pub const RESP_OK_CAPSET_INFO: u32 = 0x1102;
/// `VIRTIO_GPU_RESP_OK_CAPSET`。
pub const RESP_OK_CAPSET: u32 = 0x1103;
/// `VIRTIO_GPU_RESP_ERR_UNSPEC`。
pub const RESP_ERR_UNSPEC: u32 = 0x1200;
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
/// 応答の最大長（ヘッダ + capset データ）。
pub const MAX_RESP_LEN: usize = HDR_LEN + VENUS_CAPSET_LEN;

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
