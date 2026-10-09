//! virtio-gpu ctrl メッセージの復号と応答符号化（capset クエリ・GET_DISPLAY_INFO・CTX_CREATE / DESTROY・
//! blob リソース操作・SUBMIT_3D 分。GPU-6・TASK-172.4・#1520・#1601）。
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
/// `VIRTIO_GPU_CMD_RESOURCE_UNREF`。
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
/// `VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB`。
pub const CMD_RESOURCE_CREATE_BLOB: u32 = 0x010c;
/// `VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE`。
pub const CMD_CTX_ATTACH_RESOURCE: u32 = 0x0202;
/// `VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE`。
pub const CMD_CTX_DETACH_RESOURCE: u32 = 0x0203;
/// `VIRTIO_GPU_CMD_SUBMIT_3D`。
pub const CMD_SUBMIT_3D: u32 = 0x0207;
/// `VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB`（共有メモリが前提のため治具は未実装で `ERR_UNSPEC`。F5.2b）。
pub const CMD_RESOURCE_MAP_BLOB: u32 = 0x0208;
/// `VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB`（同上）。
pub const CMD_RESOURCE_UNMAP_BLOB: u32 = 0x0209;
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
/// `VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID`。
pub const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
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
/// ゲストのカーネルが `SUBMIT_3D` の本体を分割しない前提で受け付ける、ctrl 要求全体の最大長
/// （`session` の固定長スタックバッファと同値。設計書 10.4.6。ヒープ受信経路は作らない）。
pub const MAX_REQ_LEN: usize = 4096;
/// `SUBMIT_3D` の固定部の長さ（ヘッダ + size 4 + padding 4）。
pub const SUBMIT_3D_FIXED_LEN: usize = HDR_LEN + 8;
/// `SUBMIT_3D` の本体の最大長。
pub const MAX_SUBMIT_3D_PAYLOAD_LEN: usize = MAX_REQ_LEN - SUBMIT_3D_FIXED_LEN;
/// `RESOURCE_CREATE_BLOB` 要求の長さ（ヘッダ + resource_id 4 + blob_mem 4 + blob_flags 4 + nr_entries 4 + blob_id 8 + size 8）。
pub const RESOURCE_CREATE_BLOB_REQ_LEN: usize = HDR_LEN + 32;
/// `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE` / `RESOURCE_UNREF` 要求の長さ（ヘッダ + resource_id 4 + padding 4）。
pub const RESOURCE_ID_REQ_LEN: usize = HDR_LEN + 8;
/// `VIRTIO_GPU_BLOB_MEM_HOST3D`。治具が受理する blob_mem はこれだけ。
pub const BLOB_MEM_HOST3D: u32 = 0x0002;
/// `VIRTIO_GPU_BLOB_FLAG_USE_MAPPABLE`。治具が受理する blob_flags はこれだけ。
pub const BLOB_FLAG_USE_MAPPABLE: u32 = 0x0001;
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

/// `buf` の `off` へ `bytes` を書く。加算が溢れる・範囲外のときは何も書かず `false`（D1・#1528 の指摘）。
fn write_at(buf: &mut [u8], off: usize, bytes: &[u8]) -> bool {
    let Some(end) = off.checked_add(bytes.len()) else {
        return false;
    };
    match buf.get_mut(off..end) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

/// 本体長 `body_len` の応答の全長。ヘッダ込みで `MAX_RESP_LEN` を超える・加算が溢れるなら `None`。
fn body_end(body_len: usize) -> Option<usize> {
    HDR_LEN.checked_add(body_len).filter(|e| *e <= MAX_RESP_LEN)
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
        write_at(&mut buf, 0, &resp_type.to_le_bytes());
        if let Some(h) = req_hdr.filter(|h| h.flags & FLAG_FENCE != 0) {
            let flags = h.flags & (FLAG_FENCE | FLAG_INFO_RING_IDX);
            write_at(&mut buf, 4, &flags.to_le_bytes());
            write_at(&mut buf, 8, &h.fence_id.to_le_bytes());
            write_at(&mut buf, 16, &h.ctx_id.to_le_bytes());
            write_at(&mut buf, 20, &[h.ring_idx]);
        }
        let len = match body_end(body.len()) {
            Some(end) if write_at(&mut buf, HDR_LEN, body) => end,
            _ => HDR_LEN,
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

/// 復号済みの `RESOURCE_CREATE_BLOB` 本体（値の妥当性は資源表側と `adapter` が判定する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceCreateBlob {
    /// 作成する resource_id。
    pub res_id: u32,
    /// `blob_mem`。
    pub blob_mem: u32,
    /// `blob_flags`。
    pub blob_flags: u32,
    /// `nr_entries`（治具は 0 だけ受理）。
    pub nr_entries: u32,
    /// `blob_id`（治具は 0 だけ受理。ログには出さない）。
    pub blob_id: u64,
    /// 要求された大きさ（バイト）。
    pub size: u64,
}

impl ResourceCreateBlob {
    /// 要求全体（ヘッダ込み）を復号する。長さがちょうど `RESOURCE_CREATE_BLOB_REQ_LEN` でなければ `None`。
    pub fn parse(req: &[u8]) -> Option<Self> {
        if req.len() != RESOURCE_CREATE_BLOB_REQ_LEN {
            return None;
        }
        Some(Self {
            res_id: le32(req, HDR_LEN)?,
            blob_mem: le32(req, HDR_LEN + 4)?,
            blob_flags: le32(req, HDR_LEN + 8)?,
            nr_entries: le32(req, HDR_LEN + 12)?,
            blob_id: le64(req, HDR_LEN + 16)?,
            size: le64(req, HDR_LEN + 24)?,
        })
    }
}

/// `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE` / `RESOURCE_UNREF` の resource_id を取り出す。
/// 長さがちょうど `RESOURCE_ID_REQ_LEN` でなければ `None`。
pub fn parse_resource_id(req: &[u8]) -> Option<u32> {
    if req.len() != RESOURCE_ID_REQ_LEN {
        return None;
    }
    le32(req, HDR_LEN)
}

/// `SUBMIT_3D` の復号失敗理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submit3dError {
    /// 固定部（32 バイト）に満たない、または要求全体が `MAX_REQ_LEN` 超え。
    BadLength,
    /// `size` フィールドが実際の本体長と一致しない（復号できた `size` を保持する）。
    SizeMismatch(u32),
}

/// `SUBMIT_3D` 要求を検査して本体を返す（`size` フィールドが実長と一致し、要求全体が上限内のときだけ）。
pub fn parse_submit_3d(req: &[u8]) -> Result<&[u8], Submit3dError> {
    if req.len() < SUBMIT_3D_FIXED_LEN || req.len() > MAX_REQ_LEN {
        return Err(Submit3dError::BadLength);
    }
    let size = le32(req, HDR_LEN).ok_or(Submit3dError::BadLength)?;
    let body = req
        .get(SUBMIT_3D_FIXED_LEN..)
        .ok_or(Submit3dError::BadLength)?;
    if usize::try_from(size) != Ok(body.len()) {
        return Err(Submit3dError::SizeMismatch(size));
    }
    Ok(body)
}

/// `buf` の `off` から little-endian `u64` を読む。範囲外なら `None`。
pub(crate) fn le64(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    Some(u64::from_le_bytes(buf.get(off..end)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task1601_gpu6_response_body_boundary() {
        let max_body = MAX_RESP_LEN - HDR_LEN;
        let body = vec![0xab; max_body];
        let r = CtrlResponse::new(None, RESP_OK_CAPSET, &body);
        assert_eq!(r.as_bytes().len(), MAX_RESP_LEN);
        assert_eq!(r.as_bytes().get(HDR_LEN..), Some(&body[..]));
        let r = CtrlResponse::new(None, RESP_OK_CAPSET, &vec![0xab; max_body + 1]);
        assert_eq!(r.as_bytes().len(), HDR_LEN);
    }

    #[test]
    fn task1601_gpu6_overflow_helpers_do_not_panic() {
        assert_eq!(body_end(usize::MAX), None);
        assert_eq!(body_end(usize::MAX - HDR_LEN + 1), None);
        assert_eq!(body_end(0), Some(HDR_LEN));
        let mut buf = [0u8; 4];
        assert!(!write_at(&mut buf, usize::MAX, &[1]));
        assert!(!write_at(&mut buf, 4, &[1]));
        assert_eq!(buf, [0; 4]);
        assert!(write_at(&mut buf, 3, &[7]));
        assert_eq!(buf, [0, 0, 0, 7]);
    }
}
