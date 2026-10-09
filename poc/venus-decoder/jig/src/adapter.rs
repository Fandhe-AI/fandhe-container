//! ctrl 要求を自前 venus デコーダの capset 応答へ橋渡しするアダプタ（GPU-6・TASK-172.4・#888）。
//!
//! `session`（F1.4・#1519。vhost-user の ctrl キューの応答ループ）から要求 1 件ごとに [`CtrlAdapter::handle_ctrl`] が
//! 呼ばれ、`GET_CAPSET_INFO` は `capset_info`、`GET_CAPSET` は `respond_capset_query` へ渡す。
//! #1520 で `GET_DISPLAY_INFO`（scanout なし）・`CTX_CREATE`（venus の context_init）・`CTX_DESTROY` を追加した。
//! CTX の重複・未知を判定するため、作成済み ctx_id の表（上限 [`MAX_CONTEXTS`]）を [`CtrlAdapter`] が所有する。
//! 未知の種別は `ERR_UNSPEC`、長さ・値の不正は `ERR_INVALID_PARAMETER` で拒否する（fail-closed）。
//! #1601 で blob リソース（`RESOURCE_CREATE_BLOB`・`CTX_ATTACH_RESOURCE` / `DETACH_RESOURCE`・`RESOURCE_UNREF`。資源表は
//! `resource`）と `SUBMIT_3D` の最小応答を追加した。`SUBMIT_3D` は受理して [`Handled::submit`] で本体を呼び出し側へ渡すだけで、
//! コマンドは実行しない。`CTX_DESTROY` はその ctx への attach を暗黙に外す。
//! 未実装（REPAIR-3）: `RESOURCE_MAP_BLOB` / `UNMAP_BLOB`（共有メモリが前提。F5.2b・承認待ち。`ERR_UNSPEC` のまま）、
//! 実メモリの確保、`SUBMIT_3D` の dispatch（TASK-177.x）。

use fandhe_container_plugin_macos::gpu::venus::{
    CommandHeader, VenusWireError, WireReader, capset_info, parse_command_header,
    respond_capset_query,
};

use crate::ctrl::{
    BLOB_FLAG_USE_MAPPABLE, BLOB_MEM_HOST3D, CMD_CTX_ATTACH_RESOURCE, CMD_CTX_CREATE,
    CMD_CTX_DESTROY, CMD_CTX_DETACH_RESOURCE, CMD_GET_CAPSET, CMD_GET_CAPSET_INFO,
    CMD_GET_DISPLAY_INFO, CMD_RESOURCE_CREATE_BLOB, CMD_RESOURCE_UNREF, CMD_SUBMIT_3D,
    CTX_DESTROY_REQ_LEN, CtrlHeader, CtrlResponse, CtxCreate, CtxCreateError,
    DISPLAY_INFO_BODY_LEN, DISPLAY_INFO_REQ_LEN, FLAG_FENCE, FLAG_INFO_RING_IDX, HDR_LEN, REQ_LEN,
    RESP_ERR_INVALID_CONTEXT_ID, RESP_ERR_INVALID_PARAMETER, RESP_ERR_INVALID_RESOURCE_ID,
    RESP_ERR_OUT_OF_MEMORY, RESP_ERR_UNSPEC, RESP_OK_CAPSET, RESP_OK_CAPSET_INFO,
    RESP_OK_DISPLAY_INFO, RESP_OK_NODATA, ResourceCreateBlob, Submit3dError, le32,
    parse_resource_id, parse_submit_3d,
};
use crate::log::{self, QueryResult};
use crate::resource::{ResourceError, ResourceTable};

/// `SUBMIT_3D` の ring_idx の上限（`NUM_RINGS` = 64。`INFO_RING_IDX` が立つときだけ検査する。設計書 10.4.3）。
pub const MAX_RINGS: u8 = 64;

/// 受理した `SUBMIT_3D` の受け渡し点。#1602（コマンドストリームの記録）が使う。
///
/// `session` は応答を書き戻せなかった要求（adapter を巻き戻した要求）の `submit` を捨てる契約で、
/// ゲストが ACK を見ていない提出を記録しない。コマンドの実行はしない（TASK-177.x の範囲）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submit3d {
    /// 提出元の ctx。
    pub ctx_id: u32,
    /// `INFO_RING_IDX` が立つときだけ入る ring_idx。
    pub ring_idx: Option<u8>,
    /// `FLAG_FENCE` が立つときだけ入る fence_id。
    pub fence_id: Option<u64>,
    /// 本体の先頭 8 バイトの venus コマンドヘッダの復号結果（本体が空なら `None`）。応答の種別には影響しない。
    pub header: Option<Result<CommandHeader, VenusWireError>>,
    /// 本体のバイト列（長さ検査の後にだけ確保・コピーする。上限は `ctrl::MAX_SUBMIT_3D_PAYLOAD_LEN`）。
    pub payload: Vec<u8>,
}

/// 1 要求の処理結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    /// ゲストへ返す応答。
    pub response: CtrlResponse,
    /// 構造化ログ 1 行（改行なし）。
    pub log_line: String,
    /// 受理した `SUBMIT_3D` の受け渡し点（それ以外の要求・拒否では `None`）。
    pub submit: Option<Submit3d>,
}

/// 同時に保持する ctx の上限（ゲスト由来の無制限 insert による DoS を防ぐ）。
pub const MAX_CONTEXTS: usize = 64;

/// ctx 操作の失敗理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtxError {
    /// ctx_id が 0、重複、または未作成。
    InvalidId,
    /// 表が `MAX_CONTEXTS` に達している。
    Full,
}

/// 作成済み ctx_id の固定長表（0 は未使用スロット。ctx_id 0 は常に拒否する）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextTable {
    slots: [u32; MAX_CONTEXTS],
}

impl ContextTable {
    fn insert(&mut self, ctx_id: u32) -> Result<(), CtxError> {
        if ctx_id == 0 || self.slots.contains(&ctx_id) {
            return Err(CtxError::InvalidId);
        }
        let free = self.slots.iter_mut().find(|s| **s == 0);
        match free {
            Some(slot) => {
                *slot = ctx_id;
                Ok(())
            }
            None => Err(CtxError::Full),
        }
    }

    /// 作成済み ctx のスロット番号（ctx_id 0 は常に `None`）。
    fn index_of(&self, ctx_id: u32) -> Option<usize> {
        if ctx_id == 0 {
            return None;
        }
        self.slots.iter().position(|s| *s == ctx_id)
    }

    /// ctx を消し、解放したスロット番号を返す。
    fn remove(&mut self, ctx_id: u32) -> Result<usize, CtxError> {
        let idx = self.index_of(ctx_id).ok_or(CtxError::InvalidId)?;
        let slot = self.slots.get_mut(idx).ok_or(CtxError::InvalidId)?;
        *slot = 0;
        Ok(idx)
    }
}

/// ctx 表を持つ ctrl アダプタ。トランスポート層（F1）が接続ごとに 1 つ作る想定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrlAdapter {
    contexts: ContextTable,
    resources: ResourceTable,
}

impl Default for CtrlAdapter {
    fn default() -> Self {
        Self {
            contexts: ContextTable {
                slots: [0; MAX_CONTEXTS],
            },
            resources: ResourceTable::default(),
        }
    }
}

impl CtrlAdapter {
    /// ctrl 要求 1 件（ヘッダ + 本体）を処理する。
    pub fn handle_ctrl(&mut self, req: &[u8]) -> Handled {
        let Some(hdr) = CtrlHeader::parse(req) else {
            return Handled {
                response: CtrlResponse::new(None, RESP_ERR_INVALID_PARAMETER, &[]),
                log_line: log::rejected_line(None, QueryResult::InvalidParameter),
                submit: None,
            };
        };
        match hdr.cmd_type {
            CMD_GET_CAPSET_INFO => get_capset_info(&hdr, req),
            CMD_GET_CAPSET => get_capset(&hdr, req),
            CMD_GET_DISPLAY_INFO => get_display_info(&hdr, req),
            CMD_CTX_CREATE => self.ctx_create(&hdr, req),
            CMD_CTX_DESTROY => self.ctx_destroy(&hdr, req),
            CMD_RESOURCE_CREATE_BLOB => self.resource_create_blob(&hdr, req),
            CMD_CTX_ATTACH_RESOURCE | CMD_CTX_DETACH_RESOURCE => self.ctx_resource(&hdr, req),
            CMD_RESOURCE_UNREF => self.resource_unref(&hdr, req),
            CMD_SUBMIT_3D => self.submit_3d(&hdr, req),
            other => Handled {
                response: CtrlResponse::new(Some(&hdr), RESP_ERR_UNSPEC, &[]),
                log_line: log::rejected_line(Some(other), QueryResult::Unspec),
                submit: None,
            },
        }
    }

    fn ctx_create(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let (nlen, capset_id, result) = match CtxCreate::parse(req) {
            Ok(c) => {
                let r = match self.contexts.insert(hdr.ctx_id) {
                    Ok(()) => QueryResult::Ok,
                    Err(CtxError::InvalidId) => QueryResult::InvalidContextId,
                    Err(CtxError::Full) => QueryResult::OutOfMemory,
                };
                (Some(c.nlen), Some(c.capset_id), r)
            }
            Err(CtxCreateError::BadLength) => (None, None, QueryResult::InvalidParameter),
            Err(CtxCreateError::NameTooLong(n)) => (Some(n), None, QueryResult::InvalidParameter),
            Err(CtxCreateError::BadContextInit { nlen, capset_id }) => {
                (Some(nlen), Some(capset_id), QueryResult::InvalidParameter)
            }
        };
        Handled {
            response: ctx_response(hdr, result),
            log_line: log::ctx_create_line(hdr.ctx_id, capset_id, nlen, result),
            submit: None,
        }
    }

    fn ctx_destroy(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let result = if req.len() != CTX_DESTROY_REQ_LEN {
            QueryResult::InvalidParameter
        } else {
            match self.contexts.remove(hdr.ctx_id) {
                Ok(slot) => {
                    // 順序が崩れて attach したまま破棄されても、後続の UNREF が拒否され続けず、
                    // スロット再利用時に古い所属が新しい ctx へ化けないようにする（設計書 10.4.3）。
                    self.resources.detach_all_from(slot);
                    QueryResult::Ok
                }
                Err(_) => QueryResult::InvalidContextId,
            }
        };
        Handled {
            response: ctx_response(hdr, result),
            log_line: log::ctx_destroy_line(hdr.ctx_id, result),
            submit: None,
        }
    }

    fn resource_create_blob(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let parsed = ResourceCreateBlob::parse(req);
        let result = match &parsed {
            None => QueryResult::InvalidParameter,
            Some(c) => {
                if self.contexts.index_of(hdr.ctx_id).is_none() {
                    QueryResult::InvalidContextId
                } else if c.blob_mem != BLOB_MEM_HOST3D
                    || c.blob_flags != BLOB_FLAG_USE_MAPPABLE
                    || c.blob_id != 0
                    || c.nr_entries != 0
                {
                    QueryResult::InvalidParameter
                } else {
                    resource_result(self.resources.create(c.res_id, c.size))
                }
            }
        };
        Handled {
            response: ctx_response(hdr, result),
            log_line: log::resource_create_blob_line(hdr.ctx_id, parsed.as_ref(), result),
            submit: None,
        }
    }

    /// `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE`（`hdr.cmd_type` で分ける）。
    fn ctx_resource(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let attach = hdr.cmd_type == CMD_CTX_ATTACH_RESOURCE;
        let res_id = parse_resource_id(req);
        let result = match (res_id, self.contexts.index_of(hdr.ctx_id)) {
            (None, _) => QueryResult::InvalidParameter,
            (Some(_), None) => QueryResult::InvalidContextId,
            (Some(id), Some(slot)) => resource_result(if attach {
                self.resources.attach(id, slot)
            } else {
                self.resources.detach(id, slot)
            }),
        };
        let cmd = if attach {
            "CTX_ATTACH_RESOURCE"
        } else {
            "CTX_DETACH_RESOURCE"
        };
        Handled {
            response: ctx_response(hdr, result),
            log_line: log::ctx_resource_line(cmd, hdr.ctx_id, res_id, result),
            submit: None,
        }
    }

    fn resource_unref(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let res_id = parse_resource_id(req);
        let result = match res_id {
            None => QueryResult::InvalidParameter,
            Some(id) => resource_result(self.resources.unref(id)),
        };
        Handled {
            response: ctx_response(hdr, result),
            log_line: log::resource_unref_line(res_id, result),
            submit: None,
        }
    }

    fn submit_3d(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let reject = |result: QueryResult, size: Option<u32>| Handled {
            response: ctx_response(hdr, result),
            log_line: log::submit_3d_line(&log::Submit3dLog {
                ctx_id: hdr.ctx_id,
                ring_idx: None,
                size,
                venus_cmd: None,
                wire: "none",
                result,
            }),
            submit: None,
        };
        let body = match parse_submit_3d(req) {
            Ok(b) => b,
            Err(Submit3dError::BadLength) => return reject(QueryResult::InvalidParameter, None),
            Err(Submit3dError::SizeMismatch(n)) => {
                return reject(QueryResult::InvalidParameter, Some(n));
            }
        };
        let size = u32::try_from(body.len()).ok();
        if self.contexts.index_of(hdr.ctx_id).is_none() {
            return reject(QueryResult::InvalidContextId, size);
        }
        let ring_idx = (hdr.flags & FLAG_INFO_RING_IDX != 0).then_some(hdr.ring_idx);
        if ring_idx.is_some_and(|r| r >= MAX_RINGS) {
            return reject(QueryResult::InvalidParameter, size);
        }
        // 先頭 8 バイトだけ読む。結果は応答の種別を変えず、ログと受け渡し点で解析側へ渡す（実行はしない）。
        let header = (!body.is_empty()).then(|| parse_command_header(&mut WireReader::new(body)));
        let (venus_cmd, wire) = match &header {
            None => (None, "empty"),
            Some(Ok(h)) => (Some(h.command.as_raw()), "ok"),
            Some(Err(e)) => (None, e.code()),
        };
        Handled {
            response: ctx_response(hdr, QueryResult::Ok),
            log_line: log::submit_3d_line(&log::Submit3dLog {
                ctx_id: hdr.ctx_id,
                ring_idx,
                size,
                venus_cmd,
                wire,
                result: QueryResult::Ok,
            }),
            submit: Some(Submit3d {
                ctx_id: hdr.ctx_id,
                ring_idx,
                fence_id: (hdr.flags & FLAG_FENCE != 0).then_some(hdr.fence_id),
                header,
                payload: body.to_vec(),
            }),
        }
    }
}

fn resource_result(r: Result<(), ResourceError>) -> QueryResult {
    match r {
        Ok(()) => QueryResult::Ok,
        Err(ResourceError::InvalidId) => QueryResult::InvalidResourceId,
        Err(ResourceError::InvalidParameter) => QueryResult::InvalidParameter,
        Err(ResourceError::Full) => QueryResult::OutOfMemory,
    }
}

fn ctx_response(hdr: &CtrlHeader, result: QueryResult) -> CtrlResponse {
    let resp_type = match result {
        QueryResult::Ok => RESP_OK_NODATA,
        QueryResult::InvalidContextId => RESP_ERR_INVALID_CONTEXT_ID,
        QueryResult::InvalidResourceId => RESP_ERR_INVALID_RESOURCE_ID,
        QueryResult::OutOfMemory => RESP_ERR_OUT_OF_MEMORY,
        QueryResult::InvalidParameter => RESP_ERR_INVALID_PARAMETER,
        QueryResult::Unspec => RESP_ERR_UNSPEC,
    };
    CtrlResponse::new(Some(hdr), resp_type, &[])
}

/// `num_scanouts=0` 構成: 全 scanout を無効（enabled=0・rect 全 0）にして返す。
fn get_display_info(hdr: &CtrlHeader, req: &[u8]) -> Handled {
    if req.len() != DISPLAY_INFO_REQ_LEN {
        return invalid(hdr, log::display_info_line(QueryResult::InvalidParameter));
    }
    Handled {
        response: CtrlResponse::new(
            Some(hdr),
            RESP_OK_DISPLAY_INFO,
            &[0u8; DISPLAY_INFO_BODY_LEN],
        ),
        log_line: log::display_info_line(QueryResult::Ok),
        submit: None,
    }
}

fn invalid(hdr: &CtrlHeader, log_line: String) -> Handled {
    Handled {
        response: CtrlResponse::new(Some(hdr), RESP_ERR_INVALID_PARAMETER, &[]),
        log_line,
        submit: None,
    }
}

fn get_capset_info(hdr: &CtrlHeader, req: &[u8]) -> Handled {
    let Some(index) = body_args(req).map(|(a, _)| a) else {
        return invalid(hdr, log::info_line(None, QueryResult::InvalidParameter, 0));
    };
    let Ok(info) = capset_info(index) else {
        return invalid(
            hdr,
            log::info_line(Some(index), QueryResult::InvalidParameter, 0),
        );
    };
    // OK_CAPSET_INFO の本体: capset_id・capset_max_version・capset_max_size・padding。
    let mut body = [0u8; 16];
    let (words, _) = body.as_chunks_mut::<4>();
    for (dst, v) in words
        .iter_mut()
        .zip([info.id, info.max_version, info.max_size])
    {
        *dst = v.to_le_bytes();
    }
    Handled {
        response: CtrlResponse::new(Some(hdr), RESP_OK_CAPSET_INFO, &body),
        log_line: log::info_line(Some(index), QueryResult::Ok, info.max_size),
        submit: None,
    }
}

fn get_capset(hdr: &CtrlHeader, req: &[u8]) -> Handled {
    let Some((id, version)) = body_args(req) else {
        return invalid(
            hdr,
            log::query_line(None, 0, QueryResult::InvalidParameter, 0),
        );
    };
    match respond_capset_query(id, version) {
        Ok(resp) => Handled {
            response: CtrlResponse::new(Some(hdr), RESP_OK_CAPSET, &resp.data),
            log_line: log::query_line(Some(id), version, QueryResult::Ok, resp.info.max_size),
            submit: None,
        },
        Err(_) => invalid(
            hdr,
            log::query_line(Some(id), version, QueryResult::InvalidParameter, 0),
        ),
    }
}

/// 本体の 2 語（`capset_index, padding` または `capset_id, capset_version`）を読む。
/// 要求長がちょうど `REQ_LEN` でなければ `None`（PoC では余剰バイトも拒否する）。
fn body_args(req: &[u8]) -> Option<(u32, u32)> {
    if req.len() != REQ_LEN {
        return None;
    }
    Some((le32(req, HDR_LEN)?, le32(req, HDR_LEN + 4)?))
}
