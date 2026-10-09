//! ctrl 要求を自前 venus デコーダの capset 応答へ橋渡しするアダプタ（GPU-6・TASK-172.4・#888）。
//!
//! `session`（F1.4・#1519。vhost-user の ctrl キューの応答ループ）から要求 1 件ごとに [`CtrlAdapter::handle_ctrl`] が
//! 呼ばれ、`GET_CAPSET_INFO` は `capset_info`、`GET_CAPSET` は `respond_capset_query` へ渡す。
//! #1520 で `GET_DISPLAY_INFO`（scanout なし）・`CTX_CREATE`（venus の context_init）・`CTX_DESTROY` を追加した。
//! CTX の重複・未知を判定するため、作成済み ctx_id の表（上限 [`MAX_CONTEXTS`]）を [`CtrlAdapter`] が所有する。
//! 未知の種別は `ERR_UNSPEC`、長さ・値の不正は `ERR_INVALID_PARAMETER` で拒否する（fail-closed）。
//! 未実装（REPAIR-3）: 上記以外の ctrl 応答（RESOURCE_CREATE_BLOB・SUBMIT_3D 等。後続 F2 の残り）。

use fandhe_container_plugin_macos::gpu::venus::{capset_info, respond_capset_query};

use crate::ctrl::{
    CMD_CTX_CREATE, CMD_CTX_DESTROY, CMD_GET_CAPSET, CMD_GET_CAPSET_INFO, CMD_GET_DISPLAY_INFO,
    CTX_DESTROY_REQ_LEN, CtrlHeader, CtrlResponse, CtxCreate, CtxCreateError,
    DISPLAY_INFO_BODY_LEN, DISPLAY_INFO_REQ_LEN, HDR_LEN, REQ_LEN, RESP_ERR_INVALID_CONTEXT_ID,
    RESP_ERR_INVALID_PARAMETER, RESP_ERR_OUT_OF_MEMORY, RESP_ERR_UNSPEC, RESP_OK_CAPSET,
    RESP_OK_CAPSET_INFO, RESP_OK_DISPLAY_INFO, RESP_OK_NODATA, le32,
};
use crate::log::{self, QueryResult};

/// 1 要求の処理結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    /// ゲストへ返す応答。
    pub response: CtrlResponse,
    /// 構造化ログ 1 行（改行なし）。
    pub log_line: String,
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

    fn remove(&mut self, ctx_id: u32) -> Result<(), CtxError> {
        if ctx_id == 0 {
            return Err(CtxError::InvalidId);
        }
        match self.slots.iter_mut().find(|s| **s == ctx_id) {
            Some(slot) => {
                *slot = 0;
                Ok(())
            }
            None => Err(CtxError::InvalidId),
        }
    }
}

/// ctx 表を持つ ctrl アダプタ。トランスポート層（F1）が接続ごとに 1 つ作る想定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrlAdapter {
    contexts: ContextTable,
}

impl Default for CtrlAdapter {
    fn default() -> Self {
        Self {
            contexts: ContextTable {
                slots: [0; MAX_CONTEXTS],
            },
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
            };
        };
        match hdr.cmd_type {
            CMD_GET_CAPSET_INFO => get_capset_info(&hdr, req),
            CMD_GET_CAPSET => get_capset(&hdr, req),
            CMD_GET_DISPLAY_INFO => get_display_info(&hdr, req),
            CMD_CTX_CREATE => self.ctx_create(&hdr, req),
            CMD_CTX_DESTROY => self.ctx_destroy(&hdr, req),
            other => Handled {
                response: CtrlResponse::new(Some(&hdr), RESP_ERR_UNSPEC, &[]),
                log_line: log::rejected_line(Some(other), QueryResult::Unspec),
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
        }
    }

    fn ctx_destroy(&mut self, hdr: &CtrlHeader, req: &[u8]) -> Handled {
        let result = if req.len() != CTX_DESTROY_REQ_LEN {
            QueryResult::InvalidParameter
        } else {
            match self.contexts.remove(hdr.ctx_id) {
                Ok(()) => QueryResult::Ok,
                Err(_) => QueryResult::InvalidContextId,
            }
        };
        Handled {
            response: ctx_response(hdr, result),
            log_line: log::ctx_destroy_line(hdr.ctx_id, result),
        }
    }
}

fn ctx_response(hdr: &CtrlHeader, result: QueryResult) -> CtrlResponse {
    let resp_type = match result {
        QueryResult::Ok => RESP_OK_NODATA,
        QueryResult::InvalidContextId => RESP_ERR_INVALID_CONTEXT_ID,
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
    }
}

fn invalid(hdr: &CtrlHeader, log_line: String) -> Handled {
    Handled {
        response: CtrlResponse::new(Some(hdr), RESP_ERR_INVALID_PARAMETER, &[]),
        log_line,
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
