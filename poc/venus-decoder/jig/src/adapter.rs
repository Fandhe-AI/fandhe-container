//! ctrl 要求を自前 venus デコーダの capset 応答へ橋渡しするアダプタ（GPU-6・TASK-172.4・#888）。
//!
//! 将来のトランスポート層（後続 F1。vhost-user の ctrl キュー）から要求 1 件ごとに [`handle_ctrl`] が呼ばれ、
//! `GET_CAPSET_INFO` は `capset_info`、`GET_CAPSET` は `respond_capset_query` へ渡す。
//! 未知の種別は `ERR_UNSPEC`、長さ・値の不正は `ERR_INVALID_PARAMETER` で拒否する（fail-closed）。
//! 未実装（REPAIR-3）: capset 以外の ctrl 応答（後続 F2）。

use fandhe_container_plugin_macos::gpu::venus::{capset_info, respond_capset_query};

use crate::ctrl::{
    CMD_GET_CAPSET, CMD_GET_CAPSET_INFO, CtrlHeader, CtrlResponse, HDR_LEN, REQ_LEN,
    RESP_ERR_INVALID_PARAMETER, RESP_ERR_UNSPEC, RESP_OK_CAPSET, RESP_OK_CAPSET_INFO, le32,
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

/// ctrl 要求 1 件（ヘッダ + 本体）を処理する。
pub fn handle_ctrl(req: &[u8]) -> Handled {
    let Some(hdr) = CtrlHeader::parse(req) else {
        return Handled {
            response: CtrlResponse::new(None, RESP_ERR_INVALID_PARAMETER, &[]),
            log_line: log::rejected_line(None, QueryResult::InvalidParameter),
        };
    };
    match hdr.cmd_type {
        CMD_GET_CAPSET_INFO => get_capset_info(&hdr, req),
        CMD_GET_CAPSET => get_capset(&hdr, req),
        other => Handled {
            response: CtrlResponse::new(Some(&hdr), RESP_ERR_UNSPEC, &[]),
            log_line: log::rejected_line(Some(other), QueryResult::Unspec),
        },
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
