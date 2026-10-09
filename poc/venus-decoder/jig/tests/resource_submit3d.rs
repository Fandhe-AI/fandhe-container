//! blob リソース・ctx への割り当て・SUBMIT_3D の公開 API 結合試験（GPU-6・TASK-172.4・#1601。3 OS・既定集合）。
//!
//! `CtrlAdapter::handle_ctrl` へ ctx 作成 → blob 作成 → attach → SUBMIT_3D → detach → unref の順に要求を流し、
//! 応答種別・ログ行・SUBMIT_3D の受け渡し点を具体値で照合する。session 経由の巻き戻しは `vhost_user_session.rs`
//! （Linux 限定）で照合する。実ゲストの Mesa venus からの到達は未検証（後続 F5.2b / #725）。

use fandhe_container_poc_venus_jig::adapter::CtrlAdapter;
use fandhe_container_poc_venus_jig::ctrl::{
    CMD_CTX_ATTACH_RESOURCE, CMD_CTX_CREATE, CMD_CTX_DETACH_RESOURCE, CMD_RESOURCE_CREATE_BLOB,
    CMD_RESOURCE_UNREF, CMD_SUBMIT_3D, FLAG_INFO_RING_IDX, RESP_ERR_INVALID_PARAMETER,
    RESP_ERR_INVALID_RESOURCE_ID, RESP_OK_NODATA,
};

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn hdr(cmd: u32, flags: u32, ctx: u32, total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    put32(&mut v, 0, cmd);
    put32(&mut v, 4, flags);
    put32(&mut v, 16, ctx);
    v
}

fn create_ctx(ctx: u32) -> Vec<u8> {
    let mut v = hdr(CMD_CTX_CREATE, 0, ctx, 96);
    put32(&mut v, 24, 3);
    put32(&mut v, 28, 4);
    v
}

fn blob(ctx: u32, res: u32, size: u64) -> Vec<u8> {
    let mut v = hdr(CMD_RESOURCE_CREATE_BLOB, 0, ctx, 56);
    put32(&mut v, 24, res);
    put32(&mut v, 28, 2); // HOST3D
    put32(&mut v, 32, 1); // USE_MAPPABLE
    v[48..56].copy_from_slice(&size.to_le_bytes());
    v
}

fn res_req(cmd: u32, ctx: u32, res: u32) -> Vec<u8> {
    let mut v = hdr(cmd, 0, ctx, 32);
    put32(&mut v, 24, res);
    v
}

fn submit(ctx: u32, ring: u8, body: &[u8]) -> Vec<u8> {
    let mut v = hdr(CMD_SUBMIT_3D, FLAG_INFO_RING_IDX, ctx, 32);
    v[20] = ring;
    put32(&mut v, 24, body.len() as u32);
    v.extend_from_slice(body);
    v
}

fn ty(a: &mut CtrlAdapter, req: &[u8]) -> u32 {
    a.handle_ctrl(req).response.resp_type()
}

/// GPU-6・TASK-172.4: 資源の一生と SUBMIT_3D の最小応答（具体値）。
#[test]
fn task1601_gpu6_blob_attach_submit3d_lifecycle() {
    let mut a = CtrlAdapter::default();
    assert_eq!(ty(&mut a, &create_ctx(1)), RESP_OK_NODATA);
    assert_eq!(ty(&mut a, &blob(1, 7, 8192)), RESP_OK_NODATA);
    // 同じ ID の再作成は拒否される。
    assert_eq!(ty(&mut a, &blob(1, 7, 8192)), RESP_ERR_INVALID_RESOURCE_ID);
    // 4096 の倍数でない大きさは拒否される。
    assert_eq!(ty(&mut a, &blob(1, 8, 100)), RESP_ERR_INVALID_PARAMETER);
    assert_eq!(
        ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 7)),
        RESP_OK_NODATA
    );
    // attach 中の unref は拒否される。
    assert_eq!(
        ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 7)),
        RESP_ERR_INVALID_PARAMETER
    );

    // SUBMIT_3D は受理されて本体が受け渡し点へ渡る（コマンドは実行しない）。
    let mut body = vec![0u8; 256];
    body[..4].copy_from_slice(&188u32.to_le_bytes());
    let h = a.handle_ctrl(&submit(1, 0, &body));
    assert_eq!(h.response.resp_type(), RESP_OK_NODATA);
    assert_eq!(h.response.as_bytes().len(), 24);
    let s = h.submit.expect("submit");
    assert_eq!((s.ctx_id, s.ring_idx, s.payload.len()), (1, Some(0), 256));
    assert_eq!(
        h.log_line,
        "venus_jig event=submit_3d cmd=SUBMIT_3D ctx_id=1 ring_idx=0 size=256 venus_cmd=188 wire=ok result=ok"
    );

    assert_eq!(
        ty(&mut a, &res_req(CMD_CTX_DETACH_RESOURCE, 1, 7)),
        RESP_OK_NODATA
    );
    assert_eq!(
        ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 7)),
        RESP_OK_NODATA
    );
    // 消した後の unref は未作成扱い。
    assert_eq!(
        ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 7)),
        RESP_ERR_INVALID_RESOURCE_ID
    );
    // 未作成 ctx への SUBMIT_3D は受け渡し点に出ない。
    let h = a.handle_ctrl(&submit(9, 0, &body));
    assert!(h.submit.is_none());
}
