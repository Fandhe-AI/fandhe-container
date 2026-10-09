//! 資源表と `CtrlAdapter` の blob / SUBMIT_3D 応答のテスト（GPU-6・TASK-172.4・#1601）。
//! 合成バイト列のヘルパーはこのファイル内に置き、既存の `src/tests.rs` には依存しない。

use fandhe_container_plugin_macos::gpu::venus::{CommandType, VenusWireError};

use super::*;
use crate::adapter::{CtrlAdapter, Handled};
use crate::ctrl::{
    CMD_CTX_ATTACH_RESOURCE, CMD_CTX_CREATE, CMD_CTX_DESTROY, CMD_CTX_DETACH_RESOURCE,
    CMD_RESOURCE_CREATE_BLOB, CMD_RESOURCE_MAP_BLOB, CMD_RESOURCE_UNMAP_BLOB, CMD_RESOURCE_UNREF,
    CMD_SUBMIT_3D, FLAG_FENCE, FLAG_INFO_RING_IDX, HDR_LEN, MAX_REQ_LEN,
    RESP_ERR_INVALID_CONTEXT_ID, RESP_ERR_INVALID_PARAMETER, RESP_ERR_INVALID_RESOURCE_ID,
    RESP_ERR_OUT_OF_MEMORY, RESP_ERR_UNSPEC, RESP_OK_NODATA,
};
use crate::log::{MAX_LINE_BYTES, find_capset_queries};

const OK: u32 = RESP_OK_NODATA;
const BAD: u32 = RESP_ERR_INVALID_PARAMETER;
const NO_CTX: u32 = RESP_ERR_INVALID_CONTEXT_ID;
const NO_RES: u32 = RESP_ERR_INVALID_RESOURCE_ID;
const OOM: u32 = RESP_ERR_OUT_OF_MEMORY;
const HOST3D: u32 = 2;
const MAPPABLE: u32 = 1;
const MIB: u64 = 1024 * 1024;

fn hdr(cmd: u32, flags: u32, ctx_id: u32, total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total.max(HDR_LEN)];
    v[..4].copy_from_slice(&cmd.to_le_bytes());
    v[4..8].copy_from_slice(&flags.to_le_bytes());
    v[8..16].copy_from_slice(&0x77u64.to_le_bytes());
    v[16..20].copy_from_slice(&ctx_id.to_le_bytes());
    v[20] = 5;
    v.truncate(total);
    v
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

struct Blob {
    ctx: u32,
    res: u32,
    mem: u32,
    flags: u32,
    nr: u32,
    blob_id: u64,
    size: u64,
    total: usize,
    hdr_flags: u32,
}

fn blob(ctx: u32, res: u32, size: u64) -> Blob {
    Blob {
        ctx,
        res,
        mem: HOST3D,
        flags: MAPPABLE,
        nr: 0,
        blob_id: 0,
        size,
        total: 56,
        hdr_flags: 0,
    }
}

fn blob_req(b: &Blob) -> Vec<u8> {
    let mut v = hdr(
        CMD_RESOURCE_CREATE_BLOB,
        b.hdr_flags,
        b.ctx,
        b.total.max(56),
    );
    put32(&mut v, 24, b.res);
    put32(&mut v, 28, b.mem);
    put32(&mut v, 32, b.flags);
    put32(&mut v, 36, b.nr);
    v[40..48].copy_from_slice(&b.blob_id.to_le_bytes());
    v[48..56].copy_from_slice(&b.size.to_le_bytes());
    v.truncate(b.total);
    v
}

fn res_req(cmd: u32, ctx: u32, res: u32, total: usize) -> Vec<u8> {
    let mut v = hdr(cmd, 0, ctx, total.max(HDR_LEN + 4));
    put32(&mut v, 24, res);
    v.truncate(total);
    v
}

fn create_ctx(ctx: u32) -> Vec<u8> {
    let mut v = hdr(CMD_CTX_CREATE, 0, ctx, 96);
    put32(&mut v, 24, 3);
    put32(&mut v, 28, 4);
    v
}

fn submit_req(ctx: u32, flags: u32, ring: u8, size_field: u32, body: &[u8]) -> Vec<u8> {
    let mut v = hdr(CMD_SUBMIT_3D, flags, ctx, 32);
    v[20] = ring;
    put32(&mut v, 24, size_field);
    v.extend_from_slice(body);
    v
}

fn ring_body() -> Vec<u8> {
    let mut b = vec![0u8; 256];
    b[..4].copy_from_slice(&188u32.to_le_bytes());
    b
}

fn word(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn run(a: &mut CtrlAdapter, req: &[u8]) -> Handled {
    a.handle_ctrl(req)
}

fn ty(a: &mut CtrlAdapter, req: &[u8]) -> u32 {
    run(a, req).response.resp_type()
}

fn with_ctx(ctx: u32) -> CtrlAdapter {
    let mut a = CtrlAdapter::default();
    assert_eq!(ty(&mut a, &create_ctx(ctx)), OK);
    a
}

// ---- 資源表 ----

#[test]
fn task1601_gpu6_table_limits() {
    let mut t = ResourceTable::default();
    for i in 1..=MAX_RESOURCES as u32 {
        assert_eq!(t.create(i, 4096), Ok(()));
    }
    assert_eq!(t.len(), 256);
    assert_eq!(t.create(999, 4096), Err(ResourceError::Full));
    let mut t = ResourceTable::default();
    for i in 1..=4 {
        assert_eq!(t.create(i, 16 * MIB), Ok(()));
    }
    assert_eq!(t.total_size(), 64 * MIB);
    assert_eq!(t.create(5, 4096), Err(ResourceError::Full));
    assert_eq!(t.unref(1), Ok(()));
    assert_eq!(t.total_size(), 48 * MIB);
    assert_eq!(t.create(5, 16 * MIB), Ok(()));
}

#[test]
fn task1601_gpu6_table_size_and_id_checks() {
    let mut t = ResourceTable::default();
    assert_eq!(t.create(0, 4096), Err(ResourceError::InvalidId));
    assert_eq!(t.create(1, 0), Err(ResourceError::InvalidParameter));
    assert_eq!(t.create(1, 4095), Err(ResourceError::InvalidParameter));
    assert_eq!(
        t.create(1, 16 * MIB + 4096),
        Err(ResourceError::InvalidParameter)
    );
    assert_eq!(t.create(1, u64::MAX), Err(ResourceError::InvalidParameter));
    assert_eq!(t.create(1, 16 * MIB), Ok(()));
    assert_eq!(t.create(1, 4096), Err(ResourceError::InvalidId));
    assert!(t.attach(1, 64).is_err());
    assert_eq!(t.attach(1, 63), Ok(()));
    assert_eq!(t.unref(1), Err(ResourceError::InvalidParameter));
}

// ---- RESOURCE_CREATE_BLOB / ATTACH / DETACH / UNREF ----

#[test]
fn task1601_gpu6_success_sequence_and_log_lines() {
    let mut a = CtrlAdapter::default();
    assert_eq!(ty(&mut a, &create_ctx(1)), OK);
    let h = run(&mut a, &blob_req(&blob(1, 1, 135_168)));
    assert_eq!(
        (h.response.resp_type(), h.response.as_bytes().len()),
        (OK, 24)
    );
    assert_eq!(
        h.log_line,
        "venus_jig event=resource cmd=RESOURCE_CREATE_BLOB ctx_id=1 res_id=1 blob_mem=2 blob_flags=1 size=135168 result=ok"
    );
    let h = run(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, 32));
    assert_eq!(
        (h.response.resp_type(), h.response.as_bytes().len()),
        (OK, 24)
    );
    assert_eq!(
        h.log_line,
        "venus_jig event=resource cmd=CTX_ATTACH_RESOURCE ctx_id=1 res_id=1 result=ok"
    );
    let h = run(&mut a, &res_req(CMD_CTX_DETACH_RESOURCE, 1, 1, 32));
    assert_eq!(h.response.resp_type(), OK);
    assert_eq!(
        h.log_line,
        "venus_jig event=resource cmd=CTX_DETACH_RESOURCE ctx_id=1 res_id=1 result=ok"
    );
    let h = run(&mut a, &res_req(CMD_RESOURCE_UNREF, 0, 1, 32));
    assert_eq!(h.response.resp_type(), OK);
    assert_eq!(
        h.log_line,
        "venus_jig event=resource cmd=RESOURCE_UNREF res_id=1 result=ok"
    );
}

#[test]
fn task1601_gpu6_create_blob_rejects() {
    let mut a = with_ctx(1);
    // 長さ不正
    for total in [55usize, 57] {
        let mut b = blob(1, 1, 4096);
        b.total = total;
        let h = run(&mut a, &blob_req(&b));
        assert_eq!(h.response.resp_type(), BAD, "total={total}");
        assert!(h.log_line.contains("res_id=-1") && h.log_line.contains("size=-1"));
    }
    assert_eq!(ty(&mut a, &blob_req(&blob(2, 1, 4096))), NO_CTX);
    assert_eq!(ty(&mut a, &blob_req(&blob(0, 1, 4096))), NO_CTX);
    for mem in [0u32, 1, 3] {
        let mut b = blob(1, 1, 4096);
        b.mem = mem;
        assert_eq!(ty(&mut a, &blob_req(&b)), BAD, "mem={mem}");
    }
    for flags in [0u32, 2, 3, 4, 5] {
        let mut b = blob(1, 1, 4096);
        b.flags = flags;
        assert_eq!(ty(&mut a, &blob_req(&b)), BAD, "flags={flags}");
    }
    let mut b = blob(1, 1, 4096);
    b.blob_id = 1;
    assert_eq!(ty(&mut a, &blob_req(&b)), BAD);
    let mut b = blob(1, 1, 4096);
    b.nr = 1;
    assert_eq!(ty(&mut a, &blob_req(&b)), BAD);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 0, 4096))), NO_RES);
    for size in [0u64, 4095, 16 * MIB + 4096, u64::MAX] {
        assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, size))), BAD, "size={size}");
    }
    // 拒否では何も計上されない
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, 16 * MIB))), OK);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, 4096))), NO_RES);
}

#[test]
fn task1601_gpu6_create_blob_limits_via_adapter() {
    let mut a = with_ctx(1);
    for i in 1..=256u32 {
        assert_eq!(ty(&mut a, &blob_req(&blob(1, i, 4096))), OK, "i={i}");
    }
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 257, 4096))), OOM);
    let mut a = with_ctx(1);
    for i in 1..=4u32 {
        assert_eq!(ty(&mut a, &blob_req(&blob(1, i, 16 * MIB))), OK);
    }
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 5, 4096))), OOM);
    assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 1, 32)), OK);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 5, 16 * MIB))), OK);
}

#[test]
fn task1601_gpu6_attach_detach_unref_rejects() {
    let mut a = with_ctx(1);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, 4096))), OK);
    for total in [31usize, 33] {
        assert_eq!(
            ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, total)),
            BAD
        );
        assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 1, total)), BAD);
    }
    assert_eq!(
        ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 9, 1, 32)),
        NO_CTX
    );
    assert_eq!(
        ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 9, 32)),
        NO_RES
    );
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_DETACH_RESOURCE, 1, 1, 32)), BAD);
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, 32)), OK);
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, 32)), BAD);
    assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 1, 32)), BAD);
    assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 0, 32)), NO_RES);
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_DETACH_RESOURCE, 1, 1, 32)), OK);
    assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 1, 32)), OK);
    assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 1, 1, 32)), NO_RES);
}

#[test]
fn task1601_gpu6_ctx_destroy_detaches_implicitly() {
    let mut a = with_ctx(1);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, 4096))), OK);
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, 32)), OK);
    assert_eq!(ty(&mut a, &hdr(CMD_CTX_DESTROY, 0, 1, 24)), OK);
    // 同じ res を UNREF できる
    assert_eq!(ty(&mut a, &res_req(CMD_RESOURCE_UNREF, 0, 1, 32)), OK);
    // スロット再利用: 破棄した ctx と同じスロットに新しい ctx を作っても所属が化けない
    let mut a = with_ctx(1);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, 4096))), OK);
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, 32)), OK);
    assert_eq!(ty(&mut a, &hdr(CMD_CTX_DESTROY, 0, 1, 24)), OK);
    assert_eq!(ty(&mut a, &create_ctx(2)), OK);
    assert_eq!(ty(&mut a, &res_req(CMD_CTX_ATTACH_RESOURCE, 2, 1, 32)), OK);
}

#[test]
fn task1601_gpu6_fence_is_carried_over_on_success_and_failure() {
    let mut a = with_ctx(1);
    for (res, want) in [(1u32, OK), (0, NO_RES)] {
        let mut b = blob(1, res, 4096);
        b.hdr_flags = FLAG_FENCE;
        let h = run(&mut a, &blob_req(&b));
        let r = h.response.as_bytes();
        assert_eq!(h.response.resp_type(), want);
        assert_eq!(word(r, 4), FLAG_FENCE);
        assert_eq!(u64::from_le_bytes(r[8..16].try_into().unwrap()), 0x77);
        assert_eq!(word(r, 16), 1);
        assert_eq!(r[20], 5);
    }
}

#[test]
fn task1601_gpu6_map_unmap_blob_stay_unspec() {
    let mut a = with_ctx(1);
    assert_eq!(ty(&mut a, &blob_req(&blob(1, 1, 4096))), OK);
    for cmd in [CMD_RESOURCE_MAP_BLOB, CMD_RESOURCE_UNMAP_BLOB] {
        let h = run(&mut a, &res_req(cmd, 1, 1, 40));
        assert_eq!(h.response.resp_type(), RESP_ERR_UNSPEC);
        assert!(h.submit.is_none());
    }
}

// 応答を書き戻せず捨てた場合の巻き戻しは session の失敗経路を通す結合試験
// （tests/vhost_user_session.rs の `task1601_gpu6_dropped_blob_response_rolls_back_resource_table`）で検証する。

// ---- SUBMIT_3D ----

#[test]
fn task1601_gpu6_submit_3d_ok_with_ring_idx() {
    let mut a = with_ctx(1);
    let body = ring_body();
    let req = submit_req(1, FLAG_INFO_RING_IDX, 0, 256, &body);
    let h = run(&mut a, &req);
    assert_eq!(
        (h.response.resp_type(), h.response.as_bytes().len()),
        (OK, 24)
    );
    let s = h.submit.expect("submit");
    assert_eq!((s.ctx_id, s.ring_idx, s.fence_id), (1, Some(0), None));
    assert_eq!(s.payload, body);
    let hd = s.header.expect("header").expect("ok");
    assert_eq!(hd.command, CommandType::CreateRingMESA);
    assert_eq!(
        h.log_line,
        "venus_jig event=submit_3d cmd=SUBMIT_3D ctx_id=1 ring_idx=0 size=256 venus_cmd=188 wire=ok result=ok"
    );
}

#[test]
fn task1601_gpu6_submit_3d_empty_and_odd_bodies_still_ok() {
    let mut a = with_ctx(1);
    let h = run(&mut a, &submit_req(1, FLAG_FENCE, 0, 0, &[]));
    assert_eq!(h.response.resp_type(), OK);
    let s = h.submit.expect("submit");
    assert_eq!(
        (s.header, s.payload.len(), s.fence_id),
        (None, 0, Some(0x77))
    );
    assert_eq!(
        h.log_line,
        "venus_jig event=submit_3d cmd=SUBMIT_3D ctx_id=1 ring_idx=-1 size=0 venus_cmd=-1 wire=empty result=ok"
    );
    // 候補外の種別: 応答は変わらず、header が Err
    let body = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
    let h = run(&mut a, &submit_req(1, 0, 0, 8, &body));
    assert_eq!(h.response.resp_type(), OK);
    assert!(matches!(
        h.submit.expect("submit").header,
        Some(Err(VenusWireError::UnsupportedCommand { .. }))
    ));
    assert!(h.log_line.contains("wire=venus_wire.unsupported_command"));
    assert!(h.log_line.contains("venus_cmd=-1"));
    assert!(!h.log_line.contains("4294967295"));
    // 8 バイト未満
    let h = run(&mut a, &submit_req(1, 0, 0, 3, &[1, 2, 3]));
    assert_eq!(h.response.resp_type(), OK);
    assert!(matches!(
        h.submit.expect("submit").header,
        Some(Err(VenusWireError::Truncated { .. }))
    ));
    assert!(h.log_line.contains("wire=venus_wire.truncated"));
}

#[test]
fn task1601_gpu6_submit_3d_rejects() {
    let mut a = with_ctx(1);
    let body = ring_body();
    for size_field in [255u32, 257] {
        let h = run(&mut a, &submit_req(1, 0, 0, size_field, &body));
        assert_eq!(h.response.resp_type(), BAD);
        assert!(h.submit.is_none());
    }
    assert_eq!(ty(&mut a, &hdr(CMD_SUBMIT_3D, 0, 1, 31)), BAD);
    // 4096 ちょうどは受理、4097 は拒否
    let max = vec![0u8; MAX_REQ_LEN - 32];
    let h = run(&mut a, &submit_req(1, 0, 0, max.len() as u32, &max));
    assert_eq!(h.response.resp_type(), OK);
    assert_eq!(h.submit.expect("submit").payload.len(), 4064);
    let over = vec![0u8; MAX_REQ_LEN - 32 + 1];
    let h = run(&mut a, &submit_req(1, 0, 0, over.len() as u32, &over));
    assert_eq!(h.response.resp_type(), BAD);
    assert!(h.submit.is_none());
    // ctx 未作成
    let h = run(&mut a, &submit_req(9, 0, 0, 0, &[]));
    assert_eq!(h.response.resp_type(), NO_CTX);
    assert!(h.submit.is_none());
    // ring_idx
    let h = run(&mut a, &submit_req(1, FLAG_INFO_RING_IDX, 64, 0, &[]));
    assert_eq!(h.response.resp_type(), BAD);
    assert!(h.submit.is_none());
    let h = run(&mut a, &submit_req(1, FLAG_INFO_RING_IDX, 63, 0, &[]));
    assert_eq!(h.response.resp_type(), OK);
    let h = run(&mut a, &submit_req(1, 0, 64, 0, &[]));
    assert_eq!(h.response.resp_type(), OK);
    assert_eq!(h.submit.expect("submit").ring_idx, None);
}

#[test]
fn task1601_gpu6_submit_3d_fence_is_carried_over() {
    let mut a = with_ctx(1);
    for (ctx, want) in [(1u32, OK), (9, NO_CTX)] {
        let h = run(&mut a, &submit_req(ctx, FLAG_FENCE, 0, 0, &[]));
        let r = h.response.as_bytes();
        assert_eq!(h.response.resp_type(), want);
        assert_eq!(word(r, 4), FLAG_FENCE);
        assert_eq!(u64::from_le_bytes(r[8..16].try_into().unwrap()), 0x77);
        assert_eq!(word(r, 16), ctx);
    }
}

// ---- 照合器への影響 ----

#[test]
fn task1601_gpu6_new_log_lines_do_not_disturb_checker() {
    let mut a = CtrlAdapter::default();
    let mut log = String::from(
        "venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160\n",
    );
    let reqs = [
        create_ctx(1),
        blob_req(&blob(1, 1, 135_168)),
        blob_req(&blob(1, 0, 4096)),
        blob_req(&Blob {
            total: 55,
            ..blob(1, 1, 4096)
        }),
        res_req(CMD_CTX_ATTACH_RESOURCE, 1, 1, 32),
        res_req(CMD_CTX_ATTACH_RESOURCE, 1, 9, 31),
        res_req(CMD_CTX_DETACH_RESOURCE, 1, 1, 32),
        res_req(CMD_RESOURCE_UNREF, 1, 1, 32),
        res_req(CMD_RESOURCE_UNREF, 1, 1, 31),
        submit_req(1, FLAG_INFO_RING_IDX, 0, 256, &ring_body()),
        submit_req(1, 0, 0, 0, &[]),
        submit_req(1, 0, 0, 5, &[]),
        hdr(CMD_SUBMIT_3D, 0, 1, 10),
        submit_req(1, 0, 0, 8, &[0xff; 8]),
    ];
    for r in &reqs {
        let line = a.handle_ctrl(r).log_line;
        assert!(line.len() <= MAX_LINE_BYTES, "{line}");
        log.push_str(&line);
        log.push('\n');
    }
    let rep = find_capset_queries(&log).unwrap();
    assert_eq!(
        (rep.venus_get_capset_ok, rep.info_ok, rep.malformed_lines),
        (1, 0, 0)
    );
}
