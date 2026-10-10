//! 結合試験の共有部品: vhost-user の偽 frontend（GPU-6・REPAIR-5・TASK-172 F1.4・F4）。
//!
//! `vhost_user_session.rs`（`run` を直接呼ぶ）と `venus_jig_bin.rs`（bin の UDS へ接続する）が使う。ネゴシエーション・
//! ring 0 の設定・GET_CAPSET の投入・call の待機・used の読み出しを具体値の照合つきで提供する。
//! test crate ごとに使う項目が異なるため、片方でしか使わない項目には個別に `#[allow(dead_code)]` を付ける。

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use fandhe_container_poc_venus_jig::vhost_user::fd_passing::{
    create_memfd, recv_with_fds, send_with_fds,
};
use fandhe_container_poc_venus_jig::vhost_user::{
    ConfigPayload, MemRegion, MemTable, Reply, Request, RequestCode, VringAddr, VringFd,
    VringState, decode_reply,
};

pub const T: Duration = Duration::from_secs(5);
pub const FEATURES: u64 = 0x0000_0001_4000_0019;
pub const UVA: u64 = 0x7f00_0000_0000;
pub const MEM_LEN: u64 = 0x1_0000;

pub fn unique_name(tag: &str) -> String {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    format!(
        "jig-sess-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

pub fn memfd(name: &str, len: u64) -> File {
    create_memfd(&CString::new(name).expect("name"), len).expect("memfd")
}

pub fn send(f: &UnixStream, req: &Request, fds: &[std::os::fd::BorrowedFd<'_>]) {
    let msg = req.encode(false).expect("encode");
    let sent = send_with_fds(f, msg.as_bytes(), fds, T).expect("send");
    assert_eq!(sent.len, msg.as_bytes().len());
}

/// NEED_REPLY を立てて送る（REPLY_ACK の試験用。#1639）。
#[allow(dead_code)]
pub fn send_need_reply(f: &UnixStream, req: &Request, fds: &[std::os::fd::BorrowedFd<'_>]) {
    let msg = req.encode(true).expect("encode");
    let sent = send_with_fds(f, msg.as_bytes(), fds, T).expect("send");
    assert_eq!(sent.len, msg.as_bytes().len());
}

/// ちょうど `n` バイトを受ける（ack の生バイト照合用。#1639）。
#[allow(dead_code)]
pub fn recv_raw(f: &UnixStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    read_exact(f, &mut buf);
    buf
}

pub fn read_exact(f: &UnixStream, buf: &mut [u8]) {
    let mut done = 0;
    while done < buf.len() {
        let r = recv_with_fds(f, &mut buf[done..], 0, T).expect("recv");
        done += r.len;
    }
}

pub fn recv_reply(f: &UnixStream, expected: RequestCode) -> Reply {
    let mut hdr = [0u8; 12];
    read_exact(f, &mut hdr);
    let size = u32::from_le_bytes(hdr[8..12].try_into().expect("size")) as usize;
    let mut msg = hdr.to_vec();
    msg.resize(12 + size, 0);
    read_exact(f, &mut msg[12..]);
    decode_reply(&msg, expected).expect("decode reply")
}

pub fn cfg_req(offset: u32, size: usize) -> Request {
    Request::GetConfig(
        ConfigPayload::new(RequestCode::GetConfig, offset, 0, &vec![0u8; size]).expect("cfg"),
    )
}

/// `SET_FEATURES` まで済ませる（広告値・protocol feature・queue 数・config も具体値で照合）。
pub fn negotiate(f: &UnixStream) {
    send(f, &Request::GetFeatures, &[]);
    assert_eq!(
        recv_reply(f, RequestCode::GetFeatures),
        Reply::Features(FEATURES)
    );
    send(f, &Request::SetOwner, &[]);
    send(f, &Request::GetProtocolFeatures, &[]);
    assert_eq!(
        recv_reply(f, RequestCode::GetProtocolFeatures),
        Reply::ProtocolFeatures(0x209)
    );
    // 確定は REPLY_ACK を含まない 0x201 のままにする（NEED_REPLY を立てない既定の流れと、未確定セッションの挙動を保つ）。
    send(f, &Request::SetProtocolFeatures(0x201), &[]);
    send(f, &Request::GetQueueNum, &[]);
    assert_eq!(recv_reply(f, RequestCode::GetQueueNum), Reply::QueueNum(2));
    send(f, &cfg_req(0, 16), &[]);
    let Reply::Config(c) = recv_reply(f, RequestCode::GetConfig) else {
        panic!("config reply expected");
    };
    let mut want = [0u8; 16];
    want[12] = 1;
    assert_eq!(c.data(), &want);
    send(f, &cfg_req(12, 8), &[]);
    assert_eq!(recv_reply(f, RequestCode::GetConfig), Reply::ConfigError);
    send(f, &Request::SetFeatures(FEATURES), &[]);
}

pub struct Frontend {
    /// 保持して接続を開いたままにするための所有（読み出しはしない）。
    pub _sock: UnixStream,
    pub mem: File,
    pub kick: UnixStream,
    pub call: UnixStream,
}

/// ring 0 を設定して起動する。desc1（writable）の長さは `writable_len`。
pub fn setup_ring0(sock: UnixStream, writable_len: u32, tag: &str) -> Frontend {
    negotiate(&sock);
    let mem = memfd(&unique_name(tag), MEM_LEN);
    let table = MemTable::new(&[MemRegion {
        guest_phys_addr: 0,
        memory_size: MEM_LEN,
        userspace_addr: UVA,
        mmap_offset: 0,
    }])
    .expect("table");
    send(&sock, &Request::SetMemTable(table), &[mem.as_fd()]);
    let st = |num| VringState { index: 0, num };
    send(&sock, &Request::SetVringNum(st(8)), &[]);
    send(&sock, &Request::SetVringBase(st(0)), &[]);
    send(
        &sock,
        &Request::SetVringAddr(VringAddr {
            index: 0,
            flags: 0,
            descriptor: UVA,
            used: UVA + 0x2000,
            available: UVA + 0x1000,
            log: 0,
        }),
        &[],
    );
    let (kick, kick_back) = UnixStream::pair().expect("kick");
    let (call, call_back) = UnixStream::pair().expect("call");
    let vf = VringFd {
        index: 0,
        no_fd: false,
    };
    send(&sock, &Request::SetVringKick(vf), &[kick_back.as_fd()]);
    send(&sock, &Request::SetVringCall(vf), &[call_back.as_fd()]);
    // 送った後は手元の複製を閉じても backend 側の fd は生きている。
    drop((kick_back, call_back));
    send(&sock, &Request::SetVringEnable(st(1)), &[]);
    call.set_read_timeout(Some(T)).expect("timeout");
    let fe = Frontend {
        _sock: sock,
        mem,
        kick,
        call,
    };
    // desc0: readable 32 バイト（NEXT -> 1）、desc1: WRITE。
    let desc = |addr: u64, len: u32, flags: u16, next: u16| {
        let mut d = Vec::new();
        d.extend_from_slice(&addr.to_le_bytes());
        d.extend_from_slice(&len.to_le_bytes());
        d.extend_from_slice(&flags.to_le_bytes());
        d.extend_from_slice(&next.to_le_bytes());
        d
    };
    fe.mem.write_at(&desc(0x4000, 32, 1, 1), 0).expect("desc0");
    fe.mem
        .write_at(&desc(0x5000, writable_len, 2, 0), 16)
        .expect("desc1");
    fe
}

/// GET_CAPSET（capset_id=4・version=0）の 32 バイトを ring 0 に積んで kick する。
pub fn submit_get_capset(fe: &Frontend) -> Vec<u8> {
    let mut req = vec![0u8; 32];
    req[..4].copy_from_slice(&0x0109u32.to_le_bytes());
    req[24..28].copy_from_slice(&4u32.to_le_bytes());
    fe.mem.write_at(&req, 0x4000).expect("req");
    fe.mem.write_at(&[0, 0], 0x1004).expect("ring[0]");
    fe.mem.write_at(&[1, 0], 0x1002).expect("idx");
    (&fe.kick).write_all(&1u64.to_le_bytes()).expect("kick");
    req
}

pub fn wait_call(fe: &Frontend) {
    let mut b = [0u8; 8];
    (&fe.call).read_exact(&mut b).expect("call");
    assert_eq!(u64::from_le_bytes(b), 1);
}

pub fn used(fe: &Frontend) -> [u8; 12] {
    let mut u = [0u8; 12];
    fe.mem.read_at(&mut u, 0x2000).expect("used");
    u
}

/// n 番目（0..4）の要求を ring 0 へ積んで kick し、call を待つ。descriptor は 2n（readable・NEXT）と 2n+1（writable）。
#[allow(dead_code)]
pub fn post(fe: &Frontend, n: u16, req: &[u8], writable_len: u32) {
    let desc = |addr: u64, len: u32, flags: u16, next: u16| {
        let mut d = Vec::new();
        d.extend_from_slice(&addr.to_le_bytes());
        d.extend_from_slice(&len.to_le_bytes());
        d.extend_from_slice(&flags.to_le_bytes());
        d.extend_from_slice(&next.to_le_bytes());
        d
    };
    let req_addr = 0x4000 + u64::from(n) * 0x400;
    let resp_addr = 0x5000 + u64::from(n) * 0x400;
    let head = 2 * n;
    let readable = u32::try_from(req.len()).expect("len");
    fe.mem
        .write_at(&desc(req_addr, readable, 1, head + 1), u64::from(head) * 16)
        .expect("desc r");
    fe.mem
        .write_at(
            &desc(resp_addr, writable_len, 2, 0),
            u64::from(head + 1) * 16,
        )
        .expect("desc w");
    fe.mem.write_at(req, req_addr).expect("req");
    fe.mem
        .write_at(&head.to_le_bytes(), 0x1004 + u64::from(n) * 2)
        .expect("ring");
    fe.mem
        .write_at(&(n + 1).to_le_bytes(), 0x1002)
        .expect("idx");
    (&fe.kick).write_all(&1u64.to_le_bytes()).expect("kick");
    wait_call(fe);
}

#[allow(dead_code)]
pub fn resp_type(fe: &Frontend, n: u16) -> u32 {
    let mut b = [0u8; 4];
    fe.mem
        .read_at(&mut b, 0x5000 + u64::from(n) * 0x400)
        .expect("resp");
    u32::from_le_bytes(b)
}

#[allow(dead_code)]
pub fn used_len(fe: &Frontend, n: u16) -> u32 {
    let mut b = [0u8; 4];
    fe.mem
        .read_at(&mut b, 0x2000 + 4 + u64::from(n) * 8 + 4)
        .expect("used len");
    u32::from_le_bytes(b)
}

#[allow(dead_code)]
pub fn ctrl_req(cmd: u32, ctx: u32, total: usize, words: &[(usize, u32)]) -> Vec<u8> {
    let mut v = vec![0u8; total];
    v[..4].copy_from_slice(&cmd.to_le_bytes());
    v[16..20].copy_from_slice(&ctx.to_le_bytes());
    for (off, x) in words {
        v[*off..*off + 4].copy_from_slice(&x.to_le_bytes());
    }
    v
}

/// `CTX_CREATE`（ctx_id=`ctx`、capset 4）の要求。
#[allow(dead_code)]
pub fn ctx_create_req(ctx: u32) -> Vec<u8> {
    ctrl_req(0x0200, ctx, 96, &[(24, 3), (28, 4)])
}

/// `SUBMIT_3D`（ring_idx=0・`INFO_RING_IDX`）の要求。32 バイトの固定部の後ろに `body` を続ける。
#[allow(dead_code)]
pub fn submit_3d_req(ctx: u32, body: &[u8]) -> Vec<u8> {
    let size = u32::try_from(body.len()).expect("body len");
    let mut req = ctrl_req(0x0207, ctx, 32, &[(24, size)]);
    req[4..8].copy_from_slice(&2u32.to_le_bytes());
    req[20] = 0;
    req.extend_from_slice(body);
    req
}
