//! ctrl `RESOURCE_MAP_BLOB` / `UNMAP_BLOB` と frontend のやりとりの試験（GPU-6・REPAIR-5・TASK-172 F5.2b.4a・#1643）。
//!
//! `backend_req_tests` と同じく `socketpair` の一端を backend channel として渡し、もう一端を偽 frontend のスレッドが動かす。
//! 要求は合成バイト列で `Session::process_ctrl` へ直接渡す（ring・ゲストメモリには触れない）。期待値は具体値で照合する。

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::backend_req_tests::{T, ready, recv_request, session};
use super::*;
use crate::ctrl::{
    CMD_CTX_CREATE, CMD_RESOURCE_CREATE_BLOB, CMD_RESOURCE_MAP_BLOB, CMD_RESOURCE_UNMAP_BLOB,
    CMD_RESOURCE_UNREF, RESP_ERR_UNSPEC, RESP_OK_MAP_INFO, RESP_OK_NODATA,
};
use crate::vhost_user::backend_req::encode_backend_reply;

/// 同じ名前の memfd を作る試験どうしで fd 数の照合が干渉しないよう、MAP を送る試験は直列化する。
static FD_LOCK: Mutex<()> = Mutex::new(());

const MAP_LEN: usize = 32;
const UNMAP_LEN: usize = 24;
const BAD: u32 = RESP_ERR_INVALID_PARAMETER;

fn hdr(cmd: u32, total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    v[..4].copy_from_slice(&cmd.to_le_bytes());
    v
}

fn ctx_create(ctx: u32) -> Vec<u8> {
    let mut v = hdr(CMD_CTX_CREATE, 96);
    v[16..20].copy_from_slice(&ctx.to_le_bytes());
    v[24..28].copy_from_slice(&3u32.to_le_bytes());
    v[28..32].copy_from_slice(&4u32.to_le_bytes());
    v
}

fn create_blob(ctx: u32, res: u32, size: u64) -> Vec<u8> {
    let mut v = hdr(CMD_RESOURCE_CREATE_BLOB, 56);
    v[16..20].copy_from_slice(&ctx.to_le_bytes());
    v[24..28].copy_from_slice(&res.to_le_bytes());
    v[28..32].copy_from_slice(&2u32.to_le_bytes());
    v[32..36].copy_from_slice(&1u32.to_le_bytes());
    v[48..56].copy_from_slice(&size.to_le_bytes());
    v
}

fn map_blob(res: u32, offset: u64) -> Vec<u8> {
    let mut v = hdr(CMD_RESOURCE_MAP_BLOB, 40);
    v[24..28].copy_from_slice(&res.to_le_bytes());
    v[32..40].copy_from_slice(&offset.to_le_bytes());
    v
}

fn unmap_blob(res: u32) -> Vec<u8> {
    let mut v = hdr(CMD_RESOURCE_UNMAP_BLOB, 32);
    v[24..28].copy_from_slice(&res.to_le_bytes());
    v
}

fn unref(res: u32) -> Vec<u8> {
    let mut v = hdr(CMD_RESOURCE_UNREF, 32);
    v[24..28].copy_from_slice(&res.to_le_bytes());
    v
}

fn resp_type(p: &Processed) -> u32 {
    p.response.resp_type()
}

/// ctx 1 と res 7（8192 バイト）を作る。
fn prepare(s: &mut Session) {
    let mut sink = |_: &str| {};
    for req in [ctx_create(1), create_blob(1, 7, 8192)] {
        let p = s.process_ctrl(Some(&req), 4096, &mut sink);
        assert_eq!(resp_type(&p), RESP_OK_NODATA);
    }
}

/// 偽 frontend が受けた要求（種別・shm_offset・len・fd_offset・flags・添付 fd 数・fd の (dev, ino, 長さ)）。
type Seen = (
    BackendRequestCode,
    u64,
    u64,
    u64,
    u64,
    usize,
    Option<(u64, u64, u64)>,
);

/// 偽 frontend: `replies` の数だけ要求を受け、順に応答する。
fn frontend(b: UnixStream, replies: Vec<u64>) -> JoinHandle<Vec<Seen>> {
    thread::spawn(move || {
        let mut seen = Vec::new();
        for v in replies {
            let (d, fds) = recv_request(&b);
            let meta = fds.first().map(|f| {
                let m = File::from(f.try_clone().expect("dup"))
                    .metadata()
                    .expect("meta");
                (m.dev(), m.ino(), m.len())
            });
            seen.push((
                d.request,
                d.shm_offset,
                d.len,
                d.fd_offset,
                d.flags,
                fds.len(),
                meta,
            ));
            // 受け取った fd は応答の前に閉じる。応答後に残すと、治具側の試験が応答を受けた直後に数える memfd に
            // この dup が混ざり、fd 数の照合が競合する。
            drop(fds);
            send_with_fds(&b, &encode_backend_reply(d.request, v), &[], T).expect("reply");
        }
        seen
    })
}

fn memfd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("fd dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .filter(|l| l.to_string_lossy() == "/memfd:venus-jig-blob (deleted)")
        .count()
}

fn blob_meta(s: &Session) -> (u64, u64, u64) {
    let b = s.blobs.slots.iter().flatten().next().expect("blob");
    let m = b.memfd.metadata().expect("meta");
    (m.dev(), m.ino(), m.len())
}

#[test]
fn f5_2b_4a_gpu6_map_success_passes_one_memfd_and_returns_map_info() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let h = frontend(b, vec![0]);
    let mut lines = Vec::new();
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut |l| {
        lines.push(l.to_string())
    });
    assert_eq!(
        (resp_type(&p), p.response.as_bytes().len()),
        (RESP_OK_MAP_INFO, MAP_LEN)
    );
    assert_eq!(
        p.response.as_bytes().get(24..28),
        Some(&1u32.to_le_bytes()[..])
    );
    let seen = h.join().expect("join");
    let fd_meta = seen[0].6;
    assert_eq!(
        seen[0],
        (BackendRequestCode::ShmemMap, 4096, 8192, 0, 1, 1, fd_meta)
    );
    assert_eq!(fd_meta, Some(blob_meta(&s)));
    assert_eq!(fd_meta.map(|m| m.2), Some(8192));
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_MAP shmid=1 shm_offset=4096 len=8192 result=ok status=0"
                .to_string()
        ]
    );
    assert_eq!(
        p.log_line,
        "venus_jig event=resource cmd=RESOURCE_MAP_BLOB res_id=7 offset=4096 size=8192 map_info=1 result=ok"
    );
    assert_eq!(s.blobs.len(), 1);
    assert_eq!(s.adapter.mapped_offset(7), Some(4096));
}

#[test]
fn f5_2b_4a_gpu6_remote_failure_returns_err_and_rolls_back() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![(-22i64) as u64, 0]);
    let mut sink = |_: &str| {};
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_ERR_UNSPEC);
    assert_eq!(s.adapter.mapped_offset(7), None);
    assert_eq!(s.blobs.len(), 0);
    // 同じ MAP の再送が再び frontend へ届き、今度は成功する（巻き戻しの確認）。
    let p2 = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    assert_eq!(resp_type(&p2), RESP_OK_MAP_INFO);
    let seen = h.join().expect("join");
    assert_eq!(seen.len(), 2);
    assert_eq!(s.blobs.len(), 1);
    // 失敗した 1 回目の memfd は捨てられ、残るのは 2 回目の 1 本だけ。
    assert_eq!(memfd_count(), base + 1);
}

#[test]
fn f5_2b_4a_gpu6_timeout_returns_err_and_breaks_channel() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(Duration::from_millis(200));
    prepare(&mut s);
    let h = thread::spawn(move || {
        let _ = recv_request(&b);
        // 応答しない。治具が諦めるまで端を保つ。
        thread::sleep(Duration::from_millis(1500));
    });
    let started = Instant::now();
    let mut sink = |_: &str| {};
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_ERR_UNSPEC);
    assert!(started.elapsed() < Duration::from_millis(1200), "deadline");
    assert_eq!(s.adapter.mapped_offset(7), None);
    assert_eq!(
        s.state.host_visible(),
        negotiation::HostVisible::Unavailable(
            negotiation::HostVisibleUnavailable::BackendChannelBroken
        )
    );
    // 以後の MAP は送らずに ERR になる。
    let p2 = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    assert_eq!(resp_type(&p2), RESP_ERR_UNSPEC);
    h.join().expect("join");
}

#[test]
fn f5_2b_4a_gpu6_disconnect_returns_err() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let h = thread::spawn(move || {
        let _ = recv_request(&b);
        drop(b);
    });
    let mut sink = |_: &str| {};
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_ERR_UNSPEC);
    assert_eq!(s.adapter.mapped_offset(7), None);
    assert_eq!(s.blobs.len(), 0);
    h.join().expect("join");
}

#[test]
fn f5_2b_4a_gpu6_host_visible_unavailable_sends_nothing() {
    // SET_BACKEND_REQ_FD を送らない接続（SHMEM 未確定の接続は `GET_SHMEM_CONFIG` 自体が `OutOfOrder` で拒否される）。
    let protocol = 0x0040_0229u64;
    let (mut s, mut b) = session(protocol, false, T);
    prepare(&mut s);
    let before = s.adapter.clone();
    let mut lines = Vec::new();
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut |l| {
        lines.push(l.to_string())
    });
    assert_eq!(resp_type(&p), RESP_ERR_UNSPEC, "protocol={protocol:#x}");
    assert_eq!(s.adapter, before);
    assert!(lines.is_empty());
    assert_eq!(s.blobs.len(), 0);
    b.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 8];
    let r = b.read(&mut buf);
    assert!(
        matches!(r, Ok(0))
            || r.as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
        "nothing was sent: {r:?}"
    );
}

#[test]
fn f5_2b_4a_gpu6_unmap_sends_unmap_keeps_memfd_and_allows_remap() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![0, 0, 0]);
    let mut sink = |_: &str| {};
    assert_eq!(
        resp_type(&s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink)),
        RESP_OK_MAP_INFO
    );
    assert_eq!(memfd_count(), base + 1);
    let p = s.process_ctrl(Some(&unmap_blob(7)), 4096, &mut sink);
    assert_eq!(
        (resp_type(&p), p.response.as_bytes().len()),
        (RESP_OK_NODATA, UNMAP_LEN)
    );
    assert_eq!(
        p.log_line,
        "venus_jig event=resource cmd=RESOURCE_UNMAP_BLOB res_id=7 offset=4096 size=8192 result=ok"
    );
    // memfd は resource の寿命まで残る（map 状態だけ外れる）。
    assert_eq!(s.blobs.len(), 1);
    assert_eq!(s.blobs.mapped_of(7), None);
    assert_eq!(memfd_count(), base + 1);
    // 同じ offset への再 MAP が成功する。
    assert_eq!(
        resp_type(&s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink)),
        RESP_OK_MAP_INFO
    );
    let seen = h.join().expect("join");
    assert_eq!(
        seen[1],
        (BackendRequestCode::ShmemUnmap, 4096, 8192, 0, 0, 0, None)
    );
}

#[test]
fn f5_2b_4a_gpu6_unmap_failure_keeps_mapping() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let h = frontend(b, vec![0, (-22i64) as u64]);
    let mut sink = |_: &str| {};
    assert_eq!(
        resp_type(&s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink)),
        RESP_OK_MAP_INFO
    );
    let p = s.process_ctrl(Some(&unmap_blob(7)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_ERR_UNSPEC);
    h.join().expect("join");
    // map 中のまま（区間を再利用させない）。UNREF も拒否される。
    assert_eq!(s.adapter.mapped_offset(7), Some(4096));
    assert_eq!(s.blobs.len(), 1);
    let p = s.process_ctrl(Some(&unref(7)), 4096, &mut sink);
    assert_eq!(resp_type(&p), BAD);
}

#[test]
fn f5_2b_4a_gpu6_short_writable_drops_before_contacting_frontend() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, mut b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let before = s.adapter.clone();
    let mut lines = Vec::new();
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 24, &mut |l| {
        lines.push(l.to_string())
    });
    assert!(p.dropped);
    assert_eq!(s.adapter, before);
    assert_eq!(s.blobs.len(), 0);
    assert_eq!(memfd_count(), base);
    assert!(lines.is_empty());
    b.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 8];
    let r = b.read(&mut buf);
    assert!(
        r.as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
        "nothing was sent: {r:?}"
    );
    b.set_nonblocking(false).expect("blocking");
    // 十分な長さなら同じ MAP が成功する。
    let h = frontend(b, vec![0, 0]);
    let mut sink = |_: &str| {};
    let p = s.process_ctrl(Some(&map_blob(7, 4096)), 32, &mut sink);
    assert_eq!((resp_type(&p), p.dropped), (RESP_OK_MAP_INFO, false));
    // UNMAP は 24 バイト必要。8 では frontend へ送らず map 中のまま。
    let p = s.process_ctrl(Some(&unmap_blob(7)), 8, &mut sink);
    assert!(p.dropped);
    assert_eq!(s.adapter.mapped_offset(7), Some(4096));
    assert_eq!(s.blobs.len(), 1);
    let p = s.process_ctrl(Some(&unmap_blob(7)), 24, &mut sink);
    assert_eq!(resp_type(&p), RESP_OK_NODATA);
    assert_eq!(h.join().expect("join").len(), 2);
}

#[test]
fn f5_2b_4a_gpu6_oversized_request_is_rejected_without_adapter() {
    let (mut s, _b) = ready(T);
    let mut sink = |_: &str| {};
    let p = s.process_ctrl(None, 4096, &mut sink);
    assert_eq!(resp_type(&p), BAD);
    assert!(!p.dropped);
}

#[test]
fn f5_2b_4a_gpu6_remap_reuses_memfd_and_keeps_contents() {
    use std::os::unix::fs::FileExt;
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![0, 0, 0]);
    let mut sink = |_: &str| {};
    let map = |s: &mut Session, off: u64, sink: &mut dyn FnMut(&str)| {
        resp_type(&s.process_ctrl(Some(&map_blob(7, off)), 4096, sink))
    };
    assert_eq!(map(&mut s, 4096, &mut sink), RESP_OK_MAP_INFO);
    // frontend が map した共有メモリへゲストが書いた内容の代わりに、同じ memfd へ書く。
    let slot = s.blobs.slots.iter().flatten().next().expect("blob");
    slot.memfd.write_all_at(b"guest-data", 100).expect("write");
    let before = blob_meta(&s);
    let p = s.process_ctrl(Some(&unmap_blob(7)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_OK_NODATA);
    // 別の offset へ再 MAP しても同じ memfd（同じ inode）で内容が残る。
    assert_eq!(map(&mut s, 8192, &mut sink), RESP_OK_MAP_INFO);
    assert_eq!(blob_meta(&s), before);
    let mut got = [0u8; 10];
    let slot = s.blobs.slots.iter().flatten().next().expect("blob");
    slot.memfd.read_exact_at(&mut got, 100).expect("read");
    assert_eq!(&got, b"guest-data");
    assert_eq!(memfd_count(), base + 1);
    let seen = h.join().expect("join");
    assert_eq!(seen[0].6, seen[2].6);
    assert_eq!((seen[2].0, seen[2].1), (BackendRequestCode::ShmemMap, 8192));
}

#[test]
fn f5_2b_4a_gpu6_unref_after_unmap_closes_memfd() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![0, 0]);
    let mut sink = |_: &str| {};
    let _ = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    let _ = s.process_ctrl(Some(&unmap_blob(7)), 4096, &mut sink);
    assert_eq!(memfd_count(), base + 1);
    let p = s.process_ctrl(Some(&unref(7)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_OK_NODATA);
    s.blobs.prune(&s.adapter);
    assert_eq!(s.blobs.len(), 0);
    assert_eq!(memfd_count(), base);
    h.join().expect("join");
}
/// 終了時の片づけを呼んで、出たログ行を返す。
fn release(s: &mut Session) -> Vec<String> {
    let mut lines = Vec::new();
    s.release_blobs_at_end(&mut |l| lines.push(l.to_string()));
    lines
}

/// GPU-6・REPAIR-5・REPAIR-12（#1645・D3）: map が残ったままの終了では SHMEM_UNMAP を送って memfd を閉じる。
#[test]
fn f5_2b_4b_gpu6_release_sends_unmap_and_closes_memfd() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![0, 0]);
    let mut sink = |_: &str| {};
    assert_eq!(
        resp_type(&s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink)),
        RESP_OK_MAP_INFO
    );
    assert_eq!(memfd_count(), base + 1);
    let lines = release(&mut s);
    let seen = h.join().expect("join");
    assert_eq!(
        seen[1],
        (BackendRequestCode::ShmemUnmap, 4096, 8192, 0, 0, 0, None)
    );
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_UNMAP shmid=1 shm_offset=4096 len=8192 result=ok status=0"
                .to_string(),
            "venus_jig event=blob_release mapped=1 unmapped=1 memfds=1".to_string(),
        ]
    );
    assert_eq!(s.blobs.len(), 0);
    assert_eq!(memfd_count(), base);
}

/// GPU-6・REPAIR-5（#1645・D3）: channel が `Broken` なら 1 バイトも送らず、memfd は閉じる。
#[test]
fn f5_2b_4b_gpu6_release_with_broken_channel_sends_nothing_and_closes_memfd() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b.try_clone().expect("dup"), vec![0]);
    let mut sink = |_: &str| {};
    assert_eq!(
        resp_type(&s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink)),
        RESP_OK_MAP_INFO
    );
    h.join().expect("join");
    s.state.mark_backend_broken();
    let lines = release(&mut s);
    assert_eq!(
        lines,
        vec!["venus_jig event=blob_release mapped=1 unmapped=0 memfds=1".to_string()]
    );
    assert_eq!(s.blobs.len(), 0);
    assert_eq!(memfd_count(), base);
    b.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 8];
    let r = (&b).read(&mut buf);
    // `Broken` にした時点で治具は端を閉じるため EOF（0 バイト）。どちらでも 1 バイトも届いていない。
    assert!(
        matches!(r, Ok(0))
            || r.as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
        "nothing was sent: {r:?}"
    );
}

/// GPU-6・REPAIR-5（#1645・D3）: 非 0 の応答で打ち切る（2 件目は送らない）。memfd は 2 本とも閉じる。
#[test]
fn f5_2b_4b_gpu6_release_stops_at_first_failure_and_closes_all_memfds() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![0, 0, (-22i64) as u64]);
    let mut sink = |_: &str| {};
    let p = s.process_ctrl(Some(&create_blob(1, 8, 4096)), 4096, &mut sink);
    assert_eq!(resp_type(&p), RESP_OK_NODATA);
    for (res, off) in [(7, 4096u64), (8, 16384u64)] {
        assert_eq!(
            resp_type(&s.process_ctrl(Some(&map_blob(res, off)), 4096, &mut sink)),
            RESP_OK_MAP_INFO
        );
    }
    assert_eq!(memfd_count(), base + 2);
    let lines = release(&mut s);
    assert_eq!(h.join().expect("join").len(), 3);
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_UNMAP shmid=1 shm_offset=4096 len=8192 result=err status=18446744073709551594"
                .to_string(),
            "venus_jig event=blob_release mapped=2 unmapped=0 memfds=2".to_string(),
        ]
    );
    assert_eq!(s.blobs.len(), 0);
    assert_eq!(memfd_count(), base);
}

/// GPU-6（#1645・D3）: UNMAP 済みで memfd だけ残った blob は何も送らずに閉じる。
#[test]
fn f5_2b_4b_gpu6_release_closes_unmapped_memfd_without_sending() {
    let _g = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut s, b) = ready(T);
    prepare(&mut s);
    let base = memfd_count();
    let h = frontend(b, vec![0, 0]);
    let mut sink = |_: &str| {};
    let _ = s.process_ctrl(Some(&map_blob(7, 4096)), 4096, &mut sink);
    let _ = s.process_ctrl(Some(&unmap_blob(7)), 4096, &mut sink);
    h.join().expect("join");
    assert_eq!(memfd_count(), base + 1);
    let lines = release(&mut s);
    assert_eq!(
        lines,
        vec!["venus_jig event=blob_release mapped=0 unmapped=0 memfds=1".to_string()]
    );
    assert_eq!(memfd_count(), base);
}
