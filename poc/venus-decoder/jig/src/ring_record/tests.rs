//! リング記録の単体試験（GPU-6・REPAIR-2・REPAIR-12・TASK-172 後続・#1884。3 OS・既定集合）。
//! 偽の `BlobRead`（メモリ上の blob）で、解析・スナップショット・拒否を具体値で照合する。

use std::cell::Cell;
use std::collections::HashMap;

use fandhe_container_plugin_macos::gpu::venus::replay::validate;
use fandhe_container_plugin_macos::gpu::venus::{WireReader, parse_command_header};

use super::*;
use crate::recording::{RecorderLimits, SubmitRecorder};

const CREATE: u32 = 188;
const DESTROY: u32 = 189;

#[derive(Clone, Copy)]
struct Spec {
    res_id: u32,
    offset: u64,
    size: u64,
    head: u64,
    tail: u64,
    status: u64,
    buf_off: u64,
    buf_size: u64,
}

/// 64 バイト境界の head・tail・status の後に 64 バイトの buffer を置く標準配置（blob 全体 256 バイト）。
fn std_spec() -> Spec {
    Spec {
        res_id: 5,
        offset: 0,
        size: 256,
        head: 0,
        tail: 64,
        status: 128,
        buf_off: 192,
        buf_size: 64,
    }
}

const MON: i32 = STYPE_RING_MONITOR_INFO;
const PRI: i32 = STYPE_RING_PRIORITY_INFO;

/// 入れ子を先に出す wire 規則どおり、chain の各要素は pointer(1)・sType を順に積み、末端 pointer(0) の後に self を逆順で積む。
fn create_payload(ring: u64, sp: Spec, chain: &[i32]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&CREATE.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&ring.to_le_bytes());
    v.extend_from_slice(&1u64.to_le_bytes());
    v.extend_from_slice(&STYPE_RING_CREATE_INFO.to_le_bytes());
    for st in chain {
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&st.to_le_bytes());
    }
    v.extend_from_slice(&0u64.to_le_bytes());
    for _ in chain {
        v.extend_from_slice(&7u32.to_le_bytes());
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&sp.res_id.to_le_bytes());
    for x in [
        sp.offset,
        sp.size,
        0,
        sp.head,
        sp.tail,
        sp.status,
        sp.buf_off,
        sp.buf_size,
        0,
        0,
    ] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

fn destroy_payload(ring: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&DESTROY.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&ring.to_le_bytes());
    v
}

fn submit(payload: Vec<u8>) -> Submit3d {
    let header = parse_command_header(&mut WireReader::new(&payload));
    Submit3d {
        ctx_id: 1,
        ring_idx: None,
        fence_id: None,
        header: Some(header),
        payload,
    }
}

#[derive(Default)]
struct FakeBlobs {
    blobs: HashMap<u32, Vec<u8>>,
    fail_reads: Cell<bool>,
}

impl FakeBlobs {
    fn with(res: u32, len: usize) -> Self {
        let mut f = Self::default();
        f.blobs.insert(res, vec![0u8; len]);
        f
    }
    fn put_u32(&mut self, res: u32, off: usize, v: u32) {
        self.put(res, off, &v.to_le_bytes());
    }
    fn put(&mut self, res: u32, off: usize, d: &[u8]) {
        let b = self.blobs.get_mut(&res).expect("blob");
        b[off..off + d.len()].copy_from_slice(d);
    }
}

impl BlobRead for FakeBlobs {
    fn blob_len(&self, res_id: u32) -> Option<u64> {
        self.blobs.get(&res_id).map(|b| b.len() as u64)
    }
    fn read_exact_at(&self, res_id: u32, offset: u64, buf: &mut [u8]) -> Result<(), BlobReadError> {
        if self.fail_reads.get() {
            return Err(BlobReadError::ReadFailed);
        }
        let b = self.blobs.get(&res_id).ok_or(BlobReadError::NotHeld)?;
        let o = usize::try_from(offset).map_err(|_| BlobReadError::OutOfRange)?;
        let s = b.get(o..o + buf.len()).ok_or(BlobReadError::OutOfRange)?;
        buf.copy_from_slice(s);
        Ok(())
    }
}

type Hooks = RecordingHooks<Vec<u8>>;

fn hooks() -> Hooks {
    RecordingHooks::new(SubmitRecorder::new(Vec::new(), RecorderLimits::default()))
}

fn snap(h: &mut Hooks, blobs: &FakeBlobs) -> Vec<String> {
    let mut out = Vec::new();
    h.snapshot_all(blobs, &mut |l| out.push(l.to_string()));
    out
}

fn create(h: &mut Hooks, ring: u64, sp: Spec, chain: &[i32]) -> Vec<String> {
    let mut out = Vec::new();
    h.on_submit(&submit(create_payload(ring, sp, chain)), &mut |l| {
        out.push(l.to_string())
    });
    out
}

fn payloads(h: Hooks) -> Vec<Vec<u8>> {
    let (bytes, _) = h.into_recorder().finish();
    let bytes = bytes.expect("finish");
    validate(&bytes)
        .expect("validate")
        .records()
        .iter()
        .map(|r| r.payload.to_vec())
        .collect()
}

#[test]
fn gpu6_1884_parse_create_monitor_only_and_with_priority() {
    for chain in [vec![MON], vec![MON, PRI]] {
        let (ring, l) = RingLayout::parse_create(&create_payload(9, std_spec(), &chain)).unwrap();
        assert_eq!(ring, 9);
        assert_eq!(l.res_id(), 5);
        assert_eq!(l.buffer_size(), 64);
        assert_eq!(l.offset(), 0);
        assert_eq!(l.size(), 256);
        assert_eq!(l.status_offset(), 128);
    }
    assert_eq!(RingLayout::parse_destroy(&destroy_payload(9)).unwrap(), 9);
}

#[test]
fn gpu6_1884_parse_create_rejects_malformed() {
    let ok = create_payload(1, std_spec(), &[MON]);
    let bad = RingErrorCode::MalformedCommand;
    assert_eq!(
        RingLayout::parse_create(&ok[..ok.len() - 1]).unwrap_err(),
        bad
    );
    let mut extra = ok.clone();
    extra.push(0);
    assert_eq!(RingLayout::parse_create(&extra).unwrap_err(), bad);
    for chain in [vec![42], vec![MON, MON], vec![MON, PRI, MON]] {
        assert_eq!(
            RingLayout::parse_create(&create_payload(1, std_spec(), &chain)).unwrap_err(),
            bad
        );
    }
    let mut p2 = ok.clone();
    p2[16..24].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(RingLayout::parse_create(&p2).unwrap_err(), bad);
    assert_eq!(
        RingLayout::parse_create(&destroy_payload(1)).unwrap_err(),
        bad
    );
    let mut d = destroy_payload(1);
    d.push(0);
    assert_eq!(RingLayout::parse_destroy(&d).unwrap_err(), bad);
}

#[test]
fn gpu6_1884_parse_create_rejects_invalid_layout() {
    let s = std_spec();
    let cases = [
        Spec { buf_size: 0, ..s },
        Spec { buf_size: 48, ..s },
        Spec {
            buf_size: 32 << 20,
            size: 64 << 20,
            buf_off: 0,
            ..s
        },
        Spec {
            buf_size: 1 << 33,
            ..s
        },
        Spec { tail: 253, ..s },
        Spec { tail: 256, ..s },
        Spec {
            head: u64::MAX - 1,
            ..s
        },
        Spec { buf_off: 200, ..s },
        Spec {
            offset: u64::MAX,
            ..s
        },
        Spec { res_id: 0, ..s },
    ];
    for c in cases {
        assert_eq!(
            RingLayout::parse_create(&create_payload(1, c, &[MON])).unwrap_err(),
            RingErrorCode::InvalidLayout
        );
    }
}

#[test]
fn gpu6_1884_snapshot_records_diff_without_wrap_and_skips_empty() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    assert_eq!(
        create(&mut h, 1, std_spec(), &[MON]),
        vec!["venus_jig event=ring_create ring=1 res_id=5 buffer_size=64 result=ok"]
    );
    blobs.put(5, 192, &[1, 2, 3, 4, 5, 6, 7, 8]);
    blobs.put_u32(5, 64, 8);
    assert_eq!(
        snap(&mut h, &blobs),
        vec![
            "venus_jig event=ring_record ring=1 res_id=5 from=0 to=8 len=8 seqno=1 outcome=recorded"
        ]
    );
    assert!(snap(&mut h, &blobs).is_empty());
    blobs.put(5, 200, &[9, 9]);
    blobs.put_u32(5, 64, 10);
    assert_eq!(snap(&mut h, &blobs).len(), 1);
    let p = payloads(h);
    assert_eq!(p.len(), 3);
    assert_eq!(p[1], vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(p[2], vec![9, 9]);
}

#[test]
fn gpu6_1884_snapshot_records_wrapped_range_across_u32_overflow() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    let start = u32::MAX - 3; // index 60
    blobs.put_u32(5, 0, start);
    blobs.put_u32(5, 64, start);
    create(&mut h, 1, std_spec(), &[MON]);
    assert!(snap(&mut h, &blobs).is_empty());
    blobs.put(5, 192 + 60, &[10, 11, 12, 13]);
    blobs.put(5, 192, &[14, 15, 16, 17]);
    blobs.put_u32(5, 64, start.wrapping_add(8));
    assert_eq!(
        snap(&mut h, &blobs),
        vec![format!(
            "venus_jig event=ring_record ring=1 res_id=5 from={start} to=4 len=8 seqno=1 outcome=recorded"
        )]
    );
    assert_eq!(payloads(h)[1], vec![10, 11, 12, 13, 14, 15, 16, 17]);
}

#[test]
fn gpu6_1884_snapshot_rejects_bad_tail_and_stops_after_one_log() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    create(&mut h, 1, std_spec(), &[MON]);
    blobs.put_u32(5, 64, 65);
    assert_eq!(
        snap(&mut h, &blobs),
        vec!["venus_jig event=ring_error ring=1 code=tail_out_of_range"]
    );
    blobs.put_u32(5, 64, 4);
    assert!(snap(&mut h, &blobs).is_empty());
    assert_eq!(payloads(h).len(), 1);
}

#[test]
fn gpu6_1884_snapshot_rejects_cursor_beyond_buffer() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    create(&mut h, 1, std_spec(), &[MON]);
    blobs.put_u32(5, 64, 64);
    assert_eq!(snap(&mut h, &blobs).len(), 1); // cursor=64
    // head=tail-... を保ったまま cursor から bufferSize を超えて進める。head が追いつけば head 側の検査は通る。
    blobs.put_u32(5, 0, 100);
    blobs.put_u32(5, 64, 160);
    assert_eq!(
        snap(&mut h, &blobs),
        vec!["venus_jig event=ring_error ring=1 code=tail_out_of_range"]
    );
}

#[test]
fn gpu6_1884_snapshot_rejects_missing_blob_out_of_range_and_short_read() {
    let sp = std_spec();
    let mut h = hooks();
    create(&mut h, 1, sp, &[MON]);
    assert_eq!(
        snap(&mut h, &FakeBlobs::default()),
        vec!["venus_jig event=ring_error ring=1 code=blob_not_held"]
    );
    let mut h = hooks();
    create(&mut h, 1, sp, &[MON]);
    assert_eq!(
        snap(&mut h, &FakeBlobs::with(5, 128)),
        vec!["venus_jig event=ring_error ring=1 code=out_of_range"]
    );
    let mut h = hooks();
    create(&mut h, 1, sp, &[MON]);
    let bad = FakeBlobs::with(5, 256);
    bad.fail_reads.set(true);
    assert_eq!(
        snap(&mut h, &bad),
        vec!["venus_jig event=ring_error ring=1 code=read_failed"]
    );
}

#[test]
fn gpu6_1884_recorder_limit_stops_before_allocating() {
    let mut blobs = FakeBlobs::with(5, 256);
    let limits = RecorderLimits::new(4, 100, 1 << 20).unwrap();
    // 1 レコード 4 バイトの上限では CreateRing の本体（約 130 バイト）自体も止まるので、停止済みから始まる。
    let mut h = RecordingHooks::new(SubmitRecorder::new(Vec::new(), limits));
    let created = create(&mut h, 1, std_spec(), &[MON]);
    assert_eq!(
        created[0],
        "venus_jig event=record_stopped reason=payload_too_large records=0"
    );
    blobs.put_u32(5, 64, 8);
    // 記録器が止まっているので、読む前に Skipped で止まる（record_stopped は再度出ない）。
    assert_eq!(
        snap(&mut h, &blobs),
        vec!["venus_jig event=ring_error ring=1 code=record_stopped"]
    );
}

#[test]
fn gpu6_1884_duplicate_table_full_and_broken_create() {
    let mut h = hooks();
    let sp = std_spec();
    create(&mut h, 1, sp, &[MON]);
    assert_eq!(
        create(&mut h, 1, sp, &[MON]),
        vec![
            "venus_jig event=ring_create ring=1 res_id=5 buffer_size=64 result=err code=duplicate_ring"
        ]
    );
    for id in 2..=16u64 {
        create(&mut h, id, sp, &[MON]);
    }
    assert_eq!(
        create(&mut h, 99, sp, &[MON]),
        vec![
            "venus_jig event=ring_create ring=99 res_id=5 buffer_size=64 result=err code=table_full"
        ]
    );
    let mut broken = create_payload(1, sp, &[MON]);
    broken.pop();
    let mut out = Vec::new();
    h.on_submit(&submit(broken), &mut |l| out.push(l.to_string()));
    assert_eq!(
        out,
        vec!["venus_jig event=ring_create result=err code=malformed_command"]
    );
}

#[test]
fn gpu6_1884_destroy_takes_final_snapshot_then_drops_ring() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    create(&mut h, 1, std_spec(), &[MON]);
    blobs.put(5, 192, &[1, 2, 3, 4]);
    blobs.put_u32(5, 64, 4);
    h.before_response(&submit(destroy_payload(1)), &blobs, &mut |_| {});
    h.on_submit(&submit(destroy_payload(1)), &mut |_| {});
    // 応答の公開前に最終読み取りが済み、表から外れている。
    blobs.put_u32(5, 64, 8);
    assert!(snap(&mut h, &blobs).is_empty());
    let p = payloads(h);
    assert_eq!(p.len(), 3);
    // リングの最終読み取りは Destroy 本体の記録より前（応答の公開前）に入る。
    assert_eq!(p[1], vec![1, 2, 3, 4]);
}

fn submit_ctx(ctx_id: u32, payload: Vec<u8>) -> Submit3d {
    Submit3d {
        ctx_id,
        ..submit(payload)
    }
}

#[test]
fn gpu6_1884_same_ring_id_in_two_contexts_is_distinct() {
    let mut blobs = FakeBlobs::with(5, 256);
    blobs.blobs.insert(6, vec![0u8; 256]);
    let mut h = hooks();
    let mut out = Vec::new();
    h.on_submit(
        &submit_ctx(1, create_payload(1, std_spec(), &[MON])),
        &mut |l| out.push(l.to_string()),
    );
    let mut sp2 = std_spec();
    sp2.res_id = 6;
    h.on_submit(&submit_ctx(2, create_payload(1, sp2, &[MON])), &mut |l| {
        out.push(l.to_string())
    });
    assert!(out.iter().all(|l| !l.contains("duplicate_ring")), "{out:?}");
    // ctx 2 の破棄は ctx 1 のリングに影響しない。
    blobs.put(6, 192, &[9, 9]);
    blobs.put_u32(6, 64, 2);
    h.before_response(&submit_ctx(2, destroy_payload(1)), &blobs, &mut |_| {});
    blobs.put(5, 192, &[1, 2, 3]);
    blobs.put_u32(5, 64, 3);
    assert_eq!(snap(&mut h, &blobs).len(), 1);
    let p = payloads(h);
    assert_eq!(p.len(), 4);
    assert_eq!(p[2], vec![9, 9]);
    assert_eq!(p[3], vec![1, 2, 3]);
}

#[test]
fn gpu6_1884_destroy_then_blob_release_keeps_final_snapshot() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    create(&mut h, 1, std_spec(), &[MON]);
    blobs.put(5, 192, &[7, 8]);
    blobs.put_u32(5, 64, 2);
    // 応答の公開前に最終読み取りを済ませてから blob が解放される（Destroy → UNMAP → UNREF の並び）。
    h.before_response(&submit(destroy_payload(1)), &blobs, &mut |_| {});
    blobs.blobs.remove(&5);
    let mut out = Vec::new();
    h.snapshot_all(&blobs, &mut |l| out.push(l.to_string()));
    assert!(out.is_empty(), "{out:?}");
    let p = payloads(h);
    assert_eq!(p.last().unwrap(), &vec![7, 8]);
}

/// GPU-6・REPAIR-12（#1884）: `DestroyRingMESA` なしの `CTX_DESTROY` でその ctx のリングを解放し、同じ ID を再登録でき、
/// 古い登録が溜まって `table_full` にならない。
#[test]
fn gpu6_1884_ctx_destroy_without_destroy_ring_releases_rings() {
    let mut blobs = FakeBlobs::with(5, 256);
    let mut h = hooks();
    let mut out = Vec::new();
    h.on_submit(
        &submit_ctx(1, create_payload(1, std_spec(), &[MON])),
        &mut |l| out.push(l.to_string()),
    );
    blobs.put(5, 192, &[4, 5]);
    blobs.put_u32(5, 64, 2);
    // 他 ctx の破棄は影響しない。
    h.release_context(2, &blobs, &mut |_| {});
    h.release_context(1, &blobs, &mut |_| {});
    // 最終読み取りは済み、表は空。
    assert!(snap(&mut h, &blobs).is_empty());
    // 同じ ctx_id・ring_id を再登録できる。
    for _ in 0..(MAX_RINGS * 2) {
        h.on_submit(
            &submit_ctx(1, create_payload(1, std_spec(), &[MON])),
            &mut |l| out.push(l.to_string()),
        );
        h.release_context(1, &blobs, &mut |_| {});
    }
    assert!(
        out.iter()
            .all(|l| !l.contains("duplicate_ring") && !l.contains("table_full")),
        "{out:?}"
    );
    // ID を変えて ctx を作っては破棄しても table_full に達しない。
    for ctx in 10..(10 + 2 * MAX_RINGS as u32) {
        h.on_submit(
            &submit_ctx(ctx, create_payload(ctx as u64, std_spec(), &[MON])),
            &mut |l| out.push(l.to_string()),
        );
        h.release_context(ctx, &blobs, &mut |_| {});
    }
    assert!(out.iter().all(|l| !l.contains("table_full")), "{out:?}");
    let p = payloads(h);
    assert!(p.iter().any(|x| x == &vec![4, 5]));
}
