//! split virtqueue のユニットテスト（GPU-6・REPAIR-12・TASK-172 F1.3・#1518）。
//!
//! 合成メモリ上に desc / avail / used を手で配置する。全 OS で動く（`GuestMemory` に依存しない）。期待値は具体値で書く。

use std::cell::RefCell;

use super::*;

const GPA_BASE: u64 = 0x1000_0000;
const UVA_BASE: u64 = 0x7f00_0000_0000;
const MEM_SIZE: usize = 0x10000;
const DESC_OFF: u64 = 0x0;
const AVAIL_OFF: u64 = 0x1000;
const USED_OFF: u64 = 0x2000;
const DATA_OFF: u64 = 0x4000;

/// 1 領域だけの合成メモリ。GPA と user アドレスの基点は別の値にして変換も照合する。
struct FakeMemory {
    bytes: RefCell<Vec<u8>>,
}

impl FakeMemory {
    fn new() -> Self {
        Self {
            bytes: RefCell::new(vec![0; MEM_SIZE]),
        }
    }

    fn range(gpa: u64, len: usize) -> Result<std::ops::Range<usize>, VirtqueueError> {
        let start = gpa
            .checked_sub(GPA_BASE)
            .ok_or_else(|| err(VirtqueueErrorCode::GuestMemory))? as usize;
        let end = start
            .checked_add(len)
            .filter(|e| *e <= MEM_SIZE)
            .ok_or_else(|| err(VirtqueueErrorCode::GuestMemory))?;
        Ok(start..end)
    }

    fn put(&self, off: u64, data: &[u8]) {
        self.write_at(GPA_BASE + off, data).expect("put");
    }

    fn get(&self, off: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        self.read_at(GPA_BASE + off, &mut v).expect("get");
        v
    }

    /// 記述子 `i` を書く。
    fn desc(&self, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
        let mut d = Vec::new();
        d.extend_from_slice(&addr.to_le_bytes());
        d.extend_from_slice(&len.to_le_bytes());
        d.extend_from_slice(&flags.to_le_bytes());
        d.extend_from_slice(&next.to_le_bytes());
        self.put(DESC_OFF + 16 * i, &d);
    }

    /// avail に head を積み、idx を `idx` にする。
    fn avail(&self, idx: u16, heads: &[u16]) {
        self.put(AVAIL_OFF + 2, &idx.to_le_bytes());
        for (i, h) in heads.iter().enumerate() {
            self.put(AVAIL_OFF + 4 + 2 * i as u64, &h.to_le_bytes());
        }
    }
}

impl QueueMemory for FakeMemory {
    fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), VirtqueueError> {
        let r = Self::range(gpa, dst.len())?;
        dst.copy_from_slice(&self.bytes.borrow()[r]);
        Ok(())
    }

    fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), VirtqueueError> {
        let r = Self::range(gpa, src.len())?;
        self.bytes.borrow_mut()[r].copy_from_slice(src);
        Ok(())
    }

    fn translate_uva(&self, uva: u64, len: u64) -> Result<u64, VirtqueueError> {
        translate_uva_in([(UVA_BASE, GPA_BASE, MEM_SIZE as u64)], uva, len)
    }
}

fn vring(flags: u32) -> VringAddr {
    VringAddr {
        index: 0,
        flags,
        descriptor: UVA_BASE + DESC_OFF,
        used: UVA_BASE + USED_OFF,
        available: UVA_BASE + AVAIL_OFF,
        log: 0,
    }
}

fn queue(mem: &FakeMemory, num: u32, last_avail: u16, used_idx: u16) -> SplitQueue {
    let cfg = QueueConfig::new(num, &vring(0), mem).expect("config");
    SplitQueue::new(cfg, last_avail, used_idx)
}

fn code<T: std::fmt::Debug>(r: Result<T, VirtqueueError>) -> &'static str {
    r.expect_err("must be rejected").code.as_str()
}

const D: u64 = GPA_BASE + DATA_OFF;

/// GPU-6・REPAIR-12: 単一の記述子の走査と used への書き戻し。
#[test]
fn gpu6_single_descriptor_pop_and_used() {
    let mem = FakeMemory::new();
    mem.desc(3, D, 24, 0, 0);
    mem.avail(1, &[3]);
    let mut q = queue(&mem, 8, 0, 0);
    let chain = q.pop(&mem).expect("pop").expect("some");
    assert_eq!(chain.head(), 3);
    assert_eq!(chain.readable(), &[(D, 24)]);
    assert!(chain.writable().is_empty());
    assert_eq!(q.last_avail(), 1);
    q.add_used(&mem, chain, 0).expect("used");
    // used.ring[0] = {id=3, len=0}、used.idx = 1。
    assert_eq!(mem.get(USED_OFF + 4, 8), [3, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(mem.get(USED_OFF + 2, 2), [1, 0]);
    assert_eq!(q.used_idx(), 1);
    assert_eq!(q.pop(&mem).expect("pop"), None);
}

/// GPU-6・REPAIR-12: 連結チェーン 0 -> 5 -> 2（readable 24 + writable 408）と応答の書き込み。
#[test]
fn gpu6_chained_descriptors_roundtrip() {
    let mem = FakeMemory::new();
    mem.put(DATA_OFF, &[0xAB; 24]);
    mem.desc(0, D, 24, DESC_F_NEXT, 5);
    mem.desc(5, D + 0x100, 400, DESC_F_NEXT | DESC_F_WRITE, 2);
    mem.desc(2, D + 0x300, 8, DESC_F_WRITE, 0);
    mem.avail(1, &[0]);
    let mut q = queue(&mem, 8, 0, 0);
    let chain = q.pop(&mem).expect("pop").expect("some");
    assert_eq!(chain.head(), 0);
    assert_eq!(chain.readable(), &[(D, 24)]);
    assert_eq!(chain.writable(), &[(D + 0x100, 400), (D + 0x300, 8)]);
    assert_eq!((chain.readable_len(), chain.writable_len()), (24, 408));
    let mut req = [0u8; 64];
    assert_eq!(chain.read_readable(&mem, &mut req).expect("read"), 24);
    assert_eq!(&req[..24], &[0xAB; 24]);
    let resp = [0x5A; 408];
    assert_eq!(chain.write_writable(&mem, &resp).expect("write"), 408);
    assert_eq!(mem.get(DATA_OFF + 0x100, 400), vec![0x5A; 400]);
    assert_eq!(mem.get(DATA_OFF + 0x300, 8), vec![0x5A; 8]);
    q.add_used(&mem, chain, 408).expect("used");
    assert_eq!(mem.get(USED_OFF + 4, 8), [0, 0, 0, 0, 0x98, 0x01, 0, 0]);
    assert_eq!(mem.get(USED_OFF + 2, 2), [1, 0]);
}

/// GPU-6・REPAIR-12: 2 件の要求、3 回目は None。idx は u16 の境界を wrapping で跨ぐ。
#[test]
fn gpu6_multiple_requests_and_index_wrap() {
    let mem = FakeMemory::new();
    mem.desc(1, D, 4, 0, 0);
    mem.desc(2, D + 0x10, 4, 0, 0);
    // last_avail = 65534 は ring[65534 % 8 = 6]、次は ring[7]。avail.idx = 0 (= 65536) で差は 2。
    mem.put(AVAIL_OFF + 4 + 2 * 6, &1u16.to_le_bytes());
    mem.put(AVAIL_OFF + 4 + 2 * 7, &2u16.to_le_bytes());
    mem.put(AVAIL_OFF + 2, &0u16.to_le_bytes());
    let mut q = queue(&mem, 8, u16::MAX - 1, u16::MAX - 1);
    let a = q.pop(&mem).expect("pop").expect("first");
    let b = q.pop(&mem).expect("pop").expect("second");
    assert_eq!((a.head(), b.head()), (1, 2));
    assert_eq!(q.last_avail(), 0);
    assert_eq!(q.pop(&mem).expect("pop"), None);
    q.add_used(&mem, a, 0).expect("used a");
    q.add_used(&mem, b, 0).expect("used b");
    // used_idx 65534 -> slot 6、65535 -> slot 7、idx は 0 に戻る。
    assert_eq!(mem.get(USED_OFF + 4 + 8 * 6, 4), [1, 0, 0, 0]);
    assert_eq!(mem.get(USED_OFF + 4 + 8 * 7, 4), [2, 0, 0, 0]);
    assert_eq!(mem.get(USED_OFF + 2, 2), [0, 0]);
    assert_eq!(q.used_idx(), 0);
}

/// GPU-6・REPAIR-12: 拒否した pop は last_avail と used.idx を動かさない。
fn assert_rejected(mem: &FakeMemory, num: u32, want: &str) {
    let mut q = queue(mem, num, 0, 0);
    assert_eq!(code(q.pop(mem)), want);
    assert_eq!(q.last_avail(), 0);
    assert_eq!(q.used_idx(), 0);
    assert_eq!(mem.get(USED_OFF + 2, 2), [0, 0]);
}

#[test]
fn gpu6_loop_is_rejected() {
    let mem = FakeMemory::new();
    mem.desc(2, D, 4, DESC_F_NEXT, 5);
    mem.desc(5, D, 4, DESC_F_NEXT, 2);
    mem.avail(1, &[2]);
    assert_rejected(&mem, 8, "CHAIN_LOOP");
}

#[test]
fn gpu6_out_of_range_indexes_are_rejected() {
    let mem = FakeMemory::new();
    mem.avail(1, &[8]);
    assert_rejected(&mem, 8, "DESC_INDEX_OUT_OF_RANGE");
    mem.desc(1, D, 4, DESC_F_NEXT, 9);
    mem.avail(1, &[1]);
    assert_rejected(&mem, 8, "DESC_INDEX_OUT_OF_RANGE");
}

#[test]
fn gpu6_chain_length_limit_boundary() {
    let mem = FakeMemory::new();
    // num=128 で上限ちょうど（MAX_CHAIN_LEN 個）の線形チェーンは通る。
    let build = |len: usize| {
        for i in 0..len {
            let last = i + 1 == len;
            let flags = if last { 0 } else { DESC_F_NEXT };
            mem.desc(i as u64, D, 1, flags, (i + 1) as u16);
        }
        mem.avail(1, &[0]);
    };
    build(MAX_CHAIN_LEN);
    let mut q = queue(&mem, 128, 0, 0);
    let chain = q.pop(&mem).expect("pop").expect("some");
    assert_eq!(chain.readable().len(), MAX_CHAIN_LEN);
    build(MAX_CHAIN_LEN + 1);
    assert_rejected(&mem, 128, "CHAIN_TOO_LONG");
}

#[test]
fn gpu6_indirect_and_unknown_flags_are_rejected() {
    let mem = FakeMemory::new();
    mem.desc(0, D, 4, DESC_F_INDIRECT, 0);
    mem.avail(1, &[0]);
    assert_rejected(&mem, 8, "INDIRECT_UNSUPPORTED");
    mem.desc(0, D, 4, 0x8, 0);
    assert_rejected(&mem, 8, "INVALID_DESC_FLAGS");
}

#[test]
fn gpu6_readable_after_writable_is_rejected() {
    let mem = FakeMemory::new();
    mem.desc(0, D, 4, DESC_F_NEXT | DESC_F_WRITE, 1);
    mem.desc(1, D, 4, 0, 0);
    mem.avail(1, &[0]);
    assert_rejected(&mem, 8, "READABLE_AFTER_WRITABLE");
}

#[test]
fn gpu6_chain_bytes_and_address_overflow_are_rejected() {
    let mem = FakeMemory::new();
    mem.desc(0, D, u32::MAX, DESC_F_NEXT, 1);
    mem.desc(1, D, u32::MAX, 0, 0);
    mem.avail(1, &[0]);
    assert_rejected(&mem, 8, "CHAIN_TOO_LARGE");
    // 1 MiB ちょうどは通り、1 バイト超は拒否する。
    mem.desc(0, D, MAX_CHAIN_BYTES as u32 + 1, 0, 0);
    assert_rejected(&mem, 8, "CHAIN_TOO_LARGE");
    mem.desc(0, D, MAX_CHAIN_BYTES as u32, 0, 0);
    assert!(queue(&mem, 8, 0, 0).pop(&mem).expect("pop").is_some());
    // addr + len が u64 を溢れる。
    mem.desc(0, u64::MAX, 2, 0, 0);
    assert_rejected(&mem, 8, "GUEST_MEMORY");
}

#[test]
fn gpu6_avail_idx_too_far_ahead_is_rejected() {
    let mem = FakeMemory::new();
    mem.avail(9, &[]);
    assert_rejected(&mem, 8, "INVALID_AVAIL_IDX");
    // 差がちょうど num なら通る（全 slot が積まれた状態）。
    mem.desc(0, D, 1, 0, 0);
    mem.avail(8, &[0; 8]);
    assert!(queue(&mem, 8, 0, 0).pop(&mem).expect("pop").is_some());
}

#[test]
fn gpu6_config_rejects_bad_values() {
    let mem = FakeMemory::new();
    for n in [0u32, 6, 65536] {
        assert_eq!(
            code(QueueConfig::new(n, &vring(0), &mem)),
            "INVALID_QUEUE_SIZE"
        );
    }
    assert_eq!(
        code(QueueConfig::new(8, &vring(1), &mem)),
        "LOG_NOT_SUPPORTED"
    );
    for (field, want) in [("d", 8u64), ("a", 1), ("u", 2)] {
        let mut v = vring(0);
        match field {
            "d" => v.descriptor += want,
            "a" => v.available += want,
            _ => v.used += want,
        }
        assert_eq!(code(QueueConfig::new(8, &v, &mem)), "MISALIGNED_RING");
    }
    // 2 バイトずれた used は 4 バイトアラインメント違反、avail は 2 バイトずれなら通る。
    let mut v = vring(0);
    v.available += 2;
    assert!(QueueConfig::new(8, &v, &mem).is_ok());
    // リングが領域からはみ出す・uva が未登録。
    let mut v = vring(0);
    v.used = UVA_BASE + MEM_SIZE as u64 - 16;
    assert_eq!(code(QueueConfig::new(8, &v, &mem)), "RING_OUT_OF_REGION");
    let mut v = vring(0);
    v.descriptor = 0x1000;
    assert_eq!(code(QueueConfig::new(8, &v, &mem)), "RING_OUT_OF_REGION");
}

#[test]
fn gpu6_used_len_over_capacity_is_rejected() {
    let mem = FakeMemory::new();
    mem.desc(0, D, 4, DESC_F_WRITE, 0);
    mem.avail(1, &[0]);
    let mut q = queue(&mem, 8, 0, 0);
    let chain = q.pop(&mem).expect("pop").expect("some");
    assert_eq!(
        code(q.add_used(&mem, chain.clone(), 5)),
        "USED_LEN_EXCEEDS_WRITABLE"
    );
    assert_eq!(q.used_idx(), 0);
    assert_eq!(
        code(chain.write_writable(&mem, &[0; 5])),
        "USED_LEN_EXCEEDS_WRITABLE"
    );
    q.add_used(&mem, chain, 4).expect("used");
}

/// 記述子は 1 回だけコピーして解析する（二度読みしない）。読み出し回数を数えて照合する。
#[test]
fn gpu6_descriptor_is_read_once() {
    struct Counting(FakeMemory, RefCell<Vec<u64>>);
    impl QueueMemory for Counting {
        fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), VirtqueueError> {
            self.1.borrow_mut().push(gpa);
            self.0.read_at(gpa, dst)
        }
        fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), VirtqueueError> {
            self.0.write_at(gpa, src)
        }
        fn translate_uva(&self, uva: u64, len: u64) -> Result<u64, VirtqueueError> {
            self.0.translate_uva(uva, len)
        }
    }
    let mem = Counting(FakeMemory::new(), RefCell::new(Vec::new()));
    mem.0.desc(1, D, 4, DESC_F_NEXT, 2);
    mem.0.desc(2, D, 4, 0, 0);
    mem.0.avail(1, &[1]);
    let cfg = QueueConfig::new(8, &vring(0), &mem).expect("config");
    let mut q = SplitQueue::new(cfg, 0, 0);
    q.pop(&mem).expect("pop").expect("some");
    let reads = mem.1.borrow().clone();
    // avail.idx、ring[0]、desc[1]、desc[2] の 4 回だけ。
    assert_eq!(
        reads,
        vec![
            GPA_BASE + AVAIL_OFF + 2,
            GPA_BASE + AVAIL_OFF + 4,
            GPA_BASE + DESC_OFF + 16,
            GPA_BASE + DESC_OFF + 32
        ]
    );
}

#[test]
fn gpu6_translate_uva_in_rejects_cross_region_and_overflow() {
    let regions = [(0x1000u64, 0x9000u64, 0x1000u64), (0x2000, 0x20000, 0x1000)];
    assert_eq!(translate_uva_in(regions, 0x1010, 0x10), Ok(0x9010));
    assert_eq!(translate_uva_in(regions, 0x2000, 0x1000), Ok(0x20000));
    // 隣接する 2 領域をまたぐ範囲は拒否する。
    assert_eq!(
        code(translate_uva_in(regions, 0x1ff0, 0x20)),
        "RING_OUT_OF_REGION"
    );
    assert_eq!(
        code(translate_uva_in(regions, u64::MAX, 2)),
        "RING_OUT_OF_REGION"
    );
}

#[test]
fn gpu6_error_display_has_no_guest_values() {
    let e = err(VirtqueueErrorCode::ChainLoop);
    assert_eq!(e.to_string(), "CHAIN_LOOP: descriptor chain has a loop");
}
