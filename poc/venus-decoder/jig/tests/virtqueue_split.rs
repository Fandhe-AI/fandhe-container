//! split virtqueue の結合試験（GPU-6・REPAIR-12・TASK-172 F1.3・#1518）。
//!
//! 公開 API だけで、合成メモリ上の単一記述子・連結チェーンの走査と used への書き戻し（全 OS）、
//! 実際の memfd 上の `GuestMemory` を経由した往復（Linux の x86_64 / aarch64 のみ）を具体値で照合する。
//! 拒否系の網羅はユニットテスト（`src/virtqueue/tests.rs`）が担当する。

use std::cell::RefCell;

use fandhe_container_poc_venus_jig::vhost_user::VringAddr;
use fandhe_container_poc_venus_jig::virtqueue::{
    QueueConfig, QueueMemory, SplitQueue, VirtqueueError, VirtqueueErrorCode, translate_uva_in,
};

const GPA: u64 = 0x4000_0000;
const UVA: u64 = 0x7f10_0000_0000;
const SIZE: usize = 0x8000;

struct Fake(RefCell<Vec<u8>>);

impl QueueMemory for Fake {
    fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), VirtqueueError> {
        let s = (gpa - GPA) as usize;
        let b = self.0.borrow();
        let src = b
            .get(s..s + dst.len())
            .ok_or(VirtqueueError::new(VirtqueueErrorCode::GuestMemory))?;
        dst.copy_from_slice(src);
        Ok(())
    }
    fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), VirtqueueError> {
        let s = (gpa - GPA) as usize;
        let mut b = self.0.borrow_mut();
        let dst = b
            .get_mut(s..s + src.len())
            .ok_or(VirtqueueError::new(VirtqueueErrorCode::GuestMemory))?;
        dst.copy_from_slice(src);
        Ok(())
    }
    fn translate_uva(&self, uva: u64, len: u64) -> Result<u64, VirtqueueError> {
        translate_uva_in([(UVA, GPA, SIZE as u64)], uva, len)
    }
}

fn vring() -> VringAddr {
    VringAddr {
        index: 0,
        flags: 0,
        descriptor: UVA,
        available: UVA + 0x1000,
        used: UVA + 0x2000,
        log: 0,
    }
}

/// desc[i] を書く。
fn put_desc(mem: &impl QueueMemory, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
    let mut d = Vec::new();
    d.extend_from_slice(&addr.to_le_bytes());
    d.extend_from_slice(&len.to_le_bytes());
    d.extend_from_slice(&flags.to_le_bytes());
    d.extend_from_slice(&next.to_le_bytes());
    mem.write_at(GPA + 16 * i, &d).expect("desc");
}

/// 2 本の要求（単一記述子と 2 連結）を処理して used を具体値で照合する。
fn run(mem: &impl QueueMemory) {
    let data = GPA + 0x4000;
    put_desc(mem, 3, data, 24, 0, 0);
    put_desc(mem, 0, data + 0x100, 24, 1, 5);
    put_desc(mem, 5, data + 0x200, 408, 2, 0);
    mem.write_at(GPA + 0x1000 + 4, &[3, 0, 0, 0]).expect("ring");
    mem.write_at(GPA + 0x1000 + 2, &[2, 0]).expect("idx");
    let cfg = QueueConfig::new(8, &vring(), mem).expect("config");
    let mut q = SplitQueue::new(cfg, 0, 0);

    let first = q.pop(mem).expect("pop").expect("first");
    assert_eq!(
        (first.head(), first.readable_len(), first.writable_len()),
        (3, 24, 0)
    );
    q.add_used(mem, first, 0).expect("used 1");

    let second = q.pop(mem).expect("pop").expect("second");
    assert_eq!(
        (second.head(), second.readable_len(), second.writable_len()),
        (0, 24, 408)
    );
    let n = second.write_writable(mem, &[0x77; 408]).expect("resp");
    q.add_used(mem, second, n).expect("used 2");

    assert!(q.pop(mem).expect("pop").is_none());
    let mut used = [0u8; 20];
    mem.read_at(GPA + 0x2000, &mut used).expect("used");
    // flags=0, idx=2, ring[0]={3,0}, ring[1]={0,408}。
    assert_eq!(
        used,
        [
            0, 0, 2, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x98, 0x01, 0, 0
        ]
    );
    let mut resp = [0u8; 4];
    mem.read_at(data + 0x200, &mut resp).expect("resp");
    assert_eq!(resp, [0x77; 4]);
}

#[test]
fn gpu6_split_queue_on_synthetic_memory() {
    run(&Fake(RefCell::new(vec![0; SIZE])));
}

#[test]
fn gpu6_split_queue_rejects_loop_and_indirect_without_advancing() {
    let mem = Fake(RefCell::new(vec![0; SIZE]));
    put_desc(&mem, 1, GPA, 4, 1, 2);
    put_desc(&mem, 2, GPA, 4, 1, 1);
    mem.write_at(GPA + 0x1000 + 4, &[1, 0]).expect("ring");
    mem.write_at(GPA + 0x1000 + 2, &[1, 0]).expect("idx");
    let cfg = QueueConfig::new(8, &vring(), &mem).expect("config");
    let mut q = SplitQueue::new(cfg, 0, 0);
    assert_eq!(q.pop(&mem).expect_err("loop").code.as_str(), "CHAIN_LOOP");
    put_desc(&mem, 1, GPA, 4, 4, 0);
    assert_eq!(
        q.pop(&mem).expect_err("indirect").code.as_str(),
        "INDIRECT_UNSUPPORTED"
    );
    assert_eq!((q.last_avail(), q.used_idx()), (0, 0));
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_split_queue_guest_memory_is_linux_only() {
    eprintln!("skip: GuestMemory (memfd + mmap) is Linux x86_64 / aarch64 only");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::ffi::CString;
    use std::os::fd::OwnedFd;

    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::create_memfd;
    use fandhe_container_poc_venus_jig::vhost_user::guest_memory::GuestMemory;
    use fandhe_container_poc_venus_jig::vhost_user::{MemRegion, MemTable};

    use super::*;

    /// 実際の memfd を `GuestMemory` で map し、user アドレスの変換と読み書きの往復を通す。
    #[test]
    fn gpu6_split_queue_on_guest_memory() {
        let name = CString::new(format!("jig-vq-{}", std::process::id())).expect("name");
        let f = create_memfd(&name, SIZE as u64).expect("memfd");
        let table = MemTable::new(&[MemRegion {
            guest_phys_addr: GPA,
            memory_size: SIZE as u64,
            userspace_addr: UVA,
            mmap_offset: 0,
        }])
        .expect("table");
        let mem = GuestMemory::from_table(&table, vec![OwnedFd::from(f)]).expect("map");
        run(&mem);
        // 領域外のリングは変換で拒否される。
        let mut v = vring();
        v.used = UVA + SIZE as u64;
        assert_eq!(
            QueueConfig::new(8, &v, &mem)
                .expect_err("oob")
                .code
                .as_str(),
            "RING_OUT_OF_REGION"
        );
    }
}
