//! `BlobMemTable` の `BlobRead` 実装の境界の単体試験（GPU-6・REPAIR-12・TASK-172・#4644）。
//!
//! `ring_record` が `&dyn BlobRead` 経由で呼ぶ口（head / tail / リング本体の読み取り）を、memfd を実際に作って
//! 範囲外・長さ 0・オーバーフロー・検査順について具体値で固定する。結合の通し確認は `tests/ring_record.rs`。
//!
//! memfd の名前は `map_blob_tests` の fd 数の照合（`venus-jig-blob` を数える）と干渉しないよう別名にする。
//!
//! 対象外（REPAIR-3）: `BlobReadError::ReadFailed` は、範囲検査が先に効き memfd の実長を超える読みは
//! `OutOfRange` になるため、この口からは到達できない。`ring_record` 側の写像は `ring_record/tests.rs` の偽 `BlobRead` で照合済み。

use super::*;
use crate::vhost_user::backend_req::ShmemMapping;
use crate::vhost_user::fd_passing::create_memfd;
use crate::vhost_user::{ShmemConfig, ShmemRegion};
use std::os::unix::fs::FileExt;

fn pat(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ seed).collect()
}

/// memfd 実長 `memfd_len`・map 長 `map_len` の blob。memfd の中身は `pat(seed, memfd_len)`。
fn blob(res_id: u32, memfd_len: u64, map_len: u64, mapped: bool, seed: u8) -> BlobMem {
    let memfd = create_memfd(c"venus-jig-ring-read-test", memfd_len).expect("memfd");
    memfd
        .write_all_at(&pat(seed, memfd_len as usize), 0)
        .expect("fill memfd");
    let cfg = ShmemConfig::new(&[ShmemRegion {
        id: 1,
        size: 1 << 20,
    }])
    .expect("config");
    let mapping = ShmemMapping::new(&cfg, 1, 0, map_len).expect("mapping");
    BlobMem {
        res_id,
        memfd,
        mapping,
        mapped,
    }
}

fn table(blobs: Vec<BlobMem>) -> BlobMemTable {
    let mut t = BlobMemTable::default();
    for b in blobs {
        assert!(t.insert(b).is_ok(), "slot");
    }
    t
}

fn one(memfd_len: u64, map_len: u64) -> BlobMemTable {
    table(vec![blob(7, memfd_len, map_len, true, 0x5a)])
}

#[test]
fn gpu6_4644_blob_len_follows_the_smaller_of_map_and_memfd() {
    assert_eq!(one(4096, 4096).blob_len(7), Some(4096));
    assert_eq!(one(6000, 4096).blob_len(7), Some(4096));
    assert_eq!(one(3000, 4096).blob_len(7), Some(3000));
    assert_eq!(one(4096, 4096).blob_len(99), None);
}

#[test]
fn gpu6_4644_blob_len_survives_unmap() {
    let t = table(vec![blob(7, 4096, 4096, false, 0x5a)]);
    assert_eq!(t.blob_len(7), Some(4096));
}

#[test]
fn gpu6_4644_reads_start_and_exact_end() {
    let t = one(4096, 4096);
    let want = pat(0x5a, 4096);
    let r: &dyn BlobRead = &t;
    let mut b = [0u8; 16];
    assert_eq!(r.read_exact_at(7, 0, &mut b), Ok(()));
    assert_eq!(&b[..], &want[0..16]);
    let mut e = [0u8; 4];
    assert_eq!(r.read_exact_at(7, 4092, &mut e), Ok(()));
    assert_eq!(&e[..], &want[4092..4096]);
}

#[test]
fn gpu6_4644_one_byte_past_end_is_out_of_range_and_buf_untouched() {
    let t = one(4096, 4096);
    let mut b = [0xAAu8; 4];
    assert_eq!(
        t.read_exact_at(7, 4093, &mut b),
        Err(BlobReadError::OutOfRange)
    );
    assert_eq!(b, [0xAA; 4]);
    let mut one_b = [0xAAu8; 1];
    assert_eq!(
        t.read_exact_at(7, 4096, &mut one_b),
        Err(BlobReadError::OutOfRange)
    );
    assert_eq!(one_b, [0xAA]);
}

#[test]
fn gpu6_4644_zero_length_boundaries() {
    let t = one(4096, 4096);
    let mut z: [u8; 0] = [];
    assert_eq!(t.read_exact_at(7, 0, &mut z), Ok(()));
    assert_eq!(t.read_exact_at(7, 4096, &mut z), Ok(()));
    assert_eq!(
        t.read_exact_at(7, 4097, &mut z),
        Err(BlobReadError::OutOfRange)
    );
    assert_eq!(
        t.read_exact_at(7, u64::MAX, &mut z),
        Err(BlobReadError::OutOfRange)
    );
}

#[test]
fn gpu6_4644_offset_overflow_is_out_of_range() {
    let t = one(4096, 4096);
    let mut one_b = [0xAAu8; 1];
    assert_eq!(
        t.read_exact_at(7, u64::MAX, &mut one_b),
        Err(BlobReadError::OutOfRange)
    );
    let mut two = [0xAAu8; 2];
    assert_eq!(
        t.read_exact_at(7, u64::MAX - 1, &mut two),
        Err(BlobReadError::OutOfRange)
    );
    assert_eq!(two, [0xAA; 2]);
}

#[test]
fn gpu6_4644_not_held_is_checked_before_range() {
    let t = one(4096, 4096);
    let mut one_b = [0u8; 1];
    assert_eq!(
        t.read_exact_at(99, u64::MAX, &mut one_b),
        Err(BlobReadError::NotHeld)
    );
    let mut z: [u8; 0] = [];
    assert_eq!(t.read_exact_at(99, 0, &mut z), Err(BlobReadError::NotHeld));
}

#[test]
fn gpu6_4644_map_len_caps_memfd_with_more_data() {
    let t = one(6000, 4096);
    let mut b = [0xAAu8; 1];
    assert_eq!(
        t.read_exact_at(7, 4096, &mut b),
        Err(BlobReadError::OutOfRange)
    );
    assert_eq!(b, [0xAA]);
}

#[test]
fn gpu6_4644_memfd_len_caps_larger_map() {
    let t = one(3000, 4096);
    let want = pat(0x5a, 3000);
    let mut b = [0u8; 1];
    assert_eq!(t.read_exact_at(7, 2999, &mut b), Ok(()));
    assert_eq!(b[0], want[2999]);
    assert_eq!(
        t.read_exact_at(7, 3000, &mut b),
        Err(BlobReadError::OutOfRange)
    );
}

#[test]
fn gpu6_4644_slots_are_looked_up_by_res_id() {
    let t = table(vec![
        blob(7, 4096, 4096, true, 0x11),
        blob(9, 4096, 4096, true, 0x77),
    ]);
    let mut b = [0u8; 8];
    assert_eq!(t.read_exact_at(9, 0, &mut b), Ok(()));
    assert_eq!(&b[..], &pat(0x77, 8)[..]);
    assert_eq!(t.read_exact_at(7, 0, &mut b), Ok(()));
    assert_eq!(&b[..], &pat(0x11, 8)[..]);
}
