//! `FdtBuilder` の公開 API だけで DTB を組み立てる結合試験（#3784・MVM-5・MVM-1。KVM 不要・OS 非依存）。
//! モジュール内のユニットテストとは別に、crate 外から見える契約（出力バイト列・構造化エラー）を具体値で固定する。

use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::fdt::{FDT_MAGIC, FdtBuilder, MAX_FDT_BYTES};

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// MVM-5・MVM-1: 代表的な最小 DTB（根 + `#address-cells`）のバイト列と header を具体値で確認する。
#[test]
fn mvm5_3784_public_api_minimal_blob() {
    let mut b = FdtBuilder::new();
    b.begin_node("").unwrap();
    b.property_u32("#address-cells", 2).unwrap();
    b.end_node().unwrap();
    let blob = b.finish().unwrap();

    // header 40 + rsvmap 16 + struct(BEGIN 8 + PROP 16 + END_NODE 4 + END 4 = 32) + strings("#address-cells\0" = 15)
    assert_eq!(blob.len(), 40 + 16 + 32 + 15);
    assert_eq!(be32(&blob, 0), FDT_MAGIC);
    assert_eq!(be32(&blob, 4), 103);
    assert_eq!(be32(&blob, 8), 56);
    assert_eq!(be32(&blob, 12), 88);
    assert_eq!(be32(&blob, 16), 40);
    assert_eq!(be32(&blob, 20), 17);
    assert_eq!(be32(&blob, 24), 16);
    let words: Vec<u32> = (0..8).map(|i| be32(&blob, 56 + i * 4)).collect();
    assert_eq!(words, vec![1, 0, 3, 4, 0, 2, 2, 9]);
    assert_eq!(&blob[88..], b"#address-cells\0");
}

/// MVM-5・MVM-1: 不正入力は構造化エラー（`InvalidArgument`）になり、組み立て器は継続できる。
#[test]
fn mvm5_3784_public_api_invalid_input_is_structured_error() {
    let mut b = FdtBuilder::new();
    let e = b.property_u32("x", 1).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert!(!e.message().is_empty());

    assert_eq!(
        b.begin_node("root").unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
    b.begin_node("").unwrap();
    assert_eq!(
        b.begin_node("bad name").unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
    b.property_u32("a", 1).unwrap();
    assert_eq!(
        b.property_u32("a", 2).unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
    // 未閉じのノードがある finish は拒否。
    assert_eq!(
        b.finish().unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
}

/// MVM-5・MVM-1: 上限付近まで詰めても成功した分は閉じて finish でき、出力は上限以下。
#[test]
fn mvm5_3784_public_api_size_limit_keeps_finishable() {
    let mut b = FdtBuilder::new();
    b.begin_node("").unwrap();
    let mut depth = 1;
    while b.begin_node("n").is_ok() {
        depth += 1;
    }
    for _ in 0..depth {
        b.end_node().unwrap();
    }
    let blob = b.finish().unwrap();
    assert!(blob.len() <= MAX_FDT_BYTES);
    assert!(blob.len() > MAX_FDT_BYTES - 64);
}
