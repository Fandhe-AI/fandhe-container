//! `support/bzimage.rs`（合成 bzImage の正本）の単体試験。3 OS の既定集合で走る（REPAIR-12・MVM-1・#3750）。
//!
//! 実機前提試験（`kvm_device`・`microvm`・plugin-microvm の `e2e`）が共有する入力の各フィールドを、
//! 補助の定数を使い回さない独立したリテラルで照合し、本物のパーサ `SetupHeader::parse` とも往復させる。

#[path = "support/bzimage.rs"]
mod bzimage;

use bzimage::{
    ENTRY_64_OFFSET, EXPECTED_ENTRY, HEADER_MAGIC, IMAGE_LEN, PAYLOAD_LEN, PAYLOAD_OFFSET,
    fill_payload, header_only, put_entry_code, synthetic_bzimage,
};

fn u16_at(img: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(img[off..off + 2].try_into().unwrap())
}
fn u32_at(img: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(img[off..off + 4].try_into().unwrap())
}
fn u64_at(img: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(img[off..off + 8].try_into().unwrap())
}

/// ヘッダが書くバイト範囲（オフセット, 長さ）。「余計な書き込みが無い」照合に使う。
const FIELD_RANGES: [(usize, usize); 13] = [
    (0x1F1, 1),
    (0x1FE, 2),
    (0x201, 1),
    (0x202, 4),
    (0x206, 2),
    (0x211, 1),
    (0x22C, 4),
    (0x230, 4),
    (0x234, 1),
    (0x236, 2),
    (0x238, 4),
    (0x258, 8),
    (0x260, 4),
];

/// REPAIR-12: ヘッダの 13 フィールドが boot protocol の値になっている。
#[test]
fn bzimage_header_fields_have_boot_protocol_values() {
    let img = header_only();
    assert_eq!(img.len(), 0x1A00);
    assert_eq!(img[0x1F1], 4);
    assert_eq!(u16_at(&img, 0x1FE), 0xAA55);
    assert_eq!(img[0x201], 0x62);
    assert_eq!(&img[0x202..0x206], &[0x48, 0x64, 0x72, 0x53]);
    assert_eq!(u16_at(&img, 0x206), 0x020F);
    assert_eq!(img[0x211], 1);
    assert_eq!(u32_at(&img, 0x22C), 0x03FF_FFFF);
    assert_eq!(u32_at(&img, 0x230), 0x0020_0000);
    assert_eq!(img[0x234], 1);
    assert_eq!(u16_at(&img, 0x236), 1);
    assert_eq!(u32_at(&img, 0x238), 2047);
    assert_eq!(u64_at(&img, 0x258), 0x0100_0000);
    assert_eq!(u32_at(&img, 0x260), 0x0040_0000);
}

/// REPAIR-12: ヘッダ以外のバイトはゼロのまま。
#[test]
fn bzimage_header_only_leaves_other_bytes_zero() {
    let img = header_only();
    for (i, b) in img.iter().enumerate() {
        let in_field = FIELD_RANGES
            .iter()
            .any(|&(off, len)| i >= off && i < off + len);
        if !in_field {
            assert_eq!(*b, 0, "byte at {i:#x} must stay zero");
        }
    }
}

/// REPAIR-12: レイアウト定数の期待値。
#[test]
fn bzimage_constants_match_layout() {
    assert_eq!(PAYLOAD_OFFSET, 0xA00);
    assert_eq!(PAYLOAD_LEN, 0x1000);
    assert_eq!(IMAGE_LEN, 0x1A00);
    assert_eq!(ENTRY_64_OFFSET, 0x200);
    assert_eq!(EXPECTED_ENTRY, 0x100_0200);
    assert_eq!(HEADER_MAGIC, [0x48, 0x64, 0x72, 0x53]);
}

/// MVM-1: 本物の `SetupHeader::parse` が合成イメージを解釈し、ローダとのずれがない。
#[test]
fn bzimage_parses_with_setup_header_parser() {
    use fandhe_container_microvm::boot_x86::SetupHeader;

    let img = synthetic_bzimage(&[]);
    let h = SetupHeader::parse(&img).expect("synthetic bzImage must parse");
    assert_eq!(h.version, 0x020F);
    assert_eq!(h.payload_offset, 0xA00);
    assert_eq!(h.initrd_addr_max, 0x3FF_FFFF);
    assert_eq!(h.kernel_alignment, 0x20_0000);
    assert!(h.relocatable);
    assert_eq!(h.cmdline_size, 2047);
    assert_eq!(h.pref_address, 0x100_0000);
    assert_eq!(h.init_size, 0x40_0000);
    assert_eq!(EXPECTED_ENTRY, h.pref_address + ENTRY_64_OFFSET as u64);
}

/// エントリのコードが payload + 0x200 に置かれ、残りが ud2 の交互になる。
#[test]
fn bzimage_synthetic_places_entry_code_and_fills_ud2() {
    let code = [0xB0, 0x41, 0xE6];
    let img = synthetic_bzimage(&code);
    assert_eq!(img[..PAYLOAD_OFFSET], header_only()[..PAYLOAD_OFFSET]);
    let entry = PAYLOAD_OFFSET + 0x200;
    assert_eq!(&img[entry..entry + 3], &code);
    for i in 0..PAYLOAD_LEN {
        if (0x200..0x203).contains(&i) {
            continue;
        }
        let want = if i % 2 == 0 { 0x0F } else { 0x0B };
        assert_eq!(img[PAYLOAD_OFFSET + i], want, "payload byte {i:#x}");
    }
}

/// 空のエントリなら payload 全体が ud2 の交互。
#[test]
fn bzimage_synthetic_empty_entry_is_all_ud2() {
    let img = synthetic_bzimage(&[]);
    for i in 0..PAYLOAD_LEN {
        let want = if i % 2 == 0 { 0x0F } else { 0x0B };
        assert_eq!(img[PAYLOAD_OFFSET + i], want, "payload byte {i:#x}");
    }
}

/// `fill_payload` の添字は payload 先頭が 0 で、ヘッダ部は変わらない。
#[test]
fn bzimage_fill_payload_uses_index_from_payload_start() {
    let mut img = header_only();
    fill_payload(&mut img, |i| (i % 251) as u8 | 1);
    assert_eq!(img[0xA00], 1);
    assert_eq!(img[0xA00 + 250], 251);
    assert_eq!(img[0xA00 + 251], 1);
    assert_eq!(img[..PAYLOAD_OFFSET], header_only()[..PAYLOAD_OFFSET]);
}

/// payload に収まらないエントリコードは黙って切り詰めず panic する。
#[test]
#[should_panic(expected = "entry code must fit in the synthetic payload")]
fn bzimage_put_entry_code_rejects_overflow() {
    let mut img = header_only();
    put_entry_code(&mut img, &vec![0u8; PAYLOAD_LEN - ENTRY_64_OFFSET + 1]);
}
