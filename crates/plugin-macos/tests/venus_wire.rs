//! venus wire パース骨格の公開 API 結合試験（GPU-6・TASK-172.2・REPAIR-12）。
//!
//! `fandhe_container_plugin_macos::gpu::venus` の公開 API だけを外部 crate 視点で使い、具体的な
//! バイト列でヘッダ解釈・後続値の読み取り・不正入力の拒否を検証する。単体テスト
//! （`src/gpu/venus/tests.rs`）と併置する。GPU・実 VM は不要で 3 OS 共通。

use fandhe_container_plugin_macos::gpu::venus::{
    COMMAND_HEADER_LEN, CommandType, MAX_ARRAY_LEN, VenusWireError, WireReader,
    parse_command_header,
};

/// vkCreateRingMESA(188) + GENERATE_REPLY フラグ + 引数 u64 + 配列件数 2 + 3 バイト blob（パディング 1）。
fn sample_stream() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&188u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    b.extend_from_slice(&2u64.to_le_bytes());
    b.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x00]);
    b
}

#[test]
fn header_then_following_values_are_decoded() {
    let bytes = sample_stream();
    let mut r = WireReader::new(&bytes);
    let h = parse_command_header(&mut r).expect("header");
    assert_eq!(h.command, CommandType::CreateRingMESA);
    assert_eq!(h.command.as_raw(), 188);
    assert!(h.flags.generates_reply());
    assert_eq!(r.position(), COMMAND_HEADER_LEN);
    assert_eq!(r.read_u64().expect("u64"), 0x1122_3344_5566_7788);
    assert_eq!(r.read_array_len(MAX_ARRAY_LEN).expect("len"), 2);
    assert_eq!(r.read_bytes(3).expect("blob"), &[0xAA, 0xBB, 0xCC]);
    assert_eq!(r.remaining(), 0);
}

#[test]
fn truncated_header_is_rejected() {
    let bytes = [188u8, 0, 0, 0, 1, 0];
    let mut r = WireReader::new(&bytes);
    let err = parse_command_header(&mut r).expect_err("truncated");
    assert_eq!(err.code(), "venus_wire.truncated");
}

#[test]
fn unknown_command_type_is_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let mut r = WireReader::new(&b);
    assert_eq!(
        parse_command_header(&mut r),
        Err(VenusWireError::UnsupportedCommand { raw: 0xFFFF_FFFF })
    );
}

#[test]
fn undefined_flag_bits_are_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(&188u32.to_le_bytes());
    b.extend_from_slice(&0x2u32.to_le_bytes());
    let mut r = WireReader::new(&b);
    assert_eq!(
        parse_command_header(&mut r),
        Err(VenusWireError::InvalidFlags { raw: 2 })
    );
}

#[test]
fn oversized_array_length_is_rejected() {
    let b = (MAX_ARRAY_LEN + 1).to_le_bytes();
    let mut r = WireReader::new(&b);
    assert_eq!(
        r.read_array_len(MAX_ARRAY_LEN),
        Err(VenusWireError::LengthExceeded {
            requested: MAX_ARRAY_LEN + 1,
            max: MAX_ARRAY_LEN
        })
    );
}
