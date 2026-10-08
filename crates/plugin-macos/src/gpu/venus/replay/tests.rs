//! 記録・検証・再生の単体テスト（GPU-6・TASK-172.5・REPAIR-2・REPAIR-12）。
//!
//! 合成ストリームのみを使い、GPU・VM 不要で 3 OS 共通。実機で採取したストリームは使わない。

use super::checksum::crc32c;
use super::*;
use crate::gpu::venus::{CommandType, VenusWireError};

/// vkCreateRingMESA(188) + GENERATE_REPLY + 引数（venus_wire.rs の sample_stream と同形）。
fn stream_a() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&188u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    b
}

/// 2 つ目のバッファ（同じく CreateRingMESA 始まり、フラグ 0）。
fn stream_b() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&188u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    b
}

fn record(streams: &[Vec<u8>]) -> Vec<u8> {
    let mut w = RecordingWriter::new(Vec::new());
    for s in streams {
        w.append(s).expect("append");
    }
    w.finish().expect("finish")
}

fn code_of(bytes: &[u8]) -> &'static str {
    validate(bytes).expect_err("must be rejected").code()
}

#[derive(Default)]
struct CountingBackend {
    calls: u32,
}

impl ReplayBackend for CountingBackend {
    fn submit(&mut self, _seqno: u32, _stream: &[u8]) -> Result<(), VenusReplayError> {
        self.calls += 1;
        Ok(())
    }
}

#[test]
fn crc32c_standard_check_value() {
    // CRC-32C の標準チェック値（"123456789"）。
    assert_eq!(crc32c(&[b"123456789"]), 0xE306_9283);
    // 断片分割しても同じ。
    assert_eq!(crc32c(&[b"1234", b"56789"]), 0xE306_9283);
    // RFC 3720 付録 B.4: 32 バイトの 0x00 と 0xFF。
    assert_eq!(crc32c(&[&[0u8; 32]]), 0x8A91_36AA);
    assert_eq!(crc32c(&[&[0xFFu8; 32]]), 0x62A8_AB43);
    assert_eq!(crc32c(&[]), 0);
}

#[test]
fn task172_5_gpu6_roundtrip_matches_recorded_streams() {
    let (a, b) = (stream_a(), stream_b());
    let bytes = record(&[a.clone(), b.clone()]);
    let v = validate(&bytes).expect("validate");
    assert_eq!(v.records().len(), 2);

    let mut backend = CollectingBackend::default();
    let summary = replay(&v, &mut backend).expect("replay");
    assert_eq!(backend.submitted, vec![(0, a.clone()), (1, b.clone())]);
    assert_eq!(summary.records, 2);
    assert_eq!(summary.total_bytes, (a.len() + b.len()) as u64);
    assert_eq!(
        summary.first_commands,
        vec![CommandType::CreateRingMESA, CommandType::CreateRingMESA]
    );
}

#[test]
fn task172_5_gpu6_empty_recording_roundtrips() {
    let bytes = record(&[]);
    assert_eq!(bytes.len(), FILE_HEADER_LEN);
    let v = validate(&bytes).expect("validate");
    let summary = replay(&v, &mut CollectingBackend::default()).expect("replay");
    assert_eq!(summary.records, 0);
}

#[test]
fn repair12_known_bytes_layout_is_fixed() {
    let payload = stream_b();
    let bytes = record(std::slice::from_ref(&payload));
    // ヘッダ先頭 16 バイト: magic・version=1・flags=0・record_count=1。
    let expected_head: [u8; 16] = [
        b'F', b'C', b'V', b'N', b'S', b'R', b'E', b'C', 1, 0, 0, 0, 1, 0, 0, 0,
    ];
    assert_eq!(bytes.get(..16), Some(&expected_head[..]));
    // レコードヘッダ: kind=1・予約 0・seqno=0・payload_len=12。
    let expected_rec: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0];
    assert_eq!(bytes.get(20..32), Some(&expected_rec[..]));
    assert_eq!(bytes.get(32..44), Some(&payload[..]));
    assert_eq!(bytes.len(), 20 + 12 + 12 + 4);
}

#[test]
fn repair2_header_corruptions_are_detected_before_replay() {
    let good = record(&[stream_a()]);

    let mut m = good.clone();
    m[0] ^= 0xFF;
    assert_eq!(code_of(&m), "venus_replay.bad_magic");

    let mut m = good.clone();
    m[8] = 2;
    assert_eq!(code_of(&m), "venus_replay.unsupported_version");

    let mut m = good.clone();
    m[10] = 1;
    assert_eq!(code_of(&m), "venus_replay.invalid_flags");

    // record_count を改ざんするとヘッダ CRC が合わない。
    let mut m = good.clone();
    m[12] = 2;
    assert_eq!(code_of(&m), "venus_replay.header_checksum");

    assert_eq!(code_of(&[]), "venus_replay.truncated");
    assert_eq!(code_of(&good[..19]), "venus_replay.truncated");
}

#[test]
fn repair2_record_corruptions_are_detected_before_replay() {
    let good = record(&[stream_a(), stream_b()]);

    // ペイロード 1 バイト反転。
    let mut m = good.clone();
    m[32] ^= 0x01;
    assert_eq!(code_of(&m), "venus_replay.record_checksum");

    // チェックサム反転（レコード 0: 20 + 12 + 16 = 48 から 4 バイト）。
    let mut m = good.clone();
    m[48] ^= 0x01;
    assert_eq!(code_of(&m), "venus_replay.record_checksum");

    // レコード途中での切り詰め。
    assert_eq!(code_of(&good[..good.len() - 1]), "venus_replay.truncated");
    assert_eq!(code_of(&good[..25]), "venus_replay.truncated");

    // 未知 kind・予約バイト非 0・seqno 不連続。
    let mut m = good.clone();
    m[20] = 9;
    assert_eq!(code_of(&m), "venus_replay.unknown_kind");
    let mut m = good.clone();
    m[21] = 1;
    assert_eq!(code_of(&m), "venus_replay.reserved_nonzero");
    let mut m = good.clone();
    m[24] = 5;
    assert_eq!(code_of(&m), "venus_replay.sequence_mismatch");

    // 末尾の余剰バイト。
    let mut m = good.clone();
    m.push(0);
    assert_eq!(code_of(&m), "venus_replay.trailing_bytes");
}

#[test]
fn repair2_oversized_lengths_and_counts_are_rejected_without_allocation() {
    // 上限を超える record_count（ヘッダ CRC は正しい）。
    let mut bytes = RecordingHeader {
        record_count: MAX_RECORD_COUNT + 1,
    }
    .encode()
    .to_vec();
    assert_eq!(code_of(&bytes), "venus_replay.too_many_records");

    // 上限を超える payload_len を宣言するレコード（実データは無い）。
    bytes = RecordingHeader { record_count: 1 }.encode().to_vec();
    bytes.extend_from_slice(
        &RecordHeader {
            kind: RecordKind::GuestCommandStream,
            seqno: 0,
            payload_len: MAX_RECORD_PAYLOAD_LEN + 1,
        }
        .encode(),
    );
    assert_eq!(code_of(&bytes), "venus_replay.payload_too_large");

    // 上限内だが実データが無い宣言は truncated。
    bytes = RecordingHeader { record_count: 1 }.encode().to_vec();
    bytes.extend_from_slice(
        &RecordHeader {
            kind: RecordKind::GuestCommandStream,
            seqno: 0,
            payload_len: 1024,
        }
        .encode(),
    );
    assert_eq!(code_of(&bytes), "venus_replay.truncated");
}

#[test]
fn repair2_corrupt_file_never_reaches_backend() {
    let mut m = record(&[stream_a()]);
    m[32] ^= 0x01;
    let backend = CountingBackend::default();
    // validate が Err なので ValidatedRecording を得られず、replay を呼べない。
    assert!(validate(&m).is_err());
    assert_eq!(backend.calls, 0);
}

#[test]
fn task172_5_gpu6_replay_rejects_unsupported_command_without_submitting() {
    // 先頭 OK・2 件目が候補外コマンド種別（0xFFFF）。
    let mut bad = Vec::new();
    bad.extend_from_slice(&0xFFFFu32.to_le_bytes());
    bad.extend_from_slice(&0u32.to_le_bytes());
    let bytes = record(&[stream_a(), bad]);
    let v = validate(&bytes).expect("structurally valid");
    let mut backend = CountingBackend::default();
    let err = replay(&v, &mut backend).expect_err("must reject");
    assert_eq!(err.code(), "venus_replay.wire");
    assert_eq!(
        err,
        VenusReplayError::Wire {
            seqno: 1,
            source: VenusWireError::UnsupportedCommand { raw: 0xFFFF }
        }
    );
    assert_eq!(backend.calls, 0);
}

#[test]
fn task172_5_gpu6_replay_rejects_too_short_record() {
    let bytes = record(&[vec![1, 2, 3]]);
    let v = validate(&bytes).expect("validate");
    let err = replay(&v, &mut CountingBackend::default()).expect_err("must reject");
    assert_eq!(
        err,
        VenusReplayError::Wire {
            seqno: 0,
            source: VenusWireError::Truncated {
                needed: 4,
                remaining: 3
            }
        }
    );
}

#[test]
fn task172_5_gpu6_writer_rejects_oversized_payload() {
    let mut w = RecordingWriter::new(Vec::new());
    let big = vec![0u8; MAX_RECORD_PAYLOAD_LEN as usize + 1];
    assert_eq!(
        w.append(&big).expect_err("too large").code(),
        "venus_replay.payload_too_large"
    );
}

#[test]
fn task172_5_gpu6_writer_rejects_too_many_records() {
    let mut w = RecordingWriter::new(Vec::new());
    for _ in 0..MAX_RECORD_COUNT {
        w.append(&[]).expect("append");
    }
    assert_eq!(
        w.append(&[]).expect_err("too many").code(),
        "venus_replay.too_many_records"
    );
}

#[test]
fn error_messages_are_english_and_carry_numbers_only() {
    let e = VenusReplayError::SequenceMismatch {
        expected: 1,
        actual: 7,
    };
    assert_eq!(
        e.to_string(),
        "venus_replay.sequence_mismatch: record seqno 7 where 1 expected"
    );
}
