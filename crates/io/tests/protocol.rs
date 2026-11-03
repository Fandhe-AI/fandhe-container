//! `fandhe-container-io` 公開 API（`Frame::new` / `encode` / `decode`）の結合試験
//! （TASK-11.3・IO-1・REPAIR-2・REPAIR-12・#70）。
//!
//! `src/protocol.rs` のユニットテストは crate 内部（非公開フィールドへのアクセスを
//! 含む）から検証するが、本ファイルは `fandhe-container-io` の外部利用者（TASK-12
//! パイプライン送信クライアント・TASK-13 バッチ write-back サーバー想定）と同じ経路
//! （`pub use` された公開 API のみ）で、往復・破損フレームの拒否・エラーコードを
//! 確認する（AGENTS.md「新機能追加時に更新すべきテスト一覧」）。

use fandhe_container_io::{Frame, FrameKind, IoErrorCode};

/// IO-1・REPAIR-2: crate 外部から見える公開 API のみで、全種別・複数ペイロード長の
/// `Frame::new` → `encode` → `decode` が往復し、種別・ペイロード・チェックサムが
/// 一致する。
#[test]
fn io1_public_api_frame_round_trips() {
    for kind in [
        FrameKind::Write,
        FrameKind::Ack,
        FrameKind::Flush,
        FrameKind::FlushAck,
    ] {
        for payload in [
            Vec::new(),
            b"x".to_vec(),
            b"integration-test-payload".to_vec(),
        ] {
            let frame = Frame::new(kind, payload.clone()).expect("Frame::new must succeed");
            let encoded = frame.encode();

            let decoded = Frame::decode(&encoded).expect("decode must succeed");
            assert_eq!(decoded.kind(), kind);
            assert_eq!(decoded.payload(), payload.as_slice());
            assert_eq!(decoded.checksum(), frame.checksum());
        }
    }
}

/// IO-1・REPAIR-2: `encode` されたバイト列のペイロード領域を 1 バイト破損させると、
/// 公開 API 経由の `decode` は `IoErrorCode::DataLoss` を返す（改ざん・破損を偽装せず
/// 拒否する。security.md「ソフトウェアとデータの完全性」観点）。
#[test]
fn io1_public_api_decode_rejects_corrupted_payload() {
    let frame = Frame::new(FrameKind::Write, b"integration-test".to_vec()).expect("Frame::new");
    let mut encoded = frame.encode();

    // ヘッダ（FRAME_HEADER_LEN = 5 バイト）の直後、ペイロード先頭バイトを破損させる。
    let payload_start = fandhe_container_io::FRAME_HEADER_LEN;
    encoded[payload_start] ^= 0xFF;

    let err = Frame::decode(&encoded).expect_err("corrupted payload must be rejected");
    assert_eq!(err.code(), IoErrorCode::DataLoss);
}

/// IO-1・REPAIR-2: フレーム末尾のチェックサム自体が破損した場合も
/// `IoErrorCode::DataLoss` として拒否される。
#[test]
fn io1_public_api_decode_rejects_corrupted_checksum() {
    let frame =
        Frame::new(FrameKind::FlushAck, b"checksum-corruption".to_vec()).expect("Frame::new");
    let mut encoded = frame.encode();
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;

    let err = Frame::decode(&encoded).expect_err("corrupted checksum must be rejected");
    assert_eq!(err.code(), IoErrorCode::DataLoss);
}

/// IO-1: 公開 API 経由でも、フレーム長不一致（欠落・余剰バイト）はチェックサム不一致
/// とは別のエラーコード（`InvalidArgument`）として区別される。
#[test]
fn io1_public_api_decode_rejects_length_mismatch() {
    let frame = Frame::new(FrameKind::Ack, b"len-mismatch".to_vec()).expect("Frame::new");
    let encoded = frame.encode();

    let mut truncated = encoded.clone();
    truncated.pop();
    let err = Frame::decode(&truncated).expect_err("truncated frame must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);

    let mut extended = encoded;
    extended.push(0);
    let err = Frame::decode(&extended).expect_err("extended frame must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// IO-1・REPAIR-2: `MAX_PAYLOAD_LEN` を超えるペイロードでの `Frame::new` は、
/// crate 外部の利用者から見ても `InvalidArgument` として拒否される（DoS 対策の
/// 上限検証が公開 API 境界で機能していることの確認）。
#[test]
fn io1_public_api_frame_new_rejects_oversized_payload() {
    let oversized_len = fandhe_container_io::MAX_PAYLOAD_LEN as usize + 1;
    // 上限+1 バイトのみを確保する（実データは不要なため 0 埋めで足りる）。
    let oversized_payload = vec![0u8; oversized_len];

    let err = Frame::new(FrameKind::Write, oversized_payload)
        .expect_err("payload exceeding MAX_PAYLOAD_LEN must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// IO-1: 空・ヘッダ長未満の入力は `decode` で `InvalidArgument` になる（外部からの
/// 不正入力に対する fail-closed の確認）。
#[test]
fn io1_public_api_decode_rejects_too_short_input() {
    let err = Frame::decode(&[]).expect_err("empty input must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);

    let err = Frame::decode(&[1, 0, 0]).expect_err("truncated header must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}
/// IO-1・REPAIR-2・#3161: v1 時代の正しいフレーム（`header_crc` もトレーラも v1 として
/// 正しい）は、v2 のビルドでは版の不一致として `Unimplemented` になる。
#[test]
fn io1_public_api_v1_header_is_unimplemented() {
    let v1_frame = [
        0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x06, 0xf1, 0x29, 0xe2, 0x61, 0x62, 0x63, 0x59, 0x2a,
        0xcd, 0xe8,
    ];
    let err = Frame::decode(&v1_frame).expect_err("v1 frame must be rejected");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}

/// IO-1・REPAIR-2・#3161: 公開 API だけで v2 のファイル操作 4 種別が往復する。
#[test]
fn io1_public_api_v2_file_frames_round_trip() {
    use fandhe_container_io::{
        GuestPath, InFlightLimit, NackCode, NackReason, PROTOCOL_VERSION, SendQueue, WireRequestId,
        decode_close, decode_create, decode_nack, decode_write_file, encode_close, encode_create,
        encode_nack, encode_write_file,
    };

    assert_eq!(PROTOCOL_VERSION, 2);
    let limit = InFlightLimit::new(4).expect("limit");
    let mut queue = SendQueue::new(limit);
    let request = queue.register(FrameKind::Write).expect("register");
    let id = WireRequestId::from(request.id());
    let path = GuestPath::parse("dir/file").expect("path");

    let create = Frame::decode(&encode_create(id, &path).expect("create").encode()).expect("dec");
    let env = decode_create(&create).expect("decode_create");
    assert_eq!(env.path(), "dir/file");
    assert_eq!(env.id(), id);

    let write =
        Frame::decode(&encode_write_file(id, id, b"data").expect("write").encode()).expect("dec");
    assert_eq!(decode_write_file(&write).expect("decode").body(), b"data");

    let close = Frame::decode(&encode_close(id, id).expect("close").encode()).expect("dec");
    assert_eq!(decode_close(&close).expect("decode").handle(), id);

    let nack = encode_nack(id, NackCode::InvalidArgument, NackReason::UnknownHandle).expect("nack");
    let nack = Frame::decode(&nack.encode()).expect("dec");
    let env = decode_nack(&nack).expect("decode_nack");
    assert_eq!(env.code(), NackCode::InvalidArgument);
    assert_eq!(env.reason(), NackReason::UnknownHandle);
}
