//! PoC-8（`03-poc/ai-self-repair`）BREAK-2 を、ワイヤー上のバイト列の長さフィールド
//! そのものを書き換える形で再現し、`fandhe-container-io` の公開 API だけで検出できる
//! ことを固定する結合試験（TASK-83.1・REPAIR-2・IO-1・MS-1・#116）。
//!
//! `tests/protocol.rs` は既存 `Frame::encode` の出力をバッファ末尾の push / pop で
//! 破損させ「バッファ長の不一致」を確認するのに対し、本ファイルは
//! **ヘッダの `payload_len` フィールド自体を書き換えた入力**に絞る。BREAK-2 の
//! 本質は「送信側が申告する長さ（`data_len`）を実際のペイロード長と食い違わせる」
//! ことであり、`FrameHeader::new` を経由する内部経路（`src/protocol.rs` の
//! `repair2_decode_detects_break2_short_declared_len`）は `Frame` を組み立てる前の
//! 内部データからテストしているが、ここでは実際に送受信されるワイヤーフォーマットの
//! バイト列を直接改ざんし、公開 API（[`Frame::decode`] / [`Frame::decode_body`]）が
//! 想定どおり `Err` を返すことを確認する。
//!
//! 検出経路は 2 つ:
//! - 一括 `decode`（全長が既知。`stream.len()` から本体長を逆算できる） →
//!   申告長と実長が食い違えば `IoErrorCode::InvalidArgument`（本体長不一致）
//! - ストリーム読み（[`stream_read_frame`] が模す。TASK-12・TASK-13 が実装する
//!   想定の、申告長ぶんだけ読んでから [`Frame::decode_body`] へ渡す経路） →
//!   長さ検証は申告どおりの本体長と一致するため通過し、ヘッダ＋ペイロードから
//!   再計算した CRC-32C が一致しないため `IoErrorCode::DataLoss`
//!
//! CRC-32C は偶発的破損の検出であって、意図的な偽装（申告長・ペイロード・
//! チェックサムを揃えて送出する自己整合的な改ざん）への耐性は持たない
//! （`docs/design/io-protocol.md`「範囲外（真正性は保証しない）」節）。本ファイルの
//! 各ケースはチェックサムを再計算していない改ざん（受信側が検出できる想定の破壊）
//! のみを扱う。

use fandhe_container_io::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind, IoError, IoErrorCode,
    MAX_PAYLOAD_LEN,
};

/// `encoded`（`Frame::encode` の出力）の先頭 [`FRAME_HEADER_LEN`] バイトのうち、
/// 種別バイトはそのまま残し、ペイロード長フィールド（オフセット 1..5、`u32` LE）だけを
/// `declared` に書き換えたコピーを返す。ペイロード本体・チェックサムのバイト列は
/// 一切変更しない（BREAK-2 の「長さの申告だけを嘘にする」性質をワイヤーレベルで
/// 再現するため）。添字代入は避け、分割・分割代入で組み立てる
/// （coding-rust「外部入力」節）。
fn tamper_declared_len(encoded: &[u8], declared: u32) -> Vec<u8> {
    let (header_bytes, rest) = encoded
        .split_first_chunk::<FRAME_HEADER_LEN>()
        .expect("encoded frame must contain a full fixed-length header");
    let [kind_byte, _, _, _, _] = *header_bytes;
    let [l0, l1, l2, l3] = declared.to_le_bytes();

    let mut tampered = Vec::with_capacity(FRAME_HEADER_LEN + rest.len());
    tampered.extend_from_slice(&[kind_byte, l0, l1, l2, l3]);
    tampered.extend_from_slice(rest);
    tampered
}

/// ストリーム読みの受信側を模す（TASK-12・TASK-13 が実装する想定の経路）。
///
/// 先頭 [`FRAME_HEADER_LEN`] バイトを [`FrameHeader::from_bytes`] で検証し、
/// ヘッダが申告する長さぶん（`payload_len + CHECKSUM_LEN`）だけを `stream` から
/// 切り出して [`Frame::decode_body`] に渡す。[`Frame::decode`] の一括版と異なり、
/// 全体の長さを事前に知らず「申告された長さを信じて読む」動きを再現するため、
/// 申告長が実際のペイロード長より短い／長い場合の挙動が一括版と異なりうる
/// （本ファイルのテストが両経路を分けて確認する理由）。
fn stream_read_frame(stream: &[u8]) -> Result<Frame, IoError> {
    let (header_bytes, rest) = stream
        .split_first_chunk::<FRAME_HEADER_LEN>()
        .ok_or_else(|| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                "stream is shorter than the fixed header length",
            )
        })?;
    let header = FrameHeader::from_bytes(*header_bytes)?;

    let payload_len = usize::try_from(header.payload_len().get()).map_err(|_| {
        IoError::new(
            IoErrorCode::InvalidArgument,
            "declared payload length does not fit in usize on this platform",
        )
    })?;
    let body_len = payload_len.checked_add(CHECKSUM_LEN).ok_or_else(|| {
        IoError::new(
            IoErrorCode::InvalidArgument,
            "declared payload length + checksum length overflows",
        )
    })?;

    let body = rest.get(..body_len).ok_or_else(|| {
        IoError::new(
            IoErrorCode::InvalidArgument,
            "stream does not contain the declared body length yet",
        )
    })?;

    Frame::decode_body(header, body)
}

/// テストで使う固定ペイロード（N = 20 バイト）。改ざん後に CRC-32C が偶然一致する
/// 確率は無視できるほど小さく（2^-32）、入力は固定なので結果は決定的である。
const PAYLOAD: &[u8] = b"break2-frame-payload"; // 20 bytes

/// TASK-83.1・REPAIR-2・IO-1（受け入れ基準 1・一括 decode 経路）: 申告長を
/// 実ペイロード長 − 1 に偽った入力（PoC-8 BREAK-2 そのもの）は、全長が既知の
/// 一括 `Frame::decode` では本体長の不一致として `InvalidArgument` になる。
#[test]
fn repair2_break2_declared_len_shorter_rejected_by_decode() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();

    let shorter = u32::try_from(PAYLOAD.len() - 1).expect("small length fits in u32");
    let tampered = tamper_declared_len(&encoded, shorter);

    let err = Frame::decode(&tampered).expect_err("shorter declared length must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// TASK-83.1・REPAIR-2・IO-1（受け入れ基準 1・ストリーム読み経路）: 申告長を
/// 実ペイロード長 − 1 に偽った入力は、申告長ぶんだけ読むストリーム読み経路では
/// 本体長検証を通過し、チェックサム再計算の不一致で `DataLoss` になる。
#[test]
fn repair2_break2_declared_len_shorter_rejected_by_stream_read() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();

    let shorter = u32::try_from(PAYLOAD.len() - 1).expect("small length fits in u32");
    let tampered = tamper_declared_len(&encoded, shorter);

    let err = stream_read_frame(&tampered).expect_err("shorter declared length must be rejected");
    assert_eq!(err.code(), IoErrorCode::DataLoss);
}

/// TASK-83.1・REPAIR-2・IO-1（受け入れ基準 2・一括 decode 経路）: 申告長を
/// 実ペイロード長 + 1 に偽った入力は、一括 `Frame::decode` では本体長の不一致として
/// `InvalidArgument` になる。
#[test]
fn repair2_break2_declared_len_longer_rejected_by_decode() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();

    let longer = u32::try_from(PAYLOAD.len() + 1).expect("small length fits in u32");
    let tampered = tamper_declared_len(&encoded, longer);

    let err = Frame::decode(&tampered).expect_err("longer declared length must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// TASK-83.1・REPAIR-2・IO-1（受け入れ基準 2・ストリーム読み経路）: 申告長を
/// 実ペイロード長 + 1 に偽った入力の直後に正常な 2 本目のフレームを連結し、
/// ストリーム読み経路に 1 バイト余分に読ませると、境界がずれてチェックサム
/// 再計算が一致せず `DataLoss` になる。
#[test]
fn repair2_break2_declared_len_longer_rejected_by_stream_read() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();

    let longer = u32::try_from(PAYLOAD.len() + 1).expect("small length fits in u32");
    let mut tampered = tamper_declared_len(&encoded, longer);

    // 後続フレームを連結し、申告長ぶん読むストリーム読みが 1 バイト多く読めるように
    // する（そうしないと `rest.get(..body_len)` が範囲外で `InvalidArgument` に
    // なってしまい、境界ずれによる `DataLoss` を再現できない）。
    let next_frame = Frame::new(FrameKind::Ack, b"next-frame-marker".to_vec()).expect("Frame::new");
    tampered.extend_from_slice(&next_frame.encode());

    let err = stream_read_frame(&tampered).expect_err("longer declared length must be rejected");
    assert_eq!(err.code(), IoErrorCode::DataLoss);
}

/// 任意ケース（TASK-83.1 の受け入れ基準を上回る）: 申告長を 0（空ペイロードと偽る）
/// に書き換えた入力は、一括 decode では本体長不一致として `InvalidArgument`、
/// ストリーム読みではチェックサム再計算の不一致で `DataLoss` になる。
#[test]
fn repair2_break2_declared_len_zero_rejected_by_both_paths() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();
    let tampered = tamper_declared_len(&encoded, 0);

    let decode_err =
        Frame::decode(&tampered).expect_err("zero declared length must be rejected by decode");
    assert_eq!(decode_err.code(), IoErrorCode::InvalidArgument);

    let stream_err = stream_read_frame(&tampered)
        .expect_err("zero declared length must be rejected by stream read");
    assert_eq!(stream_err.code(), IoErrorCode::DataLoss);
}

/// 任意ケース: 申告長を `MAX_PAYLOAD_LEN + 1` に書き換えた入力は、ヘッダ検証の時点
/// （[`FrameHeader::from_bytes`]）で `InvalidArgument` として拒否される。
/// アロケーション前に拒否されることの証明（DoS 対策）自体は #117（TASK-83.2）の
/// 範囲であり、ここではエラーコードの確認のみを行う。
#[test]
fn repair2_break2_declared_len_over_max_rejected_by_decode() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();
    let tampered = tamper_declared_len(&encoded, MAX_PAYLOAD_LEN + 1);

    let err = Frame::decode(&tampered)
        .expect_err("declared length exceeding MAX_PAYLOAD_LEN must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// security.md「情報漏えい」観点: 改ざん検出のエラーメッセージにペイロード内容
/// （マーカー文字列）が含まれない。
#[test]
fn repair2_break2_error_message_omits_payload_content() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();

    let shorter = u32::try_from(PAYLOAD.len() - 1).expect("small length fits in u32");
    let tampered = tamper_declared_len(&encoded, shorter);

    let decode_err =
        Frame::decode(&tampered).expect_err("shorter declared length must be rejected");
    assert!(
        !decode_err
            .message()
            .contains(std::str::from_utf8(PAYLOAD).expect("payload fixture must be valid UTF-8"))
    );

    let stream_err =
        stream_read_frame(&tampered).expect_err("shorter declared length must be rejected");
    assert!(
        !stream_err
            .message()
            .contains(std::str::from_utf8(PAYLOAD).expect("payload fixture must be valid UTF-8"))
    );
}
