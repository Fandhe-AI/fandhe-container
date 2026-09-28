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
//!
//! # ヘッダ CRC（`header_crc`）追加に伴う注記（#67・#115・REPAIR-5）
//! [`FrameHeader`] は 2026-09-28 の設計レビューでヘッダ単体の CRC-32C
//! （`header_crc`）を持つよう拡張された。`payload_len` フィールドだけを
//! 生バイトで書き換える改ざんは、`header_crc` を再計算しない限り
//! [`FrameHeader::from_bytes`] の検証（`header_crc` を最初に検証する）で
//! `IoErrorCode::DataLoss` として即座に拒否される。本ファイルは公開 API
//! （[`FrameHeader::new`] 経由）で `payload_len` だけを差し替えた
//! **自己整合的な**（`header_crc` が新しい `payload_len` に対して正しく
//! 再計算された）ヘッダへ丸ごと入れ替えることで、BREAK-2 が本来意図する
//! 「申告長と実長の食い違い」を、ヘッダ CRC の検証を通過した状態で再現する
//! （`tamper_declared_len`）。`MAX_PAYLOAD_LEN` を超える申告長は
//! [`FrameHeader::new`] 自体が拒否するため公開 API では自己整合的に構築でき
//! ず、その 1 ケース（`repair2_break2_declared_len_over_max_rejected_by_decode`）
//! だけは元の `header_crc` を残したまま `payload_len` のみを書き換える
//! （結果として `header_crc` 不一致で `DataLoss` になる。テストのコメント参照）。

use fandhe_container_io::{
    FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind, IoError, IoErrorCode, MAX_PAYLOAD_LEN,
};

/// `encoded`（`Frame::encode` の出力）の先頭 [`FRAME_HEADER_LEN`] バイトを、
/// 種別はそのまま・ペイロード長だけを `declared` に差し替えた、**自己整合的な**
/// （`header_crc` を新しい `payload_len` に対して正しく再計算した）ヘッダへ
/// 丸ごと入れ替えたコピーを返す。ペイロード本体・チェックサムのバイト列は
/// 一切変更しない（BREAK-2 の「長さの申告だけを嘘にする」性質をワイヤーレベルで
/// 再現するため）。
///
/// `declared` が [`MAX_PAYLOAD_LEN`] を超える場合は [`FrameHeader::new`] が
/// 拒否するため使えない（モジュール冒頭の注記参照。該当テストは別の組み立て方を
/// 使う）。
fn tamper_declared_len(encoded: &[u8], declared: u32) -> Vec<u8> {
    let (header_bytes, rest) = encoded
        .split_first_chunk::<FRAME_HEADER_LEN>()
        .expect("encoded frame must contain a full fixed-length header");
    let original_header =
        FrameHeader::from_bytes(*header_bytes).expect("original encoded header must be valid");
    let tampered_header = FrameHeader::new(original_header.kind(), declared)
        .expect("declared length must be within MAX_PAYLOAD_LEN for this helper");

    let mut tampered = Vec::with_capacity(FRAME_HEADER_LEN + rest.len());
    tampered.extend_from_slice(&tampered_header.to_bytes());
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

    // `header.body_len()` は検証済みの `payload_len` から算出されるため失敗しない
    // （TASK-83.2・#117。手書きの `usize::try_from` / `checked_add` は不要）。
    let body_len = header.body_len();

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
/// （[`FrameHeader::from_bytes`]）で拒否される。
///
/// `MAX_PAYLOAD_LEN + 1` は [`FrameHeader::new`] 自体が拒否するため、
/// `tamper_declared_len`（自己整合的なヘッダへの入れ替え）は使えない。ここでは
/// 元のフレームの `header_crc` を残したまま `payload_len` フィールドだけを
/// 生バイトで書き換えるため、`header_crc` が新しい（不正な）`payload_len` と
/// 整合せず、[`FrameHeader::from_bytes`] の検証順序（`header_crc` を最初に
/// 検証する。設計レビュー P1-2）により `IoErrorCode::DataLoss` として拒否される
/// （`InvalidArgument` にはならない。仮に `header_crc` を新しい長さに対して
/// 正しく再計算できたとしても、[`PayloadLen`]（`fandhe_container_io` 未公開）の
/// 上限検証で最終的に `InvalidArgument` になることは `src/protocol.rs` の
/// `repair2_decode_rejects_over_max_len_before_allocation`〔TASK-83.2・#117〕が
/// crate 内部から `header_crc` を正しく計算した上で確認済み。アロケーション前に
/// 拒否されることの証明も同テストが行う）。
#[test]
fn repair2_break2_declared_len_over_max_rejected_by_decode() {
    let frame = Frame::new(FrameKind::Write, PAYLOAD.to_vec()).expect("Frame::new must succeed");
    let encoded = frame.encode();

    let (header_bytes, rest) = encoded
        .split_first_chunk::<FRAME_HEADER_LEN>()
        .expect("encoded frame must contain a full fixed-length header");
    let [version, kind_byte, _, _, _, _, c0, c1, c2, c3] = *header_bytes;
    let [l0, l1, l2, l3] = (MAX_PAYLOAD_LEN + 1).to_le_bytes();
    let mut tampered = Vec::with_capacity(FRAME_HEADER_LEN + rest.len());
    tampered.extend_from_slice(&[version, kind_byte, l0, l1, l2, l3, c0, c1, c2, c3]);
    tampered.extend_from_slice(rest);

    let err = Frame::decode(&tampered)
        .expect_err("declared length exceeding MAX_PAYLOAD_LEN must be rejected");
    assert_eq!(err.code(), IoErrorCode::DataLoss);
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
