//! パイプライン送信・バッチ ACK で使うフレームヘッダの newtype（TASK-11.2・IO-1・
//! REPAIR-2・MS-1・#69。ヘッダ拡張は #67・#115・REPAIR-5・REPAIR-6）。
//!
//! ヘッダは固定長 10 バイト（`[version: u8][kind: u8][payload_len: u32 LE]
//! [header_crc: u32 LE]`）で、プロトコル版（[`PROTOCOL_VERSION`]）・種別
//! （[`FrameKind`]）・ペイロード長（[`PayloadLen`]）・ヘッダ単体の CRC-32C
//! （`header_crc`。`bytes[0..6]` を対象とする）を持つ。PoC-8
//! （`03-poc/ai-self-repair` の BREAK-2）で `data_len` を 1 バイト少なく申告する
//! 壊れ方が `cargo build` を素通りした反省から、構築時に上限検証済みの値しか
//! 表現できない型として組み立てる（REPAIR-2）。
//!
//! `header_crc` を追加した理由（設計レビュー P1-2・2026-09-28 オーナー決定）:
//! ヘッダ単体にチェックサムがないと、ストリーム読み（TASK-12・TASK-13）は
//! フレーム全体のトレーラ CRC（[`FrameChecksum`]）を検証する前に `body_len()`
//! （最大 [`MAX_PAYLOAD_LEN`] + [`CHECKSUM_LEN`]）ぶんのバッファを確保して
//! 待つことになり、1 ビット化けた `payload_len` で巨大確保・待ち続けが起きる。
//! `header_crc` は 10 バイトのヘッダだけで検証でき、化けたヘッダの値
//! （`version`・`kind`・`payload_len`）を一切信用せずに早期拒否できる。
//!
//! `version` を追加した理由（設計レビュー P1-1）: ホスト側 CLI と microVM
//! ゲストは別ビルドになり得るため、ワイヤー形式が変わった版ずれを検出できないと
//! 壊れたペイロードとして誤解釈されうる。バージョンごとのネゴシエーション
//! （Hello 交換）は MVP では行わず、フレームごとの `version` 照合で不一致を
//! `Unimplemented` として検出する（`docs/design/io-protocol.md`「バージョン
//! 方針」）。
//!
//! request id・ACK status はヘッダに含めない。それらのペイロード側レイアウトと、
//! 種別ごとのペイロード長制約（例: 制御フレームは長さ 0）は、本モジュールでは扱わず
//! TASK-12・TASK-13（またはそれらの後続 sub-issue）が定める（REPAIR-3: 実装済みを
//! 装わない）。[`FrameHeader::from_bytes`] が検証するのは (a) `header_crc` が
//! `bytes[0..6]` の再計算値と一致すること（不一致なら化けたヘッダの他フィールドを
//! 一切信用せず即座に拒否する）、(b) `version` が [`PROTOCOL_VERSION`] と一致する
//! こと、(c) 種別が既知の値であること、(d) ペイロード長が [`MAX_PAYLOAD_LEN`]
//! 以下であること、の 4 点。[`Frame::decode_body`] はこれに加えて
//! (e) [`Frame`] 全体（10 バイトヘッダ ‖ ペイロード）のトレーラ CRC
//! （[`FrameChecksum`]）が一致することを検証する。ペイロードは不透明なバイト列
//! として扱う。
//!
//! [`FrameHeader`] は [`crate::transport::WireFrame`] を実装しない。`WireFrame` は
//! フレーム全体（ヘッダ + ペイロード + チェックサム。[`Frame`]）を表す型のための
//! 境界であり、ヘッダ単体はその構成要素の 1 つに過ぎないため。[`Frame::decode`] は
//! 受信バイト列の先頭 [`FRAME_HEADER_LEN`] バイトを [`FrameHeader::from_bytes`] で
//! 検証してからペイロード長ぶんのバッファを確保する（DoS 対策。security.md）。
//!
//! # ストリーム読みの手順（TASK-12・TASK-13 が実装する想定。REPAIR-5・REPAIR-6）
//! 1. 先頭 [`FRAME_HEADER_LEN`]（10 バイト）を読む
//! 2. [`FrameHeader::from_bytes`] で検証する（`header_crc` → `version` → `kind` →
//!    `payload_len` の順。上記 4 点）。ここで拒否されれば、化けた `payload_len`
//!    を信用した巨大確保は一切発生しない
//! 3. [`crate::recv_limits::ReceiveLimits::admit`]（TASK-13.4・#796）で設定上限
//!    （[`MAX_PAYLOAD_LEN`] 以下へ個別設定できる）・現在の滞留件数を照合する。
//!    ここで拒否されれば、設定上限を下回るがプロトコル上限以下の申告長でも、
//!    まだ本体バッファは確保されない
//! 4. 検証が通ってから [`FrameHeader::body_len`]（`≤ MAX_PAYLOAD_LEN +
//!    CHECKSUM_LEN`。失敗しない）ぶんのバッファを
//!    [`crate::recv_limits::AdmittedHeader::allocate_body`] で確保して読む
//! 5. [`crate::recv_limits::AdmittedHeader::decode_body`]（[`Frame::decode_body`]
//!    への薄い委譲）へ渡す
//!
//! これにより「申告長に比例するアロケーションは検証後だけ」という DoS 対策
//! （security.md）が、一括 [`Frame::decode`] だけでなくストリーム読み経路でも
//! 成り立つ。`header_crc` はヘッダの偶発的破損の検出であり、改ざん耐性
//! （真正性の保証）ではない（トレーラの [`FrameChecksum`] と同じ範囲外事項。
//! `docs/design/io-protocol.md`「範囲外」節）。
//!
//! 申告長に比例するペイロード用バッファの確保は、デコード経路
//! （[`Frame::decode`] / [`Frame::decode_body`]）全体を通じて `copy_validated_payload`
//! （非公開関数）の 1 か所に集約しており、そこへ到達するのは長さ検証（ヘッダ上限・
//! 本体長一致）とチェックサム検証をすべて通過した後だけである（アロケーション前の
//! 早期拒否をユニットテストで示す。TASK-83.2・#117）。受信側（ストリーム読み。
//! TASK-12・TASK-13）が読み取り上限に使う本体長は [`FrameHeader::body_len`] から
//! 得ること。

use crate::error::{IoError, IoErrorCode};
use crate::transport::{WireFrame, sealed};

/// ペイロード長の上限（64 MiB = 67_108_864 バイト）。
///
/// PoC-2（`03-poc/io-layer-redesign`）・linux-real-machine 版の `MAX_DATA_LEN` を
/// 根拠とする。`fandhe-container-plugin` の境界機構（plugin-framed）が使う
/// 16 MiB 上限とは別の境界のため流用しない。この値は暫定であり、#70・#71・
/// TASK-12・TASK-13 で見直してよい（REPAIR-3）。
pub const MAX_PAYLOAD_LEN: u32 = 64 * 1024 * 1024;

/// `MAX_PAYLOAD_LEN + 1` が `u32` の範囲を超えないことをコンパイル時に保証する。
const _: () = assert!(MAX_PAYLOAD_LEN < u32::MAX);

/// このビルドが送受信するワイヤー形式のバージョン（設計レビュー P1-1・
/// 2026-09-28 オーナー決定）。
///
/// ホスト側 CLI と microVM ゲストが別ビルドになり得るため、[`FrameHeader`] の
/// 版ずれをフレームごとに検出する。ワイヤー形式（ヘッダ・フレーム全体の
/// バイトレイアウト）を変える変更は必ずこの値を上げる（`docs/design/
/// io-protocol.md`「バージョン方針」）。MVP ではネゴシエーション（Hello 交換）は
/// 行わず、[`FrameHeader::from_bytes`] が受信側の値と比較して不一致を
/// [`IoErrorCode::Unimplemented`] として返す。
pub const PROTOCOL_VERSION: u8 = 1;

/// 固定長ヘッダのバイト数（version 1 バイト + 種別 1 バイト + ペイロード長
/// 4 バイト + ヘッダ CRC 4 バイト）。
pub const FRAME_HEADER_LEN: usize = 10;

/// ヘッダの意味あるフィールド（`version` + `kind` + `payload_len`）だけのバイト数。
/// `header_crc`（[`FrameHeader::to_bytes`] が末尾に足す 4 バイト）自身は含めない。
///
/// 2 箇所で使う: (a) `header_crc` を計算する入力（[`header_crc`] 関数）、
/// (b) [`Frame`] のトレーラ [`FrameChecksum`] が対象とするヘッダ部分
/// （[`Frame::compute_checksum`]）。(b) が [`FRAME_HEADER_LEN`]（10 バイト。
/// `header_crc` を含む）ではなくこの [`HEADER_PREFIX_LEN`]（6 バイト）を使う
/// 理由は CRC-32C の残差（residue）性質による設計上の制約であり、
/// [`Frame::compute_checksum`] のドキュメンテーションコメントを参照。
const HEADER_PREFIX_LEN: usize = FRAME_HEADER_LEN - CHECKSUM_LEN;

/// `usize` が 32 ビット以上であることをコンパイル時に保証する。
///
/// [`FrameHeader::body_len`] は `payload_len: u32` を `as usize` で拡張するが、
/// この変換で情報が失われないことの根拠にする（16 ビット usize のような
/// 非現実的なターゲットを将来サポートした場合の回帰を検出する）。
const _: () = assert!(usize::BITS >= 32);

/// `MAX_PAYLOAD_LEN + CHECKSUM_LEN` が `usize` の範囲でオーバーフローしないことを
/// コンパイル時に保証する（[`FrameHeader::body_len`] の加算が安全であることの根拠）。
const _: () = assert!(MAX_PAYLOAD_LEN as usize + CHECKSUM_LEN == MAX_FRAME_LEN - FRAME_HEADER_LEN);

/// フレームの種別（IO-1・IO-2）。
///
/// `#[repr(u8)]` でワイヤー上のバイト値と一致させる。`0` はゼロ埋めバッファの
/// 誤解釈を検出するための予約値で、いずれのバリアントにも割り当てない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum FrameKind {
    /// パイプライン送信の書き込みフレーム。ペイロードのレイアウト（request id 等）は
    /// TASK-12・TASK-13（またはそれらの後続 sub-issue）が定める。
    Write = 1,
    /// 書き込みフレームに対する ACK。バッファリング時点（受信プロセスが
    /// フレームを受理したこと）までを保証し、永続化は保証しない（IO-1）。
    Ack = 2,
    /// FLUSH バリア。これ以前に受理した書き込みの永続化を要求する（IO-2）。
    /// PoC-2 の `FLUSH_MARKER`（id に埋め込む番兵値）は再現せず、種別フィールドで
    /// 表現する。
    Flush = 3,
    /// FLUSH バリアに対する ACK。バリア以前に受理した書き込みが永続化済みで
    /// あることを保証する（IO-2）。[`Self::Ack`] とは保証範囲が異なるため
    /// 別バリアントとして区別する。
    FlushAck = 4,
}

impl FrameKind {
    /// ワイヤー上のバイト値を返す。
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<FrameKind> for u8 {
    fn from(value: FrameKind) -> Self {
        value.as_u8()
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = IoError;

    /// 未知のバイト値（`0` を含む）は [`IoErrorCode::InvalidArgument`] を返す。
    /// 既定値へ丸めたり黙って無視したりしない（security.md「インジェクション」観点）。
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Write),
            2 => Ok(Self::Ack),
            3 => Ok(Self::Flush),
            4 => Ok(Self::FlushAck),
            other => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("unknown frame kind byte: {other}"),
            )),
        }
    }
}

/// 検証済みのペイロード長（[`MAX_PAYLOAD_LEN`] 以下であることが構築時に保証される）。
///
/// フィールドは非公開で、[`Self::new`] を経由しない限り値を作れない
/// （REPAIR-2: 壊れた値を表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadLen(u32);

impl PayloadLen {
    /// `len` が [`MAX_PAYLOAD_LEN`] 以下であれば受理する（`0` も受理する）。
    /// 超過する場合は [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(len: u32) -> Result<Self, IoError> {
        if len > MAX_PAYLOAD_LEN {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("payload length {len} exceeds MAX_PAYLOAD_LEN ({MAX_PAYLOAD_LEN})"),
            ));
        }
        Ok(Self(len))
    }

    /// 検証済みのペイロード長を `u32` として返す。
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PayloadLen {
    type Error = IoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<usize> for PayloadLen {
    type Error = IoError;

    /// 送信側が `data.len(): usize` から直接構築するための変換。
    /// `u32` に収まらない場合も [`MAX_PAYLOAD_LEN`] 超過と同じ
    /// [`IoErrorCode::InvalidArgument`] にまとめる（呼び出し側の分岐を単純にする）。
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let len = u32::try_from(value).map_err(|_| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("payload length {value} exceeds MAX_PAYLOAD_LEN ({MAX_PAYLOAD_LEN})"),
            )
        })?;
        Self::new(len)
    }
}

/// フレームの固定長ヘッダ（version・種別・ペイロード長・ヘッダ CRC。IO-1・
/// REPAIR-2・REPAIR-5・REPAIR-6）。
///
/// request id・ACK status は含まない（TASK-12・TASK-13 がペイロード側のレイアウトを
/// 定める）。フィールドは非公開で、[`Self::new`] / [`Self::from_bytes`] を経由しない
/// 限り値を作れない。`version` は常に [`PROTOCOL_VERSION`]（構築時に検証済み）
/// であり、値として保持するのは検証結果を [`Self::from_bytes`] の呼び出し元へ
/// 伝える必要がないため（不一致は構築失敗として扱う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    kind: FrameKind,
    payload_len: PayloadLen,
}

impl FrameHeader {
    /// 種別とペイロード長（`u32`）からヘッダを作る。`version` は常に
    /// [`PROTOCOL_VERSION`] を使う（このプロセス自身が送信するヘッダのため
    /// 版ずれは起こらない）。
    ///
    /// `payload_len` が [`MAX_PAYLOAD_LEN`] を超える場合は
    /// [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(kind: FrameKind, payload_len: u32) -> Result<Self, IoError> {
        Ok(Self {
            kind,
            payload_len: PayloadLen::new(payload_len)?,
        })
    }

    /// フレーム種別を返す。
    pub fn kind(&self) -> FrameKind {
        self.kind
    }

    /// 検証済みのペイロード長を返す。
    pub fn payload_len(&self) -> PayloadLen {
        self.payload_len
    }

    /// 検証済みの `payload_len` から、ヘッダに続く本体（ペイロード + チェックサム）の
    /// バイト数を返す（TASK-83.2・IO-1・REPAIR-2・#117）。
    ///
    /// `self` は [`Self::new`] / [`Self::from_bytes`] を経由してのみ構築できるため
    /// `payload_len` は既に [`MAX_PAYLOAD_LEN`] 以下であることが保証されており、
    /// この関数は失敗しない。受信側（ストリーム読み。TASK-12・TASK-13）は、
    /// 生のヘッダバイトから長さを自前で再計算せず、この値だけを読み取りサイズ・
    /// バッファ上限として使うこと。そうしないと、検証前の値や検証していない値で
    /// バッファを確保する回帰が入りうる（[`crate::protocol`] モジュールの
    /// デコード時検証順序の説明を参照）。
    pub fn body_len(&self) -> usize {
        // 上限は MAX_PAYLOAD_LEN（型で保証）かつ usize::BITS >= 32 をコンパイル時に
        // 確認済みのため、`as usize` への切り捨ては起きない。加算も
        // `MAX_PAYLOAD_LEN as usize + CHECKSUM_LEN == MAX_FRAME_LEN - FRAME_HEADER_LEN`
        // がコンパイル時に成り立つことを確認済みのためオーバーフローしない。
        self.payload_len.get() as usize + CHECKSUM_LEN
    }

    /// ヘッダの意味あるフィールド（`[version][kind][payload_len]`。
    /// [`HEADER_PREFIX_LEN`] バイト）を組み立てる（[`Self::to_bytes`]・
    /// [`Frame::compute_checksum`] が共有する）。`self` は構築時に検証済みの
    /// ため `version` は常に [`PROTOCOL_VERSION`]。
    fn prefix_bytes(&self) -> [u8; HEADER_PREFIX_LEN] {
        let [l0, l1, l2, l3] = self.payload_len.get().to_le_bytes();
        [PROTOCOL_VERSION, self.kind.as_u8(), l0, l1, l2, l3]
    }

    /// ヘッダを `[version: u8][kind: u8][payload_len: u32 LE][header_crc: u32 LE]`
    /// の固定長配列へ変換する。`header_crc` は `[version][kind][payload_len]`
    /// （[`Self::prefix_bytes`]）に対する CRC-32C を計算して埋める。
    /// 添字アクセスを避けるため分割代入で組み立てる（coding-rust「外部入力」節）。
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_LEN] {
        let prefix = self.prefix_bytes();
        let [c0, c1, c2, c3] = header_crc(&prefix).to_le_bytes();
        [
            prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], c0, c1, c2, c3,
        ]
    }

    /// 固定長配列からヘッダを復元する。
    ///
    /// 検証順序（先に検証したフィールドが壊れていれば後続フィールドの値を
    /// 一切信用しない。設計レビュー P1-2）:
    /// 1. `header_crc` が `[version][kind][payload_len]` の再計算値と一致しない
    ///    場合は [`IoErrorCode::DataLoss`]（化けたヘッダの偶発的破損の検出。
    ///    改ざん耐性ではない）
    /// 2. `version` が [`PROTOCOL_VERSION`] と一致しない場合は
    ///    [`IoErrorCode::Unimplemented`]（message に受信 `version` と対応
    ///    `PROTOCOL_VERSION` の両方を含める）
    /// 3. 種別バイトが未知の場合は [`IoErrorCode::InvalidArgument`]
    /// 4. ペイロード長が [`MAX_PAYLOAD_LEN`] を超える場合は
    ///    [`IoErrorCode::InvalidArgument`]
    ///
    /// `bytes` は untrusted なトランスポート由来の入力を想定し、添字アクセスでは
    /// なく分割代入で読む。
    pub fn from_bytes(bytes: [u8; FRAME_HEADER_LEN]) -> Result<Self, IoError> {
        let [version, kind_byte, l0, l1, l2, l3, c0, c1, c2, c3] = bytes;
        let prefix = [version, kind_byte, l0, l1, l2, l3];
        let received_crc = u32::from_le_bytes([c0, c1, c2, c3]);
        let expected_crc = header_crc(&prefix);

        if received_crc != expected_crc {
            return Err(IoError::new(
                IoErrorCode::DataLoss,
                format!(
                    "frame header crc mismatch: expected {expected_crc:#010x}, got {received_crc:#010x}"
                ),
            ));
        }

        if version != PROTOCOL_VERSION {
            return Err(IoError::new(
                IoErrorCode::Unimplemented,
                format!(
                    "unsupported frame protocol version: received {version}, this build supports {PROTOCOL_VERSION}"
                ),
            ));
        }

        let kind = FrameKind::try_from(kind_byte)?;
        let payload_len = PayloadLen::new(u32::from_le_bytes([l0, l1, l2, l3]))?;
        Ok(Self { kind, payload_len })
    }
}

/// `prefix`（`[version][kind][payload_len]`。[`HEADER_PREFIX_LEN`] バイト）に
/// 対する CRC-32C を計算する（`header_crc` フィールドの値。設計レビュー P1-2）。
///
/// `crate::checksum::crc32c` は `#[cfg(test)]` 限定のテスト用ヘルパーのため、
/// 本番コードは [`crate::checksum::Crc32c`]（ストリーミング API）を直接使う
/// （[`Frame::compute_checksum`] と同じ流儀）。
fn header_crc(prefix: &[u8; HEADER_PREFIX_LEN]) -> u32 {
    let mut crc = crate::checksum::Crc32c::new();
    crc.update(prefix);
    crc.finalize()
}

/// チェックサムのバイト数（CRC-32C・4 バイト）。
pub const CHECKSUM_LEN: usize = 4;

/// フレーム全体（ヘッダ + ペイロード + チェックサム）の最大バイト数。
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_PAYLOAD_LEN as usize + CHECKSUM_LEN;

/// [`Frame`] のチェックサム（CRC-32C。TASK-11.3・IO-1・REPAIR-2）。
///
/// フィールドは非公開で、公開コンストラクタを持たない。crate 内（[`Frame::new`]・
/// [`Frame::decode_body`]）でヘッダ＋ペイロードから計算した値のみが
/// この型の値になり、呼び出し側が任意の値を注入することはできない
/// （REPAIR-2: 壊れた値を表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameChecksum(u32);

impl FrameChecksum {
    /// ワイヤー上の CRC-32C 値（`u32`）を返す。
    pub fn get(self) -> u32 {
        self.0
    }
}

/// ヘッダ・ペイロード・チェックサムから成るフレーム全体（TASK-11.3・IO-1・
/// REPAIR-2・#70）。
///
/// # 不変条件
/// - `header.payload_len().get() as usize == payload.len()`
/// - `checksum` はヘッダの意味あるフィールド（`[version][kind][payload_len]`。
///   [`HEADER_PREFIX_LEN`] バイト。`header_crc` は含めない） ‖ `payload` に
///   対する CRC-32C と一致する（対象から `header_crc` を除く理由は
///   [`Self::compute_checksum`] を参照）
///
/// フィールドは非公開で、[`Self::new`]・[`Self::decode`]・[`Self::decode_body`] を
/// 経由しない限り値を作れない。ペイロードは不透明なバイト列として扱い、
/// request id・ACK status 等のレイアウトはこの型の関知するところではない
/// （TASK-12・TASK-13 の責務）。
///
/// `Debug` は手書きし、ペイロード内容を出力しない（最大 64 MiB のバッファを
/// ログ・panic メッセージへ出さない。[`crate::error::IoError`] の
/// 「message にペイロード内容を含めない」契約と整合させる）。
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    header: FrameHeader,
    payload: Vec<u8>,
    checksum: FrameChecksum,
}

impl Frame {
    /// 種別とペイロードからフレームを作る。
    ///
    /// `payload.len()` が [`MAX_PAYLOAD_LEN`] を超える場合は
    /// [`IoErrorCode::InvalidArgument`] を返す。チェックサムはヘッダ＋ペイロードから
    /// 自動計算され、呼び出し側が指定する余地はない。
    pub fn new(kind: FrameKind, payload: Vec<u8>) -> Result<Self, IoError> {
        let header = FrameHeader::new(kind, PayloadLen::try_from(payload.len())?.get())?;
        let checksum = Self::compute_checksum(&header, &payload);
        Ok(Self {
            header,
            payload,
            checksum,
        })
    }

    /// ヘッダとペイロードから CRC-32C を計算する（ヘッダの意味あるフィールド
    /// [`FrameHeader::prefix_bytes`] も対象に含める。種別・長さフィールドの
    /// 破壊も検出するため。ペイロードのみだと BREAK-2 のような「長さの嘘」に
    /// 対し、送信側バグと整合したチェックサムが通る余地がある）。
    ///
    /// # なぜ `header.to_bytes()`（10 バイト。`header_crc` を含む）ではなく
    /// `header.prefix_bytes()`（6 バイト）を使うか
    /// CRC-32C は線形写像であり、`M ‖ CRC(M)` を処理した後の CRC レジスタ状態は
    /// `M` の中身によらず常に同じ定数（残差・residue）になる（Rocksoft の CRC
    /// カタログが定義する「residue」と同じ性質。Ethernet FCS の自己検証定数と
    /// 同種）。もし `header_crc` を含む 10 バイト全体をここで対象にすると、
    /// `header_crc` が正しく再計算されてさえいれば `version`・`kind`・
    /// `payload_len` にどんな値を入れても `crc.update(&header.to_bytes())` の
    /// 寄与が常に同一の定数になってしまい、以降の `payload` が同じである限り
    /// このトレーラは「どの自己整合ヘッダを差し替えても同じ値」になる
    /// （実測: `FrameHeader::to_bytes()` で `version=1`・`payload_len=5` 固定・
    /// `kind` だけを `Write`〜`FlushAck` に変えた 4 通りで、10 バイト全体を
    /// 対象にすると全て `0x64e6a5da` に一致する一方、6 バイトの
    /// `prefix_bytes()` を対象にすると 4 通りとも異なる値になることを確認
    /// 済み）。これは「トレーラは種別・長さフィールドの破壊も検出する」という
    /// 本関数冒頭の契約と、`repair2_decode_rejects_kind_swapped_to_valid_kind`
    /// が確認する回帰点を静かに壊す（自己整合的に再構築された別種別のヘッダへの
    /// 差し替えを検出できなくなる）。`header_crc` を対象から除いた
    /// `prefix_bytes()`（意味あるフィールドのみ）を使うことで、この残差性質を
    /// 回避し、ヘッダの意味あるフィールドすべてを従来どおりトレーラで検出できる
    /// ようにしている（設計レビュー・2026-09-28 オーナー決定からの実装時逸脱。
    /// 発見時の判断は PR 説明を参照）。
    fn compute_checksum(header: &FrameHeader, payload: &[u8]) -> FrameChecksum {
        let mut crc = crate::checksum::Crc32c::new();
        crc.update(&header.prefix_bytes());
        crc.update(payload);
        FrameChecksum(crc.finalize())
    }

    /// フレームの種別を返す。
    pub fn kind(&self) -> FrameKind {
        self.header.kind()
    }

    /// フレームのヘッダを返す。
    pub fn header(&self) -> FrameHeader {
        self.header
    }

    /// ペイロードへの参照を返す。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// ペイロードを所有権ごと取り出す。
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// フレームのチェックサムを返す。
    pub fn checksum(&self) -> FrameChecksum {
        self.checksum
    }

    /// フレームをワイヤーフォーマット
    /// `[header: FRAME_HEADER_LEN B][payload: N B][checksum: CHECKSUM_LEN B LE]`
    /// へ直列化する。
    ///
    /// `Frame` はすでに長さ検証済みの型のため、ここでの `Vec` 手組みは
    /// 「検証済みの値からのみ生成する」という REPAIR-2 の趣旨に反しない
    /// （公開コンストラクタが生の `Vec<u8>` を任意に受け付けるわけではない）。
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len() + CHECKSUM_LEN);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.checksum.0.to_le_bytes());
        bytes
    }

    /// 検証済みのヘッダと、それに続く「ペイロード + チェックサム」の本体から
    /// フレームを復元する（受信側の 2 段階デコード API の後段。TASK-12・TASK-13 が
    /// 使う想定）。
    ///
    /// # 検証順序
    /// 1. `header.body_len()`（検証済みの `payload_len + CHECKSUM_LEN`）を期待される
    ///    本体長とする（[`FrameHeader::body_len`] は失敗しない。TASK-83.2）
    /// 2. `body.len()` が期待長と一致しなければ [`IoErrorCode::InvalidArgument`]
    ///    （チェックサム不一致とは別コード）
    /// 3. `body` をペイロードと受信チェックサムに分割し、ヘッダ＋ペイロードから
    ///    再計算した CRC-32C と比較。不一致なら [`IoErrorCode::DataLoss`]
    ///
    /// `body` は untrusted なトランスポート由来の入力を想定し、添字アクセスではなく
    /// `split_last_chunk` で読む。申告長に比例するアロケーション（[`copy_validated_payload`]）
    /// は、上記 1〜3 の検証をすべて通過した後にしか呼ばれない（DoS 対策。security.md・
    /// TASK-83.2・#117）。
    pub fn decode_body(header: FrameHeader, body: &[u8]) -> Result<Self, IoError> {
        let expected_len = header.body_len();

        if body.len() != expected_len {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "frame body length mismatch: expected {expected_len} bytes, got {} bytes",
                    body.len()
                ),
            ));
        }

        let (payload, checksum_bytes) =
            body.split_last_chunk::<CHECKSUM_LEN>().ok_or_else(|| {
                IoError::new(
                    IoErrorCode::InvalidArgument,
                    "frame body shorter than checksum length",
                )
            })?;

        let received_checksum = u32::from_le_bytes(*checksum_bytes);
        let expected_checksum = Self::compute_checksum(&header, payload);

        if received_checksum != expected_checksum.0 {
            return Err(IoError::new(
                IoErrorCode::DataLoss,
                format!(
                    "frame checksum mismatch: expected {:#010x}, got {:#010x}",
                    expected_checksum.0, received_checksum
                ),
            ));
        }

        Ok(Self {
            header,
            payload: copy_validated_payload(payload),
            checksum: expected_checksum,
        })
    }

    /// ヘッダから始まる完全なワイヤーバイト列からフレームを復元する
    /// （[`Self::decode_body`] の一括版）。
    ///
    /// 先頭 [`FRAME_HEADER_LEN`] バイトを [`FrameHeader::from_bytes`] で検証してから
    /// 残りを [`Self::decode_body`] に渡すため、上限検証前にペイロード用の
    /// アロケーションは行わない（DoS 対策。security.md）。
    pub fn decode(bytes: &[u8]) -> Result<Self, IoError> {
        let (header_bytes, body) =
            bytes
                .split_first_chunk::<FRAME_HEADER_LEN>()
                .ok_or_else(|| {
                    IoError::new(
                        IoErrorCode::InvalidArgument,
                        "frame is shorter than the fixed header length",
                    )
                })?;
        let header = FrameHeader::from_bytes(*header_bytes)?;
        Self::decode_body(header, body)
    }
}

/// デコード経路（[`Frame::decode`] / [`Frame::decode_body`]）で、申告長に比例する
/// ペイロード用バッファを確保する唯一の箇所（TASK-83.2・IO-1・REPAIR-2・#117）。
///
/// [`Frame::decode_body`] からは、長さ検証（[`FrameHeader::from_bytes`] の上限検証・
/// 本体長一致）とチェックサム検証をすべて通過した後にのみ呼ばれる。新たに
/// 申告長に比例する確保箇所を追加する場合は、必ずこの関数を経由すること
/// （経由しないと `mod tests` の「アロケーション前に拒否される」ことを確かめる
/// テストが見逃す）。本番の挙動は `payload.to_vec()` のままで、`#[cfg(test)]` の
/// ときだけスレッドローカルの記録器（確保回数・最後に確保した長さ）を更新する
/// （`cargo test` はテストを並列スレッドで実行するため、グローバルなカウンタでは
/// 他のテストの確保が混ざってしまう）。
fn copy_validated_payload(payload: &[u8]) -> Vec<u8> {
    #[cfg(test)]
    tests::record_allocation(payload.len());

    payload.to_vec()
}

impl core::fmt::Debug for Frame {
    /// ペイロード内容を出力しない。長さ・種別・チェックサムのみを表示する
    /// （security.md「情報漏えい」観点。message/Debug にペイロード内容を含めない）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.header.kind())
            .field("payload_len", &self.payload.len())
            .field("checksum", &format_args!("{:#010x}", self.checksum.0))
            .finish()
    }
}

impl sealed::Sealed for Frame {}
impl WireFrame for Frame {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// [`copy_validated_payload`] が呼ばれた回数（スレッドローカル。TASK-83.2）。
        /// `cargo test` はテストを並列スレッドで実行するため、他のテストの確保と
        /// 混ざらないようスレッドごとに独立させる。
        static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
        /// [`copy_validated_payload`] が最後に確保したバイト数。
        static LAST_ALLOCATION_LEN: Cell<usize> = const { Cell::new(0) };
    }

    /// [`copy_validated_payload`] から呼ばれる記録の副作用（`#[cfg(test)]` 限定）。
    pub(super) fn record_allocation(len: usize) {
        ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
        LAST_ALLOCATION_LEN.with(|last| last.set(len));
    }

    /// 記録器をリセットする（各テストの冒頭で呼ぶ。前のテストの記録が残らないように
    /// する）。
    fn reset_allocation_recorder() {
        ALLOCATION_COUNT.with(|count| count.set(0));
        LAST_ALLOCATION_LEN.with(|last| last.set(0));
    }

    fn allocation_count() -> usize {
        ALLOCATION_COUNT.with(Cell::get)
    }

    fn last_allocation_len() -> usize {
        LAST_ALLOCATION_LEN.with(Cell::get)
    }

    /// IO-1・REPAIR-2: `PayloadLen::new(0)` は受理され、値は 0。
    #[test]
    fn io1_payload_len_accepts_zero() {
        let len = PayloadLen::new(0).expect("zero must be accepted");
        assert_eq!(len.get(), 0);
    }

    /// IO-1・REPAIR-2: `PayloadLen::new(MAX_PAYLOAD_LEN)` は受理され、値は 67_108_864。
    #[test]
    fn io1_payload_len_accepts_max() {
        let len = PayloadLen::new(MAX_PAYLOAD_LEN).expect("MAX_PAYLOAD_LEN must be accepted");
        assert_eq!(len.get(), 67_108_864);
    }

    /// IO-1・REPAIR-2: `MAX_PAYLOAD_LEN + 1` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_payload_len_rejects_max_plus_one() {
        let err = PayloadLen::new(MAX_PAYLOAD_LEN + 1).expect_err("must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `u32::MAX` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_payload_len_rejects_u32_max() {
        let err = PayloadLen::new(u32::MAX).expect_err("u32::MAX must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `TryFrom<usize>` の境界値（0・MAX・MAX+1・usize::MAX）を確認する。
    #[test]
    fn io1_payload_len_try_from_usize_boundaries() {
        let zero = PayloadLen::try_from(0usize).expect("0 must be accepted");
        assert_eq!(zero.get(), 0);

        let max = PayloadLen::try_from(MAX_PAYLOAD_LEN as usize).expect("MAX must be accepted");
        assert_eq!(max.get(), MAX_PAYLOAD_LEN);

        let over = PayloadLen::try_from(MAX_PAYLOAD_LEN as usize + 1)
            .expect_err("MAX + 1 must be rejected");
        assert_eq!(over.code(), IoErrorCode::InvalidArgument);

        let usize_max = PayloadLen::try_from(usize::MAX).expect_err("usize::MAX must be rejected");
        assert_eq!(usize_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・IO-2: 全種別で `as_u8` と `TryFrom<u8>` が往復し、`Ack` と `FlushAck` の
    /// バイト値が異なる（保証範囲の違いを型レベルで区別できていることの確認）。
    #[test]
    fn io1_frame_kind_round_trips_all_variants() {
        assert_eq!(FrameKind::Write.as_u8(), 1);
        assert_eq!(FrameKind::Ack.as_u8(), 2);
        assert_eq!(FrameKind::Flush.as_u8(), 3);
        assert_eq!(FrameKind::FlushAck.as_u8(), 4);

        assert_eq!(
            FrameKind::try_from(1u8).expect("1 is Write"),
            FrameKind::Write
        );
        assert_eq!(FrameKind::try_from(2u8).expect("2 is Ack"), FrameKind::Ack);
        assert_eq!(
            FrameKind::try_from(3u8).expect("3 is Flush"),
            FrameKind::Flush
        );
        assert_eq!(
            FrameKind::try_from(4u8).expect("4 is FlushAck"),
            FrameKind::FlushAck
        );

        assert_ne!(FrameKind::Ack.as_u8(), FrameKind::FlushAck.as_u8());
    }

    /// IO-1: 予約値 `0`・未知値 `5`・`0xFF` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_frame_kind_rejects_unknown_bytes() {
        for byte in [0u8, 5, 0xFF] {
            let err = FrameKind::try_from(byte).expect_err("unknown byte must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    /// IO-1・REPAIR-2: `FrameHeader::new` の境界値（0・MAX は Ok、MAX+1・u32::MAX は Err）。
    #[test]
    fn io1_frame_header_new_boundaries() {
        let zero = FrameHeader::new(FrameKind::Write, 0).expect("0 must be accepted");
        assert_eq!(zero.kind(), FrameKind::Write);
        assert_eq!(zero.payload_len().get(), 0);

        let max = FrameHeader::new(FrameKind::Write, MAX_PAYLOAD_LEN)
            .expect("MAX_PAYLOAD_LEN must be accepted");
        assert_eq!(max.payload_len().get(), MAX_PAYLOAD_LEN);

        let over = FrameHeader::new(FrameKind::Write, MAX_PAYLOAD_LEN + 1)
            .expect_err("MAX + 1 must be rejected");
        assert_eq!(over.code(), IoErrorCode::InvalidArgument);

        let err_max =
            FrameHeader::new(FrameKind::Flush, u32::MAX).expect_err("u32::MAX must be rejected");
        assert_eq!(err_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-5: `to_bytes()` が
    /// `[version][kind][payload_len: LE][header_crc: LE]` のレイアウトになる
    /// （version=1・kind=Write=1・payload_len=0x0102_0304 → LE で 04 03 02 01）。
    /// `header_crc` は `crc32c([1, 1, 0x04, 0x03, 0x02, 0x01])` の LE 表現
    /// （独立計算による golden 値。テスト自身が `header_crc` を再計算すると
    /// 実装のバグを見逃すため、実装から独立した固定値で照合する）。
    #[test]
    fn io1_frame_header_to_bytes_layout() {
        let header = FrameHeader::new(FrameKind::Write, 0x0102_0304)
            .expect("valid header must be constructed");
        assert_eq!(
            header.to_bytes(),
            [0x01, 0x01, 0x04, 0x03, 0x02, 0x01, 0x52, 0x3a, 0x29, 0xc4]
        );
    }

    /// IO-1・REPAIR-2: 全種別・長さ 0 / MAX で `to_bytes` → `from_bytes` が往復する。
    #[test]
    fn io1_frame_header_from_bytes_round_trip() {
        for kind in [
            FrameKind::Write,
            FrameKind::Ack,
            FrameKind::Flush,
            FrameKind::FlushAck,
        ] {
            for len in [0u32, MAX_PAYLOAD_LEN] {
                let header = FrameHeader::new(kind, len).expect("valid header");
                let bytes = header.to_bytes();
                let decoded = FrameHeader::from_bytes(bytes).expect("round trip must succeed");
                assert_eq!(decoded, header);
                assert_eq!(decoded.kind(), kind);
                assert_eq!(decoded.payload_len().get(), len);
            }
        }
    }

    /// `version`・種別バイト・ペイロード長（`u32` LE）から、`header_crc` を
    /// 正しく再計算した [`FRAME_HEADER_LEN`] バイトの生ヘッダを組み立てる
    /// （テスト専用ヘルパー）。`header_crc` を自前で計算せずに `kind_byte` /
    /// `len` だけを差し替えるテストは、`from_bytes` の検証順序（`header_crc`
    /// を最初に検証する。設計レビュー P1-2）により意図せず `DataLoss` に
    /// 化けてしまうため、`version`・`kind`・`payload_len` の各検証を個別に
    /// 確認したいテストはこのヘルパーで自己整合的なヘッダを作ってから
    /// 対象フィールドだけを壊す。
    fn raw_header(version: u8, kind_byte: u8, len: u32) -> [u8; FRAME_HEADER_LEN] {
        let [l0, l1, l2, l3] = len.to_le_bytes();
        let prefix = [version, kind_byte, l0, l1, l2, l3];
        let [c0, c1, c2, c3] = header_crc(&prefix).to_le_bytes();
        [
            prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], c0, c1, c2, c3,
        ]
    }

    /// IO-1: 未知の種別バイト（`0`・`0xFF`）を含むヘッダは（`header_crc`・
    /// `version` の検証を通過した上で）`from_bytes` で `InvalidArgument` として
    /// 拒否される。
    #[test]
    fn io1_frame_header_from_bytes_rejects_unknown_kind() {
        let zero_kind = FrameHeader::from_bytes(raw_header(PROTOCOL_VERSION, 0, 0))
            .expect_err("kind byte 0 must be rejected");
        assert_eq!(zero_kind.code(), IoErrorCode::InvalidArgument);

        let unknown_kind = FrameHeader::from_bytes(raw_header(PROTOCOL_VERSION, 0xFF, 0))
            .expect_err("kind byte 0xFF must be rejected");
        assert_eq!(unknown_kind.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-2: BREAK-2（PoC-8）を模した、上限を超えるペイロード長申告は
    /// （`header_crc`・`version`・`kind` の検証を通過した上で）`from_bytes` で
    /// `InvalidArgument` として拒否される。
    #[test]
    fn io1_frame_header_from_bytes_rejects_len_over_max() {
        let over_max = FrameHeader::from_bytes(raw_header(
            PROTOCOL_VERSION,
            FrameKind::Write.as_u8(),
            MAX_PAYLOAD_LEN + 1,
        ))
        .expect_err("MAX_PAYLOAD_LEN + 1 must be rejected");
        assert_eq!(over_max.code(), IoErrorCode::InvalidArgument);

        let u32_max = FrameHeader::from_bytes(raw_header(
            PROTOCOL_VERSION,
            FrameKind::Write.as_u8(),
            u32::MAX,
        ))
        .expect_err("u32::MAX must be rejected");
        assert_eq!(u32_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-5: `header_crc` が `[version][kind][payload_len]` の
    /// 再計算値と一致しない場合、`version`・`kind`・`payload_len` のいずれかが
    /// 妥当な値であっても `from_bytes` は `DataLoss` を返す（設計レビュー
    /// P1-2: 化けたヘッダの値を一切信用しない）。
    #[test]
    fn repair5_frame_header_from_bytes_rejects_header_crc_mismatch() {
        let mut bytes = raw_header(PROTOCOL_VERSION, FrameKind::Write.as_u8(), 3);
        bytes[FRAME_HEADER_LEN - 1] ^= 0x01;

        let err = FrameHeader::from_bytes(bytes).expect_err("header crc mismatch must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-5: ヘッダの `version`・`kind`・`payload_len`・`header_crc` の
    /// 各バイトを 1 ビット反転すると、すべて `header_crc` の不一致として
    /// `DataLoss` になる（設計レビュー P1-2: `header_crc` を最初に検証する
    /// ため、他のフィールドの妥当性検証には到達しない）。
    #[test]
    fn repair5_frame_header_from_bytes_detects_any_single_bit_flip() {
        let base = raw_header(PROTOCOL_VERSION, FrameKind::Write.as_u8(), 0x0102_0304);

        for byte_index in 0..FRAME_HEADER_LEN {
            let mut tampered = base;
            tampered[byte_index] ^= 0x01;
            let err = FrameHeader::from_bytes(tampered)
                .expect_err(&format!("bit flip at byte {byte_index} must be rejected"));
            assert_eq!(
                err.code(),
                IoErrorCode::DataLoss,
                "byte {byte_index} must be detected by header_crc"
            );
        }
    }

    /// IO-1・REPAIR-5: `header_crc` を正しく再計算した上で `version` だけを
    /// 不一致にすると `Unimplemented` になり、message に受信 `version` と
    /// このビルドの `PROTOCOL_VERSION` の両方が含まれる。
    #[test]
    fn repair5_frame_header_from_bytes_rejects_version_mismatch() {
        let other_version = PROTOCOL_VERSION.wrapping_add(1);
        let bytes = raw_header(other_version, FrameKind::Write.as_u8(), 0);

        let err = FrameHeader::from_bytes(bytes).expect_err("version mismatch must be rejected");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
        assert!(err.message().contains(&other_version.to_string()));
        assert!(err.message().contains(&PROTOCOL_VERSION.to_string()));
    }

    /// IO-1・REPAIR-2: 全種別・ペイロード長 0 と小サイズで `encode` → `decode` が
    /// 往復する。
    #[test]
    fn io1_frame_round_trips_all_kinds() {
        for kind in [
            FrameKind::Write,
            FrameKind::Ack,
            FrameKind::Flush,
            FrameKind::FlushAck,
        ] {
            for payload in [Vec::new(), b"abc12".to_vec()] {
                let frame = Frame::new(kind, payload.clone()).expect("Frame::new must succeed");
                let encoded = frame.encode();
                let decoded = Frame::decode(&encoded).expect("decode must succeed");
                assert_eq!(decoded.kind(), kind);
                assert_eq!(decoded.payload(), payload.as_slice());
                assert_eq!(decoded.checksum(), frame.checksum());
            }
        }
    }

    /// IO-1・REPAIR-2・REPAIR-5: 固定入力（Write・`b"abc"`）の `encode` 結果を
    /// 具体値で照合する。レイアウトは
    /// `[version][kind][payload_len LE][header_crc LE][payload][checksum LE]`。
    /// `header_crc`・`checksum` は独立計算による golden 値
    /// （`docs/design/io-protocol.md`「エンコード例」と同じ入力・結果）。
    #[test]
    fn io1_frame_encode_layout() {
        let frame = Frame::new(FrameKind::Write, b"abc".to_vec()).expect("Frame::new");
        let encoded = frame.encode();

        // ヘッダ: version=1, kind=1(Write), payload_len=3(LE), header_crc(LE)
        assert_eq!(
            &encoded[0..FRAME_HEADER_LEN],
            &[1, 1, 3, 0, 0, 0, 0x06, 0xf1, 0x29, 0xe2]
        );
        // ペイロード
        assert_eq!(&encoded[FRAME_HEADER_LEN..FRAME_HEADER_LEN + 3], b"abc");
        // チェックサム: ヘッダの意味あるフィールド（6B: version‖kind‖payload_len。
        // `header_crc` は対象外。`Frame::compute_checksum` のドキュメンテーション
        // コメント〔CRC 残差性質〕参照） ‖ ペイロード(3B) に対する CRC-32C の LE 表現
        assert_eq!(&encoded[FRAME_HEADER_LEN + 3..], &[0x59, 0x2a, 0xcd, 0xe8]);
        assert_eq!(encoded.len(), FRAME_HEADER_LEN + 3 + CHECKSUM_LEN);
    }

    /// IO-1・REPAIR-2（受け入れ条件 1）: PoC-8 BREAK-2 相当（送信側が申告する
    /// ペイロード長を実長 − 1 にする破壊）を模した入力を `decode_body` に渡すと
    /// `DataLoss` として拒否される。
    ///
    /// 正しいフレーム（長さ N）を作った上で、ヘッダの申告長だけを N-1 に書き換え、
    /// 本体（body）はオリジナルの後続 `(N-1)+CHECKSUM_LEN` バイトのまま渡す
    /// （= 本来の payload 先頭 N-1 バイト + 本来の payload 最終バイト + checksum
    /// 先頭 3 バイトが「ペイロード」として解釈される）ことで、
    /// 長さ検証は通るがチェックサムは一致しない状況を作る。
    #[test]
    fn repair2_decode_detects_break2_short_declared_len() {
        let original_payload = b"hello".to_vec(); // N = 5
        let frame = Frame::new(FrameKind::Write, original_payload.clone()).expect("Frame::new");
        let encoded = frame.encode();
        let (_header_bytes, body) = encoded
            .split_first_chunk::<FRAME_HEADER_LEN>()
            .expect("encoded frame must have a header");

        // 申告長を N-1 = 4 に書き換えたヘッダ（BREAK-2: 長さの嘘）。
        let short_header = FrameHeader::new(FrameKind::Write, (original_payload.len() - 1) as u32)
            .expect("short header must be valid");

        // body を「短い申告長 (N-1) + CHECKSUM_LEN」ぶんだけに切り詰める。これで
        // 長さ検証（InvalidArgument）は通過し、本来の payload 最終バイト＋checksum
        // 先頭バイト群が「ペイロード」として誤解釈されるためチェックサムが
        // 一致しない状況になる（BREAK-2: 長さの嘘がヘッダ層だけでは検出できない）。
        let short_body_len = (original_payload.len() - 1) + CHECKSUM_LEN;
        let short_body = body
            .get(..short_body_len)
            .expect("body must be at least short_body_len bytes");

        let err = Frame::decode_body(short_header, short_body)
            .expect_err("short declared length must be rejected as data loss");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-2: ペイロードの 1 ビット反転は `DataLoss` として拒否される。
    #[test]
    fn repair2_decode_rejects_flipped_payload_bit() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        // ペイロード領域（header FRAME_HEADER_LEN の直後）の 1 バイト目、
        // 最下位ビットを反転する。
        encoded[FRAME_HEADER_LEN] ^= 0x01;

        let err = Frame::decode(&encoded).expect_err("flipped bit must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-2・REPAIR-5: 種別バイトを別の有効な種別へ差し替え、
    /// `header_crc` は差し替え後の種別に合わせて正しく再計算した（＝ヘッダ単体は
    /// 自己整合的な）ヘッダへ入れ替えると、トレーラの [`FrameChecksum`]
    /// （元の種別で計算済み）との不一致により `DataLoss` になる（トレーラの
    /// チェックサムがヘッダも対象にしていることの確認。`header_crc` の検証を
    /// 通過させるため生の 1 バイト差し替えではなく `raw_header` で作り直す）。
    #[test]
    fn repair2_decode_rejects_kind_swapped_to_valid_kind() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        let swapped_header = raw_header(
            PROTOCOL_VERSION,
            FrameKind::Ack.as_u8(),
            frame.header().payload_len().get(),
        );
        encoded[..FRAME_HEADER_LEN].copy_from_slice(&swapped_header);

        let err = Frame::decode(&encoded).expect_err("kind swap must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-2: トレーラ（チェックサム）の 1 バイト改変は `DataLoss` になる。
    #[test]
    fn repair2_decode_rejects_corrupted_checksum() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        let err = Frame::decode(&encoded).expect_err("corrupted checksum must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1: 一括 `decode` で余剰・不足バイトは `InvalidArgument`（チェックサム不一致
    /// とは別コードであること）。
    #[test]
    fn io1_decode_rejects_length_mismatch() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let encoded = frame.encode();

        let mut truncated = encoded.clone();
        truncated.pop();
        let err = Frame::decode(&truncated).expect_err("truncated body must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let mut extended = encoded.clone();
        extended.push(0);
        let err = Frame::decode(&extended).expect_err("extended body must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // decode_body 単体でも body 長不一致を InvalidArgument として拒否する。
        let (header_bytes, body) = encoded
            .split_first_chunk::<FRAME_HEADER_LEN>()
            .expect("encoded frame must have a header");
        let header = FrameHeader::from_bytes(*header_bytes).expect("header must decode");
        let mut short_body = body.to_vec();
        short_body.pop();
        let err = Frame::decode_body(header, &short_body)
            .expect_err("short body must be rejected as invalid argument");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: ヘッダ長未満（[`FRAME_HEADER_LEN`] バイト未満）の入力は
    /// `InvalidArgument` になる。
    #[test]
    fn io1_decode_rejects_truncated_header() {
        let err = Frame::decode(&[1, 0, 0, 0]).expect_err("4 bytes must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = Frame::decode(&[]).expect_err("empty input must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// security.md「情報漏えい」観点: `Debug` 出力にペイロード内容（マーカー文字列）が
    /// 含まれない。
    #[test]
    fn io1_frame_debug_omits_payload() {
        let frame = Frame::new(FrameKind::Write, b"SECRET_MARKER".to_vec()).expect("Frame::new");
        let debug_output = format!("{frame:?}");
        assert!(!debug_output.contains("SECRET_MARKER"));
        assert!(debug_output.contains("Write"));
        assert!(debug_output.contains("13")); // payload_len
    }

    /// IO-1: `Frame` が `WireFrame`（`Sealed + Send + Debug`）境界を満たす。
    #[test]
    fn io1_frame_implements_wire_frame() {
        fn assert_wire<T: WireFrame>() {}
        assert_wire::<Frame>();
    }

    /// IO-1・TASK-83.2: `FrameHeader::body_len` の境界値。長さ 0 では
    /// `body_len() == CHECKSUM_LEN`、`MAX_PAYLOAD_LEN` では
    /// `body_len() == MAX_PAYLOAD_LEN + CHECKSUM_LEN`。
    #[test]
    fn io1_frame_header_body_len_values() {
        let zero = FrameHeader::new(FrameKind::Write, 0).expect("0 must be accepted");
        assert_eq!(zero.body_len(), 4);

        let max = FrameHeader::new(FrameKind::Write, MAX_PAYLOAD_LEN)
            .expect("MAX_PAYLOAD_LEN must be accepted");
        assert_eq!(max.body_len(), 67_108_868);
    }

    /// TASK-83.2・REPAIR-2（受け入れ基準 2。#117）: `MAX_PAYLOAD_LEN` を超える申告長
    /// （境界値と `u32::MAX`）を含むヘッダは、[`Frame::decode`] が
    /// [`FrameHeader::from_bytes`] の段階で拒否し、`copy_validated_payload`（申告長に
    /// 比例するペイロード用バッファの確保）を 1 度も呼ばない。
    ///
    /// 「アロケーション」は申告長に比例するペイロード用バッファの確保を指す
    /// （`IoError` の message 用 `String` の確保はサイズが一定でこの検証対象では
    /// ない。issue #117 実装計画 2 章）。
    #[test]
    fn repair2_decode_rejects_over_max_len_before_allocation() {
        reset_allocation_recorder();

        let raw = raw_header(
            PROTOCOL_VERSION,
            FrameKind::Write.as_u8(),
            MAX_PAYLOAD_LEN + 1,
        );
        let err =
            Frame::decode(&raw).expect_err("declared length over MAX_PAYLOAD_LEN must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(allocation_count(), 0);

        let raw = raw_header(PROTOCOL_VERSION, FrameKind::Write.as_u8(), u32::MAX);
        let err = Frame::decode(&raw).expect_err("u32::MAX declared length must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(allocation_count(), 0);
    }

    /// TASK-83.2・REPAIR-2（#117）: 上限内の申告長（`MAX_PAYLOAD_LEN` ちょうど）でも、
    /// 実際の本体が短ければ本体長不一致として `InvalidArgument` になり、
    /// `copy_validated_payload` を呼ばない。上限を通過しただけの巨大な申告に対して
    /// 64 MiB のバッファを確保してしまう増幅を防ぐことを確認する。
    #[test]
    fn repair2_decode_body_rejects_len_mismatch_before_allocation() {
        reset_allocation_recorder();

        let header = FrameHeader::new(FrameKind::Write, MAX_PAYLOAD_LEN)
            .expect("MAX_PAYLOAD_LEN must be accepted");
        let short_body = [0u8; 8];

        let err = Frame::decode_body(header, &short_body)
            .expect_err("short body under a MAX_PAYLOAD_LEN declaration must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(allocation_count(), 0);
    }

    /// TASK-83.2・REPAIR-2（#117）: チェックサム不一致で拒否される経路でも
    /// `copy_validated_payload` を呼ばない（長さ検証を通過した後段の検証失敗でも
    /// アロケーションしないことの確認）。
    #[test]
    fn repair2_decode_rejects_checksum_mismatch_before_allocation() {
        reset_allocation_recorder();

        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        encoded[FRAME_HEADER_LEN] ^= 0x01;

        let err = Frame::decode(&encoded).expect_err("flipped bit must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
        assert_eq!(allocation_count(), 0);
    }

    /// TASK-83.2（陽性対照。#117）: 正常フレームのデコードでは
    /// `copy_validated_payload` がちょうど 1 回、申告どおりの長さで呼ばれる。
    /// この陽性対照がないと、記録器自体が動いていないために上記の
    /// `*_before_allocation` テストが偽の合格になる可能性を排除できない。
    #[test]
    fn repair2_decode_allocates_exactly_once_for_valid_frame() {
        reset_allocation_recorder();

        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let encoded = frame.encode();

        let decoded = Frame::decode(&encoded).expect("valid frame must decode");
        assert_eq!(decoded.payload(), b"hello");
        assert_eq!(allocation_count(), 1);
        assert_eq!(last_allocation_len(), 5);
    }
}
