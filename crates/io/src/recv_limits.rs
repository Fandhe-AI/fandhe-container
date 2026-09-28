//! 受信フレームの長さ・件数上限検証ゲート（TASK-13.4・IO-1・#796。P0:
//! security.md「無制限リソース確保の防止」・coding-rust.md「長さ・件数を
//! 上限検証してからアロケーションに使う」）。
//!
//! # 埋める穴
//! [`crate::protocol::FrameHeader::from_bytes`] はプロトコル上限
//! （[`crate::protocol::MAX_PAYLOAD_LEN`] = 64 MiB）を検証済みだが、
//! [`crate::batch::BatchConfig`] が個別設定できるそれより小さい**設定上限**
//! （`max_bytes`）は、[`crate::protocol`] モジュール doc の「ストリーム読みの
//! 手順」の手順 4（[`crate::protocol::FrameHeader::body_len`] ぶんの本体
//! バッファを確保）より前に照合する入口がなかった。バッチの滞留件数にも、
//! 確保前に照合する入口がなかった。本モジュールは手順 2
//! （[`crate::protocol::FrameHeader::from_bytes`]）と手順 4（本体バッファ確保）の
//! 間に入る**受理判定ゲート**として、検証済みヘッダ・設定上限・現在の滞留件数を
//! 入力に取り、超過時は本体バッファを確保する前に構造化エラー
//! （[`IoErrorCode::ResourceExhausted`]）で拒否する。受理した場合に限り、
//! 本体バッファを確保できる型付きの証跡（[`AdmittedHeader`]）を返す。
//! 設定上限（`max_bytes` 由来）は `Write` 用のバッチ集約上限であり、
//! `Ack` / `Flush` / `FlushAck` 等の制御フレームには適用しない。その代わり
//! 制御フレームには [`MAX_CONTROL_PAYLOAD_LEN`]（`BatchConfig` に依存しない
//! 固定の安全弁）を適用し、確保前検証を欠かさない（詳細は
//! [`ReceiveLimits::admit`] のドキュメンテーションコメント参照）。
//!
//! # 呼び出し文脈
//! TASK-13.2.1（#820）が新設する予定の UDS 受信ループが、[`crate::protocol::Frame`]
//! を復元する際に `FrameHeader::from_bytes` → [`ReceiveLimits::admit`] →
//! [`AdmittedHeader::allocate_body`] → 本体の読み込み →
//! [`AdmittedHeader::decode_body`] → [`crate::batch::BatchBuffer::push`] の順に
//! 呼ぶ想定（TASK-13.2.2・#822 が実際の配線を行う）。
//!
//! # なぜ `server.rs` ではなく独立モジュールか
//! spec（`05-tasks.md` TASK-13）上の成果物名は `server.rs` だが、
//! TASK-13.2.1（#820）・TASK-13.2.2（#822）・TASK-13.4（本モジュール・#796）が
//! いずれも `server.rs` を対象とし並行で着手されるため、[`crate::batch`]
//! モジュール doc の前例（REPAIR-1: 単一責務・改修の波及最小化。並行 PR の
//! マージ競合回避）に倣い、独立モジュールへ切り出した。`server.rs`（#820・#822）は
//! 本モジュールを呼び出す側になる。
//!
//! # エラーコードの使い分け
//! [`ReceiveLimits::admit`] は [`IoErrorCode::ResourceExhausted`] を返す。ヘッダ
//! 自体はプロトコル上正しく、「設定上限に達したので資源確保を拒否する」という
//! 意味であり、[`crate::client::SendQueue`]（TASK-12.1）が未 ACK 件数上限到達時に
//! 返すのと同じ意味論。[`crate::protocol::FrameHeader::from_bytes`] が返す
//! `InvalidArgument`（プロトコル上限違反・形式違反）や、
//! [`crate::batch::BatchBuffer::push`] が既に実体化したフレームに対する形式上の
//! 制約違反（`Write` 以外の種別・フレーム単体が `max_bytes` 超過）で返す
//! `InvalidArgument` とは区別する。
//!
//! # 滞留件数の出どころ（スコープ外）
//! [`crate::batch::BatchBuffer`] は `batch_size` に達すると自動で排出するため、
//! `BatchBuffer::len()` 単体が [`ReceiveLimits::for_batch`] 由来の上限に達する
//! ことはない。際限なく増えうるのは「排出済みだが未書き込みのバッチのフレーム
//! 数」の方であり、これは TASK-13.2.2（#822）で初めて生まれる。そのため
//! [`ReceiveLimits::admit`] は滞留件数を**呼び出し側からの入力**として受け取る。
//! 実際の準備完了キューとの配線（`BatchBuffer::len()` + 未書き込みバッチ件数の
//! 合算）は #822 の責務。
//!
//! # スコープ外（TASK-13 の兄弟 sub-issue・後続タスクが担う）
//! - `std::io::Read` / UDS のストリーム読みループ本体・読み取りタイムアウト
//!   （REPAIR-5）・サーバー側で `Ack` / `FlushAck` を受信した場合の拒否
//!   （TASK-13.2.1・#820。`crates/io/src/server.rs` の
//!   `imp::reject_client_originated_response_frame` が、本モジュールの
//!   [`ReceiveLimits::admit`] より前・本体バッファ確保より前に拒否する）
//! - 準備完了バッチ件数の実配線・ディスク書き込み・ACK 返却（TASK-13.2.2・#822）
//! - CLI / 設定からの上限値の配線（TASK-13.3・#78）
//! - 複数接続を跨いだ累積バイト数・未フラッシュ滞留量の上限（IO-10・TASK-16）
//! - 上限値の実測校正（TASK-88・TASK-16）
//! - 制御フレームの種別ごとの厳密なペイロード長制約（`Flush` は長さ 0 等）。
//!   本モジュールが設ける [`MAX_CONTROL_PAYLOAD_LEN`] は種別を区別しない
//!   暫定の固定上限に過ぎない（TASK-12・TASK-13 の後続）
//! - ゲートが `Err` を返した後の接続の扱い（再利用禁止・`Unavailable` 化）は
//!   `docs/design/io-protocol.md` の既存契約に従い受信ループ（#820）が担う

use std::num::NonZeroUsize;

use crate::batch::{BatchConfig, MAX_BATCH_SIZE};
use crate::error::{IoError, IoErrorCode};
use crate::protocol::{Frame, FrameHeader, FrameKind, MAX_PAYLOAD_LEN};

/// 受信経路で滞留を許す最大フレーム件数の暫定上限（REPAIR-3: 実装済みを
/// 装わない）。
///
/// [`crate::batch::BatchConfig`] の `batch_size` 上限（[`MAX_BATCH_SIZE`]）と
/// 同じ値を暫定的に流用する。滞留件数の実際の出どころ（モジュール doc
/// 参照）はまだ配線されていないため、この値自体の校正は TASK-13.3・TASK-16・
/// TASK-88 の責務。
pub const MAX_RECV_PENDING_FRAMES: usize = MAX_BATCH_SIZE;

/// 制御フレーム（`Ack` / `Flush` / `FlushAck`）に対する、確保前の暫定ペイロード長
/// 上限（REPAIR-3: 実装済みを装わない。PR #1110 codex レビュー指摘の P0）。
///
/// `Write` 用の `max_payload_len`（[`BatchConfig::max_bytes`] 由来の設定値）は
/// 運用者がバッチ用に小さく絞ることがあり、それを制御フレームへ転用すると
/// 正常な制御フレームまで誤って拒否しうる（P1・解決済み。[`ReceiveLimits::admit`]
/// のドキュメンテーションコメント参照）。かといって上限を一切設けないと、
/// 制御フレームは [`crate::protocol::FrameHeader::from_bytes`] が検証する
/// プロトコル上限 [`MAX_PAYLOAD_LEN`]（64 MiB）まで申告長を偽装でき、
/// `allocate_body` がその長さのバッファを確保前検証なしに確保してしまう
/// （P0）。制御フレームのペイロードレイアウトはまだ定義されていない
/// （モジュール doc の「スコープ外」参照）ため、`BatchConfig` に依存しない
/// 固定の安全弁として本定数を設ける。値は [`MAX_BATCH_SIZE`]（4096）件分の
/// request id 相当を想定しても十分な余裕を持つ 64 KiB とした。実際の
/// 制御フレームのレイアウト確定・上限値の校正は TASK-12・TASK-13 の後続・
/// TASK-13.3（#78）・TASK-88 の責務。
pub const MAX_CONTROL_PAYLOAD_LEN: u32 = 64 * 1024;

// MAX_CONTROL_PAYLOAD_LEN はプロトコル上限を超えてはならない不変条件を
// コンパイル時に保証する。
const _: () = assert!(MAX_CONTROL_PAYLOAD_LEN <= MAX_PAYLOAD_LEN);

// MAX_RECV_PENDING_FRAMES は非ゼロでなければならない不変条件をコンパイル時に
// 保証する（`batch.rs` の `const _: () = assert!(...)` と同種のパターン）。
const _: () = assert!(MAX_RECV_PENDING_FRAMES >= 1);

// MAX_RECV_PENDING_FRAMES は MAX_BATCH_SIZE と一致することをコンパイル時に
// 保証する（`ReceiveLimits::for_batch` が `config.batch_size()`〔常に
// 1..=MAX_BATCH_SIZE〕をそのまま `Self::new` へ渡しても
// `max_pending_frames` の範囲検証で失敗しないことの根拠。将来どちらかの値を
// 個別に変更した際の乖離をコンパイル時に検出する）。
const _: () = assert!(MAX_RECV_PENDING_FRAMES == MAX_BATCH_SIZE);

/// 受信フレームの長さ・件数の受理条件（設定上限。TASK-13.4・IO-1）。
///
/// 非公開フィールドに `PayloadLen` に収まる `u32`・`NonZeroUsize` を持ち、
/// [`Self::new`] / [`Self::for_batch`] を経由しない限り
/// `1..=MAX_PAYLOAD_LEN`（バイト数）・`1..=MAX_RECV_PENDING_FRAMES`（件数）の
/// 範囲外の値を表現できない（REPAIR-2: 壊れた値を表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiveLimits {
    max_payload_len: u32,
    max_pending_frames: NonZeroUsize,
}

impl ReceiveLimits {
    /// ペイロード長上限（バイト数）・滞留件数上限を指定して受理条件を作る。
    ///
    /// `max_payload_len` が `0` または [`MAX_PAYLOAD_LEN`] を超える値、あるいは
    /// `max_pending_frames` が `0` または [`MAX_RECV_PENDING_FRAMES`] を超える値の
    /// 場合は [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(max_payload_len: u32, max_pending_frames: usize) -> Result<Self, IoError> {
        if max_payload_len == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "max payload length must be at least 1",
            ));
        }
        if max_payload_len > MAX_PAYLOAD_LEN {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("max payload length must be at most {MAX_PAYLOAD_LEN}"),
            ));
        }
        if max_pending_frames == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "max pending frames must be at least 1",
            ));
        }
        if max_pending_frames > MAX_RECV_PENDING_FRAMES {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("max pending frames must be at most {MAX_RECV_PENDING_FRAMES}"),
            ));
        }
        // 上の分岐で 1..=MAX_RECV_PENDING_FRAMES の範囲を確認済みのため、
        // 以下の NonZeroUsize::new は必ず Some を返す。
        let max_pending_frames = NonZeroUsize::new(max_pending_frames).ok_or_else(|| {
            IoError::new(IoErrorCode::Internal, "unexpected zero pending frame limit")
        })?;
        Ok(Self {
            max_payload_len,
            max_pending_frames,
        })
    }

    /// [`BatchConfig`] から受理条件を導く。
    ///
    /// `max_payload_len` は `config.max_bytes()`（最大
    /// [`crate::batch::MAX_ALLOWED_BATCH_BYTES`]。[`MAX_PAYLOAD_LEN`] を超えうる）を
    /// [`MAX_PAYLOAD_LEN`] 以下へ切り詰めてから使う（`as` による暗黙の切り捨てでは
    /// なく `min` で明示する）。`max_pending_frames` は `config.batch_size()` を
    /// そのまま使う（`config.batch_size()` は既に `1..=MAX_BATCH_SIZE` に
    /// 検証済みで [`MAX_RECV_PENDING_FRAMES`] と一致するため [`Self::new`] は
    /// 失敗しない）。
    ///
    /// この導出により、設定上限を超えるフレームを
    /// [`crate::batch::BatchBuffer::push`] へ届く前（確保前）に拒否できる。
    /// `BatchBuffer::push` 側の `InvalidArgument` 拒否は、既に実体化した
    /// フレームに対する第 2 の防御としてそのまま残る。
    pub fn for_batch(config: &BatchConfig) -> Self {
        // config.max_bytes() は BatchConfig::new / with_max_bytes により
        // 1..=MAX_ALLOWED_BATCH_BYTES（usize）に検証済みの非ゼロ値。
        // MAX_PAYLOAD_LEN（u32）を跨ぐ比較を行うため u64 へ拡張してから
        // `min` で切り詰め、`as` による暗黙の切り捨てを避ける
        // （coding-rust.md「外部入力の経路では checked 演算で明示的に処理する」）。
        let max_bytes_u64 = u64::try_from(config.max_bytes()).unwrap_or(u64::from(MAX_PAYLOAD_LEN));
        let clamped = max_bytes_u64.min(u64::from(MAX_PAYLOAD_LEN));
        // `min(u64::from(MAX_PAYLOAD_LEN))` 済みのため u32 への変換は必ず成功する。
        let max_payload_len = u32::try_from(clamped).unwrap_or(MAX_PAYLOAD_LEN);

        // config.batch_size() は BatchConfig::new / with_max_bytes により
        // 1..=MAX_BATCH_SIZE に検証済みで、上のコンパイル時 assert
        // （MAX_RECV_PENDING_FRAMES == MAX_BATCH_SIZE）によりこれは
        // 1..=MAX_RECV_PENDING_FRAMES と同じ範囲になる。max_payload_len も
        // config.max_bytes() が非ゼロであることと上記の `min` により
        // 1..=MAX_PAYLOAD_LEN の範囲に収まる。したがって以下の Self::new は
        // 失敗しない（`batch.rs` の `BatchConfig::default()` と同じ、
        // コンパイル時保証済みの到達不能パスに対する `expect`）。
        Self::new(max_payload_len, config.batch_size())
            .expect("BatchConfig-derived values must satisfy ReceiveLimits::new")
    }

    /// 検証済みのペイロード長上限（バイト数）を返す。[`Self::admit`] は
    /// この上限を `FrameKind::Write` にのみ適用する（制御フレームには
    /// 適用しない。理由は [`Self::admit`] のドキュメンテーションコメント参照）。
    pub fn max_payload_len(&self) -> u32 {
        self.max_payload_len
    }

    /// 検証済みの滞留件数上限を返す。
    pub fn max_pending_frames(&self) -> usize {
        self.max_pending_frames.get()
    }

    /// 検証済みヘッダ・現在の滞留件数を照合し、受理するかどうかを判定する
    /// （TASK-13.4 の中心処理）。
    ///
    /// # 検証順序
    /// 1. `header.kind() == FrameKind::Write` かつ
    ///    `header.payload_len().get() > self.max_payload_len` の場合は
    ///    [`IoErrorCode::ResourceExhausted`]（`max_payload_len` は
    ///    [`Self::for_batch`] が `BatchConfig::max_bytes()`〔`Write` 用の
    ///    バッチ集約上限〕から導く設定値のため、`Write` 種別にのみ適用する。
    ///    `Ack` / `Flush` / `FlushAck` 等の制御フレームにこの上限を適用すると、
    ///    運用者がバッチ用に小さい `max_bytes` を設定した場合に、正常な制御
    ///    フレームまで本体を読む前に誤って `ResourceExhausted` で拒否しうる
    ///    〔PR #1110 codex レビュー指摘の P1〕。制御フレームは
    ///    [`crate::protocol::FrameHeader::from_bytes`] が既に検証済みの
    ///    プロトコル上限 [`MAX_PAYLOAD_LEN`] の範囲でそのまま受理する。
    ///    種別ごとの妥当な長さ上限〔制御フレームは長さ 0 等〕を設ける判断は
    ///    引き続きスコープ外（モジュール doc 参照）
    /// 2. `header.kind() != FrameKind::Write`（制御フレーム）かつ
    ///    `header.payload_len().get() > MAX_CONTROL_PAYLOAD_LEN` の場合は
    ///    [`IoErrorCode::ResourceExhausted`]（`Write` 用の設定上限とは独立な
    ///    固定の安全弁。設定上限を制御フレームへ転用しない〔P1・解決済み〕
    ///    一方で、上限を一切設けないと制御フレームがプロトコル上限
    ///    [`MAX_PAYLOAD_LEN`]〔64 MiB〕まで申告長を偽装でき、確保前検証なしに
    ///    `allocate_body` が巨大確保してしまう〔PR #1110 codex レビュー指摘の
    ///    P0〕。[`MAX_CONTROL_PAYLOAD_LEN`] のドキュメンテーションコメント参照）
    /// 3. `header.kind() == FrameKind::Write` かつ
    ///    `pending_frames >= self.max_pending_frames` の場合は
    ///    [`IoErrorCode::ResourceExhausted`]（制御フレームは滞留を排出する側
    ///    のため件数判定の対象外にする）
    /// 4. いずれにも該当しなければ [`AdmittedHeader`] を返す
    ///
    /// 種別で分岐する `match` は `FrameKind` の全バリアントを網羅する
    /// （`#[non_exhaustive]` は他クレートからの網羅を防ぐだけで、同一クレート
    /// 内のこの `match` には適用されない）。将来 `FrameKind` へ新しい種別を
    /// 追加した場合はこの `match` がコンパイルエラーになり、確保前の長さ上限を
    /// 割り当てずに新種別を通してしまう事態を防ぐ（fail-closed）。
    ///
    /// 比較は `>=` / `>` のみで加算は行わない（オーバーフローの経路を作らない）。
    /// `message` には数値（申告長・上限・滞留件数・上限件数）のみを含め、
    /// ペイロード内容は含めない（security.md）。
    pub fn admit(
        &self,
        header: FrameHeader,
        pending_frames: usize,
    ) -> Result<AdmittedHeader, IoError> {
        let payload_len = header.payload_len().get();

        match header.kind() {
            FrameKind::Write => {
                if payload_len > self.max_payload_len {
                    return Err(IoError::new(
                        IoErrorCode::ResourceExhausted,
                        format!(
                            "frame payload length {payload_len} exceeds configured receive \
                             limit {}",
                            self.max_payload_len
                        ),
                    ));
                }

                if pending_frames >= self.max_pending_frames.get() {
                    return Err(IoError::new(
                        IoErrorCode::ResourceExhausted,
                        format!(
                            "pending frame count {pending_frames} has reached configured \
                             receive limit {}",
                            self.max_pending_frames.get()
                        ),
                    ));
                }
            }
            FrameKind::Ack | FrameKind::Flush | FrameKind::FlushAck => {
                if payload_len > MAX_CONTROL_PAYLOAD_LEN {
                    return Err(IoError::new(
                        IoErrorCode::ResourceExhausted,
                        format!(
                            "control frame payload length {payload_len} exceeds fixed control \
                             frame limit {MAX_CONTROL_PAYLOAD_LEN}"
                        ),
                    ));
                }
            }
        }

        Ok(AdmittedHeader { header })
    }
}

impl Default for ReceiveLimits {
    /// [`Self::for_batch`] に既定 [`BatchConfig::default`] を渡した結果を使う
    /// （IO-1 の既定値: `max_payload_len` = [`MAX_PAYLOAD_LEN`]・
    /// `max_pending_frames` = [`crate::batch::DEFAULT_BATCH_SIZE`]）。
    fn default() -> Self {
        Self::for_batch(&BatchConfig::default())
    }
}

/// [`ReceiveLimits::admit`] が受理したことの型付きの証跡（TASK-13.4・REPAIR-2）。
///
/// 非公開フィールドを持ち、[`ReceiveLimits::admit`] を経由しない限り値を作れない。
/// 本体バッファ（[`Self::allocate_body`]）を確保できるのは本型を持つ場合に
/// 限られるため、「設定上限・滞留件数の検証を通過してからしか本体バッファを
/// 確保できない」という契約を型で強制する。
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct AdmittedHeader {
    header: FrameHeader,
}

impl AdmittedHeader {
    /// 受理されたヘッダを返す。
    pub fn header(&self) -> FrameHeader {
        self.header
    }

    /// [`FrameHeader::body_len`] への委譲（受理済みヘッダの本体長）。
    pub fn body_len(&self) -> usize {
        self.header.body_len()
    }

    /// 申告長ぶんの本体（ペイロード + チェックサム）バッファをゼロ埋めで確保する
    /// （デコード経路で本体バッファを確保する唯一の箇所。`protocol.rs` の
    /// `copy_validated_payload` と同じ「確保箇所を 1 か所に集約する」パターン。
    /// `#[cfg(test)]` のときだけスレッドローカルの記録器〔確保回数・最後の
    /// 長さ〕を更新し、拒否テストで確保が起きていないことを機械的に確認できる
    /// ようにする）。
    pub fn allocate_body(&self) -> Vec<u8> {
        let len = self.body_len();
        #[cfg(test)]
        tests::record_allocation(len);
        vec![0u8; len]
    }

    /// [`Frame::decode_body`] への薄い委譲（受理済みヘッダ + 読み込んだ本体から
    /// フレームを復元する）。CRC・版数の検証は委譲先にすべて委ね、本型はそれを
    /// 迂回しない。
    pub fn decode_body(self, body: &[u8]) -> Result<Frame, IoError> {
        Frame::decode_body(self.header, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// [`AdmittedHeader::allocate_body`] が呼ばれた回数（スレッドローカル。
        /// `cargo test` はテストを並列スレッドで実行するため、他のテストの
        /// 確保と混ざらないようスレッドごとに独立させる）。
        static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
        /// [`AdmittedHeader::allocate_body`] が最後に確保したバイト数。
        static LAST_ALLOCATION_LEN: Cell<usize> = const { Cell::new(0) };
    }

    /// [`AdmittedHeader::allocate_body`] から呼ばれる記録の副作用（`#[cfg(test)]`
    /// 限定）。
    pub(super) fn record_allocation(len: usize) {
        ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
        LAST_ALLOCATION_LEN.with(|last| last.set(len));
    }

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

    fn write_header(payload_len: u32) -> FrameHeader {
        FrameHeader::new(FrameKind::Write, payload_len).expect("header must be valid")
    }

    fn flush_header() -> FrameHeader {
        FrameHeader::new(FrameKind::Flush, 0).expect("header must be valid")
    }

    /// IO-1・REPAIR-2: `0`・`MAX_PAYLOAD_LEN + 1`・`MAX_RECV_PENDING_FRAMES + 1` は
    /// 拒否され、境界値（`1`・`MAX_PAYLOAD_LEN`・`MAX_RECV_PENDING_FRAMES`）は
    /// 受理される。
    #[test]
    fn io1_recv_limits_new_rejects_zero_and_above_max() {
        let err = ReceiveLimits::new(0, 1).expect_err("0 payload len must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = ReceiveLimits::new(MAX_PAYLOAD_LEN + 1, 1)
            .expect_err("payload len above MAX_PAYLOAD_LEN must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = ReceiveLimits::new(1, 0).expect_err("0 pending frames must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = ReceiveLimits::new(1, MAX_RECV_PENDING_FRAMES + 1)
            .expect_err("pending frames above MAX_RECV_PENDING_FRAMES must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let limits = ReceiveLimits::new(1, 1).expect("boundary values must be accepted");
        assert_eq!(limits.max_payload_len(), 1);
        assert_eq!(limits.max_pending_frames(), 1);

        let limits = ReceiveLimits::new(MAX_PAYLOAD_LEN, MAX_RECV_PENDING_FRAMES)
            .expect("upper boundary values must be accepted");
        assert_eq!(limits.max_payload_len(), MAX_PAYLOAD_LEN);
        assert_eq!(limits.max_pending_frames(), MAX_RECV_PENDING_FRAMES);
    }

    /// IO-1: `for_batch` は既定 `BatchConfig` から
    /// `max_payload_len` = `MAX_PAYLOAD_LEN`・`max_pending_frames` =
    /// `DEFAULT_BATCH_SIZE` を導く。個別設定した `BatchConfig` からも
    /// `max_bytes`・`batch_size` をそのまま反映する。
    #[test]
    fn io1_recv_limits_for_batch_derives_from_config() {
        let default_limits = ReceiveLimits::for_batch(&BatchConfig::default());
        assert_eq!(default_limits.max_payload_len(), MAX_PAYLOAD_LEN);
        assert_eq!(
            default_limits.max_pending_frames(),
            crate::batch::DEFAULT_BATCH_SIZE
        );

        let custom_config =
            BatchConfig::with_max_bytes(8, 1024).expect("valid config must succeed");
        let custom_limits = ReceiveLimits::for_batch(&custom_config);
        assert_eq!(custom_limits.max_payload_len(), 1024);
        assert_eq!(custom_limits.max_pending_frames(), 8);
    }

    /// IO-1・P0: `for_batch` は `max_bytes` が `MAX_PAYLOAD_LEN` を超える設定でも
    /// `MAX_PAYLOAD_LEN` へ切り詰める（`BatchConfig::with_max_bytes` は
    /// `MAX_ALLOWED_BATCH_BYTES`〔1 GiB 級〕まで許すため、`ReceiveLimits` 側の
    /// 上限〔`MAX_PAYLOAD_LEN` = 64 MiB〕を超える値をそのまま持たせない）。
    #[test]
    fn io1_recv_limits_for_batch_clamps_to_max_payload_len() {
        let config = BatchConfig::with_max_bytes(1, crate::batch::MAX_ALLOWED_BATCH_BYTES)
            .expect("valid config must succeed");
        let limits = ReceiveLimits::for_batch(&config);
        assert_eq!(limits.max_payload_len(), MAX_PAYLOAD_LEN);
    }

    /// TASK-13.4 受け入れ条件 1（前半）: 申告長が設定上限を超える `Write`
    /// フレームは、本体バッファを確保する前に `ResourceExhausted` で拒否される。
    /// `message` に申告長・上限の数値が含まれることも確認する。
    #[test]
    fn io1_admit_rejects_payload_over_limit_before_allocation() {
        reset_allocation_recorder();
        let limits = ReceiveLimits::new(1024, 8).expect("valid limits must succeed");
        let header = write_header(1025);

        let err = limits
            .admit(header, 0)
            .expect_err("payload over limit must be rejected");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert!(err.message().contains("1025"));
        assert!(err.message().contains("1024"));
        assert_eq!(
            allocation_count(),
            0,
            "rejection must happen before any body allocation"
        );
    }

    /// TASK-13.4 受け入れ条件 1（後半）: 滞留件数が設定上限に達している状態での
    /// `Write` フレームは、本体バッファを確保する前に `ResourceExhausted` で
    /// 拒否される。
    #[test]
    fn io1_admit_rejects_pending_at_limit_before_allocation() {
        reset_allocation_recorder();
        let limits = ReceiveLimits::new(1024, 8).expect("valid limits must succeed");
        let header = write_header(4);

        let err = limits
            .admit(header, 8)
            .expect_err("pending at limit must be rejected");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert!(err.message().contains('8'));
        assert_eq!(
            allocation_count(),
            0,
            "rejection must happen before any body allocation"
        );
    }

    /// IO-1: 制御フレーム（`Flush` 等）は滞留件数判定の対象外であり、
    /// 滞留件数が上限に達していても受理される。
    #[test]
    fn io1_admit_pending_check_ignores_control_frames() {
        let limits = ReceiveLimits::new(1024, 8).expect("valid limits must succeed");
        let header = flush_header();

        let _admitted = limits
            .admit(header, 8)
            .expect("control frames must bypass the pending frame count check");
    }

    /// PR #1110 codex レビュー指摘の P1（IO-1）: `Write` 用に導出した
    /// `max_payload_len`（`BatchConfig::max_bytes()` 由来）を制御フレームへ
    /// 誤って適用すると、`max_bytes` を小さく設定した運用で正常な `Ack` /
    /// `Flush` / `FlushAck` まで拒否されてしまう。制御フレームは申告長が
    /// `max_payload_len` を超えていても（プロトコル上限
    /// `MAX_PAYLOAD_LEN` の範囲内であれば）受理されることを確認する。
    #[test]
    fn io1_admit_length_check_does_not_apply_to_control_frames() {
        let limits = ReceiveLimits::new(8, 8).expect("valid limits must succeed");

        for kind in [FrameKind::Ack, FrameKind::Flush, FrameKind::FlushAck] {
            let header =
                FrameHeader::new(kind, 1024).expect("header within protocol limit must be valid");
            let _admitted = limits.admit(header, 0).expect(
                "control frame payload length must not be checked against the Write-only \
                 max_payload_len",
            );
        }
    }

    /// IO-1・REPAIR-2: `Write` フレームの申告長が `max_payload_len` を
    /// 超える場合は引き続き `ResourceExhausted` で拒否される（制御フレーム
    /// 除外の変更が `Write` の検証を弱めていないことの回帰確認）。
    #[test]
    fn io1_admit_length_check_still_applies_to_write_frames() {
        let limits = ReceiveLimits::new(8, 8).expect("valid limits must succeed");
        let header = write_header(9);

        let err = limits
            .admit(header, 0)
            .expect_err("Write frame payload over the configured limit must be rejected");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
    }

    /// IO-1: 申告長・滞留件数がちょうど上限（境界値）のときは受理される
    /// （`>` であり `>=` ではないペイロード長判定・`pending_frames == max - 1`
    /// の滞留件数判定）。
    #[test]
    fn io1_admit_accepts_boundaries() {
        let limits = ReceiveLimits::new(1024, 8).expect("valid limits must succeed");

        let _admitted = limits
            .admit(write_header(1024), 0)
            .expect("payload len exactly at limit must be accepted");
        let _admitted = limits
            .admit(write_header(4), 7)
            .expect("pending frames one below limit must be accepted");
    }

    /// TASK-13.4 陽性対照: 受理された場合に限り `allocate_body` で本体長どおり
    /// ちょうど 1 回確保される。記録器が動いていないために拒否テストが素通り
    /// する事態を排除する。
    #[test]
    fn io1_admitted_allocates_exactly_once() {
        reset_allocation_recorder();
        let limits = ReceiveLimits::new(1024, 8).expect("valid limits must succeed");
        let header = write_header(16);
        let expected_body_len = header.body_len();

        let admitted = limits.admit(header, 0).expect("must be admitted");
        assert_eq!(admitted.body_len(), expected_body_len);

        let body = admitted.allocate_body();
        assert_eq!(body.len(), expected_body_len);
        assert_eq!(allocation_count(), 1);
        assert_eq!(last_allocation_len(), expected_body_len);
    }

    /// IO-1: `admit` → `allocate_body` → `decode_body` の一連の流れで、
    /// `Frame::encode` の出力を往復復元できる。
    #[test]
    fn io1_admitted_decode_body_round_trips() {
        let limits = ReceiveLimits::new(MAX_PAYLOAD_LEN, MAX_RECV_PENDING_FRAMES)
            .expect("valid limits must succeed");
        let original =
            Frame::new(FrameKind::Write, b"payload".to_vec()).expect("frame must be valid");
        let encoded = original.encode();
        let (header_bytes, body) = encoded
            .split_first_chunk::<{ crate::protocol::FRAME_HEADER_LEN }>()
            .expect("encoded frame must contain the fixed header");
        let header = FrameHeader::from_bytes(*header_bytes).expect("header must be valid");

        let admitted = limits.admit(header, 0).expect("must be admitted");
        let mut buffer = admitted.allocate_body();
        buffer.copy_from_slice(body);
        let decoded = admitted.decode_body(&buffer).expect("decode must succeed");

        assert_eq!(decoded, original);
    }

    /// IO-1: `ReceiveLimits` はスレッド境界を越えて受け渡せる
    /// （`BatchBuffer` と同じ契約。コンパイル時確認）。
    #[test]
    fn io1_receive_limits_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ReceiveLimits>();
        assert_send::<AdmittedHeader>();
    }

    /// PR #1110 codex レビュー指摘の P0（IO-1）: 制御フレーム（`Ack` /
    /// `Flush` / `FlushAck`）の申告長が [`MAX_CONTROL_PAYLOAD_LEN`] を超える
    /// 場合は、`Write` 用の設定上限（`max_bytes` 由来）が大きく設定されて
    /// いても、本体バッファを確保する前に `ResourceExhausted` で拒否される
    /// （設定上限を制御フレームへ転用しない P1 修正が、制御フレームの
    /// 長さ検証を完全に取り除いてしまっていないことの回帰確認）。
    #[test]
    fn io1_admit_rejects_control_frame_over_fixed_control_limit_before_allocation() {
        reset_allocation_recorder();
        // Write 用の設定上限は MAX_PAYLOAD_LEN いっぱいまで大きく取り、
        // 制御フレームの拒否が Write 用の設定上限に依存しないことを示す。
        let limits = ReceiveLimits::new(MAX_PAYLOAD_LEN, MAX_RECV_PENDING_FRAMES)
            .expect("valid limits must succeed");

        for kind in [FrameKind::Ack, FrameKind::Flush, FrameKind::FlushAck] {
            let header = FrameHeader::new(kind, MAX_CONTROL_PAYLOAD_LEN + 1)
                .expect("header within protocol limit must be valid");

            let err = limits
                .admit(header, 0)
                .expect_err("control frame payload over the fixed control limit must be rejected");
            assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
            assert!(
                err.message()
                    .contains(&(MAX_CONTROL_PAYLOAD_LEN + 1).to_string())
            );
            assert!(err.message().contains(&MAX_CONTROL_PAYLOAD_LEN.to_string()));
        }
        assert_eq!(
            allocation_count(),
            0,
            "rejection must happen before any body allocation"
        );
    }

    /// IO-1: 制御フレームは申告長がちょうど [`MAX_CONTROL_PAYLOAD_LEN`]
    /// （境界値）であれば受理される（`>` であり `>=` ではない判定）。
    #[test]
    fn io1_admit_accepts_control_frame_at_fixed_control_limit_boundary() {
        let limits = ReceiveLimits::new(8, 8).expect("valid limits must succeed");

        for kind in [FrameKind::Ack, FrameKind::Flush, FrameKind::FlushAck] {
            let header = FrameHeader::new(kind, MAX_CONTROL_PAYLOAD_LEN)
                .expect("header within protocol limit must be valid");

            let _admitted = limits.admit(header, 0).expect(
                "control frame payload exactly at the fixed control limit must be accepted",
            );
        }
    }
}
