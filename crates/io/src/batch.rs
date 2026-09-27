//! バッチ write-back サーバー（TASK-13）の最初の部品として、受信した書き込み
//! フレームをメモリ内で集約するバッファ（TASK-13.1・IO-1・#76・MS-1）。
//!
//! 本モジュールが持つのは「一定件数（既定 [`DEFAULT_BATCH_SIZE`]）ぶんの
//! [`crate::protocol::Frame`] を溜め、件数に達した時点でバッチ（値）を返す」
//! 純粋なメモリ内ロジックのみ。ソケット・スレッド・ディスク書き込み・ACK 返却・
//! タイマーは一切持たない（REPAIR-3: 実装済みを装わない）。
//!
//! # スコープ外（TASK-13 の兄弟 sub-issue が担う）
//! - ディスクへの書き込み実行・ACK フレームの返却（TASK-13.2・TASK-13.2.2）
//! - UDS 接続受付ループ（`server.rs`。TASK-13.2.1）
//! - CLI / 設定からのバッチサイズ配線（`--batch-size` 相当。TASK-13.3）
//! - 受信フレーム長・累積件数 / バイト数の上限検証（受信経路の DoS 対策。TASK-13.4）
//! - FLUSH バリアの処理（IO-2・TASK-15）・未フラッシュ滞留量上限（IO-10・TASK-16）
//!
//! # 呼び出し文脈
//! TASK-13.2.1 以降が新設する予定の `server.rs`（UDS 受信ループ）が、受信した
//! `FrameKind::Write` フレームを [`BatchBuffer::push`] へ渡し、[`PushOutcome::Ready`]
//! が返ったバッチをディスク書き込み（TASK-13.2）へ引き渡す想定。接続終了時・
//! FLUSH 受信時（TASK-15）には [`BatchBuffer::take_pending`] で件数未達分を
//! 強制的に取り出す。
//!
//! 成果物名は spec（`05-tasks.md` TASK-13）上は `server.rs` だが、TASK-13.2.1
//! （#820）・TASK-13.2.2（#822）・TASK-13.4（#796）がいずれも `server.rs` を
//! 対象とし本 issue 完了後に並行で着手されるため、集約ロジックを独立モジュールへ
//! 切り出した（REPAIR-1: 単一責務・改修の波及最小化。並行 PR のマージ競合回避）。
//!
//! # ACK 意味論の区別（P0）
//! 本モジュールは ACK を一切送らない。[`crate::protocol::FrameKind::Ack`]
//! （IO-1 の通常 ACK）は「バッファリング時点で受理されたこと」の保証であり、
//! 永続化完了は保証しない。永続化完了を保証するのは IO-2 の FLUSH ACK
//! （`FrameKind::FlushAck`。TASK-15）であり、本モジュールが返す [`Batch`] は
//! どちらの ACK 送出も引き起こさない、あくまでメモリ内に溜まった値に過ぎない。

use std::num::NonZeroUsize;

use crate::error::{IoError, IoErrorCode};
use crate::protocol::{Frame, FrameKind};

/// バッチの既定サイズ（IO-1 の既定値）。
pub const DEFAULT_BATCH_SIZE: usize = 64;

/// バッチサイズの暫定上限。
///
/// IO-1 は既定値（64 件）のみを定め、上限は定めていない。PoC-12 のスイープ
/// 最大値（256）に対し 16 倍の余裕として 4096 を暫定的に置く。件数の上限だけ
/// では 1 フレームあたり最大 64 MiB（[`crate::protocol::MAX_PAYLOAD_LEN`]）の
/// ペイロード合計バイト数は抑えられない。バイト数上限は IO-10（TASK-16）・
/// 受信側の検証は TASK-13.4（#796）の責務であり、本モジュールは関知しない。
/// この値自体も TASK-13.3・TASK-13.4・TASK-16・TASK-88（ベンチ校正）で
/// 見直してよい暫定値（REPAIR-3）。
pub const MAX_BATCH_SIZE: usize = 4096;

/// [`BatchBuffer`] の集約単位（件数）を表す設定値（IO-1）。
///
/// 非公開フィールドに `NonZeroUsize` を持ち、[`Self::new`] を経由しない限り
/// `1..=MAX_BATCH_SIZE` の範囲外の値を表現できない（REPAIR-2: 壊れた値を
/// 表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchConfig {
    batch_size: NonZeroUsize,
}

impl BatchConfig {
    /// `batch_size` からバッチ設定を作る。
    ///
    /// `0` または [`MAX_BATCH_SIZE`] を超える値は
    /// [`IoErrorCode::InvalidArgument`] として拒否する。
    pub fn new(batch_size: usize) -> Result<Self, IoError> {
        if batch_size == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "batch size must be at least 1",
            ));
        }
        if batch_size > MAX_BATCH_SIZE {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("batch size must be at most {MAX_BATCH_SIZE}"),
            ));
        }
        // 上の 2 分岐で 1..=MAX_BATCH_SIZE の範囲を確認済みのため、
        // NonZeroUsize::new は必ず Some を返す。
        let batch_size = NonZeroUsize::new(batch_size)
            .ok_or_else(|| IoError::new(IoErrorCode::Internal, "unexpected zero batch size"))?;
        Ok(Self { batch_size })
    }

    /// 検証済みのバッチサイズを返す。
    pub fn batch_size(&self) -> usize {
        self.batch_size.get()
    }
}

impl Default for BatchConfig {
    /// IO-1 の既定値（[`DEFAULT_BATCH_SIZE`] = 64）を使う。
    fn default() -> Self {
        // DEFAULT_BATCH_SIZE は 1..=MAX_BATCH_SIZE 範囲内の定数のため必ず成功する。
        Self::new(DEFAULT_BATCH_SIZE).expect("DEFAULT_BATCH_SIZE must be a valid batch size")
    }
}

impl TryFrom<usize> for BatchConfig {
    type Error = IoError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// バッチが発火した理由（REPAIR-4: 可観測性）。
///
/// `#[non_exhaustive]` により、将来の追加（例: FLUSH バリアによる発火・
/// 滞留量上限による強制発火）に備えて呼び出し側の `match` は `_` 分岐を持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BatchTrigger {
    /// 設定件数（[`BatchConfig::batch_size`]）に到達して自動発火した。
    SizeReached,
    /// [`BatchBuffer::take_pending`] により、件数未達のまま強制的に取り出された。
    Drained,
}

/// [`BatchBuffer`] から取り出された、書き込みフレームの集合（IO-1）。
///
/// # 契約
/// - `frames` は [`FrameKind::Write`] のみを含む（[`BatchBuffer::push`] が
///   他種別を拒否するため）
/// - 挿入順を保持する
/// - 本型自体はディスク書き込み・ACK 送出を引き起こさない（呼び出し側〔TASK-13.2〕
///   の責務）。IO-1 の通常 ACK と IO-2 の FLUSH ACK の区別はモジュール冒頭の説明を
///   参照
///
/// `#[must_use]` により、発火したバッチを呼び出し側が黙って捨てる
/// （＝書き込みデータの消失）経路をコンパイラ警告で塞ぐ。
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct Batch {
    frames: Vec<Frame>,
    trigger: BatchTrigger,
}

impl Batch {
    /// バッチに含まれるフレーム件数を返す。
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// バッチが空かどうかを返す。
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// バッチが発火した理由を返す。
    pub fn trigger(&self) -> BatchTrigger {
        self.trigger
    }

    /// バッチ内のフレームへの参照を、挿入順のまま返す。
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }

    /// バッチ内のフレームを所有権ごと、挿入順のまま取り出す。
    pub fn into_frames(self) -> Vec<Frame> {
        self.frames
    }
}

// Frame は Debug を手書きしペイロード内容を出力しないため、Batch の derive(Debug) も
// ペイロード内容を漏らさない（security.md「秘密情報・情報漏えい」観点）。
impl std::fmt::Debug for Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batch")
            .field("len", &self.frames.len())
            .field("trigger", &self.trigger)
            .finish()
    }
}

/// [`BatchBuffer::push`] の戻り値（IO-1）。
///
/// `#[must_use]` により、`Ready` バリアントを呼び出し側が黙って捨てる経路を
/// コンパイラ警告で塞ぐ（`Batch` 自体も `#[must_use]` だが、`match` で分解した後に
/// `Ready` アームの値を捨てる経路も別途塞ぐため戻り値自体にも付与する）。
#[must_use]
#[non_exhaustive]
#[derive(Debug)]
pub enum PushOutcome {
    /// バッファへ蓄積された（まだ発火していない）。`pending` は現在の滞留件数。
    Buffered { pending: usize },
    /// 設定件数に到達し、バッチが発火した。
    Ready(Batch),
}

/// 受信した書き込みフレームを既定 [`DEFAULT_BATCH_SIZE`]（設定可能）件単位で
/// 集約するメモリ内バッファ（IO-1・TASK-13.1・#76）。
///
/// # 契約
/// - `&mut self` を要求する単一スレッド利用を前提とする（[`crate::transport`] の
///   `FrameSender` / `FrameReceiver` と同じ契約）
/// - [`FrameKind::Write`] 以外のフレーム（`Ack` / `Flush` / `FlushAck`）を
///   [`Self::push`] へ渡すと [`IoErrorCode::InvalidArgument`] を返し、
///   バッファの内容は変更しない（FLUSH バリアの処理は IO-2・TASK-15 の責務）
/// - バッファは設定件数を超えて溜まらない（到達した時点で `push` 内部で
///   自動的にバッチを取り出して返すため、「満杯なのに未 drain」の状態を
///   構造上作らない）
/// - 時間ベースの追い出しは持たない。件数未達のまま残るフレームの扱い
///   （接続終了・FLUSH・滞留量上限）は [`Self::take_pending`] を呼ぶ側
///   （TASK-13.2.2・TASK-15・TASK-16）の責務
pub struct BatchBuffer {
    config: BatchConfig,
    pending: Vec<Frame>,
}

impl BatchBuffer {
    /// 設定からバッファを作る。
    ///
    /// `config.batch_size()` は [`BatchConfig::new`] で `1..=MAX_BATCH_SIZE` に
    /// 検証済みのため、その値でのみ `Vec::with_capacity` を呼ぶ（security.md
    /// 「長さ・件数を上限検証してからアロケーションに使う」）。
    pub fn new(config: BatchConfig) -> Self {
        let pending = Vec::with_capacity(config.batch_size());
        Self { config, pending }
    }

    /// このバッファのバッチ設定を返す。
    pub fn config(&self) -> &BatchConfig {
        &self.config
    }

    /// 現在の滞留件数を返す。
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// バッファが空かどうかを返す。
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// フレームを 1 件バッファへ追加する。
    ///
    /// `frame` が [`FrameKind::Write`] 以外の場合は
    /// [`IoErrorCode::InvalidArgument`] を返し、バッファの内容は変更しない。
    /// 追加後の滞留件数が設定件数（[`BatchConfig::batch_size`]）に到達した場合、
    /// バッファ内のフレームをすべて取り出して [`PushOutcome::Ready`] として返し、
    /// バッファは空の状態（次バッチぶんの容量を確保済み）に戻る。到達しなければ
    /// [`PushOutcome::Buffered`] を返す。
    pub fn push(&mut self, frame: Frame) -> Result<PushOutcome, IoError> {
        if frame.kind() != FrameKind::Write {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "batch buffer accepts only Write frames",
            ));
        }

        self.pending.push(frame);

        if self.pending.len() >= self.config.batch_size() {
            let batch_size = self.config.batch_size();
            let frames = std::mem::replace(&mut self.pending, Vec::with_capacity(batch_size));
            return Ok(PushOutcome::Ready(Batch {
                frames,
                trigger: BatchTrigger::SizeReached,
            }));
        }

        Ok(PushOutcome::Buffered {
            pending: self.pending.len(),
        })
    }

    /// 設定件数未達のまま滞留しているフレームを、あれば強制的に取り出す。
    ///
    /// 呼び出し元（接続終了・FLUSH バリア〔TASK-15〕・滞留量上限〔TASK-16〕）が
    /// 「これ以上フレームが来ない・待てない」と判断した時点で呼ぶことを想定する。
    /// バッファが空の場合は `None` を返す。
    pub fn take_pending(&mut self) -> Option<Batch> {
        if self.pending.is_empty() {
            return None;
        }
        let batch_size = self.config.batch_size();
        let frames = std::mem::replace(&mut self.pending, Vec::with_capacity(batch_size));
        Some(Batch {
            frames,
            trigger: BatchTrigger::Drained,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_frame(seq: u32) -> Frame {
        Frame::new(FrameKind::Write, seq.to_le_bytes().to_vec()).expect("Frame::new must succeed")
    }

    fn frame_seq(frame: &Frame) -> u32 {
        let bytes: [u8; 4] = frame
            .payload()
            .try_into()
            .expect("test payload must be 4 bytes");
        u32::from_le_bytes(bytes)
    }

    /// IO-1: 既定のバッチサイズは 64 件。
    #[test]
    fn io1_batch_config_default_is_64() {
        assert_eq!(BatchConfig::default().batch_size(), 64);
    }

    /// IO-1・REPAIR-2: `0` は拒否される。
    #[test]
    fn io1_batch_config_rejects_zero() {
        let err = BatchConfig::new(0).expect_err("0 must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-2: `MAX_BATCH_SIZE` 超過は拒否される（境界値・`usize::MAX`）。
    #[test]
    fn io1_batch_config_rejects_above_max() {
        let err = BatchConfig::new(MAX_BATCH_SIZE + 1).expect_err("MAX + 1 must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = BatchConfig::new(usize::MAX).expect_err("usize::MAX must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `1` と `MAX_BATCH_SIZE` の境界値は受理され、値が保持される。
    #[test]
    fn io1_batch_config_accepts_boundaries() {
        assert_eq!(
            BatchConfig::new(1)
                .expect("1 must be accepted")
                .batch_size(),
            1
        );
        assert_eq!(
            BatchConfig::new(MAX_BATCH_SIZE)
                .expect("MAX_BATCH_SIZE must be accepted")
                .batch_size(),
            MAX_BATCH_SIZE
        );
    }

    /// IO-1 受け入れ条件 1: 既定 64 件到達で `Ready` が発火し、
    /// 63 件目までは `Buffered` を返す。挿入順・発火後の空リセットも確認する。
    #[test]
    fn io1_batch_buffer_fires_at_default_64() {
        let mut buffer = BatchBuffer::new(BatchConfig::default());

        for seq in 0..63u32 {
            let outcome = buffer.push(write_frame(seq)).expect("push must succeed");
            match outcome {
                PushOutcome::Buffered { pending } => {
                    assert_eq!(pending, (seq + 1) as usize);
                }
                _ => panic!("must not fire before 64 frames (seq={seq})"),
            }
        }
        assert_eq!(buffer.len(), 63);

        let outcome = buffer.push(write_frame(63)).expect("push must succeed");
        let batch = match outcome {
            PushOutcome::Ready(batch) => batch,
            PushOutcome::Buffered { .. } => panic!("must fire at the 64th frame"),
        };

        assert_eq!(batch.len(), 64);
        assert_eq!(batch.trigger(), BatchTrigger::SizeReached);
        let seqs: Vec<u32> = batch.frames().iter().map(frame_seq).collect();
        assert_eq!(seqs, (0..64).collect::<Vec<_>>());
        assert_eq!(buffer.len(), 0);
    }

    /// IO-1 受け入れ条件 2: `BatchConfig::new(8)` で 8 件目に発火する。
    #[test]
    fn io1_batch_buffer_fires_at_custom_size_8() {
        let config = BatchConfig::new(8).expect("8 must be accepted");
        let mut buffer = BatchBuffer::new(config);

        for seq in 0..7u32 {
            let outcome = buffer.push(write_frame(seq)).expect("push must succeed");
            assert!(matches!(outcome, PushOutcome::Buffered { .. }));
        }

        let outcome = buffer.push(write_frame(7)).expect("push must succeed");
        let batch = match outcome {
            PushOutcome::Ready(batch) => batch,
            PushOutcome::Buffered { .. } => panic!("must fire at the 8th frame"),
        };
        assert_eq!(batch.len(), 8);
        assert_eq!(batch.trigger(), BatchTrigger::SizeReached);
    }

    /// IO-1: バッチサイズ 1 は毎回発火する。
    #[test]
    fn io1_batch_buffer_size_1_fires_every_push() {
        let config = BatchConfig::new(1).expect("1 must be accepted");
        let mut buffer = BatchBuffer::new(config);

        for seq in 0..5u32 {
            let outcome = buffer.push(write_frame(seq)).expect("push must succeed");
            let batch = match outcome {
                PushOutcome::Ready(batch) => batch,
                PushOutcome::Buffered { .. } => panic!("size 1 must fire every push"),
            };
            assert_eq!(batch.len(), 1);
            assert_eq!(frame_seq(&batch.frames()[0]), seq);
        }
        assert_eq!(buffer.len(), 0);
    }

    /// IO-1: 既定設定で 130 件投入すると、64 件ずつ 2 回連続で発火し、
    /// 各バッチの内容が連続した挿入順になり、残り 2 件がバッファに残る。
    #[test]
    fn io1_batch_buffer_emits_consecutive_batches() {
        let mut buffer = BatchBuffer::new(BatchConfig::default());
        let mut ready_batches: Vec<Batch> = Vec::new();

        for seq in 0..130u32 {
            match buffer.push(write_frame(seq)).expect("push must succeed") {
                PushOutcome::Ready(batch) => ready_batches.push(batch),
                PushOutcome::Buffered { .. } => {}
            }
        }

        assert_eq!(ready_batches.len(), 2);
        let first_seqs: Vec<u32> = ready_batches[0].frames().iter().map(frame_seq).collect();
        let second_seqs: Vec<u32> = ready_batches[1].frames().iter().map(frame_seq).collect();
        assert_eq!(first_seqs, (0..64).collect::<Vec<_>>());
        assert_eq!(second_seqs, (64..128).collect::<Vec<_>>());
        assert_eq!(buffer.len(), 2);
    }

    /// IO-1: `take_pending` は件数未達分を挿入順のまま `Drained` として返す。
    #[test]
    fn io1_take_pending_returns_partial_batch_in_order() {
        let mut buffer = BatchBuffer::new(BatchConfig::default());
        for seq in 0..3u32 {
            let outcome = buffer.push(write_frame(seq)).expect("push must succeed");
            assert!(matches!(outcome, PushOutcome::Buffered { .. }));
        }

        let batch = buffer
            .take_pending()
            .expect("3 pending frames must be returned");
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.trigger(), BatchTrigger::Drained);
        let seqs: Vec<u32> = batch.frames().iter().map(frame_seq).collect();
        assert_eq!(seqs, vec![0, 1, 2]);

        assert_eq!(buffer.len(), 0);
        assert!(buffer.take_pending().is_none());
    }

    /// IO-1: 空のバッファに対する `take_pending` は `None` を返す。
    #[test]
    fn io1_take_pending_on_empty_returns_none() {
        let mut buffer = BatchBuffer::new(BatchConfig::default());
        assert!(buffer.take_pending().is_none());
    }

    /// IO-1・REPAIR-2: `Write` 以外のフレームは拒否され、バッファの内容は
    /// 変化しない。
    #[test]
    fn io1_push_rejects_non_write_frames() {
        let mut buffer = BatchBuffer::new(BatchConfig::default());
        let outcome = buffer.push(write_frame(0)).expect("push must succeed");
        assert!(matches!(outcome, PushOutcome::Buffered { .. }));
        assert_eq!(buffer.len(), 1);

        for kind in [FrameKind::Ack, FrameKind::Flush, FrameKind::FlushAck] {
            let frame = Frame::new(kind, Vec::new()).expect("Frame::new must succeed");
            let err = buffer
                .push(frame)
                .expect_err("non-Write frame must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            assert_eq!(buffer.len(), 1, "buffer must be unchanged after rejection");
        }
    }

    /// IO-1: `BatchBuffer` はスレッド境界を越えて受け渡せる
    /// （`FrameSender` / `FrameReceiver` と同じ契約。コンパイル時確認）。
    #[test]
    fn io1_batch_buffer_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<BatchBuffer>();
    }
}
