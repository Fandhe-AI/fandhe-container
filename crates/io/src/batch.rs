//! バッチ write-back サーバー（TASK-13）の最初の部品として、受信した書き込み
//! フレームをメモリ内で集約するバッファ（TASK-13.1・IO-1・#76・MS-1）。
//!
//! 本モジュールが持つのは「一定件数（既定 [`DEFAULT_BATCH_SIZE`]）・
//! 一定累積バイト数（既定 [`MAX_BATCH_BYTES`]）ぶんの [`crate::protocol::Frame`]
//! を溜め、件数が上限に到達した時点、または次のフレームを加えると累積バイト数が
//! 上限を超えると判明した時点でバッチ（値）を返す」純粋なメモリ内
//! ロジックのみ。ソケット・スレッド・ディスク書き込み・ACK 返却・タイマーは
//! 一切持たない（REPAIR-3: 実装済みを装わない）。累積バイト数上限は
//! [`BatchBuffer`] 単体が確保し続けるメモリ量そのものを抑える安全弁であり
//! （P0: 無制限確保による DoS の防止）、下記スコープ外の「受信経路」自体の
//! 検証・複数バッファ / 接続を跨いだ滞留量上限とは独立している。
//!
//! # スコープ外（TASK-13 の兄弟 sub-issue が担う）
//! - ディスクへの書き込み実行・ACK フレームの返却（TASK-13.2・TASK-13.2.2）
//! - UDS 接続受付ループ（`server.rs`。TASK-13.2.1）
//! - CLI / 設定からのバッチサイズ・バイト数上限配線（`--batch-size` 相当。TASK-13.3）
//! - 受信フレーム長そのものの検証・複数接続を跨いだ受信経路の DoS 対策
//!   （TASK-13.4）
//! - FLUSH バリアの処理（IO-2・TASK-15）・未フラッシュ滞留量上限（IO-10・TASK-16）
//!
//! # 呼び出し文脈
//! TASK-13.2.1 以降が新設する予定の `server.rs`（UDS 受信ループ）が、受信した
//! `FrameKind::Write` フレームを [`BatchBuffer::push`] へ渡し、[`PushOutcome::Ready`]
//! （まれに [`PushOutcome::ReadyTwice`]。[`BatchBuffer::push`] 参照）が返った
//! バッチをディスク書き込み（TASK-13.2）へ引き渡す想定。接続終了時・
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
/// ペイロード合計バイト数は抑えられない（この累積バイト数の上限は
/// [`MAX_BATCH_BYTES`] が別途担う。受信経路自体の長さ・件数検証は
/// IO-10（TASK-16）・TASK-13.4（#796）の責務であり、本モジュールが持つのは
/// 「1 つの [`BatchBuffer`] インスタンスが確保し続けるメモリ量」自体の上限）。
/// この値自体も TASK-13.3・TASK-13.4・TASK-16・TASK-88（ベンチ校正）で
/// 見直してよい暫定値（REPAIR-3）。
pub const MAX_BATCH_SIZE: usize = 4096;

/// バッチ 1 つあたりの累積ペイロードバイト数の既定上限（P0: 無制限確保による
/// DoS の防止。security.md「長さ・件数を上限検証してからアロケーションに
/// 使う」）。
///
/// [`MAX_BATCH_SIZE`]（4096 件）は 1 フレームあたり最大
/// [`crate::protocol::MAX_PAYLOAD_LEN`]（64 MiB）のペイロードを持つ
/// `Write` フレームを許すため、件数のみの制限では 1 バッファが理論上
/// 約 256 GiB（4096 × 64 MiB）ものペイロードを滞留させられてしまう
/// （#76 PR #1105 codex レビュー指摘）。本定数は [`BatchBuffer`] が
/// 実際にヒープへ保持し続けるバイト数そのものに独立した上限を設け、
/// 件数上限とは別の安全弁として累積量を抑える。
///
/// 256 MiB という値自体は「256 GiB という桁を潰す」以上の根拠を持たない
/// 暫定値であり、実測に基づく校正は IO-10・TASK-13.4・TASK-16・TASK-88
/// の責務（REPAIR-3: 実装済みを装わない）。呼び出し側が独自の上限を
/// 必要とする場合は [`BatchConfig::with_max_bytes`] で個別に指定できる。
pub const MAX_BATCH_BYTES: usize = 256 * 1024 * 1024;

/// [`BatchConfig::with_max_bytes`] が受理する累積ペイロードバイト数上限の
/// 安全な最大値（P0: PR #1105 codex レビュー指摘。無制限確保による DoS の
/// 防止）。
///
/// [`with_max_bytes`](BatchConfig::with_max_bytes) は呼び出し側が既定
/// [`MAX_BATCH_BYTES`] と異なる `max_bytes` を個別指定できる抜け道を持つが、
/// `max_bytes == 0` のみを拒否し上限を設けないと、[`MAX_BATCH_SIZE`]
/// （4096 件）× [`crate::protocol::MAX_PAYLOAD_LEN`]（64 MiB）≒ 256 GiB
/// もの滞留を公開設定 API 経由で許してしまい、既定 [`MAX_BATCH_BYTES`]
/// による DoS 防御を実質的に無効化できる。本定数は「独自の上限を必要とする
/// 呼び出し側の柔軟性」と「無制限確保の防止」を両立させるため、既定値
/// （256 MiB）の 4 倍を安全な上限として個別設定を許す範囲を区切る。
///
/// この係数（4 倍）自体も [`MAX_BATCH_BYTES`] 同様、実測に基づく校正では
/// なく「桁を潰す」以上の根拠を持たない暫定値であり、見直しは
/// [`MAX_BATCH_BYTES`] と同じ TASK-13.3・TASK-13.4・TASK-16・TASK-88
/// （ベンチ校正）の責務（REPAIR-3: 実装済みを装わない）。
pub const MAX_ALLOWED_BATCH_BYTES: usize = MAX_BATCH_BYTES * 4;

// DEFAULT_BATCH_SIZE は 1..=MAX_BATCH_SIZE の範囲内でなければならない不変条件を
// コンパイル時に保証する（`protocol.rs` の `MAX_PAYLOAD_LEN < u32::MAX` と同種の
// パターン）。これにより `BatchConfig::default()` 実装（`Self::new(...).expect(...)`）
// が将来 MAX_BATCH_SIZE の変更で実行時パニックへ化けることを防ぐ。
const _: () = assert!(DEFAULT_BATCH_SIZE >= 1 && DEFAULT_BATCH_SIZE <= MAX_BATCH_SIZE);

// MAX_BATCH_BYTES は非ゼロであり、かつ MAX_ALLOWED_BATCH_BYTES（`with_max_bytes`
// が個別設定を許す上限）の範囲内でなければならない不変条件をコンパイル時に
// 保証する（既定値そのものが個別設定の上限を超えて `with_max_bytes` から
// 拒否される、という自己矛盾を防ぐ）。
const _: () = assert!(MAX_BATCH_BYTES > 0 && MAX_BATCH_BYTES <= MAX_ALLOWED_BATCH_BYTES);

// MAX_ALLOWED_BATCH_BYTES 自体が usize の乗算でオーバーフローしないことを
// コンパイル時に保証する（`MAX_BATCH_BYTES * 4` は 32bit usize では
// オーバーフローし得るため、`checked_mul` 相当の検証をコンパイル時に行う）。
const _: () = assert!(MAX_ALLOWED_BATCH_BYTES / 4 == MAX_BATCH_BYTES);

/// [`BatchBuffer`] の集約単位（件数・累積バイト数）を表す設定値（IO-1）。
///
/// 非公開フィールドに `NonZeroUsize` を持ち、[`Self::new`] /
/// [`Self::with_max_bytes`] を経由しない限り `1..=MAX_BATCH_SIZE`（件数）・
/// `1..=MAX_ALLOWED_BATCH_BYTES`（累積バイト数。P0: PR #1105 codex
/// レビュー指摘を受け `usize::MAX` を含む無制限の値は拒否する）の範囲外の
/// 値を表現できない（REPAIR-2: 壊れた値を表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchConfig {
    batch_size: NonZeroUsize,
    max_bytes: NonZeroUsize,
}

impl BatchConfig {
    /// `batch_size` からバッチ設定を作る。累積バイト数上限は既定
    /// [`MAX_BATCH_BYTES`] を使う。
    ///
    /// `0` または [`MAX_BATCH_SIZE`] を超える値は
    /// [`IoErrorCode::InvalidArgument`] として拒否する。
    pub fn new(batch_size: usize) -> Result<Self, IoError> {
        Self::with_max_bytes(batch_size, MAX_BATCH_BYTES)
    }

    /// `batch_size`・累積ペイロードバイト数上限（`max_bytes`）を指定して
    /// バッチ設定を作る（P0: 無制限確保による DoS の防止。呼び出し側〔TASK-13.3
    /// の `--batch-size` 相当の配線・TASK-16 の滞留量上限〕が既定
    /// [`MAX_BATCH_BYTES`] と異なる上限を必要とする場合に使う）。
    ///
    /// `batch_size` が `0` または [`MAX_BATCH_SIZE`] を超える値、
    /// あるいは `max_bytes` が `0` または [`MAX_ALLOWED_BATCH_BYTES`] を
    /// 超える値の場合は [`IoErrorCode::InvalidArgument`] として拒否する
    /// （P0: PR #1105 codex レビュー指摘。`max_bytes` に上限を設けない場合
    /// [`MAX_ALLOWED_BATCH_BYTES`] のドキュメンテーションコメント参照の
    /// とおり本関数が無制限確保による DoS 防御の抜け道になってしまう）。
    pub fn with_max_bytes(batch_size: usize, max_bytes: usize) -> Result<Self, IoError> {
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
        if max_bytes == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "max batch bytes must be at least 1",
            ));
        }
        if max_bytes > MAX_ALLOWED_BATCH_BYTES {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("max batch bytes must be at most {MAX_ALLOWED_BATCH_BYTES}"),
            ));
        }
        // 上の分岐で 1..=MAX_BATCH_SIZE・1..=MAX_ALLOWED_BATCH_BYTES の範囲を
        // 確認済みのため、以下の NonZeroUsize::new は必ず Some を返す。
        let batch_size = NonZeroUsize::new(batch_size)
            .ok_or_else(|| IoError::new(IoErrorCode::Internal, "unexpected zero batch size"))?;
        let max_bytes = NonZeroUsize::new(max_bytes)
            .ok_or_else(|| IoError::new(IoErrorCode::Internal, "unexpected zero max bytes"))?;
        Ok(Self {
            batch_size,
            max_bytes,
        })
    }

    /// 検証済みのバッチサイズを返す。
    pub fn batch_size(&self) -> usize {
        self.batch_size.get()
    }

    /// 検証済みの累積ペイロードバイト数上限を返す。
    pub fn max_bytes(&self) -> usize {
        self.max_bytes.get()
    }
}

impl Default for BatchConfig {
    /// IO-1 の既定値（[`DEFAULT_BATCH_SIZE`] = 64・[`MAX_BATCH_BYTES`]）を使う。
    fn default() -> Self {
        // 上記の `const _: () = assert!(...)` により DEFAULT_BATCH_SIZE は
        // 1..=MAX_BATCH_SIZE 範囲内、MAX_BATCH_BYTES は非ゼロであることが
        // コンパイル時に保証されているため、この expect は到達不能であり
        // 実行時パニックにはならない。
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
    /// 次のフレームを加えると累積ペイロードバイト数が上限
    /// （[`BatchConfig::max_bytes`]）を超えると判明し、そのフレームを加える前に
    /// 既存の滞留分が件数未達のまま自動発火した（P0: 無制限確保による DoS の
    /// 防止）。累積が上限と厳密に等しい場合はまだ発火しない（`>` であり `>=`
    /// ではない。[`BatchBuffer::push`] 参照）。
    BytesLimitReached,
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
    /// 設定件数、またはバイト数上限のいずれか一方に到達し、バッチが発火した。
    Ready(Batch),
    /// バイト数上限で既存の滞留分（`.0`。[`BatchTrigger::BytesLimitReached`]）
    /// が発火した直後、その場で積んだ新フレーム単体が設定件数
    /// （[`BatchConfig::batch_size`]）にも到達している場合、新バッチ（`.1`。
    /// [`BatchTrigger::SizeReached`]）も同じ `push` 呼び出し内で即座に発火した
    /// ことを表す（#76 PR #1105 codex レビュー指摘の P1 を受けた型設計:
    /// `Ready` だけでは 1 回の `push` が発火させる 2 つのバッチを表現できず、
    /// 新バッチを捨てるか誤って `Buffered` 扱いする経路をコンパイラで塞げない
    /// ため、専用バリアントとして両方を呼び出し側へ確実に渡す）。
    ///
    /// [`BatchBuffer::push`] の実装注記のとおり、1 回の呼び出しが 1 フレームの
    /// みを受け付ける現行の契約下ではこの分岐に到達する時点で既に
    /// `batch_size >= 2` が成立しており、発火直後にリセットされた `pending` へ
    /// 積まれる新フレームは常に 1 件のみで `batch_size` 未満のため、本バリアント
    /// は今日の実装では生成されない。将来 `push` が複数フレームをまとめて
    /// 受け付けるよう拡張された場合に備えて型として用意する。
    ///
    /// 生成された場合、呼び出し側は `.0` → `.1` の順（挿入順）で両方を必ず
    /// 処理しなければならない。`.1` を捨てると新バッチのフレームが以後の
    /// `push` 呼び出しがない限り滞留し続ける。
    ReadyTwice(Batch, Batch),
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
/// - バッファは累積ペイロードバイト数（[`BatchConfig::max_bytes`]。既定
///   [`MAX_BATCH_BYTES`]）も超えて溜まらない。新しいフレームを加えると
///   上限を超える場合は、そのフレームを加える前に既存の滞留分を
///   [`BatchTrigger::BytesLimitReached`] として強制発火させる（P0: 無制限
///   確保による DoS の防止。件数上限とは独立した安全弁）
/// - 時間ベースの追い出しは持たない。件数未達のまま残るフレームの扱い
///   （接続終了・FLUSH・滞留量上限）は [`Self::take_pending`] を呼ぶ側
///   （TASK-13.2.2・TASK-15・TASK-16）の責務
pub struct BatchBuffer {
    config: BatchConfig,
    pending: Vec<Frame>,
    /// `pending` 内の全フレームのペイロードバイト数の合計
    /// （[`BatchConfig::max_bytes`] との比較に使う。`pending` から独立して
    /// 保持することで、push のたびに `pending` 全体を走査し直す必要をなくす）。
    pending_bytes: usize,
}

impl BatchBuffer {
    /// 設定からバッファを作る。
    ///
    /// `config.batch_size()` は [`BatchConfig::new`] で `1..=MAX_BATCH_SIZE` に
    /// 検証済みのため、その値でのみ `Vec::with_capacity` を呼ぶ（security.md
    /// 「長さ・件数を上限検証してからアロケーションに使う」）。
    pub fn new(config: BatchConfig) -> Self {
        let pending = Vec::with_capacity(config.batch_size());
        Self {
            config,
            pending,
            pending_bytes: 0,
        }
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

    /// 現在の滞留ペイロードバイト数の合計を返す（[`BatchConfig::max_bytes`]
    /// との比較対象。REPAIR-4: 可観測性）。
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// `pending` を空の新しいバッファへ差し替え、それまでの内容を `trigger`
    /// 付きの [`Batch`] として取り出す共通処理（`push` の件数 / バイト数上限
    /// 到達・`take_pending` の 3 箇所から呼ばれる）。`pending_bytes` も
    /// 合わせて `0` へリセットする。
    fn drain_pending(&mut self, trigger: BatchTrigger) -> Batch {
        let batch_size = self.config.batch_size();
        let frames = std::mem::replace(&mut self.pending, Vec::with_capacity(batch_size));
        self.pending_bytes = 0;
        Batch { frames, trigger }
    }

    /// フレームを 1 件バッファへ追加する。
    ///
    /// `frame` が [`FrameKind::Write`] 以外の場合は
    /// [`IoErrorCode::InvalidArgument`] を返し、バッファの内容は変更しない。
    ///
    /// `frame` 単体のペイロード長が設定上限（[`BatchConfig::max_bytes`]）を
    /// 超える場合も同様に [`IoErrorCode::InvalidArgument`] を返し、バッファの
    /// 内容は変更しない（P0・PR #1105 codex レビュー指摘: `max_bytes` は
    /// [`BatchConfig::with_max_bytes`] で [`crate::protocol::MAX_PAYLOAD_LEN`]
    /// より小さい値へ個別設定できるため、「1 フレーム自体の長さは
    /// `MAX_PAYLOAD_LEN` で別途検証済みだから単独のフレームが理由で拒否され
    /// ない」という前提は既定設定でしか成り立たない。`pending` が空だからと
    /// 上限超過フレームをそのまま積むと、[`Self::pending_bytes`] が
    /// `max_bytes` を上回った状態を作ってしまい、本フィールドが担う
    /// 「無制限確保による DoS の防止」という安全弁の契約を破る）。
    ///
    /// 上記 2 つの拒否条件のいずれにも当てはまらない場合、このフレームを
    /// 加えると累積ペイロードバイト数が `max_bytes` を超えると判明した
    /// 場合（かつ既に滞留分がある場合）は、そのフレームを加える前に既存の
    /// 滞留分を [`BatchTrigger::BytesLimitReached`] な [`Batch`] として強制的に
    /// 取り出し、渡された `frame` は空になったバッファへ新たに積む。この時点で
    /// `frame` 単体により滞留件数が設定件数（[`BatchConfig::batch_size`]）に
    /// 到達した場合は、その新バッチも [`BatchTrigger::SizeReached`] として
    /// 同じ呼び出し内で即座に発火させ、両方を [`PushOutcome::ReadyTwice`]
    /// として返す（IO-1 の「設定件数到達時に発火する」契約を、バイト数上限
    /// 発火の直後でも型として保証するため。#76 PR #1105 codex レビュー指摘の
    /// P1 を受けた対応）。ただし、この分岐に到達する時点で既に
    /// `pending` が非空だった（＝直前の呼び出しで `Buffered` を返していた）
    /// ことが前提となるため、`batch_size >= 2` が既に成立しており、ここで
    /// リセット後に積まれる新フレームは常に 1 件のみで `batch_size` に満たない
    /// （テスト `io1_bytes_limit_flush_never_reaches_size_limit_in_same_push`
    /// 参照）。到達していなければ新フレームは次回以降の呼び出しで扱われ、旧バッチ
    /// のみを [`PushOutcome::Ready`] として返す（P0: 無制限確保による DoS
    /// の防止）。
    ///
    /// 上記のバイト数上限に抵触せず追加できた場合、追加後の滞留件数が設定件数
    /// （[`BatchConfig::batch_size`]）に到達したときも同様にバッファ内の
    /// フレームをすべて [`BatchTrigger::SizeReached`] として取り出して返し、
    /// バッファは空の状態（次バッチぶんの容量を確保済み）に戻る。
    /// どの上限にも到達しなければ [`PushOutcome::Buffered`] を返す。
    pub fn push(&mut self, frame: Frame) -> Result<PushOutcome, IoError> {
        if frame.kind() != FrameKind::Write {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "batch buffer accepts only Write frames",
            ));
        }

        let frame_len = frame.payload().len();

        if frame_len > self.config.max_bytes() {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "frame payload length {frame_len} exceeds configured max_bytes {}",
                    self.config.max_bytes()
                ),
            ));
        }

        if !self.pending.is_empty()
            && self.pending_bytes.saturating_add(frame_len) > self.config.max_bytes()
        {
            let flushed = self.drain_pending(BatchTrigger::BytesLimitReached);
            self.pending.push(frame);
            self.pending_bytes = frame_len;

            // 新フレーム単体が設定件数に既に到達している場合、ここで return
            // してしまうと新バッチが Ready にならないまま滞留し続け、以後
            // push が呼ばれるまで IO-1 の件数到達契約を破りかねない
            // （#76 PR #1105 codex レビュー指摘の P1）。この分岐に到達する
            // 時点で batch_size >= 2 が既に成立しているため（push の
            // ドキュメンテーションコメント参照）、今日の実装では
            // self.pending.len() は常に 1 でこの if は成立しないが、
            // 型の契約として両方の発火を ReadyTwice で表現できるようにする。
            if self.pending.len() >= self.config.batch_size() {
                let second = self.drain_pending(BatchTrigger::SizeReached);
                return Ok(PushOutcome::ReadyTwice(flushed, second));
            }

            return Ok(PushOutcome::Ready(flushed));
        }

        self.pending.push(frame);
        self.pending_bytes = self.pending_bytes.saturating_add(frame_len);

        if self.pending.len() >= self.config.batch_size() {
            let batch = self.drain_pending(BatchTrigger::SizeReached);
            return Ok(PushOutcome::Ready(batch));
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
        Some(self.drain_pending(BatchTrigger::Drained))
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
            PushOutcome::Buffered { .. } | PushOutcome::ReadyTwice(..) => {
                panic!("must fire at the 64th frame")
            }
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
            PushOutcome::Buffered { .. } | PushOutcome::ReadyTwice(..) => {
                panic!("must fire at the 8th frame")
            }
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
                PushOutcome::Buffered { .. } | PushOutcome::ReadyTwice(..) => {
                    panic!("size 1 must fire every push")
                }
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
                PushOutcome::ReadyTwice(first, second) => {
                    ready_batches.push(first);
                    ready_batches.push(second);
                }
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

    /// `frame` を指定バイト数のペイロードで作る（`write_frame` と異なり、
    /// バイト数上限のテストでは中身ではなくペイロード長のみが意味を持つ）。
    fn write_frame_of_len(len: usize) -> Frame {
        Frame::new(FrameKind::Write, vec![0u8; len]).expect("Frame::new must succeed")
    }

    /// P0（PR #1105 codex 指摘）・REPAIR-2: `max_bytes` に `0` は拒否される。
    #[test]
    fn batch_config_rejects_zero_max_bytes() {
        let err = BatchConfig::with_max_bytes(DEFAULT_BATCH_SIZE, 0)
            .expect_err("max_bytes == 0 must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// P0（PR #1105 codex 指摘）: `max_bytes` に `usize::MAX` を渡しても、
    /// `MAX_BATCH_SIZE`（4096 件）× `MAX_PAYLOAD_LEN`（64 MiB）≒ 256 GiB もの
    /// 滞留を許す設定は成立せず、[`MAX_ALLOWED_BATCH_BYTES`] を超える値として
    /// 拒否される（無制限確保による DoS 防御が公開設定 API から外せないことの
    /// 回帰テスト）。
    #[test]
    fn batch_config_rejects_max_bytes_above_allowed_ceiling() {
        let err = BatchConfig::with_max_bytes(DEFAULT_BATCH_SIZE, usize::MAX)
            .expect_err("max_bytes above MAX_ALLOWED_BATCH_BYTES must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// P0: `max_bytes` にちょうど [`MAX_ALLOWED_BATCH_BYTES`] を指定した境界値は
    /// 拒否されず、通常どおり設定として成立する。
    #[test]
    fn batch_config_accepts_max_bytes_exactly_at_allowed_ceiling() {
        let config = BatchConfig::with_max_bytes(DEFAULT_BATCH_SIZE, MAX_ALLOWED_BATCH_BYTES)
            .expect("max_bytes exactly at MAX_ALLOWED_BATCH_BYTES must be accepted");
        assert_eq!(config.max_bytes(), MAX_ALLOWED_BATCH_BYTES);
    }

    /// P0: `max_bytes` に [`MAX_ALLOWED_BATCH_BYTES`] を 1 バイトでも超える値は
    /// 拒否される（境界値テスト）。
    #[test]
    fn batch_config_rejects_max_bytes_one_above_allowed_ceiling() {
        let err = BatchConfig::with_max_bytes(DEFAULT_BATCH_SIZE, MAX_ALLOWED_BATCH_BYTES + 1)
            .expect_err("max_bytes one byte above MAX_ALLOWED_BATCH_BYTES must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// P0: 既定設定の `max_bytes` は [`MAX_BATCH_BYTES`] に一致する。
    #[test]
    fn batch_config_default_max_bytes_is_max_batch_bytes() {
        assert_eq!(BatchConfig::default().max_bytes(), MAX_BATCH_BYTES);
    }

    /// P0（PR #1105 codex 指摘）: 累積バイト数が `max_bytes` を超える手前
    /// （境界値ちょうど）までは `Buffered` のまま滞留し、超える 1 件目で
    /// それまでの滞留分が `BytesLimitReached` として発火する。件数上限
    /// （[`MAX_BATCH_SIZE`]）には遠く及ばない設定でも、バイト数だけを理由に
    /// 発火することを確認する。
    #[test]
    fn batch_buffer_fires_on_bytes_limit_before_size_limit() {
        // batch_size は十分大きく、bytes 側の上限（10 バイト）だけが効くように
        // する。1 件 4 バイトのフレームを 2 件（計 8 バイト）までは収まり、
        // 3 件目（計 12 バイト）で 10 バイトを超えるため、3 件目の push で
        // 直前までの 2 件が BytesLimitReached として発火する。
        let config =
            BatchConfig::with_max_bytes(MAX_BATCH_SIZE, 10).expect("valid config must succeed");
        let mut buffer = BatchBuffer::new(config);

        let outcome = buffer
            .push(write_frame_of_len(4))
            .expect("push must succeed");
        assert!(matches!(outcome, PushOutcome::Buffered { pending: 1 }));
        assert_eq!(buffer.pending_bytes(), 4);

        let outcome = buffer
            .push(write_frame_of_len(4))
            .expect("push must succeed");
        assert!(matches!(outcome, PushOutcome::Buffered { pending: 2 }));
        assert_eq!(buffer.pending_bytes(), 8);

        // 3 件目（計 12 バイト）は上限 10 バイトを超えるため、追加前に
        // それまでの 2 件が発火する。3 件目自体はリセット後の新しいバッファへ
        // 積まれ、失われない。
        let outcome = buffer
            .push(write_frame_of_len(4))
            .expect("push must succeed");
        let batch = match outcome {
            PushOutcome::Ready(batch) => batch,
            PushOutcome::Buffered { .. } | PushOutcome::ReadyTwice(..) => {
                panic!("bytes limit must fire before size limit")
            }
        };
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.trigger(), BatchTrigger::BytesLimitReached);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.pending_bytes(), 4);

        // 発火後もフレームは失われず、次の take_pending で回収できる。
        let drained = buffer
            .take_pending()
            .expect("the 3rd frame must remain buffered");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained.trigger(), BatchTrigger::Drained);
    }

    /// P0: 累積バイト数がちょうど `max_bytes` に達する境界値では、まだ
    /// 上限を超えていないため発火しない（`>` であり `>=` ではない）。
    #[test]
    fn batch_buffer_does_not_fire_when_bytes_exactly_at_limit() {
        let config =
            BatchConfig::with_max_bytes(MAX_BATCH_SIZE, 8).expect("valid config must succeed");
        let mut buffer = BatchBuffer::new(config);

        let first_outcome = buffer
            .push(write_frame_of_len(4))
            .expect("push must succeed");
        assert!(matches!(
            first_outcome,
            PushOutcome::Buffered { pending: 1 }
        ));
        let outcome = buffer
            .push(write_frame_of_len(4))
            .expect("push must succeed");
        // 累積 8 バイト = 上限 8 バイトちょうど。超過ではないため発火しない。
        assert!(matches!(outcome, PushOutcome::Buffered { pending: 2 }));
        assert_eq!(buffer.pending_bytes(), 8);
    }

    /// P0: 1 件のフレーム単体が `max_bytes` を超える場合、
    /// フレームは分割できないため、追加前に `InvalidArgument` で拒否する
    /// （バッファへは反映しない）。
    #[test]
    fn batch_buffer_rejects_single_frame_larger_than_max_bytes() {
        // P1（PR #1105 codex レビュー指摘）: `pending` が空でも、フレーム単体の
        // ペイロード長が `max_bytes` を超える場合は追加前に拒否し、累積バイト数
        // 上限の契約（無制限確保による DoS の防止）を破らない。
        let config =
            BatchConfig::with_max_bytes(MAX_BATCH_SIZE, 4).expect("valid config must succeed");
        let mut buffer = BatchBuffer::new(config);

        let err = buffer
            .push(write_frame_of_len(100))
            .expect_err("single frame exceeding max_bytes must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        // 拒否されたフレームはバッファへ反映されない。
        assert!(buffer.is_empty());
        assert_eq!(buffer.pending_bytes(), 0);
    }

    /// P1（PR #1105 codex レビュー指摘）: フレーム単体の長さがちょうど
    /// `max_bytes` に一致する境界値は拒否されず、通常どおり滞留する。
    #[test]
    fn batch_buffer_accepts_single_frame_exactly_at_max_bytes() {
        let config =
            BatchConfig::with_max_bytes(MAX_BATCH_SIZE, 4).expect("valid config must succeed");
        let mut buffer = BatchBuffer::new(config);

        let outcome = buffer
            .push(write_frame_of_len(4))
            .expect("frame exactly at max_bytes must be accepted");
        assert!(matches!(outcome, PushOutcome::Buffered { pending: 1 }));
        assert_eq!(buffer.pending_bytes(), 4);
    }

    /// IO-1・P1（PR #1105 codex レビュー指摘の対応。[`PushOutcome::ReadyTwice`]
    /// を参照）: `push` はバイト数上限で旧バッチを発火させた直後、その場で
    /// 積んだ新フレーム単体が設定件数にも到達していれば `ReadyTwice` で両方を
    /// 返す契約を持つ。ただし現行 `push` は 1 回の呼び出しで 1 フレームしか
    /// 積まないため、この分岐（`!self.pending.is_empty()`）に到達する時点で
    /// 既に `batch_size >= 2` が成立しており（`batch_size == 1` は毎回即座に
    /// [`BatchTrigger::SizeReached`] で発火し `pending` が空でない状態を作れない。
    /// [`io1_batch_buffer_size_1_fires_every_push`] が既に確認済み）、
    /// 発火直後にリセットした `pending` へ積まれるのは常にこの新フレーム 1 件
    /// のみで `1 < batch_size` が保たれる。したがって今日の実装では
    /// `ReadyTwice` は理論上到達不能で、常に `Ready` 単体（`.len() == 1`）が
    /// 返ることを、複数の `batch_size` で機械的に確認する。将来 `push` が
    /// 複数フレームをまとめて受け付けるよう拡張された場合に、この不変条件が
    /// 崩れたことを検知する回帰点として置く。
    #[test]
    fn io1_bytes_limit_flush_never_reaches_size_limit_in_same_push() {
        for batch_size in 2..=4usize {
            let config =
                BatchConfig::with_max_bytes(batch_size, 4).expect("valid config must succeed");
            let mut buffer = BatchBuffer::new(config);

            let outcome = buffer
                .push(write_frame_of_len(4))
                .expect("push must succeed");
            assert!(
                matches!(outcome, PushOutcome::Buffered { pending: 1 }),
                "batch_size={batch_size}: 1st push must buffer, got {outcome:?}"
            );

            // 2 件目（4 バイト）: 累積 8 バイトは上限 4 バイトを超えるため、
            // 追加前に 1 件目が BytesLimitReached として発火する。
            let outcome = buffer
                .push(write_frame_of_len(4))
                .expect("push must succeed");
            match outcome {
                PushOutcome::Ready(batch) => {
                    assert_eq!(batch.len(), 1);
                    assert_eq!(batch.trigger(), BatchTrigger::BytesLimitReached);
                }
                other => panic!(
                    "batch_size={batch_size}: bytes limit must fire alone here, got {other:?}"
                ),
            }
            // 新フレームはリセット後の pending へ 1 件だけ積まれ、
            // batch_size(>=2) に満たないため滞留し続ける。
            assert_eq!(buffer.len(), 1);
        }
    }

    /// P0: バイト数上限（暫定 256 GiB 規模の DoS）に対する回帰確認として、
    /// `MAX_BATCH_SIZE`（4096 件）× 1 フレーム最大長
    /// （[`crate::protocol::MAX_PAYLOAD_LEN`] = 64 MiB）の理論上の最大滞留量が
    /// 既定 [`MAX_BATCH_BYTES`]（256 MiB）を大きく上回ること（＝件数上限のみでは
    /// 抑止できないこと）を明示し、既定設定がその桁を実際に縮小することを
    /// 数値で確認する。
    #[test]
    fn max_batch_bytes_bounds_worst_case_far_below_size_only_limit() {
        let worst_case_size_only_bytes =
            MAX_BATCH_SIZE as u128 * crate::protocol::MAX_PAYLOAD_LEN as u128;
        assert!(worst_case_size_only_bytes > 200 * 1024 * 1024 * 1024); // 約 256 GiB
        assert!((MAX_BATCH_BYTES as u128) < worst_case_size_only_bytes);
        assert_eq!(MAX_BATCH_BYTES, 256 * 1024 * 1024);
    }
}
