//! サーバーのファイル操作接続 `serve_file_connection`（IO-1・IO-5・F3・F6〜F11。#3163）。
//!
//! # 役割
//! v1 の `Write` はパスを持たず、1 接続が 1 つの [`crate::writeback::BatchSink`] に固定される。
//! 本モジュールは v2 のファイル操作要求（`Create`・`WriteFile`・`Close`。#3161 で符号化と復号を
//! 実装済み）を受ける「ファイル操作モード」で、1 本の接続から多数のファイルを作って書く。
//! 作成は [`crate::guest_files::GuestFileCreator`]（共有ルート配下への閉じ込めと
//! 大文字小文字・NFC / NFD の衝突検出）へ委ね、ワイヤーのパスを `Path::join` へ渡さない。
//!
//! # 呼び出し文脈
//! [`crate::server::UdsServer`] / [`crate::vsock::VsockServer`] が accept した 1 接続
//! （`FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>`）を受けて呼ぶ。受付ループ・
//! 同時接続数の上限は呼び出し側の責務。単一 sink モードの
//! [`crate::writeback::serve_connection`] とは別の入口で、両者の挙動は互いに影響しない（F11）。
//!
//! # 受理する種別（F3）
//! `Create`・`WriteFile`・`Close`・`Flush` だけ。`Write` と、クライアントが送るべきでない
//! `Ack`・`FlushAck`・`Nack` は接続全体の `InvalidArgument` で終える。
//!
//! # ハンドルと順序（F6・F7）
//! ハンドルは `Create` の request id そのもので、接続ごとの表（上限 [`MaxOpenFiles`]）に持つ。
//! 失敗した `Create` の id は表に入れない。バッチは受信順に 1 件ずつ実行し、応答（`Ack` /
//! `Nack`）も受信順に返す。
//!
//! # ACK の意味と失敗の分類（F8・F10）
//! `Ack` は「バッファリング（OS の `write` 発行）時点」の保証で、永続化は保証しない。`Close` の
//! `Ack` はハンドルの解放だけを意味する。要求単位の失敗（パス構文・衝突・祖先・未知ハンドル・
//! 開けるファイル数の上限）は `Nack`（code と reason だけ。パス等は載せない）を返して接続を
//! 続ける。それ以外（`WriteFile` の I/O 失敗 ENOSPC・EIO を含む。内部エラー・ロックの poison・
//! 再検証や取り消しの失敗・送受信の失敗・プロトコル違反）は接続全体の失敗で、**そのバッチの
//! 応答を 1 件も送らず**に終える。実行相と送信相を分けているのはこのためで、実行済みの
//! `Create` / `WriteFile` の結果は「不定」になりうる（`write_batch` の D6 と同じ意味論）。
//! request id は接続内で単調増加（F6）。重複・逆戻り（Close 後の同じ id の `Create` を含む）は
//! 副作用の前にプロトコル違反（接続全体の `InvalidArgument`）で終える。Nack になった要求の id も消費する。
//!
//! # 受信上限（`pending_frames = 0` の不変条件）
//! 実行は同期で、`Ready` になったバッチをその場で実行・応答してから次を受信する。受信層の
//! `ReceiveLimits::admit` に渡す `pending_frames = 0` は構造上正確で、`writeback` と同じ前提。
//!
//! # FLUSH と自動フラッシュ（IO-2・IO-10・F9。#3164）
//! 明示 `Flush` は、滞留分を実行して応答を送った後、**同じ接続で `Flush` より前に `Ack` を返した
//! 要求すべて**（作成したファイルとその祖先のエントリ、`WriteFile` のデータとメタデータ。`Close`
//! 済みも含む）を永続化し、成功したときだけ `FlushAck` を返して接続を続ける。別の接続・`Nack` した
//! 要求・`Flush` より後の要求は範囲外。
//!
//! - Linux: 接続ごと・デバイス（`st_dev`）ごとの番兵 fd を、最初の `mkdir` / ファイル作成の直前に
//!   新しく開いて表に入れ（[`crate::guest_files::GuestFileCreator`] の `pre_mutation`）、FLUSH では
//!   デバイスごとに 1 回 `syncfs(番兵)` を発行する。番兵を書き込みより前に開くので、
//!   それ以前に起きた書き戻しエラーの報告を取りこぼさない。デバイス数の上限は
//!   `MAX_SENTINEL_DEVICES`（16）（超えた `Create` は何も作らず `DeviceLimit` の `Nack`）。5.8 未満の
//!   カーネルは `Unimplemented`。
//! - macOS / Windows: 汚れたファイル（開いているもの・保持中の `Close` 済みのもの）ごとに
//!   `F_FULLFSYNC` / `FlushFileBuffers`、親ディレクトリのハンドルも同期する（デバイス単位の
//!   最適化は範囲外）。
//! - `Close` 済みで未永続化のファイルは次の永続化まで保持する（上限 [`MaxRetainedDirtyFiles`]）。
//!   上限に達すると IO-10 と同じ自動フラッシュ（`FlushAck` なし）を行う。判定はバッチの実行後に
//!   行うため、1 バッチ内で一時的に上限を超えうる。
//! - 1 回の FLUSH 全体を `flush_timeout`（既定 10 秒）と `MaxConcurrentPersist` の 1 枠の中で
//!   1 本の helper スレッドが順に実行する。発行後の失敗・期限切れ・未対応は `FlushAck` を返さず
//!   接続全体の失敗で終える（状態を破棄。fail-closed）。
//! - 書き込みを挟まない連続 FLUSH は同期を起動せず `FlushAck` を返す（FS 全体の同期を増幅
//!   させない。単一 sink モードの合流と同じ）。
//!
//! IO-10 は `Create`・`WriteFile`・`Close` を 1 フレームずつ数える。上限（フレーム数・バイト数）に
//! 達する前に滞留分を実行して永続化し、`FlushAck` を送らずに計数を 0 へ戻して接続を続ける。
//! 各 sink の `persist()` は呼ばず、接続単位で 1 回にまとめる。

use std::collections::HashMap;
use std::fs::File;

use crate::barrier::{
    PersistLimiter, PersistSupport, PersistTargets, UnflushedBacklog, UnflushedLimit,
    default_persist_limiter, persist_connection, persist_support,
};
use crate::batch::{Batch, BatchBuffer, BatchConfig, PushOutcome};
use crate::error::{IoError, IoErrorCode};
use crate::guest_files::{CreateFailure, GuestFileCreator, classify_create_failure};
use crate::instrument::{IoOpKind, IoOpRecorder, IoOpTimer, NoopIoOpRecorder};
use crate::payload::{
    NackCode, NackReason, decode_close, decode_create, decode_nack, decode_request,
    decode_write_file, encode_ack, encode_nack,
};
use crate::protocol::{Frame, FrameKind};
use crate::transport::{FrameReceiver, FrameSender, IoTimeout, MAX_IO_TIMEOUT};
use crate::writeback::{AppendFileSink, WritebackTimeouts};

/// 同時に開いておけるファイル数の既定値。
pub const DEFAULT_MAX_OPEN_FILES: usize = 256;

/// [`MaxOpenFiles::new`] が受け付ける最大値（fd 枯渇による DoS を防ぐ。暫定値）。
pub const MAX_MAX_OPEN_FILES: usize = 4096;

const _: () = assert!(DEFAULT_MAX_OPEN_FILES >= 1 && DEFAULT_MAX_OPEN_FILES <= MAX_MAX_OPEN_FILES);

/// 1 接続で同時に開いておけるファイル数の上限（F6）。範囲外の値を表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaxOpenFiles(usize);

impl MaxOpenFiles {
    /// `1..=`[`MAX_MAX_OPEN_FILES`] を受け付ける。範囲外は [`IoErrorCode::InvalidArgument`]。
    pub fn new(value: usize) -> Result<Self, IoError> {
        if value == 0 || value > MAX_MAX_OPEN_FILES {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("max open files must be in 1..={MAX_MAX_OPEN_FILES}"),
            ));
        }
        Ok(Self(value))
    }

    /// 上限値。
    pub fn get(self) -> usize {
        self.0
    }
}

impl Default for MaxOpenFiles {
    fn default() -> Self {
        Self(DEFAULT_MAX_OPEN_FILES)
    }
}

/// `Close` 済みで未永続化のファイルを保持しておける数の既定値（F9）。
pub const DEFAULT_MAX_RETAINED_DIRTY_FILES: usize = 1024;

/// [`MaxRetainedDirtyFiles::new`] が受け付ける最大値（fd 枯渇による DoS を防ぐ。暫定値）。
pub const MAX_MAX_RETAINED_DIRTY_FILES: usize = 4096;

const _: () = assert!(
    DEFAULT_MAX_RETAINED_DIRTY_FILES >= 1
        && DEFAULT_MAX_RETAINED_DIRTY_FILES <= MAX_MAX_RETAINED_DIRTY_FILES
);

/// 1 接続が持てる番兵 fd のデバイス数の上限（F9・F11。Linux。公開設定にしない）。
const MAX_SENTINEL_DEVICES: usize = 16;

/// `Close` 済みで次の永続化まで保持する未永続化ファイル数の上限（F9）。到達すると IO-10 と同じ
/// 自動フラッシュを行う。範囲外の値を表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaxRetainedDirtyFiles(usize);

impl MaxRetainedDirtyFiles {
    /// `1..=`[`MAX_MAX_RETAINED_DIRTY_FILES`] を受け付ける。範囲外は
    /// [`IoErrorCode::InvalidArgument`]。
    pub fn new(value: usize) -> Result<Self, IoError> {
        if value == 0 || value > MAX_MAX_RETAINED_DIRTY_FILES {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("max retained dirty files must be in 1..={MAX_MAX_RETAINED_DIRTY_FILES}"),
            ));
        }
        Ok(Self(value))
    }

    /// 上限値。
    pub fn get(self) -> usize {
        self.0
    }
}

impl Default for MaxRetainedDirtyFiles {
    fn default() -> Self {
        Self(DEFAULT_MAX_RETAINED_DIRTY_FILES)
    }
}

/// [`serve_file_connection_with_limit`] に渡す資源上限の束。
///
/// `#[non_exhaustive]` で、上限を後から足せる形にしてある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileServeLimits {
    max_open_files: MaxOpenFiles,
    unflushed: UnflushedLimit,
    max_retained_dirty_files: MaxRetainedDirtyFiles,
    flush_timeout: Option<IoTimeout>,
}

impl FileServeLimits {
    /// 上限を組み立てる（保持上限は既定値、FLUSH の期限は既定の 10 秒）。
    pub fn new(max_open_files: MaxOpenFiles, unflushed: UnflushedLimit) -> Self {
        Self {
            max_open_files,
            unflushed,
            max_retained_dirty_files: MaxRetainedDirtyFiles::default(),
            flush_timeout: None,
        }
    }

    /// 未永続化の `Close` 済みファイルの保持上限を差し替える。
    pub fn with_max_retained_dirty_files(mut self, value: MaxRetainedDirtyFiles) -> Self {
        self.max_retained_dirty_files = value;
        self
    }

    /// 1 回の FLUSH 全体（枠待ちと永続化）の期限を差し替える（REPAIR-5）。
    pub fn with_flush_timeout(mut self, value: IoTimeout) -> Self {
        self.flush_timeout = Some(value);
        self
    }

    /// 同時に開けるファイル数の上限。
    pub fn max_open_files(&self) -> MaxOpenFiles {
        self.max_open_files
    }

    /// 未フラッシュ滞留量の上限（IO-10）。
    pub fn unflushed(&self) -> UnflushedLimit {
        self.unflushed
    }

    /// 未永続化の `Close` 済みファイルの保持上限。
    pub fn max_retained_dirty_files(&self) -> MaxRetainedDirtyFiles {
        self.max_retained_dirty_files
    }

    /// 1 回の FLUSH 全体の期限。`None` は既定（`MAX_IO_TIMEOUT` = 10 秒）。
    pub fn flush_timeout(&self) -> Option<IoTimeout> {
        self.flush_timeout
    }
}

impl Default for FileServeLimits {
    fn default() -> Self {
        Self::new(MaxOpenFiles::default(), UnflushedLimit::default())
    }
}

/// 既知の拒否理由（1〜11）の数。
const KNOWN_NACK_REASONS: usize = 11;

/// 拒否理由ごとの Nack 件数（F13）。未知の値（`Other`）は送らないので持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NackReasonCounts {
    counts: [u64; KNOWN_NACK_REASONS],
}

impl NackReasonCounts {
    fn slot(reason: NackReason) -> Option<usize> {
        usize::from(reason.wire_value()).checked_sub(1)
    }

    fn record(&mut self, reason: NackReason) {
        if let Some(slot) = Self::slot(reason).and_then(|i| self.counts.get_mut(i)) {
            *slot = slot.saturating_add(1);
        }
    }

    /// `reason` の Nack を送った件数（未知の値は常に 0）。
    pub fn get(&self, reason: NackReason) -> u64 {
        Self::slot(reason)
            .and_then(|i| self.counts.get(i))
            .copied()
            .unwrap_or(0)
    }
}

/// [`serve_file_connection`] の累積統計（F13 のサーバー側。REPAIR-4）。パスは載せず件数だけ持つ。
///
/// FLUSH 系の統計（永続化の成否・所要時間、同期したデバイス・ファイル・ディレクトリの数、
/// `FlushAck` と自動フラッシュの回数、保持数の最大値。#3164）も持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FileServeStats {
    /// 受信したフレームの総数。
    pub frames_received: u64,
    /// 実行を終えたバッチの総数。
    pub batches_executed: u64,
    /// 成功した `Create` の数。
    pub creates_succeeded: u64,
    /// 成功した `WriteFile` の数。
    pub write_files_succeeded: u64,
    /// 成功した `Close` の数。
    pub closes_succeeded: u64,
    /// 追記した body の合計バイト数。
    pub bytes_written: u64,
    /// 送出した `Ack` の数。
    pub acks_sent: u64,
    /// 送出した `Nack` の数。
    pub nacks_sent: u64,
    /// 拒否理由ごとの `Nack` 件数。
    pub nacks_by_reason: NackReasonCounts,
    /// ホストパス長が 260 を超えたが作成を続けた件数（Windows 以外。F5・IO-5）。
    pub host_path_warnings: u64,
    /// 同時に開いていたハンドル数の最大値。
    pub max_open_handles: u64,
    /// ACK を送らずに破棄した滞留フレーム件数（D5）。
    pub discarded_pending_frames: u64,
    /// 最後に成功した永続化以降に受理した未フラッシュ滞留量（IO-10）。
    pub unflushed: UnflushedBacklog,
    /// 同期を発行して成功した永続化の回数（同期対象が無く合流した FLUSH は数えない）。
    pub persist_succeeded: u64,
    /// 失敗した永続化の回数（期限切れ・未対応・同期の失敗。接続全体の失敗になる）。
    pub persist_failed: u64,
    /// 成功した永続化の所要時間の合計（マイクロ秒）。
    pub persist_elapsed_micros: u64,
    /// 送出した `FlushAck` の数。
    pub flush_acks_sent: u64,
    /// `FlushAck` を送らずに行った自動フラッシュ（IO-10 の上限・保持上限）の回数。
    pub auto_flushes: u64,
    /// 保持していた `Close` 済み未永続化ファイル数の最大値。
    pub max_retained_files: u64,
    /// 同期したデバイス（番兵 fd）数の累計（Linux）。
    pub devices_synced: u64,
    /// 同期したファイル数の累計（macOS / Windows）。
    pub files_synced: u64,
    /// 同期したディレクトリ数の累計（macOS / Windows）。
    pub dirs_synced: u64,
    /// 1 回の永続化で同期したデバイス数の最大値（Linux）。
    pub max_flush_devices: u64,
    /// 1 回の永続化で同期したファイル数の最大値（macOS / Windows）。
    pub max_flush_files: u64,
    /// 1 回の永続化で同期したディレクトリ数の最大値（macOS / Windows）。
    pub max_flush_dirs: u64,
}

/// [`serve_file_connection`] の戻り値。ループは常にエラー（EOF を含む）で終わる。
#[derive(Debug)]
#[non_exhaustive]
pub struct FileServeReport {
    /// 終了時点までの累積統計。
    pub stats: FileServeStats,
    /// 終了原因。
    pub end: IoError,
}

/// 1 接続分のファイル操作モードを実行する（上限・計装は既定）。
///
/// `creator` は共有ルートへの作成口（複数接続で共有してよい）。ループは常にエラーで終わる
/// （[`FileServeReport`]）。詳細はモジュール doc。
pub fn serve_file_connection<T>(
    conn: &mut T,
    config: BatchConfig,
    creator: &GuestFileCreator,
    timeouts: WritebackTimeouts,
) -> FileServeReport
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
{
    serve_file_connection_with_limit(conn, config, FileServeLimits::default(), creator, timeouts)
}

/// [`serve_file_connection`] に資源上限 `limits` を指定する版。
pub fn serve_file_connection_with_limit<T>(
    conn: &mut T,
    config: BatchConfig,
    limits: FileServeLimits,
    creator: &GuestFileCreator,
    timeouts: WritebackTimeouts,
) -> FileServeReport
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
{
    serve_file_connection_with_recorder(conn, config, limits, creator, timeouts, &NoopIoOpRecorder)
}

/// [`serve_file_connection_with_limit`] に計装の記録先 `recorder` を指定する版（REPAIR-4）。
///
/// 作成 1 回ごとに [`IoOpKind::Create`]、`WriteFile` 1 件ごとに [`IoOpKind::Write`] のサンプルを
/// 1 件渡す。副作用の前に拒否した要求（上限・未知ハンドル）はサンプルにしない。
pub fn serve_file_connection_with_recorder<T>(
    conn: &mut T,
    config: BatchConfig,
    limits: FileServeLimits,
    creator: &GuestFileCreator,
    timeouts: WritebackTimeouts,
    recorder: &dyn IoOpRecorder,
) -> FileServeReport
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
{
    serve_file_connection_with_env(
        conn,
        config,
        limits,
        creator,
        timeouts,
        recorder,
        PersistEnv::production(),
    )
}

/// 永続化の実行環境（判定・枠・番兵のデバイス数上限）。本番は [`PersistEnv::production`] で、
/// 単体試験だけが旧カーネル・占有済みの枠・小さいデバイス上限を注入する。
#[derive(Clone, Copy)]
pub(crate) struct PersistEnv {
    pub(crate) support: PersistSupport,
    pub(crate) limiter: &'static PersistLimiter,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "番兵 fd は Linux だけ")
    )]
    pub(crate) max_sentinel_devices: usize,
    /// 試験専用: 番兵を `O_PATH` の fd に差し替え、`syncfs` を実際に `EBADF` で失敗させる。
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "番兵 fd は Linux だけ")
    )]
    pub(crate) break_sentinels: bool,
}

impl PersistEnv {
    fn production() -> Self {
        Self {
            support: persist_support(),
            limiter: default_persist_limiter(),
            max_sentinel_devices: MAX_SENTINEL_DEVICES,
            #[cfg(test)]
            break_sentinels: false,
        }
    }
}

pub(crate) fn serve_file_connection_with_env<T>(
    conn: &mut T,
    config: BatchConfig,
    limits: FileServeLimits,
    creator: &GuestFileCreator,
    timeouts: WritebackTimeouts,
    recorder: &dyn IoOpRecorder,
    env: PersistEnv,
) -> FileServeReport
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
{
    // 既定値の構築は失敗しない（10 秒は上限以内）。万一の失敗は送信の期限へ倒す。
    let flush_timeout = limits
        .flush_timeout()
        .or_else(|| IoTimeout::new(MAX_IO_TIMEOUT).ok())
        .unwrap_or(timeouts.send);
    let mut server = FileServer {
        table: HashMap::new(),
        creator,
        recorder,
        max_open: limits.max_open_files().get(),
        last_request_id: None,
        stats: FileServeStats::default(),
        max_retained: limits.max_retained_dirty_files().get(),
        flush_timeout,
        env,
        #[cfg(target_os = "linux")]
        sentinels: Vec::new(),
        retained: Vec::new(),
    };
    let mut buffer = BatchBuffer::new(config);
    let end = server.run(conn, &mut buffer, limits.unflushed(), timeouts);
    let mut stats = server.stats;
    stats.discarded_pending_frames = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
    FileServeReport { stats, end }
}

/// `Close` 済みで未永続化のファイルの保持形。Linux は `syncfs(番兵)` がデバイス全体を覆うため
/// ファイルの fd だけを持ち（親ディレクトリの fd を閉じて fd の消費を抑える）、macOS / Windows は
/// 親ディレクトリのハンドルつきの sink ごと持つ。
#[cfg(target_os = "linux")]
type Retained = File;
#[cfg(not(target_os = "linux"))]
type Retained = AppendFileSink;

#[cfg(target_os = "linux")]
fn retain(sink: AppendFileSink) -> Retained {
    sink.into_inner()
}
#[cfg(not(target_os = "linux"))]
fn retain(sink: AppendFileSink) -> Retained {
    sink
}

/// 接続 1 本分の状態（ハンドル表・番兵 fd・保持表と統計）。
struct FileServer<'a> {
    /// ハンドル（`Create` の request id）から書き込み先への表。長さは `max_open` 以下。
    table: HashMap<u64, AppendFileSink>,
    creator: &'a GuestFileCreator,
    recorder: &'a dyn IoOpRecorder,
    max_open: usize,
    /// 受理した最後の request id。単調増加の検査用（接続内で再利用させない）。
    last_request_id: Option<u64>,
    stats: FileServeStats,
    /// `retained` の上限（到達で自動フラッシュ）。
    max_retained: usize,
    /// 1 回の FLUSH 全体の期限（REPAIR-5）。
    flush_timeout: IoTimeout,
    env: PersistEnv,
    /// Linux: デバイス（`st_dev`）ごとの番兵 fd。最初の mkdir・作成より前に開く（F9）。
    /// 長さは `env.max_sentinel_devices` 以下。
    #[cfg(target_os = "linux")]
    sentinels: Vec<(u64, File)>,
    /// `Close` 済みで次の永続化まで保持する未永続化ファイル。
    retained: Vec<Retained>,
}

/// 受信フレームの検証結果。
enum Validated {
    /// バッチに積む要求。値は IO-10 に数える body のバイト数。
    Queue(usize),
    /// 形式の正しい `Flush`（値は `FlushAck` に使う request id）。
    Flush(crate::payload::WireRequestId),
}

/// 番兵 fd を新しく開く（`struct file` を共有しない。errseq の初期位置を書き込みより前に固定する）。
#[cfg(target_os = "linux")]
fn open_sentinel(
    deepest: &File,
    internal: &dyn Fn(&str, std::io::ErrorKind) -> CreateFailure,
) -> Result<File, CreateFailure> {
    crate::sys::open_dir_beneath(deepest, ".").map_err(|err| match err {
        crate::sys::BeneathError::Io(kind) => internal("failed to open the sentinel", kind),
        _ => internal("failed to open the sentinel", std::io::ErrorKind::Other),
    })
}

/// 番兵 fd を `deepest`（存在する最も深い祖先）から開いて表に入れる（Linux。F9）。
/// 同じデバイスの番兵が既にあれば何もしない。上限なら何も作らせず `DeviceLimit` で拒否する。
#[cfg(target_os = "linux")]
fn register_sentinel(
    sentinels: &mut Vec<(u64, File)>,
    env: &PersistEnv,
    deepest: &File,
) -> Result<(), CreateFailure> {
    let max_devices = env.max_sentinel_devices;
    use std::os::unix::fs::MetadataExt;
    let internal = |what: &str, kind: std::io::ErrorKind| {
        CreateFailure::unclassified(IoError::new(
            IoErrorCode::Internal,
            format!("{what} ({kind:?})"),
        ))
    };
    let device = deepest
        .metadata()
        .map_err(|err| internal("failed to stat the sentinel directory", err.kind()))?
        .dev();
    if sentinels.iter().any(|(known, _)| *known == device) {
        return Ok(());
    }
    if sentinels.len() >= max_devices {
        return Err(CreateFailure::device_limit(IoError::new(
            IoErrorCode::ResourceExhausted,
            "too many devices for one file operation connection",
        )));
    }
    // 複製ではなく新しく開く（`struct file` を共有すると errseq の初期位置が意味を失う）。
    #[cfg(test)]
    let sentinel = if env.break_sentinels {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        // O_PATH（x86_64・aarch64 とも 0o10000000）の fd への `syncfs` は EBADF で失敗する。
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o10_000_000)
            .open(format!("/proc/self/fd/{}", deepest.as_raw_fd()))
            .map_err(|err| internal("failed to open a broken sentinel", err.kind()))?
    } else {
        open_sentinel(deepest, &internal)?
    };
    #[cfg(not(test))]
    let sentinel = open_sentinel(deepest, &internal)?;
    sentinels.push((device, sentinel));
    Ok(())
}

/// F10 の分類（`IoErrorCode`）から Nack の大分類へ。対応が無い値は接続全体の失敗に倒す。
fn nack_code_for(reason: NackReason) -> Result<NackCode, IoError> {
    match reason.code() {
        Some(IoErrorCode::InvalidArgument) => Ok(NackCode::InvalidArgument),
        Some(IoErrorCode::AlreadyExists) => Ok(NackCode::AlreadyExists),
        Some(IoErrorCode::ResourceExhausted) => Ok(NackCode::ResourceExhausted),
        _ => Err(IoError::new(
            IoErrorCode::Internal,
            "nack reason has no wire code",
        )),
    }
}

impl FileServer<'_> {
    fn run<T>(
        &mut self,
        conn: &mut T,
        buffer: &mut BatchBuffer,
        limit: UnflushedLimit,
        timeouts: WritebackTimeouts,
    ) -> IoError
    where
        T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
    {
        loop {
            let frame = match conn.recv_frame(timeouts.recv) {
                Ok(frame) => frame,
                Err(err) => return err,
            };
            self.stats.frames_received = self.stats.frames_received.saturating_add(1);

            // 形式を検証し、IO-10 に数える body のバイト数を得る（壊れた要求はバッファに触れずに終える）。
            let body_len = match self.validate(&frame) {
                Ok(Validated::Queue(len)) => len,
                Ok(Validated::Flush(id)) => {
                    // Flush: 滞留分を実行・応答し、Ack 済みの要求すべてを永続化してから
                    // FlushAck を返して続ける（F9）。
                    if let Err(err) = self.flush(conn, buffer, timeouts.send, Some(id)) {
                        return err;
                    }
                    continue;
                }
                Err(err) => return err,
            };

            // IO-10: 受理するとバイト上限を超えるなら、受理前に滞留分を実行して自動フラッシュし、
            // 続けてこのフレームを受理する。push が拒否する過大なフレームでは保留分に触れない。
            let acceptable = frame.payload().len() <= buffer.config().max_bytes();
            if acceptable
                && !self.stats.unflushed.is_empty()
                && limit.would_exceed_bytes(&self.stats.unflushed, body_len)
                && let Err(err) = self.flush(conn, buffer, timeouts.send, None)
            {
                return err;
            }

            let outcome = match buffer.push(frame) {
                Ok(outcome) => outcome,
                Err(err) => return err,
            };
            self.stats.unflushed.record_write(body_len);

            let batches: Vec<Batch> = match outcome {
                PushOutcome::Buffered { .. } => Vec::new(),
                PushOutcome::Ready(batch) => vec![batch],
                PushOutcome::ReadyTwice(first, second) => vec![first, second],
            };
            for batch in &batches {
                if let Err(err) = self.run_batch(conn, batch, timeouts.send) {
                    return err;
                }
            }
            // IO-10 の上限、または Close 済み未永続化ファイルの保持上限に達したら自動フラッシュ
            // （FlushAck なし。続けて受信する）。保持上限はバッチの実行後に判定するため、
            // 1 バッチ内で一時的に超えうる。
            if (limit.is_reached(&self.stats.unflushed) || self.retained.len() >= self.max_retained)
                && let Err(err) = self.flush(conn, buffer, timeouts.send, None)
            {
                return err;
            }
        }
    }

    /// 受信フレームの種別と形式を検証する。
    fn validate(&self, frame: &Frame) -> Result<Validated, IoError> {
        match frame.kind() {
            FrameKind::Create => decode_create(frame).map(|_| Validated::Queue(0)),
            FrameKind::WriteFile => {
                decode_write_file(frame).map(|e| Validated::Queue(e.body().len()))
            }
            FrameKind::Close => decode_close(frame).map(|_| Validated::Queue(0)),
            FrameKind::Flush => decode_request(frame).map(|e| Validated::Flush(e.id())),
            FrameKind::Write | FrameKind::Ack | FrameKind::FlushAck | FrameKind::Nack => {
                Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    "frame kind not accepted in file operation mode",
                ))
            }
        }
    }

    /// 滞留分を実行して応答を送り、Ack 済みの要求すべてを永続化する（F9）。`ack` が `Some` なら
    /// 成功後に `FlushAck` を送り、`None` は自動フラッシュ（IO-10・保持上限。FlushAck なし）。
    /// 失敗（応答の送信・永続化・FlushAck の送信）は接続全体の失敗で、FlushAck は返さない。
    fn flush<T>(
        &mut self,
        conn: &mut T,
        buffer: &mut BatchBuffer,
        send: IoTimeout,
        ack: Option<crate::payload::WireRequestId>,
    ) -> Result<(), IoError>
    where
        T: FrameSender<Frame = Frame>,
    {
        if let Some(batch) = buffer.take_pending() {
            self.run_batch(conn, &batch, send)?;
        }
        self.persist_all()?;
        match ack {
            Some(id) => {
                conn.send_frame(&encode_ack(FrameKind::FlushAck, id)?, send)?;
                self.stats.flush_acks_sent = self.stats.flush_acks_sent.saturating_add(1);
            }
            None => {
                self.stats.auto_flushes = self.stats.auto_flushes.saturating_add(1);
            }
        }
        Ok(())
    }

    /// 同じ接続で Ack 済みの要求すべてを永続化する（F9・IO-2）。未フラッシュが無ければ同期を
    /// 起動せず成功する（書き込みを挟まない連続 FLUSH で FS 全体の同期を増幅させない）。成功したら
    /// 全 sink を永続化済みにし、保持表を空にして IO-10 の計数を 0 へ戻す。失敗したら状態を破棄する
    /// 側（接続全体の失敗）に倒す。
    fn persist_all(&mut self) -> Result<(), IoError> {
        if self.stats.unflushed.is_empty() {
            self.retained.clear();
            return Ok(());
        }
        let targets = match self.collect_targets() {
            Ok(targets) => targets,
            Err(err) => {
                self.stats.persist_failed = self.stats.persist_failed.saturating_add(1);
                return Err(err);
            }
        };
        let devices = u64::try_from(targets.sentinels.len()).unwrap_or(u64::MAX);
        let files = u64::try_from(targets.files.len()).unwrap_or(u64::MAX);
        let dirs = u64::try_from(targets.dirs.len()).unwrap_or(u64::MAX);
        if !self.env.support.is_supported() || !targets.is_empty() {
            match persist_connection(
                self.env.support,
                self.env.limiter,
                targets,
                self.flush_timeout,
            ) {
                Ok(elapsed) => {
                    let s = &mut self.stats;
                    s.persist_succeeded = s.persist_succeeded.saturating_add(1);
                    s.persist_elapsed_micros = s
                        .persist_elapsed_micros
                        .saturating_add(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
                    s.devices_synced = s.devices_synced.saturating_add(devices);
                    s.files_synced = s.files_synced.saturating_add(files);
                    s.dirs_synced = s.dirs_synced.saturating_add(dirs);
                    s.max_flush_devices = s.max_flush_devices.max(devices);
                    s.max_flush_files = s.max_flush_files.max(files);
                    s.max_flush_dirs = s.max_flush_dirs.max(dirs);
                }
                Err(failure) => {
                    self.stats.persist_failed = self.stats.persist_failed.saturating_add(1);
                    return Err(failure.error);
                }
            }
        }
        for sink in self.table.values_mut() {
            sink.mark_persisted();
        }
        self.retained.clear();
        self.stats.unflushed.reset();
        Ok(())
    }

    /// 永続化の対象（複製したハンドル）を集める。Linux は番兵 fd、macOS / Windows は汚れた
    /// ファイル（開いているもの・保持中のもの）と未同期のディレクトリ。
    fn collect_targets(&self) -> Result<PersistTargets, IoError> {
        let dup_failed = |err: std::io::Error| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to duplicate handle for persist ({:?})", err.kind()),
            )
        };
        let mut targets = PersistTargets::default();
        #[cfg(target_os = "linux")]
        {
            for (_, sentinel) in &self.sentinels {
                targets
                    .sentinels
                    .push(sentinel.try_clone().map_err(dup_failed)?);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dup_failed;
            let sinks = self.table.values().chain(self.retained.iter());
            for sink in sinks.filter(|sink| sink.needs_persist()) {
                targets.files.push(sink.clone_file_for_persist()?);
                targets.dirs.extend(sink.clone_unsynced_dirs_for_persist()?);
            }
        }
        Ok(targets)
    }

    /// バッチを 2 相で処理する。実行相で全フレームの応答を作り（接続全体の失敗ならここで
    /// `Err`。応答は 1 件も送らない）、成功したときだけ送信相で受信順に送る。
    fn run_batch<T>(&mut self, conn: &mut T, batch: &Batch, send: IoTimeout) -> Result<(), IoError>
    where
        T: FrameSender<Frame = Frame>,
    {
        let mut responses: Vec<Frame> = Vec::with_capacity(batch.len());
        for frame in batch.frames() {
            responses.push(self.execute(frame)?);
        }
        self.stats.batches_executed = self.stats.batches_executed.saturating_add(1);
        for response in &responses {
            conn.send_frame(response, send)?;
            if response.kind() == FrameKind::Nack {
                self.stats.nacks_sent = self.stats.nacks_sent.saturating_add(1);
                let envelope = decode_nack(response).map_err(|_| {
                    IoError::new(
                        IoErrorCode::Internal,
                        "failed to decode a Nack built by this server",
                    )
                })?;
                self.stats.nacks_by_reason.record(envelope.reason());
            } else {
                self.stats.acks_sent = self.stats.acks_sent.saturating_add(1);
            }
        }
        Ok(())
    }

    /// 要求 1 件を実行して応答フレームを返す。再復号の失敗は構造上起きないが `Internal` に写す。
    fn execute(&mut self, frame: &Frame) -> Result<Frame, IoError> {
        self.admit_request_id(frame)?;
        let redecode = |_: IoError| {
            IoError::new(
                IoErrorCode::Internal,
                "failed to re-decode a frame already accepted by BatchBuffer::push",
            )
        };
        match frame.kind() {
            FrameKind::Create => {
                let env = decode_create(frame).map_err(redecode)?;
                self.execute_create(env.id(), env.path())
            }
            FrameKind::WriteFile => {
                let env = decode_write_file(frame).map_err(redecode)?;
                self.execute_write_file(env.id(), env.handle().get(), env.body())
            }
            FrameKind::Close => {
                let env = decode_close(frame).map_err(redecode)?;
                self.execute_close(env.id(), env.handle().get())
            }
            _ => Err(IoError::new(
                IoErrorCode::Internal,
                "unexpected frame kind in a file operation batch",
            )),
        }
    }

    /// request id が接続内で単調増加であることを副作用の前に確かめて消費する（F6）。重複・
    /// 逆戻りはプロトコル違反（接続全体の `InvalidArgument`）。失敗した要求の id も消費するので、
    /// Close 後や Nack 後の id 再利用でハンドルが使い回されない。
    fn admit_request_id(&mut self, frame: &Frame) -> Result<(), IoError> {
        let id = match frame.kind() {
            FrameKind::Create => decode_create(frame).map(|e| e.id().get()),
            FrameKind::WriteFile => decode_write_file(frame).map(|e| e.id().get()),
            FrameKind::Close => decode_close(frame).map(|e| e.id().get()),
            _ => return Ok(()),
        }
        .map_err(|_| {
            IoError::new(
                IoErrorCode::Internal,
                "failed to re-decode a frame already accepted by BatchBuffer::push",
            )
        })?;
        if self.last_request_id.is_some_and(|last| id <= last) {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "request id is not strictly increasing in the connection",
            ));
        }
        self.last_request_id = Some(id);
        Ok(())
    }

    fn nack(
        &mut self,
        id: crate::payload::WireRequestId,
        reason: NackReason,
    ) -> Result<Frame, IoError> {
        // 理由別の件数は送信に成功した後に `run_batch` が数える（`nacks_sent` と食い違わせない）。
        encode_nack(id, nack_code_for(reason)?, reason)
    }

    fn execute_create(
        &mut self,
        id: crate::payload::WireRequestId,
        path: &str,
    ) -> Result<Frame, IoError> {
        let handle = id.get();
        // 副作用（FS への作成）の前に容量を確かめる。
        if self.table.len() >= self.max_open {
            return self.nack(id, NackReason::OpenFilesLimit);
        }
        let timer = IoOpTimer::start(self.recorder, IoOpKind::Create);
        // 最初の mkdir・ファイル作成の直前に、存在する最も深い祖先から番兵 fd を開く（F9）。
        let creator = self.creator;
        let env = self.env;
        #[cfg(target_os = "linux")]
        let sentinels = &mut self.sentinels;
        let mut pre_mutation = |deepest: &File| -> Result<(), CreateFailure> {
            #[cfg(target_os = "linux")]
            {
                register_sentinel(sentinels, &env, deepest)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (env, deepest);
                Ok(())
            }
        };
        match creator.create_file_inner(path, &mut pre_mutation) {
            Ok(created) => {
                if created.host_path_warning.is_some() {
                    self.stats.host_path_warnings = self.stats.host_path_warnings.saturating_add(1);
                }
                self.table.insert(handle, created.sink);
                let open = u64::try_from(self.table.len()).unwrap_or(u64::MAX);
                self.stats.max_open_handles = self.stats.max_open_handles.max(open);
                self.stats.creates_succeeded = self.stats.creates_succeeded.saturating_add(1);
                timer.success();
                encode_ack(FrameKind::Ack, id)
            }
            Err(failure) => {
                timer.failure();
                match classify_create_failure(&failure) {
                    Some(reason) => self.nack(id, reason),
                    None => Err(failure.error),
                }
            }
        }
    }

    fn execute_write_file(
        &mut self,
        id: crate::payload::WireRequestId,
        handle: u64,
        body: &[u8],
    ) -> Result<Frame, IoError> {
        let Some(sink) = self.table.get_mut(&handle) else {
            return self.nack(id, NackReason::UnknownHandle);
        };
        let timer = IoOpTimer::start(self.recorder, IoOpKind::Write);
        // 書き込み失敗（ENOSPC・EIO を含む）は常に接続全体の失敗にする（F10）。
        let written = sink.append_body(body)?;
        timer.success();
        self.stats.write_files_succeeded = self.stats.write_files_succeeded.saturating_add(1);
        self.stats.bytes_written = self.stats.bytes_written.saturating_add(written);
        encode_ack(FrameKind::Ack, id)
    }

    fn execute_close(
        &mut self,
        id: crate::payload::WireRequestId,
        handle: u64,
    ) -> Result<Frame, IoError> {
        // 表から外す。未永続化の sink は次の永続化まで保持表に残す（F9）。Ack はハンドルの
        // 解放だけを意味し、永続化の保証はしない（F8）。
        let Some(sink) = self.table.remove(&handle) else {
            return self.nack(id, NackReason::UnknownHandle);
        };
        if sink.needs_persist() {
            self.retained.push(retain(sink));
            let held = u64::try_from(self.retained.len()).unwrap_or(u64::MAX);
            self.stats.max_retained_files = self.stats.max_retained_files.max(held);
        }
        self.stats.closes_succeeded = self.stats.closes_succeeded.saturating_add(1);
        encode_ack(FrameKind::Ack, id)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::barrier::PersistLimiter;
    use crate::client::{InFlightLimit, MAX_IN_FLIGHT_LIMIT, SendQueue};
    use crate::guest_path::GuestPath;
    use crate::instrument::{IoOpOutcome, IoOpSample};
    use crate::payload::{
        WireRequestId, decode_ack, decode_nack, encode_close, encode_create, encode_request,
        encode_write_file,
    };
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;

    fn timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_millis(50)).expect("50ms must be valid")
    }

    fn timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: timeout(),
            send: timeout(),
        }
    }

    /// `value` の request id（`WireRequestId::from_wire` は非公開のため、送信キューの連番から作る）。
    fn wid(value: u64) -> WireRequestId {
        let limit = InFlightLimit::new(MAX_IN_FLIGHT_LIMIT).expect("limit");
        let mut queue = SendQueue::new(limit);
        let mut last = None;
        for _ in 0..=value {
            last = Some(queue.register(FrameKind::Write).expect("register").id());
        }
        WireRequestId::from(last.expect("at least once"))
    }

    fn create(id: u64, path: &str) -> Frame {
        encode_create(wid(id), &GuestPath::parse(path).expect("valid path")).expect("encode")
    }

    /// 構文違反のパスも送れるよう、Create のペイロードを手で組む（クライアントが検証しない場合）。
    fn create_raw(id: u64, path: &str) -> Frame {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&u16::try_from(path.len()).expect("len").to_le_bytes());
        payload.extend_from_slice(path.as_bytes());
        Frame::new(FrameKind::Create, payload).expect("frame")
    }

    fn write_file(id: u64, handle: u64, body: &[u8]) -> Frame {
        encode_write_file(wid(id), wid(handle), body).expect("encode")
    }

    fn close(id: u64, handle: u64) -> Frame {
        encode_close(wid(id), wid(handle)).expect("encode")
    }

    fn flush(id: u64) -> Frame {
        encode_request(FrameKind::Flush, wid(id), &[]).expect("encode")
    }

    struct Fake {
        incoming: VecDeque<Frame>,
        sent: Vec<Frame>,
    }

    impl Fake {
        fn new(frames: Vec<Frame>) -> Self {
            Self {
                incoming: frames.into(),
                sent: Vec::new(),
            }
        }
    }

    impl FrameSender for Fake {
        type Frame = Frame;
        fn send_frame(&mut self, frame: &Frame, _t: IoTimeout) -> Result<(), IoError> {
            self.sent.push(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for Fake {
        type Frame = Frame;
        fn recv_frame(&mut self, _t: IoTimeout) -> Result<Frame, IoError> {
            self.incoming
                .pop_front()
                .ok_or_else(|| IoError::new(IoErrorCode::Unavailable, "fake exhausted"))
        }
    }

    struct Dir(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);
    impl Dir {
        fn new() -> Self {
            let root = crate::test_root::test_root("fcio-fs", "t");
            Self(root.to_path_buf(), root)
        }
    }

    fn run(frames: Vec<Frame>, batch_size: usize) -> (Dir, Fake, FileServeReport) {
        run_with(frames, batch_size, FileServeLimits::default())
    }

    fn run_with(
        frames: Vec<Frame>,
        batch_size: usize,
        limits: FileServeLimits,
    ) -> (Dir, Fake, FileServeReport) {
        let dir = Dir::new();
        let creator = GuestFileCreator::new(dir.0.clone()).expect("creator");
        let mut conn = Fake::new(frames);
        let config = BatchConfig::new(batch_size).expect("batch size");
        let report =
            serve_file_connection_with_limit(&mut conn, config, limits, &creator, timeouts());
        (dir, conn, report)
    }

    fn ack_ids(sent: &[Frame]) -> Vec<u64> {
        sent.iter()
            .map(|f| {
                let ack = decode_ack(f).expect("ack");
                assert_eq!(ack.kind(), FrameKind::Ack);
                ack.id().get()
            })
            .collect()
    }

    fn nack(frame: &Frame) -> (u64, NackCode, NackReason) {
        let n = decode_nack(frame).expect("nack");
        (n.id().get(), n.code(), n.reason())
    }

    #[test]
    fn io1_file_mode_create_write_close_acks_in_order() {
        let (dir, conn, report) = run(
            vec![
                create(1, "a.txt"),
                write_file(2, 1, b"hello "),
                write_file(3, 1, b"world"),
                close(4, 1),
            ],
            4,
        );
        assert_eq!(ack_ids(&conn.sent), vec![1, 2, 3, 4]);
        assert_eq!(
            std::fs::read(dir.0.join("a.txt")).expect("read"),
            b"hello world"
        );
        assert_eq!(report.stats.creates_succeeded, 1);
        assert_eq!(report.stats.write_files_succeeded, 2);
        assert_eq!(report.stats.closes_succeeded, 1);
        assert_eq!(report.stats.bytes_written, 11);
        assert_eq!(report.stats.acks_sent, 4);
        assert_eq!(report.stats.max_open_handles, 1);
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
    }

    #[test]
    fn io1_write_file_before_create_ack_is_pipelined() {
        // Create の Ack を待たずに同じバッチ内で WriteFile を送れる（F6）。
        let (dir, conn, _) = run(vec![create(1, "p"), write_file(2, 1, b"x")], 2);
        assert_eq!(ack_ids(&conn.sent), vec![1, 2]);
        assert_eq!(std::fs::read(dir.0.join("p")).expect("read"), b"x");
    }

    #[test]
    fn io5_case_collision_create_is_nacked_and_other_handles_unaffected() {
        let (dir, conn, report) = run(
            vec![
                create(1, "Foo"),
                create(2, "foo"),
                write_file(3, 1, b"ok"),
                write_file(4, 2, b"no"),
            ],
            4,
        );
        assert_eq!(conn.sent.len(), 4);
        assert_eq!(decode_ack(&conn.sent[0]).expect("ack").id().get(), 1);
        assert_eq!(
            nack(&conn.sent[1]),
            (2, NackCode::AlreadyExists, NackReason::CaseCollision)
        );
        assert_eq!(decode_ack(&conn.sent[2]).expect("ack").id().get(), 3);
        // 失敗した Create のハンドルへの WriteFile は未知ハンドル。
        assert_eq!(
            nack(&conn.sent[3]),
            (4, NackCode::InvalidArgument, NackReason::UnknownHandle)
        );
        assert_eq!(std::fs::read(dir.0.join("Foo")).expect("read"), b"ok");
        assert_eq!(report.stats.nacks_sent, 2);
        assert_eq!(
            report.stats.nacks_by_reason.get(NackReason::CaseCollision),
            1
        );
        assert_eq!(
            report.stats.nacks_by_reason.get(NackReason::UnknownHandle),
            1
        );
        assert_eq!(report.stats.nacks_by_reason.get(NackReason::Exists), 0);
    }

    #[test]
    fn io1_close_then_write_file_is_unknown_handle() {
        let (_dir, conn, _) = run(
            vec![
                create(1, "c"),
                close(2, 1),
                write_file(3, 1, b"x"),
                close(4, 1),
            ],
            4,
        );
        assert_eq!(decode_ack(&conn.sent[1]).expect("ack").id().get(), 2);
        assert_eq!(
            nack(&conn.sent[2]),
            (3, NackCode::InvalidArgument, NackReason::UnknownHandle)
        );
        assert_eq!(
            nack(&conn.sent[3]),
            (4, NackCode::InvalidArgument, NackReason::UnknownHandle)
        );
    }

    #[test]
    fn io1_open_files_limit_nack_then_close_allows_create() {
        let limits =
            FileServeLimits::new(MaxOpenFiles::new(1).expect("1"), UnflushedLimit::default());
        let (dir, conn, report) = run_with(
            vec![create(1, "a"), create(2, "b"), close(3, 1), create(4, "b")],
            4,
            limits,
        );
        assert_eq!(decode_ack(&conn.sent[0]).expect("ack").id().get(), 1);
        assert_eq!(
            nack(&conn.sent[1]),
            (2, NackCode::ResourceExhausted, NackReason::OpenFilesLimit)
        );
        assert_eq!(decode_ack(&conn.sent[3]).expect("ack").id().get(), 4);
        assert!(dir.0.join("a").exists());
        assert!(dir.0.join("b").exists());
        assert_eq!(report.stats.max_open_handles, 1);
    }

    #[test]
    fn io1_open_files_limit_does_not_touch_filesystem() {
        let limits =
            FileServeLimits::new(MaxOpenFiles::new(1).expect("1"), UnflushedLimit::default());
        let (dir, conn, _) = run_with(vec![create(1, "a"), create(2, "b")], 2, limits);
        assert_eq!(
            nack(&conn.sent[1]),
            (2, NackCode::ResourceExhausted, NackReason::OpenFilesLimit)
        );
        assert!(!dir.0.join("b").exists());
    }

    #[test]
    fn io5_path_syntax_violations_are_nacked_and_nothing_is_created() {
        let (dir, conn, _) = run(
            vec![
                create_raw(1, "../escape"),
                create_raw(2, "a/../b"),
                create_raw(3, "a\\b"),
                create_raw(4, "a:b"),
                create_raw(5, "/abs"),
            ],
            5,
        );
        assert_eq!(conn.sent.len(), 5);
        for (i, frame) in conn.sent.iter().enumerate() {
            let (id, code, reason) = nack(frame);
            assert_eq!(id, u64::try_from(i + 1).expect("id"));
            assert_eq!(
                (code, reason),
                (NackCode::InvalidArgument, NackReason::PathSyntax)
            );
        }
        assert_eq!(std::fs::read_dir(&dir.0).expect("dir").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn io5_symlink_ancestor_is_nacked_escapes_root() {
        let dir = Dir::new();
        let outside = Dir::new();
        std::os::unix::fs::symlink(&outside.0, dir.0.join("link")).expect("symlink");
        let creator = GuestFileCreator::new(dir.0.clone()).expect("creator");
        let mut conn = Fake::new(vec![create(1, "link/x")]);
        let _ = serve_file_connection(
            &mut conn,
            BatchConfig::new(1).expect("1"),
            &creator,
            timeouts(),
        );
        assert_eq!(
            nack(&conn.sent[0]),
            (1, NackCode::InvalidArgument, NackReason::EscapesRoot)
        );
        assert!(!outside.0.join("x").exists());
    }

    #[test]
    fn io1_batch_spanning_multiple_files_preserves_order() {
        let (dir, conn, _) = run(
            vec![
                create(1, "x"),
                create(2, "y"),
                write_file(3, 1, b"1"),
                write_file(4, 2, b"2"),
                write_file(5, 1, b"3"),
                write_file(6, 2, b"4"),
            ],
            4,
        );
        // 残り 2 件は件数未達のまま接続が閉じ、破棄される（D5）。
        assert_eq!(ack_ids(&conn.sent), vec![1, 2, 3, 4]);
        assert_eq!(std::fs::read(dir.0.join("x")).expect("x"), b"1");
        assert_eq!(std::fs::read(dir.0.join("y")).expect("y"), b"2");
    }

    #[test]
    fn io1_pending_frames_are_discarded_on_end() {
        let (_dir, conn, report) = run(vec![create(1, "x"), create(2, "y")], 4);
        assert!(conn.sent.is_empty());
        assert_eq!(report.stats.discarded_pending_frames, 2);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io1_mid_batch_connection_failure_sends_zero_responses() {
        crate::guest_files::test_fail_next_leaf_creation();
        // 1 件目の Create が接続全体の失敗になるバッチ。同じバッチの後続の応答も送らない。
        let (_dir, conn, report) = run(vec![create(1, "x"), create(2, "y")], 2);
        assert!(conn.sent.is_empty());
        assert_eq!(report.end.code(), IoErrorCode::Internal);
        assert_eq!(report.stats.acks_sent + report.stats.nacks_sent, 0);
    }

    #[test]
    fn io1_file_mode_rejects_write_and_server_kinds() {
        let kinds = [
            encode_request(FrameKind::Write, wid(1), b"x").expect("write"),
            Frame::new(FrameKind::Ack, 1u64.to_le_bytes().to_vec()).expect("ack"),
            Frame::new(FrameKind::FlushAck, 1u64.to_le_bytes().to_vec()).expect("flushack"),
            Frame::new(FrameKind::Nack, vec![0u8; 11]).expect("nack"),
        ];
        for frame in kinds {
            let (_d, conn, report) = run(vec![create(9, "keep"), frame], 8);
            assert!(conn.sent.is_empty());
            assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn io1_duplicate_create_handle_is_protocol_violation() {
        let (_d, conn, report) = run(vec![create(1, "a"), create(1, "b")], 2);
        assert!(conn.sent.is_empty());
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    #[test]
    fn io1_request_id_reuse_after_close_is_protocol_violation() {
        let (d, conn, report) = run(vec![create(1, "a"), close(2, 1), create(1, "b")], 3);
        assert!(conn.sent.is_empty());
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        assert!(!d.0.join("b").exists());
    }

    #[test]
    fn io1_request_id_reuse_after_failed_create_is_protocol_violation() {
        let (_d, conn, report) = run(vec![create(1, "a"), create(2, "A"), create(2, "c")], 3);
        assert!(conn.sent.is_empty());
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    #[test]
    fn repair4_nack_reason_counts_exclude_unsent_batch() {
        let (_d, conn, report) = run(vec![write_file(1, 9, b"x"), create(1, "z")], 2);
        assert!(conn.sent.is_empty());
        assert_eq!(report.stats.nacks_sent, 0);
        assert_eq!(
            report.stats.nacks_by_reason.get(NackReason::UnknownHandle),
            0
        );
    }

    fn run_env(
        frames: Vec<Frame>,
        batch_size: usize,
        limits: FileServeLimits,
        env: PersistEnv,
    ) -> (Dir, Fake, FileServeReport) {
        let dir = Dir::new();
        let creator = GuestFileCreator::new(dir.0.clone()).expect("creator");
        let mut conn = Fake::new(frames);
        let config = BatchConfig::new(batch_size).expect("batch size");
        let report = serve_file_connection_with_env(
            &mut conn,
            config,
            limits,
            &creator,
            timeouts(),
            &NoopIoOpRecorder,
            env,
        );
        (dir, conn, report)
    }

    fn env_with(support: PersistSupport, limiter: &'static PersistLimiter) -> PersistEnv {
        PersistEnv {
            support,
            limiter,
            max_sentinel_devices: MAX_SENTINEL_DEVICES,
            break_sentinels: false,
        }
    }

    /// 枠が 0 の limiter。同期を発行しようとすると枠待ちで必ず `Timeout` になる
    /// （同期が起動されないことの観測にも使う）。
    static NO_SLOT: PersistLimiter = PersistLimiter::new(0);

    fn flush_ack_ids(sent: &[Frame]) -> Vec<u64> {
        sent.iter()
            .filter(|f| f.kind() == FrameKind::FlushAck)
            .map(|f| decode_ack(f).expect("flush ack").id().get())
            .collect()
    }

    fn ack_only_ids(sent: &[Frame]) -> Vec<u64> {
        sent.iter()
            .filter(|f| f.kind() == FrameKind::Ack)
            .map(|f| decode_ack(f).expect("ack").id().get())
            .collect()
    }

    #[test]
    fn io2_flush_in_file_mode_returns_flush_ack_after_acks() {
        let (dir, conn, report) = run(
            vec![
                create(1, "a"),
                write_file(2, 1, b"z"),
                flush(3),
                create(4, "b"),
                flush(5),
            ],
            8,
        );
        if persist_support().is_supported() {
            // 滞留分の Ack の後に FlushAck が届き、同じ接続で続きも処理される。
            let kinds: Vec<FrameKind> = conn.sent.iter().map(Frame::kind).collect();
            assert_eq!(
                kinds,
                vec![
                    FrameKind::Ack,
                    FrameKind::Ack,
                    FrameKind::FlushAck,
                    FrameKind::Ack,
                    FrameKind::FlushAck
                ]
            );
            assert_eq!(flush_ack_ids(&conn.sent), vec![3, 5]);
            assert_eq!(report.end.code(), IoErrorCode::Unavailable);
            assert_eq!(report.stats.flush_acks_sent, 2);
            assert_eq!(report.stats.persist_succeeded, 2);
            assert_eq!(report.stats.unflushed.frames(), 0);
            assert_eq!(std::fs::read(dir.0.join("a")).expect("read"), b"z");
        } else {
            assert_eq!(ack_only_ids(&conn.sent), vec![1, 2]);
            assert!(flush_ack_ids(&conn.sent).is_empty());
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
    }

    #[test]
    fn io10_unflushed_limit_auto_flushes_and_continues() {
        let limits = FileServeLimits::new(
            MaxOpenFiles::default(),
            UnflushedLimit::new(3, 1024).expect("limit"),
        );
        let (_d, conn, report) = run_with(
            vec![
                create(1, "a"),
                write_file(2, 1, b"z"),
                write_file(3, 1, b"y"),
                close(4, 1),
            ],
            64,
            limits,
        );
        assert_eq!(ack_only_ids(&conn.sent), vec![1, 2, 3]);
        if persist_support().is_supported() {
            // 3 件目の受理で自動フラッシュ（FlushAck なし）して接続を続ける。4 件目はバッチ
            // 未達のまま接続が閉じ、破棄される（D5）。
            assert!(flush_ack_ids(&conn.sent).is_empty());
            assert_eq!(report.stats.auto_flushes, 1);
            assert_eq!(report.stats.flush_acks_sent, 0);
            assert_eq!(report.stats.unflushed.frames(), 1);
            assert_eq!(report.stats.discarded_pending_frames, 1);
            assert_eq!(report.end.code(), IoErrorCode::Unavailable);
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
    }

    #[test]
    fn io10_byte_limit_flushes_before_accepting_and_then_accepts() {
        let limits = FileServeLimits::new(
            MaxOpenFiles::default(),
            UnflushedLimit::new(100, 4).expect("limit"),
        );
        let (dir, conn, report) = run_with(
            vec![
                create(1, "a"),
                write_file(2, 1, b"abc"),
                write_file(3, 1, b"def"),
                flush(4),
            ],
            64,
            limits,
        );
        if persist_support().is_supported() {
            // 3 バイト + 3 バイトは上限 4 を超えるため、3 件目の受理前に自動フラッシュする。
            assert_eq!(ack_only_ids(&conn.sent), vec![1, 2, 3]);
            assert_eq!(flush_ack_ids(&conn.sent), vec![4]);
            assert_eq!(report.stats.auto_flushes, 1);
            assert_eq!(std::fs::read(dir.0.join("a")).expect("read"), b"abcdef");
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
    }

    #[test]
    fn io2_flush_without_unflushed_skips_sync() {
        // 枠が 0 の limiter でも、同期対象が無い（書き込みを挟まない）FLUSH は FlushAck を返す。
        let env = env_with(PersistSupport::SupportedFileSync, &NO_SLOT);
        let (_d, conn, report) =
            run_env(vec![flush(1), flush(2)], 8, FileServeLimits::default(), env);
        assert_eq!(flush_ack_ids(&conn.sent), vec![1, 2]);
        assert_eq!(report.stats.persist_succeeded, 0);
        assert_eq!(report.stats.persist_failed, 0);
    }

    #[test]
    fn io2_nacked_create_is_outside_flush_range() {
        // Nack された要求は範囲外で、同期対象が無いため同期は起動されない（枠 0 でも成功する）。
        let env = env_with(PersistSupport::Supported, &NO_SLOT);
        let (_d, conn, report) = run_env(
            vec![create_raw(1, "../x"), flush(2)],
            8,
            FileServeLimits::default(),
            env,
        );
        assert_eq!(flush_ack_ids(&conn.sent), vec![2]);
        assert_eq!(report.stats.persist_succeeded, 0);
        assert_eq!(report.stats.max_flush_devices, 0);
    }

    #[test]
    fn io2_kernel_too_old_flush_is_unimplemented_without_flush_ack() {
        let env = env_with(PersistSupport::KernelTooOld, default_persist_limiter());
        let (_d, conn, report) = run_env(
            vec![create(1, "a"), flush(2)],
            8,
            FileServeLimits::default(),
            env,
        );
        assert_eq!(ack_only_ids(&conn.sent), vec![1]);
        assert!(flush_ack_ids(&conn.sent).is_empty());
        assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        assert_eq!(report.stats.persist_failed, 1);
        assert_eq!(report.stats.flush_acks_sent, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn io2_persist_slot_timeout_sends_no_flush_ack() {
        let env = env_with(PersistSupport::Supported, &NO_SLOT);
        let limits = FileServeLimits::default().with_flush_timeout(
            IoTimeout::new(Duration::from_millis(100)).expect("100ms must be valid"),
        );
        let (_d, conn, report) = run_env(vec![create(1, "a"), flush(2)], 8, limits, env);
        assert_eq!(ack_only_ids(&conn.sent), vec![1]);
        assert!(flush_ack_ids(&conn.sent).is_empty());
        assert_eq!(report.end.code(), IoErrorCode::Timeout);
        assert_eq!(report.stats.persist_failed, 1);
    }

    /// 設計の受け入れ条件: mkdir を伴う Create の直前に番兵 fd が表にある。祖先を新設する
    /// `a/b/f` の Create が成功した後、同期するデバイスが 1 件ある（番兵が最初の作成より前に
    /// 登録された。コールバックが作成より前に呼ばれることは guest_files の試験が照合する）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_sentinel_is_registered_for_create_with_mkdir() {
        let env = env_with(PersistSupport::Supported, default_persist_limiter());
        let (dir, conn, report) = run_env(
            vec![create(1, "a/b/f"), write_file(2, 1, b"x"), flush(3)],
            8,
            FileServeLimits::default(),
            env,
        );
        assert_eq!(flush_ack_ids(&conn.sent), vec![3]);
        assert_eq!(report.stats.max_flush_devices, 1);
        assert_eq!(std::fs::read(dir.0.join("a/b/f")).expect("read"), b"x");
    }

    /// 同じデバイスの複数 Create は番兵 1 本を使い回し、FLUSH はデバイスごとに 1 回。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_sentinel_per_device_is_reused() {
        let env = env_with(PersistSupport::Supported, default_persist_limiter());
        let (_d, conn, report) = run_env(
            vec![create(1, "a/f"), create(2, "b/g"), create(3, "h"), flush(4)],
            8,
            FileServeLimits::default(),
            env,
        );
        assert_eq!(flush_ack_ids(&conn.sent), vec![4]);
        assert_eq!(report.stats.max_flush_devices, 1);
        assert_eq!(report.stats.devices_synced, 1);
    }

    /// 番兵のデバイス数の上限を超えた Create は、何も作らずに `DeviceLimit` で拒否される。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_device_limit_nacks_and_creates_nothing() {
        let mut env = env_with(PersistSupport::Supported, default_persist_limiter());
        env.max_sentinel_devices = 0;
        let (dir, conn, _) = run_env(vec![create(1, "a/b/f")], 1, FileServeLimits::default(), env);
        assert_eq!(
            nack(&conn.sent[0]),
            (1, NackCode::ResourceExhausted, NackReason::DeviceLimit)
        );
        assert!(!dir.0.join("a").exists());
    }

    /// 発行後の失敗（`syncfs` が実際に `EBADF`）は FlushAck を返さず接続全体の失敗になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_real_syncfs_failure_sends_no_flush_ack() {
        let mut env = env_with(PersistSupport::Supported, default_persist_limiter());
        env.break_sentinels = true;
        let (_d, conn, report) = run_env(
            vec![create(1, "a"), flush(2)],
            8,
            FileServeLimits::default(),
            env,
        );
        assert_eq!(ack_only_ids(&conn.sent), vec![1]);
        assert!(flush_ack_ids(&conn.sent).is_empty());
        assert_ne!(report.end.code(), IoErrorCode::Unavailable);
        assert_eq!(report.stats.persist_failed, 1);
        assert_eq!(report.stats.flush_acks_sent, 0);
    }

    #[test]
    fn io2_retained_limit_triggers_auto_flush() {
        let limits = FileServeLimits::default()
            .with_max_retained_dirty_files(MaxRetainedDirtyFiles::new(2).expect("2"));
        let (dir, conn, report) = run_with(
            vec![
                create(1, "a"),
                write_file(2, 1, b"A"),
                close(3, 1),
                create(4, "b"),
                write_file(5, 4, b"B"),
                close(6, 4),
                create(7, "c"),
                write_file(8, 7, b"C"),
                close(9, 7),
            ],
            3,
            limits,
        );
        if persist_support().is_supported() {
            assert_eq!(ack_only_ids(&conn.sent), (1..=9).collect::<Vec<u64>>());
            // 2 件目の Close で保持が上限に達して自動フラッシュ（FlushAck なし）し、続きを処理する。
            assert_eq!(report.stats.auto_flushes, 1);
            assert_eq!(report.stats.flush_acks_sent, 0);
            assert_eq!(report.stats.max_retained_files, 2);
            assert_eq!(report.stats.unflushed.frames(), 3);
            assert_eq!(std::fs::read(dir.0.join("a")).expect("a"), b"A");
            assert_eq!(std::fs::read(dir.0.join("b")).expect("b"), b"B");
            assert_eq!(std::fs::read(dir.0.join("c")).expect("c"), b"C");
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
    }

    #[test]
    fn io2_clean_close_is_not_retained() {
        let (_d, conn, report) = run(
            vec![
                create(1, "a"),
                write_file(2, 1, b"x"),
                flush(3),
                close(4, 1),
                flush(5),
            ],
            8,
        );
        if persist_support().is_supported() {
            assert_eq!(flush_ack_ids(&conn.sent), vec![3, 5]);
            // Flush の後は永続化済みの状態で Close されるため、保持表に入らない。
            assert_eq!(report.stats.max_retained_files, 0);
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
    }

    #[test]
    fn io2_dirty_close_is_retained_until_flush() {
        let (_d, conn, report) = run(
            vec![
                create(1, "a"),
                write_file(2, 1, b"x"),
                close(3, 1),
                flush(4),
            ],
            8,
        );
        if persist_support().is_supported() {
            assert_eq!(flush_ack_ids(&conn.sent), vec![4]);
            assert_eq!(report.stats.max_retained_files, 1);
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
    }

    #[test]
    fn io1_max_retained_dirty_files_range() {
        assert_eq!(MaxRetainedDirtyFiles::default().get(), 1024);
        assert_eq!(MaxRetainedDirtyFiles::new(1).expect("1").get(), 1);
        assert_eq!(MaxRetainedDirtyFiles::new(4096).expect("max").get(), 4096);
        for bad in [0usize, 4097] {
            let err = MaxRetainedDirtyFiles::new(bad).expect_err("out of range");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }
    #[test]
    fn io1_malformed_flush_does_not_act_as_barrier() {
        let bad = Frame::new(FrameKind::Flush, vec![1, 2, 3]).expect("frame");
        let (_d, conn, report) = run(vec![create(1, "a"), bad], 8);
        assert!(conn.sent.is_empty());
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        assert_eq!(report.stats.discarded_pending_frames, 1);
    }

    #[cfg(not(windows))]
    #[test]
    fn io5_host_path_warning_is_counted_on_non_windows() {
        // 共有ルート + 長い名前で 260 UTF-16 単位を超えるパス。
        let long = ["d".repeat(100), "e".repeat(100), "f".repeat(100)].join("/");
        let (dir, conn, report) = run(vec![create(1, &long)], 1);
        assert_eq!(ack_ids(&conn.sent), vec![1]);
        assert_eq!(report.stats.host_path_warnings, 1);
        assert!(dir.0.join(long).exists());
    }

    #[test]
    fn io1_max_open_files_range() {
        assert_eq!(MaxOpenFiles::default().get(), 256);
        assert_eq!(MaxOpenFiles::new(1).expect("1").get(), 1);
        assert_eq!(MaxOpenFiles::new(4096).expect("max").get(), 4096);
        for bad in [0usize, 4097] {
            let err = MaxOpenFiles::new(bad).expect_err("out of range");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    #[derive(Default)]
    struct Collect(Mutex<Vec<(IoOpKind, IoOpOutcome)>>);
    impl IoOpRecorder for Collect {
        fn record_io_op(&self, sample: &IoOpSample) {
            self.0
                .lock()
                .expect("lock")
                .push((sample.kind(), sample.outcome()));
        }
    }

    #[test]
    fn repair4_create_is_recorded_as_create_op() {
        let dir = Dir::new();
        let creator = GuestFileCreator::new(dir.0.clone()).expect("creator");
        let mut conn = Fake::new(vec![create(1, "a"), create(2, "A"), write_file(3, 1, b"x")]);
        let rec = Collect::default();
        let _ = serve_file_connection_with_recorder(
            &mut conn,
            BatchConfig::new(3).expect("3"),
            FileServeLimits::default(),
            &creator,
            timeouts(),
            &rec,
        );
        let got = rec.0.lock().expect("lock").clone();
        assert_eq!(
            got,
            vec![
                (IoOpKind::Create, IoOpOutcome::Success),
                (IoOpKind::Create, IoOpOutcome::Failure),
                (IoOpKind::Write, IoOpOutcome::Success),
            ]
        );
    }
}
