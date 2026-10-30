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
//! # スタブの明示（REPAIR-3）
//! この時点の persist は未実装で、明示 `Flush` と IO-10 の上限到達は、滞留分を実行して応答を
//! 送った後に [`IoErrorCode::Unimplemented`] で接続を終える。`FlushAck` は送らない
//! （偽装しない。fail-closed）。各 sink の `persist()` も呼ばない。永続化（デバイスごとの
//! 同期・番兵 fd・Close 済み未永続化ファイルの保持表）と自動フラッシュ、F13 のうち FLUSH 系の
//! 統計は #3164（IO-2・IO-10）が担う。Close は fd をその場で閉じる（保持表は #3164）。

use std::collections::HashMap;

use crate::barrier::{UnflushedBacklog, UnflushedLimit};
use crate::batch::{Batch, BatchBuffer, BatchConfig, PushOutcome};
use crate::error::{IoError, IoErrorCode};
use crate::guest_files::{GuestFileCreator, classify_create_failure};
use crate::instrument::{IoOpKind, IoOpRecorder, IoOpTimer, NoopIoOpRecorder};
use crate::payload::{
    NackCode, NackReason, decode_close, decode_create, decode_nack, decode_request,
    decode_write_file, encode_ack, encode_nack,
};
use crate::protocol::{Frame, FrameKind};
use crate::transport::{FrameReceiver, FrameSender, IoTimeout};
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

/// [`serve_file_connection_with_limit`] に渡す資源上限の束。
///
/// `#[non_exhaustive]` で、#3164 が保持中ファイル数の上限などを足せる形にしてある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileServeLimits {
    max_open_files: MaxOpenFiles,
    unflushed: UnflushedLimit,
}

impl FileServeLimits {
    /// 上限を組み立てる。
    pub fn new(max_open_files: MaxOpenFiles, unflushed: UnflushedLimit) -> Self {
        Self {
            max_open_files,
            unflushed,
        }
    }

    /// 同時に開けるファイル数の上限。
    pub fn max_open_files(&self) -> MaxOpenFiles {
        self.max_open_files
    }

    /// 未フラッシュ滞留量の上限（IO-10）。
    pub fn unflushed(&self) -> UnflushedLimit {
        self.unflushed
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
/// FLUSH 系の統計（デバイス・ファイル・ディレクトリの数、自動フラッシュ回数、保持数の最大値）は
/// 永続化の実体（#3164）と合わせて足す（REPAIR-3）。
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
    /// 最後に成功した永続化以降に受理した未フラッシュ滞留量（IO-10。現状は永続化が未実装で
    /// 増える一方）。
    pub unflushed: UnflushedBacklog,
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
    let mut server = FileServer {
        table: HashMap::new(),
        creator,
        recorder,
        max_open: limits.max_open_files().get(),
        last_request_id: None,
        stats: FileServeStats::default(),
    };
    let mut buffer = BatchBuffer::new(config);
    let end = server.run(conn, &mut buffer, limits.unflushed(), timeouts);
    let mut stats = server.stats;
    stats.discarded_pending_frames = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
    FileServeReport { stats, end }
}

/// 接続 1 本分の状態（ハンドル表と統計）。
struct FileServer<'a> {
    /// ハンドル（`Create` の request id）から書き込み先への表。長さは `max_open` 以下。
    table: HashMap<u64, AppendFileSink>,
    creator: &'a GuestFileCreator,
    recorder: &'a dyn IoOpRecorder,
    max_open: usize,
    /// 受理した最後の request id。単調増加の検査用（接続内で再利用させない）。
    last_request_id: Option<u64>,
    stats: FileServeStats,
}

fn persist_unimplemented() -> IoError {
    IoError::new(
        IoErrorCode::Unimplemented,
        "persist for file operation mode is not implemented (IO-2, #3164)",
    )
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
                Ok(Some(len)) => len,
                Ok(None) => {
                    // Flush: 形式は検証済み。滞留分を実行・応答してから persist スタブで終える。
                    return self.drain_then_unimplemented(conn, buffer, timeouts.send);
                }
                Err(err) => return err,
            };

            // IO-10: 受理するとバイト上限を超えるなら、受理前に滞留分を実行して終える。
            // push が拒否する過大なフレームでは保留分に触れない。
            let acceptable = frame.payload().len() <= buffer.config().max_bytes();
            if acceptable
                && !self.stats.unflushed.is_empty()
                && limit.would_exceed_bytes(&self.stats.unflushed, body_len)
            {
                return self.drain_then_unimplemented(conn, buffer, timeouts.send);
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
            if limit.is_reached(&self.stats.unflushed) {
                return self.drain_then_unimplemented(conn, buffer, timeouts.send);
            }
        }
    }

    /// 受信フレームの種別と形式を検証する。`Some(n)` はバッチに積む要求（n は IO-10 に数える
    /// body バイト数）、`None` は形式の正しい `Flush`。
    fn validate(&self, frame: &Frame) -> Result<Option<usize>, IoError> {
        match frame.kind() {
            FrameKind::Create => decode_create(frame).map(|_| Some(0)),
            FrameKind::WriteFile => decode_write_file(frame).map(|e| Some(e.body().len())),
            FrameKind::Close => decode_close(frame).map(|_| Some(0)),
            FrameKind::Flush => decode_request(frame).map(|_| None),
            FrameKind::Write | FrameKind::Ack | FrameKind::FlushAck | FrameKind::Nack => {
                Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    "frame kind not accepted in file operation mode",
                ))
            }
        }
    }

    /// 滞留分を実行して応答を送り、persist スタブ（`Unimplemented`）の終了原因を返す。
    /// 応答の送信に失敗したときはその失敗を返す。
    fn drain_then_unimplemented<T>(
        &mut self,
        conn: &mut T,
        buffer: &mut BatchBuffer,
        send: IoTimeout,
    ) -> IoError
    where
        T: FrameSender<Frame = Frame>,
    {
        if let Some(batch) = buffer.take_pending()
            && let Err(err) = self.run_batch(conn, &batch, send)
        {
            return err;
        }
        persist_unimplemented()
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
        match self.creator.create_file_inner(path) {
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
        // 表から外して sink を drop し fd を閉じる。永続化の保証はしない（F8。保持表は #3164）。
        if self.table.remove(&handle).is_none() {
            return self.nack(id, NackReason::UnknownHandle);
        }
        self.stats.closes_succeeded = self.stats.closes_succeeded.saturating_add(1);
        encode_ack(FrameKind::Ack, id)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn io2_flush_in_file_mode_is_unimplemented_without_flush_ack() {
        let (_d, conn, report) = run(vec![create(1, "a"), write_file(2, 1, b"z"), flush(3)], 8);
        assert_eq!(ack_ids(&conn.sent), vec![1, 2]);
        assert!(conn.sent.iter().all(|f| f.kind() != FrameKind::FlushAck));
        assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
    }

    #[test]
    fn io10_unflushed_limit_ends_with_unimplemented_without_flush_ack() {
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
        // 3 件目の受理で上限に達し、滞留分の Ack を送ってから終える。
        assert_eq!(ack_ids(&conn.sent), vec![1, 2, 3]);
        assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        assert_eq!(report.stats.unflushed.frames(), 3);
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
