//! バッチ write-back の実行と、サーバー側 ACK 返却（TASK-13.2.2・IO-1・#822）。
//!
//! [`crate::batch::BatchBuffer`]（TASK-13.1）がメモリ内で集約した
//! [`crate::batch::Batch`] を実際にディスクへ書き込み、書き込み完了後に
//! [`crate::protocol::FrameKind::Ack`] フレームを返すところまでをつなぐ。
//! [`crate::server::UdsConnection`]（TASK-13.2.1・#820）のようなトランスポート
//! 1 本（[`crate::transport::FrameSender`] + [`crate::transport::FrameReceiver`]）を
//! 受け取り、そのトランスポート固有のコードには依存しない（generic）ため、
//! 偽トランスポートによる単体テストと、実際の UDS を使った結合試験の両方から
//! 検証できる。
//!
//! # ACK の意味論（受入基準 2・3。IO-1 と IO-2 の区別）
//!
//! [`serve_connection`] が返す通常 ACK（[`FrameKind::Ack`]）は、**そのバッチの
//! 全フレームについて [`BatchSink::write_batch`] が `Ok` を返した時点**（＝OS の
//! ページキャッシュへの `write()` 発行が完了した時点）で送る。`fsync(2)` /
//! `syncfs(2)` 等の永続化は待たない。プロセスが正常に動いている限りこの時点の
//! データは他の reader から見えるが、プロセスクラッシュや電源断では失われうる。
//! これは IO-1 が言う「バッファリング時点で ACK」の、本実装における対応物である。
//!
//! 永続化完了を保証するのは IO-2 の FLUSH ACK（[`FrameKind::FlushAck`]）のみで
//! あり、本モジュールはそれを送らない（下記「FLUSH フレームの扱い」節）。
//! FLUSH ACK の返却・syncfs の呼び出しは TASK-15.2.2（#824）の責務。ACK の
//! API としての文書化（利用者向けの説明）は TASK-17 で行う。
//!
//! # 書き込み先（ワイヤーにパスがない。D1）
//!
//! [`crate::payload`]（TASK-12.2）が定めるワイヤー形式は `[request_id][body]`
//! のみでパス・オフセットを持たないため、本モジュールはファイル命名規則を
//! 独自に作らない。代わりに書き込み先を [`BatchSink`] トレイトとして抽象化し、
//! 呼び出し側が開いた [`std::fs::File`] へ不透明な `body` を到着順に追記する
//! だけの実装（[`AppendFileSink`]）を提供する。サーバーはワイヤーからパスを
//! 一切受け取らず解決もしないため、パストラバーサル・symlink 経由の書き込み
//! 経路は構造上生まれない（security.md）。
//!
//! `body` を不透明なバイト列として追記するのはスタブの意味論であり
//! （REPAIR-3）、ファイル操作（パス・rename・truncate 等。TASK-14 の整合性
//! スイートが要する）をペイロードで表す形式は、今後のプロトコル拡張
//! （IO-1 の I/O 契約変更。`PROTOCOL_VERSION` の繰り上げを伴いうる）として
//! 別途扱う。
//!
//! # FLUSH フレームの扱い（D4。FlushAck は偽装しない）
//!
//! [`FrameKind::Flush`] を受信すると、まず [`decode_request`] で形式
//! （request id がちょうど 8 バイト・body が空）を検証する（Codex #822
//! レビュー指摘。`Write` と同じ検証を経ないまま `take_pending` へ進むと、
//! request id 欠如や余分な body を持つ不正な Flush までバリアとして働き、
//! クライアントが ACK していない保留分を誤って確定させてしまうため）。
//! 検証を通ったら [`crate::batch::BatchBuffer::take_pending`] で件数未達の
//! まま滞留していた分を取り出して書き込み、通常 ACK を返した後、
//! **FlushAck は送らずに** [`crate::error::IoErrorCode::Unimplemented`] で
//! 処理を終える。FLUSH ACK は永続化の保証（IO-2）であり、`syncfs` を呼ばずに
//! 返すと契約違反になるため（fail-closed）。呼び出し側は接続を閉じる。
//!
//! # バッチが件数未達のまま残る場合の発火条件（D3。運用制約）
//!
//! ACK をバッチ書き込みの後に返すため、クライアントが `batch_size` 未満だけ
//! 送って ACK を待つと、サーバー側に発火のきっかけがない。本実装で使える
//! 発火条件は [`crate::batch::BatchTrigger::SizeReached`]・
//! [`crate::batch::BatchTrigger::BytesLimitReached`]・[`FrameKind::Flush`] の
//! 3 つのみ（時間ベースの追い出しは範囲外。IO-10・TASK-16）。呼び出し側は
//! 「クライアントの in-flight 上限 ≥ `batch_size`、または件数未達分の後に
//! `Flush` を送ること」を運用上の前提とする（既定値 64 / 64 で整合）。
//!
//! # ACK していない保留分の扱い（D5。接続断・エラー時は破棄）
//!
//! 受信エラー（EOF を含む）・プロトコル違反・sink の失敗で処理を終えるとき、
//! [`crate::batch::BatchBuffer`] に残った保留分は**書き込まずに破棄**する
//! （[`WritebackStats::discarded_pending_frames`] に件数を残す）。ACK を返して
//! いない以上クライアントはそれらを前提にできず、書いてしまうと再送時に
//! 重複を生むため（P1-3 の fail-closed と一貫する）。
//!
//! # sink の失敗（D6）
//!
//! [`BatchSink::write_batch`] が `Err` を返すと、そのバッチのフレームには
//! ACK を 1 件も返さずに処理を終える。バッチの途中まで書き込まれた可能性が
//! ある（部分書き込み）ため、ACK 前の書き込みは「書かれたかどうか不定」と
//! いう意味論になる。
//!
//! # 受信上限（D9。`pending_frames` に `0` を渡す根拠）
//!
//! 本モジュールの write-back は同期的（`Ready` になったバッチをその場で
//! 書き込み・ACK まで終えてから次のフレームを受信する）であり、受信時点で
//! 「排出済みだが未書き込み」のキューは常に空になる。また
//! `BatchBuffer::len() < batch_size ≤ max_pending_frames`（`ReceiveLimits::for_batch`
//! 由来の場合）も常に成り立つ。したがって [`crate::recv_limits::ReceiveLimits::admit`]
//! へ渡す `pending_frames` は常に `0` で構造上正確であり（[`crate::server`]・
//! [`crate::recv_limits`] も同じ不変条件を前提とする）、本モジュールが独自に
//! 別の値を計算する必要はない。write-back を非同期化する場合はこの前提を
//! 見直す必要がある。
//!
//! # 呼び出し文脈
//!
//! [`crate::server::UdsConnection`]（TASK-13.2.1・#820）のような
//! `FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>` を実装する
//! 1 接続分のトランスポートを受け取り、[`serve_connection`] が受信ループを
//! 回す。受付ループ（accept → serve_connection → 次の accept）・同時接続数の
//! 上限・クライアント側 UDS 接続との本番結合は本モジュールの範囲外で、
//! 別 sub-issue（要起票。`server.rs` モジュール doc 参照）が担う。

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom, Write as _};

use crate::batch::{Batch, BatchBuffer, BatchConfig, PushOutcome};
use crate::error::{IoError, IoErrorCode};
use crate::payload::{decode_request, encode_ack};
use crate::protocol::{Frame, FrameKind};
use crate::transport::{FrameReceiver, FrameSender, IoTimeout};

/// [`BatchSink::write_batch`] が書き込んだ内容の要約（REPAIR-4: 可観測性）。
///
/// `#[non_exhaustive]` により、将来のフィールド追加に備える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkWriteReport {
    /// このバッチで書き込んだフレーム件数。
    pub frames_written: usize,
    /// このバッチで書き込んだ body の合計バイト数。
    pub bytes_written: u64,
}

impl SinkWriteReport {
    /// `frames_written`・`bytes_written` から [`SinkWriteReport`] を作る。
    ///
    /// `#[non_exhaustive]` によりフィールドが `pub` でも構造体リテラルでは
    /// crate 外から組み立てられないため、[`BatchSink`] を crate 外で実装する
    /// 側（公開拡張点。coding-rust「crate 境界」参照）が `write_batch` の
    /// 戻り値を作るための唯一の入口として用意する。
    pub fn new(frames_written: usize, bytes_written: u64) -> Self {
        Self {
            frames_written,
            bytes_written,
        }
    }
}

/// バッチをディスク（または他の永続先）へ書き込む抽象（D1）。
///
/// [`serve_connection`] は `Batch` の中身をワイヤーの request id しか知らない
/// 不透明なバイト列として扱い、書き込み先の解決（パス・ファイル種別）は
/// 本トレイトの実装側の責務とする。
///
/// # 契約
/// - `write_batch` はバッチ内の全フレームの書き込みが完了してから `Ok` を返す
///   （部分成功を `Ok` として返さない。呼び出し元〔[`serve_connection`]〕は
///   `Ok` を「バッチ全体が書けた」の意味で ACK 送出の合図に使う）
/// - `Err` を返した場合、呼び出し元はそのバッチのフレームへ ACK を送らない
///   （D6）。バッチの途中まで書き込まれている可能性がある（部分書き込み）
pub trait BatchSink {
    /// バッチ内の各 [`FrameKind::Write`] フレームの body を、挿入順に書き込む。
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError>;
}

/// [`BatchSink`] の最小実装: 呼び出し側が開いた [`File`] へ、バッチ内の各
/// `Write` フレームの body を到着順に `write_all` で追記する（D1）。
///
/// パス解決・ファイルの作成・rename・truncate は行わない（それらはワイヤーに
/// 表現がなく、TASK-14 のファイル操作ペイロード拡張までは呼び出し側が
/// `File` を用意する）。
pub struct AppendFileSink {
    file: File,
}

impl AppendFileSink {
    /// 追記先の `file` から sink を作る。`file` は呼び出し側が書き込みモードで
    /// 開いたものとする。
    ///
    /// # 末尾への位置合わせ（Codex #822 レビュー指摘）
    ///
    /// `AppendFileSink` は「到着順に追記する」契約（構造体ドキュメント参照）を
    /// 持つが、`file` を `OpenOptions::write(true)`（`append(true)` を付けずに）
    /// で開んだだけでは書き込み位置が既定でファイル先頭になり、`write_batch`
    /// の `write_all` が既存内容を上書きしてしまう。呼び出し側がどちらの
    /// モードで開いたかに関わらず追記契約を満たせるよう、ここで明示的に
    /// `SeekFrom::End(0)` へ位置合わせしてから返す（OS の `O_APPEND` に頼ると
    /// 各書き込みがアトミックに末尾へ移動する一方、通常モードでは `seek` は
    /// 一度きりで以後は逐次書き込みに委ねる違いがあるが、本 sink は単一の
    /// `serve_connection` ループからのみ使われ他プロセスとの競合書き込みを
    /// 想定しないため、この違いは契約上問題にならない）。
    pub fn new(mut file: File) -> Result<Self, IoError> {
        file.seek(SeekFrom::End(0)).map_err(|err| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to seek to end of file ({:?})", err.kind()),
            )
        })?;
        Ok(Self { file })
    }

    /// 内部の [`File`] を参照で取り出す（TASK-15.2.2・#824 が `fsync` /
    /// `syncfs` 用に fd を取るために使う想定）。
    pub fn get_ref(&self) -> &File {
        &self.file
    }

    /// 内部の [`File`] を所有権ごと取り出す。
    pub fn into_inner(self) -> File {
        self.file
    }
}

/// [`std::io::Error`] を [`IoError`] へ変換する（D6）。
///
/// `message` にはエラー種別（[`io::ErrorKind`]）とバッチ内フレーム件数だけを
/// 載せ、書き込んだデータの中身・パスは含めない（security.md「情報漏えい」
/// 観点）。`ErrorKind::StorageFull`（ENOSPC 相当）は
/// [`IoErrorCode::ResourceExhausted`] とし、それ以外は [`IoErrorCode::Internal`]
/// とする。
fn sink_error_from_io(err: &io::Error, batch_len: usize) -> IoError {
    let code = if err.kind() == io::ErrorKind::StorageFull {
        IoErrorCode::ResourceExhausted
    } else {
        IoErrorCode::Internal
    };
    IoError::new(
        code,
        format!(
            "sink write failed ({:?}) while writing a batch of {batch_len} frame(s)",
            err.kind()
        ),
    )
}

impl BatchSink for AppendFileSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        let mut frames_written: usize = 0;
        let mut bytes_written: u64 = 0;

        for frame in batch.frames() {
            // batch.rs の契約により frame.kind() は常に Write。decode_request は
            // serve_connection が受信直後に一度検証済みだが、Batch は Frame を
            // 値として保持するため、body を取り出すにはもう一度呼ぶ必要がある
            // （unwrap せず Result のまま扱う。coding-rust「外部入力の経路では
            // unwrap しない」）。
            let envelope = decode_request(frame)?;
            self.file
                .write_all(envelope.body())
                .map_err(|err| sink_error_from_io(&err, batch.len()))?;

            frames_written = frames_written.checked_add(1).ok_or_else(|| {
                IoError::new(IoErrorCode::Internal, "frames_written counter overflowed")
            })?;
            let body_len = u64::try_from(envelope.body().len()).map_err(|_| {
                IoError::new(IoErrorCode::Internal, "body length does not fit in u64")
            })?;
            bytes_written = bytes_written.checked_add(body_len).ok_or_else(|| {
                IoError::new(IoErrorCode::Internal, "bytes_written counter overflowed")
            })?;
        }

        Ok(SinkWriteReport::new(frames_written, bytes_written))
    }
}

/// [`serve_connection`] が送受信それぞれに使うタイムアウト（REPAIR-5）。
#[derive(Debug, Clone, Copy)]
pub struct WritebackTimeouts {
    /// [`FrameReceiver::recv_frame`] に渡すタイムアウト。
    pub recv: IoTimeout,
    /// [`FrameSender::send_frame`]（ACK 送出）に渡すタイムアウト。
    pub send: IoTimeout,
}

/// [`serve_connection`] が返す統計（REPAIR-4: 可観測性）。
///
/// 真偽値・フラットな文字列ではなく件数を持つ構造体として返す
/// （coding-rust「戻り値は将来拡張できる構造を持つ型にする」）。
/// `#[non_exhaustive]` により将来のフィールド追加に備える。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct WritebackStats {
    /// 受信したフレームの総数（種別を問わない）。
    pub frames_received: u64,
    /// 書き込みを実行したバッチの総数。
    pub batches_written: u64,
    /// 書き込んだ body の合計バイト数。
    pub bytes_written: u64,
    /// 送出した通常 ACK（[`FrameKind::Ack`]）の総数。
    pub acks_sent: u64,
    /// ACK を送らずに破棄した滞留フレーム件数（D5）。
    pub discarded_pending_frames: u64,
}

/// [`serve_connection`] の戻り値（D7）。
///
/// ループは常にエラー（EOF を含む。P1-3 の下では EOF も
/// [`IoErrorCode::Unavailable`] になる）で終わるため、「Ok 側を持たない
/// `Result`」を表現する代わりに本構造体を返す（coding-rust「戻り値は
/// 将来拡張できる構造を持つ型にする」）。`end` がループの終了原因、`stats` が
/// そこまでの累積統計。
#[derive(Debug)]
#[non_exhaustive]
pub struct WritebackReport {
    /// ループ終了時点までの累積統計。
    pub stats: WritebackStats,
    /// ループの終了原因（正常終了はない。上記モジュール doc 参照）。
    pub end: IoError,
}

/// バッチ内の各フレームへ、挿入順（到着順）に通常 ACK を送る（[`FrameKind::Ack`]。
/// D2）。[`decode_request`] の再デコードが失敗するのは構造上起こらない分岐だが
/// `unwrap` せず [`IoErrorCode::Internal`] として扱う。
fn send_acks_in_order<T>(
    conn: &mut T,
    batch: &Batch,
    timeout: IoTimeout,
    stats: &mut WritebackStats,
) -> Result<(), IoError>
where
    T: FrameSender<Frame = Frame>,
{
    for frame in batch.frames() {
        let envelope = decode_request(frame).map_err(|_| {
            IoError::new(
                IoErrorCode::Internal,
                "failed to re-decode a frame already accepted by BatchBuffer::push",
            )
        })?;
        let ack = encode_ack(FrameKind::Ack, envelope.id())?;
        conn.send_frame(&ack, timeout)?;
        stats.acks_sent = stats.acks_sent.saturating_add(1);
    }
    Ok(())
}

/// バッチを `sink` へ書き込み、成功したら到着順に通常 ACK を送る（D2・D6の
/// 「sink 失敗時は ACK を 1 件も返さない」を 1 か所にまとめる）。
///
/// `sink.write_batch` の契約（[`BatchSink`] のドキュメント）は
/// 「バッチ全体が書けたときだけ `Ok`」だが、`Ok` の中身（`frames_written`）を
/// 信頼せずここで `batch.len()` と突き合わせて検証する。現行の
/// [`AppendFileSink`] は常に一致するが、将来別実装の `sink` が件数不一致の
/// `Ok` を返す可能性に備えたフェイルクローズ（防御的検証。coding-rust
/// 「外部入力の経路では明示的に処理する」の趣旨を sink 実装の誤りにも適用）。
fn write_batch_and_ack<T, W>(
    conn: &mut T,
    sink: &mut W,
    batch: &Batch,
    timeout: IoTimeout,
    stats: &mut WritebackStats,
) -> Result<(), IoError>
where
    T: FrameSender<Frame = Frame>,
    W: BatchSink,
{
    let report = sink.write_batch(batch)?;
    if report.frames_written != batch.len() {
        return Err(IoError::new(
            IoErrorCode::Internal,
            format!(
                "sink reported frames_written={} but batch.len()={}",
                report.frames_written,
                batch.len()
            ),
        ));
    }
    stats.batches_written = stats.batches_written.saturating_add(1);
    stats.bytes_written = stats.bytes_written.saturating_add(report.bytes_written);
    send_acks_in_order(conn, batch, timeout, stats)
}

/// 1 接続分のバッチ write-back を実行する（TASK-13.2.2・IO-1・#822）。
///
/// `conn` は [`FrameSender`] + [`FrameReceiver`]（[`Frame`] を扱う）を実装する
/// トランスポート 1 本（[`crate::server::UdsConnection`] 等）。`config` は
/// [`BatchBuffer`] の集約設定、`sink` は書き込み先（[`AppendFileSink`] 等）、
/// `timeouts` は送受信それぞれのタイムアウト（REPAIR-5）。
///
/// 受信した [`FrameKind::Write`] を [`BatchBuffer::push`] へ渡し、発火した
/// バッチを `sink` へ書き込んでから到着順に ACK を送る。[`FrameKind::Flush`]
/// は滞留分を書き込み・ACK した後 [`IoErrorCode::Unimplemented`] で終える
/// （D4）。[`FrameKind::Ack`] / [`FrameKind::FlushAck`]（クライアントが送る
/// べきでない種別。UDS 経由では [`crate::server`] の受信層が先に拒否するが、
/// generic なトランスポート向けの防御として本関数でも拒否する）は
/// [`IoErrorCode::InvalidArgument`] で終える。
///
/// ループは常にエラーで終わる（[`WritebackReport`] 参照）。終了時、
/// [`BatchBuffer`] に残っていた滞留フレームは書き込まずに破棄し件数を
/// [`WritebackStats::discarded_pending_frames`] へ残す（D5）。
///
/// `config` は [`crate::settings::WritebackSettings::batch_config`] から
/// 渡し、対応する [`crate::server::UdsServer::bind`] には同じ
/// [`crate::settings::WritebackSettings`] インスタンスの
/// [`crate::settings::WritebackSettings::receive_limits`] を渡すことを推奨する
/// （TASK-13.3・#78。両者を別々の設定値から個別に構築すると、受信ゲートと
/// 集約ロジックのバッチサイズが食い違う経路を作れてしまう）。この対応を型で
/// 保証したい場合は、本関数を直接呼ぶ代わりに
/// [`crate::settings::WritebackSettings::bind`] が返す
/// [`crate::settings::BoundWriteback`] と、その [`accept`][ba] が返す
/// [`crate::settings::BoundConnection::serve`] を使う（REPAIR-2・#1115 codex
/// レビュー指摘対応。`serve` は `BatchConfig` を引数に取らず、常に接続元の
/// `WritebackSettings` から導くため、別の設定値を混ぜる経路自体が無い）。
///
/// [ba]: crate::settings::BoundWriteback::accept
pub fn serve_connection<T, W>(
    conn: &mut T,
    config: BatchConfig,
    sink: &mut W,
    timeouts: WritebackTimeouts,
) -> WritebackReport
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
    W: BatchSink,
{
    let mut stats = WritebackStats::default();
    let mut buffer = BatchBuffer::new(config);

    /// ループを終える共通処理: 滞留分を破棄件数として記録し `WritebackReport` を返す
    /// （D5。マクロではなくローカル関数だと `stats`/`buffer` の可変借用が絡むため、
    /// 呼び出し側で都度 1 行にまとめる代わりにこの内部ヘルパーへ集約する）。
    fn finish(mut stats: WritebackStats, buffer: &BatchBuffer, end: IoError) -> WritebackReport {
        // buffer.len() は BatchConfig の上限（バッチサイズ）に抑えられており
        // u64 の範囲を超えることはないが、同ファイル内の他箇所（`sink` 実装
        // 等）と流儀を揃えて `as` キャストではなく `u64::try_from` で扱う。
        // 上限を超えることは構造上ないため通常は到達しないが、万一変換に
        // 失敗した場合は 0 件（＝破棄なし）ではなく `u64::MAX` を用いる
        // （このファイルの他のカウンタが `saturating_add` で飽和側へ倒す
        // のと同じ「失敗を過小報告しない」方針。discarded_pending_frames は
        // 可観測性用カウンタだが、変換失敗を理由にループ終了処理自体は
        // 失敗させない）。
        stats.discarded_pending_frames = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        WritebackReport { stats, end }
    }

    loop {
        let frame = match conn.recv_frame(timeouts.recv) {
            Ok(frame) => frame,
            Err(err) => return finish(stats, &buffer, err),
        };
        stats.frames_received = stats.frames_received.saturating_add(1);

        match frame.kind() {
            FrameKind::Write => {
                // decode_request は Write フレームの形式（request id + body 長）を
                // 検証する。8 バイト未満（request id すら入っていない）等の違反は
                // ここで検出し、バッファへは触れずに終える。
                if let Err(err) = decode_request(&frame) {
                    return finish(stats, &buffer, err);
                }

                let outcome = match buffer.push(frame) {
                    Ok(outcome) => outcome,
                    Err(err) => return finish(stats, &buffer, err),
                };

                let batches: Vec<Batch> = match outcome {
                    PushOutcome::Buffered { .. } => Vec::new(),
                    PushOutcome::Ready(batch) => vec![batch],
                    PushOutcome::ReadyTwice(first, second) => vec![first, second],
                };
                for batch in &batches {
                    if let Err(err) =
                        write_batch_and_ack(conn, sink, batch, timeouts.send, &mut stats)
                    {
                        return finish(stats, &buffer, err);
                    }
                }
            }
            FrameKind::Flush => {
                // Codex #822 レビュー指摘: Write と同様、`decode_request` で
                // 形式（request id ちょうど 8 バイト・body 空）を検証してから
                // 滞留分（`buffer.take_pending()`）へ触れる。request id が
                // 欠けている・余分な body を持つ不正な Flush をバリアとして
                // 扱うと、クライアントが ACK していない書き込みを誤って
                // 確定させてしまうため（D5 の fail-closed と一貫させる）。
                if let Err(err) = decode_request(&frame) {
                    return finish(stats, &buffer, err);
                }

                if let Some(batch) = buffer.take_pending()
                    && let Err(err) =
                        write_batch_and_ack(conn, sink, &batch, timeouts.send, &mut stats)
                {
                    return finish(stats, &buffer, err);
                }
                // D4: FLUSH ACK は永続化の保証（IO-2）であり、syncfs を呼ばずに
                // 返すと契約違反になるため偽装しない。返却は TASK-15.2.2（#824）。
                let err = IoError::new(
                    IoErrorCode::Unimplemented,
                    "flush barrier is not implemented yet (TASK-15)",
                );
                return finish(stats, &buffer, err);
            }
            FrameKind::Ack | FrameKind::FlushAck => {
                let err = IoError::new(
                    IoErrorCode::InvalidArgument,
                    "client must not send Ack/FlushAck frames to the writeback server",
                );
                return finish(stats, &buffer, err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{InFlightLimit, SendQueue};
    use crate::payload::{WireRequestId, encode_request};
    use std::collections::VecDeque;

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(std::time::Duration::from_millis(50)).expect("50ms must be valid")
    }

    fn write_frame(id: u64, body: &[u8]) -> Frame {
        encode_request(FrameKind::Write, wire_id(id), body).expect("encode_request must succeed")
    }

    fn flush_frame(id: u64) -> Frame {
        encode_request(FrameKind::Flush, wire_id(id), &[]).expect("encode_request must succeed")
    }

    fn wire_id(value: u64) -> WireRequestId {
        // WireRequestId::from_wire は非公開のため、テストでは client 側の経路
        // （新しい SendQueue で `0` から順に採番される連番。`RequestId` →
        // `From<RequestId>`）を経由して作る。`SendQueue::register` は
        // 呼ぶたびに連番を 1 つずつ払い出すだけ（`remove` しなくても上限には
        // 達しない小さな `value` のみを本テストで使う）なので、`value + 1` 回
        // 呼んで最後に払い出された id を使えば `value` そのものが得られる。
        let limit = InFlightLimit::new(crate::client::MAX_IN_FLIGHT_LIMIT)
            .expect("MAX_IN_FLIGHT_LIMIT must be a valid limit");
        let mut queue = SendQueue::new(limit);
        let mut last = None;
        for _ in 0..=value {
            let registered = queue
                .register(FrameKind::Write)
                .expect("register must succeed");
            last = Some(registered.id());
        }
        WireRequestId::from(last.expect("loop runs at least once"))
    }

    /// テスト専用の偽トランスポート: `VecDeque` から受信し、送信内容は
    /// `Vec<Frame>` に記録する。受信キューが尽きたら [`IoErrorCode::Unavailable`]
    /// を返す（EOF 相当。P1-3 と同じ意味論。一度 `exhausted` になったら以後も
    /// `Unavailable` を返し続け、poison 済み接続の再利用禁止と同じ形にする）。
    struct FakeTransport {
        incoming: VecDeque<Frame>,
        sent: Vec<Frame>,
        exhausted: bool,
    }

    impl FakeTransport {
        fn new(frames: Vec<Frame>) -> Self {
            Self {
                incoming: frames.into(),
                sent: Vec::new(),
                exhausted: false,
            }
        }
    }

    impl FrameSender for FakeTransport {
        type Frame = Frame;

        fn send_frame(&mut self, frame: &Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            self.sent.push(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for FakeTransport {
        type Frame = Frame;

        fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Frame, IoError> {
            if self.exhausted {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "fake transport exhausted",
                ));
            }
            match self.incoming.pop_front() {
                Some(frame) => Ok(frame),
                None => {
                    self.exhausted = true;
                    Err(IoError::new(
                        IoErrorCode::Unavailable,
                        "fake transport exhausted",
                    ))
                }
            }
        }
    }

    /// テスト専用の偽 sink: 書いた body を記録し、`fail_at`（1-based のバッチ
    /// 呼び出し回数）に達したら以後 `Err` を返す。
    struct FakeSink {
        written: Vec<Vec<u8>>,
        calls: usize,
        fail_at: Option<usize>,
    }

    impl FakeSink {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                calls: 0,
                fail_at: None,
            }
        }

        fn failing_at(fail_at: usize) -> Self {
            Self {
                written: Vec::new(),
                calls: 0,
                fail_at: Some(fail_at),
            }
        }
    }

    impl BatchSink for FakeSink {
        fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
            self.calls += 1;
            if self.fail_at == Some(self.calls) {
                return Err(IoError::new(IoErrorCode::Internal, "fake sink failure"));
            }
            let mut frames_written = 0usize;
            let mut bytes_written = 0u64;
            for frame in batch.frames() {
                let envelope = decode_request(frame).expect("test frames must decode");
                self.written.push(envelope.body().to_vec());
                frames_written += 1;
                bytes_written += envelope.body().len() as u64;
            }
            // `SinkWriteReport::new` を使う（crate 外実装が使う唯一の構築経路
            // であることの回帰確認を兼ねる。Bugbot #822 レビュー指摘）。
            Ok(SinkWriteReport::new(frames_written, bytes_written))
        }
    }

    fn timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: test_timeout(),
            send: test_timeout(),
        }
    }

    /// IO-1: `batch_size = 3` で Write を 6 件送ると、ACK が 6 件・id が送信順・
    /// sink の呼び出しが 2 回になり、各バッチの書き込みがその ACK より先に
    /// 完了している（sink 呼び出し後に ACK が積まれる実装のため、`sent` の
    /// 並び自体が書き込み → ACK の順序を保証する）。
    #[test]
    fn io1_writeback_batches_and_acks_in_order() {
        let frames: Vec<Frame> = (0..6u64).map(|id| write_frame(id, b"x")).collect();
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(3).expect("3 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 6);
        assert_eq!(report.stats.batches_written, 2);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(sink.calls, 2);
        assert_eq!(sink.written.len(), 6);

        let acked_ids: Vec<u64> = conn.sent.iter().map(ack_id).collect();
        assert_eq!(acked_ids, vec![0, 1, 2, 3, 4, 5]);
    }

    /// `Frame`（Ack）から request id を取り出すテスト専用ヘルパー。
    fn ack_id(frame: &Frame) -> u64 {
        crate::payload::decode_ack(frame)
            .expect("sent frame must be a valid ack")
            .id()
            .get()
    }

    /// IO-1・D4: Write 2 件 + Flush で、ACK が 2 件・FlushAck は 0 件、
    /// 終了原因が `Unimplemented` になる。
    #[test]
    fn io1_writeback_flush_acks_pending_then_unimplemented() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b"), flush_frame(2)];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::default();

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 2);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        assert!(conn.sent.iter().all(|frame| frame.kind() == FrameKind::Ack));
    }

    /// IO-1・REPAIR-2（Codex #822 レビュー指摘）: request id を持たない
    /// （空ペイロードの）Flush は `decode_request` に拒否され
    /// `InvalidArgument` で終わる。滞留していた Write はバリアとして
    /// 書き込まれず（`sink.calls == 0`）、ACK も送らず破棄される
    /// （`discarded_pending_frames`）。
    #[test]
    fn io1_writeback_rejects_malformed_flush_without_touching_pending() {
        let malformed_flush =
            Frame::new(FrameKind::Flush, Vec::new()).expect("empty payload must construct");
        let frames = vec![write_frame(0, b"a"), malformed_flush];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(4).expect("4 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(sink.calls, 0, "malformed flush must not trigger a write");
        assert_eq!(report.stats.discarded_pending_frames, 1);
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-2（Codex #822 レビュー指摘）: request id に続けて余分な
    /// body を持つ Flush も同様に `InvalidArgument` で拒否される。
    #[test]
    fn io1_writeback_rejects_flush_with_extra_body_without_touching_pending() {
        let mut payload = 7u64.to_le_bytes().to_vec();
        payload.extend_from_slice(b"unexpected-body");
        let malformed_flush =
            Frame::new(FrameKind::Flush, payload).expect("payload must construct");
        let frames = vec![write_frame(0, b"a"), malformed_flush];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(4).expect("4 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(sink.calls, 0, "malformed flush must not trigger a write");
        assert_eq!(report.stats.discarded_pending_frames, 1);
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・D5: `batch_size = 4` で 2 件送って EOF（`Unavailable`）になると、
    /// ACK は 0 件・sink は呼ばれず、`discarded_pending_frames == 2`。
    #[test]
    fn io1_writeback_discards_pending_on_disconnect() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b")];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(4).expect("4 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(sink.calls, 0);
        assert_eq!(report.stats.discarded_pending_frames, 2);
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・REPAIR-2: 8 バイト未満の Write（request id すら入っていない）は
    /// `InvalidArgument` で終わり、ACK は 0 件。
    #[test]
    fn io1_writeback_rejects_malformed_write() {
        let malformed =
            Frame::new(FrameKind::Write, vec![0u8; 4]).expect("short payload must construct");
        let mut conn = FakeTransport::new(vec![malformed]);
        let mut sink = FakeSink::new();

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    /// D6: sink の失敗では、そのバッチの ACK が 0 件で、終了原因のコードが
    /// sink のエラー由来（本テストでは `Internal`）になる。
    #[test]
    fn d6_writeback_sink_failure_sends_no_ack_for_that_batch() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b")];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::failing_at(1);
        let config = BatchConfig::new(2).expect("2 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(report.end.code(), IoErrorCode::Internal);
    }

    /// クライアント発の `Ack` / `FlushAck` は `InvalidArgument` になる
    /// （generic なトランスポート向けの防御。UDS では受信層が先に拒否する）。
    #[test]
    fn writeback_rejects_client_sent_ack_kinds() {
        for kind in [FrameKind::Ack, FrameKind::FlushAck] {
            let ack = encode_ack(kind, wire_id(0)).expect("encode_ack must succeed");
            let mut conn = FakeTransport::new(vec![ack]);
            let mut sink = FakeSink::new();

            let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

            assert_eq!(report.stats.acks_sent, 0);
            assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        }
    }

    /// バイト数上限で `BytesLimitReached` が発火したバッチも到着順に ACK される。
    #[test]
    fn writeback_acks_batch_fired_by_bytes_limit() {
        // BatchBuffer が上限と比較する `frame.payload().len()` は「request id
        // （REQUEST_ID_WIRE_LEN = 8 バイト）+ body」の合計（`crate::batch` の
        // `push` ドキュメンテーションコメント参照）。batch_size は十分大きく、
        // bytes 側の上限（1 フレームぶんの payload 長ちょうど = 8 + 4 = 12 バイト）
        // だけが効くようにする。1 件 4 バイトの body（payload 12 バイト）を
        // 2 件送ると、2 件目の push で 1 件目が BytesLimitReached として発火する。
        let max_bytes = crate::payload::REQUEST_ID_WIRE_LEN + 4;
        let config = BatchConfig::with_max_bytes(64, max_bytes).expect("valid config must succeed");
        let frames = vec![write_frame(0, b"aaaa"), write_frame(1, b"bbbb")];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        // 1 件目は BytesLimitReached で発火し ACK 済み、2 件目は EOF 時点で
        // 滞留したまま破棄される。
        assert_eq!(report.stats.acks_sent, 1);
        assert_eq!(report.stats.discarded_pending_frames, 1);
        assert_eq!(sink.written, vec![b"aaaa".to_vec()]);
    }

    /// [`AppendFileSink`] は body を到着順に追記し、`get_ref` / `into_inner` で
    /// 内部の `File` を取り出せる（TASK-15.2.2・#824 が fd を必要とする想定の
    /// 回帰点）。
    #[test]
    fn append_file_sink_appends_bodies_in_order() {
        let dir = std::env::temp_dir().join(format!(
            "fcio-writeback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("must create temp dir");
        let path = dir.join("out.bin");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("must open output file");

        let mut sink = AppendFileSink::new(file).expect("seek to end must succeed");
        let mut buffer = BatchBuffer::new(BatchConfig::new(2).expect("2 must be valid"));
        let batch = match buffer
            .push(write_frame(0, b"ab"))
            .expect("push must succeed")
        {
            PushOutcome::Buffered { .. } => {
                match buffer
                    .push(write_frame(1, b"cd"))
                    .expect("push must succeed")
                {
                    PushOutcome::Ready(batch) => batch,
                    other => panic!("expected Ready, got {other:?}"),
                }
            }
            other => panic!("expected Buffered on first push, got {other:?}"),
        };

        let report = sink.write_batch(&batch).expect("write_batch must succeed");
        assert_eq!(report.frames_written, 2);
        assert_eq!(report.bytes_written, 4);

        // `get_ref` で内部の File に触れられることを確認してから、`path` 経由で
        // 書き込み内容を読む（`File` 自体からパスを復元する API はない）。
        let _ = sink.get_ref();
        let contents = std::fs::read(&path).expect("must read output file");
        assert_eq!(contents, b"abcd");

        let _ = sink.into_inner();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex #822 レビュー指摘: `file` を `truncate(false)`（かつ `append(true)`
    /// を付けない）`write(true)` で開いた既存ファイルへ `AppendFileSink::new`
    /// を渡しても、`write_batch` は先頭から上書きせず既存内容の末尾へ追記する
    /// （追記契約〔構造体ドキュメント〕の回帰確認）。
    #[test]
    fn append_file_sink_appends_after_existing_content_without_append_mode() {
        let dir = std::env::temp_dir().join(format!(
            "fcio-writeback-existing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("must create temp dir");
        let path = dir.join("out.bin");
        std::fs::write(&path, b"existing").expect("must seed existing content");

        // `append(true)` を付けず、`truncate` もしない（=呼び出し側が
        // 追記の作法を守らなくても `AppendFileSink::new` 自身が末尾へ
        // 位置合わせすることの確認）。
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("must open existing output file");

        let mut sink = AppendFileSink::new(file).expect("seek to end must succeed");
        let mut buffer = BatchBuffer::new(BatchConfig::new(1).expect("1 must be valid"));
        let batch = match buffer
            .push(write_frame(0, b"-new"))
            .expect("push must succeed")
        {
            PushOutcome::Ready(batch) => batch,
            other => panic!("expected Ready with batch_size=1, got {other:?}"),
        };

        let report = sink.write_batch(&batch).expect("write_batch must succeed");
        assert_eq!(report.frames_written, 1);
        assert_eq!(report.bytes_written, 4);

        let contents = std::fs::read(&path).expect("must read output file");
        assert_eq!(
            contents, b"existing-new",
            "write_batch must append after existing content, not overwrite it from offset 0"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IO-1: `serve_connection` へ渡す `FakeTransport` は `Send` を満たす
    /// （`FrameSender`/`FrameReceiver` が crate 内で `Send` を要求する契約と
    /// 整合。コンパイル時確認。`BatchSink` 自体は `Send` を要求しない）。
    #[test]
    fn io1_fake_transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<FakeTransport>();
    }
}
