//! ストリーム型トランスポート（UDS・vsock）が共有する、フレーム単位の期限付き
//! read / write の部品（IO-1・REPAIR-5・TASK-13.2.1・#820、vsock 追加は #1119）。
//!
//! # 役割と呼び出し文脈
//! - `crate::server`（UDS サーバー。[`crate::server::UdsConnection`]）と
//!   `crate::vsock`（vsock サーバー・クライアント。[`crate::vsock::VsockConnection`]）
//!   が、接続ごとの `send_frame` / `recv_frame` の下回りとして呼ぶ。両者が期限・
//!   `ReceiveLimits`・本体バッファの段階的確保・drain モードの扱いを 1 か所で共有し、
//!   片方だけ直る不整合を避ける（REPAIR-1）。
//! - ストリームの種別は [`TimedStream`] で抽象化する。`UnixStream` と、vsock の
//!   fd を包んだ `TcpStream`（std の `From<OwnedFd>`。`read` / `write` /
//!   `SO_RCVTIMEO` / `SO_SNDTIMEO` / `shutdown` / `dup` はソケットのアドレスファミリに
//!   依存しない syscall のため vsock にもそのまま使える。`crate::vsock` 参照）を実装する。
//! - 挙動は UDS 専用だった時点（#820・#1115）から変えていない。macOS の
//!   `EINVAL` 判定（[`SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN`]）は UDS の
//!   macOS 向けヒューリスティックで、vsock（Linux 限定）では `false` の分岐だけを通る。

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use crate::error::{IoError, IoErrorCode};
use crate::protocol::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind};
use crate::recv_limits::ReceiveLimits;
use crate::server::RecvAttempt;
use crate::transport::IoTimeout;

/// 期限付き read / write に必要なストリーム操作（`UnixStream` と vsock 用
/// `TcpStream` が同名の固有メソッドを持つため、委譲するだけの薄いトレイト）。
pub(crate) trait TimedStream: Read + Write {
    /// `SO_RCVTIMEO` を設定する（`None` は無期限。`Some(ZERO)` は std がエラーにする）。
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    /// `SO_SNDTIMEO` を設定する。
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    /// nonblocking 状態を切り替える（drain モード用）。
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
}

impl TimedStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, dur)
    }
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_nonblocking(self, nonblocking)
    }
}

impl TimedStream for std::net::TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, dur)
    }
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        std::net::TcpStream::set_nonblocking(self, nonblocking)
    }
}

/// accept の期限切れを表すエラー（`crate::server` / `crate::vsock` の accept の全経路で共有する。
/// ループ先頭・成功経路・WouldBlock・再試行判定のどこで期限切れを検出しても
/// 同じ `code` / `message` を返し、観測イベントの見分けがつくようにする。
/// REPAIR-4・REPAIR-5・#820）。
pub(crate) fn accept_timeout_error() -> IoError {
    IoError::new(
        IoErrorCode::Timeout,
        "accept timed out waiting for a client connection",
    )
}

/// 受付ループの再試行判定（H3・H4・#820 security-auditor 指摘対応）。
///
/// `remaining` が `Duration::ZERO` なら [`IoErrorCode::Timeout`]、
/// `retries` が `max_retries` を超えていれば [`IoErrorCode::Unavailable`]
/// （相手に起因する異常であり、実装バグを示す `Internal` ではない。H4）、
/// どちらでもなければ `None`（再試行を続ける）を返す純粋関数。
///
/// 呼び出し元（`crate::server` / `crate::vsock` の accept）は、この判定の**前に**必ず件数の
/// 加算・（peer credential 拒否の場合の）拒否の通知を済ませておく（H3。
/// 期限の直前に起きた拒否も件数・記録に残すため）。
pub(crate) fn accept_retry_deadline_or_limit(
    remaining: Duration,
    retries: u32,
    max_retries: u32,
    exceeded_message: &str,
) -> Option<IoError> {
    if remaining.is_zero() {
        return Some(accept_timeout_error());
    }
    if retries > max_retries {
        return Some(IoError::new(
            IoErrorCode::Unavailable,
            exceeded_message.to_string(),
        ));
    }
    None
}

/// `accept` が `ConnectionAborted`（相手が accept 完了前に切断した）を
/// 受け続けた場合の再試行回数の上限（REPAIR-5: 相手の応答を待つ処理は
/// 無期限にループしない。`deadline` 自体も毎回照合するため、この上限は
/// 「短時間に大量の切断が続く」病的なケースの保険）。
pub(crate) const MAX_ACCEPT_ABORT_RETRIES: u32 = 32;

/// サーバーが受信してはならない応答系種別（`Ack`・`FlushAck`）を拒否する
/// （IO-1・REPAIR-2・#820 レビュー指摘）。
///
/// UDS・vsock のサーバー側はクライアントからの `Write` / `Flush` のみを受け取る
/// 想定であり（`Ack` / `FlushAck` はサーバーからクライアントへ返す側）、
/// クライアントからこれらが届くのはプロトコル違反として扱う
/// （`FrameKind` の全バリアントを列挙する `match` にし、将来種別が
/// 追加された場合はここがコンパイルエラーになって判断漏れを防ぐ。
/// fail-closed）。`crates/io/src/recv_limits.rs` モジュール doc の
/// 「スコープ外」節が「サーバー側で Ack / FlushAck を受信した場合の拒否は
/// TASK-13.2.1（#820）が担う」としている箇所の実体がこの関数である。
pub(crate) fn reject_client_originated_response_frame(kind: FrameKind) -> Result<(), IoError> {
    match kind {
        FrameKind::Write | FrameKind::Flush => Ok(()),
        FrameKind::Ack | FrameKind::FlushAck => Err(IoError::new(
            IoErrorCode::InvalidArgument,
            format!("server does not accept client-originated response frames: {kind:?}"),
        )),
    }
}

/// `crate::protocol` の「ストリーム読みの手順」（1: 固定長ヘッダを読む→
/// 2: `FrameHeader::from_bytes` で検証→3: 方向的に受理できない種別を確保前に拒否→
/// 4: `ReceiveLimits::admit` で確保前の受理判定→5: 検証済みの `body_len` を上限に
/// 本体を読む→6: `Frame::decode_body`）を実装する共通部。
///
/// `accept_kind` は「この側が受信してよい種別」の判定で、サーバー側は
/// `Write` / `Flush` のみ、クライアント側は `Ack` / `FlushAck` のみを通す
/// （方向違いのフレームは `InvalidArgument`。IO-1・REPAIR-2）。`limits` は
/// bind / connect で渡された値を使い、既定値を暗黙に使わない（TASK-13.4）。
/// `pending_frames` は常に 0（単一接続のみを担い、複数接続を跨ぐキューを持たない。
/// `crate::server` の「範囲外」節参照）。
pub(crate) fn recv_frame_on<S: TimedStream>(
    stream: &mut S,
    timeout: IoTimeout,
    limits: ReceiveLimits,
    accept_kind: fn(FrameKind) -> Result<(), IoError>,
) -> RecvAttempt {
    let deadline = Instant::now() + timeout.as_duration();

    let mut header_bytes = [0u8; FRAME_HEADER_LEN];
    if let Err(e) = read_exact_until(stream, &mut header_bytes, deadline, "frame header") {
        return RecvAttempt {
            result: Err(e),
            kind: None,
        };
    }
    let header = match FrameHeader::from_bytes(header_bytes) {
        Ok(header) => header,
        Err(e) => {
            return RecvAttempt {
                result: Err(e),
                kind: None,
            };
        }
    };
    let kind = header.kind();
    if let Err(e) = accept_kind(kind) {
        return RecvAttempt {
            result: Err(e),
            kind: Some(kind),
        };
    }
    let admitted = match limits.admit(header, 0) {
        Ok(admitted) => admitted,
        Err(e) => {
            return RecvAttempt {
                result: Err(e),
                kind: Some(kind),
            };
        }
    };
    let body = match read_body_until(stream, admitted.body_len(), deadline) {
        Ok(body) => body,
        Err(e) => {
            return RecvAttempt {
                result: Err(e),
                kind: Some(kind),
            };
        }
    };
    RecvAttempt {
        result: admitted.decode_body_owned(body),
        kind: Some(kind),
    }
}

/// `frame` をエンコードし、フレーム単位の期限つきで最後まで書き切る。
pub(crate) fn send_frame_on<S: TimedStream>(
    stream: &mut S,
    frame: &Frame,
    timeout: IoTimeout,
) -> Result<(), IoError> {
    let deadline = Instant::now() + timeout.as_duration();
    let bytes = frame.encode();
    write_all_until(stream, &bytes, deadline)
}

/// 本体読み込みを少しずつ伸ばす際の 1 回あたりの伸長量の上限
/// （申告された `body_len` が最大 64 MiB + 4 バイトでも、悪意ある相手の
/// 申告だけを信用して一度に確保しない。security.md。伸ばし方は
/// `BodyBuffer` 参照）。
pub(crate) const BODY_READ_CHUNK: usize = 64 * 1024;

/// `set_read_timeout` / `set_write_timeout` に渡す残り時間の下限
/// （#1115 codex レビュー指摘対応・macOS CI 実バグ修正）。
///
/// これらの std API は `Duration` をマイクロ秒精度の `timeval` へ変換して
/// `setsockopt(2)` へ渡す。期限直前で `remaining_or_timeout` が返す残り
/// 時間がこの精度を下回る（例: 数百ナノ秒）と、`timeval` 変換の結果が
/// 実質ゼロになる。macOS はゼロの `SO_RCVTIMEO` / `SO_SNDTIMEO` を
/// `EINVAL` で拒否し（`is_peer_shutdown_einval` はこの `EINVAL` を「相手が
/// すでに切断した」と判定する既存のヒューリスティック）、相手がまだ接続
/// したままでも `Unavailable` を誤って返してしまう
/// （`repair5_uds_send_times_out_on_unresponsive_peer` の macOS CI 再現失敗。
/// PR #1115 の `bench-regression` 以外の rust-ci macOS ジョブで観測。
/// 期限を過ぎたかどうかの判定自体は変えず、`timeval` 精度未満の残り時間を
/// 「実質期限切れ」として扱うだけで直す）。
pub(crate) const MIN_REMAINING_TIMEOUT: Duration = Duration::from_micros(1);

/// `deadline` までの残り時間を返す。残りが [`MIN_REMAINING_TIMEOUT`] 未満
/// ならその場で [`IoErrorCode::Timeout`] を返す（`Duration::ZERO` を
/// `set_read_timeout` / `set_write_timeout` に渡すと std がエラーにする上、
/// それを僅かに上回るだけの残り時間も `timeval` 精度未満に丸まりうるため、
/// 実用上の下限を [`MIN_REMAINING_TIMEOUT`] として先に弾く）。
pub(crate) fn remaining_or_timeout(deadline: Instant) -> Result<Duration, IoError> {
    let now = Instant::now();
    let remaining = deadline.checked_duration_since(now);
    match remaining {
        Some(remaining) if remaining >= MIN_REMAINING_TIMEOUT => Ok(remaining),
        _ => Err(IoError::new(
            IoErrorCode::Timeout,
            "frame deadline exceeded before the operation completed",
        )),
    }
}

/// `io::Error` を `IoError` へ変換する（`crate::error` の `IoErrorCode`・
/// ERR-1 対応）。相手から届いたデータを message に含めず、`ErrorKind`
/// 程度の情報のみを載せる（security.md「情報漏えい」観点）。
///
/// `WouldBlock` / `TimedOut` もここでは `Timeout` に写像するが、
/// `read_exact_until` / `read_body_until` / `write_all_until` は
/// これらのエラーを本関数に渡さず、`remaining_or_timeout` によるフレーム
/// 全体の期限の再計算へループを戻す（REPAIR-5・#820 レビュー指摘。ただし
/// 読み取り経路の drain モードでの `WouldBlock` は、ループを戻さず EOF と
/// 同じ `Unavailable` にする。[`ReadWait`] 参照）。テスト
/// （`task13_2_1_map_io_error_maps_would_block_and_timed_out_to_timeout`）
/// のために写像自体はここに残す。
pub(crate) fn map_io_error(e: io::Error) -> IoError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            IoError::new(IoErrorCode::Timeout, "io operation timed out")
        }
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected => IoError::new(
            IoErrorCode::Unavailable,
            format!("peer connection is unavailable: {}", e.kind()),
        ),
        other => IoError::new(IoErrorCode::Internal, format!("io error: {other}")),
    }
}

/// この OS で、`set_read_timeout` / `set_write_timeout`（`setsockopt(2)` の
/// `SO_RCVTIMEO` / `SO_SNDTIMEO`）が返す `EINVAL` を「相手がすでに切断した」
/// ことの手がかりとして扱うか。macOS だけ `true`（根拠は
/// [`is_peer_shutdown_einval`] 参照。H7・#820）。
///
/// cfg を実行時の判定から切り離して bool 定数に閉じ込め、判定関数
/// （[`classify_read_timeout_error`]・[`map_write_timeout_error`]）には引数で
/// 渡す。これにより macOS 側の分岐も Linux 上のユニットテストで確かめられる。
pub(crate) const SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN: bool = cfg!(target_os = "macos");

/// タイムアウト設定の失敗が「相手の切断を示す `EINVAL`」かを判定する純粋関数
/// （D・H7・#820。PR #1113 の macOS CI 失敗の修正）。
///
/// `einval_means_peer_shutdown` には通常 [`SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN`]
/// を渡す（テストだけが両方の値を渡す）。`true` かつ `e` が OS の返した
/// `EINVAL`（`kind() == InvalidInput` かつ `raw_os_error()` を持つ）のときだけ
/// `true` を返す。std が OS を呼ばずに合成する `InvalidInput`（`Duration::ZERO`
/// を渡した場合等。`raw_os_error()` を持たない）は対象外にし、実装の誤りを
/// 相手の切断と取り違えない（加えて `remaining_or_timeout` が
/// `Duration::ZERO` を渡さない）。
///
/// # macOS で `EINVAL` を相手の切断とみなす根拠
/// - 実測: macOS CI では、相手が close した後のソケットに対する
///   `set_read_timeout` が `EINVAL`（os error 22）を返す
///   （`io1_uds_recv_reports_unavailable_on_peer_close` が再現するケースと、
///   PR #1113 で失敗した 2 テスト）
/// - XNU のソース（`sosetoptlock`）を読む限り、ソケットが送受信とも
///   shutdown 済み（`SS_CANTRCVMORE` と `SS_CANTSENDMORE` の両方が立った状態。
///   UDS では相手の close でこの状態になるように見える）のとき、setsockopt は
///   オプションの種類によらず `EINVAL` を返すように見える。macOS の
///   `setsockopt(2)` のマニュアルの `[EINVAL]` 項にも、接続済みであることを
///   要するオプションを接続されていないソケットに指定した場合に返るとある。
///   ただしどの状態で `EINVAL` になるかを実機で網羅的に確かめたものではない
///
/// # Linux（`false`）
/// Linux では相手が切断済みでも `setsockopt` 自体は成功し、直後の
/// `read` / `write` が `map_io_error` の切断系 `ErrorKind` を返す。したがって
/// `EINVAL` は相手の接続とは無関係な実装上の異常（不正な timeout 値の指定等）を
/// 示す可能性が高い。macOS の判断を Linux に転用すると、本来 `Internal`
/// （実装バグ）として報告すべきものを相手の切断に読み替えてバグを隠す側に
/// 倒れるため、Linux では常に `false` を返す（H7・#820 security-auditor 指摘
/// 対応）。
pub(crate) fn is_peer_shutdown_einval(e: &io::Error, einval_means_peer_shutdown: bool) -> bool {
    einval_means_peer_shutdown
        && e.kind() == io::ErrorKind::InvalidInput
        && e.raw_os_error().is_some()
}

/// 読み取り経路の `set_read_timeout` が失敗したときの処置
/// （[`classify_read_timeout_error`] の戻り値）。
#[derive(Debug)]
pub(crate) enum ReadTimeoutAction {
    /// 相手が切断済みとみなし、タイムアウトを設定せずに受信バッファの残りを
    /// 読み出す（[`ReadWait`] の drain モードへ入る）。
    DrainWithoutTimeout,
    /// 読み取りを打ち切ってこのエラーを返す。
    Fail(IoError),
}

/// 読み取り経路（`read_exact_until`・`read_body_until`）の `set_read_timeout`
/// の失敗を処置へ振り分ける純粋関数（IO-1・REPAIR-5・#820。PR #1113 の macOS
/// CI 失敗の修正）。
///
/// - [`is_peer_shutdown_einval`] が `true`（macOS の `EINVAL`）:
///   [`ReadTimeoutAction::DrainWithoutTimeout`]
/// - それ以外（Linux の `EINVAL`・他の `ErrorKind`・std が合成した
///   `InvalidInput`）: `Internal` の [`ReadTimeoutAction::Fail`]
///
/// # 失敗にせず読み続ける理由
/// 相手が close 前に送り切ったデータは受信バッファに残っており、ここで
/// `Unavailable` にすると正当なフレーム（1 フレーム送って閉じる相手の最後の
/// フレーム等）を読まずに失う。以前の実装（H7）は macOS の `EINVAL` を
/// 読み取り経路でも `Unavailable` にしていたため、このフレームを失っていた。
/// タイムアウトを設定できなくてもハングしないことは、XNU の性質（送受信とも
/// shutdown 済みのソケットの read は受信バッファのデータを返し、尽きれば 0 を
/// 返してブロックしないように見えること）には依存させず、[`ReadWait`] が
/// ソケットを nonblocking にしてから read することで担保する。
pub(crate) fn classify_read_timeout_error(
    e: io::Error,
    einval_means_peer_shutdown: bool,
) -> ReadTimeoutAction {
    if is_peer_shutdown_einval(&e, einval_means_peer_shutdown) {
        ReadTimeoutAction::DrainWithoutTimeout
    } else {
        ReadTimeoutAction::Fail(IoError::new(
            IoErrorCode::Internal,
            format!("failed to set io timeout: {e}"),
        ))
    }
}

/// 書き込み経路（`write_all_until`）の `set_write_timeout` の失敗を
/// `IoError` へ変換する純粋関数（D・H7・#820）。
///
/// - [`is_peer_shutdown_einval`] が `true`（macOS の `EINVAL`）: `Unavailable`
///   （相手が閉じていれば書けないため、読み取り経路と違い続行しない。
///   切断済みの相手への操作を実装バグを示す `Internal` で誤って報告しない）
/// - それ以外: `Internal`
pub(crate) fn map_write_timeout_error(e: io::Error, einval_means_peer_shutdown: bool) -> IoError {
    if is_peer_shutdown_einval(&e, einval_means_peer_shutdown) {
        IoError::new(
            IoErrorCode::Unavailable,
            format!("peer connection is unavailable: failed to set io timeout: {e}"),
        )
    } else {
        IoError::new(
            IoErrorCode::Internal,
            format!("failed to set io timeout: {e}"),
        )
    }
}

/// 読み取り経路（`read_exact_until`・`read_body_until`）の 1 回の呼び出しの
/// 間、各 read の前の期限判定・待ち時間の設定と、相手の切断後に受信バッファの
/// 残りを読み出す drain モードを管理する（IO-1・REPAIR-5・#820。PR #1113 の
/// macOS CI 失敗の修正）。
///
/// # drain モード
/// [`Self::before_read`] で `set_read_timeout` の失敗が
/// [`ReadTimeoutAction::DrainWithoutTimeout`] に振り分けられると、ソケットを
/// nonblocking に切り替えて drain モードへ入る。drain モードでは:
///
/// - 各 read の前の期限判定（`remaining_or_timeout`）は通常時と同じく行う
/// - `set_read_timeout` はその呼び出しの残りでは呼び直さない（相手の切断は
///   元に戻らず、呼び直しても同じ失敗になるだけのため）
/// - read はブロックせず、データ・0（EOF）・`WouldBlock` のいずれかで即座に
///   返る。`WouldBlock` は受信バッファが空であることを示し、相手はもう送って
///   こないため EOF と同じ `Unavailable` にする（呼び出し元が
///   [`Self::is_draining`] で判定する。通常時のように待ち直すと期限まで
///   busy loop になる）
///
/// # blocking への復帰
/// [`Self::finish`] が読み取り関数の終了時（成功・失敗とも）に blocking へ
/// 戻し、読み取り関数の外から見たソケットの状態を「blocking＋呼び出しごとの
/// タイムアウト」に保つ。`EINVAL` が相手の切断以外の原因だった場合に
/// nonblocking のまま返すと、次の recv / send で `set_*_timeout` が成功しても
/// read / write が `WouldBlock` を返し続け、期限まで busy loop になりうる
/// （`write_all_until` は blocking＋`SO_SNDTIMEO` が前提）。相手が本当に切断
/// 済みなら、次の recv は再び drain モードへ入り、send は `set_write_timeout`
/// の失敗で `Unavailable` になるため、戻しても害はない。
///
/// nonblocking の切り替えが失敗した場合は `Internal` を返す（fail-closed。
/// 復帰の失敗では受信済みのフレームも失う）。accept 経路（`accept_with`）は
/// 相手が切断済みの接続にも `set_nonblocking(false)` を呼んでおり、その接続の
/// 最初の `set_read_timeout` が `EINVAL` になる
/// `io1_uds_recv_reports_unavailable_on_peer_close` が macOS CI で通っている
/// ことから、この状態のソケットでも切り替えは成功すると見込んでいる。
pub(crate) struct ReadWait {
    draining: bool,
}

impl ReadWait {
    pub(crate) fn new() -> Self {
        Self { draining: false }
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.draining
    }

    /// read の直前に呼ぶ。期限を過ぎていれば `Timeout`、drain モードでなければ
    /// 残り時間を `set_read_timeout` に設定する（失敗は
    /// [`classify_read_timeout_error`] で振り分ける）。
    pub(crate) fn before_read<S: TimedStream>(
        &mut self,
        stream: &S,
        deadline: Instant,
    ) -> Result<(), IoError> {
        let remaining = remaining_or_timeout(deadline)?;
        if self.draining {
            return Ok(());
        }
        match stream.set_read_timeout(Some(remaining)) {
            Ok(()) => Ok(()),
            Err(e) => {
                match classify_read_timeout_error(e, SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN) {
                    ReadTimeoutAction::DrainWithoutTimeout => self.enter_drain(stream),
                    ReadTimeoutAction::Fail(err) => Err(err),
                }
            }
        }
    }

    /// ソケットを nonblocking に切り替えて drain モードへ入る（テストは
    /// Linux 上で drain モードを強制するために直接呼ぶ）。
    pub(crate) fn enter_drain<S: TimedStream>(&mut self, stream: &S) -> Result<(), IoError> {
        stream.set_nonblocking(true).map_err(|e| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to switch a peer-closed stream to nonblocking mode: {e}"),
            )
        })?;
        self.draining = true;
        Ok(())
    }

    /// 読み取り関数の結果を受け取り、drain モードに入っていれば blocking へ
    /// 戻してから返す。読み取り自体がエラーならそのエラーを優先する（接続は
    /// 呼び出し元で poison され以後使われないため、復帰の失敗は捨てる）。
    pub(crate) fn finish<S: TimedStream, T>(
        self,
        stream: &S,
        result: Result<T, IoError>,
    ) -> Result<T, IoError> {
        if !self.draining {
            return result;
        }
        let restored = stream.set_nonblocking(false);
        match (result, restored) {
            (Err(e), _) => Err(e),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(e)) => Err(IoError::new(
                IoErrorCode::Internal,
                format!("failed to restore blocking mode after draining: {e}"),
            )),
        }
    }
}

/// `buf` を埋め切るまで読む。フレーム全体の `deadline` を基準に毎回残り
/// 時間を計算し直すため、1 バイトずつ小出しに送ってくる相手でも
/// フレーム全体の期限で打ち切られる（期限後に read を始めず、各 read の待ちも
/// 残り時間が上限。超過はソケットのタイムアウトの粒度の範囲に収まる。
/// REPAIR-5）。
///
/// 相手が切断済みでも受信バッファに残ったデータは読み切り、尽きたところで
/// `Unavailable` を返す（macOS の扱いは [`ReadWait`] 参照。IO-1・#820）。
pub(crate) fn read_exact_until<S: TimedStream>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Instant,
    what: &'static str,
) -> Result<(), IoError> {
    let mut wait = ReadWait::new();
    let result = read_exact_with(stream, buf, deadline, what, &mut wait);
    wait.finish(stream, result)
}

/// [`read_exact_until`] の読み取りループ本体。`wait` の drain モードの
/// 後始末（blocking への復帰）は呼び出し元が [`ReadWait::finish`] で行う
/// （テストは drain モードを強制した `wait` を渡して直接呼ぶ）。
pub(crate) fn read_exact_with<S: TimedStream>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Instant,
    what: &'static str,
    wait: &mut ReadWait,
) -> Result<(), IoError> {
    // 1 バイトも読めていない EOF はフレーム境界での正常な切断、読み途中の EOF は
    // 不完全なフレームでの切断なので、メッセージで区別する
    // （SIGKILL テスト用サーバー `crash_test_server` が正常切断だけを終了コード 0 に
    // するため。TASK-18.1.1・#825・IO-3）。
    let mut filled = 0usize;
    let peer_closed = |filled: usize| {
        if filled == 0 {
            IoError::new(
                IoErrorCode::Unavailable,
                format!("peer closed the connection before sending a complete {what}"),
            )
        } else {
            IoError::new(
                IoErrorCode::Unavailable,
                format!("peer closed the connection in the middle of a {what}"),
            )
        }
    };
    while filled < buf.len() {
        wait.before_read(stream, deadline)?;
        let Some(dst) = buf.get_mut(filled..) else {
            return Err(IoError::new(
                IoErrorCode::Internal,
                "read buffer index out of range",
            ));
        };
        match stream.read(dst) {
            Ok(0) => return Err(peer_closed(filled)),
            Ok(n) => filled += n,
            // drain モード（相手が切断済み）で受信バッファが尽きた。EOF と
            // 同じ扱いにする（ReadWait 参照）。
            Err(e) if wait.is_draining() && e.kind() == io::ErrorKind::WouldBlock => {
                return Err(peer_closed(filled));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                // 個々の read 呼び出しの期限切れ（`WouldBlock` /
                // `TimedOut`）では即座に諦めず、`remaining_or_timeout` に
                // よるフレーム全体の期限の再計算へループを戻す
                // （REPAIR-5）。期限を過ぎていれば次の周回の先頭で
                // `remaining_or_timeout` が `Timeout` を返す。
                continue;
            }
            Err(e) => return Err(map_io_error(e)),
        }
    }
    Ok(())
}

/// 受信中のフレーム本体（`body_len` バイト）を、届いた分だけ少しずつ
/// 確保しながらためるバッファ（REPAIR-2・security.md の DoS 対策。#820
/// codex P0 指摘対応）。[`read_body_until`] が読み取りループの中で使う。
///
/// # 確保容量の上限（#820 codex P0 指摘対応）
/// 容量を `body_len` 以下に保つ。`Vec::extend_from_slice` 等の
/// 償却つき成長は容量を幾何級数的に増やすため、実際の確保容量が受理済みの
/// `body_len` を超えうる（以前の実装の問題）。本型は次の 2 点でこれを防ぐ:
///
/// - 初期容量は `min(body_len, BODY_READ_CHUNK)`
/// - 空き領域を使い切ったときだけ `reserve_exact(min(BODY_READ_CHUNK,
///   body_len - 容量))` で伸ばす（`reserve_exact` は償却つきの上乗せを
///   せず、要求量は `body_len` を超えない。std の文書はアロケータが要求より
///   多い領域を返すことを許すが、現行の `Vec` はその余剰を容量に含めない。
///   容量の推移はテストで具体値を照合する）。`resize` は伸ばした直後に
///   その空き領域をゼロ埋めするためだけに呼び、容量ぴったりまでしか
///   伸ばさないので内部で再確保は起きない
///
/// 伸長は空きを使い切ったときに限るため、相手が 1 バイトずつ小出しに
/// 送ってきても再確保は最大 `ceil(body_len / BODY_READ_CHUNK)` 回、
/// ゼロ埋めも各バイト 1 回ずつに収まる（1 回の read ごとにゼロ埋めや
/// 再確保をやり直す実装にすると、小出しの相手に CPU を浪費させられる）。
/// 読み込み先は `Vec` の領域そのもので、ペイロード大の中間バッファ・
/// 二重コピーを使わない（以前の実装が持っていた 64 KiB のスタック上の
/// 一時配列も使わない）。
///
/// # 不変条件
/// `filled <= buf.len() <= buf.capacity() <= body_len`。`buf.len()` は
/// 初期化済み（ゼロ埋め済みまたは受信済み）の範囲、`filled` はそのうち
/// 実際に受信したバイト数を表す。受信していないゼロ埋め領域を本体として
/// 返さないよう、[`Self::into_body`] は `filled == body_len` のときだけ
/// 本体を返す。
pub(crate) struct BodyBuffer {
    buf: Vec<u8>,
    filled: usize,
    body_len: usize,
}

impl BodyBuffer {
    /// `body_len` は [`crate::recv_limits::AdmittedHeader::body_len`]
    /// （`admit` を通過した検証済みの長さ）だけを渡す。
    pub(crate) fn new(body_len: usize) -> Self {
        Self {
            buf: Vec::with_capacity(body_len.min(BODY_READ_CHUNK)),
            filled: 0,
            body_len,
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.filled >= self.body_len
    }

    /// `reader` から 1 回だけ読み、受信したバイト数を返す（`Ok(0)` は相手の
    /// 切断、`Err` は `reader` のエラーをそのまま返す。いずれの場合も
    /// 不変条件は崩れず、`Interrupted` 等で呼び直してよい）。
    pub(crate) fn read_once<R: Read>(&mut self, reader: &mut R) -> io::Result<usize> {
        if self.filled == self.buf.len() {
            self.grow_initialized();
        }
        let Some(dst) = self.buf.get_mut(self.filled..) else {
            return Err(io::Error::other("body buffer index out of range"));
        };
        if dst.is_empty() {
            // `is_complete` のときにしか起きない（呼び出し元は完了後に
            // 呼ばない）。0 を返すと切断と区別できないため別扱いにする。
            return Err(io::Error::other("body buffer is already complete"));
        }
        let got = reader.read(dst)?;
        // `Read` の契約上 `got <= dst.len()` だが、実装の誤りで超えても
        // 不変条件を崩さないよう初期化済みの範囲で頭打ちにする。
        self.filled = self.filled.saturating_add(got).min(self.buf.len());
        Ok(got)
    }

    /// 初期化済みの範囲を 1 段（最大 `BODY_READ_CHUNK`）伸ばす。容量に
    /// 空きがなければ先に `reserve_exact` で `body_len` を超えない範囲だけ
    /// 容量を増やし、その後 `resize` で容量ぴったりまでゼロ埋めする
    /// （`resize` の要求量が容量以下なので、`resize` の内部で償却つきの
    /// 再確保は起きない）。
    pub(crate) fn grow_initialized(&mut self) {
        let len = self.buf.len();
        if len == self.buf.capacity() {
            let additional = self.body_len.saturating_sub(len).min(BODY_READ_CHUNK);
            self.buf.reserve_exact(additional);
        }
        let target = self.buf.capacity().min(self.body_len);
        if target > len {
            self.buf.resize(target, 0);
        }
    }

    /// 受信し終えた本体を返す。未完了なら `Internal`（呼び出し元の
    /// ループの誤り）を返し、ゼロ埋めのまま受信していない領域を本体と
    /// して扱わない。
    pub(crate) fn into_body(self) -> Result<Vec<u8>, IoError> {
        if self.filled != self.body_len || self.buf.len() != self.body_len {
            return Err(IoError::new(
                IoErrorCode::Internal,
                "frame body buffer is incomplete",
            ));
        }
        Ok(self.buf)
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[cfg(test)]
    pub(crate) fn filled(&self) -> usize {
        self.filled
    }
}

/// `body_len` バイトの本体を、届いた分だけ少しずつ確保しながら読む
/// （申告された長さだけで一度に確保しない。security.md の DoS 対策）。
/// 確保容量を `body_len` 以下に保つ仕組みは [`BodyBuffer`] を参照
/// （#820 codex P0 指摘対応）。
///
/// # `AdmittedHeader::allocate_body` を経由しない理由（B1・#820 レビュー
/// 指摘。security P2）
/// `crate::recv_limits::AdmittedHeader::allocate_body` は一括確保する経路
/// （`crate::protocol::Frame::decode_body` 等が本体をまるごと読める場合
/// 向け）であり、本関数は相手が遅い・悪意ある場合でも接続 1 本あたりの
/// 瞬間的なメモリ使用量を抑えるため、あえて `body_len` 分を分割して読む。
/// どちらの経路でも「確保量の上限は `admit` を通過した
/// `AdmittedHeader`（ここでは `body_len`）からしか得ない」という契約は
/// 変わらない（`crates/io/src/recv_limits.rs` モジュール doc「埋める穴」
/// 節・`AdmittedHeader::allocate_body` のドキュメンテーションコメント
/// 参照）。
///
/// # 受信 1 フレームあたりの確保量
/// 本関数が返す本体の容量は `body_len` ちょうど。呼び出し元
/// （[`ConnectionInner::recv_frame`]）はこれを
/// `AdmittedHeader::decode_body_owned` → `crate::protocol::Frame::decode_body_owned`
/// へ所有権ごと渡し、チェックサム検証後に末尾のチェックサムを落とした同じ
/// 領域をペイロードとして使う（複製しない。#820 codex P0 指摘対応）。
/// したがって 1 フレームの受信で申告長に比例して確保するのは、
/// `AdmittedHeader` 由来の `body_len` ぶんの 1 回だけである。
///
/// # 相手の切断後（IO-1・#820）
/// 相手が切断済みでも受信バッファに残ったデータは読み切り、尽きたところで
/// `Unavailable` を返す（macOS の扱いは [`ReadWait`] 参照）。
pub(crate) fn read_body_until<S: TimedStream>(
    stream: &mut S,
    body_len: usize,
    deadline: Instant,
) -> Result<Vec<u8>, IoError> {
    let mut wait = ReadWait::new();
    let result = read_body_with(stream, body_len, deadline, &mut wait);
    wait.finish(stream, result)
}

/// [`read_body_until`] の読み取りループ本体（後始末の分担は
/// [`read_exact_with`] と同じ）。
pub(crate) fn read_body_with<S: TimedStream>(
    stream: &mut S,
    body_len: usize,
    deadline: Instant,
    wait: &mut ReadWait,
) -> Result<Vec<u8>, IoError> {
    let peer_closed = || {
        IoError::new(
            IoErrorCode::Unavailable,
            "peer closed the connection before sending a complete frame body",
        )
    };
    let mut body = BodyBuffer::new(body_len);
    while !body.is_complete() {
        wait.before_read(stream, deadline)?;
        match body.read_once(stream) {
            Ok(0) => return Err(peer_closed()),
            Ok(_) => {}
            // read_exact_with と同じく、drain モードで受信バッファが尽きたら
            // EOF と同じ扱いにする。
            Err(e) if wait.is_draining() && e.kind() == io::ErrorKind::WouldBlock => {
                return Err(peer_closed());
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                // read_exact_with と同じ理由でループを戻す（REPAIR-5）。
                // `BodyBuffer::read_once` はエラー時に `filled` を進めない
                // ため、ゼロ埋め済みの未受信領域が本体として数えられる
                // ことはない。
                continue;
            }
            Err(e) => return Err(map_io_error(e)),
        }
    }
    body.into_body()
}

/// `bytes` を書き切るまで送る（`write_all` 相当をフレーム単位の期限付きで
/// 自前実装したもの）。
///
/// `set_write_timeout` の失敗は [`map_write_timeout_error`] で変換する
/// （macOS で相手が切断済みなら `Unavailable`。読み取り経路と違い、相手が
/// 閉じていれば書けないため続行しない）。
pub(crate) fn write_all_until<S: TimedStream>(
    stream: &mut S,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), IoError> {
    let mut written = 0usize;
    while written < bytes.len() {
        let remaining = remaining_or_timeout(deadline)?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|e| map_write_timeout_error(e, SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN))?;
        let Some(src) = bytes.get(written..) else {
            return Err(IoError::new(
                IoErrorCode::Internal,
                "write buffer index out of range",
            ));
        };
        match stream.write(src) {
            Ok(0) => {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "peer connection accepted zero bytes",
                ));
            }
            Ok(n) => written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                // read_exact_with と同じ理由でループを戻す（REPAIR-5）。
                continue;
            }
            Err(e) => return Err(map_io_error(e)),
        }
    }
    Ok(())
}
