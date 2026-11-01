//! UDS 上の ttrpc サーバー（unix のみ。CRI-5・TASK-62.1・MS-7）。
//!
//! 呼び出し元（shim の起動経路 `bootstrap`。#872）が bind 済みの `UnixListener` を渡し、
//! [`TtrpcServer::serve`] が accept スレッドを起こして [`ServerHandle`] を返す。
//! 接続ごとに 1 スレッドで要求を読み、dispatch は要求ごとのスレッド（接続あたり上限つき）で並行に行う。
//! 応答の書き込みは接続内で直列化する。待ち中の Wait が後続の RPC を塞がず、サーバー停止・接続切断は
//! ハンドラへ取り消しとして伝わる（TASK-62.3.2・REPAIR-5）。
//! tokio の `net` は使わず std とスレッドで作る（依存・feature を足さない。#670）。
//!
//! 無期限の待ちを作らない（REPAIR-5）:
//! - 同時接続数に上限があり、超えた接続はすぐ閉じる
//! - フレームの最初の 1 バイトはアイドルで待つが、その後の残りは `frame_read_timeout` 以内に読み切る
//! - 書き込みには全体の絶対期限を付け、停止要求も確かめる。停止は期限つきの join
//!
//! 計測（REPAIR-4）: [`TtrpcServer::with_recorder`] で渡した [`CriOpRecorder`] へ、要求ごとに固定の
//! 操作種別・結果コード・所要時間だけを渡す（要求の中身・文言は渡さない）。
//!
//! peer UID の照合は扱わない（未対応で後続。REPAIR-3）。socket の配置と権限は `bootstrap` が扱う。

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use prost::Message;
use tonic::Code;

use super::frame::{FrameError, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType};
use super::message::{RpcStatus, TtrpcRequest, TtrpcResponse, metadata_within_limit};
use super::service::ServiceRegistry;
use crate::error::CriErrorCode;
use crate::instrument::{CriOpKind, CriOpRecorder, CriOpSample, NoopCriOpRecorder};

/// サーバーの設定。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 同時接続の上限。
    pub max_connections: usize,
    /// 最初の 1 バイトの後、フレームの残りを読み切る期限。
    pub frame_read_timeout: Duration,
    /// 1 回の応答の書き込み全体の絶対期限。`poll_interval` ごとに停止要求も確かめるため、
    /// 相手が少しずつ読む場合も期限で打ち切る（REPAIR-5）。
    pub write_timeout: Duration,
    /// 停止時に各スレッドの終了を待つ期限。
    pub shutdown_timeout: Duration,
    /// 停止フラグを確かめる間隔。
    pub poll_interval: Duration,
}

/// 期限系の設定値の上限（1 日）。`Instant` への加算・`poll_interval` の乗算を安全に保つ。
const MAX_CONFIG_DURATION: Duration = Duration::from_secs(86_400);

impl ServerConfig {
    /// 設定値の範囲を検証する（REPAIR-5。`Duration::MAX` 等での panic を防ぐ）。
    fn validate(&self) -> Result<(), ShimV2Error> {
        let checks = [
            ("frame_read_timeout", self.frame_read_timeout),
            ("write_timeout", self.write_timeout),
            ("shutdown_timeout", self.shutdown_timeout),
            ("poll_interval", self.poll_interval),
        ];
        for (name, d) in checks {
            if d > MAX_CONFIG_DURATION {
                return Err(ShimV2Error::InvalidConfig(name));
            }
        }
        if self.poll_interval.is_zero() {
            return Err(ShimV2Error::InvalidConfig("poll_interval"));
        }
        Ok(())
    }
}

/// `now` から `d` 後の時刻。オーバーフローしても panic せず 1 日後に丸める。
fn deadline_after(now: Instant, d: Duration) -> Instant {
    now.checked_add(d)
        .or_else(|| now.checked_add(MAX_CONFIG_DURATION))
        .unwrap_or(now)
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 16,
            frame_read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(50),
        }
    }
}

/// サーバーの起動・停止のエラー。メッセージは固定の英語で、パスや要求の中身を含めない。
#[derive(Debug)]
pub enum ShimV2Error {
    /// listener の設定に失敗した。
    Listener(io::ErrorKind),
    /// 停止の期限内にスレッドが終わらなかった。
    ShutdownTimeout,
    /// 設定値が範囲外（期限の演算がオーバーフローしうる値・ゼロの間隔）。
    InvalidConfig(&'static str),
}

impl std::fmt::Display for ShimV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listener(k) => write!(f, "listener setup failed: {k}"),
            Self::ShutdownTimeout => write!(f, "shutdown timed out"),
            Self::InvalidConfig(field) => write!(f, "invalid config: {field}"),
        }
    }
}

impl std::error::Error for ShimV2Error {}

/// ttrpc サーバー。
pub struct TtrpcServer {
    registry: Arc<ServiceRegistry>,
    config: ServerConfig,
    recorder: Arc<dyn CriOpRecorder>,
}

impl TtrpcServer {
    /// 登録簿と設定から作る（計測しない）。
    pub fn new(registry: ServiceRegistry, config: ServerConfig) -> Self {
        Self::with_recorder(registry, config, Arc::new(NoopCriOpRecorder))
    }

    /// 計測の記録先を指定して作る（REPAIR-4）。
    pub fn with_recorder(
        registry: ServiceRegistry,
        config: ServerConfig,
        recorder: Arc<dyn CriOpRecorder>,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            config,
            recorder,
        }
    }

    /// bind 済みの listener で accept スレッドを起動する。
    pub fn serve(&self, listener: UnixListener) -> Result<ServerHandle, ShimV2Error> {
        self.config.validate()?;
        listener
            .set_nonblocking(true)
            .map_err(|e| ShimV2Error::Listener(e.kind()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(Ctx {
            registry: Arc::clone(&self.registry),
            recorder: Arc::clone(&self.recorder),
            config: self.config.clone(),
            stop: Arc::clone(&stop),
            active: AtomicUsize::new(0),
        });
        let accept = thread::Builder::new()
            .name("ttrpc-accept".into())
            .spawn(move || accept_loop(listener, ctx))
            .map_err(|e| ShimV2Error::Listener(e.kind()))?;
        Ok(ServerHandle {
            stop,
            accept: Some(accept),
            shutdown_timeout: self.config.shutdown_timeout,
        })
    }
}

/// 起動中のサーバーの操作口。Drop でも停止フラグを立てる（join はしない）。
pub struct ServerHandle {
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl ServerHandle {
    /// 停止して、期限内にスレッドの終了を待つ。
    pub fn shutdown(mut self) -> Result<(), ShimV2Error> {
        self.stop.store(true, Ordering::SeqCst);
        let Some(h) = self.accept.take() else {
            return Ok(());
        };
        let deadline = deadline_after(Instant::now(), self.shutdown_timeout);
        while !h.is_finished() {
            if Instant::now() >= deadline {
                return Err(ShimV2Error::ShutdownTimeout);
            }
            thread::sleep(Duration::from_millis(5));
        }
        // 終了済みなので join は即座に戻る。panic は停止の失敗として扱う。
        h.join().map_err(|_| ShimV2Error::ShutdownTimeout)
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct Ctx {
    registry: Arc<ServiceRegistry>,
    recorder: Arc<dyn CriOpRecorder>,
    config: ServerConfig,
    stop: Arc<AtomicBool>,
    active: AtomicUsize,
}

/// 接続スレッドの終了で接続数を戻す。
struct ActiveGuard(Arc<Ctx>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_loop(listener: UnixListener, ctx: Arc<Ctx>) {
    let mut conns: Vec<JoinHandle<()>> = Vec::new();
    while !ctx.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if ctx.active.fetch_add(1, Ordering::SeqCst) >= ctx.config.max_connections {
                    ctx.active.fetch_sub(1, Ordering::SeqCst);
                    drop(stream);
                    continue;
                }
                let guard = ActiveGuard(Arc::clone(&ctx));
                let c = Arc::clone(&ctx);
                match thread::Builder::new()
                    .name("ttrpc-conn".into())
                    .spawn(move || {
                        let _guard = guard;
                        handle_conn(stream, &c);
                    }) {
                    Ok(h) => conns.push(h),
                    // spawn 失敗時は guard が closure ごと破棄され、接続数は戻る。
                    Err(_) => continue,
                }
                conns.retain(|h| !h.is_finished());
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                conns.retain(|h| !h.is_finished());
                thread::sleep(ctx.config.poll_interval);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // 一過性でない accept 失敗は無限ループを避けて間隔を空ける。
            Err(_) => thread::sleep(ctx.config.poll_interval),
        }
    }
    for h in conns {
        let _ = h.join();
    }
}

/// 読み取りの結果。
enum ReadOutcome {
    Done,
    /// 相手が閉じた、または停止要求。
    Closed,
    /// 期限切れ。
    TimedOut,
    /// 読み取りの I/O 失敗。
    Failed,
}

impl ReadOutcome {
    /// 失敗の計測（REPAIR-4）。期限切れと I/O 失敗だけを記録する（相手の正常切断・停止は記録しない）。
    fn record(&self, ctx: &Ctx, started: Instant) {
        let code = match self {
            Self::TimedOut => Code::DeadlineExceeded,
            Self::Failed => Code::Unavailable,
            Self::Done | Self::Closed => return,
        };
        record_op(ctx, CriOpKind::ShimV2Io, code, started);
    }
}

/// 計測を 1 件渡す。記録先は有界時間で戻る契約（`CriOpRecorder`）。
fn record_op(ctx: &Ctx, kind: CriOpKind, code: Code, started: Instant) {
    ctx.recorder
        .record_cri_op(&CriOpSample::new(kind, code, started.elapsed()));
}

/// 読み取りの 1 区間の期限を設定する。macOS（XNU）の `setsockopt` は、相手が close 済みで
/// 両方向の shutdown 状態の AF_UNIX stream に `EINVAL` を返す（`sosetoptlock` の
/// `SS_CANTRCVMORE | SS_CANTSENDMORE` 判定。xnu bsd/kern/uipc_socket.c）。この状態の読み取りは
/// 受信済みデータ→EOF を即座に返し、ブロックしないため、期限なしで続けてよい。
/// 無視しないと、相手が先に切断した接続の未読ヘッダが読まれず、後続の処理と計測が欠ける（CRI-5・REPAIR-4）。
fn set_read_slice(stream: &UnixStream, d: Duration) -> io::Result<()> {
    match stream.set_read_timeout(Some(d)) {
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
        r => r,
    }
}

/// 書き込みの 1 区間の期限を設定する。`EINVAL` の扱いは [`set_read_slice`] と同じで、
/// 切断済みなら実際の `write` が `ENOTCONN` / `EPIPE` で失敗し、`record_write_failure` が記録する。
fn set_write_slice(stream: &UnixStream, d: Duration) -> io::Result<()> {
    match stream.set_write_timeout(Some(d)) {
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
        r => r,
    }
}

/// `buf` を `deadline` までに満たす。
/// `poll_interval` ごとに停止フラグを確かめ、停止要求でも戻る（shutdown の期限を守る）。
fn read_full(stream: &mut UnixStream, buf: &mut [u8], deadline: Instant, ctx: &Ctx) -> ReadOutcome {
    let mut filled = 0;
    while filled < buf.len() {
        if ctx.stop.load(Ordering::SeqCst) {
            return ReadOutcome::Closed;
        }
        let now = Instant::now();
        if now >= deadline {
            return ReadOutcome::TimedOut;
        }
        let slice = (deadline - now).min(ctx.config.poll_interval);
        if set_read_slice(stream, slice).is_err() {
            return ReadOutcome::Failed;
        }
        let Some(rest) = buf.get_mut(filled..) else {
            return ReadOutcome::Failed;
        };
        match stream.read(rest) {
            Ok(0) => return ReadOutcome::Closed,
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return ReadOutcome::Failed,
        }
    }
    ReadOutcome::Done
}

/// アイドルで 1 バイト待つ。停止フラグを `poll_interval` ごとに確かめる。
fn wait_first_byte(stream: &mut UnixStream, ctx: &Ctx) -> Option<u8> {
    if set_read_slice(stream, ctx.config.poll_interval).is_err() {
        return None;
    }
    let mut b = [0u8; 1];
    loop {
        if ctx.stop.load(Ordering::SeqCst) {
            return None;
        }
        match stream.read(&mut b) {
            Ok(0) => return None,
            Ok(_) => {
                let [first] = b;
                return Some(first);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return None,
        }
    }
}

/// 応答後に書き側を閉じ、相手が送りかけのデータを短時間だけ読み捨てる。
/// 未読データを残したまま close すると RST になり、応答が読まれる前に切れうるため。
/// ペイロードは確保せず捨てるだけで、時間は `poll_interval` の数回分に限る。
fn drain_then_close(stream: &mut UnixStream, ctx: &Ctx) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    if set_read_slice(stream, ctx.config.poll_interval).is_err() {
        return;
    }
    let deadline = deadline_after(Instant::now(), ctx.config.poll_interval.saturating_mul(4));
    let mut sink = [0u8; 4096];
    while Instant::now() < deadline && !ctx.stop.load(Ordering::SeqCst) {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

fn status_response(code: CriErrorCode, msg: &str) -> TtrpcResponse {
    TtrpcResponse {
        status: Some(RpcStatus::from_code(code, msg)),
        payload: Vec::new(),
    }
}

/// 応答が上限を超えるなら `ResourceExhausted` の応答に置き換える（符号化前に `encoded_len()` で判定）。
/// 計測は実際に送る応答のコードを記録するため、計測より前に呼ぶ（REPAIR-4）。
fn bound_response(resp: TtrpcResponse) -> TtrpcResponse {
    if resp.encoded_len() > MAX_PAYLOAD_LEN as usize {
        status_response(CriErrorCode::ResourceExhausted, "response too large")
    } else {
        resp
    }
}

/// 応答を書く。符号化の前に `encoded_len()` で上限を検証する（巨大な応答の追加確保を避ける）。
/// 書き込み全体に絶対期限を持ち、`poll_interval` ごとに停止要求を確かめる（REPAIR-5）。
fn write_response(
    stream: &mut UnixStream,
    stream_id: u32,
    resp: &TtrpcResponse,
    ctx: &Ctx,
) -> io::Result<()> {
    // 上限超過の応答は呼び出し側の `bound_response` で置換済み。超えていれば下の header 生成で拒否する。
    if resp.encoded_len() > MAX_PAYLOAD_LEN as usize {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let body = resp.encode_to_vec();
    let len = u32::try_from(body.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let header = FrameHeader::new(len, stream_id, MessageType::Response, 0)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&body);
    let deadline = deadline_after(Instant::now(), ctx.config.write_timeout);
    let mut off = 0;
    while off < out.len() {
        if ctx.stop.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let slice = (deadline - now).min(ctx.config.poll_interval);
        set_write_slice(stream, slice)?;
        let Some(rest) = out.get(off..) else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        match stream.write(rest) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => off += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// 書き込み失敗の計測。停止要求による中断は記録しない。
fn record_write_failure(ctx: &Ctx, e: &io::Error, started: Instant) {
    let code = match e.kind() {
        io::ErrorKind::Interrupted => return,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Code::DeadlineExceeded,
        _ => Code::Unavailable,
    };
    record_op(ctx, CriOpKind::ShimV2Io, code, started);
}

/// 応答の status から計測用のコードを導く（status なしは `Ok`）。
fn resp_code(resp: &TtrpcResponse) -> Code {
    resp.status
        .as_ref()
        .map_or(Code::Ok, |st| Code::from(st.code))
}

/// 1 接続で同時に処理中にできる要求数の上限（REPAIR-5。超えた要求は `ResourceExhausted`）。
const MAX_INFLIGHT_PER_CONN: usize = 16;

/// 応答の書き込みを接続内で直列化して送る。失敗は計測して `false`。
///
/// 書き込みの失敗（フレームの途中のタイムアウトを含む）では応答の境界が壊れるため、接続を
/// shutdown して `done` を立てる（読み取りループと他のハンドラが終了する）。失敗状態の確認は
/// ロック内で行い、失敗後に別の書き手が書き始めて未完の本文へ連結するのを防ぐ。
fn send_response(
    ctx: &Ctx,
    writer: &Mutex<UnixStream>,
    done: &AtomicBool,
    sid: u32,
    resp: &TtrpcResponse,
    started: Instant,
) -> bool {
    let mut w = writer.lock().unwrap_or_else(|p| p.into_inner());
    if done.load(Ordering::SeqCst) {
        return false;
    }
    match write_response(&mut w, sid, resp, ctx) {
        Ok(()) => true,
        Err(e) => {
            record_write_failure(ctx, &e, started);
            done.store(true, Ordering::SeqCst);
            let _ = w.shutdown(std::net::Shutdown::Both);
            false
        }
    }
}

/// 処理中の要求数を戻す。
struct InflightGuard<'a>(&'a AtomicUsize);

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 接続を処理する。要求は接続内で並行に dispatch し（Wait が後続の RPC を塞がないように。CRI-5・
/// TASK-62.3.2）、応答の書き込みは `Mutex` で直列化する。接続が閉じる・サーバーが止まると
/// 処理中のハンドラへ取り消しを伝え、スコープの終了で全スレッドの終了を待つ（REPAIR-5）。
fn handle_conn(stream: UnixStream, ctx: &Ctx) {
    // 継承された non-blocking を解く（BSD 系の accept は listener の設定を引き継ぐ）。
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let Ok(w) = stream.try_clone() else {
        return;
    };
    let writer = Mutex::new(w);
    let done = AtomicBool::new(false);
    let inflight = AtomicUsize::new(0);
    thread::scope(|s| {
        conn_loop(stream, ctx, &writer, &done, &inflight, s);
        done.store(true, Ordering::SeqCst);
    });
}

fn conn_loop<'scope, 'env>(
    mut stream: UnixStream,
    ctx: &'env Ctx,
    writer: &'env Mutex<UnixStream>,
    done: &'env AtomicBool,
    inflight: &'env AtomicUsize,
    scope: &'scope thread::Scope<'scope, 'env>,
) {
    let mut last_stream_id: u32 = 0;
    loop {
        let Some(first) = wait_first_byte(&mut stream, ctx) else {
            return;
        };
        let started = Instant::now();
        let deadline = deadline_after(started, ctx.config.frame_read_timeout);
        let mut raw = [0u8; HEADER_LEN];
        if let Some((head, rest)) = raw.split_first_mut() {
            *head = first;
            let outcome = read_full(&mut stream, rest, deadline, ctx);
            if !matches!(outcome, ReadOutcome::Done) {
                outcome.record(ctx, started);
                return;
            }
        }
        // 検証に失敗したヘッダの応答に使うため、stream id は生のバイトから取る。
        let raw_stream_id = raw
            .get(4..8)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map_or(0, u32::from_be_bytes);
        let header = match FrameHeader::from_bytes(&raw) {
            Ok(h) => h,
            Err(e) => {
                // ペイロードは確保も読みもせず、応答して閉じる。
                let (code, msg) = match e {
                    FrameError::PayloadTooLarge { .. } => {
                        (CriErrorCode::ResourceExhausted, "payload too large")
                    }
                    FrameError::UnknownType(_) | FrameError::InvalidFlags { .. } => {
                        (CriErrorCode::InvalidArgument, "invalid frame header")
                    }
                };
                let resp = status_response(code, msg);
                record_op(ctx, CriOpKind::ShimV2Frame, resp_code(&resp), started);
                send_response(ctx, writer, done, raw_stream_id, &resp, started);
                drain_then_close(&mut stream, ctx);
                return;
            }
        };
        // 長さは検証済み（<= MAX_PAYLOAD_LEN）なのでここで初めて確保する。
        let mut payload = vec![0u8; header.length() as usize];
        let outcome = read_full(&mut stream, &mut payload, deadline, ctx);
        if !matches!(outcome, ReadOutcome::Done) {
            outcome.record(ctx, started);
            return;
        }
        let sid = header.stream_id();
        let (kind, resp) = match header.message_type() {
            MessageType::Response => return,
            MessageType::Data => (
                CriOpKind::ShimV2Frame,
                status_response(CriErrorCode::InvalidArgument, "unknown stream"),
            ),
            MessageType::Request => {
                if sid % 2 == 0 || sid <= last_stream_id {
                    (
                        CriOpKind::ShimV2Frame,
                        status_response(CriErrorCode::InvalidArgument, "invalid stream id"),
                    )
                } else {
                    last_stream_id = sid;
                    if header.flags() != 0 {
                        (
                            CriOpKind::ShimV2Frame,
                            status_response(
                                CriErrorCode::Unimplemented,
                                "streaming is not supported",
                            ),
                        )
                    } else {
                        // 復号前に metadata の件数を数えて上限を検証する（復号後では過大確保を防げない）。
                        let decoded = if metadata_within_limit(&payload) {
                            TtrpcRequest::decode(payload.as_slice()).ok()
                        } else {
                            None
                        };
                        match decoded {
                            Some(req) => {
                                if inflight.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_PER_CONN
                                {
                                    inflight.fetch_sub(1, Ordering::SeqCst);
                                    (
                                        CriOpKind::ShimV2Dispatch,
                                        status_response(
                                            CriErrorCode::ResourceExhausted,
                                            "too many in-flight requests",
                                        ),
                                    )
                                } else {
                                    let spawned = thread::Builder::new()
                                        .name("ttrpc-req".into())
                                        .spawn_scoped(scope, move || {
                                            let _g = InflightGuard(inflight);
                                            let cancelled = || {
                                                ctx.stop.load(Ordering::SeqCst)
                                                    || done.load(Ordering::SeqCst)
                                            };
                                            let resp = bound_response(
                                                ctx.registry.dispatch_cancellable(&req, &cancelled),
                                            );
                                            record_op(
                                                ctx,
                                                CriOpKind::ShimV2Dispatch,
                                                resp_code(&resp),
                                                started,
                                            );
                                            send_response(ctx, writer, done, sid, &resp, started);
                                        });
                                    match spawned {
                                        Ok(_) => continue,
                                        // spawn 失敗時は closure ごと破棄され guard が戻らないため手で戻す。
                                        Err(_) => {
                                            inflight.fetch_sub(1, Ordering::SeqCst);
                                            (
                                                CriOpKind::ShimV2Dispatch,
                                                status_response(
                                                    CriErrorCode::Unavailable,
                                                    "cannot start request handler",
                                                ),
                                            )
                                        }
                                    }
                                }
                            }
                            None => (
                                CriOpKind::ShimV2Frame,
                                status_response(CriErrorCode::InvalidArgument, "malformed request"),
                            ),
                        }
                    }
                }
            }
        };
        let resp = bound_response(resp);
        record_op(ctx, kind, resp_code(&resp), started);
        if !send_response(ctx, writer, done, sid, &resp, started) {
            return;
        }
    }
}
