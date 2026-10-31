//! UDS 上の ttrpc サーバー（unix のみ。CRI-5・TASK-62.1）。
//!
//! 呼び出し元（将来は shim の起動経路。#803）が bind 済みの `UnixListener` を渡し、
//! [`TtrpcServer::serve`] が accept スレッドを起こして [`ServerHandle`] を返す。
//! 接続ごとに 1 スレッドで要求を順に処理する（unary のみなので多重化しない）。
//! tokio の `net` は使わず std とスレッドで作る（依存・feature を足さない。#670）。
//!
//! 無期限の待ちを作らない（REPAIR-5）:
//! - 同時接続数に上限があり、超えた接続はすぐ閉じる
//! - フレームの最初の 1 バイトはアイドルで待つが、その後の残りは `frame_read_timeout` 以内に読み切る
//! - 書き込みにも期限を付ける。停止は期限つきの join
//!
//! peer UID の照合・socket の配置と権限は扱わない（#803。REPAIR-3）。

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use prost::Message;

use super::frame::{FrameError, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType};
use super::message::{RpcStatus, TtrpcRequest, TtrpcResponse};
use super::service::ServiceRegistry;
use crate::error::CriErrorCode;

/// サーバーの設定。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 同時接続の上限。
    pub max_connections: usize,
    /// 最初の 1 バイトの後、フレームの残りを読み切る期限。
    pub frame_read_timeout: Duration,
    /// 書き込みの期限。接続スレッドは書き込み中に停止要求を見ないため、`shutdown_timeout` より長いと
    /// `shutdown()` が `ShutdownTimeout` を返しうる（REPAIR-5）。`shutdown_timeout` 以下の値にする。
    pub write_timeout: Duration,
    /// 停止時に各スレッドの終了を待つ期限。
    pub shutdown_timeout: Duration,
    /// 停止フラグを確かめる間隔。
    pub poll_interval: Duration,
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
}

impl std::fmt::Display for ShimV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listener(k) => write!(f, "listener setup failed: {k}"),
            Self::ShutdownTimeout => write!(f, "shutdown timed out"),
        }
    }
}

impl std::error::Error for ShimV2Error {}

/// ttrpc サーバー。
pub struct TtrpcServer {
    registry: Arc<ServiceRegistry>,
    config: ServerConfig,
}

impl TtrpcServer {
    /// 登録簿と設定から作る。
    pub fn new(registry: ServiceRegistry, config: ServerConfig) -> Self {
        Self {
            registry: Arc::new(registry),
            config,
        }
    }

    /// bind 済みの listener で accept スレッドを起動する。
    pub fn serve(&self, listener: UnixListener) -> Result<ServerHandle, ShimV2Error> {
        listener
            .set_nonblocking(true)
            .map_err(|e| ShimV2Error::Listener(e.kind()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(Ctx {
            registry: Arc::clone(&self.registry),
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
        let deadline = Instant::now() + self.shutdown_timeout;
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
    /// 相手が閉じた、期限切れ、または停止要求。
    Closed,
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
            return ReadOutcome::Closed;
        }
        let slice = (deadline - now).min(ctx.config.poll_interval);
        if stream.set_read_timeout(Some(slice)).is_err() {
            return ReadOutcome::Closed;
        }
        let Some(rest) = buf.get_mut(filled..) else {
            return ReadOutcome::Closed;
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
            Err(_) => return ReadOutcome::Closed,
        }
    }
    ReadOutcome::Done
}

/// アイドルで 1 バイト待つ。停止フラグを `poll_interval` ごとに確かめる。
fn wait_first_byte(stream: &mut UnixStream, ctx: &Ctx) -> Option<u8> {
    if stream
        .set_read_timeout(Some(ctx.config.poll_interval))
        .is_err()
    {
        return None;
    }
    let mut b = [0u8; 1];
    loop {
        if ctx.stop.load(Ordering::SeqCst) {
            return None;
        }
        match stream.read(&mut b) {
            Ok(0) => return None,
            Ok(_) => return Some(b[0]),
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
    if stream
        .set_read_timeout(Some(ctx.config.poll_interval))
        .is_err()
    {
        return;
    }
    let deadline = Instant::now() + ctx.config.poll_interval * 4;
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

fn write_response(stream: &mut UnixStream, stream_id: u32, resp: &TtrpcResponse) -> io::Result<()> {
    let mut body = resp.encode_to_vec();
    if body.len() > MAX_PAYLOAD_LEN as usize {
        body =
            status_response(CriErrorCode::ResourceExhausted, "response too large").encode_to_vec();
    }
    let len = u32::try_from(body.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let header = FrameHeader::new(len, stream_id, MessageType::Response, 0)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&body);
    stream.write_all(&out)
}

fn handle_conn(mut stream: UnixStream, ctx: &Ctx) {
    // 継承された non-blocking を解く（BSD 系の accept は listener の設定を引き継ぐ）。
    if stream.set_nonblocking(false).is_err()
        || stream
            .set_write_timeout(Some(ctx.config.write_timeout))
            .is_err()
    {
        return;
    }
    let mut last_stream_id: u32 = 0;
    loop {
        let Some(first) = wait_first_byte(&mut stream, ctx) else {
            return;
        };
        let deadline = Instant::now() + ctx.config.frame_read_timeout;
        let mut raw = [0u8; HEADER_LEN];
        raw[0] = first;
        if let Some(rest) = raw.get_mut(1..)
            && matches!(
                read_full(&mut stream, rest, deadline, ctx),
                ReadOutcome::Closed
            )
        {
            return;
        }
        // 検証に失敗したヘッダの応答に使うため、stream id は生のバイトから取る。
        let raw_stream_id = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
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
                let _ = write_response(&mut stream, raw_stream_id, &status_response(code, msg));
                drain_then_close(&mut stream, ctx);
                return;
            }
        };
        // 長さは検証済み（<= MAX_PAYLOAD_LEN）なのでここで初めて確保する。
        let mut payload = vec![0u8; header.length() as usize];
        if matches!(
            read_full(&mut stream, &mut payload, deadline, ctx),
            ReadOutcome::Closed
        ) {
            return;
        }
        let sid = header.stream_id();
        let resp = match header.message_type() {
            MessageType::Response => return,
            MessageType::Data => status_response(CriErrorCode::InvalidArgument, "unknown stream"),
            MessageType::Request => {
                if sid % 2 == 0 || sid <= last_stream_id {
                    status_response(CriErrorCode::InvalidArgument, "invalid stream id")
                } else {
                    last_stream_id = sid;
                    if header.flags() != 0 {
                        status_response(CriErrorCode::Unimplemented, "streaming is not supported")
                    } else {
                        match TtrpcRequest::decode(&payload[..]) {
                            Ok(req) => ctx.registry.dispatch(&req),
                            Err(_) => {
                                status_response(CriErrorCode::InvalidArgument, "malformed request")
                            }
                        }
                    }
                }
            }
        };
        if write_response(&mut stream, sid, &resp).is_err() {
            return;
        }
    }
}
