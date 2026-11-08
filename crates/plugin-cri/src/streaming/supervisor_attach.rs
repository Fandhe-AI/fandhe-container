//! plugin-cri の完全版 `AttachBackend`（supervisor の kind 9 で入力の fd と出力の tap を受ける。
//! CRI-6・SEC-1・SUP-4・SUP-7・PLUG-1・REPAIR-2・REPAIR-3・REPAIR-5・#4077）。
//!
//! 呼び出し元: `adapter::CriPluginBackends::supervisor_attach_backend` が組み、`main.rs` が
//! `streaming::bind_production_streaming` へ渡す。セッション（cri の `attach::run_session`）が接続時に
//! [`SupervisorAttachBackend::attach`] を呼ぶ。cri の `AttachBackend` / `AttachSession` は変えない（PLUG-1。設計は
//! `docs/design/cri-streaming-server.md`「完全版 Attach の設計（#3765）」の D1〜D9）。
//!
//! # 方式
//! 1. 状態ストアで Running と pid1 を確かめる（`exec_launcher` と同じ写像）
//! 2. `AttachIoSource::obtain`（本番は制御チャネルの kind 9。本数・`MSG_CTRUNC`・種別は supervisor 側のクライアントが検証）で
//!    入力の fd（stdin の pipe の書き込み端、tty なら pty master の複製）と出力の tap を受ける
//! 3. [`validate_attach_io`] が要求との形の照合をやり直す（多層防御。`AttachIoSource` は注入でき、中身を信用しない。D9）。
//!    不一致は固定文言の `INTERNAL` で、`AttachIo` の drop が全 fd を閉じる（fail-closed）
//! 4. 入力は専用 std スレッドと socketpair で橋渡しする（`AsyncFd` を使わない理由: `O_NONBLOCK` は open file description 単位で、
//!    dup した fd に立てると supervisor 側の同じ記述にも効き、pty master を blocking で読む捕捉のリーダーが `EAGAIN` で壊れる）。
//!    pty master は書き込みと `TIOCSWINSZ` 専用で読まない（読むと捕捉から出力を奪う。出力は必ず tap から受ける）
//! 5. tap は std の `UnixStream` を非ブロッキングにして tokio へ載せる（supervisor の書き手とは別の記述）。EOF かエラーで
//!    `exited` の合図を立てる
//! 6. `exited` は tap の EOF と専用スレッドの kind 8（`ExitNotifier`）の購読から作る。`Transient`（ExitWatch の枠が満杯）や
//!    `NoSupervisor` のときは状態ストアの照会（1 秒刻み）へ退避する。D6 の「ポーリングはしない」は主経路の話で、この照会は退避経路
//!
//! # 後始末（REPAIR-5）
//! セッションの部品がすべて drop されると取り消しの旗が立ち、監視スレッドは 10 ms 刻みで抜ける。入力スレッドは socket の EOF
//! （`poll_shutdown`・drop）か書き込みの失敗で抜ける。スレッドは detached でプロセスの停止を待たせない
//! （`shutdown::SHUTDOWN_TOTAL_BOUND` は変わらない）。同時数は [`MAX_ATTACH_SESSIONS`] で、止まったスレッドも数える。
//!
//! # 未実装・簡易実装・残余（REPAIR-3）
//! - 本番の attach は引き続き読み取り専用: `production_stream_dispatcher` は `AttachHandler::read_only` のままで、stdin・tty は
//!   RPC 時に断られる。stdin・tty・resize の経路は偽の `AttachIoSource` を使う単体試験からしか届かない。`read_only` の解除・
//!   bundle の `tty/stdin` 拒否の解除・RPC 時の整合検査は #4078（C10）、実機の通し確認は #4079（C11）
//! - `AttachSession.stdin` の「バッファしない」に対し、socketpair のバッファ分だけ先行する（`exec_launcher` と同じ逸脱）
//! - コンテナが stdin を読まないと入力スレッドは `write` で止まり、コンテナが読むか終了するまで残る（枠は数え続けるので有界）
//! - `stdin_once` のとき `obtain` が戻った後に future が drop されると、`AttachIo` の drop で唯一の書き込み端が閉じ、コンテナは
//!   EOF を受ける（supervisor 側の `sendmsg` 直後の窓と同種の残余で、なくせない）
//! - tty でも stdin を要求しない接続には master が渡らず、resize は `None`
//! - resize の失敗は `AttachSession::resize` が `()` を返す契約のため捨てる
//! - 同時セッション 64 は暫定値（#4116 のオーナー確認待ち）

use std::fs::File;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{PtyMaster, WindowSize};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, StateStore, TraitError,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachSession, AttachTarget};
use fandhe_container_cri::streaming::remotecommand::TerminalSize;
use fandhe_container_supervisor::control::protocol::MAX_EXIT_WATCH_HOLD;
use fandhe_container_supervisor::control::{
    AttachInput, AttachIo, AttachIoRequest, AttachIoSource, ExitNotifier, ExitWatchOutcome,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 同時に持つ attach セッションの上限（`log_attach::MAX_ATTACH_FOLLOWERS` と同値。暫定。#4116）。
pub const MAX_ATTACH_SESSIONS: usize = 64;

/// kind 9 の取得に渡す期限（supervisor 側でも 5 秒以内に抑えられる）。
const OBTAIN_BUDGET: Duration = Duration::from_secs(5);

/// 取り消しや書き込みの再試行を見直す刻み。
const TICK: Duration = Duration::from_millis(10);

/// 退避経路（状態ストアの照会）の間隔。
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// 入力の橋渡しの 1 回の読み取り量。
const INPUT_CHUNK: usize = 4096;

const MSG_INVALID_IO: &str = "attach io is invalid";

/// 同時数の枠。最後の clone の drop で返す（スレッドも持つので止まったスレッドも数える）。
struct SlotGuard(Arc<AtomicUsize>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// セッションの部品（読み口・書き口・`exited`）が共有する生存の印。全部品の drop で取り消しの旗を立てる。
struct SessionLife(Arc<AtomicBool>);

impl Drop for SessionLife {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// 準備段階（blocking）の取り消し。future の drop で立てる。成功したら [`Self::disarm`]。
struct PrepCancel {
    flag: Arc<AtomicBool>,
    armed: bool,
}

impl PrepCancel {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PrepCancel {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(true, Ordering::SeqCst);
        }
    }
}

/// `exited` の合図（tokio の `sync` を使わない手作りの通知）。
#[derive(Clone, Default)]
struct ExitSignal(Arc<Mutex<(bool, Option<Waker>)>>);

impl ExitSignal {
    fn fire(&self) {
        let waker = {
            let mut st = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            st.0 = true;
            st.1.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// 合図で完了する `exited` の future。drop で生存の印を手放す。
struct ExitedFuture {
    signal: ExitSignal,
    _life: Arc<SessionLife>,
}

impl Future for ExitedFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut st = self.signal.0.lock().unwrap_or_else(PoisonError::into_inner);
        if st.0 {
            Poll::Ready(())
        } else {
            st.1 = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// tap の読み口。EOF かエラーで `exited` の合図を立てる（D2）。
struct TapReader {
    inner: tokio::net::UnixStream,
    signal: ExitSignal,
    _life: Arc<SessionLife>,
}

impl AsyncRead for TapReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let had_room = buf.remaining() > 0;
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        match &polled {
            Poll::Ready(Ok(())) if had_room && buf.filled().len() == before => this.signal.fire(),
            Poll::Ready(Err(_)) => this.signal.fire(),
            _ => {}
        }
        polled
    }
}

/// 入力の書き口。drop で生存の印を手放す。
struct InputWriter {
    inner: tokio::net::UnixStream,
    _life: Arc<SessionLife>,
}

impl AsyncWrite for InputWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 形を照合した入力。
enum ValidInput {
    Pipe(File),
    Pty(PtyMaster),
}

/// 形の照合を通った入出力。
struct ValidatedIo {
    input: Option<ValidInput>,
    stdout: Option<StdUnixStream>,
    stderr: Option<StdUnixStream>,
}

fn invalid_io() -> CriError {
    CriError::internal(MSG_INVALID_IO)
}

/// fd の種別を `fstat` で確かめて `File` として返す（std の `File::metadata` を使い、`unsafe` を持たない）。
fn check_kind(fd: OwnedFd, want: fn(&std::fs::FileType) -> bool) -> Result<File, CriError> {
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| invalid_io())?;
    if want(&meta.file_type()) {
        Ok(file)
    } else {
        Err(invalid_io())
    }
}

/// tap（socket）の種別を確かめる。
fn check_tap(s: StdUnixStream) -> Result<StdUnixStream, CriError> {
    let file = check_kind(OwnedFd::from(s), |t| t.is_socket())?;
    Ok(StdUnixStream::from(OwnedFd::from(file)))
}

/// `obtain` の結果を要求と照合する（SEC-1・D9。純粋な検査で、不一致は固定文言の `INTERNAL`。受け取った fd は drop で閉じる）。
fn validate_attach_io(target: &AttachTarget, io: AttachIo) -> Result<ValidatedIo, CriError> {
    let AttachIo {
        input,
        stdout,
        stderr,
    } = io;
    if stdout.is_some() != target.stdout || stderr.is_some() != target.stderr {
        return Err(invalid_io());
    }
    if target.tty && stderr.is_some() {
        return Err(invalid_io());
    }
    let input = match (input, target.stdin, target.tty) {
        (None, false, _) => None,
        (Some(AttachInput::Pipe(fd)), true, false) => {
            Some(ValidInput::Pipe(check_kind(fd, |t| {
                t.is_fifo() || t.is_socket()
            })?))
        }
        (Some(AttachInput::Pty(m)), true, true) => Some(ValidInput::Pty(m)),
        _ => return Err(invalid_io()),
    };
    Ok(ValidatedIo {
        input,
        stdout: stdout.map(check_tap).transpose()?,
        stderr: stderr.map(check_tap).transpose()?,
    })
}

/// `AttachIoSource` の失敗を CRI のエラーへ写す。文言は固定の英文で、ID・値を含めない（REPAIR-4）。
fn map_trait_error(e: &TraitError) -> CriError {
    match e.code() {
        ErrorCode::NotFound => CriError::not_found("container not found"),
        ErrorCode::FailedPrecondition => {
            CriError::failed_precondition("attach is not possible in the current container state")
        }
        ErrorCode::Unavailable => CriError::unavailable("attach is unavailable"),
        ErrorCode::Timeout => CriError::timeout("attach timed out"),
        ErrorCode::ResourceExhausted => {
            CriError::resource_exhausted("attach resources are exhausted")
        }
        ErrorCode::InvalidArgument => CriError::invalid_argument("attach request was rejected"),
        ErrorCode::Unimplemented => CriError::unimplemented("attach is not supported"),
        _ => CriError::internal("attach failed"),
    }
}

/// 状態ストアから Running と pid1 を読む。
fn running_pid(store: &dyn StateStore, id: &ContainerId) -> Result<NonZeroU32, CriError> {
    let record = store.get(&GetStateRequest::new(id.clone())).map_err(|e| {
        if e.code() == ErrorCode::NotFound {
            CriError::not_found("container not found")
        } else {
            CriError::unavailable("container state is unavailable")
        }
    })?;
    let status = record.status();
    match (status.state(), status.pid()) {
        (ContainerState::Running, Some(pid)) => Ok(pid),
        _ => Err(CriError::failed_precondition("container is not running")),
    }
}

/// 状態ストアの上で、`pid` のコンテナがもう動いていないと言えるか（読めないときは言えない）。
fn is_gone(store: &dyn StateStore, id: &ContainerId, pid: NonZeroU32) -> bool {
    match store.get(&GetStateRequest::new(id.clone())) {
        Ok(r) => {
            let s = r.status();
            !(s.state() == ContainerState::Running && s.pid() == Some(pid))
        }
        Err(e) => e.code() == ErrorCode::NotFound,
    }
}

/// 取り消しを見ながら `d` だけ待つ。取り消されたら `true`。
fn sleep_cancellable(d: Duration, cancel: &AtomicBool) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if cancel.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(TICK.min(end.saturating_duration_since(Instant::now())));
    }
    cancel.load(Ordering::SeqCst)
}

/// 監視スレッドの本体。終了の合図を立てるか、取り消しで抜ける。
fn watch_exit(
    store: &dyn StateStore,
    notifier: &dyn ExitNotifier,
    id: &ContainerId,
    pid: NonZeroU32,
    signal: &ExitSignal,
    cancel: &AtomicBool,
) {
    let mut use_notifier = true;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        if use_notifier {
            let until = Instant::now() + MAX_EXIT_WATCH_HOLD;
            match notifier.watch(id, pid, until, &|| cancel.load(Ordering::SeqCst)) {
                ExitWatchOutcome::Woken | ExitWatchOutcome::PidChanged => {
                    signal.fire();
                    return;
                }
                ExitWatchOutcome::Expired => continue,
                ExitWatchOutcome::Cancelled => return,
                ExitWatchOutcome::Transient => {
                    // 1 回分は照会で待ち、次の周回で購読をやり直す。
                    if sleep_cancellable(POLL_INTERVAL, cancel) {
                        return;
                    }
                }
                _ => {
                    // NoSupervisor など: 以後は通知を使わない。
                    use_notifier = false;
                }
            }
        } else if sleep_cancellable(POLL_INTERVAL, cancel) {
            return;
        }
        if is_gone(store, id, pid) {
            signal.fire();
            return;
        }
    }
}

/// `file` へ全部書く。`WouldBlock`（他者が `O_NONBLOCK` を立てた場合の防御）は取り消しを見ながら再試行する。
fn write_all_retry(file: &mut File, mut data: &[u8], cancel: &AtomicBool) -> bool {
    while !data.is_empty() {
        match file.write(data) {
            Ok(0) => return false,
            Ok(n) => data = data.get(n..).unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if sleep_cancellable(TICK, cancel) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

/// std の socket を tokio へ載せる。
fn to_tokio(s: StdUnixStream) -> Result<tokio::net::UnixStream, CriError> {
    s.set_nonblocking(true)
        .map_err(|_| CriError::internal("attach stdio setup failed"))?;
    tokio::net::UnixStream::from_std(s).map_err(|_| CriError::internal("attach stdio setup failed"))
}

/// 入力の橋渡し: tokio 側の書き口を返し、専用スレッドが socket から読んで `file` へ書く。
fn bridge_input(
    mut file: File,
    cancel: Arc<AtomicBool>,
    slot: Arc<SlotGuard>,
) -> Result<tokio::net::UnixStream, CriError> {
    let (tokio_side, mut thread_side) =
        StdUnixStream::pair().map_err(|_| CriError::unavailable("attach stdio setup failed"))?;
    std::thread::Builder::new()
        .name("attach-stdin".to_string())
        .spawn(move || {
            let _slot = slot;
            let mut buf = [0u8; INPUT_CHUNK];
            loop {
                match thread_side.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let Some(chunk) = buf.get(..n) else { return };
                        if !write_all_retry(&mut file, chunk, &cancel) {
                            return;
                        }
                    }
                }
            }
        })
        .map_err(|_| CriError::unavailable("failed to start the attach input bridge"))?;
    to_tokio(tokio_side)
}

/// `attach` の準備段階（blocking）の結果。
struct Prepared {
    io: ValidatedIo,
    id: ContainerId,
    pid: NonZeroU32,
    slot: Arc<SlotGuard>,
}

struct Inner {
    store: Arc<dyn StateStore>,
    io_source: Arc<dyn AttachIoSource>,
    exit_notifier: Arc<dyn ExitNotifier>,
    active: Arc<AtomicUsize>,
}

impl Inner {
    fn prepare(&self, target: &AttachTarget, cancel: &AtomicBool) -> Result<Prepared, CriError> {
        let cancelled = || CriError::unavailable("attach was cancelled");
        if target.tty && target.stderr {
            return Err(CriError::invalid_argument(
                "attach with tty cannot use stderr",
            ));
        }
        if self.active.fetch_add(1, Ordering::SeqCst) >= MAX_ATTACH_SESSIONS {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return Err(CriError::resource_exhausted("too many attach sessions"));
        }
        let slot = Arc::new(SlotGuard(Arc::clone(&self.active)));
        let id = ContainerId::new(target.container_id.clone())
            .map_err(|_| CriError::invalid_argument("container id is invalid"))?;
        let pid = running_pid(&*self.store, &id)?;
        if cancel.load(Ordering::SeqCst) {
            return Err(cancelled());
        }
        let io = self
            .io_source
            .obtain(
                &id,
                pid,
                AttachIoRequest {
                    stdin: target.stdin,
                    stdout: target.stdout,
                    stderr: target.stderr,
                    tty: target.tty,
                },
                Instant::now() + OBTAIN_BUDGET,
            )
            .map_err(|e| map_trait_error(&e))?;
        let io = validate_attach_io(target, io)?;
        if cancel.load(Ordering::SeqCst) {
            return Err(cancelled());
        }
        Ok(Prepared { io, id, pid, slot })
    }
}

/// 本番の完全版 `AttachBackend`。
pub struct SupervisorAttachBackend {
    inner: Arc<Inner>,
}

impl SupervisorAttachBackend {
    /// 状態ストア・fd の取得元・終了購読の口から作る（試験は偽物を注入する）。
    pub fn new(
        store: Arc<dyn StateStore>,
        io_source: Arc<dyn AttachIoSource>,
        exit_notifier: Arc<dyn ExitNotifier>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                io_source,
                exit_notifier,
                active: Arc::new(AtomicUsize::new(0)),
            }),
        }
    }

    /// 枠の使用数（観測・試験用）。
    pub fn active_sessions(&self) -> usize {
        self.inner.active.load(Ordering::SeqCst)
    }
}

impl AttachBackend for SupervisorAttachBackend {
    fn attach(
        &self,
        target: AttachTarget,
    ) -> Pin<Box<dyn Future<Output = Result<AttachSession, CriError>> + Send + 'static>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            // future が drop（期限切れ・切断）されたら blocking 側へ取り消しを伝える。
            let prep_flag = Arc::new(AtomicBool::new(false));
            let mut on_drop = PrepCancel {
                flag: Arc::clone(&prep_flag),
                armed: true,
            };
            let inner2 = Arc::clone(&inner);
            let target2 = target.clone();
            let prepared =
                tokio::task::spawn_blocking(move || inner2.prepare(&target2, &prep_flag))
                    .await
                    .map_err(|_| CriError::internal("attach failed"))??;
            on_drop.disarm();
            let Prepared { io, id, pid, slot } = prepared;
            let ValidatedIo {
                input,
                stdout,
                stderr,
            } = io;

            let cancel = Arc::new(AtomicBool::new(false));
            let life = Arc::new(SessionLife(Arc::clone(&cancel)));
            let signal = ExitSignal::default();

            let mut resize: Option<Box<dyn FnMut(TerminalSize) + Send>> = None;
            let stdin: Option<Box<dyn AsyncWrite + Send + Unpin>> = match input {
                None => None,
                Some(ValidInput::Pipe(file)) => {
                    let w = bridge_input(file, Arc::clone(&cancel), Arc::clone(&slot))?;
                    Some(Box::new(InputWriter {
                        inner: w,
                        _life: Arc::clone(&life),
                    }))
                }
                Some(ValidInput::Pty(master)) => {
                    let dup = master
                        .as_fd()
                        .try_clone_to_owned()
                        .map_err(|_| CriError::internal("attach pty setup failed"))?;
                    let w = bridge_input(File::from(dup), Arc::clone(&cancel), Arc::clone(&slot))?;
                    let master = Arc::new(master);
                    // 失敗は `()` を返す契約のため捨てる。0 行・0 列はそのまま渡す（カーネルは受け付ける）。
                    resize = Some(Box::new(move |size: TerminalSize| {
                        let _ = master.resize(WindowSize::new(size.height, size.width));
                    }));
                    Some(Box::new(InputWriter {
                        inner: w,
                        _life: Arc::clone(&life),
                    }))
                }
            };
            let tap = |s: StdUnixStream| -> Result<Box<dyn AsyncRead + Send + Unpin>, CriError> {
                Ok(Box::new(TapReader {
                    inner: to_tokio(s)?,
                    signal: signal.clone(),
                    _life: Arc::clone(&life),
                }))
            };
            let stdout = stdout.map(tap).transpose()?;
            let stderr = stderr.map(tap).transpose()?;

            let store = Arc::clone(&inner.store);
            let notifier = Arc::clone(&inner.exit_notifier);
            let watch_signal = signal.clone();
            let watch_cancel = Arc::clone(&cancel);
            std::thread::Builder::new()
                .name("attach-exit".to_string())
                .spawn(move || {
                    let _slot = slot;
                    watch_exit(&*store, &*notifier, &id, pid, &watch_signal, &watch_cancel);
                })
                .map_err(|_| CriError::unavailable("failed to start the attach watcher"))?;

            Ok(AttachSession {
                stdin,
                stdout,
                stderr,
                resize,
                exited: Box::pin(ExitedFuture {
                    signal,
                    _life: life,
                }),
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
