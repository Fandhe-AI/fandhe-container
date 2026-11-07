//! plugin-cri の本番 `ExecStreamLauncher`（supervisor の `stream-exec` helper 経由。CRI-6・SEC-1・SUP-6・PLUG-1・REPAIR-5・#3761）。
//!
//! 呼び出し元: `streaming::production_stream_dispatcher` が `ExecStreamHandler` に包んで `with_exec` する。セッション（cri の
//! `exec::run_exec_session`）が `launch_timeout` を付けて [`SupervisorExecLauncher::launch`] を呼ぶ。cri crate に実装を
//! 置かないのは PLUG-1（実行系の実装は plugin 側）のため。
//!
//! # 方式（設計は `docs/design/cri-streaming-server.md`「本番 backend の設計」・案 α）
//! Exec ごとに supervisor の実行ファイル（plugin-cri の実体と同じディレクトリの固定名。`PATH` 探索なし）を
//! `stream-exec` で起動して単一スレッドの helper にし、パスを持たない socketpair（helper の fd 0）で次をやり取りする。
//! 1. 要求された stdio の端（`UnixStream::pair` の片側）を `SCM_RIGHTS` で渡す（`send_stdio_handover`）
//! 2. helper が `Started` を返す（exec の子 cgroup の通知後）。tty の能力があれば続けて `PtyMaster`
//! 3. 専用 std スレッドが `Result` を待ち、終了コードを std の `UnixStream::pair` 経由で tokio 側へ渡す
//!    （tokio の `sync`・`io-util`・`process` feature は使わない。`log_attach` と同じ橋渡し）
//!
//! コマンドは helper が supervisor の既存の exec 入口（namespace・cgroup・rlimit・capability・NNP・Landlock・seccomp の段）
//! を通して実行するため、本 crate は分離を広げない（SEC-1）。
//!
//! # 後始末（REPAIR-5）
//! [`ExecSession`] の `exit` future を drop する（セッションの終了・切断・期限切れ）と、持ち主の `HelperGuard` が helper を
//! SIGKILL する。helper の channel が閉じると supervisor の `exec_guard` が通知済みの exec 子 cgroup を回収する。回収できない
//! helper は専用スレッドが `wait` して回収し（Child を落とさない）、その数が上限に達したら新しい exec を `RESOURCE_EXHAUSTED` にする。kill は呼び出しスレッドをブロックしない。
//! [`SupervisorExecLauncher::shutdown_all`] は plugin-cri の停止時に追跡中の全 helper を kill する。停止後の `launch` は拒否し、登録の競合で漏れた helper も直ちに止める。
//!
//! # 未実装・簡易実装・残余（REPAIR-3）
//! - tty: 受け側（`PtyMaster` の検証と resize の転送）は実装・試験済みだが、helper が `--tty` を受けず supervisor の
//!   `ExecStdio` に pty が無いため、本番の spawner は能力 `tty = false` で、tty の要求は launcher でも断る（後続 issue。
//!   cri 側は RPC 時に `ExecStreamHandler::without_tty` で断る）。tty のときは stdio の fd を送らない（mask 0。暫定）。
//! - helper の fd 1・2 は `/dev/null`。診断 JSON 行は捨てる（結果は `Result` frame の固定語彙で返る）。
//! - セッションは最長 `MAX_EXEC_HOLD_SECS`（1 時間）で helper が止める（kubelet の idle 4 時間より短い）。
//! - 同時セッション 64・回収できない helper の保持 8 は暫定値（#4116 のオーナー確認待ち）。
//! - plugin-cri が SIGKILL された場合、helper は期限まで残る（PDEATHSIG を使わない設計。helper の doc を参照）。
//! - `WindowSize` の 0 行・0 列はそのまま渡す（カーネルは受け付け、害が無い）。

use std::fs::File;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{PtyMaster, WindowSize};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, StateStore,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::streaming::exec::{
    ExecLaunch, ExecSession, ExecStreamLauncher, TerminalResizer,
};
use fandhe_container_cri::streaming::remotecommand::TerminalSize;
use fandhe_container_supervisor::control::protocol::MAX_EXEC_HOLD_SECS;
use fandhe_container_supervisor::launcher::SUPERVISOR_FILE_NAME;
use fandhe_container_supervisor::stream_exec::channel::{
    ChannelError, HelperMessage, StdioSend, recv_from_helper, send_stdio_handover,
};
use fandhe_container_supervisor::stream_exec::helper::{StreamExecArgs, stream_exec_command};
use fandhe_container_supervisor::stream_exec::wire::{ChildStatus, StdioMask, StreamExecOutcome};
use tokio::io::{AsyncRead, AsyncWrite};

/// 同時に走らせる exec セッションの上限（`StreamingConfig::max_connections` の既定と同じ。暫定。#4116）。
pub const MAX_EXEC_SESSIONS: usize = 64;

/// kill 後に回収できず保持する helper の上限（暫定。#4116）。
pub const MAX_STUCK_HELPERS: usize = 8;

/// stdio の fd を helper へ渡す期限。
const HANDOVER_BUDGET: Duration = Duration::from_secs(5);

/// `Started`（と tty の `PtyMaster`）を待つ上限。cri の `launch_timeout` の既定 30 秒より短くする。
const STARTED_BUDGET: Duration = Duration::from_secs(25);

/// helper の期限（`--timeout-ms`）に足す、`Result` を待つ余裕。
const RESULT_GRACE: Duration = Duration::from_secs(30);

/// helper が 1 件の exec を保持してよい最長（supervisor の exec 全体の上限）。
const SESSION_TIMEOUT: Duration = Duration::from_secs(MAX_EXEC_HOLD_SECS);

/// 起動された helper。`channel` は helper の fd 0 に渡した socketpair の plugin 側。
pub struct SpawnedHelper {
    /// helper のプロセス。
    pub child: Child,
    /// plugin 側の channel の端。
    pub channel: StdUnixStream,
}

/// helper が対応する機能（本番の spawner は `tty = false`。後続 issue で true にする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HelperCapabilities {
    /// helper が pty を割り当てて `PtyMaster` を返せるか。
    pub tty: bool,
}

/// helper プロセスの起動口（試験で偽の helper を差し込む）。
pub trait HelperSpawner: Send + Sync + 'static {
    /// 検証済みの引数で helper を起動する。ブロッキングしてよい。
    fn spawn(&self, args: &StreamExecArgs) -> Result<SpawnedHelper, CriError>;

    /// この spawner の helper の能力。
    fn capabilities(&self) -> HelperCapabilities;
}

/// 本番の spawner。plugin-cri の実体と同じディレクトリの固定名の supervisor を `stream-exec` で起動する。
pub struct ProductionHelperSpawner;

impl HelperSpawner for ProductionHelperSpawner {
    fn spawn(&self, args: &StreamExecArgs) -> Result<SpawnedHelper, CriError> {
        let exe = std::env::current_exe().map_err(|_| {
            CriError::failed_precondition("cannot resolve the plugin executable path")
        })?;
        let supervisor = exe
            .parent()
            .filter(|d| d.has_root())
            .map(|d| d.join(SUPERVISOR_FILE_NAME))
            .ok_or_else(|| {
                CriError::failed_precondition("cannot resolve the plugin executable path")
            })?;
        if !supervisor.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Err(CriError::failed_precondition(
                "supervisor executable is not installed",
            ));
        }
        let (plugin_end, helper_end) = StdUnixStream::pair()
            .map_err(|_| CriError::unavailable("exec channel setup failed"))?;
        let mut command = stream_exec_command(&supervisor, args);
        command
            .stdin(Stdio::from(OwnedFd::from(helper_end)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|_| CriError::unavailable("failed to start the exec helper"))?;
        Ok(SpawnedHelper {
            child,
            channel: plugin_end,
        })
    }

    fn capabilities(&self) -> HelperCapabilities {
        HelperCapabilities { tty: false }
    }
}

/// 追跡中の helper の一覧と停止状態。停止の印と登録を同じ lock で扱い、停止後の登録を漏らさない（REPAIR-5）。
#[derive(Default)]
struct Live {
    stopped: bool,
    guards: Vec<Weak<HelperGuard>>,
}

/// launcher 全体で共有する状態（同時数・回収中の helper・追跡中の helper）。
#[derive(Default)]
struct Shared {
    active: AtomicUsize,
    /// 専用スレッドが `wait` 中の kill 済み helper の数。
    reaping: AtomicUsize,
    /// 回収スレッドを作れなかった kill 済み helper。Child を落とさず終了確認まで保持する。
    stuck: Mutex<Vec<Child>>,
    live: Mutex<Live>,
}

/// 同時数の枠。drop で返す。
struct Slot(Arc<Shared>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Shared {
    /// 枠を取る。回収できない helper を先に掃除し、保持が満杯・同時数超過なら `RESOURCE_EXHAUSTED`。
    fn acquire(self: &Arc<Self>) -> Result<Slot, CriError> {
        {
            let mut stuck = self.stuck.lock().unwrap_or_else(PoisonError::into_inner);
            stuck.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
            if stuck.len() + self.reaping.load(Ordering::SeqCst) >= MAX_STUCK_HELPERS {
                return Err(CriError::resource_exhausted("too many exec helpers"));
            }
        }
        if self.active.fetch_add(1, Ordering::SeqCst) >= MAX_EXEC_SESSIONS {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return Err(CriError::resource_exhausted("too many exec sessions"));
        }
        Ok(Slot(Arc::clone(self)))
    }
}

/// helper の持ち主。drop（または [`Self::kill`]）で SIGKILL して回収する。
struct HelperGuard {
    child: Mutex<Option<Child>>,
    shared: Arc<Shared>,
    _slot: Slot,
}

impl HelperGuard {
    /// SIGKILL を送って回収する。呼び出しスレッドをブロックしない（tokio の実行時の上で呼ばれうる）。
    /// 直ちに回収できなければ、専用スレッドが `wait` する（Child を落とさず zombie を作らない）。
    fn kill(&self) {
        let taken = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(mut child) = taken else { return };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = child.kill();
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let child = Arc::new(Mutex::new(Some(child)));
        let child_for_thread = Arc::clone(&child);
        shared.reaping.fetch_add(1, Ordering::SeqCst);
        let shared_for_thread = Arc::clone(&shared);
        let spawned = std::thread::Builder::new()
            .name("exec-reap".to_string())
            .spawn(move || {
                let taken = child_for_thread
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(mut c) = taken {
                    let _ = c.wait();
                }
                shared_for_thread.reaping.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            // スレッドを作れなければ保持して、次の `launch` の入口で掃除する（上限なし。Child は落とさない）。
            shared.reaping.fetch_sub(1, Ordering::SeqCst);
            let taken = child.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(c) = taken {
                shared
                    .stuck
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(c);
            }
        }
    }
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// `launch` の blocking 部が返す、tokio へ載せる前の部品。
struct Launched {
    guard: Arc<HelperGuard>,
    stdin: Option<StdUnixStream>,
    stdout: Option<StdUnixStream>,
    stderr: Option<StdUnixStream>,
    exit: StdUnixStream,
    pty: Option<PtyMaster>,
}

/// 終了コードを tokio 側へ渡す固定長の値（タグ 1 バイト + 4 バイト）。
const EXIT_OK: u8 = 0;
const EXIT_ERR: u8 = 1;

/// `Result` frame の値を終了コードへ写す（SIGNAL は 128 + 番号。`NotStarted` は子の終了状態。純関数）。
pub fn map_outcome(outcome: StreamExecOutcome) -> Result<i32, CriError> {
    let status = |s: ChildStatus| match s {
        ChildStatus::Exited(n) => i32::from(n),
        ChildStatus::Signaled(sig) => 128 + i32::from(sig.get()),
    };
    match outcome {
        StreamExecOutcome::Exited(n) => Ok(i32::from(n)),
        StreamExecOutcome::Signaled(sig) => Ok(128 + i32::from(sig.get())),
        StreamExecOutcome::NotStarted { exit, .. } => Ok(status(exit)),
        StreamExecOutcome::Failed(code) => Err(cri_error(code)),
    }
}

/// helper の失敗分類を CRI のエラーへ写す。メッセージは固定の英文で、パス・argv・ID を含めない。
fn cri_error(code: ErrorCode) -> CriError {
    match code {
        ErrorCode::FailedPrecondition => {
            CriError::failed_precondition("exec target is not running")
        }
        ErrorCode::Unavailable => CriError::unavailable("exec helper is unavailable"),
        ErrorCode::InvalidArgument => CriError::invalid_argument("exec request was rejected"),
        ErrorCode::Timeout => CriError::timeout("exec timed out"),
        ErrorCode::ResourceExhausted => {
            CriError::resource_exhausted("exec resources are exhausted")
        }
        ErrorCode::NotFound => CriError::not_found("exec target was not found"),
        ErrorCode::Unimplemented => CriError::unimplemented("exec is not supported"),
        _ => CriError::internal("exec failed"),
    }
}

fn channel_error(e: &ChannelError) -> CriError {
    cri_error(e.code())
}

fn encode_exit(result: &Result<i32, CriError>, fallback: ErrorCode) -> [u8; 5] {
    match result {
        Ok(code) => {
            let b = code.to_be_bytes();
            [EXIT_OK, b[0], b[1], b[2], b[3]]
        }
        Err(_) => {
            let n = fandhe_container_supervisor::stream_exec::wire::error_code_to_u8(fallback)
                .unwrap_or(6);
            [EXIT_ERR, n, 0, 0, 0]
        }
    }
}

fn decode_exit(buf: [u8; 5]) -> Result<i32, CriError> {
    let [tag, a, b, c, d] = buf;
    if tag == EXIT_OK {
        return Ok(i32::from_be_bytes([a, b, c, d]));
    }
    let code = fandhe_container_supervisor::stream_exec::wire::error_code_from_u8(a)
        .unwrap_or(ErrorCode::Internal);
    Err(cri_error(code))
}

/// `Result` を待つ専用スレッドの本体。予期しない frame・受信失敗は helper を kill して内部エラーにする。
fn watch_result(
    channel: StdUnixStream,
    guard: Weak<HelperGuard>,
    mut exit_w: StdUnixStream,
    deadline: Instant,
) {
    let (result, code) = match recv_from_helper(&channel, deadline) {
        Ok(HelperMessage::Result(outcome)) => {
            let code = match outcome {
                StreamExecOutcome::Failed(c) => c,
                _ => ErrorCode::Internal,
            };
            (map_outcome(outcome), code)
        }
        Ok(_) => {
            kill_weak(&guard);
            (Err(CriError::internal("exec failed")), ErrorCode::Internal)
        }
        Err(e) => {
            kill_weak(&guard);
            (Err(channel_error(&e)), e.code())
        }
    };
    // 受け側が先に消えていれば書き込みは失敗するが、害は無い。
    let _ = exit_w.write_all(&encode_exit(&result, code));
}

fn kill_weak(guard: &Weak<HelperGuard>) {
    if let Some(g) = guard.upgrade() {
        g.kill();
    }
}

/// 終了コードの future。drop で helper の持ち主も drop され、helper を kill する。
async fn read_exit(
    sock: tokio::net::UnixStream,
    _guard: Arc<HelperGuard>,
) -> Result<i32, CriError> {
    let mut buf = [0u8; 5];
    let mut filled = 0usize;
    while filled < buf.len() {
        sock.readable()
            .await
            .map_err(|_| CriError::internal("exec failed"))?;
        let Some(tail) = buf.get_mut(filled..) else {
            return Err(CriError::internal("exec failed"));
        };
        match sock.try_read(tail) {
            Ok(0) => return Err(CriError::unavailable("exec helper is unavailable")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(CriError::internal("exec failed")),
        }
    }
    decode_exit(buf)
}

/// pty master への resize の転送（`TIOCSWINSZ`。slave 側へ SIGWINCH が届く）。
struct PtyResizer(Arc<PtyMaster>);

impl TerminalResizer for PtyResizer {
    fn resize(&mut self, size: TerminalSize) -> Result<(), CriError> {
        self.0
            .resize(WindowSize::new(size.height, size.width))
            .map_err(|_| CriError::internal("terminal resize failed"))
    }
}

/// 本番の `ExecStreamLauncher`。
pub struct SupervisorExecLauncher {
    state_root: PathBuf,
    store: Arc<dyn StateStore>,
    spawner: Arc<dyn HelperSpawner>,
    shared: Arc<Shared>,
}

impl SupervisorExecLauncher {
    /// 状態ルート（絶対パス）・状態ストア・helper の起動口から作る。
    pub fn new(
        state_root: PathBuf,
        store: Arc<dyn StateStore>,
        spawner: Arc<dyn HelperSpawner>,
    ) -> Self {
        Self {
            state_root,
            store,
            spawner,
            shared: Arc::new(Shared::default()),
        }
    }

    /// 本番の spawner で作る。
    pub fn production(state_root: PathBuf, store: Arc<dyn StateStore>) -> Self {
        Self::new(state_root, store, Arc::new(ProductionHelperSpawner))
    }

    /// 追跡中の helper の数（観測・試験用）。
    pub fn active_sessions(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    /// 追跡中の全 helper を kill する（plugin-cri の停止時。REPAIR-5）。
    pub fn shutdown_all(&self) {
        // 停止の印を先に立て、以降の登録は拒否する。全 helper へ先に kill を送り、回収は各スレッドに任せる
        // （直列に待たない。共通の停止期限を食わない）。
        let guards: Vec<Arc<HelperGuard>> = {
            let mut live = self
                .shared
                .live
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            live.stopped = true;
            live.guards.iter().filter_map(Weak::upgrade).collect()
        };
        for g in guards {
            g.kill();
        }
    }

    /// 状態を照合して helper を起動し、`Started`（tty なら `PtyMaster` も）まで進める。ブロッキング。
    fn launch_blocking(&self, req: &ExecLaunch) -> Result<Launched, CriError> {
        let caps = self.spawner.capabilities();
        if req.tty && !caps.tty {
            return Err(CriError::invalid_argument("exec with tty is not supported"));
        }
        if req.tty && req.stderr {
            return Err(CriError::invalid_argument(
                "exec with tty cannot use stderr",
            ));
        }
        if self
            .shared
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stopped
        {
            return Err(CriError::unavailable("exec launcher is stopped"));
        }
        let slot = self.shared.acquire()?;

        let id = ContainerId::new(req.container_id.clone())
            .map_err(|_| CriError::invalid_argument("container id is invalid"))?;
        let record = self
            .store
            .get(&GetStateRequest::new(id.clone()))
            .map_err(|e| {
                if e.code() == ErrorCode::NotFound {
                    CriError::not_found("container not found")
                } else {
                    CriError::unavailable("container state is unavailable")
                }
            })?;
        let status = record.status();
        let pid: NonZeroU32 = match (status.state(), status.pid()) {
            (ContainerState::Running, Some(pid)) => pid,
            _ => return Err(CriError::failed_precondition("container is not running")),
        };
        // tty のときは stdio の fd を送らない（mask 0。supervisor 側の pty 結線が入るまでの暫定）。
        let mask = if req.tty {
            StdioMask::from_presence(false, false, false)
        } else {
            StdioMask::from_presence(req.stdin, req.stdout, req.stderr)
        };
        let args = StreamExecArgs::new(
            self.state_root.clone(),
            id,
            pid,
            SESSION_TIMEOUT,
            mask,
            req.cmd.clone(),
        )
        .map_err(|_| CriError::invalid_argument("exec request was rejected"))?;

        // 要求された分だけ socketpair を作る（親側 = plugin-cri、子側 = helper へ渡す端）。
        let mut parent_stdin = None;
        let mut parent_stdout = None;
        let mut parent_stderr = None;
        let mut child_stdin = None;
        let mut child_stdout = None;
        let mut child_stderr = None;
        if !req.tty {
            let io_err = |_| CriError::unavailable("exec stdio setup failed");
            if req.stdin {
                let (p, c) = StdUnixStream::pair().map_err(io_err)?;
                let _ = p.shutdown(std::net::Shutdown::Read);
                parent_stdin = Some(p);
                child_stdin = Some(c);
            }
            if req.stdout {
                let (p, c) = StdUnixStream::pair().map_err(io_err)?;
                let _ = p.shutdown(std::net::Shutdown::Write);
                parent_stdout = Some(p);
                child_stdout = Some(c);
            }
            if req.stderr {
                let (p, c) = StdUnixStream::pair().map_err(io_err)?;
                let _ = p.shutdown(std::net::Shutdown::Write);
                parent_stderr = Some(p);
                child_stderr = Some(c);
            }
        }

        let SpawnedHelper { child, channel } = self.spawner.spawn(&args)?;
        let guard = Arc::new(HelperGuard {
            child: Mutex::new(Some(child)),
            shared: Arc::clone(&self.shared),
            _slot: slot,
        });
        let stopped = {
            let mut live = self
                .shared
                .live
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if live.stopped {
                true
            } else {
                live.guards.retain(|w| w.strong_count() > 0);
                live.guards.push(Arc::downgrade(&guard));
                false
            }
        };
        if stopped {
            // 停止後に起動した helper は直ちに止める（`shutdown_all` の一覧から漏れるため）。
            guard.kill();
            return Err(CriError::unavailable("exec launcher is stopped"));
        }

        send_stdio_handover(
            &channel,
            &StdioSend {
                stdin: child_stdin.as_ref().map(|s| s.as_fd()),
                stdout: child_stdout.as_ref().map(|s| s.as_fd()),
                stderr: child_stderr.as_ref().map(|s| s.as_fd()),
            },
            Instant::now() + HANDOVER_BUDGET,
        )
        .map_err(|e| channel_error(&e))?;
        // helper へ渡した端はここで閉じる（EOF を正しく観測するため）。
        drop((child_stdin, child_stdout, child_stderr));

        let started_deadline = Instant::now() + STARTED_BUDGET;
        // `Result` が先に来たら起動の失敗（`Started` 前）。
        match recv_from_helper(&channel, started_deadline) {
            Ok(HelperMessage::Started) => {}
            Ok(HelperMessage::Result(outcome)) => {
                return Err(match map_outcome(outcome) {
                    Err(e) => e,
                    Ok(_) => CriError::internal("exec ended before it started"),
                });
            }
            Ok(HelperMessage::PtyMaster(_)) => return Err(CriError::internal("exec failed")),
            Err(e) => return Err(channel_error(&e)),
        }
        let pty = if req.tty {
            match recv_from_helper(&channel, started_deadline) {
                Ok(HelperMessage::PtyMaster(fd)) => Some(
                    PtyMaster::from_received(fd)
                        .map_err(|_| CriError::internal("exec pty is invalid"))?,
                ),
                Ok(_) => return Err(CriError::internal("exec failed")),
                Err(e) => return Err(channel_error(&e)),
            }
        } else {
            None
        };

        let (exit_w, exit_r) =
            StdUnixStream::pair().map_err(|_| CriError::unavailable("exec stdio setup failed"))?;
        let watch_channel = channel
            .try_clone()
            .map_err(|_| CriError::unavailable("exec channel setup failed"))?;
        let weak = Arc::downgrade(&guard);
        let deadline = Instant::now() + SESSION_TIMEOUT + RESULT_GRACE;
        std::thread::Builder::new()
            .name("exec-result".to_string())
            .spawn(move || watch_result(watch_channel, weak, exit_w, deadline))
            .map_err(|_| CriError::unavailable("failed to start the exec watcher"))?;
        // `channel` はここで閉じてよい（スレッドが複製を持つ）。
        drop(channel);

        Ok(Launched {
            guard,
            stdin: parent_stdin,
            stdout: parent_stdout,
            stderr: parent_stderr,
            exit: exit_r,
            pty,
        })
    }
}

/// std の socket を tokio へ載せる（非ブロッキングにして `from_std`）。
fn to_tokio(s: StdUnixStream) -> Result<tokio::net::UnixStream, CriError> {
    s.set_nonblocking(true)
        .map_err(|_| CriError::internal("exec stdio setup failed"))?;
    tokio::net::UnixStream::from_std(s).map_err(|_| CriError::internal("exec stdio setup failed"))
}

/// pty master と tokio 側の stdio を専用スレッドで橋渡しする（master → socket、socket → master）。
/// 戻りは (tokio 側の出力の読み口, tokio 側の入力の書き口)。master が閉じる（EIO）か相手が閉じればスレッドは終わる。
fn bridge_pty(master: &PtyMaster) -> Result<(StdUnixStream, StdUnixStream), CriError> {
    let setup = |_| CriError::internal("exec pty setup failed");
    let out_file = File::from(master.as_fd().try_clone_to_owned().map_err(setup)?);
    let in_file = File::from(master.as_fd().try_clone_to_owned().map_err(setup)?);
    let (out_tokio, mut out_thread) = StdUnixStream::pair().map_err(setup)?;
    let (in_tokio, mut in_thread) = StdUnixStream::pair().map_err(setup)?;
    std::thread::Builder::new()
        .name("exec-pty-out".to_string())
        .spawn(move || {
            let mut out_file = out_file;
            let mut buf = [0u8; 4096];
            loop {
                match out_file.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let Some(chunk) = buf.get(..n) else { return };
                        if out_thread.write_all(chunk).is_err() {
                            return;
                        }
                    }
                }
            }
        })
        .map_err(|_| CriError::unavailable("failed to start the exec pty bridge"))?;
    std::thread::Builder::new()
        .name("exec-pty-in".to_string())
        .spawn(move || {
            let mut in_file = in_file;
            let mut buf = [0u8; 4096];
            loop {
                match in_thread.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let Some(chunk) = buf.get(..n) else { return };
                        if in_file.write_all(chunk).is_err() {
                            return;
                        }
                    }
                }
            }
        })
        .map_err(|_| CriError::unavailable("failed to start the exec pty bridge"))?;
    Ok((out_tokio, in_tokio))
}

impl ExecStreamLauncher for SupervisorExecLauncher {
    fn launch(
        &self,
        req: ExecLaunch,
    ) -> Pin<Box<dyn Future<Output = Result<ExecSession, CriError>> + Send + '_>> {
        Box::pin(async move {
            let this = Self {
                state_root: self.state_root.clone(),
                store: Arc::clone(&self.store),
                spawner: Arc::clone(&self.spawner),
                shared: Arc::clone(&self.shared),
            };
            let req2 = req.clone();
            let launched = tokio::task::spawn_blocking(move || this.launch_blocking(&req2))
                .await
                .map_err(|_| CriError::internal("exec failed"))??;
            let Launched {
                guard,
                stdin,
                stdout,
                stderr,
                exit,
                pty,
            } = launched;

            let as_reader =
                |s: StdUnixStream| -> Result<Box<dyn AsyncRead + Send + Unpin>, CriError> {
                    Ok(Box::new(to_tokio(s)?))
                };
            let as_writer =
                |s: StdUnixStream| -> Result<Box<dyn AsyncWrite + Send + Unpin>, CriError> {
                    Ok(Box::new(to_tokio(s)?))
                };
            let (stdin, stdout, stderr, resize) = match pty {
                Some(master) => {
                    let (out, inp) = bridge_pty(&master)?;
                    let resize: Option<Box<dyn TerminalResizer>> =
                        Some(Box::new(PtyResizer(Arc::new(master))));
                    (
                        if req.stdin {
                            Some(as_writer(inp)?)
                        } else {
                            None
                        },
                        if req.stdout {
                            Some(as_reader(out)?)
                        } else {
                            None
                        },
                        None,
                        resize,
                    )
                }
                None => (
                    stdin.map(as_writer).transpose()?,
                    stdout.map(as_reader).transpose()?,
                    stderr.map(as_reader).transpose()?,
                    None,
                ),
            };
            let exit_sock = to_tokio(exit)?;
            Ok(ExecSession {
                stdin,
                stdout,
                stderr,
                exit: Box::pin(read_exit(exit_sock, guard)),
                resize,
            })
        })
    }
}

#[cfg(test)]
mod tests;
