//! plugin-cri の読み取り専用の `AttachBackend`（回転ログの follow。CRI-6・SUP-4・SUP-7・REPAIR-3・REPAIR-5・#3763）。
//!
//! 呼び出し元: `streaming::production_stream_dispatcher` が `AttachHandler::read_only` に包んで `with_attach` する。
//! セッション（cri の `attach::run_session`）が接続時に [`LogFollowAttachBackend::attach`] を呼ぶ。
//!
//! # 方式（段階 1。設計は `docs/design/cri-streaming-server.md`「Attach > 段階 1」）
//! supervisor の回転ログ（`<state_root>/@container-logs`。CRI のコンテナも `TeeLogSink` で書く）を、セッションごとの専用スレッドが
//! `read_container_log_with_cancel` で `tail 0` から follow する。出力（`stdout ` / `stderr ` のタグつきレコード）は
//! supervisor の `RecordDemux` がタグを外して 2 本へ分け、std の `UnixStream::pair` を橋にして tokio 側の `AsyncRead` へ渡す
//! （tokio の `sync`・`io-util` feature を使わない。std の socketpair は CLOEXEC のため子プロセスへ fd が漏れない）。
//! 背圧は socketpair のバッファが担う。
//!
//! # 終わり方
//! - コンテナの終了（書き手 sink のロックが解放され、かつ状態が Running でない）・ログの削除・取り消し: 読み口は EOF で、
//!   `exited` が完了する（セッションは出力を流し切って Status(Success) を返す）。
//! - 期限（24 時間）・読み取りの失敗: EOF の後に読み口が `io::Error` を返し、セッションは Success にしない（黙って成功を装わない）。
//! - セッションの終了（クライアントの切断・idle・停止）: 読み口と `exited` の drop が取り消しの旗を立て、スレッドは次のポーリング
//!   （200 ms）以内に抜ける。書き込みが詰まっていても 200 ms 刻みで旗を見る。
//!
//! # 未実装（REPAIR-3）
//! stdin・tty は `INVALID_ARGUMENT`（RPC 時は `StreamWiring::attach_interactive` が false、接続時はここ）。完全版は #3765 の設計。

use std::future::Future;
use std::io::{self, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, StateStore,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachSession, AttachTarget};
use fandhe_container_supervisor::logs::{
    ContainerActivity, FollowEnd, FollowOptions, LogReadOptions, MAX_FOLLOW_DURATION, RecordDemux,
    TailCount, container_log_rotation_config, read_container_log_with_cancel,
};
use tokio::io::{AsyncRead, ReadBuf};

/// RPC 時にも使う固定文言（stdin・tty の拒否）。コンテナ ID は含めない。
pub const MSG_ATTACH_INTERACTIVE_UNSUPPORTED: &str = "attach with stdin or tty is not supported";

/// 同時に走らせる follow スレッドの上限（`StreamingConfig::max_connections` の既定と同じ。超えたら `RESOURCE_EXHAUSTED`）。
pub const MAX_ATTACH_FOLLOWERS: usize = 64;

/// 書き込みが詰まったときに取り消しの旗を見直す刻み（REPAIR-5）。
const WRITE_TICK: Duration = Duration::from_millis(200);

/// 追従開始位置の確定を待つ上限（REPAIR-5）。
const READY_WAIT: Duration = Duration::from_secs(5);

/// コンテナの稼働状態の問い合わせ口（試験で偽物を差し込む）。
pub trait AttachProbe: Send + Sync + 'static {
    /// 接続時に Running であることを確かめる。不在は `NOT_FOUND`、Running でなければ `FAILED_PRECONDITION`、
    /// 読めなければ `UNAVAILABLE`（RPC 時の検証と接続時の間のレースをここで再確認する）。ブロッキングしてよい。
    fn precheck(&self, id: &ContainerId) -> Result<(), CriError>;

    /// follow の継続判定に使う稼働状態（書き手がいなくなったときだけ呼ばれる）。
    fn activity(&self, id: &ContainerId) -> ContainerActivity;
}

/// 本番の probe。`StateStore` の記録を読む（CLI の `logs --follow` と同じ写像。CLI-1・SUP-7）。
pub struct StateStoreAttachProbe {
    store: Arc<dyn StateStore>,
}

impl StateStoreAttachProbe {
    /// 状態ストアから作る。
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }
}

impl AttachProbe for StateStoreAttachProbe {
    fn precheck(&self, id: &ContainerId) -> Result<(), CriError> {
        match self.store.get(&GetStateRequest::new(id.clone())) {
            Ok(rec) if rec.status().state() == ContainerState::Running => Ok(()),
            Ok(_) => Err(CriError::failed_precondition("container is not running")),
            Err(e) if e.code() == ErrorCode::NotFound => {
                Err(CriError::not_found("container not found"))
            }
            Err(_) => Err(CriError::unavailable("container state is unavailable")),
        }
    }

    fn activity(&self, id: &ContainerId) -> ContainerActivity {
        match self.store.get(&GetStateRequest::new(id.clone())) {
            Ok(rec) if rec.status().state() == ContainerState::Running => {
                ContainerActivity::Running
            }
            Ok(_) => ContainerActivity::NotRunning,
            Err(e) if e.code() == ErrorCode::NotFound => ContainerActivity::NotRunning,
            Err(_) => ContainerActivity::Unknown,
        }
    }
}

/// 読み取り専用の `AttachBackend`。
pub struct LogFollowAttachBackend {
    log_dir: PathBuf,
    probe: Arc<dyn AttachProbe>,
    follow: FollowOptions,
    active: Arc<AtomicUsize>,
}

impl LogFollowAttachBackend {
    /// ログのディレクトリ（`container_log_dir(state_root)`）と probe から作る。期限は上限の 24 時間、間隔は 200 ms。
    pub fn new(log_dir: PathBuf, probe: Arc<dyn AttachProbe>) -> Result<Self, CriError> {
        let follow = FollowOptions::new(MAX_FOLLOW_DURATION)
            .map_err(|_| CriError::internal("attach follow options are invalid"))?;
        Ok(Self {
            log_dir,
            probe,
            follow,
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// 期限・間隔を差し替える（試験用）。
    pub fn with_follow_options(mut self, follow: FollowOptions) -> Self {
        self.follow = follow;
        self
    }

    /// 走っている follow スレッドの数（観測・試験用）。
    pub fn active_followers(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// 稼働中の follow スレッドの数を戻すガード。
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 最後の持ち主が drop されたら取り消しの旗を立てる。
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// follow スレッドが書く側。書き込みが詰まっても 200 ms ごとに取り消しの旗と追従の絶対期限を見る。
struct CancellableWriter {
    sock: StdUnixStream,
    cancel: Arc<AtomicBool>,
    /// 追従の絶対期限。書き込みの再試行・進捗のたびに見る（クライアントが少量ずつ読み続けても越えて保持させない。REPAIR-5）。
    deadline: Instant,
}

impl Write for CancellableWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            match self.sock.write(buf) {
                Ok(n) => return Ok(n),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    if self.cancel.load(Ordering::SeqCst) {
                        return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// セッションへ渡す読み口。EOF の時点で follow が失敗していれば `io::Error` にする（成功を装わない）。
struct FollowReader {
    inner: tokio::net::UnixStream,
    failed: Arc<AtomicBool>,
    _cancel: Arc<CancelOnDrop>,
}

impl AsyncRead for FollowReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if buf.filled().len() == before && self.failed.load(Ordering::SeqCst) =>
            {
                Poll::Ready(Err(io::Error::other("container log follow failed")))
            }
            other => other,
        }
    }
}

fn pair() -> io::Result<(StdUnixStream, tokio::net::UnixStream)> {
    let (a, b) = StdUnixStream::pair()?;
    b.set_nonblocking(true)?;
    a.set_write_timeout(Some(WRITE_TICK))?;
    Ok((a, tokio::net::UnixStream::from_std(b)?))
}

impl AttachBackend for LogFollowAttachBackend {
    fn attach(
        &self,
        target: AttachTarget,
    ) -> Pin<Box<dyn Future<Output = Result<AttachSession, CriError>> + Send + 'static>> {
        let log_dir = self.log_dir.clone();
        let probe = Arc::clone(&self.probe);
        let follow = self.follow;
        let active = Arc::clone(&self.active);
        Box::pin(async move {
            if target.stdin || target.tty {
                return Err(CriError::invalid_argument(
                    MSG_ATTACH_INTERACTIVE_UNSUPPORTED,
                ));
            }
            if !target.stdout && !target.stderr {
                return Err(CriError::invalid_argument(
                    "attach requires stdout or stderr",
                ));
            }
            let id = ContainerId::new(target.container_id)
                .map_err(|_| CriError::invalid_argument("container id is invalid"))?;
            let p = Arc::clone(&probe);
            let id2 = id.clone();
            tokio::task::spawn_blocking(move || p.precheck(&id2))
                .await
                .map_err(|_| CriError::internal("attach precheck failed"))??;

            // 同時数の枠を先に確保する（超えたら何も作らない）。
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_ATTACH_FOLLOWERS {
                active.fetch_sub(1, Ordering::SeqCst);
                return Err(CriError::resource_exhausted("too many attach sessions"));
            }
            let guard = ActiveGuard(Arc::clone(&active));

            let cancel = Arc::new(AtomicBool::new(false));
            let failed = Arc::new(AtomicBool::new(false));
            let cancel_guard = Arc::new(CancelOnDrop(Arc::clone(&cancel)));
            let io_err = |_| CriError::internal("attach stream setup failed");
            let (out_w, out_r) = if target.stdout {
                let (w, r) = pair().map_err(io_err)?;
                (Some(w), Some(r))
            } else {
                (None, None)
            };
            let (err_w, err_r) = if target.stderr {
                let (w, r) = pair().map_err(io_err)?;
                (Some(w), Some(r))
            } else {
                (None, None)
            };
            let (exit_w, exit_r) = pair().map_err(io_err)?;

            let thread_cancel = Arc::clone(&cancel);
            let abs_deadline = Instant::now() + follow.deadline();
            let (ready_tx, ready_rx) = mpsc::channel::<()>();
            let thread_failed = Arc::clone(&failed);
            let thread_id = id.clone();
            std::thread::Builder::new()
                .name("attach-log-follow".to_string())
                .spawn(move || {
                    follow_thread(FollowJob {
                        log_dir,
                        id: thread_id,
                        probe,
                        follow,
                        out: out_w.map(|sock| CancellableWriter {
                            sock,
                            cancel: Arc::clone(&thread_cancel),
                            deadline: abs_deadline,
                        }),
                        err: err_w.map(|sock| CancellableWriter {
                            sock,
                            cancel: Arc::clone(&thread_cancel),
                            deadline: abs_deadline,
                        }),
                        exit: exit_w,
                        cancel: thread_cancel,
                        failed: thread_failed,
                        ready: ready_tx,
                        _guard: guard,
                    });
                })
                .map_err(|_| CriError::unavailable("failed to start the attach follower"))?;

            // 追従開始位置（tail 0 のスナップショット）が確定するまで返さない。返した後に書かれた行を
            // 「過去」として読み飛ばさないため。スレッドが先に終われば送り口が閉じて Err になる。
            let ready = tokio::task::spawn_blocking(move || ready_rx.recv_timeout(READY_WAIT))
                .await
                .map_err(|_| CriError::internal("attach follower setup failed"))?;
            if ready.is_err() {
                // 取り消しの旗を立てて follower を畳む（`cancel_guard` の drop でも立つが明示する）。
                cancel.store(true, Ordering::SeqCst);
                return Err(CriError::unavailable(
                    "attach follower did not become ready",
                ));
            }

            let reader = |r: tokio::net::UnixStream| -> Box<dyn AsyncRead + Send + Unpin> {
                Box::new(FollowReader {
                    inner: r,
                    failed: Arc::clone(&failed),
                    _cancel: Arc::clone(&cancel_guard),
                })
            };
            let exited_guard = Arc::clone(&cancel_guard);
            Ok(AttachSession {
                stdin: None,
                stdout: out_r.map(reader),
                stderr: err_r.map(reader),
                resize: None,
                exited: Box::pin(async move {
                    let _keep = exited_guard;
                    // 書き口が閉じる（スレッドの終了）まで読む。値は流れない。
                    let mut buf = [0u8; 8];
                    loop {
                        if exit_r.readable().await.is_err() {
                            break;
                        }
                        match exit_r.try_read(&mut buf) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(_) => break,
                        }
                    }
                }),
            })
        })
    }
}

struct FollowJob {
    log_dir: PathBuf,
    id: ContainerId,
    probe: Arc<dyn AttachProbe>,
    follow: FollowOptions,
    out: Option<CancellableWriter>,
    err: Option<CancellableWriter>,
    exit: StdUnixStream,
    cancel: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    /// 追従開始位置の確定を知らせる送り口（`attach` が受けるまでセッションを返さない）。
    ready: mpsc::Sender<()>,
    _guard: ActiveGuard,
}

/// follow スレッドの本体。どの終わり方でも、読み口の EOF → 終了通知の順に閉じる。
fn follow_thread(job: FollowJob) {
    let FollowJob {
        log_dir,
        id,
        probe,
        follow,
        mut out,
        mut err,
        exit,
        cancel,
        failed,
        ready,
        _guard,
    } = job;
    let result = match TailCount::new(0) {
        Ok(tail) => {
            let opts = LogReadOptions::default()
                .with_tail(tail)
                .with_follow(follow);
            let mut demux = RecordDemux::new(
                out.as_mut().map(|w| w as &mut dyn Write),
                err.as_mut().map(|w| w as &mut dyn Write),
            );
            let mut activity = || probe.activity(&id);
            // supervisor の追従ループは初回のスナップショットを確定して最初のポーリングを終えた後に `cancelled` を
            // 初めて呼ぶ。この最初の呼び出しを「開始位置の確定」の合図に使う（以降の行は取りこぼさない）。
            let cancelled = || {
                let _ = ready.send(());
                cancel.load(Ordering::SeqCst)
            };
            read_container_log_with_cancel(
                &log_dir,
                &id,
                container_log_rotation_config(),
                &opts,
                &mut demux,
                &mut activity,
                &cancelled,
            )
            .ok()
            .and_then(|r| r.follow_end())
        }
        Err(_) => None,
    };
    let ok = matches!(
        result,
        Some(FollowEnd::Stopped | FollowEnd::LogRemoved | FollowEnd::Cancelled)
    );
    if !ok && !cancel.load(Ordering::SeqCst) {
        failed.store(true, Ordering::SeqCst);
    }
    drop(out);
    drop(err);
    drop(exit);
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
