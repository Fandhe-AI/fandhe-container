//! 制御 UDS の Linux 実装: ヘルパー側のサーバーと、送り手（`Reload` の ack 待ち・`Stop` の要求）
//! （NET-5・PLUG-12・REPAIR-5・SEC-1・#3071）。契約は親モジュール `control` の doc を参照。
//!
//! `unsafe` は持たない（`SO_PEERCRED` と非ブロッキング connect は `sys` の薄いラッパー経由）。
//! bind と accept は標準ライブラリを使い、経路は検査済みのネットワークのディレクトリの fd 起点で組む。

use std::io::{self, Read, Write as _};
use std::net::Ipv4Addr;
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::frame::{ControlFrame, ControlMessage, ReadError, ReloadGeneration};
use super::{CONTROL_READ_TIMEOUT, DNS_RELOAD_ACK_TIMEOUT, ReloadOutcome, authorize_peer};
use crate::dns_helper::detach::{DnsHelperStopRequest, RequestOutcome};
use crate::dns_helper::load::{names_from_members, upstreams_from_members};
use crate::dns_helper::record::DnsHelperRecord;
use crate::dns_helper::upstream::DnsUpstreamMap;
use crate::dns_helper::{
    DnsHelperServer, DnsRegistry, MAX_CONSECUTIVE_RECV_ERRORS, MAX_REGISTRY_ENTRIES,
    RECV_POLL_INTERVAL, RegistryHandler,
};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, record_net_op};
use crate::network::NetworkName;
use crate::network_store::{NetworkDir, NetworkLockGuard, NetworkStore};
use crate::sys::{self, Deadline, Readiness, SysError, holder, unix_socket};

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

// ---------------------------------------------------------------------------
// 期限つきの読み取り
// ---------------------------------------------------------------------------

/// 絶対期限つきの読み取り口。呼び出しのたびに残り時間で read timeout を設定し直すため、1 バイトずつ
/// ゆっくり送って居座る相手でも、全体で `deadline` を超えて待たない（REPAIR-5）。
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        self.stream.set_read_timeout(Some(remaining))?;
        let mut s = self.stream;
        s.read(buf)
    }
}

fn map_read_error(e: ReadError) -> NetError {
    match e {
        ReadError::Invalid(e) => e,
        ReadError::Io(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            err(
                NetErrorCode::Timeout,
                "dns helper did not respond before the deadline",
            )
        }
        ReadError::Io(_) => err(
            NetErrorCode::FailedPrecondition,
            "dns helper closed the control connection",
        ),
    }
}

// ---------------------------------------------------------------------------
// ヘルパー側
// ---------------------------------------------------------------------------

/// 制御 UDS を bind する。既にあれば消さずに `AlreadyExists`（古い socket の削除は排他ロックを持つ側だけが行う）。
/// bind 後に 0600 へ直し、socket・所有者・0600 を検査し直す。
fn bind_control(dir: &NetworkDir) -> Result<UnixListener, NetError> {
    let listener = UnixListener::bind(dir.control_socket_path()).map_err(|e| {
        if e.kind() == io::ErrorKind::AddrInUse {
            err(
                NetErrorCode::AlreadyExists,
                "dns control socket already exists",
            )
        } else {
            err(NetErrorCode::Internal, "cannot bind dns control socket")
        }
    })?;
    dir.secure_control_socket()?;
    Ok(listener)
}

/// メンバー記録を読み直し、名前のレジストリと `--dns` の上流の割り当てを一括に差し替える（NET-5・NET-12・#3072）。
///
/// 両方を作り、件数の上限を先に検査してから差し替える。食い違い（`DataLoss` 等）や上限超過は、どちらも前の状態を
/// 保ったまま `Err`（片方だけが新しくなる半端な状態を作らない）。`gateway` はヘルパーの待ち受けアドレスで、
/// 上流に指定されたメンバーは飛ばす。件数だけを stderr に出す（名前・アドレスは出さない）。
fn load_into(
    dir: &NetworkDir,
    registry: &DnsRegistry,
    upstreams: &DnsUpstreamMap,
    gateway: Ipv4Addr,
) -> Result<(), NetError> {
    let members = dir.members()?;
    let names = names_from_members(&members);
    let ups = upstreams_from_members(&members, gateway);
    if names.entries.len() > MAX_REGISTRY_ENTRIES || ups.entries.len() > MAX_REGISTRY_ENTRIES {
        return Err(err(
            NetErrorCode::ResourceExhausted,
            "dns helper registry is full",
        ));
    }
    registry.replace_all(&names.entries)?;
    upstreams.replace_all(&ups.entries)?;
    let _ = writeln!(
        io::stderr(),
        "dns names loaded count={} skipped={} collisions={}",
        names.entries.len(),
        names.skipped_invalid,
        names.dropped_collisions
    );
    let _ = writeln!(
        io::stderr(),
        "dns upstreams loaded count={} skipped={} collisions={}",
        ups.entries.len(),
        ups.skipped_invalid,
        ups.dropped_collisions
    );
    Ok(())
}

/// 制御 UDS のサーバー（1 接続ずつ直列に処理する）。
pub(crate) struct ControlServer {
    listener: UnixListener,
    expected_uid: u32,
    /// 認証拒否の監査記録の置き場（本番はネットワークのディレクトリ。無ければ stderr のみ）。
    audit_dir: Option<Arc<NetworkDir>>,
}

impl ControlServer {
    /// `expected_uid` は接続を許す相手の uid（本番はヘルパーの実効 uid。試験で別の値を注入する）。
    pub(crate) fn new(listener: UnixListener, expected_uid: u32) -> Result<Self, NetError> {
        listener.set_nonblocking(true).map_err(|_| {
            err(
                NetErrorCode::Internal,
                "cannot configure dns control socket",
            )
        })?;
        Ok(Self {
            listener,
            expected_uid,
            audit_dir: None,
        })
    }

    /// 認証拒否を `dns.audit` へも残す（SEC-4。detach 起動では stderr が捨てられるため）。
    pub(crate) fn with_audit_dir(mut self, dir: Arc<NetworkDir>) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    /// `stop` が立つまで接続を受ける。`Reload` では `on_reload` を呼んで `Loaded` / `Error` を返し、`Stop` では
    /// `stop` を立てて戻る。停止確認は [`RECV_POLL_INTERVAL`] ごと（REPAIR-5）。accept の失敗が続けば `Err`。
    pub(crate) fn run(
        &self,
        stop: &AtomicBool,
        on_reload: &(dyn Fn() -> Result<(), NetError> + Sync),
    ) -> Result<(), NetError> {
        let mut consecutive_errors: u32 = 0;
        while !stop.load(Ordering::Relaxed) {
            match sys::wait_readable(self.listener.as_fd(), &Deadline::after(RECV_POLL_INTERVAL)) {
                Ok(Readiness::TimedOut) => continue,
                Ok(Readiness::Readable) => {}
                Ok(Readiness::Exceptional) | Err(_) => {
                    return Err(err(
                        NetErrorCode::Internal,
                        "cannot poll dns control socket",
                    ));
                }
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    consecutive_errors = 0;
                    self.handle(&stream, stop, on_reload);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                    ) => {}
                Err(_) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    if consecutive_errors > MAX_CONSECUTIVE_RECV_ERRORS {
                        return Err(err(
                            NetErrorCode::Internal,
                            "dns control socket accept keeps failing",
                        ));
                    }
                    // fd 枯渇などで即座に失敗し続けても CPU を使い切らない。
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
        Ok(())
    }

    fn handle(
        &self,
        stream: &UnixStream,
        stop: &AtomicBool,
        on_reload: &(dyn Fn() -> Result<(), NetError> + Sync),
    ) {
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        // 相手の uid を、フレームを読む前に照合する（違えば何も読まず・書かずに切断する。PLUG-12）。
        let uid = match holder::peer_cred(stream.as_fd()) {
            Ok((_, uid)) => uid,
            Err(_) => return,
        };
        if authorize_peer(uid, self.expected_uid).is_err() {
            let _ = writeln!(io::stderr(), "dns control peer_uid_mismatch");
            if let Some(dir) = &self.audit_dir {
                let _ = dir.append_control_audit(&format!(
                    "event=dns_control_peer_uid_mismatch peer_uid={uid} expected_uid={}",
                    self.expected_uid
                ));
            }
            return;
        }
        let mut reader = DeadlineReader {
            stream,
            deadline: Instant::now() + CONTROL_READ_TIMEOUT,
        };
        let Ok(msg) = ControlFrame::read_from(&mut reader) else {
            return;
        };
        match msg {
            ControlMessage::Reload(g) => {
                let reply = match on_reload() {
                    Ok(()) => ControlMessage::Loaded(g),
                    Err(e) => ControlMessage::Error(e.code()),
                };
                let _ = stream.set_write_timeout(Some(CONTROL_READ_TIMEOUT));
                let mut w = stream;
                let _ = ControlFrame::encode(reply).write_to(&mut w);
            }
            ControlMessage::Stop => stop.store(true, Ordering::Relaxed),
            // ヘルパー宛てに来るはずのない向きのメッセージ。応答せず切断する。
            _ => {}
        }
    }
}

/// ヘルパー側（段 2）の準備済みの制御部。`READY` の前に [`prepare_helper_control`] で作り、`READY` の後に
/// [`serve`](Self::serve) で UDP の待受と並行して動かす。
pub(crate) struct HelperControl {
    dir: Arc<NetworkDir>,
    registry: Arc<DnsRegistry>,
    /// 記録の `--dns` から組んだ上流の割り当て。製品の待受は転送しないため参照側は無い（下の `serve` を参照）。
    upstreams: Arc<DnsUpstreamMap>,
    /// ヘルパーの待ち受けアドレスの IPv4（= ネットワークの gateway。上流に指定されたメンバーを飛ばす基準）。
    gateway: Ipv4Addr,
    control: ControlServer,
}

/// ストアを開き直し（ロックなし）、制御 UDS を bind し、メンバー記録から最初のレジストリを組む。
///
/// どれかが失敗したらヘルパーは起動しない（`READY` を出さない。fail-closed）。`state_root` は絶対パスに限る。
pub(crate) fn prepare_helper_control(
    state_root: &Path,
    network: &NetworkName,
    gateway: Ipv4Addr,
) -> Result<HelperControl, NetError> {
    if !state_root.is_absolute() {
        return Err(err(
            NetErrorCode::InvalidArgument,
            "state root must be an absolute path",
        ));
    }
    let store = NetworkStore::open(state_root)?;
    let dir = store.open_network_dir(network)?;
    let listener = bind_control(&dir)?;
    let registry = Arc::new(DnsRegistry::new());
    let upstreams = Arc::new(DnsUpstreamMap::new());
    load_into(&dir, &registry, &upstreams, gateway)?;
    let dir = Arc::new(dir);
    let control =
        ControlServer::new(listener, sys::effective_uid())?.with_audit_dir(Arc::clone(&dir));
    Ok(HelperControl {
        dir,
        registry,
        upstreams,
        gateway,
        control,
    })
}

impl HelperControl {
    /// UDP の待受（`server`）と制御 UDS を並行して動かす。どちらかが終わったら（`Stop`・エラー）もう一方も止める。
    pub(crate) fn serve(self, server: &mut DnsHelperServer) -> Result<(), NetError> {
        let stop = AtomicBool::new(false);
        // 上流の割り当ては組むが、ここでは `ForwardingHandler` に切り替えない。転送には `SourceVerified`
        // （bridge 側の送信元詐称防止の証明。製品での作り方は未実装）が要り、無いまま有効にすると他コンテナの
        // 上流を詐称で使えてしまう（fail-open）。切り替えは証明の実装後（NET-12・REPAIR-3）。
        let handler = RegistryHandler::new(Arc::clone(&self.registry));
        let dir = Arc::clone(&self.dir);
        let registry = Arc::clone(&self.registry);
        let upstreams = Arc::clone(&self.upstreams);
        let gateway = self.gateway;
        let reload = move || load_into(&dir, &registry, &upstreams, gateway);
        thread::scope(|scope| {
            // スレッド生成の失敗は panic でなく構造化エラーで返す（READY の後でも NetError で終われる）。
            let control = thread::Builder::new()
                .name("dns-control".into())
                .spawn_scoped(scope, || {
                    let r = self.control.run(&stop, &reload);
                    stop.store(true, Ordering::Relaxed);
                    r
                })
                .map_err(|_| err(NetErrorCode::Internal, "cannot spawn dns control thread"))?;
            let served = server.serve(&handler, &stop);
            stop.store(true, Ordering::Relaxed);
            let controlled = control.join().unwrap_or_else(|_| {
                Err(err(NetErrorCode::Internal, "dns control thread panicked"))
            });
            served.and(controlled)
        })
    }
}

// ---------------------------------------------------------------------------
// 送り手側
// ---------------------------------------------------------------------------

fn map_connect_error(e: SysError) -> NetError {
    match e {
        SysError::Os(c) if c == sys::EAGAIN => err(
            NetErrorCode::Timeout,
            "dns control socket is busy (listen backlog is full)",
        ),
        SysError::Os(c) if c == sys::EACCES || c == sys::EPERM => err(
            NetErrorCode::PermissionDenied,
            "cannot connect to dns control socket",
        ),
        SysError::Unsupported => err(
            NetErrorCode::Unimplemented,
            "dns control socket is not supported on this architecture",
        ),
        // listener が居ない（ECONNREFUSED）・ソケットが消えた（ENOENT）等。
        _ => err(
            NetErrorCode::FailedPrecondition,
            "dns helper is not listening on its control socket",
        ),
    }
}

/// 制御 UDS へ接続して相手を検査する（connect の前に lstat、後に peer の uid と pid を照合）。
/// `expected_pid` は `dns-helper` の記録の pid。
fn connect_checked(
    guard: &NetworkLockGuard<'_>,
    expected_pid: u32,
) -> Result<UnixStream, NetError> {
    guard.check_control_socket().map_err(|e| {
        if e.code() == NetErrorCode::NotFound {
            err(
                NetErrorCode::FailedPrecondition,
                "dns control socket is missing",
            )
        } else {
            e
        }
    })?;
    let fd = unix_socket::connect_unix_nonblocking(&guard.control_socket_path())
        .map_err(map_connect_error)?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(|_| {
        err(
            NetErrorCode::Internal,
            "cannot configure dns control connection",
        )
    })?;
    let (pid, uid) = holder::peer_cred(stream.as_fd()).map_err(|_| {
        err(
            NetErrorCode::Internal,
            "cannot read dns control peer credentials",
        )
    })?;
    authorize_peer(uid, sys::effective_uid())?;
    if pid != expected_pid {
        return Err(err(
            NetErrorCode::PermissionDenied,
            "dns control peer is not the recorded helper",
        ));
    }
    Ok(stream)
}

/// 接続済みの `stream` へ `Reload{generation}` を送り、`Loaded{generation}` を `budget` まで待つ。
fn reload_over(
    stream: &UnixStream,
    generation: ReloadGeneration,
    budget: Duration,
) -> Result<(), NetError> {
    let deadline = Instant::now() + budget;
    stream.set_write_timeout(Some(budget)).map_err(|_| {
        err(
            NetErrorCode::Internal,
            "cannot configure dns control connection",
        )
    })?;
    let mut w = stream;
    ControlFrame::encode(ControlMessage::Reload(generation))
        .write_to(&mut w)
        .map_err(|e| {
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                err(
                    NetErrorCode::Timeout,
                    "dns helper did not accept the reload request before the deadline",
                )
            } else {
                err(
                    NetErrorCode::FailedPrecondition,
                    "dns helper closed the control connection",
                )
            }
        })?;
    let mut reader = DeadlineReader { stream, deadline };
    match ControlFrame::read_from(&mut reader).map_err(map_read_error)? {
        ControlMessage::Loaded(g) if g == generation => Ok(()),
        ControlMessage::Loaded(_) => Err(err(
            NetErrorCode::FailedPrecondition,
            "dns helper acknowledged a different reload generation",
        )),
        ControlMessage::Error(code) => Err(NetError::new(code, "dns helper failed to load names")),
        _ => Err(err(
            NetErrorCode::FailedPrecondition,
            "dns helper sent an unexpected control message",
        )),
    }
}

/// 起動済みの DNS ヘルパーに名前の再読込を要求し、`Loaded` の ack を [`DNS_RELOAD_ACK_TIMEOUT`]（2 秒）まで待つ。
///
/// ネットワークの排他ロックを持って呼ぶ（メンバー記録を書いた側が、書いた直後に呼ぶ。ヘルパーはロックを取らずに
/// 読む）。`dns-helper` の記録が無ければ [`ReloadOutcome::NotRunning`]。ack が来ない・世代が違う・ヘルパーが
/// `Error` を返した・接続先が記録のヘルパーでない場合は `Err`（呼び出し側は attach を失敗にする。D11・D15）。
/// 排他ロックでなければ副作用の前に `FailedPrecondition`。
pub fn reload_dns_helper(
    guard: &NetworkLockGuard<'_>,
    recorder: &dyn NetOpRecorder,
) -> Result<ReloadOutcome, NetError> {
    record_net_op(recorder, NetOpKind::DnsHelperReload, || reload_inner(guard))
}

fn reload_inner(guard: &NetworkLockGuard<'_>) -> Result<ReloadOutcome, NetError> {
    guard.require_exclusive()?;
    let Some(record) = guard.read_dns_helper()? else {
        return Ok(ReloadOutcome::NotRunning);
    };
    let started = Instant::now();
    let generation = ReloadGeneration::random()?;
    let stream = connect_checked(guard, record.identity().pid)?;
    let budget = DNS_RELOAD_ACK_TIMEOUT
        .checked_sub(started.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            err(
                NetErrorCode::Timeout,
                "dns helper did not respond before the deadline",
            )
        })?;
    reload_over(&stream, generation, budget)?;
    Ok(ReloadOutcome::Loaded)
}

/// `stop_recorded_dns_helper` に渡す停止要求の送り手（制御 UDS の `Stop`）。ネットワークの排他ロックの
/// ガードを借りる（`stop_recorded_dns_helper` に渡すのと同じガード）。
///
/// 要求を書けたら [`RequestOutcome::Sent`]（呼び出し側が猶予の間ヘルパーの自発的な終了を待つ）。socket の検査・接続・
/// 相手の照合・書き込みのどれかに失敗したら [`RequestOutcome::Unavailable`]（猶予を飛ばして pidfd 経由の
/// SIGKILL へ進む。従来の挙動）。
#[derive(Debug)]
pub struct ControlStopRequest<'a, 'g> {
    guard: &'a NetworkLockGuard<'g>,
}

impl<'a, 'g> ControlStopRequest<'a, 'g> {
    /// 排他ロックのガードを借りて作る。
    pub fn new(guard: &'a NetworkLockGuard<'g>) -> Self {
        Self { guard }
    }

    fn send(&self, record: &DnsHelperRecord) -> Result<(), NetError> {
        let stream = connect_checked(self.guard, record.identity().pid)?;
        stream
            .set_write_timeout(Some(DNS_RELOAD_ACK_TIMEOUT))
            .map_err(|_| {
                err(
                    NetErrorCode::Internal,
                    "cannot configure dns control connection",
                )
            })?;
        let mut w = &stream;
        ControlFrame::encode(ControlMessage::Stop)
            .write_to(&mut w)
            .map_err(|_| {
                err(
                    NetErrorCode::FailedPrecondition,
                    "cannot send the stop request",
                )
            })
    }
}

impl DnsHelperStopRequest for ControlStopRequest<'_, '_> {
    fn request(&self, record: &DnsHelperRecord) -> RequestOutcome {
        match self.send(record) {
            Ok(()) => RequestOutcome::Sent,
            Err(_) => RequestOutcome::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    struct Sock(PathBuf);

    impl Sock {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fcdns-ctl-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_file(&p);
            Self(p)
        }
    }

    impl Drop for Sock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn connect(p: &Path) -> UnixStream {
        let fd = unix_socket::connect_unix_nonblocking(p).expect("connect");
        let s = UnixStream::from(fd);
        s.set_nonblocking(false).expect("blocking");
        s
    }

    fn gen_(v: u64) -> ReloadGeneration {
        ReloadGeneration::new(v).expect("generation")
    }

    /// 試験用の待ちの上限（REPAIR-5）。これを超える停止は回帰として panic にする。
    const TEST_WAIT: Duration = Duration::from_secs(10);

    /// `h` の終了を `TEST_WAIT` まで待って回収する。無期限の `join` でハングさせない（REPAIR-5）。
    fn join_within<T>(h: thread::JoinHandle<T>) -> T {
        let t = Instant::now();
        while !h.is_finished() {
            assert!(t.elapsed() < TEST_WAIT, "thread did not finish in time");
            thread::sleep(Duration::from_millis(5));
        }
        h.join().expect("join")
    }

    /// accept して 1 フレーム読み、`reply` を返す（None なら何も返さず保持するだけ）の 1 回限りのサーバー。
    /// accept・受信・送信は有限の期限つき（REPAIR-5）。
    fn one_shot(
        listener: UnixListener,
        reply: Option<ControlMessage>,
        hold: Duration,
    ) -> thread::JoinHandle<()> {
        listener.set_nonblocking(true).expect("nonblocking");
        thread::spawn(move || {
            let t = Instant::now();
            let mut s = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if t.elapsed() >= Duration::from_secs(5) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            };
            let _ = s.set_nonblocking(false);
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
            let _ = ControlFrame::read_from(&mut s);
            if let Some(r) = reply {
                let _ = ControlFrame::encode(r).write_to(&mut s);
            }
            thread::sleep(hold);
        })
    }

    /// D15・REPAIR-5・NET-5・#3071: 応答しない相手には、実際の定数の期限（2 秒）で Timeout になる。
    #[test]
    fn net5_3071_reload_times_out_after_two_seconds() {
        let sock = Sock::new("timeout");
        let l = UnixListener::bind(&sock.0).expect("bind");
        let h = one_shot(l, None, Duration::from_millis(3300));
        let s = connect(&sock.0);
        assert_eq!(DNS_RELOAD_ACK_TIMEOUT, Duration::from_secs(2));
        let t = Instant::now();
        let e = reload_over(&s, gen_(1), DNS_RELOAD_ACK_TIMEOUT).expect_err("timeout");
        let el = t.elapsed();
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert!(
            el >= Duration::from_secs(2) && el < Duration::from_secs(3),
            "elapsed {el:?}"
        );
        join_within(h);
    }

    /// NET-5・REPAIR-2・#3071: 世代が食い違う `Loaded` は FailedPrecondition。
    #[test]
    fn net5_3071_reload_rejects_generation_mismatch() {
        let sock = Sock::new("mismatch");
        let l = UnixListener::bind(&sock.0).expect("bind");
        let h = one_shot(l, Some(ControlMessage::Loaded(gen_(2))), Duration::ZERO);
        let s = connect(&sock.0);
        let e = reload_over(&s, gen_(1), Duration::from_secs(2)).expect_err("mismatch");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        join_within(h);
    }

    /// NET-5・#3071: ヘルパーの `Error{DataLoss}` はそのコードで返る。同じ世代の `Loaded` は成功。
    #[test]
    fn net5_3071_reload_maps_error_and_success() {
        let sock = Sock::new("error");
        let l = UnixListener::bind(&sock.0).expect("bind");
        let h = one_shot(
            l,
            Some(ControlMessage::Error(NetErrorCode::DataLoss)),
            Duration::ZERO,
        );
        let s = connect(&sock.0);
        let e = reload_over(&s, gen_(1), Duration::from_secs(2)).expect_err("error");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        join_within(h);

        let sock = Sock::new("loaded9");
        let l = UnixListener::bind(&sock.0).expect("bind");
        let h = one_shot(l, Some(ControlMessage::Loaded(gen_(9))), Duration::ZERO);
        let s = connect(&sock.0);
        reload_over(&s, gen_(9), Duration::from_secs(2)).expect("loaded");
        join_within(h);
    }

    /// NET-5・#3071: 相手が何も返さず閉じた（EOF）なら FailedPrecondition（時間切れを待たない）。
    #[test]
    fn net5_3071_reload_eof_is_failed_precondition() {
        let sock = Sock::new("eof");
        let l = UnixListener::bind(&sock.0).expect("bind");
        let h = one_shot(l, None, Duration::ZERO);
        let s = connect(&sock.0);
        let t = Instant::now();
        let e = reload_over(&s, gen_(1), Duration::from_secs(2)).expect_err("eof");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(t.elapsed() < Duration::from_secs(1));
        join_within(h);
    }

    struct Served {
        stop: Arc<AtomicBool>,
        reloads: Arc<AtomicUsize>,
        join: thread::JoinHandle<Result<(), NetError>>,
        _sock: Sock,
        path: PathBuf,
    }

    fn serve(tag: &str, expected_uid: u32, reload_result: NetErrorCode) -> Served {
        let sock = Sock::new(tag);
        let path = sock.0.clone();
        let listener = UnixListener::bind(&path).expect("bind");
        let server = ControlServer::new(listener, expected_uid).expect("server");
        let stop = Arc::new(AtomicBool::new(false));
        let reloads = Arc::new(AtomicUsize::new(0));
        let (s2, r2) = (Arc::clone(&stop), Arc::clone(&reloads));
        let join = thread::spawn(move || {
            let on_reload = move || {
                r2.fetch_add(1, Ordering::SeqCst);
                if reload_result == NetErrorCode::Internal {
                    Ok(())
                } else {
                    Err(NetError::new(reload_result, "test"))
                }
            };
            server.run(&s2, &on_reload)
        });
        Served {
            stop,
            reloads,
            join,
            _sock: sock,
            path,
        }
    }

    /// 読み取りの結果が切断（EOF 以外では接続リセット・破損パイプ）か。`WouldBlock`・`TimedOut` は含めない。
    fn is_disconnect(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
        )
    }

    /// PLUG-12・NET-5・#3071: 別 uid の接続は、フレームを読まずに切断される（`Loaded` も `Error` も返らず、
    /// 再読込は走らない）。
    #[test]
    fn plug12_3071_wrong_uid_is_dropped_without_reading() {
        let me = sys::effective_uid();
        let s = serve("uid", me.wrapping_add(1), NetErrorCode::Internal);
        let c = connect(&s.path);
        let mut w = &c;
        ControlFrame::encode(ControlMessage::Reload(gen_(1)))
            .write_to(&mut w)
            .expect("write");
        c.set_read_timeout(Some(Duration::from_secs(2))).expect("t");
        let mut buf = [0u8; 1];
        let mut r = &c;
        // 読み取りは EOF（0 バイト）か ECONNRESET。いずれにせよフレームは返らない。
        match r.read(&mut buf) {
            Ok(0) => {}
            Err(e) if is_disconnect(&e) => {}
            Ok(n) => panic!("unexpected {n} bytes"),
            Err(e) => panic!("read was not a disconnect: {e:?}"),
        }
        assert_eq!(s.reloads.load(Ordering::SeqCst), 0);
        s.stop.store(true, Ordering::SeqCst);
        join_within(s.join).expect("run");
    }

    /// NET-5・#3071: 正しい uid の `Reload` は `Loaded` を同じ世代で返し、失敗は `Error` で返す。`Stop` で止まる。
    #[test]
    fn net5_3071_server_reload_loaded_error_and_stop() {
        let me = sys::effective_uid();
        let s = serve("serve-ok", me, NetErrorCode::Internal);
        let c = connect(&s.path);
        reload_over(&c, gen_(77), Duration::from_secs(2)).expect("loaded");
        assert_eq!(s.reloads.load(Ordering::SeqCst), 1);
        // Stop。
        let c = connect(&s.path);
        let mut w = &c;
        ControlFrame::encode(ControlMessage::Stop)
            .write_to(&mut w)
            .expect("stop");
        let t = Instant::now();
        join_within(s.join).expect("run");
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(s.stop.load(Ordering::SeqCst));

        let s = serve("err", me, NetErrorCode::DataLoss);
        let c = connect(&s.path);
        let e = reload_over(&c, gen_(5), Duration::from_secs(2)).expect_err("error");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        s.stop.store(true, Ordering::SeqCst);
        join_within(s.join).expect("run");
    }

    /// NET-5・REPAIR-2・#3071: 壊れたフレーム・上限超過の長さの接続は読まれず切られ、次の接続は処理される。
    #[test]
    fn net5_3071_server_survives_garbage_frames() {
        let me = sys::effective_uid();
        let s = serve("garbage", me, NetErrorCode::Internal);
        for junk in [vec![0xffu8; 40], {
            let mut h = ControlFrame::encode(ControlMessage::Stop)
                .as_bytes()
                .to_vec();
            h[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
            h
        }] {
            let c = connect(&s.path);
            let mut w = &c;
            w.write_all(&junk).expect("junk");
            c.set_read_timeout(Some(Duration::from_secs(2))).expect("t");
            let mut buf = [0u8; 1];
            let mut r = &c;
            match r.read(&mut buf) {
                Ok(0) => {}
                Err(e) if is_disconnect(&e) => {}
                other => panic!("expected a disconnect: {other:?}"),
            }
        }
        let c = connect(&s.path);
        reload_over(&c, gen_(3), Duration::from_secs(2)).expect("still serving");
        assert_eq!(s.reloads.load(Ordering::SeqCst), 1);
        s.stop.store(true, Ordering::SeqCst);
        join_within(s.join).expect("run");
    }

    /// REPAIR-5・#3071: 1 バイトずつ送って居座る相手でも、1 接続は絶対期限（2 秒）で切られ、次の接続が処理される。
    #[test]
    fn net5_3071_slow_client_is_cut_at_the_absolute_deadline() {
        let me = sys::effective_uid();
        let s = serve("slow", me, NetErrorCode::Internal);
        let slow = connect(&s.path);
        let t = Instant::now();
        let mut w = &slow;
        // ヘッダーの先頭 1 バイトだけ送り、あとは黙る。
        w.write_all(b"F").expect("one byte");
        let c = connect(&s.path);
        reload_over(&c, gen_(4), Duration::from_secs(5)).expect("served after the slow one");
        let el = t.elapsed();
        assert!(
            el >= Duration::from_millis(1500) && el < Duration::from_secs(4),
            "elapsed {el:?}"
        );
        drop(slow);
        s.stop.store(true, Ordering::SeqCst);
        join_within(s.join).expect("run");
    }

    // ---- 記録からの名前と上流の組み直し（NET-12・NET-5・#3072） ----

    use crate::dns_helper::DnsName;
    use crate::netlink_route::IpPrefix;
    use crate::network::EndpointId;
    use crate::network_store::{MemberId, MemberRecord, NetworkDefinition};
    use std::net::IpAddr;
    use std::os::unix::fs::DirBuilderExt as _;

    const GW: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 1);

    struct Root(PathBuf);

    impl Root {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fcdns-ld-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&p)
                .expect("root");
            Self(p)
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn prefix(last: u8, len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, last)), len).expect("prefix")
    }

    fn commit(store: &NetworkStore, net: &NetworkName, id: &str, last: u8, dns: &[IpAddr]) {
        let g = store.lock_global_exclusive().expect("global");
        let n = g.lock_network(net).expect("network");
        let token = format!("fandhe-net:web:1:0:0/ep/{id}/g/00000000000000000000000000000001");
        let rec = MemberRecord::new(
            MemberId::new(id).expect("id"),
            EndpointId::new(id).expect("ep"),
            prefix(last, 24),
            &token,
            Path::new("/run/ns"),
            (8, 9),
            dns,
        )
        .expect("member");
        n.commit_member(&rec).expect("commit");
    }

    /// 状態ルート配下の `members/` にある記録ファイルを不正な内容に書き換える。
    fn corrupt_member_files(dir: &Path) {
        for e in std::fs::read_dir(dir).expect("read_dir") {
            let path = e.expect("entry").path();
            if path.is_dir() {
                corrupt_member_files(&path);
            } else if path.parent().and_then(Path::file_name) == Some("members".as_ref()) {
                std::fs::write(&path, b"garbage").expect("corrupt");
            }
        }
    }

    fn upstream_strings(m: &DnsUpstreamMap, a: Ipv4Addr) -> Option<Vec<String>> {
        m.lookup(a)
            .map(|l| l.iter().map(|x| x.to_string()).collect())
    }

    /// NET-5・#3531: 記録の `dns-name`（コンテナ名）でも、メンバー ID と同じアドレスが引ける。
    #[test]
    fn net5_3531_load_into_resolves_container_name() {
        let root = Root::new("cname");
        let store = NetworkStore::open(&root.0).expect("store");
        store
            .create(&NetworkDefinition::bridge("web", prefix(0, 24)).expect("def"))
            .expect("create");
        let net = NetworkName::new("web").expect("name");
        {
            let g = store.lock_global_exclusive().expect("global");
            let n = g.lock_network(&net).expect("network");
            let token = "fandhe-net:web:1:0:0/ep/c1/g/00000000000000000000000000000001";
            let rec = MemberRecord::new(
                MemberId::new("c1").expect("id"),
                EndpointId::new("c1").expect("ep"),
                prefix(2, 24),
                token,
                Path::new("/run/ns"),
                (8, 9),
                &[],
            )
            .expect("member")
            .with_dns_name(crate::dns_helper::DnsName::new("web").expect("name"));
            n.commit_member(&rec).expect("commit");
        }
        let dir = store.open_network_dir(&net).expect("dir");
        let reg = DnsRegistry::new();
        let ups = DnsUpstreamMap::new();
        load_into(&dir, &reg, &ups, GW).expect("load");
        let a = Ipv4Addr::new(10, 89, 0, 2);
        assert_eq!(reg.lookup("web"), Some(a));
        assert_eq!(reg.lookup("c1"), Some(a));
    }

    /// NET-12・NET-5・#3072: 記録の `--dns` がコンテナのアドレスごとの上流として組まれ、名前も同時に登録される。
    /// 次の読み込みで記録が増えれば反映される（具体値）。
    #[test]
    fn net12_3072_load_into_builds_upstreams_from_records() {
        let root = Root::new("build");
        let store = NetworkStore::open(&root.0).expect("store");
        store
            .create(&NetworkDefinition::bridge("web", prefix(0, 24)).expect("def"))
            .expect("create");
        let net = NetworkName::new("web").expect("name");
        commit(
            &store,
            &net,
            "web1",
            2,
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
        );
        let dir = store.open_network_dir(&net).expect("dir");
        let reg = DnsRegistry::new();
        let ups = DnsUpstreamMap::new();
        load_into(&dir, &reg, &ups, GW).expect("load");
        let a = Ipv4Addr::new(10, 89, 0, 2);
        assert_eq!(
            upstream_strings(&ups, a),
            Some(vec!["192.0.2.53:53".to_owned()])
        );
        assert_eq!(reg.lookup("web1"), Some(a));
        commit(
            &store,
            &net,
            "db1",
            3,
            &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))],
        );
        load_into(&dir, &reg, &ups, GW).expect("reload");
        assert_eq!(ups.len(), 2);
        assert_eq!(
            upstream_strings(&ups, Ipv4Addr::new(10, 89, 0, 3)),
            Some(vec!["198.51.100.7:53".to_owned()])
        );
    }

    /// NET-12・REPAIR-3・#3072: 記録ファイルの破損（DataLoss）で読み込みが失敗したとき、名前も上流も前の状態を保つ（半端に更新しない）。
    #[test]
    fn net12_3072_load_failure_keeps_previous_state() {
        let root = Root::new("keep");
        let store = NetworkStore::open(&root.0).expect("store");
        store
            .create(&NetworkDefinition::bridge("web", prefix(0, 24)).expect("def"))
            .expect("create");
        let net = NetworkName::new("web").expect("name");
        let dir = store.open_network_dir(&net).expect("dir");
        let reg = DnsRegistry::new();
        let ups = DnsUpstreamMap::new();
        let a = Ipv4Addr::new(10, 89, 0, 9);
        let name = DnsName::new("old").expect("n");
        reg.register(&name, a).expect("register");
        ups.set(a, GW, &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))])
            .expect("set");
        // 記録を壊す: メンバーのディレクトリの記録ファイルを不正な内容にする。
        commit(&store, &net, "web1", 2, &[]);
        corrupt_member_files(&root.0);
        assert!(load_into(&dir, &reg, &ups, GW).is_err());
        assert_eq!(reg.lookup(name.as_str()), Some(a));
        assert_eq!(
            upstream_strings(&ups, a),
            Some(vec!["192.0.2.53:53".to_owned()])
        );
    }
}
