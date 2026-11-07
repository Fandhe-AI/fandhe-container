//! 制御チャネルのサーバ（Linux。SUP-1・SUP-9・SEC-1・REPAIR-2・REPAIR-5・#2058・#2162）。
//!
//! supervisor がコンテナの起動ハンドルを持っている間だけ、別スレッドで accept し、1 接続 1 要求を直列に処理する
//! （資源の使用量を固定に抑える）。要求は [`super::protocol`] の固定長 frame で、シグナルの送信は
//! [`super::target::SignalSlot`] を経て監視ループのスレッドが行う（ハンドルを持つスレッドだけが送る）。
//!
//! # 信頼境界と防御
//!
//! - accept の直後に `SO_PEERCRED` で接続元の uid を取り、実効 uid と違えば何も書かずに切断する
//!   （多層防御。ソケットは 0600・0700 の `<id>/` の中にあり、別 uid は通常 connect 自体ができない）。
//! - 要求（SignalRequest・StopRequest は 21 バイト、CancelRestartRequest〔#2440〕は 16 バイト、ExecHandoverRequest〔#2626〕は
//!   20 バイトの固定長。ExecCgroupNotify〔kind 7〕は保持期限 8 バイト + 名前 1〜56 バイトの可変長で、ガードだけが読む）で、kind ごとの payload 長と
//!   一致しない・ヘッダの payload_len が上限（64）を超える場合は payload を読まずに拒否する。
//! - 読み取りは絶対期限（[`ServeConfig::read_deadline`]）、返信待ちは送信期限 + 猶予、書き込みは
//!   [`ServeConfig::write_timeout`] で打ち切る（REPAIR-5）。
//! - 拒否は固定語彙の構造化ログ（理由名のみ。入力値・uid・パス・errno は出さない）。応答は理由コードだけ。
//!   認証境界の拒否（別 uid・資格情報の取得失敗）は [`ControlObserver`] 経由で SEC-4 の `AuditSink` にも記録する。
//! - 各要求の成功・失敗とレイテンシは [`ControlObserver`] が集計して構造化ログに出す（REPAIR-4）。
//!
//! ExitWatchRequest（kind 8。終了の購読。SUP-1・CRI-1・REPAIR-5・#3683）が成功した接続も例外で、接続の複製を
//! [`super::target::SignalSlot`] が預かり（スレッドを増やさない）、コンテナの終了・世代交代・保持期限で閉じる
//! （= 購読者の起床）。期限切れと相手が閉じた購読は accept ループが周回ごとに整理する。
//!
//! ExecHandoverRequest が成功した接続だけは例外で、`exec_guard` のガードスレッドが閉じずに預かり（accept ループは先へ進む）、
//! 2 つ目の要求（ExecCgroupNotify）と切断を監視する。ガードの数と待ちには上限がある（SUP-6・REPAIR-5・#2626）。
//!
//! サーバスレッドは停止可能（`accept` の non-blocking ポーリング）。restart の再 launch の再構成（#2043）で
//! スレッドを止める必要が出たときの口である。

use std::io::{self, Read, Write};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::ControlPeerRejection;

use super::exec_guard::ExecGuardPool;
use super::log_control_event;
use super::observe::ControlObserver;
use super::protocol::{
    CANCEL_RESTART_PAYLOAD_LEN, CancelRestartRequestFrame, ControlReason,
    EXEC_HANDOVER_PAYLOAD_LEN, EXIT_WATCH_PAYLOAD_LEN, ExecHandoverRequestFrame,
    ExitWatchRequestFrame, FrameHeader, HEADER_LEN, RequestHeader, ResponseFrame,
    SIGNAL_REQUEST_PAYLOAD_LEN, SignalDeadline, SignalRequestFrame, encode_hello,
};
use super::target::{ExitWatchHandle, SignalSlot, wait_reply};

/// 終了購読の接続を、整理（[`SignalSlot::prune_exit_watchers`]）が non-blocking の 1 バイト読み取りで調べられる形にする。
/// 購読者は Ack の後に何も送らない規約なので、読めたバイトは規約違反（落とす）、EOF は相手の切断、`WouldBlock` は生存。
impl ExitWatchHandle for UnixStream {
    fn is_dead(&mut self) -> bool {
        let mut byte = [0u8; 1];
        loop {
            return match self.read(&mut byte) {
                Ok(_) => true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => true,
            };
        }
    }
}

/// サーバの期限類。本番の既定は [`Default`]。試験は短い値へ差し替える。
#[derive(Debug, Clone, Copy)]
pub struct ServeConfig {
    /// 要求（ヘッダ + payload）を読み切る絶対期限（接続ごと）。
    pub read_deadline: Duration,
    /// 応答・Hello の書き込みの上限。
    pub write_timeout: Duration,
    /// 送信期限の後に、返信を待つ猶予。
    pub reply_grace: Duration,
    /// accept のポーリング間隔（停止要求を見る間隔でもある）。
    pub poll_interval: Duration,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            read_deadline: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            reply_grace: Duration::from_millis(50),
            poll_interval: Duration::from_millis(100),
        }
    }
}

/// 接続相手の資格情報（`SO_PEERCRED`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// 相手のプロセス ID。
    pub pid: u32,
    /// 相手の uid。
    pub uid: u32,
    /// 相手の gid。
    pub gid: u32,
}

/// 接続元を受け入れてよいか（同じ uid だけ）。
pub fn peer_allowed(peer_uid: u32, expected_uid: u32) -> bool {
    peer_uid == expected_uid
}

/// 絶対期限までに `buf` を読み切る。読み取りごとに残り時間を `set_read_timeout` へ設定し直す。
pub(super) fn read_exact_until(
    stream: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_read_timeout(Some(remaining))?;
        let Some(rest) = buf.get_mut(filled..) else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        match stream.read(rest) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn respond(stream: &mut UnixStream, reason: ControlReason) -> ControlReason {
    if reason != ControlReason::Ok {
        log_control_event("control_request_rejected", Some(reason.name()));
    }
    // 書き込めなくても（相手が閉じた・期限）処理は止めない。
    let _ = stream.write_all(&ResponseFrame { reason }.encode());
    reason
}

/// 1 接続を処理する（1 要求 1 応答で閉じる）。
///
/// 接続元の検証（`peer`）は呼び出し元（accept ループ）が `SO_PEERCRED` から作った値を渡す。別 uid 相当を
/// 試験から注入できるよう、資格情報は引数で受ける。別 uid は何も書かずに切断し、`observer` 経由で監査へ記録する。
/// 検証を通した接続は、結果とレイテンシを `observer` に集計する。
pub fn serve_connection(
    stream: UnixStream,
    peer: PeerCred,
    expected_uid: u32,
    slot: &SignalSlot,
    config: &ServeConfig,
    observer: &ControlObserver,
) {
    serve_connection_with_guards(stream, peer, expected_uid, slot, config, observer, None);
}

/// [`serve_connection`] に、exec 子 cgroup の回収の見張り（`guards`）を足した版。`None` なら ExecHandoverRequest は
/// `ExecReclaimUnavailable` で断る（fail-closed。SUP-6・#2626）。
pub fn serve_connection_with_guards(
    stream: UnixStream,
    peer: PeerCred,
    expected_uid: u32,
    slot: &SignalSlot,
    config: &ServeConfig,
    observer: &ControlObserver,
    guards: Option<&Arc<ExecGuardPool>>,
) {
    if !peer_allowed(peer.uid, expected_uid) {
        // 何も書かずに切断する（uid の値はログにも監査にも出さない）。
        observer.record_peer_rejection(ControlPeerRejection::PeerUidMismatch);
        return;
    }
    let started = Instant::now();
    let (reason, exit_watch) = handle_request(stream, slot, config, guards);
    if exit_watch {
        observer.record_exit_watch(reason == ControlReason::Ok, started.elapsed());
    } else {
        observer.record_request(reason == ControlReason::Ok, started.elapsed());
    }
}

/// 検証済みの接続の 1 要求を処理し、最終的な理由と「終了の購読か」を返す
/// （`Ok` が成功。応答を書けなかった場合も処理結果を返す。購読かどうかは計測の操作名を分けるため）。
fn handle_request(
    mut stream: UnixStream,
    slot: &SignalSlot,
    config: &ServeConfig,
    guards: Option<&Arc<ExecGuardPool>>,
) -> (ControlReason, bool) {
    if stream
        .set_write_timeout(Some(config.write_timeout))
        .is_err()
    {
        return (ControlReason::Internal, false);
    }
    if stream.write_all(&encode_hello()).is_err() {
        return (ControlReason::Internal, false);
    }
    let read_deadline = Instant::now() + config.read_deadline;

    let mut header = [0u8; HEADER_LEN];
    if read_exact_until(&mut stream, &mut header, read_deadline).is_err() {
        return (respond(&mut stream, ControlReason::Malformed), false);
    }
    let kind = match FrameHeader::decode(&header).and_then(FrameHeader::expect_any_request) {
        Ok(RequestHeader::Signal(kind)) => kind,
        Ok(RequestHeader::CancelRestart) => {
            return (handle_cancel_restart(stream, slot, read_deadline), false);
        }
        Ok(RequestHeader::ExecHandover) => {
            return (
                handle_exec_handover(stream, slot, read_deadline, guards),
                false,
            );
        }
        Ok(RequestHeader::ExitWatch) => {
            return (handle_exit_watch(stream, slot, read_deadline), true);
        }
        Err(reason) => return (respond(&mut stream, reason), false),
    };
    (
        handle_signal(stream, slot, config, read_deadline, kind),
        false,
    )
}

/// SignalRequest・StopRequest の payload を読んで、監視スレッドへ送信を依頼し、結果を返す。
fn handle_signal(
    mut stream: UnixStream,
    slot: &SignalSlot,
    config: &ServeConfig,
    read_deadline: Instant,
    kind: super::protocol::RequestKind,
) -> ControlReason {
    let mut payload = [0u8; SIGNAL_REQUEST_PAYLOAD_LEN];
    if read_exact_until(&mut stream, &mut payload, read_deadline).is_err() {
        return respond(&mut stream, ControlReason::Malformed);
    }
    let request = match SignalRequestFrame::decode_payload(kind, &payload) {
        Ok(r) => r,
        Err(reason) => return respond(&mut stream, reason),
    };

    let deadline = match absolute_deadline(request.deadline) {
        Ok(d) => d,
        Err(reason) => return respond(&mut stream, reason),
    };
    let reason = match slot.submit(request.kind, request.pid, request.signal, deadline) {
        Ok(rx) => wait_reply(&rx, deadline, config.reply_grace),
        Err(reason) => reason,
    };
    respond(&mut stream, reason)
}

/// ExitWatchRequest（kind 8）の payload を読んで、接続の複製を `slot` に預けてから `Response(Ok)` を返す
/// （SUP-1・CRI-1・REPAIR-5・#3683）。
///
/// 預けるのを応答より先にする: 書き込みの前に終了が観測されても、預けた複製は `mark_exited` で閉じられ、購読者は
/// Ok の後に EOF を受けて起床する（取りこぼさない）。接続は non-blocking にする（複製と元は同じファイル記述を共有し、
/// 整理の 1 バイト読み取りが待たないため。9 バイトの応答は空の送信バッファへ書くので詰まらない）。
/// 拒否では複製を drop し、元の接続で理由コードだけを返す。ロックの下では I/O をしない（`watch_exit` は判定と保管だけ）。
fn handle_exit_watch(
    mut stream: UnixStream,
    slot: &SignalSlot,
    read_deadline: Instant,
) -> ControlReason {
    let mut payload = [0u8; EXIT_WATCH_PAYLOAD_LEN];
    if read_exact_until(&mut stream, &mut payload, read_deadline).is_err() {
        return respond(&mut stream, ControlReason::Malformed);
    }
    let request = match ExitWatchRequestFrame::decode_payload(&payload) {
        Ok(r) => r,
        Err(reason) => return respond(&mut stream, reason),
    };
    if stream.set_nonblocking(true).is_err() {
        return respond(&mut stream, ControlReason::Internal);
    }
    let Ok(held) = stream.try_clone() else {
        return respond(&mut stream, ControlReason::Internal);
    };
    let reason = slot.watch_exit(request.pid, Box::new(held), request.hold());
    respond(&mut stream, reason)
}

/// CancelRestartRequest（kind 5）の payload を読んで、保留中の再起動の取り消しを `slot` に依頼する（#2440・SUP-9）。
/// 受け箱を経由せず、スロットの状態をその場で判定する（資源は固定。シグナルは送らない）。
fn handle_cancel_restart(
    mut stream: UnixStream,
    slot: &SignalSlot,
    read_deadline: Instant,
) -> ControlReason {
    let mut payload = [0u8; CANCEL_RESTART_PAYLOAD_LEN];
    if read_exact_until(&mut stream, &mut payload, read_deadline).is_err() {
        return respond(&mut stream, ControlReason::Malformed);
    }
    let request = match CancelRestartRequestFrame::decode_payload(&payload) {
        Ok(r) => r,
        Err(reason) => return respond(&mut stream, reason),
    };
    let deadline = match absolute_deadline(request.deadline) {
        Ok(d) => d,
        Err(reason) => return respond(&mut stream, reason),
    };
    let reason = slot.cancel_pending_restart(deadline);
    respond(&mut stream, reason)
}

/// ExecHandoverRequest（kind 6）の payload を読んで、起動時 pidfd の複製を `SCM_RIGHTS` で返す（SUP-6・SEC-1・#2626）。
///
/// uid の照合は `serve_connection` が済ませている。スロットの状態判定は [`SignalSlot::handover_pidfd`]（受け箱は経由せず、
/// シグナルも送らない）。成功は `Response(Ok)` と pidfd 1 本を 1 回の `sendmsg` で送り、拒否は fd なしの通常の応答。
fn handle_exec_handover(
    mut stream: UnixStream,
    slot: &SignalSlot,
    read_deadline: Instant,
    guards: Option<&Arc<ExecGuardPool>>,
) -> ControlReason {
    let mut payload = [0u8; EXEC_HANDOVER_PAYLOAD_LEN];
    if read_exact_until(&mut stream, &mut payload, read_deadline).is_err() {
        return respond(&mut stream, ControlReason::Malformed);
    }
    let request = match ExecHandoverRequestFrame::decode_payload(&payload) {
        Ok(r) => r,
        Err(reason) => return respond(&mut stream, reason),
    };
    let deadline = match absolute_deadline(request.deadline) {
        Ok(d) => d,
        Err(reason) => return respond(&mut stream, reason),
    };
    // 回収役が結線されていない supervisor は pidfd を渡さない（子孫を回収できない exec を許さない。fail-closed）。
    let Some(guards) = guards else {
        return respond(&mut stream, ControlReason::ExecReclaimUnavailable);
    };
    let pidfd = match slot.handover_pidfd(request.pid) {
        Ok(fd) => fd,
        Err(reason) => return respond(&mut stream, reason),
    };
    // ガードの枠とスレッドは pidfd を渡す前に確保する（上限超過・生成失敗なら fd を渡さず断る）。
    let guard = match guards.reserve() {
        Ok(g) => g,
        Err(reason) => return respond(&mut stream, reason),
    };
    // 期限を過ぎていたら fd を渡さない（クライアントはもう Timeout を返している。REPAIR-5）。
    if Instant::now() >= deadline {
        return respond(&mut stream, ControlReason::Timeout);
    }
    let reason = respond_with_fd(&mut stream, pidfd.as_fd(), deadline);
    if reason == ControlReason::Ok {
        // 接続を閉じずにガードへ預ける。以後の通知・切断の監視は専用スレッドが行い、accept ループは先へ進む。
        guard.start(stream);
    }
    reason
}

/// `EINTR` のときだけ、期限内なら再試行して `send_with_fd` を呼ぶ。期限切れは `TimedOut`。
fn send_with_fd_until(
    stream: &UnixStream,
    frame: &[u8],
    fd: BorrowedFd<'_>,
    deadline: Instant,
) -> io::Result<usize> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match crate::sys::send_with_fd(stream.as_fd(), frame, fd) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// `Response(Ok)` に `fd` を 1 本添えて送る。送れなかったら（相手が閉じた・期限）`Internal` を返す
/// （fd は添付されていない、または相手が受け取り済みで、こちらに残る資源は無い）。
fn respond_with_fd(
    stream: &mut UnixStream,
    fd: BorrowedFd<'_>,
    deadline: Instant,
) -> ControlReason {
    let frame = ResponseFrame {
        reason: ControlReason::Ok,
    }
    .encode();
    // `EINTR` は sys が返すので、再試行のたびに絶対期限を確かめる（割り込みが続いても期限を超えない。REPAIR-5）。
    let sent = match send_with_fd_until(stream, &frame, fd, deadline) {
        Ok(n) => n,
        Err(_) => {
            log_control_event(
                "control_request_rejected",
                Some(ControlReason::Internal.name()),
            );
            return ControlReason::Internal;
        }
    };
    // ストリームの短い書き込み: fd は最初のバイトに付いて届いているので、残りは通常の書き込みで送る。
    if let Some(rest) = frame.get(sent..)
        && !rest.is_empty()
        && stream.write_all(rest).is_err()
    {
        return ControlReason::Internal;
    }
    ControlReason::Ok
}

/// 要求が載せた絶対期限（`CLOCK_MONOTONIC`）を、サーバ側の `Instant` に写す。
///
/// 受信までの遅れの分だけ残りが縮むので、サーバ側の遅延でクライアントの期限より後ろへずれない（REPAIR-5）。
/// `Instant` を先に取ってから単調時計を読む順序にして、2 回の読み取りの間にスレッドが止まっても期限が延びず
/// 早まる側にずれるようにする。
fn absolute_deadline(deadline: SignalDeadline) -> Result<Instant, ControlReason> {
    let base = Instant::now();
    let now_ns = crate::sys::monotonic_now_ns().map_err(|_| ControlReason::Internal)?;
    let remaining = deadline.remaining_from(now_ns)?;
    Ok(base + remaining)
}

/// accept ループのスレッドとその停止の口。`Drop` で停止を要求して期限つきで join する。
pub struct ControlServer {
    stop: Arc<AtomicBool>,
    done: std::sync::mpsc::Receiver<()>,
    handle: Option<JoinHandle<()>>,
}

/// 再 launch の `pause` が exec のガードの停止に確保する予算の上限（回収の待ち 2 秒 + 余裕。REPAIR-5）。
pub const GUARD_STOP_BUDGET: Duration = Duration::from_secs(3);

/// スレッドの停止を待つ上限（超えたら切り離す。REPAIR-5）。
const JOIN_TIMEOUT: Duration = Duration::from_secs(1);

impl ControlServer {
    /// accept ループのスレッドを起動する。`listener` は non-blocking であること。
    ///
    /// exec 子 cgroup の回収役を持たない構成で、ExecHandoverRequest は `ExecReclaimUnavailable` で断る（fail-closed。
    /// 子孫を回収できない exec に pidfd を渡さない）。回収役つきは [`Self::spawn_with_exec_guard`]。
    pub fn spawn(
        listener: UnixListener,
        slot: SignalSlot,
        expected_uid: u32,
        config: ServeConfig,
        observer: Arc<ControlObserver>,
    ) -> io::Result<Self> {
        Self::spawn_with_exec_guard(listener, slot, expected_uid, config, observer, None)
    }

    /// [`Self::spawn`] に、exec 子 cgroup の回収の見張り（`guards`）を足した版（SUP-6・REPAIR-5・#2626）。
    pub fn spawn_with_exec_guard(
        listener: UnixListener,
        slot: SignalSlot,
        expected_uid: u32,
        config: ServeConfig,
        observer: Arc<ControlObserver>,
        guards: Option<Arc<ExecGuardPool>>,
    ) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done) = channel();
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("control-channel".to_owned())
            .spawn(move || {
                accept_loop(
                    &listener,
                    &slot,
                    expected_uid,
                    &config,
                    &thread_stop,
                    &observer,
                    guards.as_ref(),
                );
                let _ = done_tx.send(());
            })?;
        Ok(Self {
            stop,
            done,
            handle: Some(handle),
        })
    }

    /// 停止を要求し、期限つきで終了を待つ。
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let Some(handle) = self.handle.take() else {
            return;
        };
        match self.done.recv_timeout(JOIN_TIMEOUT) {
            // スレッドは done を送った直後に終わる。
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let _ = handle.join();
            }
            // 期限内に止まらなければ切り離す（プロセス終了まで残り得る）。
            Err(RecvTimeoutError::Timeout) => {
                log_control_event("control_server_detached", None);
            }
        }
    }
}

impl ControlServer {
    /// 停止を要求し、`timeout` 内にスレッドが終わったことを確かめて join する（[`Self::shutdown`] と違い、
    /// 止まらなければ `false` を返して切り離さない。呼び出し側は再 launch をしない。#2043・REPAIR-5）。
    fn stop_confirmed(&mut self, timeout: Duration) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        let Some(handle) = self.handle.take() else {
            return true;
        };
        match self.done.recv_timeout(timeout) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let _ = handle.join();
                true
            }
            Err(RecvTimeoutError::Timeout) => {
                self.handle = Some(handle);
                false
            }
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 再 launch の間だけ accept ループを止められる制御チャネルのサーバ（#2043・SUP-3・CORE-1・SUP-1）。
///
/// restart の再 launch は core の本番 launcher が単一スレッド（`Threads: 1`）を要求するため、`control-channel` スレッドを
/// [`Self::pause`] で止めて launch し、[`Self::resume`] で作り直す。listener は pause の間も bind したまま保持し、
/// close・unlink・rebind をしない（パスの差し替えの窓を作らない）。pause の間に届いた接続は backlog に積まれ、resume の
/// 後に同じ検証（`SO_PEERCRED`・期限・固定長 frame）で処理される。pause 中に届いた CancelRestartRequest は resume の後に
/// 処理されるため、`Active` の状態で `ContainerRunning` になり得る（CLI は記録の読み直しとして扱う。`stop_delete` 参照）。
pub struct PausableServer {
    inner: std::sync::Mutex<PausableInner>,
}

struct PausableInner {
    server: Option<ControlServer>,
    listener: UnixListener,
    slot: SignalSlot,
    expected_uid: u32,
    config: ServeConfig,
    observer: Arc<ControlObserver>,
    guards: Option<Arc<ExecGuardPool>>,
}

impl PausableServer {
    /// accept ループのスレッドを起動する。`listener` は non-blocking にされる。回収役は持たない
    /// （ExecHandoverRequest は断る。回収役つきは [`Self::spawn_with_exec_guard`]）。
    pub fn spawn(
        listener: UnixListener,
        slot: SignalSlot,
        expected_uid: u32,
        config: ServeConfig,
        observer: Arc<ControlObserver>,
    ) -> io::Result<Self> {
        Self::spawn_with_exec_guard(listener, slot, expected_uid, config, observer, None)
    }

    /// [`Self::spawn`] に exec 子 cgroup の回収の見張りを足した版。ガードのプールは pause / resume をまたいで保持する
    /// （再 launch の間も、預かった接続の見張りは続く。#2043）。
    pub fn spawn_with_exec_guard(
        listener: UnixListener,
        slot: SignalSlot,
        expected_uid: u32,
        config: ServeConfig,
        observer: Arc<ControlObserver>,
        guards: Option<Arc<ExecGuardPool>>,
    ) -> io::Result<Self> {
        let keep = listener.try_clone()?;
        let server = ControlServer::spawn_with_exec_guard(
            listener,
            slot.clone(),
            expected_uid,
            config,
            Arc::clone(&observer),
            guards.clone(),
        )?;
        Ok(Self {
            inner: std::sync::Mutex::new(PausableInner {
                server: Some(server),
                listener: keep,
                slot,
                expected_uid,
                config,
                observer,
                guards,
            }),
        })
    }

    /// accept ループと exec のガードを止める（`timeout` 内に止まらなければ `Err`）。
    ///
    /// 予算は 2 つに分ける（片方が使い切っても他方に残す。SUP-3・REPAIR-5・#2043）: ガードの停止に
    /// `min(GUARD_STOP_BUDGET, timeout / 2)`（回収の待ち 2 秒 + 余裕）、accept の停止にその残り。accept が止まっていても
    /// （`server` が無くても）ガードの停止は必ず試みる。`Err` のとき、止まらなかったガードはプールに残り、次の `pause` が
    /// 再び join する。
    pub fn pause(
        &self,
        timeout: Duration,
    ) -> Result<(), fandhe_container_core::traits::TraitError> {
        use fandhe_container_core::traits::{ErrorCode, TraitError};
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let guard_budget = GUARD_STOP_BUDGET.min(timeout / 2);
        let accept_budget = timeout.saturating_sub(guard_budget);
        if let Some(server) = inner.server.as_mut() {
            if !server.stop_confirmed(accept_budget) {
                log_control_event("relaunch_pause_failed", Some("accept_timeout"));
                return Err(TraitError::new(
                    ErrorCode::Timeout,
                    "control channel thread did not stop in time",
                ));
            }
            inner.server = None;
        }
        // accept ループが止まった後に、預かっている exec のガードのスレッドも止める（単一スレッドの再 launch のため。
        // 通知済みの旧世代の exec 子 cgroup はここで回収される）。止まらなければ launch させない（fail-closed）。
        if let Some(guards) = &inner.guards
            && let Err(e) = guards.shutdown_all(guard_budget)
        {
            log_control_event("relaunch_pause_failed", Some("guard_timeout"));
            return Err(e);
        }
        Ok(())
    }

    /// [`Self::pause`] で止めた accept ループを、保持していた listener で作り直す。動いていれば何もしない。
    pub fn resume(&self) -> Result<(), fandhe_container_core::traits::TraitError> {
        use fandhe_container_core::traits::{ErrorCode, TraitError};
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.server.is_some() {
            return Ok(());
        }
        // 停止要求の後は、新しいガードを受けられるように戻す。
        if let Some(guards) = &inner.guards {
            guards.reopen();
        }
        let spawned = inner.listener.try_clone().and_then(|l| {
            ControlServer::spawn_with_exec_guard(
                l,
                inner.slot.clone(),
                inner.expected_uid,
                inner.config,
                Arc::clone(&inner.observer),
                inner.guards.clone(),
            )
        });
        match spawned {
            Ok(server) => {
                inner.server = Some(server);
                Ok(())
            }
            Err(_) => Err(TraitError::new(
                ErrorCode::Unavailable,
                "failed to resume the control channel server",
            )),
        }
    }

    /// accept ループを止めて取り除く（後始末用。以後は [`Self::resume`] で作り直せる）。止まらなければ切り離す。
    pub fn shutdown(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut server) = inner.server.take() {
            server.shutdown();
        }
    }
}

impl super::target::RelaunchPause for PausableServer {
    fn pause(&self, timeout: Duration) -> Result<(), fandhe_container_core::traits::TraitError> {
        PausableServer::pause(self, timeout)
    }

    fn resume(&self) -> Result<(), fandhe_container_core::traits::TraitError> {
        PausableServer::resume(self)
    }
}

fn accept_loop(
    listener: &UnixListener,
    slot: &SignalSlot,
    expected_uid: u32,
    config: &ServeConfig,
    stop: &AtomicBool,
    observer: &ControlObserver,
    guards: Option<&Arc<ExecGuardPool>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let Ok(cred) = crate::sys::peer_credentials(stream.as_fd()) else {
                    // 資格情報を確かめられない接続は受け付けない。
                    observer
                        .record_peer_rejection(ControlPeerRejection::PeerCredentialsUnavailable);
                    continue;
                };
                let peer = PeerCred {
                    pid: cred.pid,
                    uid: cred.uid,
                    gid: cred.gid,
                };
                serve_connection_with_guards(
                    stream,
                    peer,
                    expected_uid,
                    slot,
                    config,
                    observer,
                    guards,
                );
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // 接続が無い周回で、期限切れ・相手が閉じた終了購読を整理する（#3683・REPAIR-5）。
                slot.prune_exit_watchers(Instant::now());
                std::thread::sleep(config.poll_interval);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                // 一時的な失敗（EMFILE 等）で全力ループしない。
                slot.prune_exit_watchers(Instant::now());
                std::thread::sleep(config.poll_interval);
            }
        }
    }
}
