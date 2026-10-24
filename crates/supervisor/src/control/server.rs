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
//!   20 バイトの固定長）で、kind ごとの payload 長と
//!   一致しない・ヘッダの payload_len が上限（64）を超える場合は payload を読まずに拒否する。
//! - 読み取りは絶対期限（[`ServeConfig::read_deadline`]）、返信待ちは送信期限 + 猶予、書き込みは
//!   [`ServeConfig::write_timeout`] で打ち切る（REPAIR-5）。
//! - 拒否は固定語彙の構造化ログ（理由名のみ。入力値・uid・パス・errno は出さない）。応答は理由コードだけ。
//!   認証境界の拒否（別 uid・資格情報の取得失敗）は [`ControlObserver`] 経由で SEC-4 の `AuditSink` にも記録する。
//! - 各要求の成功・失敗とレイテンシは [`ControlObserver`] が集計して構造化ログに出す（REPAIR-4）。
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

use super::log_control_event;
use super::observe::ControlObserver;
use super::protocol::{
    CANCEL_RESTART_PAYLOAD_LEN, CancelRestartRequestFrame, ControlReason,
    EXEC_HANDOVER_PAYLOAD_LEN, ExecHandoverRequestFrame, FrameHeader, HEADER_LEN, RequestHeader,
    ResponseFrame, SIGNAL_REQUEST_PAYLOAD_LEN, SignalDeadline, SignalRequestFrame, encode_hello,
};
use super::target::{SignalSlot, wait_reply};

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
    if !peer_allowed(peer.uid, expected_uid) {
        // 何も書かずに切断する（uid の値はログにも監査にも出さない）。
        observer.record_peer_rejection(ControlPeerRejection::PeerUidMismatch);
        return;
    }
    let started = Instant::now();
    let reason = handle_request(stream, slot, config);
    observer.record_request(reason == ControlReason::Ok, started.elapsed());
}

/// 検証済みの接続の 1 要求を処理し、最終的な理由を返す（`Ok` が成功。応答を書けなかった場合も処理結果を返す）。
fn handle_request(
    mut stream: UnixStream,
    slot: &SignalSlot,
    config: &ServeConfig,
) -> ControlReason {
    if stream
        .set_write_timeout(Some(config.write_timeout))
        .is_err()
    {
        return ControlReason::Internal;
    }
    if stream.write_all(&encode_hello()).is_err() {
        return ControlReason::Internal;
    }
    let read_deadline = Instant::now() + config.read_deadline;

    let mut header = [0u8; HEADER_LEN];
    if read_exact_until(&mut stream, &mut header, read_deadline).is_err() {
        return respond(&mut stream, ControlReason::Malformed);
    }
    let kind = match FrameHeader::decode(&header).and_then(FrameHeader::expect_any_request) {
        Ok(RequestHeader::Signal(kind)) => kind,
        Ok(RequestHeader::CancelRestart) => {
            return handle_cancel_restart(stream, slot, read_deadline);
        }
        Ok(RequestHeader::ExecHandover) => {
            return handle_exec_handover(stream, slot, read_deadline);
        }
        Err(reason) => return respond(&mut stream, reason),
    };
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
    let pidfd = match slot.handover_pidfd(request.pid) {
        Ok(fd) => fd,
        Err(reason) => return respond(&mut stream, reason),
    };
    // 期限を過ぎていたら fd を渡さない（クライアントはもう Timeout を返している。REPAIR-5）。
    if Instant::now() >= deadline {
        return respond(&mut stream, ControlReason::Timeout);
    }
    respond_with_fd(&mut stream, pidfd.as_fd())
}

/// `Response(Ok)` に `fd` を 1 本添えて送る。送れなかったら（相手が閉じた・期限）`Internal` を返す
/// （fd は添付されていない、または相手が受け取り済みで、こちらに残る資源は無い）。
fn respond_with_fd(stream: &mut UnixStream, fd: BorrowedFd<'_>) -> ControlReason {
    let frame = ResponseFrame {
        reason: ControlReason::Ok,
    }
    .encode();
    let sent = match crate::sys::send_with_fd(stream.as_fd(), &frame, fd) {
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

/// スレッドの停止を待つ上限（超えたら切り離す。REPAIR-5）。
const JOIN_TIMEOUT: Duration = Duration::from_secs(1);

impl ControlServer {
    /// accept ループのスレッドを起動する。`listener` は non-blocking であること。
    pub fn spawn(
        listener: UnixListener,
        slot: SignalSlot,
        expected_uid: u32,
        config: ServeConfig,
        observer: Arc<ControlObserver>,
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

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(
    listener: &UnixListener,
    slot: &SignalSlot,
    expected_uid: u32,
    config: &ServeConfig,
    stop: &AtomicBool,
    observer: &ControlObserver,
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
                serve_connection(stream, peer, expected_uid, slot, config, observer);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(config.poll_interval);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                // 一時的な失敗（EMFILE 等）で全力ループしない。
                std::thread::sleep(config.poll_interval);
            }
        }
    }
}
