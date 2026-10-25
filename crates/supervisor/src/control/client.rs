//! 制御チャネルのクライアント入口（SUP-1・SUP-9・SEC-1・REPAIR-5・#2058・#2162・#2440）。
//!
//! CLI の `stop`（と `kill`）が、起動ハンドルを持つ supervisor へシグナル送信を依頼するための公開 API。core の
//! `ProcessSignaler`（`oci_runtime::kill` の送信境界）を実装する。CLI の `stop_delete::production_signaler` が
//! これを使う（`stop` は [`ControlSignaler::for_stop`] で結線済み。#2059・#2162。`kill` は #1902 が [`ControlSignaler::new`] を使う。#1544 の段 C）。
//! `for_stop` は StopRequest（kind 4）を送り、supervisor に明示 stop の意図を記録させる（SUP-9）。意図を記録できない
//! supervisor（書き先なし・古い版）は、シグナルを送らずに構造化エラーを返す（fail-closed）。
//! `state.json` の pid へ生の `kill(2)` は送らない（pid 再利用で無関係なプロセスを止めない。SEC-1・CORE-1）。
//!
//! バックオフ中・再 launch 中（記録は `Stopped` で pid が無い）の stop は [`ControlRestartCanceller`] が
//! CancelRestartRequest（kind 5）を送り、保留中の再起動を取り消す（SUP-9・SUP-3・#2440）。シグナルは送らない。
//!
//! # 手順（Linux）
//!
//! 1. `<state_root>/<id>/` を symlink を辿らずに開き、所有者（実効 uid）・権限（0700 相当）を検証する
//!    （listen 側と同じ検証。`control::listener`）。
//! 2. 検証した fd 経由で `supervisor.sock` へ non-blocking で接続する。start の報告と bind の間の短い空白と、前回の異常終了で残った
//!    ソケットのため、`ENOENT`・`ECONNREFUSED` は 20ms 間隔で最大 500ms（または期限）まで再試行し、超えたら
//!    `Unavailable`（固定文言）を返す。
//! 3. 接続したソケットの `SO_PEERCRED`（listen 側の資格情報）が自分の実効 uid と一致することを確かめる。
//! 4. Hello を受けてから、期限から余裕（20ms）を引いた絶対期限を載せて要求を送り、応答を受ける。
//!
//! 接続は non-blocking の試行（listen backlog 満杯は `EAGAIN`）を絶対期限まで繰り返し、読み書きは残り時間を
//! タイムアウトにして呼び出しスレッドの上で行う（作業スレッドを切り離さない。REPAIR-5）。要求には余裕を引いた
//! 絶対期限（`CLOCK_MONOTONIC`）を載せ、サーバの受信が遅れても送信期限が延びないようにする。期限の残りが余裕
//! 以下なら接続せずに `Timeout` を返す（送らない）。
//!
//! 非 Linux では同名の型が `Unimplemented` を返す（CLI に `cfg` を持ち込まないため）。

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Instant;

use fandhe_container_core::oci_runtime::ProcessSignaler;
use fandhe_container_core::traits::{ContainerId, Signal, TraitError};

use super::PendingRestartCanceller;
use super::protocol::RequestKind;

/// [`PendingRestartCanceller::cancel`] の結果（SUP-9・SUP-3・#2440）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelOutcome {
    /// 保留中の再起動を取り消した（supervisor はもう再起動しない）。
    Cancelled,
    /// 取り消す時点で新しいプロセスが動いていた（通常の stop をやり直す対象）。
    ContainerRunning,
    /// 届く supervisor が無い（ソケットが無い・接続先が無い・取り消しを知らない古い版・ハンドル未保持）。
    NoSupervisor,
}

/// supervisor の制御チャネルへ「保留中の再起動の取り消し」を依頼する [`PendingRestartCanceller`]。
#[derive(Debug, Clone)]
pub struct ControlRestartCanceller {
    state_root: PathBuf,
}

impl ControlRestartCanceller {
    /// 状態ルートから作る。
    pub fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }
}

#[cfg(target_os = "linux")]
impl PendingRestartCanceller for ControlRestartCanceller {
    fn cancel(&self, id: &ContainerId, deadline: Instant) -> Result<CancelOutcome, TraitError> {
        linux::cancel_restart(&self.state_root, id, deadline)
    }
}

#[cfg(not(target_os = "linux"))]
impl PendingRestartCanceller for ControlRestartCanceller {
    fn cancel(&self, id: &ContainerId, deadline: Instant) -> Result<CancelOutcome, TraitError> {
        let _ = (&self.state_root, id, deadline);
        Err(TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "the supervisor control channel requires Linux",
        ))
    }
}

/// supervisor の制御チャネルから、稼働中コンテナの起動時 pidfd の複製を受け取る [`super::ExecPidfdSource`]
/// （CLI の `exec` 用。SUP-6・SEC-1・CLI-1・#2626）。Linux のみ（pidfd と `SCM_RIGHTS` は Linux の機能）。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct ControlExecHandover {
    state_root: PathBuf,
}

#[cfg(target_os = "linux")]
impl ControlExecHandover {
    /// 状態ルート（`<state_root>/<id>/supervisor.sock` の `<state_root>`）から作る。
    pub fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }
}

#[cfg(target_os = "linux")]
impl super::ExecPidfdSource for ControlExecHandover {
    fn obtain(
        &self,
        id: &ContainerId,
        pid: NonZeroU32,
        deadline: Instant,
    ) -> Result<std::os::fd::OwnedFd, TraitError> {
        linux::exec_handover(&self.state_root, id, pid, deadline)
    }
}

/// supervisor の制御チャネルへシグナル送信を依頼する `ProcessSignaler`。
#[derive(Debug, Clone)]
pub struct ControlSignaler {
    state_root: PathBuf,
    kind: RequestKind,
}

impl ControlSignaler {
    /// 状態ルート（`<state_root>/<id>/supervisor.sock` の `<state_root>`）から作る。シグナルを送るだけで、
    /// stop の意図は記録させない（`kill` 用。#1902）。
    pub fn new(state_root: PathBuf) -> Self {
        Self {
            state_root,
            kind: RequestKind::Signal,
        }
    }

    /// 明示 stop 用に作る。送るシグナルの前に、supervisor に stop の意図を記録させる（SUP-9・#2162）。
    pub fn for_stop(state_root: PathBuf) -> Self {
        Self {
            state_root,
            kind: RequestKind::Stop,
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcessSignaler for ControlSignaler {
    fn signal(
        &self,
        id: &ContainerId,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        linux::signal(&self.state_root, self.kind, id, pid, signal, deadline)
    }
}

#[cfg(not(target_os = "linux"))]
impl ProcessSignaler for ControlSignaler {
    fn signal(
        &self,
        id: &ContainerId,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        let _ = (&self.state_root, self.kind, id, pid, signal, deadline);
        Err(TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "the supervisor control channel requires Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, Write as _};
    use std::num::NonZeroU32;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};

    use super::CancelOutcome;
    use crate::control::listener::{
        CONTROL_SOCKET_NAME, effective_uid, open_state_dir, path_via_fd,
    };
    use crate::control::protocol::{
        CancelRestartRequestFrame, ControlReason, ExecHandoverRequestFrame, FrameHeader,
        HEADER_LEN, MAX_SIGNAL_BUDGET, RESPONSE_LEN, RESPONSE_PAYLOAD_LEN, RequestKind,
        ResponseFrame, SignalDeadline, SignalRequestFrame,
    };
    use crate::control::server::{peer_allowed, read_exact_until};

    /// 1 回の交換で送る要求。
    #[derive(Clone, Copy)]
    enum Request {
        Signal {
            kind: RequestKind,
            pid: NonZeroU32,
            signal: Signal,
        },
        CancelRestart,
        /// exec 用 pidfd の受け渡し（#2626）。応答に fd が添えられる。
        ExecHandover {
            pid: NonZeroU32,
        },
    }

    /// connect の再試行の間隔と、`ENOENT`・`ECONNREFUSED` を再試行する窓。
    const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(20);
    const CONNECT_RETRY_WINDOW: Duration = Duration::from_millis(500);
    /// backlog 満杯（`EAGAIN`）の再試行の間隔（期限までは待つ）。
    const CONNECT_BACKLOG_INTERVAL: Duration = Duration::from_millis(5);
    /// 期限からサーバの処理・応答の往復のために引いておく余裕。
    const DEADLINE_MARGIN: Duration = Duration::from_millis(20);

    fn unavailable() -> TraitError {
        TraitError::new(
            ErrorCode::Unavailable,
            "the supervisor control channel is unavailable",
        )
    }

    fn timeout() -> TraitError {
        ControlReason::Timeout
            .to_error()
            .unwrap_or_else(unavailable)
    }

    /// 期限つきの呼び出し本体。
    ///
    /// 作業スレッドは使わない。接続は non-blocking の試行を絶対期限まで繰り返し、読み書きは残り時間を
    /// タイムアウトに設定し直すので、すべて呼び出しスレッドの上で期限に終わる（切り離されたスレッドも
    /// 残った fd も無い。REPAIR-5）。
    pub(super) fn signal(
        state_root: &Path,
        kind: RequestKind,
        id: &ContainerId,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        let usable = deadline.saturating_duration_since(Instant::now());
        if usable <= DEADLINE_MARGIN {
            // 期限が迫っているときは接続せず、送らない（期限後にシグナルが届かない。REPAIR-5）。
            return Err(timeout());
        }
        let reason = exchange(
            state_root,
            Request::Signal { kind, pid, signal },
            id,
            deadline,
        )?;
        match reason.to_error() {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// 保留中の再起動の取り消しを依頼する（SUP-9・SUP-3・#2440）。
    ///
    /// 接続できない（`Unavailable`）・取り消しを知らない古い supervisor（`Malformed` 等で拒否）・ハンドル未保持は
    /// `NoSupervisor`（呼び出し側が従来の stop の扱いへ倒す）。それ以外の拒否は固定文言の構造化エラー。
    pub(super) fn cancel_restart(
        state_root: &Path,
        id: &ContainerId,
        deadline: Instant,
    ) -> Result<CancelOutcome, TraitError> {
        let usable = deadline.saturating_duration_since(Instant::now());
        if usable <= DEADLINE_MARGIN {
            return Err(timeout());
        }
        let reason = match exchange(state_root, Request::CancelRestart, id, deadline) {
            Ok(reason) => reason,
            Err(e) if e.code() == ErrorCode::Unavailable => return Ok(CancelOutcome::NoSupervisor),
            Err(e) => return Err(e),
        };
        match reason {
            ControlReason::Ok => Ok(CancelOutcome::Cancelled),
            ControlReason::ContainerRunning => Ok(CancelOutcome::ContainerRunning),
            ControlReason::NoHandle
            | ControlReason::Malformed
            | ControlReason::TooLarge
            | ControlReason::UnsupportedVersion => Ok(CancelOutcome::NoSupervisor),
            other => Err(other.to_error().unwrap_or_else(unavailable)),
        }
    }

    fn connect_until(path: &Path, deadline: Instant) -> Result<UnixStream, TraitError> {
        let retry_until = deadline.min(Instant::now() + CONNECT_RETRY_WINDOW);
        loop {
            let interval = match crate::sys::connect_unix_nonblocking(path) {
                Ok(s) => return Ok(s),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) && Instant::now() < retry_until =>
                {
                    CONNECT_RETRY_INTERVAL
                }
                // 相手の listen backlog が満杯。期限まで待つ。
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(timeout());
                    }
                    CONNECT_BACKLOG_INTERVAL
                }
                Err(_) => return Err(unavailable()),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timeout());
            }
            std::thread::sleep(interval.min(remaining));
        }
    }

    fn io_error(e: &io::Error) -> TraitError {
        if e.kind() == io::ErrorKind::TimedOut {
            timeout()
        } else {
            unavailable()
        }
    }

    /// 1 要求を送って理由コードを受ける。接続・転送の失敗は `Err`（`Unavailable` は「届かない」を表す）。
    fn exchange(
        state_root: &Path,
        request: Request,
        id: &ContainerId,
        deadline: Instant,
    ) -> Result<ControlReason, TraitError> {
        exchange_with_fds(state_root, request, id, deadline).map(|(reason, _fds)| reason)
    }

    /// [`exchange`] と同じだが、応答に添えられた fd も受け取る（ExecHandoverRequest だけが fd つきの応答を受ける。
    /// 他の要求では `fds` は常に空で、通常の `read` 経路のまま）。受け取った fd は呼び出し側が検証し、想定外なら drop で閉じる。
    fn exchange_with_fds(
        state_root: &Path,
        request: Request,
        id: &ContainerId,
        deadline: Instant,
    ) -> Result<(ControlReason, Vec<OwnedFd>), TraitError> {
        let euid = effective_uid()?;
        let dir = open_state_dir(state_root, id, euid)?;
        let path = path_via_fd(&dir, CONTROL_SOCKET_NAME);
        let mut stream = connect_until(&path, deadline)?;

        // listen 側の資格情報を確かめる（別 uid が同名のソケットを置いていても送らない）。
        let cred = crate::sys::peer_credentials(stream.as_fd()).map_err(|_| unavailable())?;
        if !peer_allowed(cred.uid, euid) {
            return Err(TraitError::new(
                ErrorCode::PermissionDenied,
                "the supervisor control channel peer is not trusted",
            ));
        }
        let write_limit = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        stream
            .set_write_timeout(Some(write_limit))
            .map_err(|_| unavailable())?;

        // Hello（サーバが接続元の検証を通した合図）。
        let mut head = [0u8; HEADER_LEN];
        read_exact_until(&mut stream, &mut head, deadline).map_err(|e| io_error(&e))?;
        FrameHeader::decode(&head)
            .and_then(FrameHeader::expect_hello)
            .map_err(|r| r.to_error().unwrap_or_else(unavailable))?;

        // 余裕を引いた絶対期限（CLOCK_MONOTONIC）をサーバへ渡す。サーバの受信が遅れても期限は延びない。
        // 単調時計を `Instant` より先に読む。2 回の読み取りの間にスレッドが止まっても、載せる絶対期限は
        // 早まる側にずれ、クライアントが Timeout を返した後に送信されうる期限にならない（REPAIR-5）。
        let now_ns = crate::sys::monotonic_now_ns().map_err(|_| unavailable())?;
        let send_budget = deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(DEADLINE_MARGIN)
            .min(MAX_SIGNAL_BUDGET);
        if send_budget.is_zero() {
            return Err(timeout());
        }
        let abs_ns = u64::try_from(send_budget.as_nanos())
            .ok()
            .and_then(|n| now_ns.checked_add(n))
            .ok_or_else(unavailable)?;
        let deadline_frame = SignalDeadline::from_nanos(abs_ns).map_err(|_| unavailable())?;
        let sent = match request {
            Request::Signal { kind, pid, signal } => stream.write_all(
                &SignalRequestFrame {
                    kind,
                    pid,
                    signal,
                    deadline: deadline_frame,
                }
                .encode(),
            ),
            Request::CancelRestart => stream.write_all(
                &CancelRestartRequestFrame {
                    deadline: deadline_frame,
                }
                .encode(),
            ),
            Request::ExecHandover { pid } => stream.write_all(
                &ExecHandoverRequestFrame {
                    pid,
                    deadline: deadline_frame,
                }
                .encode(),
            ),
        };
        sent.map_err(|e| io_error(&e))?;

        if matches!(request, Request::ExecHandover { .. }) {
            return read_response_with_fds(&mut stream, deadline);
        }
        read_exact_until(&mut stream, &mut head, deadline).map_err(|e| io_error(&e))?;
        FrameHeader::decode(&head)
            .and_then(FrameHeader::expect_response)
            .map_err(|r| r.to_error().unwrap_or_else(unavailable))?;
        let mut payload = [0u8; RESPONSE_PAYLOAD_LEN];
        read_exact_until(&mut stream, &mut payload, deadline).map_err(|e| io_error(&e))?;
        Ok((ResponseFrame::decode_payload(&payload).reason, Vec::new()))
    }

    /// 応答（Response frame 9 バイト）を、添えられた fd とともに受ける。fd は応答の最初のバイトに付いて届くので、
    /// 最初の読み取りを `recvmsg` で行い、足りない残りだけを通常の読み取りで補う（通常の `read` は fd を捨てる）。
    /// 読み取りごとに残り時間を受信タイムアウトへ設定し直す（REPAIR-5）。
    fn read_response_with_fds(
        stream: &mut UnixStream,
        deadline: Instant,
    ) -> Result<(ControlReason, Vec<OwnedFd>), TraitError> {
        let mut frame = [0u8; RESPONSE_LEN];
        // `EINTR` は sys が返すので、再試行のたびに残り時間を受信タイムアウトへ設定し直す（割り込みが続いても
        // 絶対期限を超えない。REPAIR-5）。`EAGAIN`（受信タイムアウト）は期限切れ。
        let received = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timeout());
            }
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| unavailable())?;
            match crate::sys::recv_with_fds(stream.as_fd(), &mut frame) {
                Ok(r) => break r,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(timeout()),
                Err(e) => return Err(io_error(&e)),
            }
        };
        // 切り詰められた（想定外の本数）制御データは、受け切れなかった分をカーネルが閉じている。受け取った分は drop で閉じる。
        if received.truncated {
            return Err(unavailable());
        }
        if received.len == 0 {
            return Err(unavailable());
        }
        if let Some(rest) = frame.get_mut(received.len..)
            && !rest.is_empty()
        {
            read_exact_until(stream, rest, deadline).map_err(|e| io_error(&e))?;
        }
        let (head, payload) = frame
            .split_first_chunk::<HEADER_LEN>()
            .ok_or_else(unavailable)?;
        FrameHeader::decode(head)
            .and_then(FrameHeader::expect_response)
            .map_err(|r| r.to_error().unwrap_or_else(unavailable))?;
        let payload: [u8; RESPONSE_PAYLOAD_LEN] = payload.try_into().map_err(|_| unavailable())?;
        Ok((ResponseFrame::decode_payload(&payload).reason, received.fds))
    }

    /// 稼働中コンテナの起動時 pidfd の複製を supervisor から受け取る（SUP-6・SEC-1・#2626）。
    ///
    /// 成功は「`Response(Ok)` と fd がちょうど 1 本」のときだけ。拒否（理由コード）に fd が添えられていても、Ok に
    /// fd が無い・2 本以上でも、受け取った fd はすべて閉じて失敗にする（fail-closed。fd を漏らさない）。届いた fd が
    /// 本当に記録 pid の pidfd かは、呼び出し側が `identify_pid1_with_pidfd` で確かめる（この関数は fd を信用しない）。
    pub(super) fn exec_handover(
        state_root: &Path,
        id: &ContainerId,
        pid: NonZeroU32,
        deadline: Instant,
    ) -> Result<OwnedFd, TraitError> {
        let usable = deadline.saturating_duration_since(Instant::now());
        if usable <= DEADLINE_MARGIN {
            return Err(timeout());
        }
        let (reason, fds) =
            exchange_with_fds(state_root, Request::ExecHandover { pid }, id, deadline)?;
        if let Some(e) = reason.to_error() {
            return Err(e);
        }
        let mut fds = fds.into_iter();
        match (fds.next(), fds.next()) {
            (Some(fd), None) => Ok(fd),
            // fd が無い・2 本以上: 契約違反の応答。受け取った fd は drop で閉じる。
            _ => Err(TraitError::new(
                ErrorCode::Internal,
                "the supervisor control channel returned an unexpected descriptor set",
            )),
        }
    }
}
