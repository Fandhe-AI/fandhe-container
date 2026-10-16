//! 制御チャネルのクライアント入口（SUP-1・SEC-1・REPAIR-5・#2058）。
//!
//! CLI の `stop`（と `kill`）が、起動ハンドルを持つ supervisor へシグナル送信を依頼するための公開 API。core の
//! `ProcessSignaler`（`oci_runtime::kill` の送信境界）を実装するので、CLI は `UnavailableSignaler` をこの
//! `ControlSignaler` に差し替えるだけで済む（結線は別 issue。#1544 の段 C。REPAIR-3）。
//! `state.json` の pid へ生の `kill(2)` は送らない（pid 再利用で無関係なプロセスを止めない。SEC-1・CORE-1）。
//!
//! # 手順（Linux）
//!
//! 1. `<state_root>/<id>/` を symlink を辿らずに開き、所有者（実効 uid）・権限（0700 相当）を検証する
//!    （listen 側と同じ検証。`control::listener`）。
//! 2. 検証した fd 経由で `supervisor.sock` へ接続する。start の報告と bind の間の短い空白と、前回の異常終了で残った
//!    ソケットのため、`ENOENT`・`ECONNREFUSED` は 20ms 間隔で最大 500ms（または期限）まで再試行し、超えたら
//!    `Unavailable`（固定文言）を返す。
//! 3. 接続したソケットの `SO_PEERCRED`（listen 側の資格情報）が自分の実効 uid と一致することを確かめる。
//! 4. Hello を受けてから、残り時間から余裕（20ms）を引いた値を budget として要求を送り、応答を受ける。
//!
//! やり取り全体は作業スレッドで行い、`recv_timeout` で期限に打ち切る（`UnixStream::connect` にタイムアウトが
//! 無いため）。期限の残りが余裕以下なら接続せずに `Timeout` を返す（送らない）。
//!
//! 非 Linux では同名の型が `Unimplemented` を返す（CLI に `cfg` を持ち込まないため）。

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Instant;

use fandhe_container_core::oci_runtime::ProcessSignaler;
use fandhe_container_core::traits::{ContainerId, Signal, TraitError};

/// supervisor の制御チャネルへシグナル送信を依頼する `ProcessSignaler`。
#[derive(Debug, Clone)]
pub struct ControlSignaler {
    state_root: PathBuf,
}

impl ControlSignaler {
    /// 状態ルート（`<state_root>/<id>/supervisor.sock` の `<state_root>`）から作る。
    pub fn new(state_root: PathBuf) -> Self {
        Self { state_root }
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
        linux::signal(&self.state_root, id, pid, signal, deadline)
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
        let _ = (&self.state_root, id, pid, signal, deadline);
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
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};

    use crate::control::listener::{
        CONTROL_SOCKET_NAME, effective_uid, open_state_dir, path_via_fd,
    };
    use crate::control::protocol::{
        ControlReason, FrameHeader, HEADER_LEN, MAX_SIGNAL_BUDGET, RESPONSE_PAYLOAD_LEN,
        ResponseFrame, SignalBudget, SignalRequestFrame,
    };
    use crate::control::server::{peer_allowed, read_exact_until};

    /// connect の再試行の間隔と窓。
    const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(20);
    const CONNECT_RETRY_WINDOW: Duration = Duration::from_millis(500);
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

    /// 期限つきの呼び出し本体（作業スレッドを起こして打ち切る）。
    pub(super) fn signal(
        state_root: &Path,
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
        let (tx, rx) = sync_channel(1);
        let root = state_root.to_path_buf();
        let id = id.clone();
        std::thread::Builder::new()
            .name("control-client".to_owned())
            .spawn(move || {
                let _ = tx.send(exchange(&root, &id, pid, signal, deadline));
            })
            .map_err(|_| unavailable())?;
        match rx.recv_timeout(usable) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Err(timeout()),
        }
    }

    fn connect_with_retry(path: &Path, deadline: Instant) -> Result<UnixStream, TraitError> {
        let retry_until = deadline.min(Instant::now() + CONNECT_RETRY_WINDOW);
        loop {
            match UnixStream::connect(path) {
                Ok(s) => return Ok(s),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) && Instant::now() < retry_until =>
                {
                    std::thread::sleep(CONNECT_RETRY_INTERVAL);
                }
                Err(_) => return Err(unavailable()),
            }
        }
    }

    fn io_error(e: &io::Error) -> TraitError {
        if e.kind() == io::ErrorKind::TimedOut {
            timeout()
        } else {
            unavailable()
        }
    }

    fn exchange(
        state_root: &Path,
        id: &ContainerId,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        let euid = effective_uid()?;
        let dir = open_state_dir(state_root, id, euid)?;
        let path = path_via_fd(&dir, CONTROL_SOCKET_NAME);
        let mut stream = connect_with_retry(&path, deadline)?;

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

        let budget = deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(DEADLINE_MARGIN)
            .min(MAX_SIGNAL_BUDGET);
        let Ok(budget) = SignalBudget::new(budget) else {
            return Err(timeout());
        };
        let frame = SignalRequestFrame {
            pid,
            signal,
            budget,
        };
        stream
            .write_all(&frame.encode())
            .map_err(|e| io_error(&e))?;

        read_exact_until(&mut stream, &mut head, deadline).map_err(|e| io_error(&e))?;
        FrameHeader::decode(&head)
            .and_then(FrameHeader::expect_response)
            .map_err(|r| r.to_error().unwrap_or_else(unavailable))?;
        let mut payload = [0u8; RESPONSE_PAYLOAD_LEN];
        read_exact_until(&mut stream, &mut payload, deadline).map_err(|e| io_error(&e))?;
        match ResponseFrame::decode_payload(&payload).reason.to_error() {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
}
