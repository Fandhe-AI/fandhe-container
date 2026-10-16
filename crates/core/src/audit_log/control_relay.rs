//! 複数スレッドのプロセスから制御チャネルの拒否を期限付きで永続化する中継（Linux。SEC-4・REPAIR-5・SUP-1・SEC-1・#2058）。
//!
//! # 役割
//!
//! [`FileAuditSink`] は主経路のファイル I/O を fork した使い捨ての子で実行するため、呼び出しプロセスが
//! 複数スレッドだと主経路を試行できず（`isolation_unavailable`）、`CAP_AUDIT_WRITE` の無い非特権起動では代替経路
//! （カーネル監査）も失敗して拒否が残らない。supervisor の制御チャネルのサーバスレッドは監視スレッドと並行して
//! 動くため常にこの状態になる。本中継は、**スレッドを作る前の単一スレッドの時点で** 監査専用の子プロセス
//! （helper）を 1 つ fork して常駐させ、以後の `record` を socketpair 越しに helper へ渡す。helper は単一スレッドの
//! ままなので、持たせた [`FileAuditSink`] の隔離（主経路 → 代替経路 → 失敗通知）がそのまま働く。
//!
//! # 契約
//!
//! - 構築（[`ControlAuditRelay::spawn`]）は呼び出しプロセスが単一スレッドのときだけ成功する（`FailedPrecondition`）。
//!   制御チャネルの listener を bind する前に呼ぶこと（helper は fd 3 以上を閉じるため listener を持たない）
//! - 運べるのは [`AuditEvent::ControlPeer`] の記録だけ（他の層は `InvalidArgument`）。時刻・PID・コンテナ ID・理由トークンを
//!   固定の枠で送り、helper が [`AuditRecord`] を組み直す（生のバイト列を記録として扱わない。REPAIR-2）
//! - `record` は helper の応答を [`RECORD_WAIT_LIMIT`] まで待つ（helper の sink の最悪待ち時間と同じ）。応答が無ければ
//!   helper を SIGKILL して以後の `record` を `Unavailable` で拒否する（ずれた応答を次の要求へ取り違えない。fail-closed）。
//!   拒否の判定自体は呼び出し側で既に確定しており、本中継の失敗は判定を覆さない
//! - 親が終了すると socketpair が EOF になり helper も終了する。drop でも SIGKILL して回収を試みる
//!
//! # 未実装（REPAIR-3）
//!
//! helper が死んだ後の再起動はしない（以後 `Unavailable`。呼び出し側が構造化ログへ縮退する）。

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::sys;
use crate::traits::{ContainerId, ErrorCode, TraitError};

use super::{
    AuditEvent, AuditPid, AuditRecord, AuditSink, AuditTimestamp, ControlPeerRejection,
    FileAuditSink, RECORD_WAIT_LIMIT,
};

/// 枠の固定部: 理由 1・秒 8・ナノ秒 4・PID 4・コンテナ ID 長 1。
const FIXED_LEN: usize = 1 + 8 + 4 + 4 + 1;
/// helper の応答: 永続化できた。
const ACK_OK: u8 = 1;
/// helper の応答: 主経路・代替経路とも失敗した。
const ACK_FAIL: u8 = 0;
/// helper が fd 3 以上を閉じられなかったときの終了コード。
const CLOSE_FDS_FAILED_EXIT: i32 = 3;
/// 回収待ちの上限（drop 時）。
const REAP_WAIT: Duration = Duration::from_secs(1);

/// 運べる拒否理由（枠の先頭バイトが添字）。
const REJECTIONS: [ControlPeerRejection; 2] = [
    ControlPeerRejection::PeerUidMismatch,
    ControlPeerRejection::PeerCredentialsUnavailable,
];

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

/// 記録を枠へ符号化する。`ControlPeer` 以外・長すぎるコンテナ ID は拒否する。
fn encode(record: &AuditRecord) -> Result<Vec<u8>, TraitError> {
    let AuditEvent::ControlPeer { reason } = record.event() else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the audit relay only carries control channel records",
        ));
    };
    let Some(tag) = REJECTIONS
        .iter()
        .position(|r| r.as_str() == reason.as_str())
        .and_then(|i| u8::try_from(i).ok())
    else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the audit relay does not know this rejection reason",
        ));
    };
    let id = record.container_id().map_or("", ContainerId::as_str);
    let Ok(id_len) = u8::try_from(id.len()) else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the container id is too long for the audit relay",
        ));
    };
    let at = record.timestamp().as_unix_duration();
    let mut frame = Vec::with_capacity(FIXED_LEN + id.len());
    frame.push(tag);
    frame.extend_from_slice(&at.as_secs().to_be_bytes());
    frame.extend_from_slice(&at.subsec_nanos().to_be_bytes());
    frame.extend_from_slice(&record.pid().get().to_be_bytes());
    frame.push(id_len);
    frame.extend_from_slice(id.as_bytes());
    Ok(frame)
}

/// 枠から記録を組み直す。壊れた枠は `None`（記録を捏造しない）。
fn decode(frame: &[u8]) -> Option<AuditRecord> {
    let tag = *frame.first()?;
    let secs = u64::from_be_bytes(frame.get(1..9)?.try_into().ok()?);
    let nanos = u32::from_be_bytes(frame.get(9..13)?.try_into().ok()?);
    let pid = u32::from_be_bytes(frame.get(13..17)?.try_into().ok()?);
    let id_len = usize::from(*frame.get(17)?);
    let id = frame.get(FIXED_LEN..)?;
    if id.len() != id_len || nanos >= 1_000_000_000 {
        return None;
    }
    let rejection = *REJECTIONS.get(usize::from(tag))?;
    let at = AuditTimestamp::from_unix_duration(Duration::new(secs, nanos));
    let pid = AuditPid::new(i32::try_from(pid).ok()?).ok()?;
    let mut record = AuditRecord::new(at, pid, rejection.audit_event());
    if !id.is_empty() {
        record = record.with_container_id(ContainerId::new(std::str::from_utf8(id).ok()?).ok()?);
    }
    Some(record)
}

/// helper の本体。枠を読んで `sink` に記録し、結果を 1 バイトで返す。EOF（親の終了）で終わる。
fn serve(mut stream: UnixStream, sink: &FileAuditSink) -> i32 {
    loop {
        let mut head = [0u8; FIXED_LEN];
        if stream.read_exact(&mut head).is_err() {
            return 0;
        }
        let id_len = usize::from(head.last().copied().unwrap_or(0));
        let mut frame = head.to_vec();
        frame.resize(FIXED_LEN + id_len, 0);
        if let Some(body) = frame.get_mut(FIXED_LEN..)
            && stream.read_exact(body).is_err()
        {
            return 1;
        }
        let ok = decode(&frame).is_some_and(|r| sink.record(&r).is_ok());
        if stream
            .write_all(&[if ok { ACK_OK } else { ACK_FAIL }])
            .is_err()
        {
            return 1;
        }
    }
}

/// fd 0〜2 が閉じていても helper の `close_range(3, ..)` と衝突しないよう、fd を 3 以上へ移す。
fn dup_high(stream: UnixStream) -> Option<UnixStream> {
    let fd: OwnedFd = stream.into();
    sys::dup_fd_at_least(fd.as_fd(), 3)
        .ok()
        .map(UnixStream::from)
}

struct State {
    stream: UnixStream,
    broken: bool,
}

/// 単一スレッドの時点で fork した監査専用 helper へ制御チャネルの拒否を渡す [`AuditSink`]。
pub struct ControlAuditRelay {
    state: Mutex<State>,
    pid: u32,
    pidfd: Option<OwnedFd>,
}

impl std::fmt::Debug for ControlAuditRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlAuditRelay").finish_non_exhaustive()
    }
}

impl ControlAuditRelay {
    /// `sink` を持つ helper を fork する。呼び出しプロセスが複数スレッドなら `FailedPrecondition`。
    ///
    /// 呼び出し元: supervisor の `start`（制御チャネルの `install` の前、スレッドを作る前）。
    pub fn spawn(sink: FileAuditSink) -> Result<Self, TraitError> {
        let unavailable = || err(ErrorCode::Unavailable, "failed to start the audit relay");
        let (parent, child) = UnixStream::pair().map_err(|_| unavailable())?;
        let parent = dup_high(parent).ok_or_else(unavailable)?;
        let child = dup_high(child).ok_or_else(unavailable)?;
        let forked = sys::fork_single_threaded_no_flush(
            || {
                if sys::close_fds_from_except(3, child.as_fd()).is_err() {
                    return CLOSE_FDS_FAILED_EXIT;
                }
                serve(child, &sink)
            },
            2,
        );
        let pid = match forked {
            Ok(pid) => pid,
            Err(sys::SysError::MultiThreaded) => {
                return Err(err(
                    ErrorCode::FailedPrecondition,
                    "the audit relay must be started before any thread is created",
                ));
            }
            Err(_) => return Err(unavailable()),
        };
        // 回収前に開く（以後 pid が再利用されても元の子を指す）。
        let pidfd = sys::pidfd_open(pid).ok();
        Ok(Self {
            state: Mutex::new(State {
                stream: parent,
                broken: false,
            }),
            pid,
            pidfd,
        })
    }

    /// helper を SIGKILL する（pidfd 優先。無ければ未回収を確かめてから pid へ送る）。
    fn kill_helper(&self) {
        match &self.pidfd {
            Some(fd) => {
                let _ = sys::pidfd_send_signal(fd.as_fd(), sys::Signal::Kill);
            }
            None => {
                if matches!(sys::wait_pid_nohang(self.pid), Ok(None)) {
                    let _ = sys::kill_pid(self.pid, sys::Signal::Kill);
                }
            }
        }
    }
}

impl AuditSink for ControlAuditRelay {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        let frame = encode(record)?;
        let Ok(mut state) = self.state.lock() else {
            return Err(err(ErrorCode::Internal, "the audit relay lock is poisoned"));
        };
        if state.broken {
            return Err(err(
                ErrorCode::Unavailable,
                "the audit relay is unavailable",
            ));
        }
        let deadline = Instant::now() + RECORD_WAIT_LIMIT;
        let mut ack = [0u8; 1];
        let sent = state
            .stream
            .set_write_timeout(Some(RECORD_WAIT_LIMIT))
            .is_ok()
            && state.stream.write_all(&frame).is_ok();
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        let answered = sent
            && state.stream.set_read_timeout(Some(remaining)).is_ok()
            && state.stream.read_exact(&mut ack).is_ok();
        if !answered {
            state.broken = true;
            drop(state);
            self.kill_helper();
            return Err(err(
                ErrorCode::Timeout,
                "the audit relay did not answer in time",
            ));
        }
        if ack == [ACK_OK] {
            Ok(())
        } else {
            Err(err(
                ErrorCode::Internal,
                "the audit record was not persisted",
            ))
        }
    }
}

impl Drop for ControlAuditRelay {
    fn drop(&mut self) {
        self.kill_helper();
        let end = Instant::now() + REAP_WAIT;
        while Instant::now() < end {
            if !matches!(sys::wait_pid_nohang(self.pid), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rejection: ControlPeerRejection, id: Option<&str>) -> AuditRecord {
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(4242).unwrap(),
            rejection.audit_event(),
        );
        match id {
            Some(id) => r.with_container_id(ContainerId::new(id).unwrap()),
            None => r,
        }
    }

    /// SEC-4・SUP-1: 枠の往復で時刻・PID・理由・コンテナ ID が一致する。
    #[test]
    fn sec4_frame_round_trips_every_field() {
        for rejection in REJECTIONS {
            for id in [None, Some("web-1")] {
                let rec = sample(rejection, id);
                let back = decode(&encode(&rec).unwrap()).unwrap();
                assert_eq!(back.timestamp(), rec.timestamp());
                assert_eq!(back.pid(), rec.pid());
                assert_eq!(back.container_id(), rec.container_id());
                assert_eq!(
                    encode(&back).unwrap(),
                    encode(&rec).unwrap(),
                    "reason token must survive"
                );
            }
        }
    }

    /// SEC-4: 制御チャネル以外の層は運ばない。
    #[test]
    fn sec4_non_control_records_are_rejected() {
        use super::super::{AuditSyscallArch, AuditSyscallNr};
        let rec = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1, 0)),
            AuditPid::new(1).unwrap(),
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(1).unwrap(),
                arch: AuditSyscallArch::from_raw(0xC000_003E),
            },
        );
        assert_eq!(encode(&rec).unwrap_err().code(), ErrorCode::InvalidArgument);
    }

    /// REPAIR-2: 壊れた枠（短い・未知の理由・不正な時刻・PID 0）は記録にしない。
    #[test]
    fn repair2_malformed_frames_are_not_decoded() {
        let good = encode(&sample(ControlPeerRejection::PeerUidMismatch, Some("a"))).unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        assert!(decode(&[]).is_none());
        let mut bad_tag = good.clone();
        bad_tag[0] = 9;
        assert!(decode(&bad_tag).is_none());
        let mut bad_nanos = good.clone();
        bad_nanos[9..13].copy_from_slice(&1_000_000_000u32.to_be_bytes());
        assert!(decode(&bad_nanos).is_none());
        let mut zero_pid = good;
        zero_pid[13..17].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode(&zero_pid).is_none());
    }
}
