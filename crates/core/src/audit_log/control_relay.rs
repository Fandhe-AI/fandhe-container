//! 複数スレッドのプロセスから制御チャネルの拒否と seccomp の拒否を期限付きで永続化する中継（Linux。SEC-4・REPAIR-5・SUP-1・SEC-1・#2058）。
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
//! - 運べるのは [`AuditEvent::ControlPeer`] と [`AuditEvent::Seccomp`] の記録だけ（他の層は `InvalidArgument`）。時刻・PID・
//!   コンテナ ID・理由トークン（seccomp は種別トークンと syscall 番号・arch）を固定の枠で送り、helper が [`AuditRecord`] を
//!   組み直す（生のバイト列を記録として扱わない。REPAIR-2）。seccomp の記録は supervisor の seccomp 通知ループ
//!   （`record_seccomp_denial_for` 経由。SEC-4・REPAIR-5・#2025）が書く
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
    AuditEvent, AuditPid, AuditRecord, AuditSink, AuditSyscallArch, AuditSyscallNr, AuditTimestamp,
    ControlPeerRejection, FileAuditSink, RECORD_WAIT_LIMIT,
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

/// seccomp の記録を示す先頭バイト（`REJECTIONS` の添字と重ならない値）。コンテナ ID の後に syscall 番号（u32）と arch（u32）が付く。
const TAG_SECCOMP: u8 = 0x80;
/// seccomp の枠だけが持つ追加部（番号 4・arch 4）。
const SECCOMP_EXTRA_LEN: usize = 8;

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
    let (tag, extra) = match record.event() {
        AuditEvent::ControlPeer { reason } => {
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
            (tag, None)
        }
        AuditEvent::Seccomp { syscall, arch } => (TAG_SECCOMP, Some((syscall.get(), arch.get()))),
        _ => {
            return Err(err(
                ErrorCode::InvalidArgument,
                "the audit relay only carries control channel and seccomp records",
            ));
        }
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
    if let Some((nr, arch)) = extra {
        frame.extend_from_slice(&nr.to_be_bytes());
        frame.extend_from_slice(&arch.to_be_bytes());
    }
    Ok(frame)
}

/// 枠から記録を組み直す。壊れた枠は `None`（記録を捏造しない）。
fn decode(frame: &[u8]) -> Option<AuditRecord> {
    let tag = *frame.first()?;
    let secs = u64::from_be_bytes(frame.get(1..9)?.try_into().ok()?);
    let nanos = u32::from_be_bytes(frame.get(9..13)?.try_into().ok()?);
    let pid = u32::from_be_bytes(frame.get(13..17)?.try_into().ok()?);
    let id_len = usize::from(*frame.get(17)?);
    let rest = frame.get(FIXED_LEN..)?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    let (id, event) = if tag == TAG_SECCOMP {
        // 長さは厳密に一致させる（余りも不足も壊れた枠）。
        if rest.len() != id_len.checked_add(SECCOMP_EXTRA_LEN)? {
            return None;
        }
        let (id, extra) = rest.split_at(id_len);
        let nr = u32::from_be_bytes(extra.get(0..4)?.try_into().ok()?);
        let arch = u32::from_be_bytes(extra.get(4..8)?.try_into().ok()?);
        (
            id,
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::from_seccomp_data_nr(nr.cast_signed()),
                arch: AuditSyscallArch::from_raw(arch),
            },
        )
    } else {
        if rest.len() != id_len {
            return None;
        }
        (rest, REJECTIONS.get(usize::from(tag))?.audit_event())
    };
    let at = AuditTimestamp::from_unix_duration(Duration::new(secs, nanos));
    let pid = AuditPid::new(i32::try_from(pid).ok()?).ok()?;
    let mut record = AuditRecord::new(at, pid, event);
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
        let extra = if head.first() == Some(&TAG_SECCOMP) {
            SECCOMP_EXTRA_LEN
        } else {
            0
        };
        let mut frame = head.to_vec();
        frame.resize(FIXED_LEN + id_len + extra, 0);
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
    /// fork 直後に未回収の自分の子と確認できなければ `Unavailable`（pid を保持しない）。
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
        // 開いた後に未回収の自分の子だと確かめる。SIGCHLD が SIG_IGN／SA_NOCLDWAIT だと fork から
        // pidfd_open までの間に自動回収・PID 再利用が起き得る。確認できなければ helper は既に終了して
        // いる（または自分の子でない）ため、pidfd も数値 pid も保持せず起動失敗にする（どの経路でも
        // 送信・wait しない。fail-closed。回収済みなので回収の後始末は不要。SUP-1・SEC-4・CORE-1）。
        let pidfd = sys::pidfd_open(pid).ok();
        if !is_unreaped_own_child(sys::wait_pid_nohang(pid)) {
            return Err(unavailable());
        }
        Ok(Self {
            state: Mutex::new(State {
                stream: parent,
                broken: false,
            }),
            pid,
            pidfd,
        })
    }

    /// helper の PID。呼び出し元（supervisor）が cgroup の退避で自プロセスと一緒に移す対象として宣言する
    /// （`DelegatedCgroup::with_companions`。helper が委譲 cgroup に残ると退避が拒否される。CORE-3・SUP-1）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// helper を SIGKILL する。どの経路でも、未回収の自分の子と確認できた場合だけ送る
    /// （pidfd があればそれへ、無ければ pid へ。確認できなければ送らない。SUP-1・SEC-4）。
    fn kill_helper(&self) {
        kill_if_unreaped(sys::wait_pid_nohang(self.pid), || match &self.pidfd {
            Some(fd) => sys::pidfd_send_signal(fd.as_fd(), sys::Signal::Kill),
            None => sys::kill_pid(self.pid, sys::Signal::Kill),
        });
    }
}

/// `wait_pid_nohang` の結果が「自分の未回収の子（まだ終わっていない）」を示すか。
/// `ECHILD`（自動回収済み・他人の PID）やその他のエラー、回収済みは false（fail-closed）。
fn is_unreaped_own_child(polled: Result<Option<i32>, sys::SysError>) -> bool {
    matches!(polled, Ok(None))
}

/// 未回収の自分の子と確認できた場合だけ `send` を呼ぶ。呼んだら true。
fn kill_if_unreaped<E>(
    polled: Result<Option<i32>, sys::SysError>,
    send: impl FnOnce() -> Result<(), E>,
) -> bool {
    if !is_unreaped_own_child(polled) {
        return false;
    }
    let _ = send();
    true
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

    /// SUP-1・SEC-4・CORE-1: 確認できない場合は送信 0 回（pidfd・pid どちらの送信手段でも同じ）。
    #[test]
    fn kill_if_unreaped_unverified_sends_zero_times() {
        let mut sent = 0;
        let r = kill_if_unreaped(Err(sys::SysError::Os(10)), || {
            sent += 1;
            Ok::<(), ()>(())
        });
        assert_eq!((r, sent), (false, 0));
    }

    /// SUP-1・SEC-4: 未回収と確認できない場合（ECHILD・他エラー・回収済み）は送信しない。
    #[test]
    fn kill_if_unreaped_sends_only_for_unreaped_child() {
        let mut sent = 0;
        assert!(kill_if_unreaped(Ok(None), || {
            sent += 1;
            Ok::<(), ()>(())
        }));
        assert_eq!(sent, 1);
        for polled in [
            Ok(Some(0)),
            Err(sys::SysError::Os(10)),
            Err(sys::SysError::Os(22)),
        ] {
            assert!(!kill_if_unreaped(polled, || {
                sent += 1;
                Ok::<(), ()>(())
            }));
        }
        assert_eq!(sent, 1);
    }

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

    /// SEC-4: 運ぶのは制御チャネルと seccomp だけ。それ以外の層（Mount）は拒否する。
    #[test]
    fn sec4_other_layers_are_rejected() {
        let rec = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1, 0)),
            AuditPid::new(1).unwrap(),
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        assert_eq!(encode(&rec).unwrap_err().code(), ErrorCode::InvalidArgument);
    }

    fn seccomp_sample(nr: i32, arch: u32, id: Option<&str>) -> AuditRecord {
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 7)),
            AuditPid::new(77).unwrap(),
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::from_seccomp_data_nr(nr),
                arch: AuditSyscallArch::from_raw(arch),
            },
        );
        match id {
            Some(id) => r.with_container_id(ContainerId::new(id).unwrap()),
            None => r,
        }
    }

    /// SEC-4・#2025: seccomp の枠は番号・arch・PID・コンテナ ID が往復で一致する（負の番号のビット列も保つ）。
    #[test]
    fn sec4_2025_seccomp_frame_round_trips() {
        for (nr, arch, id) in [
            (312, 0xC000_003E, Some("web-1")),
            (272, 0xC000_00B7, None),
            (-1, 0xDEAD_BEEF, Some("a")),
        ] {
            let rec = seccomp_sample(nr, arch, id);
            let frame = encode(&rec).unwrap();
            assert_eq!(
                frame.len(),
                FIXED_LEN + id.map_or(0, str::len) + SECCOMP_EXTRA_LEN
            );
            let back = decode(&frame).unwrap();
            assert_eq!(
                back.syscall().map(AuditSyscallNr::get),
                Some(nr.cast_unsigned())
            );
            assert_eq!(back.seccomp_arch().map(AuditSyscallArch::get), Some(arch));
            assert_eq!(back.pid(), rec.pid());
            assert_eq!(back.timestamp(), rec.timestamp());
            assert_eq!(back.container_id(), rec.container_id());
        }
    }

    /// REPAIR-2・#2025: seccomp の壊れた枠（追加部の不足・余り・ID 長の不一致）は記録にしない。
    #[test]
    fn repair2_2025_malformed_seccomp_frames_are_not_decoded() {
        let good = encode(&seccomp_sample(312, 0xC000_003E, Some("ab"))).unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
        let mut wrong_len = good;
        wrong_len[17] = 3;
        assert!(decode(&wrong_len).is_none());
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
