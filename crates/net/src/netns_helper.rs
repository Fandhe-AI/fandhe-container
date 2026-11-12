//! netns holder と netns-dial helper が共有する下位処理（Linux のみ。REPAIR-1・REPAIR-5・NET-9・CRI-6・SEC-1・#4510）。
//!
//! 呼び出し元は `crate::netns_holder::holder`（NET-9）と `crate::netns_dial::helper`（CRI-6）の 2 つの helper プロセス本体と、
//! 親側の `crate::netns_holder::channel`（supervisor）・`crate::netns_dial::channel`（plugin-cri）の期限つき受信と識別の
//! 取得（#4533。親側は多スレッドのプロセスで動く。期限つき受信と識別の取得はスレッド数を前提にしない）。
//! 両者は `setns(CLONE_NEWUSER)` の前に単一スレッドで動くため、親の照合・期限つき受信・fd と参加後の ns の識別の
//! 取得を別々に持つと、片方だけ直して欠陥が残る（#4498 の受信の修正が例）。本モジュールはその 4 つの本体を
//! 失敗の型に依存しない形で 1 か所に置き、失敗の `Fail` / `DialErrorCode` への写像は各 helper が持つ。
//! 例外として errno から `NetErrorCode` への分類（[`classify`]）も置く。`NetErrorCode` は crate 共通の分類で、holder 本体・
//! holder の親側 channel・dial の親側 channel の 3 か所が同じ写像を使い、複製すると片方だけ直す事故になるため（#4545）。
//! dial helper 本体は `DialErrorCode` への写像を持ち続け、`classify` は使わない。
//!
//! 契約: `unsafe` を持たない（syscall は `crate::sys` の安全なラッパーだけ）。スレッドを作らない。stderr・stdout へ
//! 書かない（dial は stderr null の契約）。ログを出さない。

use std::fs::File;
use std::os::fd::BorrowedFd;
use std::os::unix::fs::MetadataExt as _;
use std::time::Duration;

use crate::error::NetErrorCode;
use crate::sys::holder as sysh;
use crate::sys::{self, Deadline, Readiness, SysError};

/// 親の照合の失敗。holder は分類と文言を分けるため区別を保つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentCheckError {
    /// `SO_PEERCRED` を読めなかった。
    PeerCred(SysError),
    /// 親が 1（孤児化）か、socketpair の作成者でない。
    NotCreator,
}

/// 親が存在し、作成者（`SO_PEERCRED` の pid）と一致するかの述語（純関数）。
pub(crate) fn parent_is_creator(parent: u32, peer: u32) -> bool {
    parent != 1 && parent == peer
}

/// stdin の socketpair の作成者が親プロセスであることを確かめる。親が先に死ぬと `getppid` は 1 かサブリーパーに
/// 変わり不一致になる（PDEATHSIG の設定前に死んだ場合の備え）。
pub(crate) fn check_parent_is_creator(fd: BorrowedFd<'_>) -> Result<(), ParentCheckError> {
    let peer = sysh::peer_pid(fd).map_err(ParentCheckError::PeerCred)?;
    let parent = std::os::unix::process::parent_id();
    if parent_is_creator(parent, peer) {
        Ok(())
    } else {
        Err(ParentCheckError::NotCreator)
    }
}

/// errno の分類（12.9。REPAIR-1・NET-9・CRI-6・#4545）。`setns` の `EPERM` は PermissionDenied、`EINVAL`（型違い・自身の
/// userns を含む）とソケットでない stdin は FailedPrecondition。呼び出し元は holder 本体の `sys_fail`、holder の親側
/// channel の `sys_err`、dial の親側 channel の `sys_err`。未知の errno は Internal（fail-closed）。
pub(crate) fn classify(e: SysError) -> NetErrorCode {
    match e {
        SysError::Unsupported => NetErrorCode::Unimplemented,
        SysError::Os(n) if n == sys::EPERM || n == sys::EACCES => NetErrorCode::PermissionDenied,
        SysError::Os(n) if n == sys::EINVAL || n == sysh::ENOTSOCK || n == sysh::EPIPE => {
            NetErrorCode::FailedPrecondition
        }
        SysError::Os(n) if n == sys::EMFILE || n == sys::ENFILE || n == sys::ENOMEM => {
            NetErrorCode::ResourceExhausted
        }
        _ => NetErrorCode::Internal,
    }
}

/// poll の後に recv が `EAGAIN` / `EINTR` だったときの待ち直しの間隔（HUP だけの場合に空回りしないため）。
pub(crate) const RECV_RETRY_INTERVAL: Duration = Duration::from_millis(1);

/// 期限つき受信の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecvError {
    /// `poll(2)` の失敗。
    Wait(SysError),
    /// 期限切れ。
    TimedOut,
    /// `recvmsg(2)` の失敗。
    Recv(SysError),
}

/// 期限つきで 1 通受ける。`Exceptional`（HUP 等）でも recv を試み、EOF は長さ 0 として `Ok` で返る。
/// 切り詰めの判定と decode は呼び出し側が行う（判定の意味が helper ごとに違うため）。
pub(crate) fn recv_before_deadline(
    fd: BorrowedFd<'_>,
    deadline: &Deadline,
    buf: &mut [u8],
    max_fds: usize,
) -> Result<sysh::Received, RecvError> {
    recv_loop_before_deadline(fd, deadline, || sysh::recv_with_fds(fd, buf, max_fds))
}

/// 期限つき受信のループ本体（helper と親側 channel の唯一の実装。#4533）。受信そのものは `recv` が行う。
/// fd の受信上限（dial は 1、holder の READY は 0）は呼び出し側が `recv` の中で決める（SEC-1）。
pub(crate) fn recv_loop_before_deadline(
    fd: BorrowedFd<'_>,
    deadline: &Deadline,
    mut recv: impl FnMut() -> Result<sysh::Received, SysError>,
) -> Result<sysh::Received, RecvError> {
    loop {
        match sys::wait_readable(fd, deadline) {
            Err(e) => return Err(RecvError::Wait(e)),
            Ok(Readiness::TimedOut) => return Err(RecvError::TimedOut),
            Ok(Readiness::Readable | Readiness::Exceptional) => {}
        }
        match recv() {
            Ok(r) => return Ok(r),
            // poll の後に消えた・シグナル中断。残り時間で待ち直す。
            Err(SysError::Os(n)) if n == sys::EAGAIN || n == sys::EINTR => {
                if deadline.remaining().is_zero() {
                    return Err(RecvError::TimedOut);
                }
                std::thread::sleep(RECV_RETRY_INTERVAL);
            }
            Err(e) => return Err(RecvError::Recv(e)),
        }
    }
}

/// fd の識別（`fstat` の dev・ino）。
pub(crate) fn fd_identity(file: &File) -> std::io::Result<(u64, u64)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino()))
}

/// 参加後に識別を読む ns。任意の文字列から `/proc/self/ns/<任意>` を組めないよう型で固定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinedNs {
    User,
    Net,
}

impl JoinedNs {
    fn proc_path(self) -> &'static str {
        match self {
            JoinedNs::User => "/proc/self/ns/user",
            JoinedNs::Net => "/proc/self/ns/net",
        }
    }
}

/// 参加後の自分の ns の識別の取得の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelfNsError {
    Open,
    Stat,
}

/// 参加後の自分の ns の識別（`/proc/self/ns/<name>` の dev・ino）。
pub(crate) fn self_ns_identity(ns: JoinedNs) -> Result<(u64, u64), SelfNsError> {
    let f = File::open(ns.proc_path()).map_err(|_| SelfNsError::Open)?;
    fd_identity(&f).map_err(|_| SelfNsError::Stat)
}

#[cfg(test)]
mod tests {
    /// 12.9: errno の分類（具体値。REPAIR-1・#4545）。
    #[test]
    fn repair1_4545_classify_maps_errno_to_codes() {
        for n in [sys::EPERM, sys::EACCES] {
            assert_eq!(classify(SysError::Os(n)), NetErrorCode::PermissionDenied);
        }
        for n in [sys::EINVAL, sysh::ENOTSOCK, sysh::EPIPE] {
            assert_eq!(classify(SysError::Os(n)), NetErrorCode::FailedPrecondition);
        }
        for n in [sys::EMFILE, sys::ENFILE, sys::ENOMEM] {
            assert_eq!(classify(SysError::Os(n)), NetErrorCode::ResourceExhausted);
        }
        assert_eq!(classify(SysError::Os(sys::ENOENT)), NetErrorCode::Internal);
        assert_eq!(classify(SysError::BadSenderAddress), NetErrorCode::Internal);
        assert_eq!(classify(SysError::BadLocalAddress), NetErrorCode::Internal);
        assert_eq!(classify(SysError::Unsupported), NetErrorCode::Unimplemented);
    }

    use super::*;
    use std::os::fd::AsFd as _;
    use std::time::Instant;

    /// REPAIR-1・SEC-1・#4510: 親の述語の表。親が 1 は常に拒否。
    #[test]
    fn repair1_4510_parent_is_creator_table() {
        assert!(parent_is_creator(100, 100));
        assert!(!parent_is_creator(1, 1));
        assert!(!parent_is_creator(100, 101));
    }

    /// SEC-1・#4510: 自プロセスが作った対の peer は自分で、親ではない。
    #[test]
    fn sec1_4510_check_parent_rejects_self_created_pair() {
        let (a, _b) = sysh::socketpair_seqpacket().unwrap();
        assert_eq!(
            check_parent_is_creator(a.as_fd()),
            Err(ParentCheckError::NotCreator)
        );
    }

    /// SEC-1・#4510: ソケットでない fd は peer cred の失敗。
    #[test]
    fn sec1_4510_check_parent_on_non_socket_is_peer_cred_error() {
        let f = File::open("/dev/null").unwrap();
        assert!(matches!(
            check_parent_is_creator(f.as_fd()),
            Err(ParentCheckError::PeerCred(SysError::Os(n))) if n == sysh::ENOTSOCK
        ));
    }

    /// REPAIR-5・#4510: データが来ないと期限で TimedOut。
    #[test]
    fn repair5_4510_recv_times_out_at_deadline() {
        let (a, _b) = sysh::socketpair_seqpacket().unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 16];
        let r = recv_before_deadline(
            a.as_fd(),
            &Deadline::after(Duration::from_millis(100)),
            &mut buf,
            2,
        );
        assert!(matches!(r, Err(RecvError::TimedOut)), "{r:?}");
        let e = started.elapsed();
        assert!(
            e >= Duration::from_millis(100) && e < Duration::from_secs(2),
            "{e:?}"
        );
    }

    /// REPAIR-5・#4510: 相手が閉じると EOF が長さ 0 の Ok で返る（Exceptional でも recv する）。
    #[test]
    fn repair5_4510_recv_returns_eof_as_zero_length() {
        let (a, b) = sysh::socketpair_seqpacket().unwrap();
        drop(b);
        let mut buf = [0u8; 16];
        let r = recv_before_deadline(
            a.as_fd(),
            &Deadline::after(Duration::from_secs(2)),
            &mut buf,
            2,
        )
        .unwrap();
        assert_eq!((r.len, r.fds.len()), (0, 0));
    }

    /// NET-9・#4510: 4 バイトと fd 2 本を受ける。
    #[test]
    fn net9_4510_recv_returns_frame_and_fds() {
        let (a, b) = sysh::socketpair_seqpacket().unwrap();
        let f1 = File::open("/dev/null").unwrap();
        let f2 = File::open("/dev/null").unwrap();
        sysh::send_with_fds(b.as_fd(), b"abcd", &[f1.as_fd(), f2.as_fd()], true).unwrap();
        let mut buf = [0u8; 16];
        let r = recv_before_deadline(
            a.as_fd(),
            &Deadline::after(Duration::from_secs(2)),
            &mut buf,
            2,
        )
        .unwrap();
        assert_eq!((r.len, r.fds.len()), (4, 2));
        assert!(!r.ctrl_truncated && !r.data_truncated);
    }

    /// REPAIR-5・#4510: recv の失敗は Recv に写る。
    #[test]
    fn repair5_4510_recv_on_non_socket_is_recv_error() {
        let f = File::open("/dev/null").unwrap();
        let mut buf = [0u8; 16];
        let r = recv_before_deadline(
            f.as_fd(),
            &Deadline::after(Duration::from_secs(2)),
            &mut buf,
            2,
        );
        assert!(
            matches!(r, Err(RecvError::Recv(SysError::Os(n))) if n == sysh::ENOTSOCK),
            "{r:?}"
        );
    }

    /// CRI-6・#4510: fd の識別は metadata の dev・ino と一致する。
    #[test]
    fn cri6_4510_fd_identity_matches_metadata() {
        let f = File::open("/dev/null").unwrap();
        let m = std::fs::metadata("/dev/null").unwrap();
        assert_eq!(fd_identity(&f).unwrap(), (m.dev(), m.ino()));
    }

    /// NET-9・#4510: 自分の ns の識別は /proc/self/ns の metadata と一致する。
    #[test]
    fn net9_4510_self_ns_identity_matches_proc() {
        for (ns, path) in [
            (JoinedNs::Net, "/proc/self/ns/net"),
            (JoinedNs::User, "/proc/self/ns/user"),
        ] {
            assert_eq!(ns.proc_path(), path);
            let m = std::fs::metadata(path).unwrap();
            assert_eq!(self_ns_identity(ns), Ok((m.dev(), m.ino())));
        }
    }

    fn ready_pair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        let (a, b) = sysh::socketpair_seqpacket().unwrap();
        // 1 通置いたままにして readable を続けさせる（偽の recv は読まない）。
        sysh::send_with_fds(b.as_fd(), b"x", &[], true).unwrap();
        (a, b)
    }

    fn ok_recv() -> Result<sysh::Received, SysError> {
        Ok(sysh::Received {
            len: 4,
            data_truncated: false,
            ctrl_truncated: false,
            fds: vec![],
        })
    }

    /// REPAIR-5・#4533: EAGAIN / EINTR は待ち直して次の recv の成功を返す。
    #[test]
    fn repair5_4533_recv_loop_retries_eagain_and_eintr_then_succeeds() {
        let (a, _b) = ready_pair();
        let mut calls = 0u32;
        let started = Instant::now();
        let r =
            recv_loop_before_deadline(a.as_fd(), &Deadline::after(Duration::from_secs(2)), || {
                calls += 1;
                match calls {
                    1 | 3 => Err(SysError::Os(sys::EAGAIN)),
                    2 => Err(SysError::Os(sys::EINTR)),
                    _ => ok_recv(),
                }
            })
            .unwrap();
        assert_eq!((calls, r.len), (4, 4));
        let e = started.elapsed();
        assert!(
            e >= 3 * RECV_RETRY_INTERVAL && e < Duration::from_secs(2),
            "{e:?}"
        );
    }

    /// REPAIR-5・#4533: EAGAIN が続くと期限で TimedOut。
    #[test]
    fn repair5_4533_recv_loop_eagain_until_deadline_is_timed_out() {
        let (a, _b) = ready_pair();
        let mut calls = 0u32;
        let started = Instant::now();
        let r = recv_loop_before_deadline(
            a.as_fd(),
            &Deadline::after(Duration::from_millis(100)),
            || {
                calls += 1;
                Err(SysError::Os(sys::EAGAIN))
            },
        );
        assert!(matches!(r, Err(RecvError::TimedOut)), "{r:?}");
        let e = started.elapsed();
        assert!(
            e >= Duration::from_millis(100) && e < Duration::from_secs(2),
            "{e:?}"
        );
        assert!(calls >= 1);
    }

    /// REPAIR-5・#4533: その他の errno は待ち直さず Recv。
    #[test]
    fn repair5_4533_recv_loop_other_errno_is_recv_error() {
        let (a, _b) = ready_pair();
        let mut calls = 0u32;
        let r =
            recv_loop_before_deadline(a.as_fd(), &Deadline::after(Duration::from_secs(2)), || {
                calls += 1;
                Err(SysError::Os(sys::EINVAL))
            });
        assert!(
            matches!(r, Err(RecvError::Recv(SysError::Os(n))) if n == sys::EINVAL),
            "{r:?}"
        );
        assert_eq!(calls, 1);
    }
}
