//! seccomp の listener fd の受け渡し（SEC-4・TASK-41 追補・#2024。監査配送 2/6。方式は
//! `docs/design/audit-delivery.md`）。
//!
//! # 役割と呼び出し文脈
//!
//! コンテナの PID 1（または exec の worker）が seccomp の最終段で `NEW_LISTENER` 付きで filter を載せ、得た
//! listener fd を起動側（supervisor 側のプロセス C）へ socketpair の `SCM_RIGHTS` で渡す。
//! `exec/seccomp.rs` の `apply_default_seccomp_with_listener` が [`ListenerSender::hand_over`] を呼び、
//! `exec/launch_intermediate.rs` の launch 経路（と exec の経路）が [`receive_listener`] で受け取る。
//! 受け取った [`SeccompListener`] は `LaunchedProcess::take_seccomp_listener` で supervisor へ渡る。
//! 通知を読んで応答するループ（PID 変換・`record_seccomp_denial`・`EPERM` 応答）は #2025 が担い、本モジュールは
//! 取得と受け渡しだけを担う。**本番の filter は当面 ERRNO 版のまま**（`USER_NOTIF` を返さない）なので通知は生じず、
//! listener を保持するだけでコンテナの挙動は変わらない（`audit-delivery.md` 9 章の案 2 の段階実装）。
//!
//! # ワイヤー形式（REPAIR-2。AF_UNIX `SOCK_SEQPACKET` の socketpair。パスを持たない）
//!
//! | 方向 | 内容 |
//! | ---- | ---- |
//! | 子 → C | 本文 1 バイト `L`（[`TOKEN_LISTENER`]）＋ `SCM_RIGHTS` の fd 1 本（listener）。受信側の `SO_PASSCRED` により送信元の pid が付く |
//! | C → 子 | 本文 1 バイト `A`（[`ACK`]）。受領と検証の完了。子はこれを待ってから exec に進む |
//!
//! # 受信側の検証（PLUG-12 と同じ系統。fail-closed）
//!
//! `SO_PEERCRED` は socketpair では作成者（C 自身）を両端で返すため検証の根拠にならず使わない。代わりに次をすべて
//! 満たすときだけ受理し、満たさなければ受け取った fd をすべて閉じて拒否する。
//!
//! - 切り詰め（`MSG_TRUNC` / `MSG_CTRUNC`）が無い・本文がちょうど `L` 1 バイト
//! - `SCM_RIGHTS` の fd がちょうど 1 本
//! - `SCM_CREDENTIALS` の pid が、C が起動した子（PID 1 または worker）の pid と一致する（pid は C の PID namespace へ
//!   カーネルが変換する）。uid は照合しない: 子は新しい user namespace の写像下にあり、C から導ける期待値が
//!   権限モデル（単一 ID 写像・範囲写像）で変わる。socketpair の子の端を持つのは C が起動した子だけなので、pid の
//!   一致で送信元を特定できる
//! - fd が close-on-exec（`MSG_CMSG_CLOEXEC`）で、種別が `anon_inode:seccomp notify`
//!
//! # 漏れの防止（分離）
//!
//! listener を workload（execve 後）が持つと、自分の通知に自分で応答して拒否を回避できる。listener はカーネルが
//! `O_CLOEXEC` で作り、子は送信後に自分の fd を閉じ、socket も `SOCK_CLOEXEC` で、ACK の後に閉じる。
//!
//! # 制約
//!
//! - ワークロードが自分で `NEW_LISTENER` 付きの filter を載せる、または祖先の filter が既に listener を持つ環境では
//!   `EBUSY` になる。後者の launch は `FailedPrecondition`（段 `Seccomp`）で失敗する（fail-closed）
//! - Linux 5.0 未満は対象外

use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use super::{ExecError, IsolationStage};
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

/// listener を送るときの本文（1 バイト）。
pub(crate) const TOKEN_LISTENER: u8 = b'L';
/// 受領の確認応答の本文（1 バイト）。
pub(crate) const ACK: u8 = b'A';
/// 子が ACK を待つ上限（C は受信直後に返すため通常は即時。launch の開始ゲートと同じ値。REPAIR-5）。
pub(crate) const ACK_TIMEOUT: Duration = Duration::from_secs(60);
/// listener fd の種別（`/proc/self/fd/N` の readlink）。
const NOTIFY_FD_KIND: &str = "anon_inode:seccomp notify";

/// seccomp の listener fd（通知の受信側）。supervisor が監視の間保持する。
///
/// 検証付きの受信でしか作れない（公開コンストラクタを持たない）。`Clone` を持たず、drop で閉じる。閉じると
/// カーネルは `USER_NOTIF` 側の待機中の syscall を `ENOSYS` にする。
#[derive(Debug)]
pub struct SeccompListener(OwnedFd);

impl SeccompListener {
    /// 通知の読み取り（#2025）に使う借用。
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// 子（PID 1 / worker）側の送信口。socketpair の子の端を所有する。
#[derive(Debug)]
pub(crate) struct ListenerSender(OwnedFd);

impl ListenerSender {
    pub(crate) fn new(child_end: OwnedFd) -> Self {
        Self(child_end)
    }

    /// `listener` を C へ送り、自分の fd を閉じ、C の ACK を期限つきで待つ。どれかが失敗したら exec に進ませない
    /// （段 `Seccomp` の `ExecError`）。
    pub(crate) fn hand_over(self, listener: OwnedFd, timeout: Duration) -> Result<(), ExecError> {
        const STAGE: IsolationStage = IsolationStage::Seccomp;
        sys::seccomp_notify::send_fd_with_token(self.0.as_fd(), TOKEN_LISTENER, listener.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "send of the seccomp listener"))?;
        // 手元の listener を閉じる（workload が持たないように）。
        drop(listener);
        let deadline = Instant::now() + timeout;
        match wait_readable(self.0.as_fd(), deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ExecError::new(
                    ErrorCode::Timeout,
                    STAGE,
                    "the launcher did not acknowledge the seccomp listener in time",
                ));
            }
            Err(e) => return Err(ExecError::from_sys(e, STAGE, "wait for the listener ACK")),
        }
        let mut buf = [0u8; 2];
        let n = sys::seccomp_notify::recv_nowait(self.0.as_fd(), &mut buf)
            .map_err(|e| ExecError::from_sys(e, STAGE, "receive of the listener ACK"))?;
        if n == 1 && buf.first() == Some(&ACK) {
            Ok(())
        } else {
            Err(ExecError::new(
                ErrorCode::Internal,
                STAGE,
                "the launcher rejected or dropped the seccomp listener",
            ))
        }
    }
}

/// `deadline` まで `fd` が読み取り可能になるのを待つ（`EINTR` は残り時間で再試行）。時間切れは `false`。
fn wait_readable(fd: BorrowedFd<'_>, deadline: Instant) -> Result<bool, SysError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let ms = i32::try_from(remaining.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX);
        match sys::poll_readable(fd, ms) {
            Ok(true) => return Ok(true),
            Ok(false) => {
                if Instant::now() >= deadline {
                    return Ok(false);
                }
            }
            Err(SysError::Os(e)) if e == sys::EINTR => {
                if Instant::now() >= deadline {
                    return Ok(false);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// 受信した 1 通の検証（純粋な判定。fd は `received` の drop で閉じる）。受理なら listener を返し、拒否なら
/// 固定の理由語を返す。
fn validate(
    received: sys::seccomp_notify::ReceivedFd,
    expected_pid: u32,
) -> Result<OwnedFd, &'static str> {
    let sys::seccomp_notify::ReceivedFd {
        payload,
        mut fds,
        creds,
        truncated,
    } = received;
    if payload.is_empty() && fds.is_empty() {
        return Err("the sender closed before delivering the seccomp listener");
    }
    if truncated {
        return Err("the listener message was truncated");
    }
    if payload.as_slice() != [TOKEN_LISTENER] {
        return Err("the listener message had an unexpected payload");
    }
    if fds.len() != 1 {
        return Err("the listener message did not carry exactly one fd");
    }
    let Some(creds) = creds else {
        return Err("the listener message carried no sender credentials");
    };
    if u32::try_from(creds.pid).ok() != Some(expected_pid) {
        return Err("the listener message came from an unexpected process");
    }
    let Some(fd) = fds.pop() else {
        return Err("the listener message did not carry exactly one fd");
    };
    match sys::seccomp_notify::fd_is_cloexec(fd.as_fd()) {
        Ok(true) => {}
        _ => return Err("the received fd is not close-on-exec"),
    }
    let kind = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok();
    if kind.as_deref().and_then(|p| p.to_str()) != Some(NOTIFY_FD_KIND) {
        return Err("the received fd is not a seccomp notification fd");
    }
    Ok(fd)
}

/// 子の端と対になる C の端から listener を受け取って検証し、ACK を返す。
///
/// `expected_pid` は C が起動した子（launch は PID 1、exec は worker）の pid。`deadline` までに届かなければ
/// `Timeout`、EOF（子が送る前に死んだ）・検証の不一致は `Internal`（段 `Seccomp`）。呼び出し側が子を回収する。
pub(crate) fn receive_listener(
    sock: BorrowedFd<'_>,
    expected_pid: u32,
    deadline: Instant,
) -> Result<SeccompListener, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Seccomp;
    match wait_readable(sock, deadline) {
        Ok(true) => {}
        Ok(false) => {
            return Err(ExecError::new(
                ErrorCode::Timeout,
                STAGE,
                "the seccomp listener was not delivered in time",
            ));
        }
        Err(e) => {
            return Err(ExecError::from_sys(
                e,
                STAGE,
                "wait for the seccomp listener",
            ));
        }
    }
    let received = sys::seccomp_notify::recv_fd_with_creds(sock)
        .map_err(|e| ExecError::from_sys(e, STAGE, "receive of the seccomp listener"))?;
    let fd = validate(received, expected_pid)
        .map_err(|why| ExecError::new(ErrorCode::Internal, STAGE, why))?;
    sys::send_nonblocking_unix(sock, &[ACK])
        .map_err(|e| ExecError::from_sys(e, STAGE, "send of the listener ACK"))?;
    Ok(SeccompListener(fd))
}

/// 新しい socketpair（C の端、子の端）。C の端には `SO_PASSCRED` を設定済み（送信の前に必要）。
/// どちらも fd 3 以上へ置く（子の標準入出力の付け替えで潰されないように）。
pub(crate) fn listener_socketpair() -> Result<(OwnedFd, OwnedFd), ExecError> {
    const STAGE: IsolationStage = IsolationStage::Spawn;
    let (parent_end, child_end) = sys::seccomp_notify::unix_seqpacket_pair()
        .map_err(|e| ExecError::from_sys(e, STAGE, "create the listener socketpair"))?;
    sys::seccomp_notify::set_passcred(parent_end.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "enable SO_PASSCRED"))?;
    Ok((
        super::process::keep_above_stdio(parent_end)?,
        super::process::keep_above_stdio(child_end)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sys::seccomp_notify::{ReceivedFd, Ucred};

    fn me() -> u32 {
        std::process::id()
    }

    fn pipe_fd() -> OwnedFd {
        let (r, _w) = std::io::pipe().unwrap();
        OwnedFd::from(r)
    }

    fn msg(payload: &[u8], fds: Vec<OwnedFd>, pid: Option<u32>, truncated: bool) -> ReceivedFd {
        ReceivedFd {
            payload: payload.to_vec(),
            fds,
            creds: pid.map(|p| Ucred {
                pid: i32::try_from(p).unwrap(),
                uid: 0,
                gid: 0,
            }),
            truncated,
        }
    }

    /// 実 listener を使い捨てスレッドで作る（filter の適用はスレッド単位。通知は生じない ERRNO 版）。
    fn real_listener() -> OwnedFd {
        std::thread::spawn(|| {
            assert_eq!(sys::set_no_new_privs(), Ok(()));
            let p = crate::seccomp::build_filter_for_target_arch().unwrap();
            sys::seccomp_notify::seccomp_set_filter_new_listener(&p).unwrap()
        })
        .join()
        .unwrap()
    }

    /// SEC-4: 拒否する条件の表（理由語を具体値で照合する）。
    #[test]
    fn sec4_validate_rejects_every_malformed_message() {
        let cases: Vec<(&str, ReceivedFd, &str)> = vec![
            (
                "eof",
                msg(b"", vec![], None, false),
                "the sender closed before delivering the seccomp listener",
            ),
            (
                "truncated",
                msg(b"L", vec![pipe_fd()], Some(me()), true),
                "the listener message was truncated",
            ),
            (
                "token",
                msg(b"X", vec![pipe_fd()], Some(me()), false),
                "the listener message had an unexpected payload",
            ),
            (
                "no fd",
                msg(b"L", vec![], Some(me()), false),
                "the listener message did not carry exactly one fd",
            ),
            (
                "two fds",
                msg(b"L", vec![pipe_fd(), pipe_fd()], Some(me()), false),
                "the listener message did not carry exactly one fd",
            ),
            (
                "no creds",
                msg(b"L", vec![pipe_fd()], None, false),
                "the listener message carried no sender credentials",
            ),
            (
                "pid mismatch",
                msg(b"L", vec![pipe_fd()], Some(me() + 1), false),
                "the listener message came from an unexpected process",
            ),
            (
                "wrong kind",
                msg(b"L", vec![pipe_fd()], Some(me()), false),
                "the received fd is not a seccomp notification fd",
            ),
        ];
        for (name, m, why) in cases {
            assert_eq!(validate(m, me()).unwrap_err(), why, "{name}");
        }
    }

    /// SEC-4: 正しい listener は受理される（種別・close-on-exec・pid の照合を通る）。
    #[test]
    fn sec4_validate_accepts_a_real_listener() {
        let l = real_listener();
        let fd = validate(msg(b"L", vec![l], Some(me()), false), me()).unwrap();
        let kind = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
    }

    /// SEC-4: socketpair 越しの送受信と ACK の往復（同一プロセス内。送信元 pid は自分）。
    #[test]
    fn sec4_handover_and_receive_roundtrip_with_ack() {
        let (parent_end, child_end) = listener_socketpair().unwrap();
        let l = real_listener();
        let sender = ListenerSender::new(child_end);
        let t = std::thread::spawn(move || sender.hand_over(l, Duration::from_secs(10)));
        let got = receive_listener(
            parent_end.as_fd(),
            me(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        t.join().unwrap().unwrap();
        let kind =
            std::fs::read_link(format!("/proc/self/fd/{}", got.as_fd().as_raw_fd())).unwrap();
        assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
    }

    /// REPAIR-5・SEC-4: 子が送らずに閉じると、C は期限まで待たずに EOF を拒否として観測する。
    #[test]
    fn sec4_receive_sees_eof_immediately_when_the_child_end_closes() {
        let (parent_end, child_end) = listener_socketpair().unwrap();
        drop(child_end);
        let started = Instant::now();
        let e = receive_listener(
            parent_end.as_fd(),
            me(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::Seccomp);
        assert_eq!(
            e.message,
            "the sender closed before delivering the seccomp listener"
        );
    }

    /// REPAIR-5: 届かないまま期限が切れると `Timeout`。
    #[test]
    fn sec4_receive_times_out_when_nothing_arrives() {
        let (parent_end, _child_end) = listener_socketpair().unwrap();
        let e = receive_listener(
            parent_end.as_fd(),
            me(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Timeout);
    }

    /// SEC-4: ACK が届かないまま C が閉じると、子の `hand_over` は失敗する（exec に進ませない）。
    #[test]
    fn sec4_handover_fails_when_the_launcher_closes_without_ack() {
        let (parent_end, child_end) = listener_socketpair().unwrap();
        let l = real_listener();
        let sender = ListenerSender::new(child_end);
        let t = std::thread::spawn(move || sender.hand_over(l, Duration::from_secs(10)));
        // 送信を待ってから ACK せずに閉じる。
        assert_eq!(
            wait_readable(parent_end.as_fd(), Instant::now() + Duration::from_secs(10)),
            Ok(true)
        );
        drop(parent_end);
        let e = t.join().unwrap().unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::Seccomp);
    }

    /// SEC-4・#2024(issue コメントの要求): ACK の後に execve したプロセス(workload 相当)へ、listener fd も受け渡しに
    /// 使った socket も継承されない。`ls -l /proc/self/fd` の出力を具体的に照合する。
    #[test]
    fn sec4_2024_listener_and_socket_are_not_inherited_across_execve() {
        use std::io::Read as _;
        use std::os::unix::process::CommandExt as _;
        let (parent_end, child_end) = listener_socketpair().unwrap();
        let socket_name =
            std::fs::read_link(format!("/proc/self/fd/{}", child_end.as_raw_fd())).unwrap();
        let socket_name = socket_name.to_str().unwrap().to_string();
        assert!(socket_name.starts_with("socket:["), "{socket_name}");
        let (mut out_r, out_w) = std::io::pipe().unwrap();
        let pid = sys::fork_single_threaded_with(
            || true,
            move || {
                if sys::set_no_new_privs().is_err() {
                    return 9;
                }
                let Ok(p) = crate::seccomp::build_filter_for_target_arch() else {
                    return 8;
                };
                let Ok(listener) = sys::seccomp_notify::seccomp_set_filter_new_listener(&p) else {
                    return 10;
                };
                if ListenerSender::new(child_end)
                    .hand_over(listener, Duration::from_secs(20))
                    .is_err()
                {
                    return 11;
                }
                let err = std::process::Command::new("/bin/ls")
                    .args(["-l", "/proc/self/fd"])
                    .stdout(out_w)
                    .exec();
                let _ = err;
                127
            },
            1,
        )
        .unwrap();
        let child = super::super::process::ContainerChild::spawned(pid);
        // `child_end` と `out_w` は子へ move 済み(親の複製は fork 後に閉じる扱い)。ここでの `out_r` 以外の端は無い。
        let got = receive_listener(
            parent_end.as_fd(),
            pid,
            Instant::now() + Duration::from_secs(20),
        );
        assert!(got.is_ok(), "{got:?}");
        let mut listing = String::new();
        // 子が exec した ls の終了(= 書き込み側の全 close)まで読む。ハング防止に期限を付ける。
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match wait_readable(out_r.as_fd(), deadline) {
                Ok(true) => {}
                other => panic!("probe output did not arrive: {other:?}"),
            }
            let mut buf = [0u8; 4096];
            let n = out_r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            listing.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert_eq!(
            child.wait_for_exit(Duration::from_secs(10)).unwrap(),
            Some(super::super::process::ChildExit::Exited(0)),
            "{listing}"
        );
        assert!(listing.contains("-> pipe:["), "control: {listing}");
        assert!(!listing.contains("seccomp notify"), "{listing}");
        assert!(!listing.contains(&socket_name), "{listing}");
    }
}
