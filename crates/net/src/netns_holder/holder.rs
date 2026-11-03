//! netns holder プロセスの本体（Linux のみ。NET-9・CORE-6・SEC-5・REPAIR-5・#3197）。手順と契約は親モジュール
//! `crate::netns_holder` の `//!` を参照。supervisor の bin の main が `run_netns_holder_main` 経由で呼ぶ。
//!
//! 単一スレッドで同期的に動く（`setns(CLONE_NEWUSER)` が多スレッドで `EINVAL` になるため。待ちは `poll(2)` だけ）。
//! unsafe は持たず、syscall は `crate::sys::holder` の安全なラッパーだけを使う。

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::process::ExitCode;
use std::time::Duration;

use super::frame::{FRAME_LEN, HolderFrame, HolderMessage, NsIdentity};
use super::{FDS_RECV_TIMEOUT, NETNS_HOLDER_SUBCOMMAND};
use crate::error::NetErrorCode;
use crate::sys::holder as sysh;
use crate::sys::{self, Deadline, Readiness, SysError};

/// 失敗の分類と固定の英文（パス・入力値を含めない。12.9・ERR-1）。
struct Fail {
    code: NetErrorCode,
    message: &'static str,
}

impl Fail {
    fn new(code: NetErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

/// errno の分類（12.9）。`setns` の `EPERM` は PermissionDenied、`EINVAL`（型違い・自身の userns を含む）と
/// ソケットでない stdin は FailedPrecondition。
pub(super) fn classify(e: SysError) -> NetErrorCode {
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

fn sys_fail(e: SysError, message: &'static str) -> Fail {
    Fail::new(classify(e), message)
}

/// 失敗行を stderr へ出す。読み手が止まって pipe が満杯でも終了を妨げないよう、書き込みは別スレッドで行い
/// 期限（`FAIL_LINE_TIMEOUT`）で見切る（REPAIR-5）。見切った場合、ブロック中のスレッドはプロセス終了で消える。
/// 失敗経路でだけ呼ぶ（`setns` を終えた後か、参加できずに終了する経路）ため、単一スレッド前提を壊さない。
fn fail_line(code: NetErrorCode, message: &str) {
    let line = format!("error code={} message={message}\n", code.as_str());
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let spawned = std::thread::Builder::new().spawn(move || {
        let _ = std::io::stderr().write_all(line.as_bytes());
        let _ = tx.send(());
    });
    if spawned.is_ok() {
        let _ = rx.recv_timeout(FAIL_LINE_TIMEOUT);
    }
}

/// `fail_line` の書き込みを待つ上限。
const FAIL_LINE_TIMEOUT: Duration = Duration::from_millis(500);

/// 親が存在し、stdin の socketpair の作成者（`SO_PEERCRED` の pid）と一致することを確かめる。
/// 親が先に死ぬと `getppid` は 1 かサブリーパーに変わり不一致になる（PDEATHSIG の設定前に死んだ場合の備え）。
fn check_parent(fd: BorrowedFd<'_>) -> Result<(), Fail> {
    let peer = sysh::peer_pid(fd).map_err(|e| sys_fail(e, "cannot read the peer credentials"))?;
    let parent = std::os::unix::process::parent_id();
    if parent == 1 || parent != peer {
        return Err(Fail::new(
            NetErrorCode::FailedPrecondition,
            "the parent process is not the creator of the socket",
        ));
    }
    Ok(())
}

/// 期限つきで 1 通受ける。`Exceptional`（HUP 等）でも recv を試み、EOF は長さ 0 として返る。
fn recv_one(
    fd: BorrowedFd<'_>,
    deadline: &Deadline,
    max_fds: usize,
) -> Result<(sysh::Received, [u8; FRAME_LEN]), Fail> {
    let mut buf = [0u8; FRAME_LEN];
    loop {
        match sys::wait_readable(fd, deadline) {
            Err(e) => return Err(sys_fail(e, "cannot wait for the supervisor")),
            Ok(Readiness::TimedOut) => {
                return Err(Fail::new(
                    NetErrorCode::Timeout,
                    "timed out waiting for the supervisor",
                ));
            }
            Ok(Readiness::Readable | Readiness::Exceptional) => {}
        }
        match sysh::recv_with_fds(fd, &mut buf, max_fds) {
            Ok(r) => return Ok((r, buf)),
            // poll の後に消えた・シグナル中断。残り時間で待ち直す（HUP だけの場合に空回りしないよう短く休む）。
            Err(SysError::Os(n)) if n == sys::EAGAIN || n == sys::EINTR => {
                if deadline.remaining().is_zero() {
                    return Err(Fail::new(
                        NetErrorCode::Timeout,
                        "timed out waiting for the supervisor",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(sys_fail(e, "cannot receive from the supervisor")),
        }
    }
}

/// fd の識別（`fstat` の dev・ino）。
fn identity_of(file: &File) -> Result<(u64, u64), Fail> {
    let m = file
        .metadata()
        .map_err(|_| Fail::new(NetErrorCode::Internal, "cannot stat a namespace descriptor"))?;
    Ok((m.dev(), m.ino()))
}

/// 参加後の自分の ns の識別（`/proc/self/ns/<name>` の dev・ino）。
fn self_ns_identity(name: &str) -> Result<(u64, u64), Fail> {
    let f = File::open(format!("/proc/self/ns/{name}"))
        .map_err(|_| Fail::new(NetErrorCode::Internal, "cannot open the joined namespace"))?;
    identity_of(&f)
}

/// 手順 1〜4: 親の確認・fd の受信・参加・検証・特権の破棄。成功なら READY に載せる識別を返す。
fn prepare(fd: BorrowedFd<'_>) -> Result<NsIdentity, Fail> {
    sysh::set_pdeathsig_sigkill().map_err(|e| sys_fail(e, "cannot set the parent-death signal"))?;
    match sysh::socket_type(fd) {
        Ok(t) if t == sysh::SOCK_SEQPACKET => {}
        Ok(_) | Err(SysError::Os(_)) => {
            return Err(Fail::new(
                NetErrorCode::FailedPrecondition,
                "stdin is not a seqpacket socket",
            ));
        }
        Err(e) => return Err(sys_fail(e, "cannot inspect stdin")),
    }
    check_parent(fd)?;

    let deadline = Deadline::after(FDS_RECV_TIMEOUT);
    let (got, buf) = recv_one(fd, &deadline, sysh::MAX_FDS)?;
    if got.ctrl_truncated || got.data_truncated {
        return Err(Fail::new(
            NetErrorCode::InvalidArgument,
            "the supervisor message was truncated or carried extra descriptors",
        ));
    }
    let msg = HolderFrame::decode(buf.get(..got.len).unwrap_or(&[])).map_err(|_| {
        Fail::new(
            NetErrorCode::InvalidArgument,
            "the supervisor message is not a valid frame",
        )
    })?;
    if msg != HolderMessage::Namespaces {
        return Err(Fail::new(
            NetErrorCode::InvalidArgument,
            "the supervisor message has an unexpected kind",
        ));
    }
    let mut it = got.fds.into_iter();
    let (Some(user_fd), Some(net_fd), None) = (it.next(), it.next(), it.next()) else {
        return Err(Fail::new(
            NetErrorCode::InvalidArgument,
            "exactly two namespace descriptors are required",
        ));
    };
    join_and_verify(user_fd, net_fd)
}

/// fd の識別を記録し、`setns(user)` → `setns(net)` の順に参加して、参加先を `/proc/self/ns` で確かめる。
/// 成功時に fd を閉じ、capability を落とす。
fn join_and_verify(user_fd: OwnedFd, net_fd: OwnedFd) -> Result<NsIdentity, Fail> {
    let user = File::from(user_fd);
    let net = File::from(net_fd);
    let (user_dev, user_ino) = identity_of(&user)?;
    let (net_dev, net_ino) = identity_of(&net)?;
    if user_dev != net_dev || user_ino == net_ino {
        return Err(Fail::new(
            NetErrorCode::FailedPrecondition,
            "the namespace descriptors are not distinct namespaces on one filesystem",
        ));
    }
    sysh::join_namespace(user.as_fd(), sysh::CLONE_NEWUSER)
        .map_err(|e| sys_fail(e, "cannot join the user namespace"))?;
    sysh::join_namespace(net.as_fd(), sysh::CLONE_NEWNET)
        .map_err(|e| sys_fail(e, "cannot join the network namespace"))?;
    if self_ns_identity("net")? != (net_dev, net_ino)
        || self_ns_identity("user")? != (user_dev, user_ino)
    {
        return Err(Fail::new(
            NetErrorCode::FailedPrecondition,
            "the joined namespaces do not match the received descriptors",
        ));
    }
    drop(user);
    drop(net);

    sysh::drop_all_capabilities().map_err(|e| sys_fail(e, "cannot drop capabilities"))?;
    sysh::set_no_new_privs().map_err(|e| sys_fail(e, "cannot set no_new_privs"))?;
    // 資格情報が変わった後でも PDEATHSIG が効いていることを設定し直して確かめる。
    sysh::set_pdeathsig_sigkill().map_err(|e| sys_fail(e, "cannot set the parent-death signal"))?;
    match sysh::get_pdeathsig() {
        Ok(s) if s == sysh::PR_SIGKILL => {}
        Ok(_) => {
            return Err(Fail::new(
                NetErrorCode::FailedPrecondition,
                "the parent-death signal is not armed",
            ));
        }
        Err(e) => return Err(sys_fail(e, "cannot read the parent-death signal")),
    }
    // pasta が `/proc/<holder>/ns/*` を開ける前提（12.2）。dumpable でなければ参加の意味が無いので失敗させる。
    match sysh::get_dumpable() {
        Ok(1) => {}
        Ok(_) => {
            return Err(Fail::new(
                NetErrorCode::FailedPrecondition,
                "the process is not dumpable after joining the namespaces",
            ));
        }
        Err(e) => return Err(sys_fail(e, "cannot read the dumpable flag")),
    }
    Ok(NsIdentity {
        dev: net_dev,
        net_ino,
        user_ino,
    })
}

/// 手順 5 の後: STOP または EOF を待つだけにする。期限は無い（終わる経路は PDEATHSIG・EOF・STOP。12.2）。
fn wait_for_stop(fd: BorrowedFd<'_>) -> Result<(), Fail> {
    let deadline = Deadline::after(Duration::MAX);
    // READY の後に fd や余計な通信を受けたら fail-closed（fd は受信時にカーネルが閉じる）。
    let (got, buf) = recv_one(fd, &deadline, 0)?;
    if got.ctrl_truncated || got.data_truncated {
        return Err(Fail::new(
            NetErrorCode::InvalidArgument,
            "unexpected descriptors after READY",
        ));
    }
    if got.len == 0 {
        return Ok(());
    }
    match HolderFrame::decode(buf.get(..got.len).unwrap_or(&[])) {
        Ok(HolderMessage::Stop) => Ok(()),
        _ => Err(Fail::new(
            NetErrorCode::InvalidArgument,
            "unexpected message after READY",
        )),
    }
}

/// `run_netns_holder_main` の本体（`crate::netns_holder` から委譲される）。
pub(super) fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    // 継承 fd（3 以上）を最初に閉じる。dumpable な holder に残さない（SEC-1）。閉じられなければ起動を拒否する。
    if let Err(e) = sysh::close_inherited_fds() {
        fail_line(classify(e), "cannot close inherited descriptors");
        return ExitCode::from(1);
    }
    if args.count() != 0 {
        fail_line(
            NetErrorCode::InvalidArgument,
            "unexpected argument (the argv is fixed)",
        );
        return ExitCode::from(2);
    }
    debug_assert_eq!(NETNS_HOLDER_SUBCOMMAND, "netns-holder");
    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    match prepare(fd) {
        Ok(identity) => {
            let ready = HolderFrame::encode(HolderMessage::Ready(identity));
            if sysh::send_with_fds(fd, ready.as_bytes(), &[], true).is_err() {
                fail_line(NetErrorCode::Internal, "cannot send READY");
                return ExitCode::from(1);
            }
            match wait_for_stop(fd) {
                Ok(()) => ExitCode::SUCCESS,
                Err(f) => {
                    fail_line(f.code, f.message);
                    ExitCode::from(1)
                }
            }
        }
        Err(f) => {
            let frame = HolderFrame::encode(HolderMessage::Error(f.code));
            let _ = sysh::send_with_fds(fd, frame.as_bytes(), &[], true);
            fail_line(f.code, f.message);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 12.9: errno の分類（具体値）。
    #[test]
    fn classify_maps_errno_to_codes() {
        assert_eq!(
            classify(SysError::Os(sys::EPERM)),
            NetErrorCode::PermissionDenied
        );
        assert_eq!(
            classify(SysError::Os(sys::EINVAL)),
            NetErrorCode::FailedPrecondition
        );
        assert_eq!(
            classify(SysError::Os(sysh::ENOTSOCK)),
            NetErrorCode::FailedPrecondition
        );
        assert_eq!(
            classify(SysError::Os(sys::EMFILE)),
            NetErrorCode::ResourceExhausted
        );
        assert_eq!(classify(SysError::Os(sys::ENOENT)), NetErrorCode::Internal);
        assert_eq!(classify(SysError::Unsupported), NetErrorCode::Unimplemented);
    }
}
