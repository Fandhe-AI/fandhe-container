//! netns holder の supervisor 側の端（Linux のみ。NET-9・CORE-6・REPAIR-2・REPAIR-5・#3197）。
//!
//! launch が holder を起動するときに使う。socketpair を作り（[`NetnsHolderChannel::pair`]）、子の端を holder の
//! stdin にして spawn した後、コンテナの user / net namespace の fd を [`NetnsHolderChannel::send_namespaces`] で
//! 送り、[`NetnsHolderChannel::wait_ready`] で READY（参加した ns の識別）を期限つきで検証する。契約は親モジュール
//! `crate::netns_holder` の `//!` を参照。

use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, Instant};

use super::READY_TIMEOUT;
use super::frame::{FRAME_LEN, HolderFrame, HolderMessage, NsIdentity};
use super::holder::classify;
use crate::error::{NetError, NetErrorCode};
use crate::sys::holder as sysh;
use crate::sys::{self, Deadline, Readiness, SysError};

fn sys_err(e: SysError, message: &'static str) -> NetError {
    NetError::new(classify(e), message)
}

fn precondition(message: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, message)
}

/// コンテナの user / net namespace の fd の組。順（user、net）を型で固定し、送る前に (dev, ino) を記録する。
///
/// 基準（supervisor 自身）の netns との照合（D8 の `Other`）は呼び出し側（#1939）の責務で、ここでは
/// 2 本が同じ nsfs 上の別の namespace であることだけを確かめる。
#[derive(Debug)]
pub struct NetnsHolderFds {
    user: File,
    net: File,
    expected: NsIdentity,
}

impl NetnsHolderFds {
    /// `user`・`net` の順に fd を受け取る。同じ fd を 2 回渡した・別の filesystem のものは `FailedPrecondition`。
    pub fn new(user: OwnedFd, net: OwnedFd) -> Result<Self, NetError> {
        let user = File::from(user);
        let net = File::from(net);
        let stat = |f: &File| {
            f.metadata().map(|m| (m.dev(), m.ino())).map_err(|_| {
                NetError::new(NetErrorCode::Internal, "cannot stat a namespace descriptor")
            })
        };
        let (user_dev, user_ino) = stat(&user)?;
        let (net_dev, net_ino) = stat(&net)?;
        if user_dev != net_dev || user_ino == net_ino {
            return Err(precondition(
                "the namespace descriptors are not distinct namespaces on one filesystem",
            ));
        }
        Ok(Self {
            user,
            net,
            expected: NsIdentity {
                dev: net_dev,
                net_ino,
                user_ino,
            },
        })
    }
}

/// 送信済みの fd の識別。[`NetnsHolderChannel::wait_ready`] が READY と照合する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentNamespaces {
    expected: NsIdentity,
}

impl SentNamespaces {
    /// 試験専用: fd を送らずに期待する識別だけを持つ値を作る（負の場面で `wait_ready` を呼ぶため）。
    #[cfg(feature = "netns-holder-test-support")]
    #[doc(hidden)]
    pub fn for_test(expected: NsIdentity) -> Self {
        Self { expected }
    }

    /// 送った namespace の識別。
    pub fn identity(&self) -> NsIdentity {
        self.expected
    }
}

/// READY の検証結果（supervisor が構造化ログ `netns_holder_ready` に使う材料。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderReady {
    /// holder が参加した namespace の識別（送った fd と一致済み）。
    pub identity: NsIdentity,
    /// `wait_ready` の開始から READY を受けるまでの時間。
    pub elapsed: Duration,
}

/// supervisor 側の端。drop すると端が閉じ、holder は EOF で終了する。
#[derive(Debug)]
pub struct NetnsHolderChannel {
    fd: OwnedFd,
}

impl NetnsHolderChannel {
    /// `SOCK_SEQPACKET` の socketpair を作り、`(supervisor 側の端, holder の stdin にする端)` を返す。
    /// 両端とも close-on-exec で、子の端は `Command::stdin(Stdio::from(..))` に渡すと stdin へ複製される。
    pub fn pair() -> Result<(Self, OwnedFd), NetError> {
        let (mine, child) = sysh::socketpair_seqpacket()
            .map_err(|e| sys_err(e, "cannot create the holder socket pair"))?;
        Ok((Self { fd: mine }, child))
    }

    /// user・net の fd を 1 通の `SCM_RIGHTS` で送り、送った後に fd を閉じる（pin しない。12.10）。
    pub fn send_namespaces(&self, fds: NetnsHolderFds) -> Result<SentNamespaces, NetError> {
        let frame = HolderFrame::encode(HolderMessage::Namespaces);
        sysh::send_with_fds(
            self.fd.as_fd(),
            frame.as_bytes(),
            &[fds.user.as_fd(), fds.net.as_fd()],
            true,
        )
        .map_err(|e| sys_err(e, "cannot send the namespaces to the holder"))?;
        Ok(SentNamespaces {
            expected: fds.expected,
        })
    }

    /// holder の READY を `timeout` 以内（0 より大きく [`READY_TIMEOUT`] 以下）に待つ。
    ///
    /// 期限切れは `Timeout`、holder の終了（EOF）・不正なフレーム・fd つきの応答・送った fd と一致しない識別は
    /// `FailedPrecondition`、holder が報告した失敗（`Error`）はその code のまま返す（12.9）。
    pub fn wait_ready(
        &self,
        sent: &SentNamespaces,
        timeout: Duration,
    ) -> Result<HolderReady, NetError> {
        if timeout.is_zero() || timeout > READY_TIMEOUT {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "the READY timeout must be in (0, READY_TIMEOUT]",
            ));
        }
        let started = Instant::now();
        let deadline = Deadline::after(timeout);
        let mut buf = [0u8; FRAME_LEN];
        let got = loop {
            match sys::wait_readable(self.fd.as_fd(), &deadline) {
                Err(e) => return Err(sys_err(e, "cannot wait for the holder")),
                Ok(Readiness::TimedOut) => {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out waiting for the holder READY",
                    ));
                }
                Ok(Readiness::Readable | Readiness::Exceptional) => {}
            }
            match sysh::recv_with_fds(self.fd.as_fd(), &mut buf, 0) {
                Ok(r) => break r,
                Err(SysError::Os(n)) if n == sys::EAGAIN || n == sys::EINTR => {
                    if deadline.remaining().is_zero() {
                        return Err(NetError::new(
                            NetErrorCode::Timeout,
                            "timed out waiting for the holder READY",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(sys_err(e, "cannot receive from the holder")),
            }
        };
        if got.len == 0 && !got.ctrl_truncated {
            return Err(precondition("the holder exited before READY"));
        }
        if got.ctrl_truncated || got.data_truncated {
            return Err(precondition(
                "the holder sent unexpected descriptors or data",
            ));
        }
        match HolderFrame::decode(buf.get(..got.len).unwrap_or(&[]))? {
            HolderMessage::Ready(id) if id == sent.expected => Ok(HolderReady {
                identity: id,
                elapsed: started.elapsed(),
            }),
            HolderMessage::Ready(_) => Err(precondition(
                "the holder READY identity does not match the sent namespaces",
            )),
            HolderMessage::Error(code) => Err(NetError::new(
                code,
                "the netns holder reported a startup failure",
            )),
            HolderMessage::Namespaces | HolderMessage::Stop => {
                Err(precondition("the holder sent an unexpected message"))
            }
        }
    }

    /// STOP を送る（待たない）。holder が既に終了していれば成功とみなす。送った後は [`super::STOP_GRACE`]
    /// 待ち、超えたら SIGKILL して [`super::REAP_TIMEOUT`] 以内に回収する（呼び出し側の責務）。
    pub fn send_stop(&self) -> Result<(), NetError> {
        let frame = HolderFrame::encode(HolderMessage::Stop);
        match sysh::send_with_fds(self.fd.as_fd(), frame.as_bytes(), &[], true) {
            Ok(_) => Ok(()),
            Err(SysError::Os(n)) if n == sysh::EPIPE => Ok(()),
            Err(e) => Err(sys_err(e, "cannot send STOP to the holder")),
        }
    }

    /// 端を閉じる（holder に EOF を伝える。`drop` でも同じ）。
    pub fn close(self) {
        drop(self);
    }

    /// 試験専用: 端の fd を取り出す（別プロセスへ端を持たせて「端が閉じない」状況を作るため）。
    #[cfg(feature = "netns-holder-test-support")]
    #[doc(hidden)]
    pub fn into_fd_for_test(self) -> OwnedFd {
        self.fd
    }

    /// 試験専用: 任意のバイト列と任意本数（4 本まで）の fd をそのまま送る（負の場面の試験用）。
    /// リリースビルドでは feature ごとコンパイルを止める（`lib.rs`）。
    #[cfg(feature = "netns-holder-test-support")]
    #[doc(hidden)]
    pub fn send_raw_for_test(
        &self,
        bytes: &[u8],
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> Result<(), NetError> {
        sysh::send_with_fds(self.fd.as_fd(), bytes, fds, true)
            .map(|_| ())
            .map_err(|e| sys_err(e, "cannot send raw bytes to the holder"))
    }
}
