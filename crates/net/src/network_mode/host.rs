//! host モード（ホスト netns 共有）の検証（NET-6・TASK-143.1・#326・MS-8。Linux のみ）。
//!
//! host モードは新しい netns を作らず、runtime が OCI `linux.namespaces` から `network` を外して
//! 起動することでホストの netns を引き継ぐ（PoC-15 と同じ方式）。runtime（core）側の接続は本 crate の
//! スコープ外で、本モジュールは「呼び出しスレッドが本当にホスト netns にいるか」と「あるプロセスが
//! ホスト netns に属するか」を `/proc/<pid>/ns/net` の (dev, ino) 照合で確かめる。`setns(2)` は使わず
//! unsafe も追加しない。
//!
//! # 契約
//! - ホスト netns の基準は `/proc/1/ns/net`。読めない場合は fail-closed（非 root では
//!   `PermissionDenied`。rootless の host モードは NET-9・TASK-147 の領域で未対応）
//! - 呼び出しスレッドがホスト netns 以外にいる場合は `FailedPrecondition`。setns による加入
//!   （runtime 自体がホスト以外の netns で動く構成）は未実装の将来仕様（REPAIR-3）
//! - [`HostNetns::verify_process`] は pid 再利用による TOCTOU が残る。呼び出し側は自分の子 pid に限って使う
//! - エラーメッセージは固定の英語文で、パスや inode の中身を含めない

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::classify_errno;

/// netns の識別子（nsfs inode の dev, ino）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NsId {
    dev: u64,
    ino: u64,
}

impl NsId {
    /// (dev, ino) から作る。
    pub fn new(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }
    /// nsfs のデバイス番号。
    pub fn dev(&self) -> u64 {
        self.dev
    }
    /// nsfs の inode 番号。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// プロセスの netns がホスト netns と一致するかの判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostNetnsMembership {
    /// ホスト netns に属する。
    Member,
    /// 別の netns に属する。
    Other {
        /// 観測した netns の識別子。
        observed: NsId,
    },
}

/// 検証済みのホスト netns（呼び出しスレッドが属していることを `detect` が確認済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostNetns {
    id: NsId,
}

fn stat_ns(path: &Path) -> Result<NsId, NetError> {
    // stat は ns の magic link を辿り nsfs inode の (dev, ino) を返す。
    let md = fs::metadata(path).map_err(|e| {
        NetError::new(
            e.raw_os_error()
                .map_or(NetErrorCode::Internal, classify_errno),
            "failed to stat network namespace entry in /proc",
        )
    })?;
    Ok(NsId::new(md.dev(), md.ino()))
}

/// 呼び出しスレッドの netns が init の netns と一致することを確認する純粋関数。
///
/// 一致しなければ `FailedPrecondition`（fail-closed）。
pub fn classify_host_netns(thread: NsId, init: NsId) -> Result<NsId, NetError> {
    if thread == init {
        Ok(init)
    } else {
        Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "calling thread is not in the host network namespace",
        ))
    }
}

impl HostNetns {
    /// 呼び出しスレッドがホスト netns（`/proc/1/ns/net`）にいることを確認する。
    ///
    /// netns はスレッド単位のため `/proc/thread-self` を参照する。
    pub fn detect() -> Result<Self, NetError> {
        let thread = stat_ns(Path::new("/proc/thread-self/ns/net"))?;
        let init = stat_ns(Path::new("/proc/1/ns/net"))?;
        Ok(Self {
            id: classify_host_netns(thread, init)?,
        })
    }

    /// ホスト netns の識別子。
    pub fn id(&self) -> NsId {
        self.id
    }

    /// `pid` のプロセスがホスト netns に属するかを返す。
    ///
    /// `pid` は 1..=`i32::MAX` のみ。pid 再利用の TOCTOU は残る（モジュール doc）。
    pub fn verify_process(&self, pid: u32) -> Result<HostNetnsMembership, NetError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "pid is out of range",
            ));
        }
        let path = Path::new("/proc")
            .join(pid.to_string())
            .join("ns")
            .join("net");
        let observed = stat_ns(&path)?;
        Ok(if observed == self.id {
            HostNetnsMembership::Member
        } else {
            HostNetnsMembership::Other { observed }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-6: 一致は Ok、不一致は FAILED_PRECONDITION。
    #[test]
    fn net6_classify_host_netns() {
        let a = NsId::new(4, 100);
        assert_eq!(classify_host_netns(a, a).unwrap(), a);
        let e = classify_host_netns(NsId::new(4, 101), a).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.code().as_str(), "FAILED_PRECONDITION");
        let e = classify_host_netns(NsId::new(5, 100), a).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-6: pid 範囲外は INVALID_ARGUMENT。
    #[test]
    fn net6_verify_process_rejects_bad_pid() {
        let h = HostNetns {
            id: NsId::new(1, 1),
        };
        for pid in [0u32, i32::MAX as u32 + 1, u32::MAX] {
            let e = h.verify_process(pid).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "pid {pid}");
        }
    }

    /// NET-6: 自プロセスの netns は非 root でも読め、同一 id なら Member、別 id なら Other。
    #[test]
    fn net6_verify_process_self() {
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let same = HostNetns { id: own };
        assert_eq!(
            same.verify_process(std::process::id()).unwrap(),
            HostNetnsMembership::Member
        );
        let other = HostNetns {
            id: NsId::new(own.dev(), own.ino() + 1),
        };
        assert_eq!(
            other.verify_process(std::process::id()).unwrap(),
            HostNetnsMembership::Other { observed: own }
        );
    }

    /// NET-6: 存在しない pid は NOT_FOUND。
    #[test]
    fn net6_verify_process_missing() {
        let h = HostNetns {
            id: NsId::new(1, 1),
        };
        // pid_max は 2^22 以下のため i32::MAX は存在しない。
        let e = h.verify_process(i32::MAX as u32).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
    }

    /// NET-6: detect は環境依存（root なら Ok、非 root は /proc/1 が読めず PERMISSION_DENIED。
    /// コンテナ内など別 netns なら FAILED_PRECONDITION）。それ以外の code にはならない。
    #[test]
    fn net6_detect_known_outcomes() {
        match HostNetns::detect() {
            Ok(h) => assert_eq!(h.id(), stat_ns(Path::new("/proc/1/ns/net")).unwrap()),
            Err(e) => assert!(
                matches!(
                    e.code(),
                    NetErrorCode::PermissionDenied | NetErrorCode::FailedPrecondition
                ),
                "unexpected code {:?}",
                e.code()
            ),
        }
    }
}
