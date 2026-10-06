//! 稼働中コンテナの pid1 の特定と、その namespace への `setns(2)` 参加（SUP-6・TASK-163.1・#500・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `fandhe-container-supervisor` の `exec` モジュール（`identify_pid1` / `enter_namespaces`）が、
//! `state.json` の記録 pid を **候補** として [`Pid1Target::open`] へ渡し、検証を通った対象に対して
//! [`join_namespaces`] を呼ぶ。`unsafe` はここへは置かず、`crate::sys::setns_pidfd` に閉じ込める。
//!
//! # 契約
//!
//! - 対象の固定は pidfd を **先に** 開いてから `/proc/<pid>` を検証する順で行う。検証後・参加前に
//!   対象が終了しても、pidfd は元のプロセスを指し続けるため `ESRCH` で失敗し、再利用された別プロセスの
//!   namespace へは入らない（pid 再利用対策。SEC-1）
//! - 対象は入れ子の PID namespace の PID 1（`NSpid:` の要素が 2 以上で末尾が 1）に限り、自プロセスと
//!   同じ pid / mnt namespace へは参加しない。任意プロセスの namespace へ入る汎用手段にしない
//! - 参加は **不可逆** で、呼び出しスレッドに作用する。単一スレッドのプロセスからのみ呼べる
//!   （`CLONE_NEWNS` はスレッドが複数あると拒否され、他 namespace もスレッドごとに食い違うため
//!   fail-closed で拒否する）。呼び出すのは exec 専用の単一スレッドプロセスで、logs 捕捉スレッドを
//!   持つ supervisor 本体から直接呼ばない（#503）
//! - pid namespace への参加は **以後に fork した子** にだけ効く（2 段目の fork は #503）
//! - 順序: ホスト側 fd の確保（cgroup.procs。#501）は [`join_namespaces`] の **前**、seccomp / Landlock
//!   の再適用（#502）は **後**（`setns` は seccomp の禁止 syscall に含まれ、適用後は参加できない）
//!
//! # 未実装（REPAIR-3）
//!
//! - user namespace への参加。rootless コンテナへ非特権で exec するには先に必要になり得るが、本実装は
//!   `User` を型に持たず拒否する（fail-closed）。SUP-6 の列挙（pid / mnt / uts / ipc / net）に従う
//! - 分離違反の拒否の監査ログ（SEC-4）への記録配線。構造化エラーで返すのみ

use std::fs;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;

use super::{ExecError, IsolationStage, errno_to_code, status_threads};
use crate::sys::{self, NsFlag, SysError};
use crate::traits::types::ErrorCode;

/// `/proc/<pid>/status` の読み取り上限（バイト）。通常は 2 KiB 前後で、無制限確保を避ける。
const STATUS_READ_LIMIT: u64 = 64 * 1024;

/// 参加する namespace 種別（SUP-6。user namespace は含まない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoinNamespace {
    /// PID namespace（以後に fork した子にだけ効く）。
    Pid,
    /// mount namespace。
    Mount,
    /// UTS namespace。
    Uts,
    /// IPC namespace。
    Ipc,
    /// network namespace。
    Net,
}

impl JoinNamespace {
    /// SUP-6 が固定する参加対象 5 種。
    pub const SUP6_SET: [JoinNamespace; 5] = [
        JoinNamespace::Pid,
        JoinNamespace::Mount,
        JoinNamespace::Uts,
        JoinNamespace::Ipc,
        JoinNamespace::Net,
    ];

    fn flag(self) -> NsFlag {
        match self {
            Self::Pid => NsFlag::Pid,
            Self::Mount => NsFlag::Mount,
            Self::Uts => NsFlag::Uts,
            Self::Ipc => NsFlag::Ipc,
            Self::Net => NsFlag::Net,
        }
    }

    /// `/proc/<pid>/ns/` 配下のエントリ名。
    fn proc_name(self) -> &'static str {
        match self {
            Self::Pid => "pid",
            Self::Mount => "mnt",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Net => "net",
        }
    }
}

/// 検証済みの参加対象（pid1）。pidfd でプロセス同一性を固定している。
#[derive(Debug)]
pub struct Pid1Target {
    pid: NonZeroU32,
    pidfd: OwnedFd,
}

impl Pid1Target {
    /// 対象の pid（ホストの PID namespace から見た値）。
    pub fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// `pid` を候補として pid1 を特定し、検証を通ったものだけを対象にする。
    ///
    /// 手順は順序固定: pidfd で固定 → `NSpid` が入れ子の PID 1 → 自分と同じ pid / mnt namespace でない →
    /// pidfd が未終了。いずれも満たさなければ `FailedPrecondition`（存在しない pid は `NotFound`）。
    pub fn open(pid: NonZeroU32) -> Result<Self, ExecError> {
        let stage = IsolationStage::SetNs;
        let pidfd = sys::pidfd_open(pid.get()).map_err(|e| setns_error(e, "pidfd_open"))?;
        let status = read_bounded(&format!("/proc/{pid}/status"))
            .map_err(|e| ExecError::from_io(&e, stage, "read target status"))?;
        if !nspid_is_nested_pid1(&status) {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                stage,
                format!("process {pid} is not PID 1 of a nested PID namespace"),
            ));
        }
        for ns in [JoinNamespace::Pid, JoinNamespace::Mount] {
            let target = ns_identity(&format!("/proc/{pid}/ns/{}", ns.proc_name()))
                .map_err(|e| ExecError::from_io(&e, stage, "read target namespace"))?;
            let own = ns_identity(&format!("/proc/self/ns/{}", ns.proc_name()))
                .map_err(|e| ExecError::from_io(&e, stage, "read own namespace"))?;
            if target == own {
                return Err(ExecError::new(
                    ErrorCode::FailedPrecondition,
                    stage,
                    format!(
                        "process {pid} shares the {} namespace with the caller; refusing to join",
                        ns.proc_name()
                    ),
                ));
            }
        }
        // 終了後は pid が再利用され得るため、`/proc` の検証結果が pidfd の指すプロセスのものである
        // ことを、未終了の確認で保証する。
        let exited = sys::poll_readable(pidfd.as_fd(), 0)
            .map_err(|e| setns_error(e, "poll target pidfd"))?;
        if exited {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                stage,
                format!("process {pid} has already exited"),
            ));
        }
        Ok(Self { pid, pidfd })
    }
}

/// [`join_namespaces`] の成功結果（将来拡張できる構造）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamespaceJoinReport {
    /// 参加した対象の pid（ホストの PID namespace から見た値）。
    pub target_pid: NonZeroU32,
    /// 参加した namespace（呼び出し側が渡した順）。
    pub joined: Vec<JoinNamespace>,
}

/// 検証済みの対象 `target` の namespace 群へ、1 回の `setns(2)` で参加する。
///
/// 呼び出しスレッドの namespace を不可逆に変える。単一スレッドでなければ `FailedPrecondition`、
/// `set` が空なら `InvalidArgument`。契約全体はモジュール doc を参照（SUP-6・TASK-163.1）。
pub fn join_namespaces(
    target: &Pid1Target,
    set: &[JoinNamespace],
) -> Result<NamespaceJoinReport, ExecError> {
    let stage = IsolationStage::SetNs;
    if set.is_empty() {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            stage,
            "namespace set to join is empty",
        ));
    }
    let own = read_bounded("/proc/self/status")
        .map_err(|e| ExecError::from_io(&e, stage, "read own status"))?;
    if status_threads(&own) != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "the caller is multi-threaded or its thread count is unknown; refusing to setns",
        ));
    }
    let flags: Vec<NsFlag> = set.iter().map(|n| n.flag()).collect();
    sys::setns_pidfd(target.pidfd.as_fd(), &flags).map_err(|e| setns_error(e, "setns"))?;
    Ok(NamespaceJoinReport {
        target_pid: target.pid,
        joined: set.to_vec(),
    })
}

/// syscall 失敗を `SetNs` 段の `ExecError` にする。`ESRCH`（対象の終了）は `NotFound`。
fn setns_error(err: SysError, what: &str) -> ExecError {
    let mut e = ExecError::from_sys(err, IsolationStage::SetNs, what);
    e.code = if err == SysError::Os(sys::ESRCH) {
        ErrorCode::NotFound
    } else {
        errno_to_code(err)
    };
    e
}

/// 上限つきでテキストを読む。
fn read_bounded(path: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    fs::File::open(path)?
        .take(STATUS_READ_LIMIT)
        .read_to_string(&mut buf)?;
    Ok(buf)
}

/// namespace の識別子（nsfs の dev, ino）。
fn ns_identity(path: &str) -> std::io::Result<(u64, u64)> {
    let m = fs::metadata(path)?;
    Ok((m.dev(), m.ino()))
}

/// `NSpid:` の要素が 2 以上で、末尾（最も内側の PID namespace での PID）が 1 か。
/// 行なし・非数値は fail-closed で `false`。
fn nspid_is_nested_pid1(status: &str) -> bool {
    let Some(rest) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
        return false;
    };
    let mut parsed = Vec::new();
    for tok in rest.split_whitespace() {
        match tok.parse::<u32>() {
            Ok(v) => parsed.push(v),
            Err(_) => return false,
        }
    }
    parsed.len() >= 2 && parsed.last() == Some(&1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-6: NSpid の解析（入れ子の PID 1 のみ許可）。
    #[test]
    fn sup6_nspid_parse() {
        assert!(nspid_is_nested_pid1("Name:\tx\nNSpid:\t4242\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\n"));
        assert!(!nspid_is_nested_pid1("Name:\tx\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\tabc\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t\n"));
    }

    /// SUP-6: 自プロセスは pid1 として特定されない。
    #[test]
    fn sup6_open_rejects_self() {
        let me = NonZeroU32::new(std::process::id()).unwrap();
        let err = Pid1Target::open(me).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
    }

    /// SUP-6: PID_MAX_LIMIT 超の pid は存在しない（NotFound）。
    #[test]
    fn sup6_open_missing_pid_is_not_found() {
        let err = Pid1Target::open(NonZeroU32::new(4_194_305).unwrap()).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.stage, IsolationStage::SetNs);
    }

    /// SUP-6: 空集合は InvalidArgument、マルチスレッドは FailedPrecondition。
    #[test]
    fn sup6_join_preconditions() {
        let pidfd = sys::pidfd_open(std::process::id()).unwrap();
        let target = Pid1Target {
            pid: NonZeroU32::new(std::process::id()).unwrap(),
            pidfd,
        };
        let err = join_namespaces(&target, &[]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        // 別スレッドを生かしたまま呼び、Threads が 2 以上になる状態を作る。
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let err = join_namespaces(&target, &JoinNamespace::SUP6_SET).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        let _ = tx.send(());
        let _ = helper.join();
    }
}
