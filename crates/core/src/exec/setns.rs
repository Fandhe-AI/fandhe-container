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
//!   対象が終了しても、pidfd は元のプロセスを指し続けるため、再利用された別プロセスの namespace へは
//!   入らない（pid 再利用対策。SEC-1）。さらに [`join_namespaces`] は `setns` の直前に pidfd の終了状態を
//!   再確認し、終了済みなら `FailedPrecondition` で拒否する（カーネルが終了済みの対象を `ESRCH` で拒否する
//!   挙動には依存しない。fail-closed）。残る隙間は確認から `setns` までの極小の窓で、その間に終了した
//!   場合も pidfd は元のプロセスを指すため別プロセスへは入らない。[`join_namespaces`] は同じ時点で所属 cgroup も
//!   期待パスと再照合し、`open` の後に対象が別の cgroup へ移されていれば拒否する
//! - pidfd は「呼び出した時点でその pid にいたプロセス」を固定するだけで、`state.json` に記録された
//!   元のコンテナのプロセスであることまでは証明しない（元のコンテナが終了し、その pid が別コンテナの
//!   PID 1 に再利用されると、NSpid や namespace 差異の検査は通ってしまう）。そこで [`Pid1Target::open`] は
//!   呼び出し側が渡す期待 cgroup パス（`<委譲スコープ>/fc-<id>@<instance>`。instance はストア全体で
//!   再利用されず、コンテナごとに一意。OCI-6）と、対象の `/proc/<pid>/cgroup` の cgroup v2 行のパスが
//!   **全体で完全一致** することを必須にする。別コンテナの cgroup とは一致しないため、再利用された
//!   別コンテナの PID 1 は拒否される（fail-closed。SEC-1）。パス要素のどこかに名前が現れるだけ・末尾要素が
//!   同名なだけでは認めない（コンテナが自分の配下に同名の子 cgroup を作って偽装する経路と、コンテナ用
//!   cgroup の配下に作られた入れ子の PID namespace の PID 1 を取り違える経路を塞ぐ）。照合は文字列で行う
//!   ため、記録した側と同じ cgroup 名前空間から読むことが前提で、食い違えば不一致として拒否する
//!   （`CgroupScope` と同じ前提）。`/proc` の読み取りはすべて pidfd を開いた後・未終了の確認の前に行うので、
//!   読んだ内容は pidfd の指すプロセスのものである（TOCTOU 対策）
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

/// 期待 cgroup パスの最大バイト数（Linux の `PATH_MAX`）。
const CGROUP_PATH_MAX: usize = 4096;

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
    /// `open` で照合した期待 cgroup パス。[`join_namespaces`] が参加の直前に再照合する。
    expected_cgroup_path: String,
}

impl Pid1Target {
    /// 対象の pid（ホストの PID namespace から見た値）。
    pub fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// `pid` を候補として pid1 を特定し、検証を通ったものだけを対象にする。
    ///
    /// `expected_cgroup_path` は記録したコンテナの cgroup の絶対パス（cgroup v2 のルート起点。
    /// `<委譲スコープ>/fc-<id>@<instance>`）。対象の所属 cgroup がこれと完全一致しなければ、pid が
    /// 別コンテナに再利用されたものとして拒否する（SEC-1）。
    ///
    /// 手順は順序固定: pidfd で固定 → `NSpid` が入れ子の PID 1 → 期待 cgroup に属する →
    /// 自分と同じ pid / mnt namespace でない → pidfd が未終了。いずれも満たさなければ
    /// `FailedPrecondition`（存在しない pid・検証中に消えた対象は `NotFound`、期待 cgroup パスが不正なら `InvalidArgument`）。
    pub fn open(pid: NonZeroU32, expected_cgroup_path: &str) -> Result<Self, ExecError> {
        let stage = IsolationStage::SetNs;
        if !is_valid_cgroup_path(expected_cgroup_path) {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                stage,
                "expected cgroup path must be an absolute, normalized, non-root cgroup path",
            ));
        }
        let pidfd = sys::pidfd_open(pid.get()).map_err(|e| setns_error(e, "pidfd_open"))?;
        let status = read_bounded(&format!("/proc/{pid}/status"))
            .map_err(|e| target_proc_error(&e, "read target status"))?;
        if !nspid_is_nested_pid1(&status) {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                stage,
                format!("process {pid} is not PID 1 of a nested PID namespace"),
            ));
        }
        verify_cgroup_membership(pid, expected_cgroup_path)?;
        for ns in [JoinNamespace::Pid, JoinNamespace::Mount] {
            let target = ns_identity(&format!("/proc/{pid}/ns/{}", ns.proc_name()))
                .map_err(|e| target_proc_error(&e, "read target namespace"))?;
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
        Ok(Self {
            pid,
            pidfd,
            expected_cgroup_path: expected_cgroup_path.to_owned(),
        })
    }
}

/// 対象 `pid` の所属 cgroup（`/proc/<pid>/cgroup` の v2 行）が `expected` と完全一致することを確かめる。
///
/// 不一致は `FailedPrecondition`。読み取りの結果が pidfd の指すプロセスのものであることは、呼び出し側が
/// この後に pidfd の未終了を確認することで保証する（終了していなければ pid は再利用されていない）。
fn verify_cgroup_membership(pid: NonZeroU32, expected: &str) -> Result<(), ExecError> {
    let cgroup = read_bounded(&format!("/proc/{pid}/cgroup"))
        .map_err(|e| target_proc_error(&e, "read target cgroup"))?;
    if !cgroup_path_matches(&cgroup, expected) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::SetNs,
            format!("process {pid} does not belong to the expected container cgroup"),
        ));
    }
    Ok(())
}

/// pidfd の指すプロセスが終了済みなら `FailedPrecondition`（`what` はメッセージの末尾に付ける）。
fn ensure_not_exited(target: &Pid1Target, what: &str) -> Result<(), ExecError> {
    let exited = sys::poll_readable(target.pidfd.as_fd(), 0)
        .map_err(|e| setns_error(e, "poll target pidfd"))?;
    if exited {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::SetNs,
            format!("process {} has already exited; {what}", target.pid),
        ));
    }
    Ok(())
}

/// 参加の直前に、対象が `open` のときと同じ期待 cgroup に属していることを再照合する（SEC-1）。
///
/// `open` から参加までの間に対象が別の cgroup へ移されていれば `FailedPrecondition`。cgroup の読み取りの後に
/// pidfd の未終了を確認し、読んだ内容が pidfd の指すプロセスのものであることを保証する。
fn recheck_cgroup_membership(target: &Pid1Target) -> Result<(), ExecError> {
    verify_cgroup_membership(target.pid, &target.expected_cgroup_path)?;
    ensure_not_exited(target, "refusing to setns")
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
/// 参加の直前に対象の終了と所属 cgroup（`open` で照合した期待パスとの完全一致）を再確認し、終了済み・
/// 別 cgroup へ移動済みなら `FailedPrecondition`。
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
    // 検証（`open`）から参加までの間に対象が終了していないか、参加の直前に再確認する。
    ensure_not_exited(target, "refusing to setns")?;
    let own = read_bounded("/proc/self/status")
        .map_err(|e| ExecError::from_io(&e, stage, "read own status"))?;
    if status_threads(&own) != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "the caller is multi-threaded or its thread count is unknown; refusing to setns",
        ));
    }
    // 所属 cgroup の再照合は `setns` の直前に置く（残る窓を最小にする）。
    recheck_cgroup_membership(target)?;
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

/// 対象の `/proc/<pid>` 配下の読み取り失敗を `SetNs` 段の `ExecError` にする。
///
/// pidfd を開いた後に対象が終了・回収されると、`/proc/<pid>` のエントリが消えて `ENOENT`（開いた後の
/// 読み取りでは `ESRCH`）になる。これは内部障害ではなく対象の終了なので、`pidfd_open` / `setns` の
/// `ESRCH` と同じ `NotFound` に揃える。それ以外の errno は通常の分類に従う。
fn target_proc_error(err: &std::io::Error, what: &str) -> ExecError {
    let mut e = ExecError::from_io(err, IsolationStage::SetNs, what);
    if matches!(err.raw_os_error(), Some(n) if n == sys::ENOENT || n == sys::ESRCH) {
        e.code = ErrorCode::NotFound;
    }
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

/// 期待 cgroup パスの形式検証: `/` 始まりの絶対パスで、ルート（`/`）でなく、各要素が空 / `.` / `..` で
/// なく、NUL・改行を含まず、[`CGROUP_PATH_MAX`] 以下。ルートを認めないのは、コンテナ用 cgroup が必ず
/// 委譲スコープの子であり、ルート所属の任意プロセスを対象にさせないため。
fn is_valid_cgroup_path(path: &str) -> bool {
    if path.len() > CGROUP_PATH_MAX || path.contains(['\0', '\n']) {
        return false;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// `/proc/<pid>/cgroup` の cgroup v2 行（`0::<path>`）のパスが `expected` と全体で完全一致するか。
///
/// v2 行なし・v2 行が複数・不一致は fail-closed で `false`。部分一致（接頭辞・接尾辞・途中の要素）は
/// 認めない。削除済み cgroup に残るプロセスはカーネルが ` (deleted)` を付けるため一致しない。
fn cgroup_path_matches(cgroup: &str, expected: &str) -> bool {
    let mut v2 = cgroup.lines().filter_map(|l| l.strip_prefix("0::"));
    match (v2.next(), v2.next()) {
        (Some(path), None) => path == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-6・SEC-1: cgroup は v2 行のパス全体が完全一致したときだけ一致する。別コンテナ（別 instance・
    /// 別 ID・別スコープ）、配下の子 cgroup、他コンテナ配下に作られた同名の子 cgroup、削除済み、v1 行は
    /// すべて不一致（pid 再利用と偽装の拒否）。
    #[test]
    fn sup6_cgroup_path_exact_match() {
        let want = "/user.slice/x.scope/fc-c1@7";
        assert!(cgroup_path_matches(
            "0::/user.slice/x.scope/fc-c1@7\n",
            want
        ));
        for other in [
            "0::/user.slice/x.scope/fc-c1@8\n",
            "0::/user.slice/x.scope/fc-c2@7\n",
            "0::/user.slice/y.scope/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c1@7/nested\n",
            "0::/user.slice/x.scope/fc-c2@9/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c2@9/user.slice/x.scope/fc-c1@7\n",
            "0::/user.slice/x.scope\n",
            "0::/user.slice/x.scope/fc-c1@7 (deleted)\n",
            "0::/user.slice/x.scope/fc-c1@7/\n",
            "1:name=x:/user.slice/x.scope/fc-c1@7\n",
            "0::/a\n0::/user.slice/x.scope/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c1@7\n0::/user.slice/x.scope/fc-c1@7\n",
            "",
        ] {
            assert!(!cgroup_path_matches(other, want), "{other:?}");
        }
    }

    /// SUP-6: 期待 cgroup パスの形式検証（絶対・正規形・ルート以外）。
    #[test]
    fn sup6_cgroup_path_validation() {
        for ok in ["/fc-c1@7", "/user.slice/x.scope/fc-c1@7"] {
            assert!(is_valid_cgroup_path(ok), "{ok}");
        }
        let too_long = format!("/{}", "a".repeat(CGROUP_PATH_MAX));
        for bad in [
            "",
            "/",
            "fc-c1@7",
            "a/b",
            "/a//b",
            "/a/",
            "/a/./b",
            "/a/../b",
            "/..",
            "/a\0b",
            "/a\n0::/b",
            too_long.as_str(),
        ] {
            assert!(!is_valid_cgroup_path(bad), "{bad:?}");
        }
    }

    /// SUP-6: 期待 cgroup パスが不正なら、対象へ触れる前に InvalidArgument。
    #[test]
    fn sup6_open_rejects_invalid_cgroup_path() {
        let me = NonZeroU32::new(std::process::id()).unwrap();
        for bad in ["", "/", "fc-c1@7", "/a/../b", "/a//b"] {
            let err = Pid1Target::open(me, bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.stage, IsolationStage::SetNs);
        }
    }

    /// SUP-6: 検証中に対象が消えた（`/proc/<pid>` の ENOENT / ESRCH）場合は Internal ではなく NotFound。
    /// それ以外の errno は通常の分類（EACCES は PermissionDenied）。
    #[test]
    fn sup6_target_proc_error_maps_vanished_target_to_not_found() {
        for errno in [sys::ENOENT, sys::ESRCH] {
            let io = std::io::Error::from_raw_os_error(errno);
            let err = target_proc_error(&io, "read target status");
            assert_eq!(err.code, ErrorCode::NotFound, "{errno}");
            assert_eq!(err.stage, IsolationStage::SetNs);
            assert!(
                err.message.starts_with("read target status failed: "),
                "{}",
                err.message
            );
        }
        let io = std::io::Error::from_raw_os_error(sys::EACCES);
        let err = target_proc_error(&io, "read target cgroup");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

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
        let err = Pid1Target::open(me, "/fc-x@1").unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
    }

    /// SUP-6: PID_MAX_LIMIT 超の pid は存在しない（NotFound）。
    #[test]
    fn sup6_open_missing_pid_is_not_found() {
        let err = Pid1Target::open(NonZeroU32::new(4_194_305).unwrap(), "/fc-x@1").unwrap_err();
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
            expected_cgroup_path: "/fc-x@1".to_owned(),
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

    /// SUP-6・SEC-1: 参加直前の再照合は、対象の現在の所属 cgroup が `open` 時の期待パスと完全一致する
    /// ときだけ通る。別の cgroup（移動後を想定）なら FailedPrecondition。
    #[test]
    fn sup6_recheck_cgroup_membership_rejects_moved_target() {
        let me = NonZeroU32::new(std::process::id()).unwrap();
        let own = read_bounded("/proc/self/cgroup").unwrap();
        let own_path = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2 line")
            .to_owned();
        let target = |path: &str| Pid1Target {
            pid: me,
            pidfd: sys::pidfd_open(me.get()).unwrap(),
            expected_cgroup_path: path.to_owned(),
        };
        assert_eq!(
            recheck_cgroup_membership(&target(&own_path)).map_err(|e| e.code),
            Ok(())
        );
        let moved = format!("{}/fc-x@1", own_path.trim_end_matches('/'));
        let err = recheck_cgroup_membership(&target(&moved)).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            format!("process {me} does not belong to the expected container cgroup")
        );
    }

    /// SUP-6: 検証後に終了した対象への参加は、setns の前に FailedPrecondition で拒否される。
    #[test]
    fn sup6_join_rejects_exited_target() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let pidfd = sys::pidfd_open(pid).unwrap();
        child.wait().unwrap();
        let target = Pid1Target {
            pid: NonZeroU32::new(pid).unwrap(),
            pidfd,
            expected_cgroup_path: "/fc-x@1".to_owned(),
        };
        let err = join_namespaces(&target, &JoinNamespace::SUP6_SET).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("already exited"), "{}", err.message);
    }
}
