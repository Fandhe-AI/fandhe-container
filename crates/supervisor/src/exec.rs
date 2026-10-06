//! exec の入口: 稼働中コンテナの pid1 を特定し、その namespace へ参加する（SUP-6・TASK-163.1・#500・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `state.json` のレコードから対象を決め、`fandhe_container_core::exec` の安全 API（`Pid1Target` /
//! `join_namespaces`）へ配線するだけの薄い層で、`unsafe` も OS 分岐も持たない（OS 局所化は core。CLI-1）。
//! 将来 #503 の exec 専用プロセスと TASK-161（SUP-4）の healthcheck が同じ関数を使う
//! （`health.rs` の `HealthProbe` が期待する共通コードパス）。
//!
//! # 契約
//!
//! - 記録上の pid は **候補** にすぎず、シグナル送信・回収・`/proc` の宛先にそのまま使わない
//!   （pid 再利用対策。SEC-1）。core の `Pid1Target::open` が pidfd 固定のうえで pid1 であることを検証し、
//!   通ったものだけを [`ExecTarget`] にする。さらに pid が別コンテナに再利用されていないことを、
//!   記録した cgroup 配置から導くコンテナ固有の cgroup 名で確認する（SEC-1）
//! - [`enter_namespaces`] は呼び出しスレッドの namespace を不可逆に変える。単一スレッドのプロセスから
//!   のみ呼べる。logs 捕捉スレッドを持つ supervisor 本体からは呼ばず、exec 専用プロセスから呼ぶ（#503）
//! - 順序: cgroup.procs の fd 確保（#501）は [`enter_namespaces`] の前、seccomp / Landlock の再適用
//!   （#502）は後
//!
//! # 未実装（REPAIR-3）
//!
//! namespace 参加までで、コマンド実行は未実装。cgroup join（#501・TASK-163.2）、seccomp / Landlock 再適用
//! （#502・TASK-163.3）、fork・execve と統合テスト（#503・TASK-163.4）、user namespace への参加は
//! 未実装（SUP-6）。

use fandhe_container_core::cgroups::CgroupName;
use fandhe_container_core::exec::{
    ExecError, JoinNamespace, NamespaceJoinReport, Pid1Target, join_namespaces,
};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, StateRecord, TraitError,
};

/// 検証済みの exec 対象（コンテナ ID と、pidfd で固定した pid1）。
#[derive(Debug)]
pub struct ExecTarget {
    id: ContainerId,
    pid1: Pid1Target,
}

impl ExecTarget {
    /// 対象のコンテナ ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 検証済みの pid1。
    pub fn pid1(&self) -> &Pid1Target {
        &self.pid1
    }
}

/// `record` の稼働中コンテナから pid1 を特定する。
///
/// `Running` かつ pid 記録ありでなければ `FailedPrecondition`。記録 pid は検証（pidfd 固定・
/// 入れ子の PID 1・自分と別の pid / mnt namespace）を通ったときだけ採用する。
pub fn identify_pid1(record: &StateRecord) -> Result<ExecTarget, TraitError> {
    let status = record.status();
    if status.state() != ContainerState::Running || status.pid().is_none() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not running or has no recorded pid; cannot identify pid1",
        ));
    }
    // 記録 pid が別コンテナの PID 1 に再利用されていないことを、コンテナ固有の cgroup 名で確かめる
    // （pidfd だけでは記録上の元プロセスとの同一性を証明できない。SEC-1）。cgroup 配置の記録がなければ
    // 同一性を確認できないため拒否する（fail-closed）。
    let Some(placement) = record.cgroup() else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container has no recorded cgroup placement; cannot verify pid1 identity",
        ));
    };
    let name = CgroupName::for_instance(status.id(), placement.instance()).map_err(|_| {
        TraitError::new(ErrorCode::InvalidArgument, "invalid container cgroup name")
    })?;
    identify_pid1_in(record, name.as_str())
}

/// [`identify_pid1`] と同じ検証を、呼び出し側が解決済みの cgroup リーフ名（`fc-<id>@<instance>`）で行う。
///
/// 記録の cgroup 配置を介さず名前を直接渡したい呼び出し元（実機結合試験等）向け。名前は必須で、
/// 対象が属さなければ `FailedPrecondition`（SEC-1）。
pub fn identify_pid1_in(
    record: &StateRecord,
    expected_cgroup_name: &str,
) -> Result<ExecTarget, TraitError> {
    let status = record.status();
    if status.state() != ContainerState::Running {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not running; cannot identify pid1",
        ));
    }
    let Some(pid) = status.pid() else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container has no recorded pid; cannot identify pid1",
        ));
    };
    let pid1 = Pid1Target::open(pid, expected_cgroup_name).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: status.id().clone(),
        pid1,
    })
}

/// SUP-6 の 5 種（pid / mnt / uts / ipc / net）の namespace へ参加する。単一スレッドからのみ呼ぶこと。
pub fn enter_namespaces(target: &ExecTarget) -> Result<NamespaceJoinReport, TraitError> {
    join_namespaces(&target.pid1, &JoinNamespace::SUP6_SET).map_err(from_exec_error)
}

/// `ExecError` を `code` を保ったまま `TraitError` へ写す（段名はメッセージへ含める）。
fn from_exec_error(err: ExecError) -> TraitError {
    TraitError::new(
        err.code,
        format!("exec stage {:?}: {}", err.stage, err.message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{ContainerStatus, StateRevision};
    use std::num::NonZeroU32;

    fn record(status: ContainerStatus) -> StateRecord {
        StateRecord::new(
            status,
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap()
    }

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    /// SUP-6: Running 以外・pid なしは FailedPrecondition。
    #[test]
    fn sup6_identify_rejects_non_running_or_pidless() {
        let pid = NonZeroU32::new(std::process::id());
        for st in [
            ContainerStatus::created(cid(), pid),
            ContainerStatus::stopped(cid(), Some(0)),
            ContainerStatus::running(cid(), None),
        ] {
            let err = identify_pid1(&record(st)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        }
    }

    /// SUP-6・SEC-1: cgroup 配置の記録がなければ pid の同一性を確認できないため拒否する。
    #[test]
    fn sup6_identify_rejects_missing_cgroup_placement() {
        let pid = NonZeroU32::new(std::process::id());
        let err = identify_pid1(&record(ContainerStatus::running(cid(), pid))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(err.message().contains("cgroup"), "{}", err.message());
    }

    /// SUP-6: 記録 pid が pid1 でなければ（自プロセス）検証を素通りしない。
    #[test]
    fn sup6_identify_rejects_self_pid() {
        let pid = NonZeroU32::new(std::process::id());
        let rec = record(ContainerStatus::running(cid(), pid));
        let err = identify_pid1_in(&rec, "fc-c1@1").unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(err.message().contains("SetNs"), "{}", err.message());
    }
}
