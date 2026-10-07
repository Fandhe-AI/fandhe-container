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
//!   記録した cgroup 配置（委譲スコープと instance）から core が導くコンテナ固有の cgroup パス
//!   `<scope>/fc-<id>@<instance>` と対象の所属 cgroup の完全一致で確認する（SEC-1）。instance は
//!   ストア全体で再利用されないため、`state.json` へプロセス識別情報（開始時刻等）を追加せずに
//!   「記録したコンテナのプロセスであること」を照合できる（スキーマ変更なし）。この照合が依存する前提
//!   （コンテナから cgroupfs に書けないこと）と見直しの条件は core の `exec/setns.rs` のモジュール doc を参照
//! - 既定のビルドの公開 API に、期待 cgroup パスを文字列で受ける入口は無い（core・supervisor とも
//!   `exec-test-support` feature を付けたビルドに限る）
//! - [`enter_namespaces`] は呼び出しスレッドの namespace を不可逆に変える。単一スレッドのプロセスから
//!   のみ呼べる。logs 捕捉スレッドを持つ supervisor 本体からは呼ばず、exec 専用プロセスから呼ぶ（#503）
//! - 順序: cgroup.procs の fd 確保（#501）は [`enter_namespaces`] の前、seccomp / Landlock の再適用
//!   （#502）は後
//!
//! # 未実装（REPAIR-3）
//!
//! namespace 参加までで、コマンド実行は未実装。cgroup join（#501・TASK-163.2）、seccomp / Landlock 再適用
//! （#502・TASK-163.3）、fork・execve と統合テスト（#503・TASK-163.4）は未実装（SUP-6）。
//! user namespace への参加も未実装で、既定の rootless（コンテナが user namespace を持つ）では
//! [`enter_namespaces`] が `EPERM` で失敗する（fail-closed。rootless の exec には必須）。
//! 違反記録（SEC-4）の監査ログへの保存の配線も未実装（#839・#503）。

use fandhe_container_core::exec::{ExecError, NamespaceJoinReport, Pid1Target, join_namespaces};
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

/// `record` が稼働中で pid の記録を持つことを確かめ、記録 pid（候補）を返す。
fn running_pid(record: &StateRecord) -> Result<std::num::NonZeroU32, TraitError> {
    let status = record.status();
    match status.pid() {
        Some(pid) if status.state() == ContainerState::Running => Ok(pid),
        _ => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not running or has no recorded pid; cannot identify pid1",
        )),
    }
}

/// `record` の稼働中コンテナから pid1 を特定する。
///
/// `Running` かつ pid 記録ありでなければ `FailedPrecondition`。記録 pid は検証（pidfd 固定・直接入れ子の
/// PID 1・記録の cgroup 配置から導いた cgroup への所属・自分と別の pid / mnt namespace）を通ったときだけ
/// 採用する。期待 cgroup パスは core が記録の型（コンテナ ID・cgroup 配置）から組み立て、ここでは文字列を
/// 扱わない。
pub fn identify_pid1(record: &StateRecord) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    // 記録 pid が別コンテナの PID 1 に再利用されていないことを、コンテナ固有の cgroup で確かめる
    // （pidfd だけでは記録上の元プロセスとの同一性を証明できない。SEC-1）。cgroup 配置の記録がなければ
    // 同一性を確認できないため拒否する（fail-closed）。
    let Some(placement) = record.cgroup() else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container has no recorded cgroup placement; cannot verify pid1 identity",
        ));
    };
    let id = record.status().id();
    let pid1 = Pid1Target::open(pid, id, placement).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: id.clone(),
        pid1,
    })
}

/// 実機結合試験専用の入口: 期待 cgroup 絶対パスを呼び出し側から受け取って pid1 を特定する。
///
/// `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルド（リリース成果物を含む）の公開 API には
/// 含まれない（core の `Pid1Target::open_with_cgroup_path` も同じ feature に限る）。コンテナ用 cgroup を
/// 作れない試験環境で `Pid1Target` 以降の成功経路を通すためのもので、期待値を記録から導かないため
/// 「記録したコンテナのプロセスであること」（SEC-1）の照合にはならない。本番経路は必ず [`identify_pid1`] を使う。
#[cfg(feature = "exec-test-support")]
pub fn identify_pid1_in(
    record: &StateRecord,
    expected_cgroup_path: &str,
) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    let pid1 =
        Pid1Target::open_with_cgroup_path(pid, expected_cgroup_path).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: record.status().id().clone(),
        pid1,
    })
}

/// SUP-6 の 5 種（pid / mnt / uts / ipc / net）の namespace へ参加する。単一スレッドからのみ呼ぶこと。
pub fn enter_namespaces(target: &ExecTarget) -> Result<NamespaceJoinReport, TraitError> {
    join_namespaces(&target.pid1).map_err(from_exec_error)
}

/// `ExecError` を `code` を保ったまま `TraitError` へ写す（段名はメッセージへ含める）。
///
/// 分離違反による拒否（`ExecError::violation`。SEC-4）は、種別・理由コード・ビヘイビア ID をメッセージの
/// 末尾に機械可読な形で残す（`TraitError` は違反記録を運べないため）。違反の対象（期待 cgroup パス）は
/// メッセージへ含めない。監査ログへの保存の配線は未実装（#839・#503。REPAIR-3）。
fn from_exec_error(err: ExecError) -> TraitError {
    let violation = err.violation.as_ref().map_or_else(String::new, |v| {
        format!(
            " (violation: {}/{}, {})",
            v.kind.as_str(),
            v.reason.as_str(),
            v.behavior_id
        )
    });
    TraitError::new(
        err.code,
        format!("exec stage {:?}: {}{violation}", err.stage, err.message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerStatus, StateRevision,
    };
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
            assert_eq!(
                err.message(),
                "container is not running or has no recorded pid; cannot identify pid1"
            );
        }
    }

    /// SUP-6・SEC-1: cgroup 配置の記録がなければ pid の同一性を確認できないため拒否する。
    #[test]
    fn sup6_identify_rejects_missing_cgroup_placement() {
        let pid = NonZeroU32::new(std::process::id());
        let err = identify_pid1(&record(ContainerStatus::running(cid(), pid))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container has no recorded cgroup placement; cannot verify pid1 identity"
        );
    }

    /// SUP-6・SEC-1・SEC-4: cgroup 配置の記録があれば、記録の型のまま core の検証まで進む。自プロセスは
    /// 入れ子の PID 1 でないため SetNs 段で拒否され、違反の種別・理由コード・ビヘイビア ID がメッセージに残る。
    #[test]
    fn sup6_identify_with_placement_reaches_core_verification() {
        let pid = NonZeroU32::new(std::process::id());
        let rec = record(ContainerStatus::running(cid(), pid)).with_cgroup(CgroupPlacement::new(
            CgroupScope::new("/user.slice/x.scope").unwrap(),
            StateRevision::from_raw(7),
        ));
        let err = identify_pid1(&rec).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target is not PID 1 of a directly nested PID namespace \
             (violation: exec_target/exec_target_not_nested_pid1, SUP-6)"
        );
    }

    /// SUP-6: 違反記録のないエラー（システムエラー）は、段とメッセージだけを写す。
    #[test]
    fn sup6_identify_missing_pid_has_no_violation_suffix() {
        let rec = record(ContainerStatus::running(cid(), NonZeroU32::new(4_194_305))).with_cgroup(
            CgroupPlacement::new(CgroupScope::new("/").unwrap(), StateRevision::from_raw(7)),
        );
        let err = identify_pid1(&rec).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert!(
            err.message().starts_with("exec stage SetNs: pidfd_open"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("violation"), "{}", err.message());
    }
}
