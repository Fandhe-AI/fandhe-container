//! pod の pid namespace を共有するコンテナの kill-all（CRI-2・SUP-1・CORE-4・REPAIR-4・REPAIR-5・#4811）。
//!
//! # 役割と呼び出し元
//!
//! pid を共有すると、コンテナの init が終わっても子孫は pod の PID 1（保持役の pod-init）へ付け替わって残り、
//! 「init の終了で pid ns ごと回収される」前提が崩れる（設計 `docs/design/pod-namespace-holder.md`「pid の共有」の
//! 「停止と終了」・#4607 の O4）。そこで supervisor は次の 2 か所で、記録した配置のコンテナ cgroup へ `cgroup.kill` を
//! 書き、空になるのを [`KILL_ALL_LIMIT`] まで待つ（core の `cgroups::kill_all_in_recorded`）。
//!
//! 1. 監視ループが init の終了を観測した直後・終了を記録する前（`run::monitor_after_claim`。containerd の shim が
//!    init の終了を公開する前に全プロセスを止めるのと同じ順）
//! 2. 起動後に起動ハンドルを回収したすべての経路（停止・監視の失敗・出力の捕捉や seccomp の受け渡しの失敗・再起動の
//!    失敗。`start_entry::kill_after_dispose`）
//!
//! 対象かどうかは core の start の結果（`StartedContainer::shares_pod_pid_namespace`。config の pid の path）で決まり、
//! 対象でないコンテナの停止・終了の挙動は変えない。
//!
//! containerd v2.1.0 の一次情報: `cmd/containerd-shim-runc-v2/runc/util.go` の `ShouldKillAllOnExit`（31〜47 行。
//! pid の namespace が path なしで宣言されていなければ真）と、`cmd/containerd-shim-runc-v2/task/service.go` の
//! `handleInitExit`（696〜713 行。真なら `p.KillAll` の後に init の終了を公開する）。
//!
//! # 結果の構造化ログ
//!
//! 1 行 1 JSON（`component` = `supervisor`・`event` = `pid_shared_kill_all`）で、`outcome`（`killed`・`was_empty`・
//! `already_absent`・`no_cgroup`・`failed`）・`killed`（止める前に数えた件数。数えられなければ `null`）・`code`（失敗の
//! コード。期限切れは `TIMEOUT`）を出す。パス・pid は載せない。
//!
//! 失敗（期限切れ・権限不足等）の扱い: 終了の記録は続けるが、監視ループは `MonitorOutcome::ExitedProcessesRemain` を
//! 返し、再起動ループは再 launch しない（旧い世代の子孫が残った cgroup に新しい init を起動しない。fail-closed）。停止の
//! 経路は失敗の終了コードで終わる。停止の経路の配置は start 時に保持した値（`Running::placement`）で、ストアを読み直さない
//! （同じ ID の削除・再作成で別の世代を止めない）。残ったプロセスは delete の空の確認が拒否する（何も止めずに失敗する）。

use fandhe_container_core::traits::{CgroupPlacement, ContainerId, ErrorCode, TraitError};

/// kill-all で cgroup が空になるのを待つ上限（REPAIR-5）。
#[cfg(target_os = "linux")]
const KILL_ALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// 記録した配置のコンテナ cgroup を kill-all し、結果を構造化ログに 1 行出す（失敗も `Err` で返す）。
///
/// 配置が無い（cgroup を作っていない）ときは何もせず `no_cgroup` を出して `Ok`。
pub(crate) fn kill_remaining(
    id: &ContainerId,
    placement: Option<&CgroupPlacement>,
) -> Result<(), TraitError> {
    #[cfg(test)]
    if let Some(code) = FORCED_FAILURE.get() {
        emit(&kill_all_line("failed", None, Some(code)));
        return Err(TraitError::new(code, "forced kill-all failure for a test"));
    }
    let Some(placement) = placement else {
        emit(&kill_all_line("no_cgroup", Some(0), None));
        return Ok(());
    };
    match kill_all(id, placement) {
        Ok((outcome, killed)) => {
            emit(&kill_all_line(outcome, killed, None));
            Ok(())
        }
        Err(e) => {
            emit(&kill_all_line("failed", None, Some(e.code())));
            Err(e)
        }
    }
}

#[cfg(target_os = "linux")]
fn kill_all(
    id: &ContainerId,
    placement: &CgroupPlacement,
) -> Result<(&'static str, Option<u32>), TraitError> {
    use fandhe_container_core::cgroups::{RecordedCgroupOutcome, kill_all_in_recorded};
    let deadline = std::time::Instant::now() + KILL_ALL_LIMIT;
    let report = kill_all_in_recorded(id, placement, deadline).map_err(|e| {
        TraitError::new(
            e.code,
            "failed to kill the remaining processes of the container cgroup",
        )
    })?;
    let outcome = match report.outcome {
        RecordedCgroupOutcome::Killed => "killed",
        RecordedCgroupOutcome::WasEmpty => "was_empty",
        RecordedCgroupOutcome::AlreadyAbsent => "already_absent",
    };
    Ok((outcome, report.killed))
}

/// pid の共有は Linux だけ（core の `shares_pod_pid_namespace` は他 OS で常に偽）。
#[cfg(not(target_os = "linux"))]
fn kill_all(
    _id: &ContainerId,
    _placement: &CgroupPlacement,
) -> Result<(&'static str, Option<u32>), TraitError> {
    Err(TraitError::new(
        ErrorCode::Unimplemented,
        "cgroup kill-all is only available on Linux",
    ))
}

#[cfg(test)]
thread_local! {
    /// 試験の継ぎ目: `Some` なら [`kill_remaining`] が cgroup に触れずにこのコードで失敗する（呼び出したスレッドだけ）。
    static FORCED_FAILURE: std::cell::Cell<Option<ErrorCode>> = const { std::cell::Cell::new(None) };
}

/// 試験の継ぎ目: 呼び出したスレッドの [`kill_remaining`] を `code` で失敗させる（`None` で戻す）。
#[cfg(test)]
pub(crate) fn force_failure_for_test(code: Option<ErrorCode>) {
    FORCED_FAILURE.set(code);
}

/// 結果の 1 行（末尾改行つき）。値は固定語彙と数値だけ。
fn kill_all_line(outcome: &str, killed: Option<u32>, code: Option<ErrorCode>) -> String {
    let killed = killed.map_or_else(|| "null".to_owned(), |n| n.to_string());
    let code = code.map(|c| c.as_str()).unwrap_or("");
    format!(
        "{{\"component\":\"supervisor\",\"event\":\"pid_shared_kill_all\",\"outcome\":\"{outcome}\",\"killed\":{killed},\"code\":\"{code}\"}}\n"
    )
}

/// 満杯・書き込み失敗でも止めない（ログの欠落は許す）。
fn emit(line: &str) {
    let _ = crate::stderr_sink::stderr().emit(line.as_bytes().to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-4・#4811: 結果の行は固定語彙・件数・コードだけの 1 行 1 JSON。
    #[test]
    fn repair4_4811_kill_all_line_is_fixed_json() {
        assert_eq!(
            kill_all_line("killed", Some(3), None),
            "{\"component\":\"supervisor\",\"event\":\"pid_shared_kill_all\",\"outcome\":\"killed\",\"killed\":3,\"code\":\"\"}\n"
        );
        assert_eq!(
            kill_all_line("failed", None, Some(ErrorCode::Timeout)),
            "{\"component\":\"supervisor\",\"event\":\"pid_shared_kill_all\",\"outcome\":\"failed\",\"killed\":null,\"code\":\"TIMEOUT\"}\n"
        );
    }

    /// #4811: 配置が無ければ cgroup に触れず `Ok`。
    #[test]
    fn sup1_4811_no_placement_is_noop() {
        let id = ContainerId::new("c1").expect("id");
        assert!(kill_remaining(&id, None).is_ok());
    }
}
