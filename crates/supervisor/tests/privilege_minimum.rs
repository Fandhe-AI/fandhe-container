//! 権限昇格が必要最小の capability 集合に限定されることの機械照合（SUP-14・TASK-171.1.2・#858）。
//!
//! 公開 API のみを通し、fixture の `/proc/<pid>/status` 文字列で具体値を照合する。syscall・root・setuid を使わない
//! 純ロジックのため 3 OS・既定テスト集合で実行する（実機検証は #538・#539）。

use fandhe_container_core::capabilities::Capability;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::privilege::{
    KeepCapsState, PrivilegeErrorReason, PrivilegeMethod, elevate, parse_proc_status,
    runtime_required_capabilities, verify_elevation,
};

fn fixture(prm: &str, bnd: &str, amb: &str) -> String {
    format!(
        "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\nCapInh:\t{amb}\nCapPrm:\t{prm}\nCapEff:\t{prm}\nCapBnd:\t{bnd}\nCapAmb:\t{amb}\nNoNewPrivs:\t0\n"
    )
}

#[test]
fn sup14_task171_1_2_exact_minimum_set_is_accepted() {
    let t = fixture("0000000028201122", "0000000028201122", "0000000028201122");
    let snap = parse_proc_status(&t).unwrap();
    let report = verify_elevation(
        &snap,
        KeepCapsState::Cleared,
        runtime_required_capabilities(),
        PrivilegeMethod::LauncherAmbient,
    )
    .unwrap();
    let names: Vec<&str> = report.held.iter().map(Capability::as_str).collect();
    assert_eq!(
        names,
        [
            "CAP_DAC_OVERRIDE",
            "CAP_KILL",
            "CAP_SETPCAP",
            "CAP_NET_ADMIN",
            "CAP_SYS_ADMIN",
            "CAP_MKNOD",
            "CAP_AUDIT_WRITE"
        ]
    );
}

#[test]
fn sup14_task171_1_2_full_privileges_are_rejected() {
    let full = "000001ffffffffff";
    let snap = parse_proc_status(&fixture(full, full, "0000000028201122")).unwrap();
    let e = verify_elevation(
        &snap,
        KeepCapsState::Cleared,
        runtime_required_capabilities(),
        PrivilegeMethod::SetuidRoot,
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(e.reason, PrivilegeErrorReason::ExcessCapabilities);
}

#[test]
fn sup14_task171_1_2_elevate_stub_reports_unimplemented() {
    let e = elevate(PrivilegeMethod::LauncherAmbient).unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    assert_eq!(e.reason, PrivilegeErrorReason::Unimplemented);
}

/// SUP-14: 権限保持設定（`PR_SET_KEEPCAPS`）が残る・未確認の縮退結果は、capability が最小集合ちょうどでも拒否する。
#[test]
fn sup14_task171_1_2_keepcaps_retained_is_rejected() {
    let t = fixture("0000000028201122", "0000000028201122", "0000000028201122");
    let snap = parse_proc_status(&t).unwrap();
    for (state, code) in [
        (KeepCapsState::Set, ErrorCode::PermissionDenied),
        (KeepCapsState::Unknown, ErrorCode::FailedPrecondition),
    ] {
        let e = verify_elevation(
            &snap,
            state,
            runtime_required_capabilities(),
            PrivilegeMethod::SetuidRoot,
        )
        .unwrap_err();
        assert_eq!(e.code, code);
        assert_eq!(e.reason, PrivilegeErrorReason::KeepCapsRetained);
    }
}
